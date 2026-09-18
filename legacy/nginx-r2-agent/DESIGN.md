# Design Notes — nginx-r2-agent

This document holds the explanatory context that used to live as comments
directly in the source. The code is written to be readable from names and
structure alone; this is where the *why*, the caveats, and the things that
aren't obvious from reading a function signature live instead.

## Overview (`cmd/agent/main.go`)

`nginx-r2-agent` is a single static binary with two long-running modes:

```
nginx-r2-agent sync     - pulls nginx config releases from R2 and applies them
nginx-r2-agent publish  - issues certs, snapshots config, publishes releases to R2
```

Both modes run forever with an internal ticker until SIGINT/SIGTERM, so
they're meant to be started once (e.g. via systemd) rather than re-invoked
by cron. Pass `--once` to run a single iteration and exit — handy for
testing, or for anyone who'd still rather drive this from cron or a systemd
timer instead of running it as a persistent daemon.

## Package `internal/r2sync`

Wraps the AWS S3 SDK pointed at a Cloudflare R2 endpoint and implements the
two operations these tools need: mirroring a remote prefix down to a local
directory (`sync --delete`), and mirroring a local directory up to a remote
prefix. Both directions compare on size + MD5/ETag so re-runs are cheap —
unchanged files are skipped entirely.

**`New(ctx, endpoint, bucket)`** builds a client against an R2 endpoint,
e.g. `https://<account-id>.r2.cloudflarestorage.com`. Credentials come from
the standard AWS env vars / shared config (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, or a profile) — nothing R2-specific is needed
there since R2's auth is S3-compatible.

**`DownloadTree`** mirrors `s3://bucket/remotePrefix` down into a local
directory: downloads new/changed objects, deletes local files with no
remote match. Equivalent to `aws s3 sync --delete <remote> <local>`.

**`UploadTree`** mirrors a local directory up to `s3://bucket/remotePrefix`:
uploads new/changed files, deletes remote objects with no local match.
Equivalent to `aws s3 sync --delete <local> <remote>`.

**Caveat on ETag comparison:** R2's ETag equals plain MD5 only for objects
uploaded via a single `PutObject` call (no multipart). Everything this tool
uploads goes through `PutObject`, so the comparison is reliable for
round-tripping through this tool specifically. If you later start uploading
large objects via multipart from somewhere else, ETag comparison for those
particular objects will always report "changed" and trigger a
re-download/re-upload — harmless, just not a no-op.

## Package `internal/fsutil`

Small local directory copy/mirror helpers that replace the `rsync -a` /
`rsync -a --delete` calls from the original bash scripts.

**`CopyDir(src, dst)`** recursively copies `src` into `dst`, creating `dst`
if needed. Existing files at the destination are overwritten; nothing at
the destination is removed. Use `MirrorDir` if you also want deletions.

**`MirrorDir(src, dst)`** makes `dst` look exactly like `src`: copies
everything from `src`, then removes any file under `dst` with no
counterpart in `src`. Equivalent to `rsync -a --delete src/ dst/`.

**Fidelity vs. rsync:** file mode bits are preserved; ownership, xattrs,
and ACLs are not, and symlinks are followed rather than recreated as links.
That matches what these scripts actually needed rsync for — plain
config-tree copies — but is worth knowing if this gets reused for trickier
trees later.

## Package `internal/nginxsync`

The long-running replacement for the old `nginx-sync-r2.sh` cron job: on
each tick it checks R2 for a new release, pulls it down, applies it to
`/etc/nginx`, tests + reloads nginx, and rolls back on failure.

`Config.Mode` is either `"full"` (mirror the entire release tree over
`/etc/nginx`) or `"partial"` (only sync the paths listed in
`Config.PartialPaths`).

**`RunLoop`** ticks forever (respecting context cancellation), running one
sync attempt immediately and then every `cfg.Interval`. A failed attempt is
logged and retried on the next tick rather than crashing the daemon —
matching the original script's behavior of "try again next cron run" but
without needing cron to provide the retry.

## Package `internal/certpublish`

The long-running replacement for the old `nginx-publish-r2.sh` cron job: on
each tick it (optionally) runs your cert issuer script, snapshots the
source tree, test-compiles the nginx config, builds a manifest, and
(optionally) publishes the release to R2.

Manifest hashing (`writeManifest`) is native Go (`crypto/sha256`), which is
why the `python3` dependency from the original bash script is gone
entirely — that script shelled out to a small inline Python snippet to
walk the tree and hash each file; here it's just a `filepath.WalkDir` +
`sha256.New()` loop.

## Cron reliability — what a compiled daemon actually fixes

The original motivation for this rewrite was cron flakiness. The classic
causes, and how this design addresses (or doesn't) each:

- **Minimal `PATH` under cron** — cron typically runs with
  `PATH=/usr/bin:/bin`, so `aws`, `rsync`, `python3` might not resolve even
  though they work fine interactively. Fixed: this binary only shells out
  to `nginx` and `systemctl` (both referenced by absolute or well-known
  path), and does its own S3 sync / directory mirroring / manifest hashing
  natively — no `aws`, `rsync`, or `python3` dependency left.
- **`$HOME` unset or wrong under cron** — the `aws` CLI reads credentials
  from `~/.aws/`, resolved via `$HOME`. Fixed: this binary takes
  credentials from explicit env vars, not a dotfile.
- **Bash-vs-`sh` shebang ambiguity** — cron sometimes invokes `sh
  script.sh` regardless of the shebang, breaking bashisms. Not applicable:
  there's no shell script left to misinterpret.
- **Working-directory assumptions** — cron starts jobs in the user's home
  directory, not wherever you ran the script from interactively; any
  relative paths would misbehave. Fixed: every path in this tool's config
  is either absolute or resolved from explicit config, never `cwd`-relative.
- **Silent failures** — a failed cron job that doesn't have `MAILTO` set up
  just disappears. Improved: running under systemd with
  `Restart=on-failure` gives automatic retry, and `journalctl -u
  nginx-r2-sync` gives you real, persistent logs.

What this rewrite does **not** by itself fix: if R2 itself is unreachable,
or your DNS/network is flaky, both the old scripts and this daemon will
still fail that attempt — the daemon just retries on its own schedule
instead of waiting for the next cron tick.

## Behavior differences from the original bash scripts

- No `rsync`/`aws` CLI / `python3` dependency — sync, mirroring, and
  manifest hashing are all native Go now.
- R2 sync comparison uses size + MD5/ETag, with the multipart caveat noted
  above.
- `publish` now polls on an interval (`PUBLISH_INTERVAL`, default 12h)
  rather than being triggered externally right after cert renewal. If you
  want it event-driven instead — fired by your ACME client immediately
  after issuance — call the binary with `--once` from that hook rather
  than running the daemon loop for `publish`.
