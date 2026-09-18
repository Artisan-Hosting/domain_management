# nginx-r2-agent

A single static Go binary replacing the old cron-driven `nginx-sync-r2.sh` /
`nginx-publish-r2.sh` bash scripts. It runs as a long-lived daemon with its
own internal scheduler instead of being re-invoked by cron, which sidesteps
the classic causes of "works by hand, flaky under cron":

- No dependency on cron's minimal `PATH` — it's one binary, no `aws`/`rsync`/
  `python3` shelling out for the S3 sync or manifest work (still shells out
  to `nginx` and `systemctl`, which are expected to exist).
- No dependency on `$HOME` being set correctly for credential file lookup —
  credentials come from explicit env vars.
- No bash-vs-sh shebang ambiguity, no relative-path-from-wrong-cwd surprises.
- Long-running process under systemd means `Restart=on-failure` gives you
  automatic retry with backoff, and journald gives you real logs, instead of
  cron's silent-failure-unless-you-set-up-MAILTO behavior.

## Build

Dependencies aren't vendored here — build on a machine with normal internet
access (this was generated in a network-restricted sandbox that can't reach
the Go module proxy, though `go.sum` is already pinned from a successful
build there).

```
cd nginx-r2-agent
make build          # -> ./nginx-r2-agent
```

Other targets:

```
make check          # gofmt + go vet + a throwaway build, no artifact left behind
make tidy           # go mod tidy
make install        # build, then install to /usr/local/bin
make linux-amd64    # cross-compile to dist/nginx-r2-agent-linux-amd64
make cross          # cross-compile for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
make clean          # remove build output
```

`make build` strips debug symbols (`-ldflags '-s -w'`) for a smaller
binary. Override `GOFLAGS` on the command line if you want a debug build,
e.g. `make build GOFLAGS=-gcflags=all=-N\ -l`.

See `DESIGN.md` for the reasoning behind the internal package structure,
known caveats (R2 ETag comparison, rsync fidelity), and what this rewrite
does and doesn't fix about the original cron reliability problem.

## Run

Two modes, same binary:

```
nginx-r2-agent sync      # was nginx-sync-r2.sh
nginx-r2-agent publish   # was nginx-publish-r2.sh
```

Add `--once` to run a single pass and exit (useful for testing, or if you'd
rather keep driving this from cron/a systemd timer instead of running it as
a persistent daemon).

Both modes read all configuration from environment variables — see
`deploy/sync.env.example` and `deploy/publish.env.example` for the full
list. `R2_ENDPOINT` is required; everything else has a default matching the
original scripts' defaults.

## Deploy as a systemd service (recommended)

```
sudo cp nginx-r2-agent /usr/local/bin/nginx-r2-agent
sudo mkdir -p /etc/nginx-r2-agent
sudo cp deploy/sync.env.example /etc/nginx-r2-agent/sync.env
sudo cp deploy/publish.env.example /etc/nginx-r2-agent/publish.env
# edit both .env files with real R2 credentials/endpoint

sudo cp deploy/nginx-r2-sync.service /etc/systemd/system/
sudo cp deploy/nginx-r2-publish.service /etc/systemd/system/
sudo chmod 600 /etc/nginx-r2-agent/*.env

sudo systemctl daemon-reload
sudo systemctl enable --now nginx-r2-sync.service
sudo systemctl enable --now nginx-r2-publish.service
```

Check on it with `systemctl status nginx-r2-sync` / `journalctl -u
nginx-r2-sync -f`.

## Behavior differences from the bash scripts worth knowing about

- **No `rsync`/`aws` CLI dependency.** Directory mirroring and S3 sync are
  implemented natively (`internal/fsutil`, `internal/r2sync`). File mode
  bits are preserved; ownership, xattrs, ACLs, and symlinks-as-links are
  not — fine for plain nginx config trees, worth knowing if you extend this.
- **R2 sync comparison uses size + MD5/ETag.** This only reliably detects
  "unchanged" for objects this tool itself uploaded via a single PutObject
  (no multipart). See the comment in `internal/r2sync/r2sync.go`.
- **Manifest hashing is native Go** (`crypto/sha256`), so the `python3`
  dependency from the publish script is gone entirely.
- **Intervals, not one-shot triggers.** `publish` now polls on
  `PUBLISH_INTERVAL` (default 12h) rather than being triggered externally
  right after cert renewal. If you want it event-driven instead (e.g. fired
  by your ACME client immediately after issuance), keep using `--once` from
  that hook instead of running the daemon loop for `publish`.
