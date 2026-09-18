# ais_domains

Domain and SSL management for the Artisan Hosting platform: buy a domain (or
bring one), get its DNS right, issue certificates, render an nginx vhost, and
publish the tree the edges serve.

It replaces three manual tools that used to live in this directory and are now
kept, unmodified, in `legacy/`:

| Was | Is now |
|---|---|
| `legacy/certs` -- acme.sh loop over `/etc/acme-sh/domains.txt` | `src/acme/` (issuance), `src/dns/` (the `dig` gating) |
| `legacy/issuer` -- stage, `nginx -t`, manifest, publish to GCS | `src/publish/` |
| `legacy/nginx-r2-agent` -- Go, publishes to R2 and pulls on edges | publishing side replaced by `src/publish/r2.rs`; **the edge side stays** |

The edge agent is deliberately untouched, so this service has to publish in the
layout it already reads. `tests/manifest_compat.rs` enforces that by running
the original Python manifest code from `legacy/issuer` and comparing byte for
byte.

## Running it

```
ais_domains serve              # the gRPC service and its workers (default)
ais_domains migrate            # apply database migrations and exit
ais_domains scan               # index what already exists -> inventory.json + plan.json
ais_domains plan show          # summarize a plan file
ais_domains apply --dry-run    # what applying that plan would change
ais_domains clean --fix        # move confirmed junk to the attic
ais_domains issue example.com  # one domain, by hand -- the old `certs` script
ais_domains publish --dry-run  # stage and nginx -t, upload nothing
```

`scan`, ### The certificate snippet

A vhost in this tree never names its certificate. It says:

```nginx
include snippets/artisanhosting_cert.conf;
```

and that snippet carries the four lines linking the ECDSA and RSA pair, with
the paths spelled as the edge sees them (`/etc/nginx/certs/_.<domain>/...`).
One snippet per zone, shared by every vhost on it.

Writing that file was a manual step after every issuance, and forgetting it is
invisible -- the certificate renews happily and nothing serves it. So
`issue` writes it, and the scanner reports `cert_without_snippet` for any
certificate that never got one.

**Snippets written by hand are never overwritten.** If a snippet exists
without this service's header, issuance leaves it exactly as it is and says
so, because those files carry commented-out history and deliberate overrides
that are not ours to discard.

`issue` and `publish` work without a database on purpose: when
something is broken at 3am, finding out what is on disk, or issuing one
certificate, should not depend on MySQL being up.

## Adopting what is already there

The system this replaces was loosely defined -- a flat `domains.txt`,
hand-written vhosts, certificate directories nobody tracked -- so the first
job is to see it clearly and attach it to the organizations and projects the
platform already knows about.

### 1. Look

```
ais_domains scan \
  --domains-file /etc/acme-sh/domains.txt \
  --check-dns \
  --login you@artisanhosting.net \
  --portal-url https://api.artisanhosting.net
```

Read-only. Safe against production at any time. It writes two files:

* **`inventory.json`** -- the facts. Every config file (followed through
  `include`, so what is actually live), every server block, every certificate
  with its real SANs and expiry, every line of `domains.txt`.
* **`plan.json`** -- the decisions, for you to edit.

`--login` (or `ARTISAN_TOKEN`) fetches organizations and runners from
`ais_auth` so the plan can suggest where things belong. `--portal-url` adds
repo names from Portal's `/v1/repos`, without which a suggestion can only
match runner ids -- and no domain name contains one of those. Both are
optional; without them the scan still works and simply suggests nothing.

### What it looks for

| Finding | Means |
|---|---|
| `vhost_only` | served over TLS but absent from `domains.txt` -- **renewal was never happening for it** |
| `vhost_without_cert` | a vhost pointing at a certificate that is not there -- usually already an outage |
| `cert_name_mismatch` | the certificate does not cover the name being served |
| `duplicate_server_name` | two files claim one hostname; nginx serves whichever loaded first and says nothing |
| `cert_expired` / `cert_expiring` | past, or inside `renew_before_days` |
| `key_permissions` | a private key readable by more than its owner |
| `cert_without_snippet` | a certificate exists and **no snippet links it**, so nothing can serve it however well it renews |
| `cert_without_vhost` | a certificate directory nothing serves |
| `domains_txt_only` | renewed for years; nothing serves it |
| `unreferenced_config` | a `.conf` no `include` reaches, so none of it is live |
| `unparsed_file` | the scanner declined to interpret it, and left it alone |
| `cert_unreadable` | an empty or half-copied certificate directory |
| `dns_mismatch`, `missing_challenge_cname` | with `--check-dns` |

### 2. Decide

Edit `plan.json`. Per domain, `suggested` is what the scanner guessed and why;
`assign` is what will actually happen. Set `action` to `skip` for anything you
want left alone. Tick `confirm: true` on any quarantine entry you actually
want moved. `//` comments are allowed -- annotate as you work.

Domains are keyed by **what a certificate would be issued for**, not by
registrable domain, so `shop.example.com` and `blog.example.com` on one shared
zone stay separate records belonging to separate customers.

`organization_id` may stay `null` for as long as you like. A domain with no
organization is a normal, durable state, and attaching one later is an
ordinary operation (`AssignDomain`), not a re-run of the migration.

### 3. Apply

```
ais_domains apply plan.json --dry-run   # prints every row it would change
ais_domains apply plan.json
```

Idempotent: applying the same plan twice changes nothing the second time. A
domain already attached to an organization is never silently moved --
that needs `--force-reassign`. Certificates are recorded with the expiry read
off disk, so adopting a working system does not queue a hundred ACME orders.

A plan may also carry `runner_org_assignments`, which fix `ais_auth`'s own
runner→org table -- the assignments that otherwise have to be made in the
database by hand. Those write to another service, so they need an elevated
token and will ask for your password.

### 4. Tidy

```
ais_domains clean plan.json          # report only
ais_domains clean plan.json --fix    # move confirmed entries to the attic
```

Nothing is ever deleted. Confirmed entries move to
`<work_root>/attic/<timestamp>/`, keeping their path, with a `manifest.json`
saying why. `nginx -t` then runs against the resulting tree, and **if it
fails, every move is rolled back**. Duplicate `server_name`s and cert
mismatches are reported but never auto-fixed: only a person knows which of two
duplicates was meant.

## Attaching a domain to a runner

A runner's instances are addressed as `ahpn-<node id>.ah.internal:<port>` --
the node id with the internal domain glued on, and the port from that
instance's own config. The caller placed the repo on the node and read its
config, so it sends both and the vhost is assembled from them:

```
AttachDomain {
  id_or_fqdn: "artisanhosting.net",
  runner_id:  "ab12cd34",
  backends: [
    { node_id: "2973453917896704", port: 8093 },
    { node_id: "3091229306929152", port: 8093 },
  ],
  extra_names: ["www.artisanhosting.net"],
}
```

More than one instance becomes a balanced upstream, with the same
`max_fails`/`fail_timeout` tuning the hand-written `artisan_release` block
uses. Re-attaching with a different set rewrites the upstream, which is how
scaling out reaches the edge.

Order and safety:

1. The certificate must already exist. Attaching without one is refused with
   the reason, before anything is written -- nginx will not load a vhost whose
   certificate is missing.
2. The snippet is ensured, then the vhost written.
3. **The tree is staged and `nginx -t` run.** If it fails, the vhost is
   removed (or the previous one restored, byte for byte) and the error
   returned. A tree that cannot be published takes every *other* domain with
   it, so a bad attach is never allowed to stay.

Hand-written vhosts are never replaced. The existing files carry CORS rules,
`OPTIONS` handling and per-site quirks no template reproduces; an attach
against one reports what it *would* have written and changes nothing.

## Configuration

* `/opt/artisan/etc/ais_domains.json` -- see `ais_domains.json.example`.
  JSON, with `//` and `/* */` comments stripped before parsing.
* `/opt/artisan/etc/ais_domains.env` (mode 0600) -- credentials only. Accepts
  the same `KEY=value` shape as the old `/etc/acme-sh/cloudflare.env`, and
  reads `CF_Token`/`CF_Account_ID` under their acme.sh names so that file can
  be moved across as-is.

Four Cloudflare tokens, split by blast radius:

| Env var | Scope | Why separate |
|---|---|---|
| `CF_CHALLENGE_TOKEN` | DNS edit, alias zone only | Used on every renewal; a leak cannot touch a customer zone |
| `CF_ZONES_TOKEN` | Zone + DNS edit, account | Creates zones, writes edge records |
| `CF_REGISTRAR_TOKEN` | Registrar write | The only credential that can spend money |
| `CF_MEMBERS_TOKEN` | Account members | Customer invites |

Ship defaults are safe: Let's Encrypt **staging**, publishing in **shadow
mode** (no `latest` pointer), purchasing **off**.

## Where this is up to

**Done:** config and secrets, schema and migrations, the Cloudflare DNS/zones
client, DNS probing, ACME issuance (ECDSA P-256 + RSA-4096 over DNS-01 with a
challenge alias), certificate installation, staging + `nginx -t` + manifest +
R2 publish, and the whole adoption path above -- scanner, findings, plan file,
apply, quarantine, plus the `AssignDomain` / `ListInventory` / `ListFindings` /
`RescanInventory` / `ListAdoptedVhosts` RPCs.

**Not wired yet:** Portal's `/v1/domains/*` routes and the dashboard view, so
attachment is CLI- and gRPC-only for now. `ConvertVhost` waits on the vhost
template work. The purchasing RPCs (Cloudflare Registrar, Stripe, zone
invites) return `unimplemented` naming their phase.

**Blocked on access to the running systems** (phase 0 in the plan):

1. The Go agent's source on the publisher host (`/opt/nginx-r2-agent`) --
   the R2 key layout in `src/publish/manifest.rs::Keys` is taken from the old
   shell script and is *assumed* unchanged. Confirm before turning
   `shadow_mode` off.
2. Two or three real server blocks from `/mnt/nginx_local`, to base the vhost
   template on.
3. Where a runner's upstream `host:port` per node actually lives, which is
   what vhost rendering needs.
