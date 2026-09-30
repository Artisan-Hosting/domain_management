//! `ais_domains` -- domain and SSL management for the Artisan Hosting platform.
//!
//! Replaces three manual tools that used to live in this directory (now under
//! `legacy/`): the `certs` acme.sh wrapper, the `issuer` publish script, and
//! the publishing half of `nginx-r2-agent`. The edge half of that agent stays
//! exactly where it is -- this service publishes to R2 in the layout it
//! already reads.
//!
//! Exposed as a library as well as a binary so the integration tests in
//! `tests/` can reach the pieces that have to stay wire-compatible with what
//! they replace -- the release manifest above all.
//!
//! ## Three subsystems in one binary
//!
//! By the time everything in `proto/domains.proto` is implemented, this
//! crate is really three things wearing one `Cargo.toml`, sharing the same
//! [`config::Config`]/[`config::Secrets`] and, once it exists, the same
//! `jobs` table. Knowing which one a given piece of code belongs to is the
//! fastest way to understand why it's shaped the way it is:
//!
//! 1. **The CLI** ([`main`][crate] -- see `src/main.rs`'s `Command` enum).
//!    Synchronous, one process per invocation, and deliberately able to run
//!    with a broken or absent database (`issue`, `publish`) -- "what running
//!    the old script by hand did," for the 3am case where tidiness loses to
//!    availability. `scan`/`plan`/`apply`/`clean` are the migration tooling
//!    that brought the pre-existing hand-managed fleet under this service's
//!    tracking in the first place.
//! 2. **The gRPC API** ([`grpc`]). One long-lived process (`ais_domains
//!    serve`), one connection pool, thin handlers per the doc on
//!    [`grpc::service`] -- authorize, read or write the database, and
//!    either act directly (when the work is local and fast: rendering a
//!    vhost, staging and `nginx -t`-ing a freeform submission, a single
//!    Cloudflare DNS record CRUD call) or hand off to subsystem 3 (when the
//!    work spends money, talks to a registrar, or otherwise must survive
//!    the request that started it being cancelled).
//! 3. **The async job worker** (`worker`, landing alongside the purchase
//!    flow -- see the `jobs` table in `migrations/0001_init.sql`). Claims
//!    rows with `SELECT ... FOR UPDATE SKIP LOCKED`, so a restart or a
//!    second process can never run the same job twice -- the property that
//!    matters most for a domain registration, where running it twice means
//!    charging twice. Spawned from inside the same `serve()` process as
//!    subsystem 2 to start with (one shared pool, one shared config), with
//!    room to split into its own process later purely by moving where
//!    `tokio::spawn` is called -- the `jobs` table, not the process
//!    boundary, is what makes that split safe.
//!
//! A function that looks like it's doing too little to justify existing
//! (`cloudflare::dns::ensure_challenge_cname`, say) is usually one that gets
//! called from more than one of these three -- once synchronously from the
//! API when a BYO domain's zone already exists, and later from inside a
//! `register` job when a purchase completes. Doc comments on functions like
//! that call out every caller on purpose, since "who else calls this" is
//! not otherwise visible from any one call site.

pub mod acme;
pub mod auth;
pub mod billing;
pub mod cloudflare;
pub mod config;
pub mod db;
pub mod dns;
pub mod error;
pub mod grpc;
pub mod inventory;
pub mod mtls_client;
pub mod proto;
pub mod publish;
pub mod purchasing;
pub mod vhost;
pub mod worker;
