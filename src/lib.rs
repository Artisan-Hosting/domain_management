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

pub mod acme;
pub mod auth;
pub mod cloudflare;
pub mod config;
pub mod db;
pub mod dns;
pub mod error;
pub mod grpc;
pub mod intake;
pub mod inventory;
pub mod mtls_client;
pub mod proto;
pub mod publish;
pub mod vhost;
