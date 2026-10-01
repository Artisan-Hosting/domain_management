//! DNS probing -- what the `certs` script shelled out to `dig` for.
//!
//! Two jobs:
//!
//! * **Gating** (`alias_cname_ok` / `ip_matches` in the old script): does a
//!   domain actually point at us before we spend a Let's Encrypt rate-limit
//!   slot on it?
//! * **Propagation**: has the TXT record we just wrote appeared on the alias
//!   zone's *authoritative* nameservers? The old flow slept a fixed number of
//!   seconds and hoped; asking the nameservers directly is both faster in the
//!   common case and correct in the slow one.

pub mod probe;
pub mod write;
