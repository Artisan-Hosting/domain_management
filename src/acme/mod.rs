//! Certificate issuance -- what the `certs` script did with acme.sh.
//!
//! Same shape as before: DNS-01 through Cloudflare, a challenge alias so TXT
//! records only ever land in one zone we control, and an ECDSA + RSA pair per
//! domain covering both `example.com` and `*.example.com`.
//!
//! What changed, and why:
//!
//! * **Per-domain challenge targets.** The script pointed every domain's
//!   `_acme-challenge` at one shared name. Two issuances at once then wrote
//!   TXT records to the same name and deleted each other's during cleanup.
//!   Domains onboarded here get their own target; imported ones keep the
//!   shared name and are serialized instead.
//! * **Propagation is checked, not slept through.** The TXT record is looked
//!   up on the alias zone's own nameservers before the CA is told to
//!   validate.
//! * **A failed issuance never deletes anything.** The old script `rm -rf`'d
//!   the certificate directory when a copy failed, taking the working
//!   certificate with it. New files are staged and renamed into place; if
//!   anything fails, what is already serving stays untouched.

pub mod account;
pub mod install;
pub mod issue;

/// The two key types every domain gets, exactly as before: an ECDSA P-256
/// certificate for clients that support it and an RSA-4096 one for those that
/// do not. nginx serves whichever the handshake asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ecc,
    Rsa,
}

impl KeyType {
    pub const ALL: [KeyType; 2] = [KeyType::Ecc, KeyType::Rsa];

    /// Also the on-disk basename (`ecc.pem`/`ecc.key`), which existing nginx
    /// configs already reference.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Ecc => "ecc",
            KeyType::Rsa => "rsa",
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A freshly issued certificate, in memory. Nothing is on disk yet -- that is
/// [`install::write_pair`]'s job, and it only runs once both key types have
/// succeeded.
pub struct IssuedCert {
    pub key_type: KeyType,
    /// Full chain, leaf first.
    pub cert_pem: String,
    pub key_pem: String,
}
