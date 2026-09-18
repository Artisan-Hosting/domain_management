//! What is actually in the certificate tree.
//!
//! Reads `<tree>/certs/_.<domain>/` as the acme.sh era left it: an `ecc` and
//! an `rsa` pair per domain, both covering the apex and its wildcard. Nothing
//! here trusts the directory name -- the names a certificate really covers
//! come from its SANs, because a directory called `_.example.com` holding a
//! certificate for something else is exactly the kind of thing worth finding.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::acme::KeyType;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDir {
    /// Directory name as found, e.g. `_.example.com`.
    pub dir: String,
    /// The domain implied by the directory name.
    pub implied_fqdn: String,
    pub entries: Vec<CertEntry>,
    /// Anything unreadable or missing, kept per directory rather than thrown.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertEntry {
    pub key_type: String,
    pub cert_path: String,
    pub key_path: String,
    pub subject_cn: Option<String>,
    /// The names the certificate actually covers.
    pub sans: Vec<String>,
    pub issuer: Option<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub key_present: bool,
    /// Unix mode of the private key, when there is one. Anything but 0600 is
    /// a finding: these files are world-readable on a shared host otherwise.
    pub key_mode: Option<u32>,
}

impl CertEntry {
    pub fn covers(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();

        self.sans.iter().any(|san| {
            let san = san.trim_end_matches('.').to_ascii_lowercase();
            if let Some(suffix) = san.strip_prefix("*.") {
                // A wildcard covers exactly one label, so `*.example.com`
                // matches `a.example.com` but not `a.b.example.com` -- the
                // mistake that makes a cert look fine until a subdomain of a
                // subdomain shows up.
                match name.strip_suffix(suffix) {
                    Some(prefix) => {
                        prefix.ends_with('.') && prefix.trim_end_matches('.').split('.').count() == 1
                    }
                    None => false,
                }
            } else {
                san == name
            }
        })
    }

    pub fn expires_in_days(&self, now: i64) -> i64 {
        (self.not_after - now) / 86_400
    }
}

/// Walks the certificate root. Missing root is not an error -- a tree with no
/// certificates yet is a legitimate state.
pub fn scan(certs_root: &Path) -> Result<Vec<CertDir>> {
    let mut out = Vec::new();

    let entries = match std::fs::read_dir(certs_root) {
        Ok(entries) => entries,
        Err(_) => return Ok(out),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dir = entry.file_name().to_string_lossy().into_owned();
        // The `_.` prefix is the acme.sh-era convention for "apex plus
        // wildcard"; anything else in here is not ours to interpret.
        let implied_fqdn = dir.strip_prefix("_.").unwrap_or(&dir).to_owned();

        let mut cert_dir =
            CertDir { dir, implied_fqdn, entries: Vec::new(), problems: Vec::new() };

        for key_type in KeyType::ALL {
            let cert_path = path.join(format!("{key_type}.pem"));
            let key_path = path.join(format!("{key_type}.key"));

            if !cert_path.exists() && !key_path.exists() {
                continue;
            }
            if !cert_path.exists() {
                cert_dir
                    .problems
                    .push(format!("{key_type}.key present with no {key_type}.pem"));
                continue;
            }

            match read_entry(&cert_path, &key_path, key_type) {
                Ok(entry) => cert_dir.entries.push(entry),
                Err(err) => cert_dir.problems.push(format!("{key_type}.pem: {err}")),
            }
        }

        if cert_dir.entries.is_empty() && cert_dir.problems.is_empty() {
            cert_dir.problems.push("no certificates in this directory".to_owned());
        }

        out.push(cert_dir);
    }

    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    Ok(out)
}

fn read_entry(cert_path: &Path, key_path: &Path, key_type: KeyType) -> std::result::Result<CertEntry, String> {
    let pem_bytes = std::fs::read(cert_path).map_err(|e| e.to_string())?;

    // A fullchain holds the leaf first; the leaf is what a client validates
    // against, so the leaf is what we describe.
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes).map_err(|e| e.to_string())?;
    let cert = pem.parse_x509().map_err(|e| e.to_string())?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);

    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);

    let key_present = key_path.exists();
    let key_mode = key_mode_of(key_path);

    Ok(CertEntry {
        key_type: key_type.to_string(),
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        subject_cn,
        sans,
        issuer,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        key_present,
        key_mode,
    })
}

#[cfg(unix)]
fn key_mode_of(key_path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(key_path).ok().map(|meta| meta.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn key_mode_of(_key_path: &Path) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with_sans(sans: &[&str]) -> CertEntry {
        CertEntry {
            key_type: "ecc".to_owned(),
            cert_path: String::new(),
            key_path: String::new(),
            subject_cn: None,
            sans: sans.iter().map(|s| (*s).to_owned()).collect(),
            issuer: None,
            not_before: 0,
            not_after: 0,
            key_present: true,
            key_mode: Some(0o600),
        }
    }

    #[test]
    fn wildcards_cover_one_label_only() {
        let cert = entry_with_sans(&["example.com", "*.example.com"]);

        assert!(cert.covers("example.com"));
        assert!(cert.covers("www.example.com"));
        assert!(cert.covers("WWW.Example.com."), "comparison is case- and dot-insensitive");
        assert!(
            !cert.covers("a.b.example.com"),
            "a wildcard spans one label; treating it as more is how a cert looks fine until it isn't"
        );
        assert!(!cert.covers("example.net"));
    }

    #[test]
    fn a_wildcard_does_not_cover_the_apex_by_itself() {
        let cert = entry_with_sans(&["*.example.com"]);
        assert!(!cert.covers("example.com"));
        assert!(cert.covers("www.example.com"));
    }

    #[test]
    fn expiry_is_reported_in_whole_days() {
        let mut cert = entry_with_sans(&["example.com"]);
        cert.not_after = 1_000_000 + 45 * 86_400;
        assert_eq!(cert.expires_in_days(1_000_000), 45);
    }

    #[test]
    fn a_missing_certificate_root_is_not_an_error() {
        let missing = std::env::temp_dir().join("ais_domains_no_such_certs_dir");
        assert!(scan(&missing).unwrap().is_empty());
    }
}
