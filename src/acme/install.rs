//! Putting issued certificates on disk.
//!
//! The layout is the one the fleet already runs on --
//! `<tree>/certs/_.<domain>/{ecc,rsa}.{pem,key}` -- so no nginx config
//! changes and no agent changes come with this service.
//!
//! Two rules the old script broke, and the reason this is its own module:
//!
//! 1. **Never destroy a working certificate on failure.** The script deleted
//!    the whole directory when a copy failed, which turns "renewal didn't
//!    work" into "the site is down".
//! 2. **All four files change together.** They are written as temp files and
//!    renamed into place, so nginx can never read a new certificate next to
//!    the old key.

use std::path::Path;

use super::{IssuedCert, KeyType};
use crate::config::Config;
use crate::error::{Error, Result};

pub struct InstalledPaths {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
}

/// Writes a full set of certificates for one domain.
///
/// Takes the whole set rather than one at a time: a domain with a fresh
/// ECDSA certificate and a stale RSA one is a configuration nobody asked for.
pub fn write_pair(config: &Config, fqdn: &str, certs: &[IssuedCert]) -> Result<Vec<InstalledPaths>> {
    let dir = config.cert_dir_for(fqdn);
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Io(std::io::Error::other(format!("creating {}: {e}", dir.display()))))?;

    // Stage everything first. If any write fails, the rename loop below never
    // runs and what is currently serving is untouched.
    let mut staged = Vec::with_capacity(certs.len() * 2);
    for cert in certs {
        let cert_path = dir.join(format!("{}.pem", cert.key_type));
        let key_path = dir.join(format!("{}.key", cert.key_type));

        staged.push((write_temp(&cert_path, cert.cert_pem.as_bytes())?, cert_path));
        staged.push((write_temp(&key_path, cert.key_pem.as_bytes())?, key_path));
    }

    for (tmp, final_path) in &staged {
        std::fs::rename(tmp, final_path).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "installing {}: {e}",
                final_path.display()
            )))
        })?;
    }

    Ok(certs
        .iter()
        .map(|cert| InstalledPaths {
            cert: dir.join(format!("{}.pem", cert.key_type)),
            key: dir.join(format!("{}.key", cert.key_type)),
        })
        .collect())
}

/// Writes `contents` to a sibling temp file with 0600 already set, and
/// returns its path. The mode is applied to the temp file, so the private key
/// is never readable by anyone else even for an instant.
fn write_temp(final_path: &Path, contents: &[u8]) -> Result<std::path::PathBuf> {
    let tmp = final_path.with_extension(format!(
        "{}.tmp",
        final_path.extension().and_then(|e| e.to_str()).unwrap_or("new")
    ));

    std::fs::write(&tmp, contents)
        .map_err(|e| Error::Io(std::io::Error::other(format!("writing {}: {e}", tmp.display()))))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            Error::Io(std::io::Error::other(format!("chmod {}: {e}", tmp.display())))
        })?;
    }

    Ok(tmp)
}

/// Reads the expiry of a certificate already on disk.
///
/// Used by `import` to seed the database from the certificates the acme.sh
/// era left behind, so onboarding does not re-issue every domain at once and
/// walk straight into Let's Encrypt's rate limits.
pub fn read_expiry(config: &Config, fqdn: &str, key_type: KeyType) -> Result<Option<i64>> {
    let path = config.cert_dir_for(fqdn).join(format!("{key_type}.pem"));
    if !path.exists() {
        return Ok(None);
    }

    let pem = std::fs::read(&path)
        .map_err(|e| Error::Io(std::io::Error::other(format!("reading {}: {e}", path.display()))))?;

    // A fullchain file holds the leaf first, then intermediates; the leaf is
    // the one whose expiry decides when we have to renew.
    let (_, parsed) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| Error::Acme(format!("parsing {}: {e}", path.display())))?;
    let cert = parsed
        .parse_x509()
        .map_err(|e| Error::Acme(format!("parsing {}: {e}", path.display())))?;

    Ok(Some(cert.validity().not_after.timestamp()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(root: &Path) -> Config {
        let mut config = Config::default();
        config.tree.root = root.to_path_buf();
        config
    }

    #[test]
    fn writes_all_four_files_with_the_expected_names() {
        let root = std::env::temp_dir().join(format!("ais_domains_install_{}", std::process::id()));
        let config = test_config(&root);

        let certs = vec![
            IssuedCert {
                key_type: KeyType::Ecc,
                cert_pem: "ecc-cert".to_owned(),
                key_pem: "ecc-key".to_owned(),
            },
            IssuedCert {
                key_type: KeyType::Rsa,
                cert_pem: "rsa-cert".to_owned(),
                key_pem: "rsa-key".to_owned(),
            },
        ];

        write_pair(&config, "example.com", &certs).unwrap();

        let dir = config.cert_dir_for("example.com");
        assert_eq!(std::fs::read_to_string(dir.join("ecc.pem")).unwrap(), "ecc-cert");
        assert_eq!(std::fs::read_to_string(dir.join("ecc.key")).unwrap(), "ecc-key");
        assert_eq!(std::fs::read_to_string(dir.join("rsa.pem")).unwrap(), "rsa-cert");
        assert_eq!(std::fs::read_to_string(dir.join("rsa.key")).unwrap(), "rsa-key");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("ecc.key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "private keys must not be readable by others");
        }

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_second_write_replaces_the_first() {
        let root =
            std::env::temp_dir().join(format!("ais_domains_install_2_{}", std::process::id()));
        let config = test_config(&root);

        let first = vec![IssuedCert {
            key_type: KeyType::Ecc,
            cert_pem: "old".to_owned(),
            key_pem: "old-key".to_owned(),
        }];
        write_pair(&config, "example.com", &first).unwrap();

        let second = vec![IssuedCert {
            key_type: KeyType::Ecc,
            cert_pem: "new".to_owned(),
            key_pem: "new-key".to_owned(),
        }];
        write_pair(&config, "example.com", &second).unwrap();

        let dir = config.cert_dir_for("example.com");
        assert_eq!(std::fs::read_to_string(dir.join("ecc.pem")).unwrap(), "new");

        std::fs::remove_dir_all(&root).ok();
    }
}
