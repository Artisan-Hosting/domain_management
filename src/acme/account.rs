//! The ACME account.
//!
//! One account, reused for every issuance, stored as credentials JSON on
//! disk. Losing it is not fatal (a new one is created on the next run), but
//! it does reset the account's rate-limit standing with Let's Encrypt, so the
//! file is written 0600 and kept.

use instant_acme::{Account, AccountCredentials, NewAccount};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{Error, Result};

/// Loads the stored account, or registers a new one and stores it.
///
/// Staging and production credentials are kept in separate files: they are
/// not interchangeable, and pointing a production issuance at a staging
/// account produces certificates no browser trusts.
pub async fn load_or_create(config: &Config) -> Result<Account> {
    let path = credentials_path(config);
    let directory = config.acme_directory_url().to_owned();

    if path.exists() {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Acme(format!("reading {}: {e}", path.display())))?;
        let credentials: AccountCredentials = serde_json::from_str(&raw)
            .map_err(|e| Error::Acme(format!("parsing {}: {e}", path.display())))?;

        return Account::builder()
            .map_err(|e| Error::Acme(format!("acme client: {e}")))?
            .from_credentials(credentials)
            .await
            .map_err(|e| Error::Acme(format!("loading account from {}: {e}", path.display())));
    }

    let contact = if config.acme.contact_email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{}", config.acme.contact_email)]
    };

    let (account, credentials) = Account::builder()
        .map_err(|e| Error::Acme(format!("acme client: {e}")))?
        .create(
            &NewAccount {
                contact: &contact.iter().map(String::as_str).collect::<Vec<_>>(),
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await
        .map_err(|e| Error::Acme(format!("creating account: {e}")))?;

    store(&path, &credentials)?;
    Ok(account)
}

fn credentials_path(config: &Config) -> PathBuf {
    let path = &config.acme.account_key_path;
    if config.acme.staging {
        let mut name = path.as_os_str().to_owned();
        name.push(".staging");
        PathBuf::from(name)
    } else {
        path.clone()
    }
}

fn store(path: &Path, credentials: &AccountCredentials) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Acme(format!("creating {}: {e}", parent.display())))?;
    }

    let json = serde_json::to_string_pretty(credentials)
        .map_err(|e| Error::Acme(format!("serializing account credentials: {e}")))?;

    // Written through a temp file with the mode set before any content is in
    // it, so the key material is never briefly world-readable.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json)
        .map_err(|e| Error::Acme(format!("writing {}: {e}", tmp.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Acme(format!("chmod {}: {e}", tmp.display())))?;
    }

    std::fs::rename(&tmp, path)
        .map_err(|e| Error::Acme(format!("installing {}: {e}", path.display())))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_and_production_credentials_live_in_different_files() {
        let mut config = Config::default();
        config.acme.staging = true;
        let staging = credentials_path(&config);

        config.acme.staging = false;
        let production = credentials_path(&config);

        assert_ne!(staging, production);
        assert!(staging.to_string_lossy().ends_with(".staging"));
    }
}
