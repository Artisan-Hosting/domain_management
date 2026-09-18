//! The certificate snippet -- the step between "a certificate exists" and
//! "a site serves it".
//!
//! In this tree a vhost never names a certificate. It says:
//!
//! ```text
//! include snippets/artisanhosting_cert.conf;
//! ```
//!
//! and that snippet carries the four lines linking the ECDSA and RSA pair.
//! One snippet per zone, shared by every vhost on it -- which is why
//! `link1_artisanstudio` through `link6_artisanstudio` all get their
//! certificate from one file.
//!
//! Writing that file was a manual step after every issuance, and a forgotten
//! one is invisible: the certificate renews happily, and nothing serves it.
//! So issuance writes it.
//!
//! **Only files this service wrote are ever rewritten.** An existing snippet
//! someone tuned by hand -- the ones with commented-out `acme_client_cert`
//! lines still in them -- is left exactly as it is and reported instead.

use std::path::{Path, PathBuf};

use crate::acme::KeyType;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::inventory::nginx::MANAGED_HEADER;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetOutcome {
    /// Did not exist; written.
    Created(PathBuf),
    /// Ours, and out of date; rewritten.
    Updated(PathBuf),
    /// Ours and already correct.
    Unchanged(PathBuf),
    /// Someone else's file. Left alone, with what it would have said.
    HandWritten { path: PathBuf, would_be: String },
}

impl SnippetOutcome {
    pub fn path(&self) -> &Path {
        match self {
            SnippetOutcome::Created(path)
            | SnippetOutcome::Updated(path)
            | SnippetOutcome::Unchanged(path) => path,
            SnippetOutcome::HandWritten { path, .. } => path,
        }
    }
}

/// The snippet body for a domain.
///
/// Both key types are listed, in the order the existing snippets use. nginx
/// accepts several `ssl_certificate` directives and serves whichever the
/// client's handshake can use -- that dual-certificate setup is the whole
/// reason issuance produces a pair.
///
/// Paths are written as the *deployed* tree spells them (`/etc/nginx/...`),
/// not as they sit on the publisher, because that is where nginx reads them.
pub fn render(config: &Config, fqdn: &str) -> String {
    let dir = config.deployed_cert_dir_for(fqdn).to_string_lossy().into_owned();

    let mut out = String::new();
    out.push_str(&format!("# {MANAGED_HEADER} -- certificates for {fqdn}\n"));
    out.push_str("# Link a vhost to it with:\n");
    out.push_str(&format!(
        "#     include {}/{}_cert.conf;\n",
        config.tree.snippets_dir,
        crate::config::snippet_slug(fqdn)
    ));
    out.push_str("# Edits here are overwritten on the next issuance.\n\n");

    for key_type in KeyType::ALL {
        out.push_str(&format!(
            "ssl_certificate     {dir}/{key_type}.pem;\nssl_certificate_key {dir}/{key_type}.key;\n",
        ));
        if key_type != KeyType::ALL[KeyType::ALL.len() - 1] {
            out.push('\n');
        }
    }

    out
}

/// Writes the snippet for a domain, unless it belongs to someone else.
pub fn ensure(config: &Config, fqdn: &str) -> Result<SnippetOutcome> {
    let path = config.snippet_path_for(fqdn);
    let desired = render(config, fqdn);

    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.contains(MANAGED_HEADER) {
            // A hand-written snippet. It may carry overrides, commented-out
            // history, or a deliberately different certificate; none of that
            // is ours to throw away.
            return Ok(SnippetOutcome::HandWritten { path, would_be: desired });
        }
        if existing == desired {
            return Ok(SnippetOutcome::Unchanged(path));
        }

        write_atomic(&path, &desired)?;
        return Ok(SnippetOutcome::Updated(path));
    }

    write_atomic(&path, &desired)?;
    Ok(SnippetOutcome::Created(path))
}

/// Does any snippet reference this domain's certificate directory?
///
/// The question behind `cert_without_snippet`: a certificate that renews on
/// schedule and that no configuration can reach.
pub fn references_cert_dir(snippet_body: &str, fqdn: &str) -> bool {
    let needle = format!("/_.{fqdn}/");
    snippet_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .any(|line| line.contains(&needle))
}

fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Io(std::io::Error::other(format!("creating {}: {e}", parent.display())))
        })?;
    }

    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, contents)
        .map_err(|e| Error::Io(std::io::Error::other(format!("writing {}: {e}", tmp.display()))))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        Error::Io(std::io::Error::other(format!("installing {}: {e}", path.display())))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_in(root: &Path) -> Config {
        let mut config = Config::default();
        config.tree.root = root.to_path_buf();
        config
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ais_domains_snippet_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn the_body_matches_the_shape_already_in_production() {
        let config = Config::default();
        let body = render(&config, "artisanhosting.net");

        // Four lines, both key types, deployed paths.
        assert!(body.contains("ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/ecc.pem;"));
        assert!(body.contains("ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/ecc.key;"));
        assert!(body.contains("ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/rsa.pem;"));
        assert!(body.contains("ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/rsa.key;"));
        // And it says how to use it, since that was the step people forgot.
        assert!(body.contains("include snippets/artisanhosting_cert.conf;"));
    }

    #[test]
    fn issuance_creates_then_leaves_alone() {
        let root = scratch("create");
        let config = config_in(&root);

        let first = ensure(&config, "example.com").unwrap();
        assert!(matches!(first, SnippetOutcome::Created(_)));
        assert_eq!(
            first.path(),
            root.join("snippets/example_cert.conf"),
            "named the way the existing snippets are"
        );

        // A renewal must not churn the file.
        let second = ensure(&config, "example.com").unwrap();
        assert!(matches!(second, SnippetOutcome::Unchanged(_)), "{second:?}");
    }

    #[test]
    fn a_hand_written_snippet_is_never_overwritten() {
        let root = scratch("handwritten");
        let config = config_in(&root);
        let path = config.snippet_path_for("artisanhosting.net");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // The real thing, commented history and all.
        let original = "#ssl_certificate /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/fullchain.pem;\n\
                        ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/ecc.pem;\n";
        std::fs::write(&path, original).unwrap();

        let outcome = ensure(&config, "artisanhosting.net").unwrap();

        match outcome {
            SnippetOutcome::HandWritten { would_be, .. } => {
                assert!(would_be.contains("rsa.pem"), "it still says what it would have written");
            }
            other => panic!("someone's hand-tuned snippet must survive: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "byte for byte untouched"
        );
    }

    #[test]
    fn a_snippet_we_wrote_is_brought_up_to_date() {
        let root = scratch("update");
        let config = config_in(&root);
        let path = config.snippet_path_for("example.com");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("# {MANAGED_HEADER} -- certificates for example.com\nssl_certificate /old/path.pem;\n"),
        )
        .unwrap();

        let outcome = ensure(&config, "example.com").unwrap();
        assert!(matches!(outcome, SnippetOutcome::Updated(_)), "{outcome:?}");
        assert!(std::fs::read_to_string(&path).unwrap().contains("rsa.key"));
    }

    #[test]
    fn a_snippets_certificate_reference_is_recognised() {
        let body = "ssl_certificate /etc/nginx/certs/_.example.com/ecc.pem;\n";
        assert!(references_cert_dir(body, "example.com"));
        assert!(!references_cert_dir(body, "other.com"));

        // A commented-out line links nothing.
        let commented = "#ssl_certificate /etc/nginx/certs/_.example.com/ecc.pem;\n";
        assert!(!references_cert_dir(commented, "example.com"));
    }
}
