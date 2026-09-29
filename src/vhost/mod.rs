//! nginx configuration this service writes.
//!
//! Two files per domain, and a rule that governs both.
//!
//! * [`snippet`] -- the `<zone>_cert.conf` that links a vhost to its ECDSA
//!   and RSA pair. One per zone, shared by every vhost on it.
//! * [`render`] -- the vhost itself, assembled from a runner's deployed
//!   instances (`ahpn-<node id>.ah.internal:<port>`), balanced across them
//!   when there is more than one.
//!
//! **The rule: only files carrying `MANAGED_HEADER` are ever rewritten.**
//! Everything already in this tree was written by hand, often with CORS
//! rules, `OPTIONS` handling and per-site quirks no template reproduces.
//! Those are read, reported and left alone.

pub mod render;
pub mod snippet;

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;

use crate::acme::KeyType;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::publish::stage::{self, Stage};

/// Everything attaching a domain to a runner writes, and the check that it
/// was safe to write.
#[derive(Debug)]
pub struct AttachOutcome {
    pub snippet: snippet::SnippetOutcome,
    pub vhost: render::VhostOutcome,
}

/// Writes the snippet and the vhost, then proves the tree still loads.
///
/// The order matters. The vhost includes the snippet, and the snippet names
/// certificate files -- so the certificates have to exist before any of this
/// is worth writing, and the whole lot has to pass `nginx -t` before it is
/// allowed to stay. A vhost that fails the test is removed again, leaving the
/// tree exactly as it was: the alternative is a tree that cannot be published
/// at all, which takes every *other* domain down with it.
pub async fn attach(config: &Config, spec: &render::VhostSpec) -> Result<AttachOutcome> {
    // Rendered first so an invalid request costs nothing.
    let _ = render::render(config, spec)?;

    let cert_dir = config.cert_dir_for(spec.cert_zone());
    let missing: Vec<String> = KeyType::ALL
        .iter()
        .filter(|key_type| !cert_dir.join(format!("{key_type}.pem")).exists())
        .map(|key_type| format!("{key_type}.pem"))
        .collect();

    if !missing.is_empty() {
        return Err(Error::Invalid(format!(
            "{}: no certificate yet ({} missing from {}); issue one before attaching, \
             or nginx will refuse to load the vhost",
            spec.cert_zone(),
            missing.join(" and "),
            cert_dir.display()
        )));
    }

    let snippet_outcome = snippet::ensure(config, spec.cert_zone())?;

    // Kept so a failed check can put things back exactly as they were.
    let vhost_path = config.vhost_path_for(&spec.fqdn);
    let previous = std::fs::read_to_string(&vhost_path).ok();

    let vhost_outcome = render::write(config, spec)?;

    if let Err(err) = validate(config, &spec.fqdn).await {
        match &previous {
            Some(content) => {
                let _ = std::fs::write(&vhost_path, content);
                log!(
                    LogLevel::Warn,
                    "{}: restored the previous vhost after nginx rejected the new one",
                    spec.fqdn
                );
            }
            None => {
                let _ = std::fs::remove_file(&vhost_path);
                log!(
                    LogLevel::Warn,
                    "{}: removed the new vhost after nginx rejected it",
                    spec.fqdn
                );
            }
        }
        return Err(err);
    }

    Ok(AttachOutcome { snippet: snippet_outcome, vhost: vhost_outcome })
}

async fn validate(config: &Config, fqdn: &str) -> Result<()> {
    let stage = Stage::create(config, &format!("attach-{}", crate::config::snippet_slug(fqdn)))?;
    stage::nginx_test(config, &stage).await
}
