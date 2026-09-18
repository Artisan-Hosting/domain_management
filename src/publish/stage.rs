//! Staging and validating the nginx tree before anything is published.
//!
//! Straight from `legacy/issuer`: snapshot the tree, run `nginx -t` against
//! the snapshot, and only then upload. The point is that a broken config
//! fails here, on the publisher, instead of on every edge at once.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{Error, Result};

pub struct Stage {
    /// `<work_root>/stage/<release id>`
    pub dir: PathBuf,
    /// `<dir>/tree` -- the snapshot itself, and what gets uploaded.
    pub tree: PathBuf,
    pub release_id: String,
    keep: bool,
}

impl Stage {
    /// Snapshots the live tree.
    pub fn create(config: &Config, release_id: &str) -> Result<Self> {
        let dir = config.work_stage_dir(release_id);
        let tree = dir.join("tree");

        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| Error::Publish(format!("clearing {}: {e}", dir.display())))?;
        }
        std::fs::create_dir_all(&tree)
            .map_err(|e| Error::Publish(format!("creating {}: {e}", tree.display())))?;

        copy_tree(&config.tree.root, &tree)?;

        Ok(Self {
            dir,
            tree,
            release_id: release_id.to_owned(),
            keep: config.tree.keep_stage,
        })
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // The script removed the staging directory unless KEEP_STAGE=1. Doing
        // it in Drop means it also happens when a publish fails partway, which
        // is exactly when stale snapshots used to pile up.
        if self.keep {
            log!(LogLevel::Info, "keeping staged release at {}", self.dir.display());
            return;
        }

        if let Err(err) = std::fs::remove_dir_all(&self.dir) {
            if err.kind() != std::io::ErrorKind::NotFound {
                log!(LogLevel::Warn, "could not clean up {}: {}", self.dir.display(), err);
            }
        }
    }
}

/// `rsync -a --delete` in the script. The destination is always freshly
/// created here, so there is nothing to delete.
///
/// Symlinks are followed and copied as their content: the certificate tree
/// has none today, and an edge that received a dangling link would fail to
/// load its config.
pub(crate) fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    let entries = std::fs::read_dir(from)
        .map_err(|e| Error::Publish(format!("reading {}: {e}", from.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| Error::Publish(format!("reading {}: {e}", from.display())))?;
        let source = entry.path();
        let destination = to.join(entry.file_name());

        let meta = std::fs::metadata(&source)
            .map_err(|e| Error::Publish(format!("stat {}: {e}", source.display())))?;

        if meta.is_dir() {
            std::fs::create_dir_all(&destination).map_err(|e| {
                Error::Publish(format!("creating {}: {e}", destination.display()))
            })?;
            copy_tree(&source, &destination)?;
        } else if meta.is_file() {
            // `fs::copy` carries the mode across, which matters: the private
            // keys in this tree are 0600 and must stay that way in the
            // snapshot.
            std::fs::copy(&source, &destination).map_err(|e| {
                Error::Publish(format!(
                    "copying {} to {}: {e}",
                    source.display(),
                    destination.display()
                ))
            })?;
        }
    }

    Ok(())
}

/// Runs `nginx -t` against a staged tree.
///
/// Both attempts from the script are kept. The first treats the staged tree
/// as an nginx prefix; when a config uses absolute paths that fails, and the
/// fallback re-runs the test against a copy laid out as `etc/nginx`.
pub async fn nginx_test(config: &Config, stage: &Stage) -> Result<()> {
    let first = run_nginx(
        config,
        &["-t", "-p", &stage.tree.to_string_lossy(), "-c", "nginx.conf"],
    )
    .await?;

    if first.success {
        log!(LogLevel::Info, "nginx config test: OK");
        return Ok(());
    }

    log!(
        LogLevel::Warn,
        "nginx -t against the staged prefix failed; retrying in a sandbox copy"
    );

    let sandbox = stage.dir.join("sandbox/etc/nginx");
    std::fs::create_dir_all(&sandbox)
        .map_err(|e| Error::Publish(format!("creating {}: {e}", sandbox.display())))?;
    copy_tree(&stage.tree, &sandbox)?;

    let second = run_nginx(
        config,
        &["-t", "-c", &sandbox.join("nginx.conf").to_string_lossy()],
    )
    .await?;

    if second.success {
        log!(LogLevel::Info, "nginx config test: OK (sandbox)");
        return Ok(());
    }

    Err(Error::Nginx(format!(
        "config test failed.\n-- staged prefix --\n{}\n-- sandbox --\n{}",
        first.output.trim(),
        second.output.trim()
    )))
}

struct NginxRun {
    success: bool,
    output: String,
}

async fn run_nginx(config: &Config, args: &[&str]) -> Result<NginxRun> {
    let output = tokio::process::Command::new(&config.tree.nginx_bin)
        .args(args)
        .output()
        .await
        .map_err(|e| {
            Error::Nginx(format!("running {}: {e}", config.tree.nginx_bin.display()))
        })?;

    // nginx writes the result of -t to stderr even when it passes.
    let mut combined = String::from_utf8_lossy(&output.stderr).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));

    Ok(NginxRun { success: output.status.success(), output: combined })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_tree_preserves_structure_and_mode() {
        let root = std::env::temp_dir().join(format!("ais_domains_stage_{}", std::process::id()));
        let source = root.join("src");
        let destination = root.join("dst");
        std::fs::create_dir_all(source.join("certs/_.example.com")).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("nginx.conf"), b"events {}\n").unwrap();

        let key = source.join("certs/_.example.com/ecc.key");
        std::fs::write(&key, b"secret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        copy_tree(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read_to_string(destination.join("nginx.conf")).unwrap(),
            "events {}\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(destination.join("certs/_.example.com/ecc.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "a staged private key must stay unreadable");
        }

        std::fs::remove_dir_all(&root).ok();
    }
}
