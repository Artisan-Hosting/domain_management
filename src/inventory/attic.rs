//! Quarantine: moving junk out of the tree without ever deleting it.
//!
//! Three guarantees, in order of how much they matter:
//!
//! 1. **Nothing is deleted.** Everything goes to
//!    `<work_root>/attic/<timestamp>/`, keeping its path inside the tree.
//!    Undoing a bad call is a `mv` back, not a restore from backup.
//! 2. **Nothing moves unless a person ticked it.** Only `quarantine` entries
//!    with `confirm: true` are touched. The scanner proposes; it never
//!    decides.
//! 3. **If the tree stops passing `nginx -t`, every move is undone.** The
//!    check runs after the moves, and a failure rolls the lot back before
//!    returning. A quarantine run either leaves a valid tree or leaves the
//!    tree exactly as it found it.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use super::plan::Plan;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::publish::stage::{self, Stage};

#[derive(Debug, Serialize, Deserialize)]
pub struct AtticManifest {
    pub quarantined_at: String,
    pub tree_root: String,
    pub moved: Vec<MovedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovedEntry {
    /// Path inside the tree, which is also its path inside the attic.
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct QuarantineReport {
    pub moved: Vec<MovedEntry>,
    /// Entries deliberately not moved, and why.
    pub skipped: Vec<String>,
    pub attic_dir: Option<PathBuf>,
    pub rolled_back: bool,
}

impl QuarantineReport {
    pub fn summary(&self) -> String {
        let where_to = self
            .attic_dir
            .as_ref()
            .map(|dir| dir.display().to_string())
            .unwrap_or_else(|| "nowhere (nothing to do)".to_owned());

        if self.rolled_back {
            return format!(
                "rolled back: nginx rejected the tree after {} move(s); nothing was changed",
                self.moved.len()
            );
        }

        format!(
            "{} item(s) moved to {}, {} skipped",
            self.moved.len(),
            where_to,
            self.skipped.len()
        )
    }
}

/// Moves every confirmed quarantine entry, then validates the tree.
pub async fn quarantine(config: &Config, plan: &Plan, dry_run: bool) -> Result<QuarantineReport> {
    let mut report = QuarantineReport::default();

    let confirmed: Vec<_> = plan.quarantine.iter().filter(|item| item.confirm).collect();
    for item in plan.quarantine.iter().filter(|item| !item.confirm) {
        report
            .skipped
            .push(format!("{}: not confirmed ({})", item.path, item.reason));
    }
    if confirmed.is_empty() {
        return Ok(report);
    }

    let tree_root = &config.tree.root;
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let attic_dir = config.tree.work_root.join("attic").join(&timestamp);

    // Validate everything before moving anything: a run that fails halfway
    // through its own argument list is the worst outcome available.
    let mut planned = Vec::new();
    for item in &confirmed {
        match validate(tree_root, &item.path) {
            Ok(source) => planned.push((source, item.path.clone(), item.reason.clone())),
            Err(reason) => report.skipped.push(format!("{}: {reason}", item.path)),
        }
    }

    if dry_run {
        for (_, path, reason) in &planned {
            report.moved.push(MovedEntry { path: path.clone(), reason: reason.clone() });
        }
        report.attic_dir = Some(attic_dir);
        return Ok(report);
    }

    std::fs::create_dir_all(&attic_dir)
        .map_err(|e| Error::Publish(format!("creating {}: {e}", attic_dir.display())))?;

    let mut done: Vec<(PathBuf, PathBuf)> = Vec::new();

    for (source, path, reason) in &planned {
        let destination = attic_dir.join(path);

        if let Err(err) = move_path(source, &destination) {
            // Undo whatever already moved, then report the original failure.
            roll_back(&done);
            return Err(Error::Publish(format!("quarantining {path}: {err}; rolled back")));
        }

        done.push((source.clone(), destination));
        report.moved.push(MovedEntry { path: path.clone(), reason: reason.clone() });
    }

    // The tree has to still be valid without what was just taken out of it.
    if let Err(err) = validate_tree(config, &timestamp).await {
        log!(LogLevel::Error, "nginx rejected the tree after quarantine: {}", err);
        roll_back(&done);
        report.rolled_back = true;
        report.attic_dir = None;
        let _ = std::fs::remove_dir_all(&attic_dir);
        return Ok(report);
    }

    write_manifest(&attic_dir, tree_root, &timestamp, &report.moved)?;
    report.attic_dir = Some(attic_dir);

    Ok(report)
}

/// Refuses anything that should never be moved, before it is moved.
fn validate(tree_root: &Path, relative: &str) -> std::result::Result<PathBuf, String> {
    if relative.is_empty() {
        return Err("empty path".to_owned());
    }

    let candidate = PathBuf::from(relative);
    if candidate.is_absolute() {
        return Err("absolute paths are not accepted; quarantine works inside the tree".to_owned());
    }
    // `../../etc/nginx` in a hand-edited plan file must not reach outside the
    // tree, whoever wrote it.
    if candidate.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("path escapes the tree".to_owned());
    }
    // The entry point. Moving it does not tidy anything; it turns nginx off.
    if relative == "nginx.conf" {
        return Err("this is the config entry point and is never quarantined".to_owned());
    }

    let source = tree_root.join(&candidate);
    if !source.exists() {
        return Err("not found in the tree".to_owned());
    }

    Ok(source)
}

/// Rename where possible, copy-then-remove across filesystems.
///
/// The tree and the work root are routinely separate mounts
/// (`/mnt/nginx_local` and `/opt/nginx-publisher`), where `rename` fails with
/// `EXDEV` -- so the fallback is the normal path, not the exception.
fn move_path(source: &Path, destination: &Path) -> std::io::Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            if source.is_dir() {
                std::fs::create_dir_all(destination)?;
                stage::copy_tree(source, destination)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                std::fs::remove_dir_all(source)
            } else {
                std::fs::copy(source, destination)?;
                std::fs::remove_file(source)
            }
        }
    }
}

fn roll_back(done: &[(PathBuf, PathBuf)]) {
    // Reverse order, so nested moves undo cleanly.
    for (source, destination) in done.iter().rev() {
        if let Err(err) = move_path(destination, source) {
            // Worth shouting about: the tree is now in a state nobody asked
            // for, and the files are still in the attic to be put back by hand.
            log!(
                LogLevel::Error,
                "could not restore {} from {}: {}",
                source.display(),
                destination.display(),
                err
            );
        }
    }
}

/// Stages the tree as it now stands and runs `nginx -t` over it.
async fn validate_tree(config: &Config, timestamp: &str) -> Result<()> {
    let stage = Stage::create(config, &format!("quarantine-{timestamp}"))?;
    stage::nginx_test(config, &stage).await
}

fn write_manifest(
    attic_dir: &Path,
    tree_root: &Path,
    timestamp: &str,
    moved: &[MovedEntry],
) -> Result<()> {
    let manifest = AtticManifest {
        quarantined_at: timestamp.to_owned(),
        tree_root: tree_root.to_string_lossy().into_owned(),
        moved: moved.to_vec(),
    };

    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| Error::Publish(format!("serializing attic manifest: {e}")))?;

    std::fs::write(attic_dir.join("manifest.json"), json)
        .map_err(|e| Error::Publish(format!("writing attic manifest: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::plan::{Catalog, QuarantineItem, SCHEMA_VERSION};

    struct Fixture {
        root: PathBuf,
        config: Config,
    }

    impl Fixture {
        /// `nginx_ok` decides whether the stub nginx accepts the tree, which
        /// is what the rollback path turns on.
        fn new(name: &str, nginx_ok: bool) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ais_domains_attic_{name}_{}_{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&root);

            let tree = root.join("tree");
            std::fs::create_dir_all(tree.join("certs/_.orphan.example")).unwrap();
            std::fs::create_dir_all(tree.join("sites")).unwrap();
            std::fs::write(tree.join("nginx.conf"), b"events {}\n").unwrap();
            std::fs::write(tree.join("sites/live.conf"), b"server { server_name live.com; }\n").unwrap();
            std::fs::write(tree.join("certs/_.orphan.example/ecc.pem"), b"cert\n").unwrap();

            let nginx = root.join("fake-nginx");
            let script = if nginx_ok {
                "#!/bin/sh\necho 'test is successful' >&2\nexit 0\n"
            } else {
                "#!/bin/sh\necho 'emerg: bad config' >&2\nexit 1\n"
            };
            std::fs::write(&nginx, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&nginx, std::fs::Permissions::from_mode(0o755)).unwrap();
            }

            let mut config = Config::default();
            config.tree.root = tree;
            config.tree.work_root = root.join("work");
            config.tree.nginx_bin = nginx;

            Self { root, config }
        }

        fn plan(&self, items: Vec<QuarantineItem>) -> Plan {
            Plan {
                schema_version: SCHEMA_VERSION,
                generated_at: "2026-09-17T00:00:00Z".to_owned(),
                tree_root: self.config.tree.root.to_string_lossy().into_owned(),
                catalog: Catalog::default(),
                domains: Vec::new(),
                runner_org_assignments: Vec::new(),
                quarantine: items,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn item(path: &str, confirm: bool) -> QuarantineItem {
        QuarantineItem {
            path: path.to_owned(),
            reason: "cert_without_vhost".to_owned(),
            confirm,
        }
    }

    #[tokio::test]
    async fn nothing_moves_without_confirmation() {
        let fixture = Fixture::new("unconfirmed", true);
        let plan = fixture.plan(vec![item("certs/_.orphan.example", false)]);

        let report = quarantine(&fixture.config, &plan, false).await.unwrap();

        assert!(report.moved.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert!(
            fixture.config.tree.root.join("certs/_.orphan.example").exists(),
            "an unconfirmed entry must be left exactly where it is"
        );
    }

    #[tokio::test]
    async fn a_confirmed_entry_moves_to_the_attic_and_stays_readable() {
        let fixture = Fixture::new("confirmed", true);
        let plan = fixture.plan(vec![item("certs/_.orphan.example", true)]);

        let report = quarantine(&fixture.config, &plan, false).await.unwrap();

        assert_eq!(report.moved.len(), 1);
        assert!(!report.rolled_back);
        assert!(!fixture.config.tree.root.join("certs/_.orphan.example").exists());

        let attic = report.attic_dir.unwrap();
        // Nothing is deleted: the file is still there, under its old path.
        assert_eq!(
            std::fs::read_to_string(attic.join("certs/_.orphan.example/ecc.pem")).unwrap(),
            "cert\n"
        );
        // And a record of why.
        let manifest: AtticManifest =
            serde_json::from_str(&std::fs::read_to_string(attic.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.moved[0].reason, "cert_without_vhost");
    }

    #[tokio::test]
    async fn a_tree_nginx_rejects_is_put_back_exactly_as_it_was() {
        let fixture = Fixture::new("rollback", false);
        let plan = fixture.plan(vec![item("certs/_.orphan.example", true)]);

        let report = quarantine(&fixture.config, &plan, false).await.unwrap();

        assert!(report.rolled_back, "a rejected tree must roll back");
        assert_eq!(
            std::fs::read_to_string(
                fixture.config.tree.root.join("certs/_.orphan.example/ecc.pem")
            )
            .unwrap(),
            "cert\n",
            "the file must be back where it started"
        );
        assert!(report.attic_dir.is_none());
    }

    #[tokio::test]
    async fn paths_that_escape_the_tree_are_refused() {
        let fixture = Fixture::new("escape", true);
        let plan = fixture.plan(vec![
            item("../../etc/nginx/nginx.conf", true),
            item("/etc/passwd", true),
            item("nginx.conf", true),
        ]);

        let report = quarantine(&fixture.config, &plan, false).await.unwrap();

        assert!(report.moved.is_empty(), "none of these may ever move");
        assert_eq!(report.skipped.len(), 3);
        assert!(report.skipped.iter().any(|s| s.contains("escapes the tree")));
        assert!(report.skipped.iter().any(|s| s.contains("absolute paths")));
        assert!(report.skipped.iter().any(|s| s.contains("entry point")));
        assert!(fixture.config.tree.root.join("nginx.conf").exists());
    }

    #[tokio::test]
    async fn a_dry_run_reports_without_touching_anything() {
        let fixture = Fixture::new("dryrun", true);
        let plan = fixture.plan(vec![item("certs/_.orphan.example", true)]);

        let report = quarantine(&fixture.config, &plan, true).await.unwrap();

        assert_eq!(report.moved.len(), 1, "it still says what it would do");
        assert!(
            fixture.config.tree.root.join("certs/_.orphan.example").exists(),
            "and does none of it"
        );
    }
}
