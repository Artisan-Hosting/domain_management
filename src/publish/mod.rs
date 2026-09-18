//! Publishing a release -- what `legacy/issuer` did, minus the GCS half.
//!
//! Order matters and is the whole reason this is one function:
//!
//! 1. snapshot the tree,
//! 2. `nginx -t` the snapshot,
//! 3. hash it into a manifest,
//! 4. upload the files, then the manifest,
//! 5. **and only then** move the `latest` pointer.
//!
//! An edge that reads `latest` mid-publish must never find an id whose files
//! are not all there yet, which is why the pointer is written last and is the
//! only write that makes a release live.

pub mod manifest;
pub mod r2;
pub mod stage;

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;

use crate::config::{Config, Secrets};
use crate::error::Result;
use manifest::Manifest;
use stage::Stage;

pub struct PublishOutcome {
    pub release_id: String,
    pub file_count: usize,
    pub manifest_sha256: String,
    /// False for a dry run, or in shadow mode -- in both cases the edges keep
    /// serving whatever they already have.
    pub published: bool,
}

/// Stages, validates, and (unless `dry_run`) publishes the tree.
pub async fn publish(config: &Config, secrets: &Secrets, dry_run: bool) -> Result<PublishOutcome> {
    let release_id = manifest::release_id(chrono::Utc::now());
    log!(LogLevel::Info, "release {release_id}: staging {}", config.tree.root.display());

    let stage = Stage::create(config, &release_id)?;
    stage::nginx_test(config, &stage).await?;

    let created_unix = chrono::Utc::now().timestamp();
    let manifest = Manifest::build(&stage.tree, &release_id, created_unix)?;
    let manifest_json = manifest.to_json()?;
    let manifest_sha256 = manifest.sha256()?;

    log!(
        LogLevel::Info,
        "release {release_id}: {} file(s), manifest {}",
        manifest.file_count,
        &manifest_sha256[..12]
    );

    if dry_run {
        return Ok(PublishOutcome {
            release_id,
            file_count: manifest.file_count,
            manifest_sha256,
            published: false,
        });
    }

    let r2 = r2::R2::new(config, secrets)?;

    for entry in &manifest.files {
        let key = r2.keys.tree_file(&release_id, &entry.path);
        r2.put_file(&key, &stage.tree.join(&entry.path)).await?;
    }

    r2.put_string(&r2.keys.manifest(&release_id), &manifest_json, "application/json")
        .await?;

    if config.publish.shadow_mode {
        // Phase 1 runs beside the existing Go publisher: the files and
        // manifest go up so they can be diffed against the real ones, but the
        // pointer is left alone, so no edge acts on this release.
        log!(
            LogLevel::Warn,
            "release {release_id}: shadow mode, leaving the `latest` pointer untouched"
        );
        return Ok(PublishOutcome {
            release_id,
            file_count: manifest.file_count,
            manifest_sha256,
            published: false,
        });
    }

    // The pointer is the commit. Everything above this line is reversible by
    // doing nothing.
    r2.put_string(&r2.keys.latest(), &release_id, "text/plain").await?;
    log!(LogLevel::Info, "release {release_id}: published");

    prune(config, &r2, &release_id).await;

    Ok(PublishOutcome {
        release_id,
        file_count: manifest.file_count,
        manifest_sha256,
        published: true,
    })
}

/// Drops the oldest releases beyond `publish.keep_releases`.
///
/// Best-effort: a bucket with a few extra releases costs pennies, while a
/// failed publish because cleanup errored would cost an outage. The release
/// just published is never a candidate.
async fn prune(config: &Config, r2: &r2::R2, current: &str) {
    let keep = config.publish.keep_releases.max(1);

    let ids = match r2.list_release_ids().await {
        Ok(ids) => ids,
        Err(err) => {
            log!(LogLevel::Warn, "could not list releases to prune: {}", err);
            return;
        }
    };

    if ids.len() <= keep {
        return;
    }

    for id in ids.iter().take(ids.len() - keep) {
        if id == current {
            continue;
        }
        match r2.delete_release(id).await {
            Ok(count) => log!(LogLevel::Info, "pruned release {id} ({count} object(s))"),
            Err(err) => log!(LogLevel::Warn, "could not prune release {id}: {}", err),
        }
    }
}
