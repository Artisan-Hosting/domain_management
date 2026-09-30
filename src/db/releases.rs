//! Records of what `PublishNow` produced.
//!
//! `publish::publish()` itself stays deliberately DB-free (see its own doc
//! comment) -- this is where the RPC handler records a release after the
//! fact, the same split `ais_domains.json`'s CLI `publish` command and the
//! gRPC `PublishNow` RPC share: one function does the work, the caller
//! decides whether it's worth a database row.

use sqlx::{MySqlPool, Row};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ReleaseRow {
    pub release_id: String,
    pub file_count: i32,
    pub manifest_sha256: Option<String>,
    pub status: String,
    pub created_at: i64,
}

pub async fn record(
    pool: &MySqlPool,
    release_id: &str,
    file_count: i32,
    manifest_sha256: &str,
    status: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO releases (release_id, file_count, manifest_sha256, status) VALUES (?, ?, ?, ?)")
        .bind(release_id)
        .bind(file_count)
        .bind(manifest_sha256)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list(pool: &MySqlPool, limit: i64) -> Result<Vec<ReleaseRow>> {
    let rows = sqlx::query(
        "SELECT release_id, file_count, manifest_sha256, status, UNIX_TIMESTAMP(created_at) AS created_at \
         FROM releases ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ReleaseRow {
            release_id: row.get("release_id"),
            file_count: row.get("file_count"),
            manifest_sha256: row.get("manifest_sha256"),
            status: row.get("status"),
            created_at: row.get("created_at"),
        })
        .collect())
}
