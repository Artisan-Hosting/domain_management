//! Tracking for vhosts applied through [`crate::vhost::freeform`].
//!
//! One row per domain: a later `ApplyFreeformVhost` on the same domain
//! updates this row in place, the same way the file itself is updated in
//! place rather than duplicated.

use sqlx::{MySqlPool, Row};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct FreeformVhostRow {
    pub domain_id: u64,
    pub source_path: String,
    pub body: String,
    pub sha256: String,
    pub applied_by: Option<String>,
}

/// Records (or updates) what was applied for a domain.
pub async fn record_apply(
    pool: &MySqlPool,
    domain_id: u64,
    source_path: &str,
    body: &str,
    sha256: &str,
    applied_by: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO freeform_vhosts (domain_id, source_path, body, sha256, applied_by) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE source_path = VALUES(source_path), body = VALUES(body), \
         sha256 = VALUES(sha256), applied_by = VALUES(applied_by)",
    )
    .bind(domain_id)
    .bind(source_path)
    .bind(body)
    .bind(sha256)
    .bind(applied_by)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn find_by_domain(pool: &MySqlPool, domain_id: u64) -> Result<Option<FreeformVhostRow>> {
    let row = sqlx::query(
        "SELECT domain_id, source_path, body, sha256, applied_by FROM freeform_vhosts WHERE domain_id = ?",
    )
    .bind(domain_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| FreeformVhostRow {
        domain_id: row.get("domain_id"),
        source_path: row.get("source_path"),
        body: row.get("body"),
        sha256: row.get("sha256"),
        applied_by: row.get("applied_by"),
    }))
}
