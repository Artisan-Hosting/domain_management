//! Queries behind the caller-facing DNS record CRUD surface
//! (`ListDnsRecords` / `CreateDnsRecord` / `UpdateDnsRecord` /
//! `DeleteDnsRecord`).
//!
//! This table is a local index of what a caller created through the API --
//! Cloudflare stays authoritative for the record's actual content. Kept
//! apart from `crate::db::inventory`, which is the adoption/scan surface,
//! not the lifecycle CRUD one.

use sqlx::{MySqlPool, Row};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct DnsRecordRow {
    pub id: u64,
    pub domain_id: u64,
    pub cf_record_id: String,
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
}

/// The zone a domain's records live in, if it has one. `None` for a domain
/// with no Cloudflare zone yet -- a BYO domain still on another registrar's
/// DNS, or one still mid-purchase.
pub async fn zone_id_for(pool: &MySqlPool, domain_id: u64) -> Result<Option<String>> {
    let row = sqlx::query("SELECT cf_zone_id FROM domains WHERE id = ?")
        .bind(domain_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.and_then(|row| row.get::<Option<String>, _>("cf_zone_id")))
}

pub async fn list(pool: &MySqlPool, domain_id: u64) -> Result<Vec<DnsRecordRow>> {
    let rows = sqlx::query(
        "SELECT id, domain_id, cf_record_id, record_type, name, content, ttl, proxied \
         FROM domain_dns_records WHERE domain_id = ? ORDER BY id",
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(row_to_entry).collect())
}

pub async fn find(pool: &MySqlPool, domain_id: u64, id: u64) -> Result<Option<DnsRecordRow>> {
    let row = sqlx::query(
        "SELECT id, domain_id, cf_record_id, record_type, name, content, ttl, proxied \
         FROM domain_dns_records WHERE domain_id = ? AND id = ?",
    )
    .bind(domain_id)
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(row_to_entry))
}

/// Records a record this service created on the caller's behalf.
pub async fn record_created(
    pool: &MySqlPool,
    domain_id: u64,
    cf_record_id: &str,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: bool,
    created_by: Option<&str>,
) -> Result<u64> {
    sqlx::query(
        "INSERT INTO domain_dns_records \
         (domain_id, cf_record_id, record_type, name, content, ttl, proxied, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(domain_id)
    .bind(cf_record_id)
    .bind(record_type)
    .bind(name)
    .bind(content)
    .bind(ttl)
    .bind(proxied)
    .bind(created_by)
    .execute(pool)
    .await?;

    let id: u64 = sqlx::query("SELECT id FROM domain_dns_records WHERE domain_id = ? AND cf_record_id = ?")
        .bind(domain_id)
        .bind(cf_record_id)
        .fetch_one(pool)
        .await?
        .get("id");

    Ok(id)
}

/// Reflects a Cloudflare update back onto the local row -- everything but
/// the identity columns (`domain_id`, `cf_record_id`) can change.
pub async fn record_updated(
    pool: &MySqlPool,
    id: u64,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: bool,
) -> Result<()> {
    sqlx::query(
        "UPDATE domain_dns_records SET record_type = ?, name = ?, content = ?, ttl = ?, proxied = ? \
         WHERE id = ?",
    )
    .bind(record_type)
    .bind(name)
    .bind(content)
    .bind(ttl)
    .bind(proxied)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete(pool: &MySqlPool, id: u64) -> Result<()> {
    sqlx::query("DELETE FROM domain_dns_records WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

fn row_to_entry(row: sqlx::mysql::MySqlRow) -> DnsRecordRow {
    DnsRecordRow {
        id: row.get("id"),
        domain_id: row.get("domain_id"),
        cf_record_id: row.get("cf_record_id"),
        record_type: row.get("record_type"),
        name: row.get("name"),
        content: row.get("content"),
        ttl: row.get("ttl"),
        proxied: row.get("proxied"),
    }
}
