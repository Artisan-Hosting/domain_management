//! Lifecycle writes and reads against the `domains` table itself, distinct
//! from the adoption/scan-focused `crate::db::inventory` (which reads
//! existing rows back out with their vhosts/certs/findings joined in for the
//! migration-era adoption surface) and the purchasing-focused
//! `crate::db::orders`.
//!
//! Started with just what the `register` job needed; Phase 7's
//! `GetDomain`/`ListDomains`/`AddDomain`/etc. grew it rather than duplicate
//! it, per this module's original doc note.

use sqlx::{MySqlPool, QueryBuilder, Row};

use crate::error::Result;

/// Every column a full `Domain` proto response can be built from, plus
/// `has_vhost` -- a single boolean rather than making every caller run its
/// own subquery.
#[derive(Debug, Clone)]
pub struct DomainRow {
    pub id: u64,
    pub fqdn: String,
    pub organization_id: Option<String>,
    pub runner_id: Option<String>,
    pub source: String,
    pub status: String,
    pub cf_zone_id: Option<String>,
    pub challenge_target: String,
    pub expires_at: Option<i64>,
    pub auto_renew: bool,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub ownership_token: Option<String>,
    pub ownership_verified: bool,
    pub has_vhost: bool,
}

const SELECT_DOMAIN: &str = "SELECT id, fqdn, organization_id, runner_id, source, status, cf_zone_id, \
     challenge_target, UNIX_TIMESTAMP(expires_at) AS expires_at, auto_renew, last_error, \
     UNIX_TIMESTAMP(created_at) AS created_at, UNIX_TIMESTAMP(updated_at) AS updated_at, \
     ownership_token, ownership_verified, \
     (SELECT COUNT(*) FROM vhosts v WHERE v.domain_id = domains.id) > 0 AS has_vhost \
     FROM domains";

fn row_to_domain(row: sqlx::mysql::MySqlRow) -> DomainRow {
    DomainRow {
        id: row.get("id"),
        fqdn: row.get("fqdn"),
        organization_id: row.get("organization_id"),
        runner_id: row.get("runner_id"),
        source: row.get("source"),
        status: row.get("status"),
        cf_zone_id: row.get("cf_zone_id"),
        challenge_target: row.get("challenge_target"),
        expires_at: row.get("expires_at"),
        auto_renew: row.get("auto_renew"),
        last_error: row.get("last_error"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        ownership_token: row.get("ownership_token"),
        ownership_verified: row.get("ownership_verified"),
        has_vhost: row.get("has_vhost"),
    }
}

pub async fn find_full(pool: &MySqlPool, id: u64) -> Result<Option<DomainRow>> {
    let row = sqlx::query(&format!("{SELECT_DOMAIN} WHERE id = ?")).bind(id).fetch_optional(pool).await?;
    Ok(row.map(row_to_domain))
}

/// Looks a domain up by id or name, same convention as
/// `inventory::find_domain`, but returning every field a full `Domain`
/// response needs rather than the lighter adoption-surface row.
pub async fn find_full_by_id_or_fqdn(pool: &MySqlPool, id_or_fqdn: &str) -> Result<Option<DomainRow>> {
    let row = sqlx::query(&format!("{SELECT_DOMAIN} WHERE fqdn = ? OR id = ? LIMIT 1"))
        .bind(id_or_fqdn)
        .bind(id_or_fqdn.parse::<u64>().unwrap_or(0))
        .fetch_optional(pool)
        .await?;
    Ok(row.map(row_to_domain))
}

/// A page of domains for `ListDomains` -- filtered by organization (via
/// `authz::scope`), optionally by runner and status.
pub async fn list(
    pool: &MySqlPool,
    organization_id: Option<&str>,
    runner_id: Option<&str>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<DomainRow>> {
    let mut builder = QueryBuilder::new(format!("{SELECT_DOMAIN} WHERE status <> 'removed'"));

    if let Some(organization_id) = organization_id {
        builder.push(" AND organization_id = ").push_bind(organization_id);
    }
    if let Some(runner_id) = runner_id {
        builder.push(" AND runner_id = ").push_bind(runner_id);
    }
    if let Some(status) = status {
        builder.push(" AND status = ").push_bind(status);
    }

    builder
        .push(" ORDER BY fqdn LIMIT ")
        .push_bind(limit.clamp(1, 1000))
        .push(" OFFSET ")
        .push_bind(offset.max(0));

    let rows = builder.build().fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_domain).collect())
}

/// Records a BYO domain a caller has just claimed. Ownership is not yet
/// proven -- `status` starts at `pending_dns` and stays there until
/// `VerifyDomainNow` confirms the `_ais-domains-verify` TXT token below.
pub async fn insert_byo(
    pool: &MySqlPool,
    fqdn: &str,
    organization_id: &str,
    runner_id: &str,
    ownership_token: &str,
    challenge_target: &str,
) -> Result<u64> {
    let runner_id = (!runner_id.is_empty()).then_some(runner_id);

    let result = sqlx::query(
        "INSERT INTO domains (fqdn, organization_id, runner_id, source, status, challenge_target, \
         auto_renew, ownership_token, ownership_verified) \
         VALUES (?, ?, ?, 'byo', 'pending_dns', ?, 1, ?, 0)",
    )
    .bind(fqdn)
    .bind(organization_id)
    .bind(runner_id)
    .bind(challenge_target)
    .bind(ownership_token)
    .execute(pool)
    .await?;

    Ok(result.last_insert_id())
}

pub async fn mark_ownership_verified(pool: &MySqlPool, id: u64) -> Result<()> {
    sqlx::query("UPDATE domains SET ownership_verified = 1 WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

pub async fn set_status(pool: &MySqlPool, id: u64, status: &str, last_error: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE domains SET status = ?, last_error = ? WHERE id = ?")
        .bind(status)
        .bind(last_error)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Records a probe result without moving `status` -- `VerifyDomainNow`
/// against a domain that still isn't pointed at us correctly.
pub async fn set_last_error(pool: &MySqlPool, id: u64, last_error: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE domains SET last_error = ? WHERE id = ?").bind(last_error).bind(id).execute(pool).await?;
    Ok(())
}

/// `RemoveDomain`'s soft delete -- matches the existing convention every
/// listing query already filters on (`status <> 'removed'`), so a removed
/// domain disappears from every read surface without losing its history or
/// freeing its `fqdn` for someone else to race for.
pub async fn soft_delete(pool: &MySqlPool, id: u64) -> Result<()> {
    sqlx::query("UPDATE domains SET status = 'removed' WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

/// Records a domain this service just registered on the caller's behalf.
///
/// `ON DUPLICATE KEY UPDATE id = id` on the unique `fqdn` key: the
/// `register` job re-reads its order and can re-enter this step after a
/// partial failure (a crash between inserting the domain and marking the
/// order `completed`, say), and a second insert for the same `fqdn` must
/// return the existing row rather than erroring or creating a duplicate.
pub async fn insert_purchased(
    pool: &MySqlPool,
    fqdn: &str,
    organization_id: &str,
    cf_zone_id: &str,
    challenge_target: &str,
) -> Result<u64> {
    sqlx::query(
        "INSERT INTO domains (fqdn, organization_id, source, status, cf_zone_id, challenge_target, auto_renew) \
         VALUES (?, ?, 'purchased', 'issuing', ?, ?, 1) \
         ON DUPLICATE KEY UPDATE id = id",
    )
    .bind(fqdn)
    .bind(organization_id)
    .bind(cf_zone_id)
    .bind(challenge_target)
    .execute(pool)
    .await?;

    let id: u64 = sqlx::query("SELECT id FROM domains WHERE fqdn = ?").bind(fqdn).fetch_one(pool).await?.get("id");

    Ok(id)
}

pub async fn mark_active(pool: &MySqlPool, domain_id: u64) -> Result<()> {
    sqlx::query("UPDATE domains SET status = 'active' WHERE id = ?").bind(domain_id).execute(pool).await?;
    Ok(())
}

/// The minimal shape `WatchDomain` polls on: enough to notice a status
/// change and describe it, nothing a listing would need.
#[derive(Debug, Clone)]
pub struct StatusRow {
    pub id: u64,
    pub fqdn: String,
    pub organization_id: Option<String>,
    pub status: String,
    pub last_error: Option<String>,
}

/// One domain (`only_id`) or every domain in scope (`organization_id`,
/// `None` for every organization -- `Super` only), re-run on every tick so a
/// mid-stream reassignment changes what comes back on the very next poll.
pub async fn poll_statuses(
    pool: &MySqlPool,
    only_id: Option<u64>,
    organization_id: Option<&str>,
) -> Result<Vec<StatusRow>> {
    let mut builder = QueryBuilder::new(
        "SELECT id, fqdn, organization_id, status, last_error FROM domains WHERE status <> 'removed'",
    );
    if let Some(id) = only_id {
        builder.push(" AND id = ").push_bind(id);
    }
    if let Some(organization_id) = organization_id {
        builder.push(" AND organization_id = ").push_bind(organization_id);
    }
    builder.push(" ORDER BY id");

    let rows = builder.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| StatusRow {
            id: row.get("id"),
            fqdn: row.get("fqdn"),
            organization_id: row.get("organization_id"),
            status: row.get("status"),
            last_error: row.get("last_error"),
        })
        .collect())
}

/// A certificate row, read back for `GetDomain`'s detail view and
/// `ListCertificates`.
#[derive(Debug, Clone)]
pub struct CertRow {
    pub key_type: String,
    pub serial: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub renew_after: Option<i64>,
    pub fail_count: i32,
    pub last_error: Option<String>,
}

const SELECT_CERT: &str = "key_type, serial, UNIX_TIMESTAMP(not_before) AS not_before, \
     UNIX_TIMESTAMP(not_after) AS not_after, UNIX_TIMESTAMP(renew_after) AS renew_after, \
     fail_count, last_error";

fn row_to_cert(row: sqlx::mysql::MySqlRow) -> CertRow {
    CertRow {
        key_type: row.get("key_type"),
        serial: row.get("serial"),
        not_before: row.get("not_before"),
        not_after: row.get("not_after"),
        renew_after: row.get("renew_after"),
        fail_count: row.get("fail_count"),
        last_error: row.get("last_error"),
    }
}

pub async fn certificates_for(pool: &MySqlPool, domain_id: u64) -> Result<Vec<CertRow>> {
    let rows = sqlx::query(&format!("SELECT {SELECT_CERT} FROM certificates WHERE domain_id = ?"))
        .bind(domain_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(row_to_cert).collect())
}

/// Every certificate across an organization (or the whole fleet, for
/// `Super`), optionally filtered to those expiring soon -- `ListCertificates`.
pub async fn list_certificates(
    pool: &MySqlPool,
    organization_id: Option<&str>,
    expiring_within_days: i32,
) -> Result<Vec<(u64, CertRow)>> {
    let mut builder = QueryBuilder::new(format!(
        "SELECT c.domain_id, {SELECT_CERT} FROM certificates c \
         JOIN domains d ON d.id = c.domain_id WHERE d.status <> 'removed'"
    ));
    if let Some(organization_id) = organization_id {
        builder.push(" AND d.organization_id = ").push_bind(organization_id);
    }
    if expiring_within_days > 0 {
        builder
            .push(" AND c.not_after IS NOT NULL AND c.not_after <= DATE_ADD(NOW(), INTERVAL ")
            .push_bind(expiring_within_days)
            .push(" DAY)");
    }
    builder.push(" ORDER BY c.not_after");

    let rows = builder.build().fetch_all(pool).await?;
    Ok(rows.into_iter().map(|row| (row.get::<u64, _>("domain_id"), row_to_cert(row))).collect())
}

/// Records (or refreshes) one key type's certificate metadata after an
/// issuance -- the same `ON DUPLICATE KEY UPDATE` idempotency every other
/// write in this service uses, since `ForceRenew`/`VerifyDomainNow` can both
/// re-enter this step on a retry.
pub async fn record_certificate(
    pool: &MySqlPool,
    domain_id: u64,
    key_type: &str,
    not_after: i64,
    renew_after: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO certificates (domain_id, key_type, not_after, renew_after, issued_at) \
         VALUES (?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), NOW()) \
         ON DUPLICATE KEY UPDATE not_after = VALUES(not_after), renew_after = VALUES(renew_after), \
         issued_at = NOW()",
    )
    .bind(domain_id)
    .bind(key_type)
    .bind(not_after)
    .bind(renew_after)
    .execute(pool)
    .await?;
    Ok(())
}

/// How long ago this domain last had a certificate issued, if ever --
/// `ForceRenew`'s cooldown, independent of its caller's own `force` intent:
/// Let's Encrypt's rate limit is shared across every tenant on this
/// service, so even a legitimate forced renewal must not be spammable.
pub async fn seconds_since_last_issuance(pool: &MySqlPool, domain_id: u64) -> Result<Option<i64>> {
    let row = sqlx::query(
        "SELECT TIMESTAMPDIFF(SECOND, MAX(issued_at), NOW()) AS age FROM certificates \
         WHERE domain_id = ? AND issued_at IS NOT NULL",
    )
    .bind(domain_id)
    .fetch_one(pool)
    .await?;
    Ok(row.try_get::<Option<i64>, _>("age").ok().flatten())
}

/// A record this service manages for a domain (edge A/AAAA, the challenge
/// CNAME) -- `GetDomain`'s detail view.
#[derive(Debug, Clone)]
pub struct ManagedRecordRow {
    pub purpose: String,
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub cf_record_id: Option<String>,
    pub drifted: bool,
}

pub async fn managed_records_for(pool: &MySqlPool, domain_id: u64) -> Result<Vec<ManagedRecordRow>> {
    let rows = sqlx::query(
        "SELECT purpose, record_type, name, content, cf_record_id, drifted FROM managed_dns_records \
         WHERE domain_id = ?",
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ManagedRecordRow {
            purpose: row.get("purpose"),
            record_type: row.get("record_type"),
            name: row.get("name"),
            content: row.get("content"),
            cf_record_id: row.get("cf_record_id"),
            drifted: row.get("drifted"),
        })
        .collect())
}
