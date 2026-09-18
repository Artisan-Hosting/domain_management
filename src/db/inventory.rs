//! Queries behind the adoption surface.
//!
//! Kept apart from the gRPC handlers so the handlers stay about
//! authorization and shape, and so these can be read as what they are: the
//! answers to "what do we have, what is wrong with it, and what is still
//! unattached".

use sqlx::{MySqlPool, QueryBuilder, Row};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct InventoryRow {
    pub id: u64,
    pub fqdn: String,
    pub organization_id: Option<String>,
    pub runner_id: Option<String>,
    pub source: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub vhost_paths: Vec<String>,
    pub cert_dirs: Vec<String>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InventoryCounts {
    pub total: i64,
    pub unassigned: i64,
}

#[derive(Debug, Clone)]
pub struct FindingRow {
    pub code: String,
    pub severity: String,
    pub subject: String,
    pub message: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AdoptedVhostRow {
    pub path: String,
    pub domain_fqdn: String,
    pub server_names: Vec<String>,
    pub file_sha256: Option<String>,
}

/// A page of domains, with what each is made of.
///
/// Four queries rather than one join: a domain has many vhosts, many
/// certificates and many findings, and a single join would multiply them
/// together and need de-duplicating in Rust anyway.
pub async fn list_inventory(
    pool: &MySqlPool,
    organization_id: Option<&str>,
    unassigned_only: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<InventoryRow>> {
    let mut builder = QueryBuilder::new(
        "SELECT id, fqdn, organization_id, runner_id, source, status, UNIX_TIMESTAMP(expires_at) AS expires_at \
         FROM domains WHERE status <> 'removed'",
    );

    if let Some(organization_id) = organization_id {
        builder.push(" AND organization_id = ").push_bind(organization_id);
    }
    if unassigned_only {
        builder.push(" AND organization_id IS NULL");
    }

    builder
        .push(" ORDER BY fqdn LIMIT ")
        .push_bind(limit.clamp(1, 1000))
        .push(" OFFSET ")
        .push_bind(offset.max(0));

    let rows = builder.build().fetch_all(pool).await?;

    let mut out: Vec<InventoryRow> = rows
        .into_iter()
        .map(|row| InventoryRow {
            id: row.get("id"),
            fqdn: row.get("fqdn"),
            organization_id: row.get("organization_id"),
            runner_id: row.get("runner_id"),
            source: row.get("source"),
            status: row.get("status"),
            expires_at: row.get("expires_at"),
            vhost_paths: Vec::new(),
            cert_dirs: Vec::new(),
            findings: Vec::new(),
        })
        .collect();

    if out.is_empty() {
        return Ok(out);
    }

    let ids: Vec<u64> = out.iter().map(|row| row.id).collect();

    for (domain_id, path) in fetch_pairs(
        pool,
        "SELECT domain_id, source_path FROM vhosts WHERE source_path IS NOT NULL AND domain_id IN (",
        "source_path",
        &ids,
    )
    .await?
    {
        if let Some(row) = out.iter_mut().find(|row| row.id == domain_id) {
            row.vhost_paths.push(path);
        }
    }

    for (domain_id, _key_type) in fetch_pairs(
        pool,
        "SELECT domain_id, key_type FROM certificates WHERE domain_id IN (",
        "key_type",
        &ids,
    )
    .await?
    {
        if let Some(row) = out.iter_mut().find(|row| row.id == domain_id) {
            // One directory holds both key types, so the ecc and rsa rows
            // name the same place.
            let dir = format!("_.{}", row.fqdn);
            if !row.cert_dirs.contains(&dir) {
                row.cert_dirs.push(dir);
            }
        }
    }

    for (domain_id, code) in fetch_pairs(
        pool,
        "SELECT domain_id, code FROM inventory_findings WHERE resolved_at IS NULL AND domain_id IN (",
        "code",
        &ids,
    )
    .await?
    {
        if let Some(row) = out.iter_mut().find(|row| row.id == domain_id) {
            row.findings.push(code);
        }
    }

    Ok(out)
}

async fn fetch_pairs(
    pool: &MySqlPool,
    prefix: &str,
    column: &str,
    ids: &[u64],
) -> Result<Vec<(u64, String)>> {
    let mut builder = QueryBuilder::new(prefix);
    let mut separated = builder.separated(", ");
    for id in ids {
        separated.push_bind(*id);
    }
    builder.push(")");

    let rows = builder.build().fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(|row| (row.get::<u64, _>("domain_id"), row.get::<String, _>(column)))
        .collect())
}

pub async fn inventory_counts(pool: &MySqlPool, organization_id: Option<&str>) -> Result<InventoryCounts> {
    let mut builder = QueryBuilder::new(
        "SELECT COUNT(*) AS total, SUM(organization_id IS NULL) AS unassigned \
         FROM domains WHERE status <> 'removed'",
    );
    if let Some(organization_id) = organization_id {
        builder.push(" AND organization_id = ").push_bind(organization_id);
    }

    let row = builder.build().fetch_one(pool).await?;

    Ok(InventoryCounts {
        total: row.get::<i64, _>("total"),
        // SUM over no rows is NULL, not 0.
        unassigned: row.try_get::<Option<i64>, _>("unassigned").ok().flatten().unwrap_or(0),
    })
}

/// Looks a domain up by id or name, so callers can use whichever they have.
pub async fn find_domain(pool: &MySqlPool, id_or_fqdn: &str) -> Result<Option<InventoryRow>> {
    let row = sqlx::query(
        "SELECT id, fqdn, organization_id, runner_id, source, status, UNIX_TIMESTAMP(expires_at) AS expires_at \
         FROM domains WHERE fqdn = ? OR id = ? LIMIT 1",
    )
    .bind(id_or_fqdn)
    .bind(id_or_fqdn.parse::<u64>().unwrap_or(0))
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| InventoryRow {
        id: row.get("id"),
        fqdn: row.get("fqdn"),
        organization_id: row.get("organization_id"),
        runner_id: row.get("runner_id"),
        source: row.get("source"),
        status: row.get("status"),
        expires_at: row.get("expires_at"),
        vhost_paths: Vec::new(),
        cert_dirs: Vec::new(),
        findings: Vec::new(),
    }))
}

/// Writes an attachment. `None` leaves a field as it is; `Some(None)` clears
/// it -- the two are different intents and the caller has already told them
/// apart.
pub async fn set_assignment(
    pool: &MySqlPool,
    domain_id: u64,
    organization_id: Option<Option<String>>,
    runner_id: Option<Option<String>>,
) -> Result<()> {
    if organization_id.is_none() && runner_id.is_none() {
        return Ok(());
    }

    let mut builder = QueryBuilder::new("UPDATE domains SET ");
    let mut separated = builder.separated(", ");

    if let Some(value) = &organization_id {
        separated.push("organization_id = ");
        separated.push_bind_unseparated(value.clone());
    }
    if let Some(value) = &runner_id {
        separated.push("runner_id = ");
        separated.push_bind_unseparated(value.clone());
    }

    builder.push(" WHERE id = ").push_bind(domain_id);
    builder.build().execute(pool).await?;

    Ok(())
}

/// Records a vhost this service rendered.
///
/// `origin = 'generated'` is the difference that matters: an adopted file is
/// never rewritten, a generated one is rewritten whenever the instances
/// behind it change.
pub async fn record_generated_vhost(
    pool: &MySqlPool,
    domain_id: u64,
    runner_id: &str,
    source_path: &str,
    server_names: &[String],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO vhosts (domain_id, runner_id, origin, source_path, file_path, template) \
         VALUES (?, ?, 'generated', ?, ?, 'default') \
         ON DUPLICATE KEY UPDATE domain_id = VALUES(domain_id), runner_id = VALUES(runner_id), \
         origin = 'generated', template = VALUES(template)",
    )
    .bind(domain_id)
    .bind(runner_id)
    .bind(source_path)
    .bind(source_path)
    .execute(pool)
    .await?;

    let vhost_id: u64 = sqlx::query("SELECT id FROM vhosts WHERE source_path = ?")
        .bind(source_path)
        .fetch_one(pool)
        .await?
        .get("id");

    // Names can be removed as well as added, so the set is replaced rather
    // than merged -- a stale `www` row would claim a name nothing serves.
    sqlx::query("DELETE FROM vhost_server_names WHERE vhost_id = ?")
        .bind(vhost_id)
        .execute(pool)
        .await?;

    for name in server_names {
        sqlx::query(
            "INSERT INTO vhost_server_names (vhost_id, name, domain_id, is_wildcard) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(vhost_id)
        .bind(name)
        .bind(domain_id)
        .bind(name.starts_with("*."))
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub async fn list_findings(
    pool: &MySqlPool,
    code: Option<&str>,
    severity: Option<&str>,
    open_only: bool,
    limit: i64,
) -> Result<Vec<FindingRow>> {
    let mut builder = QueryBuilder::new(
        "SELECT code, severity, subject, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.message')), '') AS message, \
         UNIX_TIMESTAMP(first_seen) AS first_seen, UNIX_TIMESTAMP(last_seen) AS last_seen, \
         UNIX_TIMESTAMP(resolved_at) AS resolved_at \
         FROM inventory_findings WHERE 1 = 1",
    );

    if let Some(code) = code {
        builder.push(" AND code = ").push_bind(code);
    }
    if let Some(severity) = severity {
        builder.push(" AND severity = ").push_bind(severity);
    }
    if open_only {
        builder.push(" AND resolved_at IS NULL");
    }

    // Worst first: an operator opening this wants the outages, not the tidying.
    builder
        .push(" ORDER BY FIELD(severity, 'error', 'warn', 'info'), last_seen DESC LIMIT ")
        .push_bind(limit.clamp(1, 1000));

    let rows = builder.build().fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(|row| FindingRow {
            code: row.get("code"),
            severity: row.get("severity"),
            subject: row.get("subject"),
            message: row.get("message"),
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
            resolved_at: row.get("resolved_at"),
        })
        .collect())
}

pub async fn list_adopted_vhosts(
    pool: &MySqlPool,
    organization_id: Option<&str>,
) -> Result<Vec<AdoptedVhostRow>> {
    let mut builder = QueryBuilder::new(
        "SELECT v.id, v.source_path, v.file_sha256, COALESCE(d.fqdn, '') AS fqdn \
         FROM vhosts v LEFT JOIN domains d ON d.id = v.domain_id \
         WHERE v.origin = 'adopted'",
    );
    if let Some(organization_id) = organization_id {
        builder.push(" AND d.organization_id = ").push_bind(organization_id);
    }
    builder.push(" ORDER BY v.source_path");

    let rows = builder.build().fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());

    for row in rows {
        let vhost_id: u64 = row.get("id");
        let names = sqlx::query("SELECT name FROM vhost_server_names WHERE vhost_id = ? ORDER BY name")
            .bind(vhost_id)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>("name"))
            .collect();

        out.push(AdoptedVhostRow {
            path: row.try_get::<Option<String>, _>("source_path")?.unwrap_or_default(),
            domain_fqdn: row.get("fqdn"),
            server_names: names,
            file_sha256: row.get("file_sha256"),
        });
    }

    Ok(out)
}

/// Records a scan and its findings.
///
/// Findings already present have `last_seen` moved forward; ones this scan no
/// longer reproduces are marked resolved rather than deleted, so a problem
/// that keeps coming back reads as one recurring thing.
pub async fn record_scan(
    pool: &MySqlPool,
    inventory: &crate::inventory::model::Inventory,
) -> Result<i64> {
    let scan = sqlx::query(
        "INSERT INTO inventory_scans (tree_root, finished_at, file_count, server_count, cert_count, finding_count) \
         VALUES (?, NOW(), ?, ?, ?, ?)",
    )
    .bind(&inventory.tree_root)
    .bind(inventory.nginx.files.len() as i32)
    .bind(inventory.nginx.servers.len() as i32)
    .bind(inventory.certs.len() as i32)
    .bind(inventory.findings.len() as i32)
    .execute(pool)
    .await?;

    let seen: Vec<String> = inventory
        .findings
        .iter()
        .map(|finding| format!("{}|{}", finding.code.as_str(), finding.subject))
        .collect();

    for finding in &inventory.findings {
        let detail = serde_json::json!({
            "message": finding.message,
            "evidence": finding.evidence,
        });

        sqlx::query(
            "INSERT INTO inventory_findings (code, severity, subject, detail, last_seen) \
             VALUES (?, ?, ?, ?, NOW()) \
             ON DUPLICATE KEY UPDATE last_seen = NOW(), resolved_at = NULL, \
             severity = VALUES(severity), detail = VALUES(detail)",
        )
        .bind(finding.code.as_str())
        .bind(match finding.severity {
            crate::inventory::model::Severity::Error => "error",
            crate::inventory::model::Severity::Warn => "warn",
            crate::inventory::model::Severity::Info => "info",
        })
        .bind(&finding.subject)
        .bind(detail)
        .execute(pool)
        .await?;
    }

    // Close anything this scan did not reproduce.
    let open = sqlx::query("SELECT id, code, subject FROM inventory_findings WHERE resolved_at IS NULL")
        .fetch_all(pool)
        .await?;

    for row in open {
        let key = format!(
            "{}|{}",
            row.get::<String, _>("code"),
            row.get::<String, _>("subject")
        );
        if !seen.contains(&key) {
            sqlx::query("UPDATE inventory_findings SET resolved_at = NOW() WHERE id = ?")
                .bind(row.get::<u64, _>("id"))
                .execute(pool)
                .await?;
        }
    }

    Ok(scan.last_insert_id() as i64)
}
