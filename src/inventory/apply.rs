//! Turning a reviewed plan into rows.
//!
//! Three properties this is built around:
//!
//! * **Idempotent.** Applying the same plan twice changes nothing the second
//!   time. Everything compares before it writes, so re-running after fixing
//!   one line is normal, not dangerous.
//! * **Never silently reassigns.** A domain already attached to an
//!   organization is left alone and reported, unless `--force-reassign` says
//!   otherwise. A stale plan file on someone's laptop must not be able to
//!   move a customer's domain to another tenant.
//! * **Adoption does not trigger issuance.** Certificates are recorded with
//!   the expiry read off disk, so a hundred adopted domains do not become a
//!   hundred ACME orders the moment the renewal scan next runs.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use sqlx::{MySqlPool, Row};

use super::plan::{Action, Plan, PlanDomain};
use crate::auth::{AuthClient, Credentials};
use crate::config::Config;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Work out every change and print it, write nothing.
    pub dry_run: bool,
    /// Allow moving a domain that already belongs to an organization.
    pub force_reassign: bool,
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub vhosts_adopted: usize,
    pub certs_recorded: usize,
    pub findings_recorded: usize,
    pub runner_assignments: usize,
    /// Every change, in the order made -- the body of a `--dry-run`.
    pub changes: Vec<String>,
    /// Things deliberately not done, and why.
    pub conflicts: Vec<String>,
}

impl ApplyReport {
    pub fn summary(&self) -> String {
        format!(
            "{} created, {} updated, {} unchanged, {} skipped\n\
             {} vhost(s) adopted, {} certificate(s) recorded, {} finding(s) carried over\n\
             {} runner org assignment(s)\n\
             {} conflict(s)",
            self.created,
            self.updated,
            self.unchanged,
            self.skipped,
            self.vhosts_adopted,
            self.certs_recorded,
            self.findings_recorded,
            self.runner_assignments,
            self.conflicts.len(),
        )
    }
}

/// What the plan says a domain row should look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredDomain {
    pub fqdn: String,
    pub organization_id: Option<String>,
    pub runner_id: Option<String>,
    pub challenge_target: String,
    pub status: &'static str,
}

/// What is in the database now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingDomain {
    pub id: u64,
    pub organization_id: Option<String>,
    pub runner_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainDecision {
    Insert,
    /// Field-level description of what changes, for the dry run.
    Update(Vec<String>),
    Unchanged,
    /// Deliberately not done.
    Conflict(String),
}

/// The whole reassignment policy, in one place and free of I/O so it can be
/// tested properly.
pub fn decide_domain(
    existing: Option<&ExistingDomain>,
    desired: &DesiredDomain,
    force_reassign: bool,
) -> DomainDecision {
    let Some(existing) = existing else {
        return DomainDecision::Insert;
    };

    let mut changes = Vec::new();

    match (&existing.organization_id, &desired.organization_id) {
        // Attaching something unassigned: the ordinary case, and the whole
        // point of the exercise.
        (None, Some(new)) => changes.push(format!("organization_id: none -> {new}")),

        (Some(current), Some(new)) if current != new => {
            if !force_reassign {
                return DomainDecision::Conflict(format!(
                    "{} is already in org {current}; the plan says {new}. Re-run with --force-reassign if that is intended.",
                    desired.fqdn
                ));
            }
            changes.push(format!("organization_id: {current} -> {new} (forced)"));
        }

        // The plan leaving a field null never clears an existing assignment;
        // "I did not fill this in" is not "remove what is there".
        _ => {}
    }

    match (&existing.runner_id, &desired.runner_id) {
        (None, Some(new)) => changes.push(format!("runner_id: none -> {new}")),
        (Some(current), Some(new)) if current != new => {
            if !force_reassign {
                return DomainDecision::Conflict(format!(
                    "{} is already attached to runner {current}; the plan says {new}.",
                    desired.fqdn
                ));
            }
            changes.push(format!("runner_id: {current} -> {new} (forced)"));
        }
        _ => {}
    }

    if existing.status != desired.status {
        changes.push(format!("status: {} -> {}", existing.status, desired.status));
    }

    if changes.is_empty() {
        DomainDecision::Unchanged
    } else {
        DomainDecision::Update(changes)
    }
}

/// Status a freshly adopted domain lands in.
///
/// Adoption describes what is already true: something with a certificate and
/// a vhost is serving traffic right now and is `active`, whatever this
/// service did or did not do to get it there.
pub fn adopted_status(domain: &PlanDomain) -> &'static str {
    if !domain.certs.is_empty() && !domain.vhosts.is_empty() {
        "active"
    } else if !domain.certs.is_empty() {
        // A certificate but nothing serving it: real, but not in service.
        "provisioning_dns"
    } else {
        "pending_dns"
    }
}

pub async fn apply(
    pool: &MySqlPool,
    config: &Config,
    plan: &Plan,
    auth: Option<(&AuthClient, &Credentials)>,
    options: &ApplyOptions,
) -> Result<ApplyReport> {
    let mut report = ApplyReport::default();

    for domain in &plan.domains {
        if domain.action == Action::Skip {
            report.skipped += 1;
            continue;
        }

        let desired = DesiredDomain {
            fqdn: domain.fqdn.clone(),
            organization_id: domain.assign.organization_id.clone(),
            runner_id: domain.assign.runner_id.clone(),
            // Everything adopted is already CNAME'd at the shared alias the
            // acme.sh era used; per-domain targets are for new domains only,
            // and changing an existing one would break its next renewal.
            challenge_target: config.acme.legacy_challenge_target.clone(),
            status: adopted_status(domain),
        };

        let existing = fetch_domain(pool, &domain.fqdn).await?;
        let decision = decide_domain(existing.as_ref(), &desired, options.force_reassign);

        let domain_id = match decision {
            DomainDecision::Conflict(message) => {
                report.conflicts.push(message);
                continue;
            }
            DomainDecision::Insert => {
                report.created += 1;
                report.changes.push(format!("create {}", domain.fqdn));
                if options.dry_run {
                    continue;
                }
                insert_domain(pool, &desired).await?
            }
            DomainDecision::Update(changes) => {
                report.updated += 1;
                for change in &changes {
                    report.changes.push(format!("{}: {change}", domain.fqdn));
                }
                let id = existing.as_ref().map(|e| e.id).unwrap_or_default();
                if options.dry_run {
                    continue;
                }
                update_domain(pool, id, &desired).await?;
                id
            }
            DomainDecision::Unchanged => {
                report.unchanged += 1;
                existing.as_ref().map(|e| e.id).unwrap_or_default()
            }
        };

        if options.dry_run {
            continue;
        }

        for cert in &domain.certs {
            if record_certificate(pool, domain_id, cert, config.acme.renew_before_days).await? {
                report.certs_recorded += 1;
            }
        }

        for vhost in domain.vhosts.iter().filter(|v| v.adopt) {
            if record_vhost(pool, domain_id, vhost).await? {
                report.vhosts_adopted += 1;
            }
        }

        for code in &domain.findings {
            record_finding(pool, domain_id, code, &domain.fqdn).await?;
            report.findings_recorded += 1;
        }
    }

    apply_runner_assignments(plan, auth, options, &mut report).await;

    Ok(report)
}

async fn apply_runner_assignments(
    plan: &Plan,
    auth: Option<(&AuthClient, &Credentials)>,
    options: &ApplyOptions,
    report: &mut ApplyReport,
) {
    let wanted: Vec<_> = plan.runner_org_assignments.iter().filter(|a| a.apply).collect();
    if wanted.is_empty() {
        return;
    }

    let Some((client, credentials)) = auth else {
        report.conflicts.push(format!(
            "{} runner org assignment(s) skipped: no ais_auth credentials were provided",
            wanted.len()
        ));
        return;
    };

    // Writing to another service's table costs a password, every time.
    let Some(elevated) = credentials.elevated_token.as_ref() else {
        report.conflicts.push(format!(
            "{} runner org assignment(s) skipped: they write to ais_auth and need an elevated token",
            wanted.len()
        ));
        return;
    };

    for assignment in wanted {
        report.changes.push(format!(
            "runner {} -> org {}",
            assignment.runner_id, assignment.organization_id
        ));

        if options.dry_run {
            report.runner_assignments += 1;
            continue;
        }

        match client
            .assign_runner_org(elevated, &assignment.runner_id, &assignment.organization_id)
            .await
        {
            Ok(true) => report.runner_assignments += 1,
            Ok(false) => report.conflicts.push(format!(
                "ais_auth declined to assign runner {} to org {}",
                assignment.runner_id, assignment.organization_id
            )),
            Err(err) => report.conflicts.push(format!(
                "assigning runner {} to org {} failed: {err}",
                assignment.runner_id, assignment.organization_id
            )),
        }
    }
}

// --- the SQL ------------------------------------------------------------
//
// Runtime queries rather than the compile-time macros, matching ais_auth:
// this crate has to build without a live database to point `sqlx` at.

async fn fetch_domain(pool: &MySqlPool, fqdn: &str) -> Result<Option<ExistingDomain>> {
    let row = sqlx::query("SELECT id, organization_id, runner_id, status FROM domains WHERE fqdn = ?")
        .bind(fqdn)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|row| ExistingDomain {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        runner_id: row.get("runner_id"),
        status: row.get("status"),
    }))
}

async fn insert_domain(pool: &MySqlPool, desired: &DesiredDomain) -> Result<u64> {
    let result = sqlx::query(
        "INSERT INTO domains (fqdn, organization_id, runner_id, source, status, challenge_target) \
         VALUES (?, ?, ?, 'imported', ?, ?)",
    )
    .bind(&desired.fqdn)
    .bind(&desired.organization_id)
    .bind(&desired.runner_id)
    .bind(desired.status)
    .bind(&desired.challenge_target)
    .execute(pool)
    .await?;

    Ok(result.last_insert_id())
}

async fn update_domain(pool: &MySqlPool, id: u64, desired: &DesiredDomain) -> Result<()> {
    // COALESCE so a null in the plan leaves what is already there alone.
    sqlx::query(
        "UPDATE domains SET organization_id = COALESCE(?, organization_id), runner_id = COALESCE(?, runner_id), \
         status = ? WHERE id = ?",
    )
    .bind(&desired.organization_id)
    .bind(&desired.runner_id)
    .bind(desired.status)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

async fn record_certificate(
    pool: &MySqlPool,
    domain_id: u64,
    cert: &super::plan::PlanCert,
    renew_before_days: i64,
) -> Result<bool> {
    let not_after = chrono::DateTime::parse_from_rfc3339(&cert.not_after)
        .map_err(|e| Error::Invalid(format!("certificate not_after {:?}: {e}", cert.not_after)))?
        .timestamp();
    let renew_after = not_after - renew_before_days * 86_400;

    // The expiry comes from the certificate already on disk, so the renewal
    // scan sees a healthy certificate and leaves it alone until it is
    // genuinely near expiry.
    sqlx::query(
        "INSERT INTO certificates (domain_id, key_type, not_after, renew_after, issued_at) \
         VALUES (?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), NULL) \
         ON DUPLICATE KEY UPDATE not_after = VALUES(not_after), renew_after = VALUES(renew_after)",
    )
    .bind(domain_id)
    .bind(&cert.key_type)
    .bind(not_after)
    .bind(renew_after)
    .execute(pool)
    .await?;

    Ok(true)
}

async fn record_vhost(
    pool: &MySqlPool,
    domain_id: u64,
    vhost: &super::plan::PlanVhost,
) -> Result<bool> {
    // `origin = 'adopted'` is what stops this file ever being rewritten.
    let result = sqlx::query(
        "INSERT INTO vhosts (domain_id, origin, source_path, file_sha256, file_path, adopted_at) \
         VALUES (?, 'adopted', ?, ?, ?, NOW()) \
         ON DUPLICATE KEY UPDATE domain_id = VALUES(domain_id), file_sha256 = VALUES(file_sha256)",
    )
    .bind(domain_id)
    .bind(&vhost.path)
    .bind(&vhost.sha256)
    .bind(&vhost.path)
    .execute(pool)
    .await?;

    let vhost_id = if result.last_insert_id() > 0 {
        result.last_insert_id()
    } else {
        sqlx::query("SELECT id FROM vhosts WHERE source_path = ?")
            .bind(&vhost.path)
            .fetch_one(pool)
            .await?
            .get::<u64, _>("id")
    };

    for name in &vhost.server_names {
        sqlx::query(
            "INSERT INTO vhost_server_names (vhost_id, name, domain_id, is_wildcard) \
             VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE domain_id = VALUES(domain_id)",
        )
        .bind(vhost_id)
        .bind(name)
        .bind(domain_id)
        .bind(name.starts_with("*."))
        .execute(pool)
        .await?;
    }

    Ok(true)
}

async fn record_finding(
    pool: &MySqlPool,
    domain_id: u64,
    code: &str,
    subject: &str,
) -> Result<()> {
    // One row per (code, subject): a re-scan moves `last_seen` rather than
    // adding another copy, so a long-standing problem reads as one thing that
    // has been wrong for months.
    sqlx::query(
        "INSERT INTO inventory_findings (code, severity, subject, domain_id, last_seen) \
         VALUES (?, 'warn', ?, ?, NOW()) \
         ON DUPLICATE KEY UPDATE last_seen = NOW(), resolved_at = NULL, domain_id = VALUES(domain_id)",
    )
    .bind(code)
    .bind(subject)
    .bind(domain_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Logs a report the way an operator wants to read it.
pub fn log_report(report: &ApplyReport, dry_run: bool) {
    if dry_run {
        log!(LogLevel::Info, "dry run -- nothing was written");
    }

    for change in &report.changes {
        log!(LogLevel::Info, "  {}", change);
    }
    for conflict in &report.conflicts {
        log!(LogLevel::Warn, "  {}", conflict);
    }

    log!(LogLevel::Info, "{}", report.summary());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::plan::{Assignment, PlanCert, PlanVhost};

    fn desired(org: Option<&str>, runner: Option<&str>) -> DesiredDomain {
        DesiredDomain {
            fqdn: "example.com".to_owned(),
            organization_id: org.map(str::to_owned),
            runner_id: runner.map(str::to_owned),
            challenge_target: "_acme-challenge.artisanhosting.net".to_owned(),
            status: "active",
        }
    }

    fn existing(org: Option<&str>, runner: Option<&str>) -> ExistingDomain {
        ExistingDomain {
            id: 1,
            organization_id: org.map(str::to_owned),
            runner_id: runner.map(str::to_owned),
            status: "active".to_owned(),
        }
    }

    #[test]
    fn an_unknown_domain_is_inserted() {
        assert_eq!(decide_domain(None, &desired(Some("4"), None), false), DomainDecision::Insert);
    }

    #[test]
    fn attaching_an_unassigned_domain_is_the_ordinary_case() {
        let decision = decide_domain(Some(&existing(None, None)), &desired(Some("4"), Some("ab12cd34")), false);

        match decision {
            DomainDecision::Update(changes) => {
                assert_eq!(changes.len(), 2, "{changes:?}");
                assert!(changes[0].contains("organization_id: none -> 4"));
                assert!(changes[1].contains("runner_id: none -> ab12cd34"));
            }
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn applying_the_same_plan_twice_changes_nothing() {
        // The property the whole design rests on: re-running after fixing one
        // line must be safe.
        let decision = decide_domain(Some(&existing(Some("4"), Some("ab12cd34"))), &desired(Some("4"), Some("ab12cd34")), false);
        assert_eq!(decision, DomainDecision::Unchanged);
    }

    #[test]
    fn moving_a_domain_between_orgs_needs_saying_so_twice() {
        let decision = decide_domain(Some(&existing(Some("4"), None)), &desired(Some("9"), None), false);

        match decision {
            DomainDecision::Conflict(message) => {
                assert!(message.contains("already in org 4"), "{message}");
                assert!(message.contains("--force-reassign"), "{message}");
            }
            other => panic!("a silent tenant move must never happen: {other:?}"),
        }

        match decide_domain(Some(&existing(Some("4"), None)), &desired(Some("9"), None), true) {
            DomainDecision::Update(changes) => assert!(changes[0].contains("forced")),
            other => panic!("expected a forced update, got {other:?}"),
        }
    }

    #[test]
    fn a_blank_assignment_never_clears_an_existing_one() {
        // Someone trims a plan file down to the domains they care about; the
        // ones they left empty must not lose their organization.
        let decision = decide_domain(Some(&existing(Some("4"), Some("ab12cd34"))), &desired(None, None), false);
        assert_eq!(decision, DomainDecision::Unchanged);
    }

    #[test]
    fn status_changes_are_recorded_as_updates() {
        let mut current = existing(Some("4"), None);
        current.status = "pending_dns".to_owned();

        match decide_domain(Some(&current), &desired(Some("4"), None), false) {
            DomainDecision::Update(changes) => {
                assert_eq!(changes, vec!["status: pending_dns -> active".to_owned()]);
            }
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn adopted_status_describes_what_is_already_true() {
        let with_both = PlanDomain {
            fqdn: "example.com".to_owned(),
            source: "imported".to_owned(),
            found_in: Vec::new(),
            suggested: None,
            assign: Assignment::default(),
            action: Action::Import,
            vhosts: vec![PlanVhost {
                path: "sites/example.com.conf".to_owned(),
                adopt: true,
                server_names: vec!["example.com".to_owned()],
                managed: false,
                sha256: String::new(),
            }],
            certs: vec![PlanCert {
                key_type: "ecc".to_owned(),
                dir: "_.example.com".to_owned(),
                not_after: "2026-12-01T00:00:00Z".to_owned(),
                covers: vec!["example.com".to_owned()],
            }],
            findings: Vec::new(),
        };
        assert_eq!(adopted_status(&with_both), "active");

        let mut cert_only = with_both.clone();
        cert_only.vhosts.clear();
        assert_eq!(adopted_status(&cert_only), "provisioning_dns");

        let mut neither = with_both.clone();
        neither.vhosts.clear();
        neither.certs.clear();
        assert_eq!(adopted_status(&neither), "pending_dns");
    }
}
