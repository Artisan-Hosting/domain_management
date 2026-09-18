//! Running a scan: the collectors, the cross-reference, and the optional
//! live checks.
//!
//! Strictly read-only. `scan` can be run against production at any time, by
//! anyone, without consequence -- that is what makes it useful as the first
//! step of a migration nobody fully remembers the shape of.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use std::net::IpAddr;
use std::path::PathBuf;

use super::model::{self, Finding, FindingCode, Inventory};
use super::{certs, domains_txt, nginx};
use crate::cloudflare::{CfSuite, zones};
use crate::config::{Config, Secrets};
use crate::dns::probe::Probe;
use crate::error::Result;

pub struct ScanOptions {
    /// The acme.sh-era domain list. Defaults to the path the `certs` script used.
    pub domains_file: PathBuf,
    /// Resolve each domain and check it points at the edge, and that its
    /// `_acme-challenge` CNAME is in place.
    pub check_dns: bool,
    /// Ask Cloudflare whether we hold a zone for each domain.
    pub check_cloudflare: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            domains_file: PathBuf::from("/etc/acme-sh/domains.txt"),
            check_dns: false,
            check_cloudflare: false,
        }
    }
}

pub async fn run(config: &Config, secrets: &Secrets, options: &ScanOptions) -> Result<Inventory> {
    let tree_root = config.tree.root.clone();
    log!(LogLevel::Info, "scanning {}", tree_root.display());

    let nginx_index = nginx::scan_tree(&tree_root, &config.tree.snippets_dir)?;
    let cert_dirs = certs::scan(&tree_root.join(&config.tree.certs_dir))?;
    let domain_list = domains_txt::scan(&options.domains_file)?;

    log!(
        LogLevel::Info,
        "found {} config file(s), {} server block(s), {} cert snippet(s), {} certificate director(ies), {} domains.txt entr(ies)",
        nginx_index.files.len(),
        nginx_index.servers.len(),
        nginx_index.snippets.len(),
        cert_dirs.len(),
        domain_list.entries.len()
    );

    let mut inventory = model::build(
        &tree_root,
        &config.tree.certs_dir,
        nginx_index,
        cert_dirs,
        domain_list,
        chrono::Utc::now().timestamp(),
        config.acme.renew_before_days,
    );

    if options.check_dns {
        check_dns(config, &mut inventory).await;
    }
    if options.check_cloudflare {
        check_cloudflare(config, secrets, &mut inventory).await;
    }

    let counts = inventory.counts_by_code();
    if counts.is_empty() {
        log!(LogLevel::Info, "no findings");
    } else {
        for (code, count) in &counts {
            log!(LogLevel::Info, "{count} x {code}");
        }
    }

    Ok(inventory)
}

/// Checks each domain against public DNS: does it point at the edge, and is
/// the `_acme-challenge` CNAME in place for renewals to work?
///
/// Failures here are recorded, never fatal. A scan that stops because one
/// domain's nameservers are slow is worse than one that says so.
async fn check_dns(config: &Config, inventory: &mut Inventory) {
    let probe = match Probe::with_servers(&config.dns.resolvers) {
        Ok(probe) => probe,
        Err(err) => {
            log!(LogLevel::Warn, "skipping DNS checks: {}", err);
            return;
        }
    };

    let expected: Vec<IpAddr> = config
        .dns
        .edge_ipv4
        .iter()
        .chain(config.dns.edge_ipv6.iter())
        .filter_map(|ip| ip.parse().ok())
        .collect();

    let mut findings = Vec::new();

    for record in &inventory.domains {
        if expected.is_empty() {
            // No edge IPs configured: the old EXPECTED_IPS being unset meant
            // "do not gate", and it means the same here.
        } else if let Ok(false) = probe.resolves_to_edge(&record.fqdn, &expected).await {
            findings.push(Finding {
                code: FindingCode::DnsMismatch,
                severity: FindingCode::DnsMismatch.severity(),
                subject: record.fqdn.clone(),
                message: "does not resolve to any configured edge address".to_owned(),
                evidence: config.dns.edge_ipv4.clone(),
            });
        }

        // Only matters for domains we are expected to renew.
        if !record.serves_tls && !record.in_domains_txt {
            continue;
        }

        let targets = [
            config.challenge_target_for(&record.fqdn),
            config.acme.legacy_challenge_target.clone(),
        ];

        let mut ok = false;
        for target in &targets {
            if let Ok(true) = probe.challenge_cname_ok(&record.fqdn, target).await {
                ok = true;
                break;
            }
        }

        if !ok {
            findings.push(Finding {
                code: FindingCode::MissingChallengeCname,
                severity: FindingCode::MissingChallengeCname.severity(),
                subject: record.fqdn.clone(),
                message: format!(
                    "_acme-challenge.{} does not CNAME to a target we write to; renewal cannot validate",
                    record.fqdn
                ),
                evidence: targets.to_vec(),
            });
        }
    }

    attach(inventory, findings);
}

async fn check_cloudflare(config: &Config, secrets: &Secrets, inventory: &mut Inventory) {
    let cf = match CfSuite::new(config, secrets) {
        Ok(cf) => cf,
        Err(err) => {
            log!(LogLevel::Warn, "skipping Cloudflare checks: {}", err);
            return;
        }
    };
    if !cf.zones.has_token() {
        log!(LogLevel::Warn, "skipping Cloudflare checks: no zones token configured");
        return;
    }

    for record in &mut inventory.domains {
        match zones::find(&cf.zones, &record.fqdn).await {
            Ok(Some(zone)) => record.cloudflare_zone_id = Some(zone.id),
            Ok(None) => {}
            Err(err) => log!(LogLevel::Warn, "zone lookup for {} failed: {}", record.fqdn, err),
        }
    }
}

fn attach(inventory: &mut Inventory, findings: Vec<Finding>) {
    for finding in findings {
        if let Some(record) = inventory
            .domains
            .iter_mut()
            .find(|record| record.fqdn == finding.subject)
        {
            if !record.findings.contains(&finding.code) {
                record.findings.push(finding.code);
            }
        }
        inventory.findings.push(finding);
    }
}
