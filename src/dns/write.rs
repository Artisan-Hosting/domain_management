//! Writing a name's edge records into the Cloudflare zone we hold for it.
//!
//! One function, shared by the `AddDomain` path (a customer's subdomain or free address) and the purchase
//! worker (a domain that has just been registered), so both obey the same rule: nothing already there is
//! ever overwritten.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;

use crate::config::{Config, Secrets};

/// Writes the DNS records into the zone we hold for `fqdn`, if we hold one.
///
/// Returns the zone id and whether everything is now in place. Never
/// overwrites: see [`crate::intake::plan_dns`]. Every reason it did not
/// write is added to `notes`.
pub async fn write_records(
    config: &Config,
    secrets: &Secrets,
    fqdn: &str,
    records: &[crate::intake::RecordSpec],
    notes: &mut Vec<String>,
) -> (Option<String>, bool) {
    use crate::cloudflare::{CfSuite, dns, zones};

    let cf = match CfSuite::new(config, secrets) {
        Ok(cf) if cf.zones.has_token() => cf,
        Ok(_) => {
            notes.push("No Cloudflare zones token is configured, so DNS was not written.".to_owned());
            return (None, false);
        }
        Err(err) => {
            notes.push(format!("Cloudflare is unavailable ({err}), so DNS was not written."));
            return (None, false);
        }
    };

    let Some(apex) = crate::inventory::model::registrable_domain(fqdn) else {
        return (None, false);
    };
    let zone = match zones::find(&cf.zones, &apex).await {
        Ok(Some(zone)) => zone,
        Ok(None) => {
            notes.push(format!("We hold no Cloudflare zone for {apex}, so DNS was not written."));
            return (None, false);
        }
        Err(err) => {
            log!(LogLevel::Warn, "zone lookup for {apex} failed: {err}");
            notes.push(format!("Looking up the Cloudflare zone for {apex} failed, so DNS was not written."));
            return (None, false);
        }
    };

    let mut existing = Vec::new();
    let mut names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        match dns::list(&cf.zones, &zone.id, None, Some(name)).await {
            Ok(found) => existing.extend(found.into_iter().map(|r| crate::intake::ExistingRecord {
                record_type: r.record_type,
                name: r.name,
                content: r.content,
            })),
            Err(err) => {
                log!(LogLevel::Warn, "listing {name} in {apex} failed: {err}");
                notes.push(format!("Reading existing DNS for {name} failed, so nothing was written."));
                return (Some(zone.id), false);
            }
        }
    }

    let plan = crate::intake::plan_dns(records, &existing);
    if !plan.conflicts.is_empty() {
        notes.extend(plan.conflicts.iter().map(|c| format!("Not written: {c}.")));
        return (Some(zone.id), false);
    }

    for record in &plan.create {
        // DNS-only: the edge terminates TLS with our certificates, and a
        // proxied record would put Cloudflare's certificate in front.
        if let Err(err) = dns::create(&cf.zones, &zone.id, record.record_type, &record.name, &record.content, 1, Some(false)).await {
            log!(LogLevel::Warn, "creating {} {} failed: {err}", record.record_type, record.name);
            notes.push(format!("Creating {} {} failed ({err}); create the remaining records by hand.", record.record_type, record.name));
            return (Some(zone.id), false);
        }
    }

    notes.push(format!(
        "DNS: created {} record(s), {} already correct, in the {apex} zone.",
        plan.create.len(),
        plan.present.len()
    ));
    (Some(zone.id), true)
}

