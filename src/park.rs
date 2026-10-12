//! Parking the free zone: `*.<zone>` resolves to the edge and an nginx catch-all answers for any name that has no
//! vhost of its own. A claimed name has an exact `server_name`, which nginx prefers over this wildcard, so nothing
//! per-name has to change when a host is provisioned.

use crate::config::{Config, Secrets};
use crate::dns::write::write_records;
use crate::error::{Error, Result};
use crate::intake::RecordSpec;

/// Wildcard edge records for the zone (never overwriting), then the catch-all vhost.
/// Returns what was done, for the operator.
pub async fn park_zone(config: &Config, secrets: &Secrets, pool: &sqlx::MySqlPool, dry_run: bool) -> Result<Vec<String>> {
    let zone = config.free_zone.zone.trim().to_ascii_lowercase();
    if zone.is_empty() {
        return Err(Error::Config("free_zone.zone is not set".to_owned()));
    }
    let wildcard = format!("*.{zone}");
    let mut records = Vec::new();
    for ip in &config.dns.edge_ipv4 {
        records.push(RecordSpec { record_type: "A", name: wildcard.clone(), content: ip.clone(), note: String::new() });
    }
    for ip in &config.dns.edge_ipv6 {
        records.push(RecordSpec { record_type: "AAAA", name: wildcard.clone(), content: ip.clone(), note: String::new() });
    }
    if records.is_empty() {
        return Err(Error::Config("dns.edge_ipv4 / dns.edge_ipv6 are not set".to_owned()));
    }

    let mut notes = Vec::new();
    if dry_run {
        notes.extend(records.iter().map(|r| format!("would ensure {} {} -> {}", r.record_type, r.name, r.content)));
    } else {
        let (zone_id, _) = write_records(config, secrets, &zone, &records, &mut notes).await;
        // Remember the zone on the zone's own domain row so DNS record editing works for it.
        if let (Some(zone_id), Some(row)) = (zone_id, crate::db::inventory::find_domain(pool, &zone).await?) {
            crate::db::dns_records::set_zone_id(pool, row.id, &zone_id).await?;
        }
    }

    let slug = crate::config::snippet_slug(&zone);
    let snippets = &config.tree.snippets_dir;
    // 404 with a plain page: the name resolves but nothing is set up on it yet.
    let vhost = format!(
        "server {{\n    listen 80;\n    server_name *.{zone};\n    return 301 https://$host$request_uri;\n}}\n\n\
         server {{\n    listen 443 ssl http2;\n    server_name *.{zone};\n\n\
         \x20   include {snippets}/{slug}_cert.conf;\n    include {snippets}/ssl-params.conf;\n\n\
         \x20   default_type text/html;\n\
         \x20   return 404 \"<!doctype html><title>Not set up yet</title><body style='font-family:sans-serif;text-align:center;margin-top:20vh'><h1>Nothing here yet</h1><p>This address is reserved on Artisan Hosting but has no service attached.</p></body>\";\n}}\n"
    );

    // The vhost file is keyed by the zone, which may already have a hand-written vhost: never replace one.
    let path = config.vhost_path_for(&zone);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.contains(crate::inventory::nginx::FREEFORM_MANAGED_HEADER) {
            notes.push(format!("{} exists and is not ours; parking vhost not written", path.display()));
            return Ok(notes);
        }
    }
    let outcome = crate::vhost::freeform::apply(config, &zone, &vhost, dry_run).await?;
    notes.push(if dry_run { "parking vhost validated by nginx -t (dry run, not written)".to_owned() } else { format!("parking vhost written to {}", path.display()) });
    let _ = outcome;
    Ok(notes)
}
