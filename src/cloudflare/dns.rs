//! DNS record operations.
//!
//! The ACME half of this (TXT records on the alias zone) is the code path
//! that runs on every renewal, so it is written to be safe to re-run: create
//! is idempotent-ish by way of `upsert`, and cleanup deletes only the exact
//! records it wrote.

use serde::{Deserialize, Serialize};

use super::Api;
use crate::error::Result;

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub proxied: Option<bool>,
}

#[derive(Debug, Serialize)]
struct NewRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

/// Stamped on every record this service creates, so an operator looking at
/// the Cloudflare dashboard can tell ours from a customer's by eye.
pub const MANAGED_COMMENT: &str = "managed by ais_domains";

/// TTL for challenge records: the minimum Cloudflare accepts, because these
/// live for seconds and a long TTL only delays the next issuance.
const CHALLENGE_TTL: u32 = 60;

pub async fn list(
    api: &Api,
    zone_id: &str,
    record_type: Option<&str>,
    name: Option<&str>,
) -> Result<Vec<DnsRecord>> {
    let mut path = format!("zones/{zone_id}/dns_records?per_page=100");
    if let Some(record_type) = record_type {
        path.push_str(&format!("&type={record_type}"));
    }
    if let Some(name) = name {
        path.push_str(&format!("&name={name}"));
    }
    api.get(&path).await
}

pub async fn create(
    api: &Api,
    zone_id: &str,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: Option<bool>,
) -> Result<DnsRecord> {
    let body = NewRecord {
        record_type,
        name,
        content,
        ttl,
        proxied,
        comment: Some(MANAGED_COMMENT),
    };
    api.post(&format!("zones/{zone_id}/dns_records"), &body).await
}

pub async fn update(
    api: &Api,
    zone_id: &str,
    record_id: &str,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: Option<bool>,
) -> Result<DnsRecord> {
    let body = NewRecord {
        record_type,
        name,
        content,
        ttl,
        proxied,
        comment: Some(MANAGED_COMMENT),
    };
    api.put(&format!("zones/{zone_id}/dns_records/{record_id}"), &body).await
}

#[derive(Debug, Deserialize)]
pub struct DeletedRecord {
    pub id: String,
}

pub async fn delete(api: &Api, zone_id: &str, record_id: &str) -> Result<()> {
    let _: DeletedRecord = api
        .delete(&format!("zones/{zone_id}/dns_records/{record_id}"))
        .await?;
    Ok(())
}

/// Create the record, or update the existing one of that name and type.
/// Used for the records this service owns (edge A/AAAA, the challenge CNAME),
/// where "there can be only one" is the intent.
pub async fn upsert(
    api: &Api,
    zone_id: &str,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: Option<bool>,
) -> Result<DnsRecord> {
    let existing = list(api, zone_id, Some(record_type), Some(name)).await?;

    match existing.into_iter().next() {
        Some(record) if record.content == content => Ok(record),
        Some(record) => {
            update(api, zone_id, &record.id, record_type, name, content, ttl, proxied).await
        }
        None => create(api, zone_id, record_type, name, content, ttl, proxied).await,
    }
}

/// Add one ACME TXT value at `name`.
///
/// Deliberately *not* an upsert: a single order for `example.com` plus
/// `*.example.com` produces two authorizations whose TXT records share a
/// name, and both values have to be present at once. Replacing instead of
/// adding is the classic way to make wildcard issuance fail intermittently.
pub async fn add_challenge_txt(api: &Api, zone_id: &str, name: &str, value: &str) -> Result<String> {
    let record = create(api, zone_id, "TXT", name, value, CHALLENGE_TTL, None).await?;
    Ok(record.id)
}

/// Remove challenge records by id, ignoring ones already gone.
///
/// Cleanup runs even when issuance failed, so a botched order does not leave
/// TXT records behind to confuse the next attempt. A record that has already
/// been deleted is not an error worth failing the job over.
pub async fn remove_challenge_txt(api: &Api, zone_id: &str, record_ids: &[String]) -> Vec<String> {
    let mut failures = Vec::new();

    for record_id in record_ids {
        if let Err(err) = delete(api, zone_id, record_id).await {
            failures.push(format!("{record_id}: {err}"));
        }
    }

    failures
}
