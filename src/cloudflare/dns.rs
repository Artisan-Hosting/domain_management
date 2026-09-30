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

/// Ensures `_acme-challenge.<fqdn>` CNAMEs to `challenge_target` in a zone
/// this service controls (a purchased domain, or a BYO one whose
/// nameservers now point at Cloudflare). This is the automation that used
/// to be a manual DNS step after buying or importing a domain: nothing
/// issues against `challenge_target` until this record exists, and
/// `FindingCode::MissingChallengeCname` is the scanner catching it when it
/// doesn't.
///
/// Called on `cf.zones` (the account-wide zone/DNS credential), never
/// `cf.challenge` (scoped only to the alias zone itself) -- this writes
/// into the *customer's* zone, not the shared alias zone the TXT values
/// above live on.
///
/// A long TTL on purpose: unlike the per-issuance TXT values, this record is
/// long-lived infrastructure, not something a renewal churns every few
/// weeks.
///
/// One function, two callers in two different subsystems (see the crate
/// root doc): `add_domain`'s BYO body calls this synchronously, inline in
/// the gRPC handler (subsystem 2) right after the zone is found to already
/// exist -- a single idempotent upsert costs nothing to retry, so it needs
/// no job. The `register` job (subsystem 3, landing with the purchase
/// flow) calls the same function from inside a worker, right after
/// `zones::ensure` creates a brand-new zone and before the first
/// `acme::issue::Issuer::issue_pair` call -- issuance would otherwise race
/// a CNAME that isn't there yet. Both callers are expected to exist; if you
/// only find one, the other's phase hasn't landed yet, not a bug.
const CHALLENGE_CNAME_TTL: u32 = 300;

pub async fn ensure_challenge_cname(
    api: &Api,
    zone_id: &str,
    fqdn: &str,
    challenge_target: &str,
) -> Result<DnsRecord> {
    upsert(
        api,
        zone_id,
        "CNAME",
        &format!("_acme-challenge.{fqdn}"),
        challenge_target,
        CHALLENGE_CNAME_TTL,
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A minimal, sequential HTTP/1.1 mock: one canned `(status, json body)`
    /// response per accepted connection, served in order. Enough to stand
    /// in for Cloudflare's envelope shape without pulling in a mocking
    /// crate for a handful of endpoints -- the same call this service's own
    /// `Api` makes not to do that either.
    async fn mock_server(responses: Vec<(u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;

                let response = format!(
                    "HTTP/1.1 {status} status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        format!("http://{addr}")
    }

    fn api(base: &str) -> Api {
        Api::new(base, "test-token", "test", Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn creates_the_cname_when_none_exists() {
        let base = mock_server(vec![
            (200, r#"{"success":true,"result":[]}"#.to_owned()),
            (
                200,
                r#"{"success":true,"result":{"id":"rec1","type":"CNAME","name":"_acme-challenge.example.com","content":"target.acme.artisanhosting.net","ttl":300}}"#
                    .to_owned(),
            ),
        ])
        .await;

        let record = ensure_challenge_cname(&api(&base), "zone1", "example.com", "target.acme.artisanhosting.net")
            .await
            .unwrap();

        assert_eq!(record.record_type, "CNAME");
        assert_eq!(record.content, "target.acme.artisanhosting.net");
    }

    #[tokio::test]
    async fn updates_the_cname_when_the_content_differs() {
        let base = mock_server(vec![
            (
                200,
                r#"{"success":true,"result":[{"id":"rec1","type":"CNAME","name":"_acme-challenge.example.com","content":"stale.acme.artisanhosting.net","ttl":300}]}"#
                    .to_owned(),
            ),
            (
                200,
                r#"{"success":true,"result":{"id":"rec1","type":"CNAME","name":"_acme-challenge.example.com","content":"target.acme.artisanhosting.net","ttl":300}}"#
                    .to_owned(),
            ),
        ])
        .await;

        let record = ensure_challenge_cname(&api(&base), "zone1", "example.com", "target.acme.artisanhosting.net")
            .await
            .unwrap();

        assert_eq!(record.content, "target.acme.artisanhosting.net");
    }

    #[tokio::test]
    async fn leaves_a_matching_cname_alone() {
        // Only one response queued: if this called update or create instead
        // of recognising the match, the second request would hang waiting
        // for a connection nothing accepts, and the test would time out
        // rather than fail cleanly -- which is itself the point.
        let base = mock_server(vec![(
            200,
            r#"{"success":true,"result":[{"id":"rec1","type":"CNAME","name":"_acme-challenge.example.com","content":"target.acme.artisanhosting.net","ttl":300}]}"#
                .to_owned(),
        )])
        .await;

        let record = tokio::time::timeout(
            Duration::from_secs(2),
            ensure_challenge_cname(&api(&base), "zone1", "example.com", "target.acme.artisanhosting.net"),
        )
        .await
        .expect("must not need a second request")
        .unwrap();

        assert_eq!(record.content, "target.acme.artisanhosting.net");
    }
}
