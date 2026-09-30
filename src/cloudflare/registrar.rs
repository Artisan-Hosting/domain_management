//! Cloudflare Registrar: search, availability + pricing, and registration.
//!
//! Verified against Cloudflare's current published API reference
//! (`https://developers.cloudflare.com/registrar/registrar-api/` and
//! `https://developers.cloudflare.com/api/resources/registrar/`) rather
//! than guessed -- the module doc one level up calls this "a 2026 beta,"
//! and the account-scoped `list`/`get`/`update` domain endpoints under
//! `/registrar/domains` are documented as **deprecated** in favour of the
//! ones below. Every request/response shape here mirrors a real example
//! from that reference; the tests feed those exact documented payloads
//! through this module's types.
//!
//! Three endpoints, one purpose each:
//!
//! * [`search`] -- `GET .../registrar/domain-search`. Candidate names from
//!   a keyword or phrase. Cached, browsing-grade: good for "what's
//!   available like this," not the price a purchase gets built on.
//! * [`check`] -- `POST .../registrar/domain-check`. Real-time
//!   availability and pricing for up to 20 specific names. This is the
//!   one to call immediately before [`register`] -- Cloudflare's own docs
//!   say as much, and it's the only price a purchase may be built on for
//!   the same reason `QuoteDomain` exists as a distinct step from
//!   `SearchDomains` in this service's own proto.
//! * [`register`]/[`registration_status`] -- `POST
//!   .../registrar/registrations` and `GET
//!   .../registrar/registrations/{domain}/registration-status`.
//!   Registration can complete synchronously (HTTP 201) or still be
//!   running (202, or always, if `respond_async` is set) -- either way
//!   the response body's own `state` field is the source of truth, not
//!   the status code, so callers only ever need to look at one place.
//!   **Non-refundable once `state` reaches `"succeeded"`** -- Cloudflare's
//!   own words. This is the call [`super::CfSuite::registrar`]'s doc
//!   comment means when it says nothing else can spend money.
//!
//! None of this applies pricing markup, guardrails, or authorization --
//! this module is the wire shape only, the same division `zones`/`dns`
//! already draw. Turning a [`DomainAvailability`] into this service's own
//! `DomainOffer` (with markup applied) and enforcing `Pricing`/`Purchasing`
//! belongs to whatever calls this, not to this module.

use serde::{Deserialize, Serialize};

use super::Api;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct DomainPricing {
    pub currency: String,
    /// Decimal string, e.g. `"8.57"` -- never a float, this is money.
    /// [`DomainPricing::registration_cost_cents`] is the safe way to turn
    /// it into an integer.
    pub registration_cost: String,
    pub renewal_cost: String,
}

impl DomainPricing {
    pub fn registration_cost_cents(&self) -> Result<i64> {
        parse_decimal_cents(&self.registration_cost)
    }

    pub fn renewal_cost_cents(&self) -> Result<i64> {
        parse_decimal_cents(&self.renewal_cost)
    }
}

/// One name in a search or check result. `pricing` is absent for a name
/// that isn't `registrable` -- there is nothing to price.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainAvailability {
    pub name: String,
    pub registrable: bool,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub pricing: Option<DomainPricing>,
}

#[derive(Debug, Deserialize)]
struct DomainListResult {
    domains: Vec<DomainAvailability>,
}

/// Candidate names from a keyword, phrase, or partial domain name.
/// Cached/browsing-grade -- re-check with [`check`] before quoting a real
/// price. `limit` bounds how many candidates come back; Cloudflare's own
/// examples use single digits.
pub async fn search(api: &Api, account_id: &str, query: &str, limit: u32) -> Result<Vec<DomainAvailability>> {
    let path = format!(
        "accounts/{account_id}/registrar/domain-search?q={}&limit={limit}",
        percent_encode(query)
    );
    let result: DomainListResult = api.get(&path).await?;
    Ok(result.domains)
}

/// Real-time availability and pricing for specific names -- the registry
/// itself, not a cache. Cloudflare accepts at most 20 per call; refused
/// here rather than left for the server to reject, since the error is the
/// same either way and there is no reason to spend the round trip.
pub async fn check(api: &Api, account_id: &str, domains: &[String]) -> Result<Vec<DomainAvailability>> {
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    if domains.len() > 20 {
        return Err(Error::Invalid(format!(
            "domain-check accepts at most 20 domains per request, got {}",
            domains.len()
        )));
    }

    #[derive(Serialize)]
    struct CheckBody<'a> {
        domains: &'a [String],
    }

    let result: DomainListResult =
        api.post(&format!("accounts/{account_id}/registrar/domain-check"), &CheckBody { domains }).await?;
    Ok(result.domains)
}

/// A postal address, per Cloudflare's documented contact shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostalAddress {
    pub street: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    /// ISO 3166-1 alpha-2, e.g. `"US"`.
    pub country_code: String,
}

/// One registration contact. `email` and `postal_info` are what
/// Cloudflare's documented examples always carry; `phone`/`fax` are E.164
/// strings (`"+1.5555555555"`) and optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationContact {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fax: Option<String>,
    pub postal_info: PostalInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostalInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub address: PostalAddress,
}

/// Only `registrant` is modelled: it's the only role every extension
/// accepts (`administrator`/`billing`/`technical` are "accepted only if
/// the extension schema includes this role," per Cloudflare's docs, and
/// nothing in this platform's purchase flow needs them yet). Add the
/// others here if a supported extension ever requires one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contacts {
    pub registrant: RegistrationContact,
}

/// The `POST .../registrations` request body. `domain_name` is the only
/// required field; everything else falls back to Cloudflare's own
/// defaults when omitted (`years`: the extension's minimum, `auto_renew`:
/// `false`, `privacy_mode`: `"redaction"`, contacts: the account's default
/// address book entry).
#[derive(Debug, Clone, Serialize, Default)]
pub struct RegistrationRequest {
    pub domain_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub years: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_renew: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Contacts>,
}

impl RegistrationRequest {
    pub fn new(domain_name: &str) -> Self {
        Self { domain_name: domain_name.to_owned(), ..Default::default() }
    }
}

/// A registration (or registration-status poll)'s terminal and
/// in-between states. `Succeeded` is non-refundable per Cloudflare's own
/// docs; `Failed` carries detail in [`RegistrationResult::error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Pending,
    InProgress,
    ActionRequired,
    Blocked,
    Succeeded,
    Failed,
    /// Cloudflare is free to add a state this build hasn't heard of yet;
    /// treating that as a hard parse failure would turn "the API added
    /// something" into "this service crashes," so it doesn't.
    #[serde(other)]
    Unknown,
}

impl RegistrationState {
    /// `snake_case`, for storing alongside an order (`domain_orders.cf_workflow_state`)
    /// where a human is going to read it back -- distinct from `Debug`'s
    /// `PascalCase`, which would read as `inprogress` once lowercased
    /// rather than `in_progress`.
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationState::Pending => "pending",
            RegistrationState::InProgress => "in_progress",
            RegistrationState::ActionRequired => "action_required",
            RegistrationState::Blocked => "blocked",
            RegistrationState::Succeeded => "succeeded",
            RegistrationState::Failed => "failed",
            RegistrationState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationLinks {
    #[serde(rename = "self")]
    pub self_link: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationInfo {
    #[serde(default)]
    pub domain_name: Option<String>,
    #[serde(default)]
    pub auto_renew: Option<bool>,
    #[serde(default)]
    pub privacy_mode: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub locked: Option<bool>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationContext {
    #[serde(default)]
    pub domain_name: Option<String>,
    #[serde(default)]
    pub registration: Option<RegistrationInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationError {
    pub code: String,
    pub message: String,
}

/// The body shared by a synchronous (201), asynchronous (202), and
/// polled (`registration-status`) response alike -- `state` is what tells
/// them apart, not which endpoint or status code produced this value.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationResult {
    pub completed: bool,
    pub state: RegistrationState,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub links: Option<RegistrationLinks>,
    #[serde(default)]
    pub context: Option<RegistrationContext>,
    #[serde(default)]
    pub error: Option<RegistrationError>,
}

impl RegistrationResult {
    /// Whether this is a terminal state -- either outcome, nothing left
    /// to poll for.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, RegistrationState::Succeeded | RegistrationState::Failed)
    }
}

/// Registers a domain. Call [`check`] immediately before this -- per
/// Cloudflare's own docs, `domain-check` is "the one price a purchase may
/// be built on," and this endpoint bills against the account's default
/// payment profile the moment `state` reaches `succeeded`, refundable
/// never.
///
/// `respond_async` sends `Prefer: respond-async` (skip the bounded
/// synchronous wait and always get 202 back immediately) -- the worker
/// that calls this in production wants this set, since it already polls
/// [`registration_status`] and has no reason to hold a connection open
/// waiting for a registry round trip that can take real wall-clock time.
pub async fn register(
    api: &Api,
    account_id: &str,
    request: &RegistrationRequest,
    respond_async: bool,
) -> Result<RegistrationResult> {
    let path = format!("accounts/{account_id}/registrar/registrations");
    if respond_async {
        api.post_with_headers(&path, request, &[("Prefer", "respond-async")]).await
    } else {
        api.post(&path, request).await
    }
}

/// Polls a registration in progress. Same body shape [`register`]
/// returns -- check `state`, not the HTTP status, to decide whether to
/// poll again.
pub async fn registration_status(api: &Api, account_id: &str, domain_name: &str) -> Result<RegistrationResult> {
    api.get(&format!("accounts/{account_id}/registrar/registrations/{domain_name}/registration-status")).await
}

/// Percent-encodes a query parameter value. Hand-rolled rather than
/// pulling in a URL-encoding crate for one call site (`search`'s `q=`) --
/// the same "no dependency for a handful of endpoints" reasoning this
/// whole module is under. Encodes by byte, which is correct for UTF-8: a
/// multi-byte character's bytes each fall outside the unreserved set and
/// each get escaped individually, reassembling correctly on the other
/// end.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A decimal money string (`"8.57"`, `"11.00"`, `"5"`) to integer cents.
/// Never a float, deliberately -- this is money, and `8.57_f64 * 100.0`
/// is not reliably `857`. Truncates rather than rounds if Cloudflare ever
/// sends more than two fractional digits, which none of its documented
/// examples do; truncation only ever costs this side of the transaction a
/// fraction of a cent, never the customer.
fn parse_decimal_cents(value: &str) -> Result<i64> {
    let value = value.trim();
    let (whole_str, frac_str) = value.split_once('.').unwrap_or((value, ""));

    let whole: i64 = whole_str
        .parse()
        .map_err(|_| Error::Cloudflare(format!("cloudflare returned a non-numeric price: {value:?}")))?;

    let mut frac_digits: String = frac_str.chars().take(2).collect();
    while frac_digits.len() < 2 {
        frac_digits.push('0');
    }
    let frac: i64 = frac_digits
        .parse()
        .map_err(|_| Error::Cloudflare(format!("cloudflare returned a non-numeric price: {value:?}")))?;

    Ok(whole * 100 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn registration_state_as_str_uses_snake_case_not_lowercased_debug() {
        assert_eq!(RegistrationState::InProgress.as_str(), "in_progress");
        assert_eq!(RegistrationState::ActionRequired.as_str(), "action_required");
        assert_eq!(RegistrationState::Unknown.as_str(), "unknown");
    }

    /// The same minimal sequential HTTP/1.1 mock `cloudflare::dns`'s tests
    /// use -- one canned `(status, body)` response per accepted
    /// connection, served in order.
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

    /// Like [`mock_server`], but also hands back the raw request text of
    /// every accepted connection, for a test that needs to assert on a
    /// header or the request body rather than just the parsed response.
    async fn mock_server_capturing(responses: Vec<(u16, String)>) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..read]).into_owned());

                let response = format!(
                    "HTTP/1.1 {status} status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        (format!("http://{addr}"), rx)
    }

    /// Verbatim from Cloudflare's Registrar API reference's domain-search
    /// example.
    const SEARCH_RESPONSE: &str = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "domains": [
                {"name": "acmecorp.com", "registrable": true, "tier": "standard",
                 "pricing": {"currency": "USD", "registration_cost": "8.57", "renewal_cost": "8.57"}},
                {"name": "acmecorp.dev", "registrable": true, "tier": "standard",
                 "pricing": {"currency": "USD", "registration_cost": "10.11", "renewal_cost": "10.11"}},
                {"name": "acmecorp.app", "registrable": true, "tier": "standard",
                 "pricing": {"currency": "USD", "registration_cost": "11.00", "renewal_cost": "11.00"}}
            ]
        }
    }"#;

    #[tokio::test]
    async fn search_sends_the_percent_encoded_query_and_limit_on_the_url() {
        let (base, mut requests) = mock_server_capturing(vec![(200, SEARCH_RESPONSE.to_owned())]).await;
        search(&api(&base), "acct1", "acme corp", 3).await.unwrap();

        let request = requests.recv().await.expect("the request was captured");
        let request_line = request.lines().next().unwrap_or_default();
        assert!(
            request_line.contains("/accounts/acct1/registrar/domain-search?q=acme%20corp&limit=3"),
            "{request_line}"
        );
    }

    #[tokio::test]
    async fn check_sends_the_documented_request_body() {
        let (base, mut requests) = mock_server_capturing(vec![(200, CHECK_RESPONSE.to_owned())]).await;
        check(&api(&base), "acct1", &["acmecorp.dev".to_owned()]).await.unwrap();

        let request = requests.recv().await.expect("the request was captured");
        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        let sent: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(sent, serde_json::json!({"domains": ["acmecorp.dev"]}));
    }

    #[tokio::test]
    async fn search_parses_the_documented_response_shape() {
        let base = mock_server(vec![(200, SEARCH_RESPONSE.to_owned())]).await;
        let domains = search(&api(&base), "acct1", "acme corp", 3).await.unwrap();

        assert_eq!(domains.len(), 3);
        assert_eq!(domains[0].name, "acmecorp.com");
        assert!(domains[0].registrable);
        assert_eq!(domains[0].tier.as_deref(), Some("standard"));
        assert_eq!(domains[0].pricing.as_ref().unwrap().registration_cost_cents().unwrap(), 857);
        assert_eq!(domains[2].pricing.as_ref().unwrap().registration_cost_cents().unwrap(), 1100);
    }

    /// Verbatim from Cloudflare's documented domain-check example.
    const CHECK_RESPONSE: &str = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "domains": [
                {"name": "acmecorp.dev", "registrable": true, "tier": "standard",
                 "pricing": {"currency": "USD", "registration_cost": "10.11", "renewal_cost": "10.11"}}
            ]
        }
    }"#;

    #[tokio::test]
    async fn check_parses_the_documented_response_shape() {
        let base = mock_server(vec![(200, CHECK_RESPONSE.to_owned())]).await;
        let domains = check(&api(&base), "acct1", &["acmecorp.dev".to_owned()]).await.unwrap();

        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].pricing.as_ref().unwrap().renewal_cost_cents().unwrap(), 1011);
    }

    #[tokio::test]
    async fn check_refuses_more_than_twenty_domains_without_a_request() {
        let domains: Vec<String> = (0..21).map(|i| format!("d{i}.com")).collect();
        // No mock server at all: a real HTTP request here would hang
        // waiting for a connection nothing accepts, so a request going out
        // is itself the failure this test would catch.
        let err = check(&api("http://127.0.0.1:1"), "acct1", &domains).await.unwrap_err();
        assert!(err.to_string().contains("at most 20"), "{err}");
    }

    #[tokio::test]
    async fn a_non_registrable_domain_has_no_pricing() {
        let body = r#"{"success":true,"errors":[],"messages":[],"result":{"domains":[
            {"name": "taken.com", "registrable": false, "tier": "standard"}
        ]}}"#;
        let base = mock_server(vec![(200, body.to_owned())]).await;
        let domains = check(&api(&base), "acct1", &["taken.com".to_owned()]).await.unwrap();

        assert!(!domains[0].registrable);
        assert!(domains[0].pricing.is_none());
    }

    /// Verbatim from Cloudflare's documented synchronous (201) create
    /// registration example.
    const SYNC_REGISTRATION_RESPONSE: &str = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "domain_name": "acmecorp.dev",
            "state": "succeeded",
            "completed": true,
            "created_at": "2025-10-27T10:00:00Z",
            "updated_at": "2025-10-27T10:00:03Z",
            "context": {
                "registration": {
                    "domain_name": "acmecorp.dev",
                    "status": "active",
                    "created_at": "2025-10-27T10:00:00Z",
                    "expires_at": "2026-10-27T10:00:00Z",
                    "auto_renew": false,
                    "privacy_mode": "redaction",
                    "locked": true
                }
            },
            "links": {
                "self": "/accounts/abc/registrar/registrations/acmecorp.dev/registration-status",
                "resource": "/accounts/abc/registrar/registrations/acmecorp.dev"
            }
        }
    }"#;

    #[tokio::test]
    async fn register_sends_the_documented_minimal_request_body_over_the_wire() {
        let (base, mut requests) = mock_server_capturing(vec![(201, SYNC_REGISTRATION_RESPONSE.to_owned())]).await;
        register(&api(&base), "acct1", &RegistrationRequest::new("acmecorp.dev"), false).await.unwrap();

        let request = requests.recv().await.expect("the request was captured");
        let request_line = request.lines().next().unwrap_or_default();
        assert!(request_line.contains("POST /accounts/acct1/registrar/registrations"), "{request_line}");

        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        let sent: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(sent, serde_json::json!({"domain_name": "acmecorp.dev"}));
    }

    #[tokio::test]
    async fn register_parses_the_documented_synchronous_success_response() {
        let base = mock_server(vec![(201, SYNC_REGISTRATION_RESPONSE.to_owned())]).await;
        let result = register(&api(&base), "acct1", &RegistrationRequest::new("acmecorp.dev"), false).await.unwrap();

        assert_eq!(result.state, RegistrationState::Succeeded);
        assert!(result.completed);
        assert!(result.is_terminal());
        let registration = result.context.unwrap().registration.unwrap();
        assert_eq!(registration.status.as_deref(), Some("active"));
        assert_eq!(registration.locked, Some(true));
    }

    /// The generic schema Cloudflare documents for every in-between
    /// state, instantiated as `pending` -- what a 202 "still processing"
    /// response looks like before there is a `context.registration` to
    /// report yet.
    const PENDING_REGISTRATION_RESPONSE: &str = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "completed": false,
            "state": "pending",
            "created_at": "2025-10-27T10:00:00Z",
            "updated_at": "2025-10-27T10:00:00Z",
            "links": {
                "self": "/accounts/abc/registrar/registrations/acmecorp.dev/registration-status",
                "resource": "/accounts/abc/registrar/registrations/acmecorp.dev"
            },
            "context": {"domain_name": "acmecorp.dev"}
        }
    }"#;

    #[tokio::test]
    async fn register_async_sends_the_prefer_header_and_parses_a_pending_state() {
        let (base, mut requests) = mock_server_capturing(vec![(202, PENDING_REGISTRATION_RESPONSE.to_owned())]).await;
        let result = register(&api(&base), "acct1", &RegistrationRequest::new("acmecorp.dev"), true).await.unwrap();

        assert_eq!(result.state, RegistrationState::Pending);
        assert!(!result.completed);
        assert!(!result.is_terminal());

        let request = requests.recv().await.expect("the request was captured");
        assert!(
            request.to_lowercase().contains("prefer: respond-async"),
            "respond_async=true must send the Prefer header:\n{request}"
        );
    }

    #[tokio::test]
    async fn register_without_async_sends_no_prefer_header() {
        let (base, mut requests) = mock_server_capturing(vec![(201, SYNC_REGISTRATION_RESPONSE.to_owned())]).await;
        register(&api(&base), "acct1", &RegistrationRequest::new("acmecorp.dev"), false).await.unwrap();

        let request = requests.recv().await.expect("the request was captured");
        assert!(!request.to_lowercase().contains("prefer:"), "{request}");
    }

    const FAILED_REGISTRATION_RESPONSE: &str = r#"{
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "completed": true,
            "state": "failed",
            "created_at": "2025-10-27T10:00:00Z",
            "updated_at": "2025-10-27T10:00:05Z",
            "error": {"code": "registry_rejected", "message": "the registry declined this registration"}
        }
    }"#;

    #[tokio::test]
    async fn a_failed_registration_carries_its_error_detail() {
        let base = mock_server(vec![(200, FAILED_REGISTRATION_RESPONSE.to_owned())]).await;
        let result = registration_status(&api(&base), "acct1", "acmecorp.dev").await.unwrap();

        assert_eq!(result.state, RegistrationState::Failed);
        assert!(result.is_terminal());
        assert_eq!(result.error.unwrap().code, "registry_rejected");
    }

    #[tokio::test]
    async fn an_unrecognized_state_deserializes_as_unknown_rather_than_failing() {
        let body = r#"{"success":true,"errors":[],"messages":[],"result":{
            "completed": false, "state": "a_future_state_this_build_never_heard_of"
        }}"#;
        let base = mock_server(vec![(200, body.to_owned())]).await;
        let result = registration_status(&api(&base), "acct1", "acmecorp.dev").await.unwrap();

        assert_eq!(result.state, RegistrationState::Unknown);
        assert!(!result.is_terminal(), "an unknown state is never assumed terminal");
    }

    #[test]
    fn decimal_prices_parse_to_exact_cents() {
        assert_eq!(parse_decimal_cents("8.57").unwrap(), 857);
        assert_eq!(parse_decimal_cents("11.00").unwrap(), 1100);
        assert_eq!(parse_decimal_cents("5").unwrap(), 500);
        assert_eq!(parse_decimal_cents("5.5").unwrap(), 550);
        assert_eq!(parse_decimal_cents("0.09").unwrap(), 9);
    }

    #[test]
    fn a_non_numeric_price_is_a_cloudflare_error_not_a_panic() {
        assert!(parse_decimal_cents("not-a-price").is_err());
    }

    #[test]
    fn the_search_query_is_percent_encoded() {
        assert_eq!(percent_encode("acme corp"), "acme%20corp");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("safe-chars_1.2~3"), "safe-chars_1.2~3");
    }

    #[tokio::test]
    async fn registration_request_omits_absent_optional_fields() {
        // Serializes with only `domain_name` present, matching
        // Cloudflare's documented "minimal" request body exactly --
        // proven by round-tripping through a real (de)serialization
        // rather than asserting on the struct's shape alone.
        let request = RegistrationRequest::new("acmecorp.dev");
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json, serde_json::json!({"domain_name": "acmecorp.dev"}));
    }

    #[tokio::test]
    async fn registration_request_with_a_contact_matches_the_documented_shape() {
        let mut request = RegistrationRequest::new("acmecorp.dev");
        request.contacts = Some(Contacts {
            registrant: RegistrationContact {
                email: "ada@example.com".to_owned(),
                phone: Some("+1.5555555555".to_owned()),
                fax: None,
                postal_info: PostalInfo {
                    name: "Ada Lovelace".to_owned(),
                    organization: Some("Example Inc".to_owned()),
                    address: PostalAddress {
                        street: "123 Main St".to_owned(),
                        city: "Austin".to_owned(),
                        state: "TX".to_owned(),
                        postal_code: "78701".to_owned(),
                        country_code: "US".to_owned(),
                    },
                },
            },
        });

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "domain_name": "acmecorp.dev",
                "contacts": {
                    "registrant": {
                        "email": "ada@example.com",
                        "phone": "+1.5555555555",
                        "postal_info": {
                            "name": "Ada Lovelace",
                            "organization": "Example Inc",
                            "address": {
                                "street": "123 Main St",
                                "city": "Austin",
                                "state": "TX",
                                "postal_code": "78701",
                                "country_code": "US"
                            }
                        }
                    }
                }
            })
        );
    }
}
