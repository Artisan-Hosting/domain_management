//! Cloudflare API client.
//!
//! Deliberately hand-rolled over `reqwest` instead of a general-purpose
//! Cloudflare crate: this service touches a handful of endpoints (zones, DNS
//! records, registrar, members), and the registrar ones are a 2026 beta that
//! no published crate covers yet.
//!
//! Each [`Api`] carries exactly one token, so least privilege is visible at
//! the call site: writing an ACME TXT record goes through the challenge API,
//! which holds a token scoped to the alias zone alone, and nothing but
//! [`CfSuite::registrar`] can spend money.

pub mod dns;
pub mod zones;

use serde::{Deserialize, de::DeserializeOwned};
use std::time::Duration;

use crate::config::{Config, Secrets};
use crate::error::{Error, Result};

/// Cloudflare's envelope. `success: false` arrives with HTTP 200 often
/// enough that checking the status code alone is not enough.
#[derive(Debug, Deserialize)]
// Without this, serde's derive infers `T: Default` from the `#[serde(default)]`
// on `result` and every caller has to implement Default for no reason.
#[serde(bound(deserialize = "T: DeserializeOwned"))]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: String,
    token: String,
    /// Named for error messages, so a failure says which credential was used
    /// without ever printing it.
    label: &'static str,
}

impl Api {
    pub fn new(base: &str, token: &str, label: &'static str, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("ais_domains/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Cloudflare(format!("building http client: {e}")))?;

        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            label,
        })
    }

    pub fn has_token(&self) -> bool {
        !self.token.is_empty()
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(reqwest::Method::GET, path, None::<&()>, &[]).await
    }

    pub async fn post<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.send(reqwest::Method::POST, path, Some(body), &[]).await
    }

    pub async fn post_with_headers<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        headers: &[(&str, &str)],
    ) -> Result<T> {
        self.send(reqwest::Method::POST, path, Some(body), headers).await
    }

    pub async fn put<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.send(reqwest::Method::PUT, path, Some(body), &[]).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(reqwest::Method::DELETE, path, None::<&()>, &[]).await
    }

    async fn send<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
        headers: &[(&str, &str)],
    ) -> Result<T> {
        if self.token.is_empty() {
            return Err(Error::Cloudflare(format!(
                "no {} token configured; cannot call {path}",
                self.label
            )));
        }

        let url = format!("{}/{}", self.base, path.trim_start_matches('/'));
        let mut request = self.http.request(method, &url).bearer_auth(&self.token);

        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Cloudflare(format!("{} {path}: {e}", self.label)))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Cloudflare(format!("{} {path}: reading body: {e}", self.label)))?;

        let envelope: Envelope<T> = serde_json::from_str(&text).map_err(|e| {
            // Keep a slice of the body: Cloudflare's HTML error pages and
            // WAF blocks are otherwise indistinguishable from a parse bug.
            let snippet: String = text.chars().take(300).collect();
            Error::Cloudflare(format!(
                "{} {path}: HTTP {status}, undecodable response ({e}): {snippet}",
                self.label
            ))
        })?;

        if !envelope.success {
            let detail = envelope
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(Error::Cloudflare(format!(
                "{} {path}: HTTP {status}: {}",
                self.label,
                if detail.is_empty() { "no detail given".to_owned() } else { detail }
            )));
        }

        envelope.result.ok_or_else(|| {
            Error::Cloudflare(format!("{} {path}: succeeded with no result body", self.label))
        })
    }
}

/// The four credentials, kept apart on purpose.
#[derive(Clone)]
pub struct CfSuite {
    /// Zone + DNS edit across the account: creates zones, writes edge records.
    pub zones: Api,
    /// DNS edit on the alias zone only -- the credential every renewal uses.
    pub challenge: Api,
    /// The only one that can spend money.
    pub registrar: Api,
    /// Account member management: customer invites.
    pub members: Api,
    pub account_id: String,
}

impl CfSuite {
    pub fn new(config: &Config, secrets: &Secrets) -> Result<Self> {
        let base = &config.cloudflare.api_base;
        let timeout = Duration::from_secs(config.cloudflare.timeout_secs);

        Ok(Self {
            zones: Api::new(base, &secrets.cf_zones_token, "zones", timeout)?,
            challenge: Api::new(base, &secrets.cf_challenge_token, "challenge", timeout)?,
            registrar: Api::new(base, &secrets.cf_registrar_token, "registrar", timeout)?,
            members: Api::new(base, &secrets.cf_members_token, "members", timeout)?,
            account_id: secrets.cf_account_id.clone(),
        })
    }
}
