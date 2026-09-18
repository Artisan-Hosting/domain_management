//! Talking to `ais_auth`.
//!
//! Organizations and runners are read from there and nowhere else. This
//! service could reach the same rows directly -- they live in the same MySQL
//! instance -- and deliberately does not: `ais_auth` owns that schema, has
//! already been through several migrations of it, and is the only thing that
//! should have to care when it changes again.
//!
//! Two kinds of credential, because `ais_auth` draws the line and this side
//! respects it:
//!
//! * an **access token** for reads (`ListOrganizations`, `ListRunnersInOrg`),
//! * an **elevated token** -- minted by `ElevateSession` after a fresh
//!   password check -- for writes (`AssignRunnerOrg`). Adoption writes to
//!   another service's table, so it costs a password every time.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use serde::Deserialize;
use tonic::transport::Channel;

use crate::error::{Error, Result};
use crate::inventory::plan::{Catalog, OrgEntry, RunnerEntry};
use crate::proto::accounts::account_internal_client::AccountInternalClient;
use crate::proto::accounts::{
    AssignRunnerOrgRequest, ElevateRequest, ListOrganizationsRequest, ListRunnersInOrgRequest,
    LoginRequest, PermissionRequest, TokenRequest,
};
use artisan_middleware::api::claims::Claims;
use artisan_middleware::api::roles::Role;

#[derive(Clone)]
pub struct AuthClient {
    channel: Channel,
}

/// What the CLI holds after logging in. The password itself is never kept --
/// only what it bought.
#[derive(Clone, Default)]
pub struct Credentials {
    pub access_token: String,
    /// Short-lived, and only present when a write was actually intended.
    pub elevated_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_token", &"<redacted>")
            .field("elevated_token", &self.elevated_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl AuthClient {
    /// Lazy connection, the same pattern Portal uses (`system/grpc.rs`): the
    /// channel is built without touching the network, so constructing a
    /// client in a CLI that may never call ais_auth costs nothing.
    ///
    /// Must be called from inside a Tokio runtime -- `connect_lazy` registers
    /// with the reactor even though it dials nothing, and panics outside one.
    /// Every call site here is already async, but it is worth knowing before
    /// someone reaches for this from `main` before the runtime starts.
    pub fn new(addr: &str) -> Result<Self> {
        let channel = Channel::from_shared(addr.to_owned())
            .map_err(|e| Error::Config(format!("auth.grpc_addr {addr:?}: {e}")))?
            .connect_lazy();

        Ok(Self { channel })
    }

    fn client(&self) -> AccountInternalClient<Channel> {
        AccountInternalClient::new(self.channel.clone())
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<Credentials> {
        let response = self
            .client()
            .login(LoginRequest { email: email.to_owned(), password: password.to_owned() })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(Credentials { access_token: response.access_token, elevated_token: None })
    }

    /// Re-checks the password and mints a short-TTL elevated token. Required
    /// for anything that writes to ais_auth's own tables.
    pub async fn elevate(&self, access_token: &str, password: &str) -> Result<String> {
        let response = self
            .client()
            .elevate_session(ElevateRequest {
                access_token: access_token.to_owned(),
                password: password.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response.elevated_token)
    }

    pub async fn list_organizations(&self, access_token: &str) -> Result<Vec<OrgEntry>> {
        let response = self
            .client()
            .list_organizations(ListOrganizationsRequest {
                access_token: access_token.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response
            .organizations
            .into_iter()
            .map(|org| OrgEntry { organization_id: org.id, name: org.name })
            .collect())
    }

    pub async fn list_runners_in_org(
        &self,
        access_token: &str,
        organization_id: &str,
    ) -> Result<Vec<String>> {
        let response = self
            .client()
            .list_runners_in_org(ListRunnersInOrgRequest {
                access_token: access_token.to_owned(),
                organization_id: organization_id.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response.runner_names)
    }

    pub async fn assign_runner_org(
        &self,
        elevated_token: &str,
        runner_name: &str,
        organization_id: &str,
    ) -> Result<bool> {
        let response = self
            .client()
            .assign_runner_org(AssignRunnerOrgRequest {
                elevated_token: elevated_token.to_owned(),
                runner_name: runner_name.to_owned(),
                organization_id: organization_id.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response.success)
    }

    /// Validates an access token and returns who it belongs to.
    ///
    /// The claims come back as a string map and are rebuilt with
    /// `Claims::from_map` from artisan_middleware -- the same type Portal and
    /// ais_auth pass around, so role and org comparisons mean the same thing
    /// in all three places.
    pub async fn validate(&self, access_token: &str) -> Result<Claims> {
        let response = self
            .client()
            .validate_token(TokenRequest { access_token: access_token.to_owned() })
            .await
            .map_err(status_to_error)?
            .into_inner();

        if !response.valid {
            return Err(Error::Unauthenticated("token rejected by ais_auth".to_owned()));
        }

        Claims::from_map(response.claims)
            .map_err(|e| Error::Unauthenticated(format!("claims from ais_auth: {e}")))
    }

    /// Per-project permission, decided by ais_auth rather than re-implemented
    /// here: it owns the override table and the org rules.
    pub async fn has_permission(
        &self,
        claims: &Claims,
        project: &str,
        role: Role,
    ) -> Result<bool> {
        let response = self
            .client()
            .has_permission(PermissionRequest {
                claims: claims.to_map(),
                project_name: project.to_owned(),
                role: role.to_str().to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response.yes)
    }

    /// Every organization, and the runners in each.
    ///
    /// Reads only. A failure to reach ais_auth is reported by the caller and
    /// leaves the catalog empty -- a scan with nothing to suggest is still a
    /// perfectly good scan, and blocking the whole migration on one service
    /// being up would be the wrong trade.
    pub async fn catalog(&self, access_token: &str) -> Result<Catalog> {
        let organizations = self.list_organizations(access_token).await?;
        let mut runners = Vec::new();

        for org in &organizations {
            match self.list_runners_in_org(access_token, &org.organization_id).await {
                Ok(names) => runners.extend(names.into_iter().map(|runner_id| RunnerEntry {
                    runner_id,
                    // Filled in later from Portal's repo catalog when it is
                    // reachable; ais_auth only knows the id.
                    repo: None,
                    branch: None,
                    organization_id: Some(org.organization_id.clone()),
                })),
                Err(err) => log!(
                    LogLevel::Warn,
                    "could not list runners for org {}: {}",
                    org.organization_id,
                    err
                ),
            }
        }

        Ok(Catalog { organizations, runners })
    }
}

/// Portal's `GET /v1/repos`, the only place the platform knows a runner id's
/// repo name.
///
/// Optional enrichment: without it, suggestions fall back to matching ids,
/// which no domain name contains. With it, `acme-web.com` can be tied to the
/// repo `acme-web`.
pub async fn enrich_from_portal(
    catalog: &mut Catalog,
    portal_url: &str,
    access_token: &str,
) -> Result<usize> {
    #[derive(Deserialize)]
    struct ApiResponse {
        #[serde(default)]
        data: Option<Vec<RepoCatalogEntry>>,
    }

    #[derive(Deserialize)]
    struct RepoCatalogEntry {
        id: String,
        repo: String,
        branch: String,
        #[serde(default)]
        organization_id: Option<String>,
    }

    let url = format!("{}/v1/repos", portal_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| Error::Invalid(format!("portal {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::Invalid(format!("portal {url}: HTTP {}", response.status())));
    }

    let body: ApiResponse = response
        .json()
        .await
        .map_err(|e| Error::Invalid(format!("portal {url}: {e}")))?;

    let repos = body.data.unwrap_or_default();
    let mut enriched = 0;

    for entry in repos {
        match catalog.runners.iter_mut().find(|runner| runner.runner_id == entry.id) {
            Some(runner) => {
                runner.repo = Some(entry.repo);
                runner.branch = Some(entry.branch);
                if runner.organization_id.is_none() {
                    runner.organization_id = entry.organization_id;
                }
                enriched += 1;
            }
            None => {
                // Portal sees repos deployed on nodes that ais_auth has no
                // org assignment for -- exactly the gap adoption exists to
                // close, so they are kept rather than dropped.
                catalog.runners.push(RunnerEntry {
                    runner_id: entry.id,
                    repo: Some(entry.repo),
                    branch: Some(entry.branch),
                    organization_id: entry.organization_id,
                });
                enriched += 1;
            }
        }
    }

    Ok(enriched)
}

/// Asks for a password on the terminal without echoing it.
///
/// `ARTISAN_PASSWORD` is honoured first so the same command works in a
/// script, but it is never the documented path: a password in an environment
/// variable is a password in a process listing.
pub fn prompt_password(prompt: &str) -> Result<String> {
    if let Ok(password) = std::env::var("ARTISAN_PASSWORD") {
        if !password.is_empty() {
            return Ok(password);
        }
    }

    rpassword::prompt_password(prompt)
        .map_err(|e| Error::Unauthenticated(format!("reading password: {e}")))
}

fn status_to_error(status: tonic::Status) -> Error {
    match status.code() {
        tonic::Code::Unauthenticated => Error::Unauthenticated(status.message().to_owned()),
        tonic::Code::PermissionDenied => Error::Forbidden(status.message().to_owned()),
        tonic::Code::InvalidArgument => Error::Invalid(status.message().to_owned()),
        tonic::Code::Unavailable => {
            Error::Invalid(format!("ais_auth is unreachable: {}", status.message()))
        }
        _ => Error::Invalid(format!("ais_auth: {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_print_their_contents() {
        let credentials = Credentials {
            access_token: "super-secret-token".to_owned(),
            elevated_token: Some("also-secret".to_owned()),
        };

        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert!(!rendered.contains("also-secret"), "{rendered}");
    }

    #[tokio::test]
    async fn a_bad_address_fails_at_construction_not_at_first_use() {
        assert!(AuthClient::new("not a url").is_err());
        // Valid address, no server: lazy connect means this still succeeds.
        assert!(AuthClient::new("http://127.0.0.1:50051").is_ok());
    }

    #[test]
    fn unauthenticated_statuses_keep_their_meaning() {
        let error = status_to_error(tonic::Status::unauthenticated("bad token"));
        assert!(matches!(error, Error::Unauthenticated(_)));

        let error = status_to_error(tonic::Status::permission_denied("not an admin"));
        assert!(matches!(error, Error::Forbidden(_)));
    }
}
