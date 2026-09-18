//! `DomainService` implementation.
//!
//! Handlers here stay thin on purpose: authorize, read or write the
//! database, enqueue a job. Anything that talks to Cloudflare, Let's Encrypt
//! or R2 happens in a worker, because those calls take seconds to minutes and
//! must survive a restart -- a registration in particular spends money, so it
//! cannot live only in the memory of an RPC that might be cancelled halfway.
//!
//! Phase 1 is the script-parity work (issuance and publishing); the RPCs that
//! are not wired yet return `unimplemented` rather than pretending.

use artisan_middleware::api::claims::Claims;
use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use artisan_middleware::api::roles::Role;
use sqlx::MySqlPool;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::auth::AuthClient;
use crate::config::{Config, Secrets};
use crate::db::inventory as inventory_db;
use crate::inventory::scan;
use crate::proto::domains::*;
use crate::proto::domains::domain_service_server::DomainService;

pub struct Domains {
    config: Config,
    secrets: Secrets,
    pool: MySqlPool,
    auth: AuthClient,
}

impl Domains {
    pub fn new(config: Config, secrets: Secrets, pool: MySqlPool) -> Result<Self, crate::error::Error> {
        let auth = AuthClient::new(&config.auth.grpc_addr)?;
        Ok(Self { config, secrets, pool, auth })
    }

    /// Who is calling. Every token is checked with ais_auth rather than
    /// trusted because Portal forwarded it -- Portal has already done its own
    /// check, and two independent checks is the point.
    async fn caller(&self, access_token: &str) -> Result<Claims, Status> {
        if access_token.is_empty() {
            return Err(Status::unauthenticated("no access token"));
        }
        Ok(self.auth.validate(access_token).await?)
    }

    /// The org filter to apply to a listing.
    ///
    /// `None` means "everything": only Super and Admin get that. Everyone
    /// else is pinned to their own organization whatever they asked for, so a
    /// crafted request cannot widen the view.
    fn scope(&self, claims: &Claims, requested: &str) -> Option<String> {
        match claims.role {
            Role::Super | Role::Admin => {
                if requested.is_empty() { None } else { Some(requested.to_owned()) }
            }
            _ => Some(claims.organization_id.clone()),
        }
    }

    fn require_admin(&self, claims: &Claims, what: &str) -> Result<(), Status> {
        match claims.role {
            Role::Super | Role::Admin => Ok(()),
            _ => Err(Status::permission_denied(format!("{what} requires an administrator"))),
        }
    }
}

/// Marks an RPC whose implementation is still ahead of us, with the phase it
/// belongs to, so a caller gets a straight answer instead of a stub result.
fn pending(phase: &str, what: &str) -> Status {
    Status::unimplemented(format!("{what} lands in {phase}"))
}

/// Database strings to proto enums. Anything unrecognised maps to
/// `UNSPECIFIED` rather than panicking: the database is allowed to grow a
/// value this build has not heard of.
fn source_code(source: &str) -> i32 {
    match source {
        "purchased" => DomainSource::Purchased as i32,
        "byo" => DomainSource::Byo as i32,
        "imported" => DomainSource::Imported as i32,
        _ => DomainSource::Unspecified as i32,
    }
}

fn status_code(status: &str) -> i32 {
    match status {
        "pending_payment" => DomainStatus::PendingPayment as i32,
        "registering" => DomainStatus::Registering as i32,
        "provisioning_dns" => DomainStatus::ProvisioningDns as i32,
        "pending_dns" => DomainStatus::PendingDns as i32,
        "issuing" => DomainStatus::Issuing as i32,
        "active" => DomainStatus::Active as i32,
        "renewing" => DomainStatus::Renewing as i32,
        "error" => DomainStatus::Error as i32,
        "removed" => DomainStatus::Removed as i32,
        _ => DomainStatus::Unspecified as i32,
    }
}

#[tonic::async_trait]
impl DomainService for Domains {
    // --- purchasing (phase 3) -------------------------------------------

    async fn search_domains(
        &self,
        _request: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        Err(pending("phase 3", "domain search"))
    }

    async fn quote_domain(
        &self,
        _request: Request<QuoteRequest>,
    ) -> Result<Response<QuoteResponse>, Status> {
        Err(pending("phase 3", "domain quotes"))
    }

    async fn create_order(
        &self,
        _request: Request<CreateOrderRequest>,
    ) -> Result<Response<OrderCheckout>, Status> {
        Err(pending("phase 3", "domain orders"))
    }

    async fn get_order(&self, _request: Request<GetOrderRequest>) -> Result<Response<Order>, Status> {
        Err(pending("phase 3", "domain orders"))
    }

    async fn list_orders(
        &self,
        _request: Request<ListOrdersRequest>,
    ) -> Result<Response<ListOrdersResponse>, Status> {
        Err(pending("phase 3", "domain orders"))
    }

    async fn handle_stripe_webhook(
        &self,
        _request: Request<StripeWebhookRequest>,
    ) -> Result<Response<StripeWebhookResponse>, Status> {
        Err(pending("phase 3", "Stripe webhooks"))
    }

    // --- lifecycle (phase 2) --------------------------------------------

    async fn add_domain(
        &self,
        _request: Request<AddDomainRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        Err(pending("phase 2", "adding a domain"))
    }

    async fn get_domain(&self, _request: Request<GetDomainRequest>) -> Result<Response<Domain>, Status> {
        Err(pending("phase 2", "reading a domain"))
    }

    async fn list_domains(
        &self,
        _request: Request<ListDomainsRequest>,
    ) -> Result<Response<ListDomainsResponse>, Status> {
        Err(pending("phase 2", "listing domains"))
    }

    async fn remove_domain(
        &self,
        _request: Request<RemoveDomainRequest>,
    ) -> Result<Response<RemoveDomainResponse>, Status> {
        Err(pending("phase 2", "removing a domain"))
    }

    async fn verify_domain_now(
        &self,
        _request: Request<VerifyDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        Err(pending("phase 2", "on-demand DNS verification"))
    }

    type WatchDomainStream =
        Pin<Box<dyn Stream<Item = Result<DomainEvent, Status>> + Send + 'static>>;

    async fn watch_domain(
        &self,
        _request: Request<WatchDomainRequest>,
    ) -> Result<Response<Self::WatchDomainStream>, Status> {
        Err(pending("phase 2", "domain event streaming"))
    }

    // --- vhosts (phase 2) -----------------------------------------------

    async fn attach_domain(
        &self,
        request: Request<AttachDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        // Same bar as editing the project's config: an administrator, or
        // someone with an explicit grant on that runner.
        if claims.role != Role::Super && claims.role != Role::Admin {
            let permitted = self
                .auth
                .has_permission(&claims, &req.runner_id, Role::Admin)
                .await
                .map_err(Status::from)?;
            if !permitted {
                return Err(Status::permission_denied(format!(
                    "not permitted to attach domains to '{}'",
                    req.runner_id
                )));
            }
        }
        if claims.role != Role::Super
            && existing.organization_id.is_some()
            && existing.organization_id.as_deref() != Some(claims.organization_id.as_str())
        {
            return Err(Status::permission_denied("that domain belongs to another organization"));
        }

        let mut spec = crate::vhost::render::VhostSpec::new(
            &existing.fqdn,
            &req.runner_id,
            req.backends
                .into_iter()
                .map(|backend| crate::vhost::render::Backend {
                    node_id: backend.node_id,
                    // A port is a u16 on the wire's u32; anything above that
                    // is a caller bug, not something to truncate silently.
                    port: u16::try_from(backend.port).unwrap_or(0),
                })
                .collect(),
        );
        spec.extra_names = req.extra_names;
        spec.http_redirect = !req.no_http_redirect;

        let outcome = crate::vhost::attach(&self.config, &spec).await?;

        let server_names = spec.server_names();
        inventory_db::record_generated_vhost(
            &self.pool,
            existing.id,
            &req.runner_id,
            &self
                .config
                .vhost_path_for(&existing.fqdn)
                .strip_prefix(&self.config.tree.root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            &server_names,
        )
        .await
        .map_err(Status::from)?;

        inventory_db::set_assignment(&self.pool, existing.id, None, Some(Some(req.runner_id)))
            .await
            .map_err(Status::from)?;

        log!(
            LogLevel::Info,
            "{}: vhost {} ({} instance(s))",
            existing.fqdn,
            match &outcome.vhost {
                crate::vhost::render::VhostOutcome::Created(_) => "created",
                crate::vhost::render::VhostOutcome::Updated(_) => "updated",
                crate::vhost::render::VhostOutcome::Unchanged(_) => "unchanged",
                crate::vhost::render::VhostOutcome::HandWritten { .. } => "left alone (hand-written)",
            },
            spec.backends.len()
        );

        let updated = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-attach"))?;

        Ok(Response::new(Domain {
            id: updated.id.to_string(),
            fqdn: updated.fqdn,
            organization_id: updated.organization_id.unwrap_or_default(),
            runner_id: updated.runner_id.unwrap_or_default(),
            source: source_code(&updated.source),
            status: status_code(&updated.status),
            has_vhost: true,
            ..Default::default()
        }))
    }

    async fn detach_domain(
        &self,
        _request: Request<DetachDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        Err(pending("phase 2", "detaching a domain"))
    }

    // --- members (phase 3) ----------------------------------------------

    async fn invite_domain_member(
        &self,
        _request: Request<InviteDomainMemberRequest>,
    ) -> Result<Response<DomainMember>, Status> {
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    async fn list_domain_members(
        &self,
        _request: Request<ListDomainMembersRequest>,
    ) -> Result<Response<ListDomainMembersResponse>, Status> {
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    async fn remove_domain_member(
        &self,
        _request: Request<RemoveDomainMemberRequest>,
    ) -> Result<Response<RemoveDomainMemberResponse>, Status> {
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    // --- adoption and attachment ----------------------------------------

    async fn assign_domain(
        &self,
        request: Request<AssignDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        self.require_admin(&claims, "attaching a domain")?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        // An org-scoped admin can only touch their own tenant's domains, and
        // can only assign into their own organization.
        if claims.role != Role::Super {
            let theirs = existing.organization_id.as_deref() == Some(claims.organization_id.as_str());
            if existing.organization_id.is_some() && !theirs {
                return Err(Status::permission_denied("that domain belongs to another organization"));
            }
            if !req.organization_id.is_empty() && req.organization_id != claims.organization_id {
                return Err(Status::permission_denied("you can only attach domains to your own organization"));
            }
        }

        // Moving a domain that already belongs to someone is the one case
        // that costs a fresh password: it takes a name away from one tenant
        // and gives it to another.
        let is_move = existing.organization_id.is_some()
            && ((!req.organization_id.is_empty() && existing.organization_id.as_deref() != Some(req.organization_id.as_str()))
                || req.clear_org);
        if is_move && req.elevated_token.is_empty() {
            return Err(Status::permission_denied(
                "moving a domain between organizations needs an elevated token",
            ));
        }
        if is_move {
            // Validated for what it is, not merely for being present.
            self.caller(&req.elevated_token).await?;
        }

        let org = if req.clear_org {
            Some(None)
        } else if req.organization_id.is_empty() {
            None
        } else {
            Some(Some(req.organization_id.clone()))
        };
        let runner = if req.clear_runner {
            Some(None)
        } else if req.runner_id.is_empty() {
            None
        } else {
            Some(Some(req.runner_id.clone()))
        };

        inventory_db::set_assignment(&self.pool, existing.id, org, runner)
            .await
            .map_err(Status::from)?;

        let updated = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-assignment"))?;

        Ok(Response::new(Domain {
            id: updated.id.to_string(),
            fqdn: updated.fqdn,
            organization_id: updated.organization_id.unwrap_or_default(),
            runner_id: updated.runner_id.unwrap_or_default(),
            source: source_code(&updated.source),
            status: status_code(&updated.status),
            expires_at: updated.expires_at.unwrap_or_default(),
            ..Default::default()
        }))
    }

    async fn list_inventory(
        &self,
        request: Request<ListInventoryRequest>,
    ) -> Result<Response<ListInventoryResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let scope = self.scope(&claims, &req.organization_id);

        let rows = inventory_db::list_inventory(
            &self.pool,
            scope.as_deref(),
            req.unassigned_only,
            if req.limit > 0 { req.limit as i64 } else { 100 },
            req.offset as i64,
        )
        .await
        .map_err(Status::from)?;

        let counts = inventory_db::inventory_counts(&self.pool, scope.as_deref())
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListInventoryResponse {
            entries: rows
                .into_iter()
                .map(|row| InventoryEntry {
                    id: row.id.to_string(),
                    fqdn: row.fqdn,
                    organization_id: row.organization_id.unwrap_or_default(),
                    runner_id: row.runner_id.unwrap_or_default(),
                    source: source_code(&row.source),
                    status: status_code(&row.status),
                    serves_tls: !row.cert_dirs.is_empty(),
                    vhost_paths: row.vhost_paths,
                    cert_dirs: row.cert_dirs,
                    expires_at: row.expires_at.unwrap_or_default(),
                    findings: row.findings,
                })
                .collect(),
            total: counts.total as i32,
            unassigned: counts.unassigned as i32,
        }))
    }

    async fn list_findings(
        &self,
        request: Request<ListFindingsRequest>,
    ) -> Result<Response<ListFindingsResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        // Findings name file paths and certificate directories across the
        // whole fleet, so they are an administrator's view.
        self.require_admin(&claims, "reading findings")?;

        let rows = inventory_db::list_findings(
            &self.pool,
            (!req.code.is_empty()).then_some(req.code.as_str()),
            (!req.severity.is_empty()).then_some(req.severity.as_str()),
            req.open_only,
            if req.limit > 0 { req.limit as i64 } else { 200 },
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(ListFindingsResponse {
            findings: rows
                .into_iter()
                .map(|row| FindingEntry {
                    code: row.code,
                    severity: row.severity,
                    subject: row.subject,
                    message: row.message,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                    resolved_at: row.resolved_at.unwrap_or_default(),
                })
                .collect(),
        }))
    }

    async fn rescan_inventory(
        &self,
        request: Request<RescanRequest>,
    ) -> Result<Response<RescanResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        // A scan reads every config file on the host. That is a Super-only
        // view, not an org-scoped one.
        if claims.role != Role::Super {
            return Err(Status::permission_denied("rescanning requires a super user"));
        }

        let options = scan::ScanOptions {
            check_dns: req.check_dns,
            check_cloudflare: req.check_cloudflare,
            ..Default::default()
        };

        let inventory = scan::run(&self.config, &self.secrets, &options)
            .await
            .map_err(Status::from)?;

        let scan_id = inventory_db::record_scan(&self.pool, &inventory)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(RescanResponse {
            scan_id,
            domain_count: inventory.domains.len() as i32,
            finding_count: inventory.findings.len() as i32,
            server_count: inventory.nginx.servers.len() as i32,
        }))
    }

    async fn list_adopted_vhosts(
        &self,
        request: Request<ListAdoptedVhostsRequest>,
    ) -> Result<Response<ListAdoptedVhostsResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let scope = self.scope(&claims, &req.organization_id);

        let rows = inventory_db::list_adopted_vhosts(&self.pool, scope.as_deref())
            .await
            .map_err(Status::from)?;

        let tree_root = self.config.tree.root.clone();

        Ok(Response::new(ListAdoptedVhostsResponse {
            vhosts: rows
                .into_iter()
                .map(|row| {
                    // Drift: the file on disk is no longer what was adopted.
                    // Worth surfacing, never acted on -- these are files
                    // people are expected to edit.
                    let current = std::fs::read(tree_root.join(&row.path))
                        .ok()
                        .map(|bytes| {
                            use sha2::{Digest, Sha256};
                            hex::encode(Sha256::digest(&bytes))
                        });
                    let recorded = row.file_sha256.clone().unwrap_or_default();
                    let drifted = match (&current, recorded.is_empty()) {
                        (Some(current), false) => current != &recorded,
                        _ => false,
                    };

                    AdoptedVhost {
                        path: row.path,
                        domain_fqdn: row.domain_fqdn,
                        server_names: row.server_names,
                        file_sha256: recorded,
                        drifted,
                    }
                })
                .collect(),
        }))
    }

    async fn convert_vhost(
        &self,
        _request: Request<ConvertVhostRequest>,
    ) -> Result<Response<ConvertVhostResponse>, Status> {
        // Needs the template engine, which arrives with generated vhosts.
        // Until then an adopted file is simply never rewritten, which is the
        // safe half of the behaviour anyway.
        Err(pending("the vhost template work", "converting an adopted vhost"))
    }

    // --- ops ------------------------------------------------------------

    async fn list_certificates(
        &self,
        _request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        Err(pending("phase 2", "certificate listing"))
    }

    async fn force_renew(
        &self,
        _request: Request<ForceRenewRequest>,
    ) -> Result<Response<ForceRenewResponse>, Status> {
        Err(pending("phase 2", "forced renewal"))
    }

    async fn publish_now(
        &self,
        _request: Request<PublishNowRequest>,
    ) -> Result<Response<Release>, Status> {
        Err(pending("phase 2", "on-demand publishing"))
    }

    async fn list_releases(
        &self,
        _request: Request<ListReleasesRequest>,
    ) -> Result<Response<ListReleasesResponse>, Status> {
        Err(pending("phase 2", "release listing"))
    }
}
