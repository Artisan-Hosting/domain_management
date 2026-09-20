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
use artisan_middleware::api::claims::TokenType;
use artisan_middleware::identity::{Action, ResourceType};
use sqlx::MySqlPool;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::auth::AuthClient;
use crate::grpc::authz;
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

    /// Re-checks a step-up token and confirms it belongs to the same person
    /// as the access token that came with it.
    ///
    /// Validity alone is not enough: an ordinary access token is also valid,
    /// so checking only that would let "this costs a fresh password" be
    /// satisfied by pasting the same token twice. `ais_auth` mints
    /// [`TokenType::Elevated`] only after re-checking the password.
    async fn elevated(&self, elevated_token: &str, caller: &Claims) -> Result<(), Status> {
        if elevated_token.is_empty() {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let elevated = self.caller(elevated_token).await?;
        if elevated.kind != TokenType::Elevated {
            return Err(Status::permission_denied(
                "that is an ordinary access token, not an elevated one",
            ));
        }
        if elevated.sub != caller.sub {
            return Err(Status::permission_denied(
                "the elevated token belongs to a different user",
            ));
        }

        Ok(())
    }

    /// Whether the caller may write the runner a domain is being pointed at.
    ///
    /// Asked of `ais_auth`, which resolves the runner to its organization
    /// through its own `runners` table and applies that org's policy and any
    /// grants -- the decision this service cannot make for itself. `Super` is
    /// never org-scoped, so nothing is asked on its behalf.
    ///
    /// `Action::Write` is the same bar Portal uses for editing a runner's
    /// config: pointing a hostname at a runner changes what the world reaches
    /// on it, which is a configuration change in every sense that matters.
    async fn may_write_runner(
        &self,
        claims: &Claims,
        runner_id: &str,
    ) -> Result<authz::RunnerAccess, Status> {
        if claims.role == Role::Super || runner_id.is_empty() {
            return Ok(None);
        }

        let allowed = self
            .auth
            .evaluate_access(claims, ResourceType::Project, runner_id, Action::Write)
            .await
            .map_err(Status::from)?;

        Ok(Some(allowed))
    }
}

/// Marks an RPC whose implementation is still ahead of us, with the phase it
/// belongs to, so a caller gets a straight answer instead of a stub result.
///
/// **Every call site carries an `AUTHZ:` note** saying which check has to be
/// written when the body is. The authorization is the part that is easy to
/// forget once the business logic is the interesting problem, and a stub that
/// grows a body without one is a hole that ships quietly --
/// `authorization_contracts::every_stub_documents_its_authorization` fails the
/// build if a marker goes missing. The notes are the RBAC Phase 6 mapping.
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
        // AUTHZ: Action::Read on ResourceType::Domain. Searching the registry
        // for an unregistered name is not tenant data and may end up needing no
        // scope at all -- but whatever shape it takes, a result set must never
        // reveal that *another* organization already owns a name. Say "taken",
        // never by whom.
        Err(pending("phase 3", "domain search"))
    }

    async fn quote_domain(
        &self,
        _request: Request<QuoteRequest>,
    ) -> Result<Response<QuoteResponse>, Status> {
        // AUTHZ: Action::Read on ResourceType::Domain, scoped to the caller's
        // own organization. A quote is the only price a purchase may be built
        // on, so it is also the first place a caller could be shown someone
        // else's negotiated cost -- keep `markup_percent` application on this
        // side of the wire.
        Err(pending("phase 3", "domain quotes"))
    }

    async fn create_order(
        &self,
        _request: Request<CreateOrderRequest>,
    ) -> Result<Response<OrderCheckout>, Status> {
        // AUTHZ: Action::Purchase on ResourceType::Domain **and** an elevated
        // token (`self.elevated`), not merely a role check -- this is the one
        // action in this service that spends an organization's money, and the
        // GLOBAL policy seed gives `purchase` to Admin and Super only. Charge
        // the caller's own organization; never an org id taken from the
        // request.
        Err(pending("phase 3", "domain orders"))
    }

    async fn get_order(&self, _request: Request<GetOrderRequest>) -> Result<Response<Order>, Status> {
        // AUTHZ: Action::Read on ResourceType::Domain, and the order's owning
        // organization must match `authz::scope` -- an order id is guessable,
        // so "knows the id" cannot be the check.
        Err(pending("phase 3", "domain orders"))
    }

    async fn list_orders(
        &self,
        _request: Request<ListOrdersRequest>,
    ) -> Result<Response<ListOrdersResponse>, Status> {
        // AUTHZ: Action::Read, filtered through `authz::scope` exactly like
        // ListInventory -- non-Super callers only ever see their own
        // organization's orders, whatever organization_id they ask for.
        Err(pending("phase 3", "domain orders"))
    }

    /// Stripe calling in, not a user. See the AUTHZ note inside: this one is
    /// deliberately *not* a Claims/RBAC call.
    async fn handle_stripe_webhook(
        &self,
        _request: Request<StripeWebhookRequest>,
    ) -> Result<Response<StripeWebhookResponse>, Status> {
        // AUTHZ: **not** evaluate_access, and not a token at all. The caller is
        // Stripe, and the only thing that authenticates it is an HMAC of the
        // raw request body against `secrets.stripe_webhook_secret`, compared in
        // constant time, with the timestamp checked for replay. Portal forwards
        // the body and Stripe-Signature header untouched precisely so the
        // signature still verifies here. A domain must never be registered
        // because a browser said a payment succeeded.
        Err(pending("phase 3", "Stripe webhooks"))
    }

    // --- lifecycle (phase 2) --------------------------------------------

    async fn add_domain(
        &self,
        _request: Request<AddDomainRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        // AUTHZ: a BYO domain is claimed, not created, so proving control of
        // the name is half the check -- the DNS probe gates the record, and
        // Action::Write on ResourceType::Domain (plus `authz::may_write_domain`
        // once a row exists) gates the caller. Stamp organization_id from the
        // caller's own claims, never from the request.
        Err(pending("phase 2", "adding a domain"))
    }

    async fn get_domain(&self, _request: Request<GetDomainRequest>) -> Result<Response<Domain>, Status> {
        // AUTHZ: Action::Read, then `authz::scope` on the row that comes back
        // -- an fqdn is public knowledge, so the lookup succeeding must not be
        // what decides whether the caller may see the record.
        Err(pending("phase 2", "reading a domain"))
    }

    async fn list_domains(
        &self,
        _request: Request<ListDomainsRequest>,
    ) -> Result<Response<ListDomainsResponse>, Status> {
        // AUTHZ: `authz::scope`, same as ListInventory.
        Err(pending("phase 2", "listing domains"))
    }

    async fn remove_domain(
        &self,
        _request: Request<RemoveDomainRequest>,
    ) -> Result<Response<RemoveDomainResponse>, Status> {
        // AUTHZ: `authz::may_write_domain` with Action::Delete on the runner,
        // and an elevated token: removing a domain takes a live site off the
        // internet and frees a name someone else can then claim.
        Err(pending("phase 2", "removing a domain"))
    }

    async fn verify_domain_now(
        &self,
        _request: Request<VerifyDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        // AUTHZ: Action::Read via `authz::may_write_domain`'s ownership half --
        // a probe is read-only, but it is also a way to ask this service to
        // make outbound DNS queries, so it stays scoped to the caller's own
        // domains rather than being open to any authenticated user.
        Err(pending("phase 2", "on-demand DNS verification"))
    }

    type WatchDomainStream =
        Pin<Box<dyn Stream<Item = Result<DomainEvent, Status>> + Send + 'static>>;

    async fn watch_domain(
        &self,
        _request: Request<WatchDomainRequest>,
    ) -> Result<Response<Self::WatchDomainStream>, Status> {
        // AUTHZ: Action::Read on the domain before the stream opens, and again
        // if the domain is reassigned mid-stream -- a long-lived stream must not
        // outlive the permission that opened it.
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

        // Attaching points a hostname at a runner, so it takes permission on
        // both ends: the domain record (this service's own row) and the runner
        // the traffic will land on (ais_auth's decision). Neither the caller's
        // role nor their membership of the owning org is sufficient by itself
        // -- see `grpc::authz`.
        let runner = self.may_write_runner(&claims, &req.runner_id).await?;
        authz::may_write_domain(
            claims.role,
            &claims.organization_id,
            existing.organization_id.as_deref(),
            runner,
        )
        .map_err(|denial| denial.into_status(&existing.fqdn))?;

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
        // AUTHZ: the same two-ended check as attach_domain -- `may_write_runner`
        // on the runner being detached from, and `authz::may_write_domain` on
        // the record.
        Err(pending("phase 2", "detaching a domain"))
    }

    // --- members (phase 3) ----------------------------------------------

    async fn invite_domain_member(
        &self,
        _request: Request<InviteDomainMemberRequest>,
    ) -> Result<Response<DomainMember>, Status> {
        // AUTHZ: Action::Grant on ResourceType::Domain -- handing someone
        // Cloudflare access to a zone is delegating authority over it, which is
        // a grant, not a write. Elevated token, and only ever for a zone the
        // caller's own organization owns.
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    async fn list_domain_members(
        &self,
        _request: Request<ListDomainMembersRequest>,
    ) -> Result<Response<ListDomainMembersResponse>, Status> {
        // AUTHZ: Action::Read on the owning domain. The member list is a list
        // of people's email addresses -- scoped to the owning org, never fleet
        // -wide.
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    async fn remove_domain_member(
        &self,
        _request: Request<RemoveDomainMemberRequest>,
    ) -> Result<Response<RemoveDomainMemberResponse>, Status> {
        // AUTHZ: Action::Grant on the owning domain, as for the invite.
        Err(pending("phase 3", "Cloudflare zone invites"))
    }

    // --- adoption and attachment ----------------------------------------

    async fn assign_domain(
        &self,
        request: Request<AssignDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        // The runner this assignment would point the domain at, if it names
        // one -- the caller has to be allowed to write it, exactly as for
        // AttachDomain.
        let runner = if req.clear_runner {
            None
        } else {
            self.may_write_runner(&claims, &req.runner_id).await?
        };
        authz::may_write_domain(
            claims.role,
            &claims.organization_id,
            existing.organization_id.as_deref(),
            runner,
        )
        .map_err(|denial| denial.into_status(&existing.fqdn))?;

        // Claiming a domain *into* an organization is separate from being
        // allowed to change it: a non-Super may only ever assign into their
        // own. (Reaching an unassigned domain at all is already Super-only.)
        if claims.role != Role::Super
            && authz::real_org(&req.organization_id).is_some()
            && authz::real_org(&req.organization_id) != authz::real_org(&claims.organization_id)
        {
            return Err(Status::permission_denied(
                "you can only assign domains to your own organization",
            ));
        }

        // Moving a domain that already belongs to someone is the one case
        // that costs a fresh password: it takes a name away from one tenant
        // and gives it to another.
        if authz::is_org_move(
            existing.organization_id.as_deref(),
            &req.organization_id,
            req.clear_org,
        ) {
            self.elevated(&req.elevated_token, &claims).await.map_err(|err| {
                Status::permission_denied(format!(
                    "moving {} between organizations: {}",
                    existing.fqdn,
                    err.message()
                ))
            })?;
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
        let scope = authz::scope(claims.role, &claims.organization_id, &req.organization_id)?;

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
        // whole host -- every tenant's, in one list, with no organization to
        // filter them by. That is a platform operator's view, the same bar as
        // RescanInventory; an org-scoped Admin is not one.
        if claims.role != Role::Super {
            return Err(Status::permission_denied("reading findings requires a super user"));
        }

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
        let scope = authz::scope(claims.role, &claims.organization_id, &req.organization_id)?;

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
        //
        // AUTHZ: `authz::may_write_domain` plus `may_write_runner`, as for
        // attach_domain -- converting rewrites a file that is currently serving
        // live traffic, so it is a write on both ends, and it must keep
        // `VhostOutcome::HandWritten`'s refusal to clobber a hand-written file.
        Err(pending("the vhost template work", "converting an adopted vhost"))
    }

    // --- ops ------------------------------------------------------------

    async fn list_certificates(
        &self,
        _request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        // AUTHZ: `authz::scope` -- a certificate's SANs name every site it
        // serves, so an unscoped list is a map of the whole estate.
        Err(pending("phase 2", "certificate listing"))
    }

    async fn force_renew(
        &self,
        _request: Request<ForceRenewRequest>,
    ) -> Result<Response<ForceRenewResponse>, Status> {
        // AUTHZ: `authz::may_write_domain` with no runner in play (so: Super, or
        // an Admin of the owning org). Rate limits are per registered domain
        // per week and are shared by every tenant on a zone, so an unscoped
        // force-renew is a denial of service against everyone else's renewals.
        Err(pending("phase 2", "forced renewal"))
    }

    async fn publish_now(
        &self,
        _request: Request<PublishNowRequest>,
    ) -> Result<Response<Release>, Status> {
        // AUTHZ: Super only, like RescanInventory. A release is the whole
        // nginx tree -- every tenant's vhosts in one artifact -- so there is no
        // per-org version of this action, and `publish.shadow_mode` must still
        // be honoured.
        Err(pending("phase 2", "on-demand publishing"))
    }

    async fn list_releases(
        &self,
        _request: Request<ListReleasesRequest>,
    ) -> Result<Response<ListReleasesResponse>, Status> {
        // AUTHZ: Super only, for the same reason as publish_now.
        Err(pending("phase 2", "release listing"))
    }
}

/// The stubbed RPCs are a deliberate, documented state -- not an oversight.
///
/// These tests exist so that stays true: the first one fails if a stub grows a
/// body without its authorization check being written (RBAC Phase 6's whole
/// point), and the second fails the moment a stub starts answering, forcing
/// whoever implements it to come back and state what it now does.
#[cfg(test)]
mod authorization_contracts {
    use super::*;
    use std::path::Path;
    use tonic::Code;

    /// Every `pending()` call site carries an `AUTHZ:` note within the handful
    /// of lines above it.
    #[test]
    fn every_stub_documents_its_authorization() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/grpc/service.rs");
        let source = std::fs::read_to_string(&path).expect("read service.rs");
        // Only the handlers: everything from `#[cfg(test)]` down is this module
        // talking about itself.
        let source = source.split("#[cfg(test)]").next().unwrap_or_default();
        let lines: Vec<&str> = source.lines().collect();

        let mut undocumented = Vec::new();
        let mut call_sites = 0;
        for (n, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            // A call, not the definition and not prose about it.
            if code.starts_with("//") || code.starts_with("fn pending(") || !code.contains("pending(")
            {
                continue;
            }
            call_sites += 1;

            // Back to the top of *this* handler, never further: a fixed-size
            // window lets one stub borrow the note belonging to the one above
            // it, which is exactly the mistake this test exists to catch.
            let start = lines[..n]
                .iter()
                .rposition(|above| above.contains("async fn "))
                .map(|at| at + 1)
                .unwrap_or(0);
            if !lines[start..n].iter().any(|above| above.contains("AUTHZ:")) {
                undocumented.push(format!("{}: {}", n + 1, line.trim()));
            }
        }

        assert!(call_sites >= 20, "expected the stubs to still be here, found {call_sites}");
        assert!(
            undocumented.is_empty(),
            "these stubs do not say what authorization they will need:\n{}",
            undocumented.join("\n")
        );
    }

    fn service() -> Domains {
        // Nothing here touches the database or ais_auth: every stub returns
        // before it reads `self`. A lazy pool and an unreachable auth address
        // are therefore enough, and keep this a unit test.
        let secrets = Secrets::load(Some(Path::new("/nonexistent/ais_domains.env")))
            .expect("a missing env file is not fatal");
        let pool = sqlx::MySqlPool::connect_lazy("mysql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");

        let mut config = Config::default();
        // Plaintext, so building the client needs no certificate on disk. The
        // address is never dialled: `connect_lazy` only registers with the
        // reactor, and no test here gets far enough to make a call.
        config.auth.grpc_addr = "http://127.0.0.1:1".to_owned();

        Domains::new(config, secrets, pool).expect("service")
    }

    macro_rules! assert_still_a_stub {
        ($service:expr, $method:ident, $request:ty) => {{
            let outcome = $service.$method(Request::new(<$request>::default())).await;
            let status = outcome.err().unwrap_or_else(|| {
                panic!(concat!(
                    stringify!($method),
                    " answers now -- write its AUTHZ check (see the note above its \
                     `pending()` call), then update this test"
                ))
            });
            assert_eq!(
                status.code(),
                Code::Unimplemented,
                concat!(stringify!($method), ": {}"),
                status.message()
            );
            assert!(
                !status.message().is_empty(),
                concat!(stringify!($method), " must say which phase it lands in")
            );
        }};
    }

    #[tokio::test]
    async fn the_unimplemented_rpcs_say_so_rather_than_answering() {
        let service = service();

        // Purchasing: the money path. Nothing here may work before its
        // Action::Purchase + elevated-token check exists.
        assert_still_a_stub!(service, search_domains, SearchRequest);
        assert_still_a_stub!(service, quote_domain, QuoteRequest);
        assert_still_a_stub!(service, create_order, CreateOrderRequest);
        assert_still_a_stub!(service, get_order, GetOrderRequest);
        assert_still_a_stub!(service, list_orders, ListOrdersRequest);
        assert_still_a_stub!(service, handle_stripe_webhook, StripeWebhookRequest);

        // Lifecycle.
        assert_still_a_stub!(service, add_domain, AddDomainRequest);
        assert_still_a_stub!(service, get_domain, GetDomainRequest);
        assert_still_a_stub!(service, list_domains, ListDomainsRequest);
        assert_still_a_stub!(service, remove_domain, RemoveDomainRequest);
        assert_still_a_stub!(service, verify_domain_now, VerifyDomainRequest);
        assert_still_a_stub!(service, watch_domain, WatchDomainRequest);
        assert_still_a_stub!(service, detach_domain, DetachDomainRequest);

        // Cloudflare account members.
        assert_still_a_stub!(service, invite_domain_member, InviteDomainMemberRequest);
        assert_still_a_stub!(service, list_domain_members, ListDomainMembersRequest);
        assert_still_a_stub!(service, remove_domain_member, RemoveDomainMemberRequest);

        // Vhost conversion and ops.
        assert_still_a_stub!(service, convert_vhost, ConvertVhostRequest);
        assert_still_a_stub!(service, list_certificates, ListCertificatesRequest);
        assert_still_a_stub!(service, force_renew, ForceRenewRequest);
        assert_still_a_stub!(service, publish_now, PublishNowRequest);
        assert_still_a_stub!(service, list_releases, ListReleasesRequest);
    }

    /// An empty access token is rejected before anything else happens, on the
    /// RPCs that *are* implemented -- the one check that must never depend on
    /// reaching ais_auth.
    #[tokio::test]
    async fn an_implemented_rpc_refuses_an_empty_token_without_calling_ais_auth() {
        let service = service();

        let status = service
            .list_inventory(Request::new(ListInventoryRequest::default()))
            .await
            .err()
            .expect("no token is not a valid request");
        assert_eq!(status.code(), Code::Unauthenticated, "{}", status.message());
    }
}
