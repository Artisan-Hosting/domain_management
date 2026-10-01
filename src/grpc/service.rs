//! `DomainService` implementation.
//!
//! Handlers here stay thin on purpose: authorize, then read or write the
//! database. What happens after that authorization check splits along one
//! line, and it isn't "does this call Cloudflare" -- several handlers below
//! do (`create_dns_record`, `update_dns_record`, `delete_dns_record`,
//! and eventually `add_domain`'s BYO path) and still run synchronously,
//! inline in the RPC. The line is **can this be retried for free**:
//!
//! * A single Cloudflare DNS record write, or
//!   [`crate::cloudflare::dns::ensure_challenge_cname`]'s upsert, costs
//!   nothing to fail and retry -- there is no partial state to clean up and
//!   nothing it does spends money. Those run inline, and the RPC's own
//!   error is the retry signal: the caller sees a failed call and tries
//!   again, same as any other request.
//! * Registering a domain through Cloudflare Registrar is the opposite: it
//!   spends money, can take real wall-clock time, and running it twice
//!   because a request was retried or an RPC got cancelled mid-flight means
//!   charging twice. That work is a `jobs` row, claimed and retried by the
//!   worker described in [the crate root doc][crate] (subsystem 3), never
//!   run from inside a handler here.
//!
//! Phase 1 is the script-parity work (issuance and publishing); the RPCs that
//! are not wired yet return `unimplemented` rather than pretending. See each
//! stub's `AUTHZ:` comment for the authorization it will need once its body
//! is written -- those notes are RBAC Phase 6's mapping, meant to be reused
//! verbatim rather than re-derived.

use artisan_middleware::api::claims::Claims;
use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use artisan_middleware::api::roles::Role;
use artisan_middleware::api::claims::TokenType;
use artisan_middleware::identity::{Action, ResourceType};
use sqlx::{MySqlPool, Row};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::acme::KeyType;
use crate::auth::AuthClient;
use crate::billing::BillingClient;
use crate::dns::probe::Probe;
use crate::grpc::authz;
use crate::config::{Config, Secrets};
use crate::db::dns_records as dns_records_db;
use crate::db::domains as domains_db;
use crate::db::inventory as inventory_db;
use crate::db::orders as orders_db;
use crate::db::reserved as reserved_db;
use crate::db::releases as releases_db;
use crate::inventory::scan;
use crate::purchasing;
use crate::proto::domains::*;
use crate::proto::domains::domain_service_server::DomainService;

pub struct Domains {
    config: Config,
    secrets: Secrets,
    pool: MySqlPool,
    auth: AuthClient,
    billing: BillingClient,
}

/// The vhost options only `AttachDomain` exposes; `AddDomain` passes none.
#[derive(Default)]
struct VhostExtras {
    extra_headers: Vec<crate::vhost::render::HeaderEntry>,
    cors: Option<crate::vhost::render::CorsPolicy>,
    extra_locations: Vec<crate::vhost::render::ExtraLocation>,
}

impl Domains {
    /// The Stripe charge behind `order`, and what the browser needs to pay it.
    /// Safe to call any number of times for the same order: Billing creates
    /// the PaymentIntent once per `(consumer, order id)` and returns the same
    /// one after that, but only hands out its client secret on creation -- so
    /// a repeat asks for it again. (The stored intent id is written here too,
    /// which also repairs an order whose first attempt died between creating
    /// the intent and recording it.)
    async fn checkout_for(&self, order: crate::db::orders::OrderRow) -> Result<Response<OrderCheckout>, Status> {
        let order_ref = order.id.to_string();
        let mut payment_intent = self
            .billing
            .create_payment_intent(
                "domain_management",
                &order_ref,
                order.price_cents,
                &order.currency.to_lowercase(),
                &[("fqdn", order.fqdn.as_str()), ("organization_id", order.organization_id.as_str())],
            )
            .await
            .map_err(Status::from)?;

        if order.stripe_payment_intent_id.as_deref() != Some(payment_intent.stripe_payment_intent_id.as_str()) {
            orders_db::set_payment_intent(&self.pool, order.id, &payment_intent.stripe_payment_intent_id)
                .await
                .map_err(Status::from)?;
        }

        if payment_intent.client_secret.is_empty() {
            payment_intent = self
                .billing
                .get_payment_intent_for_checkout(&format!("domain_management:{order_ref}"))
                .await
                .map_err(Status::from)?;
        }

        let order = orders_db::find_order(&self.pool, order.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("order vanished mid-checkout"))?;

        Ok(Response::new(OrderCheckout {
            order: Some(order_response(order)),
            stripe_client_secret: payment_intent.client_secret,
            stripe_publishable_key: payment_intent.publishable_key,
        }))
    }

    /// A second submit of a quote that already produced an order. Still
    /// waiting for payment: hand back the same checkout. Anything else: say
    /// what became of it, because the quote cannot be used again.
    async fn resume_order(&self, order: crate::db::orders::OrderRow) -> Result<Response<OrderCheckout>, Status> {
        if order.state == "awaiting_payment" {
            return self.checkout_for(order).await;
        }
        Err(Status::failed_precondition(format!(
            "this quote already produced order {} ({}); request a new quote to try again",
            order.id, order.state
        )))
    }
}

impl Domains {
    pub fn new(config: Config, secrets: Secrets, pool: MySqlPool) -> Result<Self, crate::error::Error> {
        let auth = AuthClient::new(&config.auth.grpc_addr)?;
        let billing = BillingClient::new(&config.billing.grpc_addr)?;
        Ok(Self { config, secrets, pool, auth, billing })
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

    /// Records what a successful freeform apply (whether reached through
    /// `ApplyFreeformVhost` directly or via `ConvertVhost`) wrote, so a later
    /// re-validate/re-apply can diff against what is actually on disk.
    async fn record_freeform_apply(
        &self,
        domain_id: u64,
        fqdn: &str,
        body: &str,
        applied_by: &str,
    ) -> Result<(), Status> {
        let source_path = self
            .config
            .vhost_path_for(fqdn)
            .strip_prefix(&self.config.tree.root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(body.as_bytes()))
        };
        crate::db::freeform::record_apply(&self.pool, domain_id, &source_path, body, &sha256, Some(applied_by))
            .await
            .map_err(Status::from)
    }

    /// The grant-tier half of a domain-scoped write. `evaluate_access` can
    /// only ever say yes for a `Domain` resource by way of an explicit
    /// grant -- it cannot resolve a domain to an organization the way it
    /// resolves a `Project` -- so this is always used *alongside*
    /// `authz::may_write_domain`'s org-ownership half, never instead of it.
    /// `Super` bypasses the round trip entirely, same as everywhere else.
    async fn require_domain_grant(&self, claims: &Claims, domain_id: u64, action: Action) -> Result<(), Status> {
        if claims.role == Role::Super {
            return Ok(());
        }

        let allowed = self
            .auth
            .evaluate_access(claims, ResourceType::Domain, &domain_id.to_string(), action)
            .await
            .map_err(Status::from)?;

        if !allowed {
            return Err(Status::permission_denied("not permitted for this domain"));
        }

        Ok(())
    }

    /// Adds a hostname under a domain we already hold.
    ///
    /// DNS is written through Cloudflare when we hold the zone, and the vhost
    /// when instances were given. Anything we cannot or should not do falls
    /// back to instructions, with the reason, rather than failing the request:
    /// the name is still recorded and the caller still learns what is left.
    async fn add_subdomain(
        &self,
        claims: &Claims,
        req: &AddDomainRequest,
        fqdn: &str,
        parent: &inventory_db::InventoryRow,
        org: Option<String>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        // Covered by a certificate we already hold: nothing to issue, and no
        // challenge record needed. Otherwise it needs its own.
        let covered = inventory_db::has_certificate(&self.pool, parent.id)
            .await
            .map_err(Status::from)?;
        let records = crate::intake::required_records(&self.config, fqdn, !covered)?;

        let mut notes = vec![format!("{fqdn} is under {}, which is already managed.", parent.fqdn)];
        if covered {
            notes.push(format!("It is covered by {}'s certificate; nothing to issue.", parent.fqdn));
        }

        let (zone_id, written) = self.write_dns(fqdn, &records, &mut notes).await;

        inventory_db::insert_domain(
            &self.pool,
            &inventory_db::NewDomain {
                fqdn,
                organization_id: org.as_deref(),
                runner_id: (!req.runner_id.is_empty()).then_some(req.runner_id.as_str()),
                source: "byo",
                status: if written { "provisioning_dns" } else { "pending_dns" },
                challenge_target: &self.config.challenge_target_for(fqdn),
                cf_zone_id: zone_id.as_deref(),
                parent_id: Some(parent.id),
                created_by: Some(&claims.sub),
            },
        )
        .await
        .map_err(Status::from)?;

        let mut vhost = false;
        if !req.backends.is_empty() {
            let row = inventory_db::find_domain(&self.pool, fqdn)
                .await
                .map_err(Status::from)?
                .ok_or_else(|| Status::internal("domain vanished mid-add"))?;
            match self
                .write_vhost(&row, &req.runner_id, req.backends.clone(), req.extra_names.clone(), req.no_http_redirect, VhostExtras::default())
                .await
            {
                Ok(()) => {
                    vhost = true;
                    notes.push("The nginx vhost was written and passed nginx -t.".to_owned());
                }
                // The name and its DNS are already recorded; a vhost that could
                // not be written (a certificate still to issue, nginx refusing
                // it) is reported, and AttachDomain retries it.
                Err(status) => notes.push(format!(
                    "The vhost was not written ({}); attach the domain again once that is resolved.",
                    status.message()
                )),
            }
        }

        let outcome = if written {
            AddDomainOutcome::Provisioned
        } else {
            AddDomainOutcome::NeedsDns
        };
        // Only what is still to do goes back as instructions.
        let outstanding = if written { Vec::new() } else { records };

        self.add_domain_response(fqdn, outcome, notes, outstanding, vhost).await
    }

    /// The free zone, or a precondition failure when the operator has not turned it on.
    fn free_zone(&self) -> Result<String, Status> {
        let zone = self.config.free_zone.zone.trim().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Status::failed_precondition("free addresses are not turned on"));
        }
        Ok(zone)
    }

    /// `(fqdn, why it cannot be claimed)` for a name a customer typed. Shape first, then the operator's
    /// reservations, then whether somebody already holds it.
    async fn free_name_problem(&self, zone: &str, name: &str) -> Result<(String, Option<String>), Status> {
        let label = match crate::reserved::free_label(name) {
            Ok(label) => label,
            Err(why) => return Ok((format!("{}.{zone}", name.trim().to_ascii_lowercase()), Some(why))),
        };
        let fqdn = format!("{label}.{zone}");

        let rules = reserved_db::rules(&self.pool).await.map_err(Status::from)?;
        if crate::reserved::reserved_by(&rules, &label).is_some() {
            return Ok((fqdn, Some("that name is reserved".to_owned())));
        }
        let taken = inventory_db::find_domain(&self.pool, &fqdn)
            .await
            .map_err(Status::from)?
            .is_some_and(|row| row.status != "removed");
        if taken {
            return Ok((fqdn, Some("that name is already taken".to_owned())));
        }
        Ok((fqdn, None))
    }

    /// Writes the DNS records into the zone we hold for `fqdn`, if we hold one.
    ///
    /// Returns the zone id and whether everything is now in place. Never
    /// overwrites: see [`crate::intake::plan_dns`]. Every reason it did not
    /// write is added to `notes`.
    async fn write_dns(
        &self,
        fqdn: &str,
        records: &[crate::intake::RecordSpec],
        notes: &mut Vec<String>,
    ) -> (Option<String>, bool) {
        use crate::cloudflare::{CfSuite, dns, zones};

        let cf = match CfSuite::new(&self.config, &self.secrets) {
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

    async fn add_domain_response(
        &self,
        fqdn: &str,
        outcome: AddDomainOutcome,
        notes: Vec<String>,
        records: Vec<crate::intake::RecordSpec>,
        has_vhost: bool,
    ) -> Result<Response<AddDomainResponse>, Status> {
        let row = inventory_db::find_domain(&self.pool, fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-add"))?;

        Ok(Response::new(AddDomainResponse {
            domain: Some(Domain {
                id: row.id.to_string(),
                fqdn: row.fqdn,
                organization_id: row.organization_id.unwrap_or_default(),
                runner_id: row.runner_id.unwrap_or_default(),
                source: source_code(&row.source),
                status: status_code(&row.status),
                expires_at: row.expires_at.unwrap_or_default(),
                has_vhost,
                parent_fqdn: row.parent_fqdn.unwrap_or_default(),
                ..Default::default()
            }),
            required_records: records
                .into_iter()
                .map(|r| RequiredRecord {
                    r#type: r.record_type.to_owned(),
                    name: r.name,
                    content: r.content,
                    note: r.note,
                })
                .collect(),
            outcome: outcome as i32,
            notes,
        }))
    }

    /// A host with no certificate of its own is served from its parent's.
    ///
    /// Own certificate first: a host someone gave a dedicated certificate must
    /// keep using it, and switching it to the wildcard because a parent
    /// exists would change what its visitors are shown.
    fn cert_zone_for(&self, domain: &inventory_db::InventoryRow) -> Option<String> {
        domain
            .parent_fqdn
            .clone()
            .filter(|_| !self.config.cert_dir_for(&domain.fqdn).exists())
    }

    /// Renders and installs the vhost for a domain, records it, and points the
    /// domain at the runner. The caller has already been authorized on both
    /// the domain and the runner.
    async fn write_vhost(
        &self,
        existing: &inventory_db::InventoryRow,
        runner_id: &str,
        backends: Vec<Backend>,
        extra_names: Vec<String>,
        no_http_redirect: bool,
        extras: VhostExtras,
    ) -> Result<(), Status> {
        let backends = backends.into_iter().map(backend_from_proto).collect::<Result<Vec<_>, Status>>()?;
        let mut spec = crate::vhost::render::VhostSpec::new(&existing.fqdn, runner_id, backends);
        spec.extra_names = extra_names;
        spec.http_redirect = !no_http_redirect;
        spec.cert_zone = self.cert_zone_for(existing);
        spec.extra_headers = extras.extra_headers;
        spec.cors = extras.cors;
        spec.extra_locations = extras.extra_locations;

        let outcome = crate::vhost::attach(&self.config, &spec).await?;

        let server_names = spec.server_names();
        inventory_db::record_generated_vhost(
            &self.pool,
            existing.id,
            runner_id,
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

        inventory_db::set_assignment(&self.pool, existing.id, None, Some(Some(runner_id.to_owned())))
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

        Ok(())
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

fn require_super(role: Role, what: &str) -> Result<(), Status> {
    if role != Role::Super {
        return Err(Status::permission_denied(format!("{what} requires a super user")));
    }
    Ok(())
}

fn reserved_rule_from_request(req: &AddReservedNameRequest) -> Result<crate::reserved::Rule, Status> {
    use crate::reserved::Rule;
    let prefix = req.prefix.trim().to_owned();
    let rule = match req.kind.as_str() {
        "exact" => Rule::Exact(prefix),
        "prefix" => Rule::Prefix(prefix),
        "range" => Rule::Range {
            prefix,
            digits: u8::try_from(req.digits).map_err(|_| Status::invalid_argument("digits must be between 1 and 18"))?,
            min: u64::try_from(req.min_value).map_err(|_| Status::invalid_argument("min_value must not be negative"))?,
            max: u64::try_from(req.max_value).map_err(|_| Status::invalid_argument("max_value must not be negative"))?,
        },
        other => return Err(Status::invalid_argument(format!("kind must be exact, prefix or range, not {other:?}"))),
    };
    rule.validate().map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(rule)
}

fn reserved_response(row: reserved_db::ReservedRow) -> ReservedName {
    use crate::reserved::Rule;
    let (kind, prefix, digits, min, max) = match row.rule {
        Rule::Exact(s) => ("exact", s, 0, 0, 0),
        Rule::Prefix(s) => ("prefix", s, 0, 0, 0),
        Rule::Range { prefix, digits, min, max } => ("range", prefix, i32::from(digits), min, max),
    };
    ReservedName {
        id: row.id as i64,
        kind: kind.to_owned(),
        prefix,
        digits,
        min_value: min as i64,
        max_value: max as i64,
        note: row.note,
        created_by: row.created_by.unwrap_or_default(),
        created_at: row.created_at,
    }
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

/// A wire `Backend` selects the node-id or static form by which field is
/// non-empty. Exactly one of `node_id`/`host` may be set -- ambiguity here
/// would otherwise silently prefer one form over the other.
fn backend_from_proto(backend: crate::proto::domains::Backend) -> Result<crate::vhost::render::Backend, Status> {
    let has_node = !backend.node_id.is_empty();
    let has_host = !backend.host.is_empty();

    match (has_node, has_host) {
        (true, true) => Err(Status::invalid_argument(
            "a backend must set exactly one of node_id or host, not both",
        )),
        (false, false) => Err(Status::invalid_argument("a backend must set node_id or host")),
        (true, false) => {
            // A port is a u16 on the wire's u32; anything above that is a
            // caller bug, not something to truncate silently.
            let port = u16::try_from(backend.port)
                .map_err(|_| Status::invalid_argument(format!("port {} does not fit in u16", backend.port)))?;
            Ok(crate::vhost::render::Backend::Node { node_id: backend.node_id, port })
        }
        (false, true) => {
            let port = u16::try_from(backend.port)
                .map_err(|_| Status::invalid_argument(format!("port {} does not fit in u16", backend.port)))?;
            Ok(crate::vhost::render::Backend::Static {
                host: backend.host,
                port,
                tls: backend.tls,
                insecure_skip_verify: backend.insecure_skip_verify,
            })
        }
    }
}

fn freeform_response(outcome: crate::vhost::freeform::ValidateOutcome) -> ValidateFreeformVhostResponse {
    ValidateFreeformVhostResponse {
        nginx_ok: outcome.nginx_ok,
        nginx_output: outcome.nginx_output,
        new_findings: outcome
            .new_findings
            .into_iter()
            .map(|f| FreeformLintFinding { code: f.code, severity: f.severity, message: f.message })
            .collect(),
        corrected: outcome.corrected,
    }
}

fn dns_record_response(row: crate::db::dns_records::DnsRecordRow) -> DnsRecordEntry {
    DnsRecordEntry {
        id: row.id.to_string(),
        cf_record_id: row.cf_record_id,
        r#type: row.record_type,
        name: row.name,
        content: row.content,
        ttl: row.ttl,
        proxied: row.proxied,
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

fn key_type_code(key_type: &str) -> i32 {
    match key_type {
        "ecc" => KeyType::Ecc as i32,
        "rsa" => KeyType::Rsa as i32,
        _ => 0,
    }
}

fn cert_response(domain_id: u64, row: domains_db::CertRow) -> Certificate {
    Certificate {
        domain_id: domain_id.to_string(),
        key_type: key_type_code(&row.key_type),
        serial: row.serial.unwrap_or_default(),
        not_before: row.not_before.unwrap_or(0),
        not_after: row.not_after.unwrap_or(0),
        renew_after: row.renew_after.unwrap_or(0),
        fail_count: row.fail_count,
        last_error: row.last_error.unwrap_or_default(),
    }
}

/// The common fields every lifecycle handler (`AddDomain`, `RemoveDomain`,
/// `VerifyDomainNow`, `DetachDomain`, ...) returns. `GetDomain` alone also
/// attaches certificates and managed records -- see its own handler --
/// mirroring how `attach_domain`/`assign_domain` already return a Domain
/// with those left empty rather than joining them on every write.
fn domain_response(row: &domains_db::DomainRow) -> Domain {
    Domain {
        id: row.id.to_string(),
        fqdn: row.fqdn.clone(),
        organization_id: row.organization_id.clone().unwrap_or_default(),
        runner_id: row.runner_id.clone().unwrap_or_default(),
        source: source_code(&row.source),
        status: status_code(&row.status),
        cf_zone_id: row.cf_zone_id.clone().unwrap_or_default(),
        challenge_target: row.challenge_target.clone(),
        expires_at: row.expires_at.unwrap_or(0),
        auto_renew: row.auto_renew,
        last_error: row.last_error.clone().unwrap_or_default(),
        created_at: row.created_at,
        updated_at: row.updated_at,
        has_vhost: row.has_vhost,
        ..Default::default()
    }
}

/// The inverse of `status_code`, for filtering `ListDomains` by the proto
/// enum a caller sent in.
fn status_db_value(status: DomainStatus) -> &'static str {
    match status {
        DomainStatus::PendingPayment => "pending_payment",
        DomainStatus::Registering => "registering",
        DomainStatus::ProvisioningDns => "provisioning_dns",
        DomainStatus::PendingDns => "pending_dns",
        DomainStatus::Issuing => "issuing",
        DomainStatus::Active => "active",
        DomainStatus::Renewing => "renewing",
        DomainStatus::Error => "error",
        DomainStatus::Removed => "removed",
        DomainStatus::Unspecified => "",
    }
}

fn member_status_code(status: &str) -> i32 {
    match status {
        "pending" => MemberStatus::Pending as i32,
        "accepted" => MemberStatus::Accepted as i32,
        "removed" => MemberStatus::Removed as i32,
        _ => MemberStatus::Unspecified as i32,
    }
}

fn order_state_code(state: &str) -> i32 {
    match state {
        "awaiting_payment" => OrderState::AwaitingPayment as i32,
        "paid" => OrderState::Paid as i32,
        "registering" => OrderState::Registering as i32,
        "completed" => OrderState::Completed as i32,
        "refunded" => OrderState::Refunded as i32,
        "failed" => OrderState::Failed as i32,
        "needs_admin" => OrderState::NeedsAdmin as i32,
        _ => OrderState::Unspecified as i32,
    }
}

fn order_response(row: orders_db::OrderRow) -> Order {
    Order {
        id: row.id.to_string(),
        fqdn: row.fqdn,
        organization_id: row.organization_id,
        user_id: row.user_id,
        cost: Some(Money { amount_cents: row.cost_cents, currency: row.currency.clone() }),
        price: Some(Money { amount_cents: row.price_cents, currency: row.currency }),
        state: order_state_code(&row.state),
        cf_workflow_state: row.cf_workflow_state.unwrap_or_default(),
        stripe_payment_intent_id: row.stripe_payment_intent_id.unwrap_or_default(),
        domain_id: row.domain_id.map(|id| id.to_string()).unwrap_or_default(),
        last_error: row.last_error.unwrap_or_default(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// A Cloudflare search/check result to this service's own `DomainOffer`,
/// collapsing every reason a name isn't sellable (Cloudflare says taken,
/// the TLD isn't one we sell, pricing is missing or unparseable, or it
/// would exceed our own price cap) to the same `registrable: false` shape
/// -- see `search_domains`'s own doc comment for why that collapsing
/// matters.
fn domain_offer(availability: crate::cloudflare::registrar::DomainAvailability, pricing: &crate::config::Pricing) -> DomainOffer {
    let tier = availability.tier.clone().unwrap_or_default();
    let unsellable = |reason: &str| DomainOffer {
        fqdn: availability.name.clone(),
        registrable: false,
        reason: reason.to_owned(),
        tier: tier.clone(),
        price: None,
    };

    if !availability.registrable {
        return unsellable("");
    }
    if !purchasing::tld_allowed(&availability.name, pricing) {
        return unsellable("not a supported extension");
    }
    let Some(cf_pricing) = &availability.pricing else {
        return unsellable("no pricing available");
    };
    let Ok(cost_cents) = cf_pricing.registration_cost_cents() else {
        return unsellable("pricing unavailable");
    };
    match purchasing::price_for(cost_cents, pricing) {
        Ok(price_cents) => DomainOffer {
            fqdn: availability.name,
            registrable: true,
            reason: String::new(),
            tier,
            price: Some(Money { amount_cents: price_cents, currency: pricing.currency.clone() }),
        },
        Err(_) => unsellable("price exceeds platform limit"),
    }
}

#[tonic::async_trait]
impl DomainService for Domains {
    // --- purchasing (phase 3) -------------------------------------------

    /// AUTHZ: Action::Read on ResourceType::Domain. Searching the registry
    /// for an unregistered name is not tenant data, so this is deliberately
    /// open to any authenticated caller -- but whatever shape the result
    /// takes, it must never reveal that *another* organization already owns
    /// a name. Collapsed to `registrable: false` here for every reason a
    /// name isn't sellable (Cloudflare says taken, the TLD isn't one we
    /// sell, or the price would exceed our own cap) -- one signal, not
    /// three, so a caller can never distinguish "not available" from "not
    /// for sale here."
    async fn search_domains(
        &self,
        request: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        let req = request.into_inner();
        self.caller(&req.access_token).await?;

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        let limit = if req.limit <= 0 { 5 } else { req.limit.min(20) } as u32;
        let candidates = crate::cloudflare::registrar::search(&cf.registrar, &cf.account_id, &req.query, limit)
            .await
            .map_err(Status::from)?;

        let offers = candidates.into_iter().map(|c| domain_offer(c, &self.config.pricing)).collect();
        Ok(Response::new(SearchResponse { offers }))
    }

    /// AUTHZ: Action::Read on ResourceType::Domain, scoped to the caller's
    /// own organization -- a quote is the only price a purchase may be
    /// built on, so it is also the first place a caller could be shown
    /// someone else's negotiated cost. `markup_percent` is applied here,
    /// server-side, never trusted from the caller.
    async fn quote_domain(
        &self,
        request: Request<QuoteRequest>,
    ) -> Result<Response<QuoteResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let organization_id = authz::real_org(&claims.organization_id)
            .ok_or_else(|| Status::permission_denied("caller has no organization to quote for"))?
            .to_owned();

        if !purchasing::tld_allowed(&req.fqdn, &self.config.pricing) {
            return Err(Status::invalid_argument(format!("{}: this extension is not sold here", req.fqdn)));
        }

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        let mut availability =
            crate::cloudflare::registrar::check(&cf.registrar, &cf.account_id, &[req.fqdn.clone()])
                .await
                .map_err(Status::from)?;
        let entry = availability
            .pop()
            .ok_or_else(|| Status::internal("cloudflare returned no availability information"))?;
        if !entry.registrable {
            return Err(Status::failed_precondition(format!("{} is not registrable", req.fqdn)));
        }
        let cf_pricing = entry
            .pricing
            .ok_or_else(|| Status::internal("cloudflare reported no pricing for a registrable domain"))?;
        let cost_cents = cf_pricing.registration_cost_cents().map_err(Status::from)?;
        let price_cents = purchasing::price_for(cost_cents, &self.config.pricing).map_err(Status::from)?;

        let quote_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + self.config.pricing.quote_ttl_secs;
        let tier = entry.tier.clone().unwrap_or_default();

        orders_db::insert_quote(
            &self.pool,
            &quote_id,
            &req.fqdn,
            &organization_id,
            &claims.sub,
            cost_cents,
            price_cents,
            &self.config.pricing.currency,
            &tier,
            expires_at,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(QuoteResponse {
            quote_id,
            offer: Some(DomainOffer {
                fqdn: req.fqdn,
                registrable: true,
                reason: String::new(),
                tier,
                price: Some(Money { amount_cents: price_cents, currency: self.config.pricing.currency.clone() }),
            }),
            expires_at,
        }))
    }

    /// AUTHZ: Action::Purchase on ResourceType::Domain **and** an elevated
    /// token (`self.elevated`), not merely a role check -- this is the one
    /// action in this service that spends an organization's money, and the
    /// GLOBAL policy seed gives `purchase` to Admin and Super only. Charge
    /// the caller's own organization; never an org id taken from the
    /// request, unless the caller is Super acting on another org's behalf.
    /// Also gated on `Billing::organization_permits_new_purchases` (fail
    /// closed): a suspended org, or a Billing that can't be reached to ask,
    /// refuses the purchase outright rather than risk letting a delinquent
    /// account keep spending.
    async fn create_order(
        &self,
        request: Request<CreateOrderRequest>,
    ) -> Result<Response<OrderCheckout>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        self.elevated(&req.elevated_token, &claims).await?;

        if !self.config.purchasing.enabled {
            return Err(Status::failed_precondition("domain purchasing is not enabled"));
        }

        let allowed = self
            .auth
            .evaluate_access(&claims, ResourceType::Domain, "", Action::Purchase)
            .await
            .map_err(Status::from)?;
        if !allowed && claims.role != Role::Super {
            return Err(Status::permission_denied("not permitted to purchase domains"));
        }

        let caller_org = authz::real_org(&claims.organization_id)
            .ok_or_else(|| Status::permission_denied("caller has no organization to charge"))?
            .to_owned();
        if claims.role != Role::Super && !req.organization_id.is_empty() && req.organization_id != caller_org {
            return Err(Status::permission_denied("cannot create an order for another organization"));
        }
        let charge_org =
            if claims.role == Role::Super && !req.organization_id.is_empty() { req.organization_id } else { caller_org };

        // Fail closed: a purchase-shaped action refuses outright if Billing
        // can't even be asked whether this org is in good standing, rather
        // than assuming "fine" and letting a suspended (or unreachable-to-check)
        // org keep buying domains. This is the billing overhaul's stated
        // policy for *new*-purchase-shaped actions specifically -- an
        // already-registered domain is never touched by this check, only
        // whether a *new* one may be bought.
        let billing_ok = self.billing.organization_permits_new_purchases(&charge_org).await.map_err(Status::from)?;
        if !billing_ok {
            return Err(Status::failed_precondition("organization billing is not in good standing"));
        }

        let quote = orders_db::find_quote(&self.pool, &req.quote_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("no such quote"))?;
        if quote.expires_at <= chrono::Utc::now().timestamp() {
            return Err(Status::failed_precondition("quote has expired; request a new one"));
        }
        if quote.organization_id != charge_org {
            return Err(Status::permission_denied("this quote does not belong to this organization"));
        }

        // One order per quote: a double submit (a double click, a retried
        // request) gets the order the first one made, not a second order and a
        // second charge.
        if let Some(existing) =
            orders_db::find_order_by_quote(&self.pool, &req.quote_id).await.map_err(Status::from)?
        {
            return self.resume_order(existing).await;
        }

        if inventory_db::find_domain(&self.pool, &quote.fqdn).await.map_err(Status::from)?.is_some() {
            return Err(Status::already_exists(format!("{} is already registered here", quote.fqdn)));
        }

        // The spending caps are checked inside this call, under a lock on the
        // organization, so concurrent orders cannot each slip under a cap.
        let order_id = match orders_db::insert_order_with_job(
            &self.pool,
            &self.config.purchasing,
            &quote.fqdn,
            &charge_org,
            &claims.sub,
            &req.quote_id,
            quote.cost_cents,
            quote.price_cents,
            &quote.currency,
            &req.runner_id,
            &req.invite_email,
        )
        .await
        {
            Ok(orders_db::NewOrder::Created(id)) => id,
            Ok(orders_db::NewOrder::CapReached) => {
                return Err(Status::resource_exhausted("purchasing cap reached for this organization"));
            }
            Err(err) if orders_db::is_duplicate(&err) => {
                // Lost a race: either the same quote was submitted at the
                // same instant, or another order is already buying this name.
                return match orders_db::find_order_by_quote(&self.pool, &req.quote_id)
                    .await
                    .map_err(Status::from)?
                {
                    Some(existing) => self.resume_order(existing).await,
                    None => Err(Status::already_exists(format!("{} is already being bought", quote.fqdn))),
                };
            }
            Err(err) => return Err(Status::from(err)),
        };

        let order = orders_db::find_order(&self.pool, order_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("order vanished mid-create"))?;

        log!(LogLevel::Info, "{}: order {} created ({}c)", order.fqdn, order_id, order.price_cents);

        self.checkout_for(order).await
    }

    /// AUTHZ: Action::Read on ResourceType::Domain, and the order's owning
    /// organization must match the caller's own -- an order id is
    /// guessable, so "knows the id" cannot be the check.
    async fn get_order(&self, request: Request<GetOrderRequest>) -> Result<Response<Order>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let order_id: u64 =
            req.order_id.parse().map_err(|_| Status::invalid_argument("order_id must be numeric"))?;

        let order = orders_db::find_order(&self.pool, order_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("no such order"))?;

        if claims.role != Role::Super {
            let caller_org = authz::real_org(&claims.organization_id)
                .ok_or_else(|| Status::permission_denied("caller has no organization"))?;
            if order.organization_id != caller_org {
                return Err(Status::permission_denied("not permitted to view this order"));
            }
        }

        Ok(Response::new(order_response(order)))
    }

    /// AUTHZ: Action::Read, filtered through `authz::scope` exactly like
    /// ListInventory -- non-Super callers only ever see their own
    /// organization's orders, whatever organization_id they ask for.
    async fn list_orders(
        &self,
        request: Request<ListOrdersRequest>,
    ) -> Result<Response<ListOrdersResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let scope = authz::scope(claims.role, &claims.organization_id, &req.organization_id)?;

        let limit = if req.limit <= 0 { 50 } else { req.limit.min(200) } as i64;
        let offset = req.offset.max(0) as i64;

        let rows = orders_db::list_orders(&self.pool, scope.as_deref(), limit, offset)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListOrdersResponse { orders: rows.into_iter().map(order_response).collect() }))
    }

    // No handle_stripe_webhook: superseded entirely by Billing's own RPC of
    // the same shape. See billing.proto's comment on why it isn't in this
    // service's own proto file anymore.

    // --- lifecycle (phase 2) --------------------------------------------

    /// AUTHZ: Action::Write on ResourceType::Domain -- there is no row yet
    /// for `authz::may_write_domain` to check ownership of, so this is the
    /// same "may create at all" grant `create_order` checks for purchasing,
    /// not a per-domain one. `organization_id` is always the caller's own
    /// (`authz::real_org`), never taken from the request: a BYO domain is
    /// claimed by whoever proves control of it, not assigned by name.
    /// Proving that control is a second, later step -- see `VerifyDomainNow`
    /// -- so accepting the *request* here only ever produces a domain in
    /// `pending_dns`, never `active`.
    async fn add_domain(
        &self,
        request: Request<AddDomainRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let allowed = self
            .auth
            .evaluate_access(&claims, ResourceType::Domain, "", Action::Write)
            .await
            .map_err(Status::from)?;
        if !allowed && claims.role != Role::Super {
            return Err(Status::permission_denied("not permitted to add domains"));
        }

        let fqdn = crate::intake::normalize(&req.fqdn)?;

        // AUTHZ: what a name *is* decides which check applies, and each is
        // stricter than "the caller is logged in":
        //   * already recorded  -> `authz::may_write_domain` on that record;
        //   * under a domain we hold -> the same check on the *parent*, so a
        //     tenant can add `staging.theirs.com` and never `x.someone-else.com`;
        //   * already on the edge but unrecorded -> only via an owned parent, or
        //     Super -- adopting an unowned live name is how one tenant takes
        //     another's hostname;
        //   * brand new -> `authz::may_add_domain`, stamped from the caller's
        //     own claims (`authz::owner_for_new`), never from the request.
        // The runner, if one is named, is `may_write_runner` in every case.
        let runner = self.may_write_runner(&claims, &req.runner_id).await?;
        let wants_vhost = !req.backends.is_empty();
        if wants_vhost && req.runner_id.is_empty() {
            return Err(Status::invalid_argument("instances were given but no runner_id to attach them to"));
        }

        // 1. Already ours: link, change nothing about the record.
        if let Some(existing) = inventory_db::find_domain(&self.pool, &fqdn)
            .await
            .map_err(Status::from)?
            .filter(|row| row.status != "removed")
        {
            authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), runner)
                .map_err(|denial| denial.into_status(&existing.fqdn))?;

            if wants_vhost {
                self.write_vhost(&existing, &req.runner_id, req.backends, req.extra_names, req.no_http_redirect, VhostExtras::default())
                    .await?;
            }
            return self
                .add_domain_response(
                    &fqdn,
                    AddDomainOutcome::Linked,
                    vec![format!("{fqdn} is already recorded; nothing was changed.")],
                    Vec::new(),
                    wants_vhost,
                )
                .await;
        }

        // 2. Look at the configs. Read-only, and the only way to know whether a
        //    name someone is "adding" is in fact already being served.
        let inventory = scan::run(&self.config, &self.secrets, &scan::ScanOptions::default())
            .await
            .map_err(Status::from)?;

        let ancestors = crate::intake::ancestors(&fqdn);
        let parent = inventory_db::nearest_ancestor(&self.pool, &ancestors)
            .await
            .map_err(Status::from)?;
        let parent_access = match &parent {
            Some(parent) => Some(
                authz::may_write_domain(claims.role, &claims.organization_id, parent.organization_id.as_deref(), runner)
                    .map_err(|denial| denial.into_status(&parent.fqdn)),
            ),
            None => None,
        };

        let org = authz::owner_for_new(
            claims.role,
            &claims.organization_id,
            &req.organization_id,
            parent.as_ref().and_then(|p| p.organization_id.as_deref()),
        );

        // A parent that exists on disk but was never recorded is invisible to
        // the lookup above; without this a tenant could claim a subdomain of it.
        let unrecorded_parent = parent.is_none()
            && inventory.domains.iter().any(|d| ancestors.contains(&d.fqdn) || d.names.iter().any(|n| ancestors.contains(n)));

        // 3. Already on the edge: record it, never rewrite it.
        if let Some(found) = inventory.domains.iter().find(|d| d.fqdn == fqdn) {
            match &parent_access {
                _ if claims.role == Role::Super => {}
                Some(Ok(())) => {}
                Some(Err(status)) => return Err(status.clone()),
                None => {
                    return Err(Status::permission_denied(format!(
                        "{fqdn} is already served from the edge but not assigned to anyone; an operator must adopt it"
                    )));
                }
            }

            let mut plan = crate::inventory::plan::from_inventory(&inventory, Default::default());
            plan.domains.retain(|d| d.fqdn == found.fqdn);
            plan.quarantine.clear();
            for domain in &mut plan.domains {
                domain.assign.organization_id = org.clone();
                domain.assign.runner_id = (!req.runner_id.is_empty()).then(|| req.runner_id.clone());
            }
            crate::inventory::apply::apply(&self.pool, &self.config, &plan, None, &Default::default())
                .await
                .map_err(Status::from)?;

            return self
                .add_domain_response(
                    &fqdn,
                    AddDomainOutcome::Adopted,
                    vec![format!("{fqdn} was already served from the edge's configs and is now recorded; its vhost is left as written.")],
                    Vec::new(),
                    false,
                )
                .await;
        }

        // 4. New, under a domain we hold: DNS and vhost can be ours to do.
        if let (Some(parent), Some(access)) = (&parent, parent_access) {
            access?;
            return self.add_subdomain(&claims, &req, &fqdn, parent, org).await;
        }
        if unrecorded_parent && claims.role != Role::Super {
            return Err(Status::permission_denied(format!(
                "{fqdn} sits under a domain that exists on the edge but is not assigned to an organization; an operator must assign that first"
            )));
        }

        // 5. New and unrelated to anything we hold: the customer owns the DNS.
        //    `may_add_domain` is the role bar. A tenant then has to *prove* the
        //    name is theirs (a TXT token, checked by VerifyDomainNow) before it
        //    is accepted -- otherwise any org Admin could claim any unowned name.
        //    Only Super, the operator, is trusted to add one without proof.
        authz::may_add_domain(claims.role, &claims.organization_id)
            .map_err(|denial| denial.into_status(&fqdn))?;

        if claims.role != Role::Super {
            let organization_id = org
                .clone()
                .ok_or_else(|| Status::permission_denied(authz::Denial::NoOrg.message("")))?;
            let ownership_token = uuid::Uuid::new_v4().to_string();
            let challenge_target = self.config.challenge_target_for(&fqdn);

            let domain_id = domains_db::insert_byo(
                &self.pool,
                &fqdn,
                &organization_id,
                &req.runner_id,
                &ownership_token,
                &challenge_target,
            )
            .await
            .map_err(Status::from)?;

            let mut required_records = vec![RequiredRecord {
                r#type: "TXT".to_owned(),
                name: format!("_ais-domains-verify.{fqdn}"),
                content: ownership_token,
                note: "proves you control this domain; create this first, then call VerifyDomainNow".to_owned(),
            }];
            for ip in &self.config.dns.edge_ipv4 {
                required_records.push(RequiredRecord {
                    r#type: "A".to_owned(),
                    name: fqdn.clone(),
                    content: ip.clone(),
                    note: "points this domain at our edge".to_owned(),
                });
            }
            for ip in &self.config.dns.edge_ipv6 {
                required_records.push(RequiredRecord {
                    r#type: "AAAA".to_owned(),
                    name: fqdn.clone(),
                    content: ip.clone(),
                    note: "points this domain at our edge".to_owned(),
                });
            }
            required_records.push(RequiredRecord {
                r#type: "CNAME".to_owned(),
                name: format!("_acme-challenge.{fqdn}"),
                content: challenge_target,
                note: "lets us issue and renew your certificate with no further steps".to_owned(),
            });

            let row = domains_db::find_full(&self.pool, domain_id)
                .await
                .map_err(Status::from)?
                .ok_or_else(|| Status::internal("domain vanished mid-create"))?;

            log!(LogLevel::Info, "{fqdn}: added as BYO, awaiting ownership proof");

            return Ok(Response::new(AddDomainResponse {
                domain: Some(domain_response(&row)),
                required_records,
                outcome: AddDomainOutcome::NeedsDns as i32,
                notes: vec![format!(
                    "{fqdn} is recorded but not yet yours: create the TXT record below, then call VerifyDomainNow."
                )],
            }));
        }

        // Super: the operator adds it directly, no proof needed.
        let records = crate::intake::required_records(&self.config, &fqdn, true)?;
        inventory_db::insert_domain(
            &self.pool,
            &inventory_db::NewDomain {
                fqdn: &fqdn,
                organization_id: org.as_deref(),
                runner_id: (!req.runner_id.is_empty()).then_some(req.runner_id.as_str()),
                source: "byo",
                status: "pending_dns",
                challenge_target: &self.config.challenge_target_for(&fqdn),
                cf_zone_id: None,
                parent_id: None,
                created_by: Some(&claims.sub),
            },
        )
        .await
        .map_err(Status::from)?;

        self.add_domain_response(
            &fqdn,
            AddDomainOutcome::NeedsDns,
            vec![format!(
                "{fqdn} is not under any domain we manage, so its DNS is yours to change. Create the records below and we will pick it up."
            )],
            records,
            false,
        )
        .await
    }

    /// AUTHZ: `authz::may_read_domain` -- an fqdn is public knowledge, so the
    /// lookup succeeding must never be what decides visibility; only
    /// ownership does.
    async fn get_domain(&self, request: Request<GetDomainRequest>) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let row = domains_db::find_full_by_id_or_fqdn(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_read_domain(claims.role, &claims.organization_id, row.organization_id.as_deref())
            .map_err(|denial| denial.into_status(&row.fqdn))?;

        let certificates =
            domains_db::certificates_for(&self.pool, row.id).await.map_err(Status::from)?;
        let records = domains_db::managed_records_for(&self.pool, row.id).await.map_err(Status::from)?;

        let mut domain = domain_response(&row);
        domain.certificates = certificates.into_iter().map(|cert| cert_response(row.id, cert)).collect();
        domain.records = records
            .into_iter()
            .map(|record| ManagedRecord {
                purpose: match record.purpose.as_str() {
                    "edge_a" => RecordPurpose::EdgeA as i32,
                    "edge_aaaa" => RecordPurpose::EdgeAaaa as i32,
                    "www" => RecordPurpose::Www as i32,
                    "acme_alias" => RecordPurpose::AcmeAlias as i32,
                    _ => RecordPurpose::Unspecified as i32,
                },
                r#type: record.record_type,
                name: record.name,
                content: record.content,
                cf_record_id: record.cf_record_id.unwrap_or_default(),
                drifted: record.drifted,
            })
            .collect();

        Ok(Response::new(domain))
    }

    /// AUTHZ: `authz::scope`, same as `ListInventory`.
    async fn list_domains(
        &self,
        request: Request<ListDomainsRequest>,
    ) -> Result<Response<ListDomainsResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let scope = authz::scope(claims.role, &claims.organization_id, &req.organization_id)?;

        let status = DomainStatus::try_from(req.status).unwrap_or(DomainStatus::Unspecified);
        let status_filter = match status {
            DomainStatus::Unspecified => None,
            other => Some(status_db_value(other)),
        };

        let limit = if req.limit <= 0 { 100 } else { req.limit as i64 };
        let rows = domains_db::list(
            &self.pool,
            scope.as_deref(),
            (!req.runner_id.is_empty()).then_some(req.runner_id.as_str()),
            status_filter,
            limit,
            req.offset as i64,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(ListDomainsResponse { domains: rows.iter().map(domain_response).collect() }))
    }

    /// AUTHZ: `authz::may_write_domain` (no runner in play -- the request
    /// names none) plus `require_domain_grant`'s `Action::Delete`, and an
    /// elevated token: removing a domain takes a live site off the internet
    /// and frees a name someone else can then claim, the same bar
    /// `delete_dns_record` sits behind for a single record.
    async fn remove_domain(
        &self,
        request: Request<RemoveDomainRequest>,
    ) -> Result<Response<RemoveDomainResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Delete).await?;

        if req.delete_zone {
            let zone_id = domains_db::find_full(&self.pool, existing.id)
                .await
                .map_err(Status::from)?
                .and_then(|row| row.cf_zone_id)
                .filter(|id| !id.is_empty());

            if let Some(zone_id) = zone_id {
                let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
                if let Err(err) = crate::cloudflare::zones::delete(&cf.zones, &zone_id).await {
                    log!(LogLevel::Warn, "{}: could not delete cloudflare zone {}: {}", existing.fqdn, zone_id, err);
                }
            }
        }
        // keep_registration is documentation-only, per its own proto comment:
        // this handler never calls the registrar either way.

        domains_db::soft_delete(&self.pool, existing.id).await.map_err(Status::from)?;
        log!(LogLevel::Info, "{}: removed", existing.fqdn);

        Ok(Response::new(RemoveDomainResponse { success: true }))
    }

    /// AUTHZ: `authz::may_write_domain` with no runner in play -- a probe is
    /// read-only in itself, but success here can advance the domain's status
    /// and even trigger issuance, so it sits at the write bar (Super, or an
    /// Admin of the owning org), not the lighter read one.
    async fn verify_domain_now(
        &self,
        request: Request<VerifyDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        let row = domains_db::find_full(&self.pool, existing.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-verify"))?;

        let probe = Probe::with_servers(&self.config.dns.resolvers).map_err(Status::from)?;

        // Step one, BYO only: prove control of the name before anything else
        // is even checked. Purchased and imported domains skip this --
        // ownership was never in question for either.
        if row.source == "byo" && !row.ownership_verified {
            let Some(token) = &row.ownership_token else {
                return Err(Status::internal(format!("{}: no ownership token on record", row.fqdn)));
            };
            let values = probe
                .txt(&format!("_ais-domains-verify.{}", row.fqdn))
                .await
                .map_err(Status::from)?;

            if !values.iter().any(|value| value == token) {
                domains_db::set_last_error(
                    &self.pool,
                    row.id,
                    Some("ownership TXT record not found yet; create it and try again"),
                )
                .await
                .ok();
                let updated = domains_db::find_full(&self.pool, row.id).await.map_err(Status::from)?.unwrap();
                return Ok(Response::new(domain_response(&updated)));
            }

            domains_db::mark_ownership_verified(&self.pool, row.id).await.map_err(Status::from)?;
        }

        // Step two: is the domain actually pointed at us? Same checks
        // `inventory::scan::check_dns` runs in bulk, against just this one
        // domain, on demand.
        let expected: Vec<std::net::IpAddr> = self
            .config
            .dns
            .edge_ipv4
            .iter()
            .chain(self.config.dns.edge_ipv6.iter())
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let edge_ok = probe.resolves_to_edge(&row.fqdn, &expected).await.unwrap_or(false);
        let cname_ok = probe.challenge_cname_ok(&row.fqdn, &row.challenge_target).await.unwrap_or(false);

        if !edge_ok || !cname_ok {
            let mut missing = Vec::new();
            if !edge_ok {
                missing.push("the A/AAAA record pointing at our edge");
            }
            if !cname_ok {
                missing.push("the _acme-challenge CNAME");
            }
            domains_db::set_last_error(
                &self.pool,
                row.id,
                Some(&format!("still missing: {}", missing.join(", "))),
            )
            .await
            .ok();
            let updated = domains_db::find_full(&self.pool, row.id).await.map_err(Status::from)?.unwrap();
            return Ok(Response::new(domain_response(&updated)));
        }

        // Everything checks out. Issue (or re-issue) and go live, unless
        // this domain is already active -- a repeated VerifyDomainNow on a
        // healthy domain should not burn a certificate issuance every time.
        if row.status != "active" {
            match crate::acme::issue_and_install(&self.config, &self.secrets, &row.fqdn).await {
                Ok(_) => {
                    for key_type in KeyType::ALL {
                        if let Ok(Some(not_after)) =
                            crate::acme::install::read_expiry(&self.config, &row.fqdn, key_type)
                        {
                            let renew_after = not_after - self.config.acme.renew_before_days * 86_400;
                            domains_db::record_certificate(&self.pool, row.id, key_type.as_str(), not_after, renew_after)
                                .await
                                .ok();
                        }
                    }
                    domains_db::set_status(&self.pool, row.id, "active", None).await.map_err(Status::from)?;
                    log!(LogLevel::Info, "{}: verified and issued", row.fqdn);
                }
                Err(err) => {
                    domains_db::set_status(&self.pool, row.id, "error", Some(&err.to_string())).await.ok();
                    return Err(err.into());
                }
            }
        }

        let updated = domains_db::find_full(&self.pool, row.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-verify"))?;
        Ok(Response::new(domain_response(&updated)))
    }

    type WatchDomainStream =
        Pin<Box<dyn Stream<Item = Result<DomainEvent, Status>> + Send + 'static>>;

    /// AUTHZ: `authz::may_read_domain` before the stream opens (a specific
    /// `id_or_fqdn`), or `authz::scope` for "every domain I may see"
    /// (`id_or_fqdn` empty) -- and re-checked on every poll tick, so a
    /// domain reassigned mid-stream stops producing events for the caller
    /// who no longer owns it rather than a long-lived stream outliving the
    /// permission that opened it.
    async fn watch_domain(
        &self,
        request: Request<WatchDomainRequest>,
    ) -> Result<Response<Self::WatchDomainStream>, Status> {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let only_id = if req.id_or_fqdn.is_empty() {
            None
        } else {
            let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
                .await
                .map_err(Status::from)?
                .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
            authz::may_read_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref())
                .map_err(|denial| denial.into_status(&existing.fqdn))?;
            Some(existing.id)
        };
        // `None` (every organization) only for Super -- `scope` already
        // enforces that; a non-Super caller watching "every domain" is
        // silently narrowed to their own, same as ListInventory.
        let scope = authz::scope(claims.role, &claims.organization_id, "")?;

        let pool = self.pool.clone();
        let role = claims.role;
        let caller_org = claims.organization_id.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            // Seeds `last` without emitting: a fresh stream reports changes
            // from here forward, not the state the domain happened to
            // already be in when the caller connected.
            let mut last: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
            if let Ok(rows) = domains_db::poll_statuses(&pool, only_id, scope.as_deref()).await {
                for row in rows {
                    last.insert(row.id, row.status);
                }
            }

            loop {
                tokio::time::sleep(POLL_INTERVAL).await;

                let rows = match domains_db::poll_statuses(&pool, only_id, scope.as_deref()).await {
                    Ok(rows) => rows,
                    Err(err) => {
                        let _ = tx.send(Err(Status::from(err))).await;
                        return;
                    }
                };

                for row in rows {
                    if authz::may_read_domain(role, &caller_org, row.organization_id.as_deref()).is_err() {
                        continue;
                    }

                    let changed = last.get(&row.id).is_none_or(|previous| previous != &row.status);
                    if !changed {
                        continue;
                    }
                    last.insert(row.id, row.status.clone());

                    let event = DomainEvent {
                        domain_id: row.id.to_string(),
                        fqdn: row.fqdn,
                        status: status_code(&row.status),
                        message: row.last_error.unwrap_or_default(),
                        at: chrono::Utc::now().timestamp(),
                    };
                    if tx.send(Ok(event)).await.is_err() {
                        return; // caller disconnected
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))))
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

        let extras = VhostExtras {
            extra_headers: req
                .extra_headers
                .into_iter()
                .map(|h| crate::vhost::render::HeaderEntry { name: h.name, value: h.value })
                .collect(),
            cors: req.cors.map(|c| crate::vhost::render::CorsPolicy {
                allow_origin: c.allow_origin,
                allow_methods: c.allow_methods,
                allow_headers: c.allow_headers,
                expose_headers: c.expose_headers,
            }),
            extra_locations: req
                .extra_locations
                .into_iter()
                .map(|l| {
                    let kind = match LocationKind::try_from(l.kind).unwrap_or(LocationKind::Unspecified) {
                        LocationKind::Websocket => crate::vhost::render::LocationKind::Websocket,
                        LocationKind::DenyAll => crate::vhost::render::LocationKind::DenyAll,
                        LocationKind::Unspecified => {
                            return Err(Status::invalid_argument(format!(
                                "extra_locations[{}]: kind must be set",
                                l.path
                            )));
                        }
                    };
                    Ok(crate::vhost::render::ExtraLocation { path: l.path, kind })
                })
                .collect::<Result<Vec<_>, Status>>()?,
        };

        self.write_vhost(
            &existing,
            &req.runner_id,
            req.backends,
            req.extra_names,
            req.no_http_redirect,
            extras,
        )
        .await?;

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

    /// Read-only: stages a copy of the tree, writes the submission into it,
    /// and runs `nginx -t` plus a lint diff. Never touches the live tree, so
    /// this needs only a read-level check, not the write bar `attach_domain`
    /// and `apply_freeform_vhost` sit behind.
    async fn validate_freeform_vhost(
        &self,
        request: Request<ValidateFreeformVhostRequest>,
    ) -> Result<Response<ValidateFreeformVhostResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_read_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref())
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        let outcome = crate::vhost::freeform::validate(&self.config, &existing.fqdn, &req.server_block)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(freeform_response(outcome)))
    }

    /// Validates, then -- if valid and not a dry run -- writes into the live
    /// tree. This rewrites a file that may be serving live traffic, so it
    /// sits behind the same two-ended write check as `attach_domain`, plus
    /// an elevated token: an arbitrary, caller-supplied nginx config is a
    /// materially bigger blast radius than a structured, validated spec.
    async fn apply_freeform_vhost(
        &self,
        request: Request<ApplyFreeformVhostRequest>,
    ) -> Result<Response<ApplyFreeformVhostResponse>, Status> {
        let req = request.into_inner();
        // Only one token travels with this request, and it must already be
        // an elevated one -- there is no separate access_token to compare it
        // against, unlike `self.elevated()`'s usual two-token shape.
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        let outcome = crate::vhost::freeform::apply(&self.config, &existing.fqdn, &req.server_block, req.dry_run)
            .await
            .map_err(Status::from)?;

        if outcome.applied {
            self.record_freeform_apply(existing.id, &existing.fqdn, &outcome.body, &claims.sub).await?;
            log!(LogLevel::Info, "{}: freeform vhost applied", existing.fqdn);
        }

        Ok(Response::new(ApplyFreeformVhostResponse {
            applied: outcome.applied,
            diff: outcome.diff,
            validation: Some(freeform_response(outcome.validation)),
        }))
    }

    /// AUTHZ: the same two-ended check as `attach_domain` -- `may_write_runner`
    /// on the runner being detached from, and `authz::may_write_domain` on
    /// the record.
    async fn detach_domain(
        &self,
        request: Request<DetachDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        let runner = self.may_write_runner(&claims, existing.runner_id.as_deref().unwrap_or("")).await?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), runner)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        // Only ever remove a file this service generated -- a hand-written
        // or freeform one is left alone with a warning, the same caution
        // `attach_domain`/`ConvertVhost` already take with a file that is
        // not ours to throw away.
        match inventory_db::vhost_origin(&self.pool, existing.id).await.map_err(Status::from)? {
            Some(origin) if origin == "generated" => {
                let path = self.config.vhost_path_for(&existing.fqdn);
                if let Err(err) = std::fs::remove_file(&path) {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        return Err(Status::internal(format!(
                            "{}: removing {}: {}",
                            existing.fqdn,
                            path.display(),
                            err
                        )));
                    }
                }
                inventory_db::delete_vhost(&self.pool, existing.id).await.map_err(Status::from)?;
            }
            Some(origin) => log!(
                LogLevel::Warn,
                "{}: leaving the {} vhost file alone; detaching only clears the assignment",
                existing.fqdn,
                origin
            ),
            None => {}
        }

        inventory_db::set_assignment(&self.pool, existing.id, None, Some(None)).await.map_err(Status::from)?;

        let updated = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::internal("domain vanished mid-detach"))?;

        log!(LogLevel::Info, "{}: detached", updated.fqdn);

        Ok(Response::new(Domain {
            id: updated.id.to_string(),
            fqdn: updated.fqdn,
            organization_id: updated.organization_id.unwrap_or_default(),
            runner_id: updated.runner_id.unwrap_or_default(),
            source: source_code(&updated.source),
            status: status_code(&updated.status),
            has_vhost: false,
            ..Default::default()
        }))
    }

    // --- members (phase 3) ----------------------------------------------

    /// AUTHZ: `authz::may_write_domain` (no runner in play) plus
    /// `require_domain_grant`'s `Action::Grant` -- handing someone
    /// Cloudflare access to the account is delegating authority, which is a
    /// grant, not a plain write. (No elevated token here: unlike
    /// `CreateOrder`/`RemoveDomain`, `InviteDomainMemberRequest` carries only
    /// an `access_token` -- the grant check itself is the bar.)
    async fn invite_domain_member(
        &self,
        request: Request<InviteDomainMemberRequest>,
    ) -> Result<Response<DomainMember>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Grant).await?;

        if req.email.trim().is_empty() {
            return Err(Status::invalid_argument("email is required"));
        }
        let role_name = if req.role.is_empty() { &self.config.cloudflare.member_role } else { &req.role };

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        let role_id = crate::cloudflare::members::role_id_for(&cf.members, &cf.account_id, role_name)
            .await
            .map_err(Status::from)?;
        let member = crate::cloudflare::members::invite(&cf.members, &cf.account_id, &req.email, &role_id)
            .await
            .map_err(Status::from)?;

        sqlx::query(
            "INSERT INTO domain_members (domain_id, email, cf_member_id, role, status) VALUES (?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE cf_member_id = VALUES(cf_member_id), role = VALUES(role), \
             status = VALUES(status)",
        )
        .bind(existing.id)
        .bind(&req.email)
        .bind(&member.id)
        .bind(role_name)
        .bind(&member.status)
        .execute(&self.pool)
        .await
        .map_err(crate::error::Error::from)
        .map_err(Status::from)?;

        log!(LogLevel::Info, "{}: invited {} as {}", existing.fqdn, req.email, role_name);

        Ok(Response::new(DomainMember {
            domain_id: existing.id.to_string(),
            email: req.email,
            cf_member_id: member.id,
            role: role_name.clone(),
            status: member_status_code(&member.status),
            invited_at: chrono::Utc::now().timestamp(),
        }))
    }

    /// AUTHZ: `authz::may_read_domain` -- the member list names people's
    /// email addresses, scoped to the owning org, never fleet-wide.
    async fn list_domain_members(
        &self,
        request: Request<ListDomainMembersRequest>,
    ) -> Result<Response<ListDomainMembersResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
        authz::may_read_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref())
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        let rows = sqlx::query(
            "SELECT email, cf_member_id, role, status, UNIX_TIMESTAMP(invited_at) AS invited_at \
             FROM domain_members WHERE domain_id = ? ORDER BY email",
        )
        .bind(existing.id)
        .fetch_all(&self.pool)
        .await
        .map_err(crate::error::Error::from)
        .map_err(Status::from)?;

        let members = rows
            .into_iter()
            .map(|row| DomainMember {
                domain_id: existing.id.to_string(),
                email: row.get("email"),
                cf_member_id: row.try_get::<Option<String>, _>("cf_member_id").ok().flatten().unwrap_or_default(),
                role: row.get("role"),
                status: member_status_code(row.get::<String, _>("status").as_str()),
                invited_at: row.get("invited_at"),
            })
            .collect();

        Ok(Response::new(ListDomainMembersResponse { members }))
    }

    /// AUTHZ: `authz::may_write_domain` plus `require_domain_grant`'s
    /// `Action::Grant`, as for the invite -- same reasoning on the missing
    /// elevated token: `RemoveDomainMemberRequest` carries none.
    async fn remove_domain_member(
        &self,
        request: Request<RemoveDomainMemberRequest>,
    ) -> Result<Response<RemoveDomainMemberResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Grant).await?;

        let row = sqlx::query("SELECT cf_member_id FROM domain_members WHERE domain_id = ? AND email = ?")
            .bind(existing.id)
            .bind(&req.email)
            .fetch_optional(&self.pool)
            .await
            .map_err(crate::error::Error::from)
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("{} has no member {}", existing.fqdn, req.email)))?;

        if let Some(cf_member_id) = row.try_get::<Option<String>, _>("cf_member_id").ok().flatten() {
            let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
            if let Err(err) = crate::cloudflare::members::remove(&cf.members, &cf.account_id, &cf_member_id).await {
                log!(LogLevel::Warn, "{}: could not remove cloudflare member {}: {}", existing.fqdn, req.email, err);
            }
        }

        sqlx::query("UPDATE domain_members SET status = 'removed' WHERE domain_id = ? AND email = ?")
            .bind(existing.id)
            .bind(&req.email)
            .execute(&self.pool)
            .await
            .map_err(crate::error::Error::from)
            .map_err(Status::from)?;

        log!(LogLevel::Info, "{}: removed member {}", existing.fqdn, req.email);

        Ok(Response::new(RemoveDomainMemberResponse { success: true }))
    }

    // --- dns records ------------------------------------------------------

    /// Read-only, so this needs only `authz::may_read_domain` -- no grant
    /// round trip, same reasoning as `validate_freeform_vhost`.
    async fn list_dns_records(
        &self,
        request: Request<ListDnsRecordsRequest>,
    ) -> Result<Response<ListDnsRecordsResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_read_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref())
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        let rows = dns_records_db::list(&self.pool, existing.id).await.map_err(Status::from)?;

        Ok(Response::new(ListDnsRecordsResponse { records: rows.into_iter().map(dns_record_response).collect() }))
    }

    /// `Action::Write` on the owning domain -- per
    /// `RBAC_PHASE_6_DOMAIN_PURCHASE.md` §2.1, records are authorized
    /// through their parent domain, not a resource type of their own.
    async fn create_dns_record(
        &self,
        request: Request<CreateDnsRecordRequest>,
    ) -> Result<Response<CreateDnsRecordResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Write).await?;

        let record = req.record.ok_or_else(|| Status::invalid_argument("record is required"))?;
        let zone_id = dns_records_db::zone_id_for(&self.pool, existing.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::failed_precondition(format!("{}: no Cloudflare zone yet", existing.fqdn)))?;

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        let ttl = record.ttl.max(1);
        let created = crate::cloudflare::dns::create(
            &cf.zones,
            &zone_id,
            &record.r#type,
            &record.name,
            &record.content,
            ttl,
            Some(record.proxied),
        )
        .await
        .map_err(Status::from)?;

        let id = dns_records_db::record_created(
            &self.pool,
            existing.id,
            &created.id,
            &created.record_type,
            &created.name,
            &created.content,
            ttl,
            record.proxied,
            Some(claims.sub.as_str()),
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(CreateDnsRecordResponse {
            record: Some(DnsRecordEntry {
                id: id.to_string(),
                cf_record_id: created.id,
                r#type: created.record_type,
                name: created.name,
                content: created.content,
                ttl,
                proxied: record.proxied,
            }),
        }))
    }

    /// Same bar as `create_dns_record` -- `Action::Write` on the owning
    /// domain, not a separate check per record.
    async fn update_dns_record(
        &self,
        request: Request<UpdateDnsRecordRequest>,
    ) -> Result<Response<UpdateDnsRecordResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Write).await?;

        let record_id: u64 =
            req.id.parse().map_err(|_| Status::invalid_argument("id must be this service's numeric record id"))?;
        let current = dns_records_db::find(&self.pool, existing.id, record_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("no such DNS record on this domain"))?;

        let record = req.record.ok_or_else(|| Status::invalid_argument("record is required"))?;
        let zone_id = dns_records_db::zone_id_for(&self.pool, existing.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::failed_precondition(format!("{}: no Cloudflare zone", existing.fqdn)))?;

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        let ttl = record.ttl.max(1);
        let updated = crate::cloudflare::dns::update(
            &cf.zones,
            &zone_id,
            &current.cf_record_id,
            &record.r#type,
            &record.name,
            &record.content,
            ttl,
            Some(record.proxied),
        )
        .await
        .map_err(Status::from)?;

        dns_records_db::record_updated(
            &self.pool,
            record_id,
            &updated.record_type,
            &updated.name,
            &updated.content,
            ttl,
            record.proxied,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(UpdateDnsRecordResponse {
            record: Some(DnsRecordEntry {
                id: req.id,
                cf_record_id: updated.id,
                r#type: updated.record_type,
                name: updated.name,
                content: updated.content,
                ttl,
                proxied: record.proxied,
            }),
        }))
    }

    /// `Action::Delete` plus an elevated token -- deleting a record can
    /// take a live site down, the same bar `remove_domain` sits behind.
    async fn delete_dns_record(
        &self,
        request: Request<DeleteDnsRecordRequest>,
    ) -> Result<Response<DeleteDnsRecordResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;
        self.require_domain_grant(&claims, existing.id, Action::Delete).await?;

        let record_id: u64 =
            req.id.parse().map_err(|_| Status::invalid_argument("id must be this service's numeric record id"))?;
        let current = dns_records_db::find(&self.pool, existing.id, record_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("no such DNS record on this domain"))?;

        let zone_id = dns_records_db::zone_id_for(&self.pool, existing.id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::failed_precondition(format!("{}: no Cloudflare zone", existing.fqdn)))?;

        let cf = crate::cloudflare::CfSuite::new(&self.config, &self.secrets).map_err(Status::from)?;
        crate::cloudflare::dns::delete(&cf.zones, &zone_id, &current.cf_record_id).await.map_err(Status::from)?;
        dns_records_db::delete(&self.pool, record_id).await.map_err(Status::from)?;

        Ok(Response::new(DeleteDnsRecordResponse { success: true }))
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
                    parent_fqdn: row.parent_fqdn.unwrap_or_default(),
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

    async fn list_reserved_names(
        &self,
        request: Request<ListReservedNamesRequest>,
    ) -> Result<Response<ListReservedNamesResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        // Reservations are platform-wide policy about a zone the platform owns; no organization has a say.
        require_super(claims.role, "reading reserved names")?;

        let rows = reserved_db::list(&self.pool).await.map_err(Status::from)?;
        Ok(Response::new(ListReservedNamesResponse {
            rules: rows.into_iter().map(reserved_response).collect(),
            free_zone: self.config.free_zone.zone.clone(),
        }))
    }

    async fn add_reserved_name(
        &self,
        request: Request<AddReservedNameRequest>,
    ) -> Result<Response<ReservedName>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        // Reserving a name stops every customer from claiming it: an operator's call.
        require_super(claims.role, "reserving a name")?;

        let rule = reserved_rule_from_request(&req)?;
        let id = reserved_db::add(&self.pool, &rule, &req.note, &claims.sub).await.map_err(Status::from)?;
        let row = reserved_db::list(&self.pool)
            .await
            .map_err(Status::from)?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| Status::internal("reservation vanished after it was stored"))?;
        Ok(Response::new(reserved_response(row)))
    }

    async fn remove_reserved_name(
        &self,
        request: Request<RemoveReservedNameRequest>,
    ) -> Result<Response<RemoveReservedNameResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        // Lifting a reservation lets customers claim the names it covered: an operator's call.
        require_super(claims.role, "lifting a reservation")?;

        let id = u64::try_from(req.id).map_err(|_| Status::invalid_argument("id must be positive"))?;
        let removed = reserved_db::remove(&self.pool, id).await.map_err(Status::from)?;
        if !removed {
            return Err(Status::not_found("no such reservation"));
        }
        Ok(Response::new(RemoveReservedNameResponse { removed }))
    }

    async fn check_free_name(
        &self,
        request: Request<CheckFreeNameRequest>,
    ) -> Result<Response<CheckFreeNameResponse>, Status> {
        let req = request.into_inner();
        // AUTHZ: any signed-in caller may ask; it reveals only whether a name is free, which a claim
        // would reveal anyway.
        self.caller(&req.access_token).await?;

        let zone = self.free_zone()?;
        let (fqdn, problem) = self.free_name_problem(&zone, &req.name).await?;
        Ok(Response::new(CheckFreeNameResponse {
            available: problem.is_none(),
            fqdn,
            reason: problem.unwrap_or_default(),
        }))
    }

    async fn claim_free_address(
        &self,
        request: Request<ClaimFreeAddressRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;

        // AUTHZ: the same bar as adding a domain (an org Admin, or Super), plus `ais_auth`'s decision on the
        // runner the name is for. The owner is the caller's own organization, never taken from the request.
        authz::may_add_domain(claims.role, &claims.organization_id).map_err(|d| d.into_status(&req.name))?;
        if req.runner_id.is_empty() {
            return Err(Status::invalid_argument("a free address belongs to an app: runner_id is required"));
        }
        let runner = self.may_write_runner(&claims, &req.runner_id).await?;
        if runner == Some(false) {
            return Err(Status::permission_denied("not permitted to change that app"));
        }
        let org = authz::real_org(&claims.organization_id)
            .map(str::to_owned)
            .ok_or_else(|| Status::permission_denied(authz::Denial::NoOrg.message("")))?;

        let zone = self.free_zone()?;
        let (fqdn, problem) = self.free_name_problem(&zone, &req.name).await?;
        if let Some(reason) = problem {
            return Err(Status::failed_precondition(reason));
        }

        // The zone is recorded (and holds the wildcard certificate) by an operator; without that row there
        // is nothing for a free name to ride on.
        let parent = inventory_db::find_domain(&self.pool, &zone)
            .await
            .map_err(Status::from)?
            .filter(|row| row.status != "removed")
            .ok_or_else(|| Status::failed_precondition(format!("{zone} is not set up as a managed domain yet")))?;

        let add = AddDomainRequest {
            runner_id: req.runner_id,
            backends: req.backends,
            ..Default::default()
        };
        self.add_subdomain(&claims, &add, &fqdn, &parent, Some(org)).await
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

    /// Brings a hand-written, currently-untracked vhost under this
    /// service's tracking. `template = "structured"` would recognize it as a
    /// [`crate::vhost::render::VhostSpec`] and re-render it -- that
    /// heuristic recognizer is not built yet, so only the freeform path
    /// (the common case) is implemented: the file's exact existing text is
    /// run through the same validate/apply pipeline as
    /// `ApplyFreeformVhost`, changing only its tracking, not its directives.
    async fn convert_vhost(
        &self,
        request: Request<ConvertVhostRequest>,
    ) -> Result<Response<ConvertVhostResponse>, Status> {
        let req = request.into_inner();
        // AUTHZ: `authz::may_write_domain` plus `may_write_runner` -- converting
        // rewrites a file that is currently serving live traffic, so it is a
        // write on both ends, and an elevated token for the same reason
        // ApplyFreeformVhost needs one.
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;

        let runner = self.may_write_runner(&claims, existing.runner_id.as_deref().unwrap_or("")).await?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), runner)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        if req.template == "structured" {
            return Err(pending(
                "the vhost template work",
                "recognizing a hand-written vhost as a structured VhostSpec",
            ));
        }

        let path = self.config.vhost_path_for(&existing.fqdn);
        let current = std::fs::read_to_string(&path)
            .map_err(|_| Status::not_found(format!("{}: no vhost file at {}", existing.fqdn, path.display())))?;

        let outcome = crate::vhost::freeform::apply(&self.config, &existing.fqdn, &current, req.dry_run)
            .await
            .map_err(Status::from)?;

        if outcome.applied {
            self.record_freeform_apply(existing.id, &existing.fqdn, &outcome.body, &claims.sub).await?;
            log!(LogLevel::Info, "{}: adopted vhost brought under freeform tracking", existing.fqdn);
        }

        Ok(Response::new(ConvertVhostResponse { diff: outcome.diff, converted: outcome.applied }))
    }

    // --- ops ------------------------------------------------------------

    /// AUTHZ: `authz::scope` -- a certificate's SANs name every site it
    /// serves, so an unscoped list is a map of the whole estate.
    async fn list_certificates(
        &self,
        request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        let scope = authz::scope(claims.role, &claims.organization_id, &req.organization_id)?;

        let rows = domains_db::list_certificates(&self.pool, scope.as_deref(), req.expiring_within_days)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListCertificatesResponse {
            certificates: rows.into_iter().map(|(domain_id, cert)| cert_response(domain_id, cert)).collect(),
        }))
    }

    /// AUTHZ: `authz::may_write_domain` with no runner in play (so: Super, or
    /// an Admin of the owning org). A forced renewal always issues both key
    /// types together -- the same "the pair moves as one" rule
    /// `install::write_pair` already enforces -- so `key_type` on the
    /// request is accepted but does not select a subset. Rate limits are per
    /// registered domain per week and shared by every tenant on a zone, so a
    /// cooldown independent of the caller's own `force` intent guards
    /// against a spammed forced renewal becoming a denial of service against
    /// everyone else's.
    async fn force_renew(
        &self,
        request: Request<ForceRenewRequest>,
    ) -> Result<Response<ForceRenewResponse>, Status> {
        const COOLDOWN_SECS: i64 = 3600;

        let req = request.into_inner();
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }

        let existing = inventory_db::find_domain(&self.pool, &req.id_or_fqdn)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("no domain {}", req.id_or_fqdn)))?;
        authz::may_write_domain(claims.role, &claims.organization_id, existing.organization_id.as_deref(), None)
            .map_err(|denial| denial.into_status(&existing.fqdn))?;

        if let Some(age) = domains_db::seconds_since_last_issuance(&self.pool, existing.id).await.map_err(Status::from)?
        {
            if age < COOLDOWN_SECS {
                return Err(Status::resource_exhausted(format!(
                    "{}: renewed {age}s ago; wait at least {COOLDOWN_SECS}s between forced renewals",
                    existing.fqdn
                )));
            }
        }

        crate::acme::issue_and_install(&self.config, &self.secrets, &existing.fqdn)
            .await
            .map_err(Status::from)?;

        for key_type in KeyType::ALL {
            if let Ok(Some(not_after)) = crate::acme::install::read_expiry(&self.config, &existing.fqdn, key_type) {
                let renew_after = not_after - self.config.acme.renew_before_days * 86_400;
                domains_db::record_certificate(&self.pool, existing.id, key_type.as_str(), not_after, renew_after)
                    .await
                    .map_err(Status::from)?;
            }
        }

        log!(LogLevel::Info, "{}: force-renewed", existing.fqdn);

        // Synchronous, like the CLI's `issue` command -- there is no job to
        // report an id for.
        Ok(Response::new(ForceRenewResponse { job_id: String::new() }))
    }

    /// AUTHZ: Super only, like `RescanInventory`. A release is the whole
    /// nginx tree -- every tenant's vhosts in one artifact -- so there is no
    /// per-org version of this action, and `publish.shadow_mode` must still
    /// be honoured (`publish::publish` itself already does that).
    async fn publish_now(&self, request: Request<PublishNowRequest>) -> Result<Response<Release>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.elevated_token).await?;
        if claims.kind != TokenType::Elevated {
            return Err(Status::permission_denied("this needs an elevated token"));
        }
        if claims.role != Role::Super {
            return Err(Status::permission_denied("publishing requires a super user"));
        }

        let outcome = crate::publish::publish(&self.config, &self.secrets, req.dry_run)
            .await
            .map_err(Status::from)?;

        let status = if req.dry_run {
            "dry_run"
        } else if outcome.published {
            "published"
        } else {
            "staged"
        };

        releases_db::record(&self.pool, &outcome.release_id, outcome.file_count as i32, &outcome.manifest_sha256, status)
            .await
            .map_err(Status::from)?;

        log!(LogLevel::Info, "release {}: {status} ({} file(s))", outcome.release_id, outcome.file_count);

        Ok(Response::new(Release {
            release_id: outcome.release_id,
            file_count: outcome.file_count as i32,
            manifest_sha256: outcome.manifest_sha256,
            status: status.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
        }))
    }

    /// AUTHZ: Super only, for the same reason as `publish_now`.
    async fn list_releases(
        &self,
        request: Request<ListReleasesRequest>,
    ) -> Result<Response<ListReleasesResponse>, Status> {
        let req = request.into_inner();
        let claims = self.caller(&req.access_token).await?;
        if claims.role != Role::Super {
            return Err(Status::permission_denied("listing releases requires a super user"));
        }

        let limit = if req.limit <= 0 { 50 } else { req.limit as i64 };
        let rows = releases_db::list(&self.pool, limit).await.map_err(Status::from)?;

        Ok(Response::new(ListReleasesResponse {
            releases: rows
                .into_iter()
                .map(|row| Release {
                    release_id: row.release_id,
                    file_count: row.file_count,
                    manifest_sha256: row.manifest_sha256.unwrap_or_default(),
                    status: row.status,
                    created_at: row.created_at,
                })
                .collect(),
        }))
    }
}

/// What's left of Phase 6's stub-tracking tests, now that Phase 7 landed
/// every RPC that used to be tracked here (see the crate's rollout plan).
///
/// `the_unimplemented_rpcs_say_so_rather_than_answering` -- the test that
/// asserted a whole list of RPCs still answered `unimplemented` -- is gone
/// per that plan's own Phase 8 note ("delete when done, not patch the
/// count"): there is nothing left in `DomainService` for it to track.
/// `every_stub_documents_its_authorization` survives in a smaller form: one
/// `pending()` call site remains (`convert_vhost`'s `template == "structured"`
/// branch, a real, still-unbuilt feature, not a placeholder for an RPC that
/// doesn't exist yet), and it still deserves its own AUTHZ note.
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

        // Just `convert_vhost`'s "structured" branch now that Phase 7 landed
        // every RPC-level stub -- update this the moment that lands too,
        // rather than letting it drift from reality.
        assert_eq!(call_sites, 1, "expected exactly convert_vhost's remaining pending() call, found {call_sites}");
        assert!(
            undocumented.is_empty(),
            "these stubs do not say what authorization they will need:\n{}",
            undocumented.join("\n")
        );
    }

    fn add_req(kind: &str, prefix: &str, digits: i32, min: i64, max: i64) -> AddReservedNameRequest {
        AddReservedNameRequest { kind: kind.into(), prefix: prefix.into(), digits, min_value: min, max_value: max, ..Default::default() }
    }

    #[test]
    fn a_reserved_name_request_maps_to_a_rule_and_bad_ones_are_invalid_argument() {
        use crate::reserved::Rule;
        assert_eq!(
            reserved_rule_from_request(&add_req("range", "c", 8, 0, 99_999_999)).unwrap(),
            Rule::Range { prefix: "c".into(), digits: 8, min: 0, max: 99_999_999 }
        );
        assert_eq!(reserved_rule_from_request(&add_req("exact", " www ", 0, 0, 0)).unwrap(), Rule::Exact("www".into()));
        for bad in [
            add_req("regex", "c.*", 0, 0, 0),
            add_req("range", "c", 300, 0, 1),
            add_req("range", "c", 8, -1, 5),
            add_req("range", "c", 3, 0, 1000),
            add_req("exact", "Has Space", 0, 0, 0),
        ] {
            let status = reserved_rule_from_request(&bad).unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument, "{bad:?}");
        }
    }

    #[test]
    fn only_super_may_change_reservations() {
        for role in [Role::Admin, Role::Controller, Role::Viewer, Role::Audit, Role::None] {
            assert_eq!(require_super(role, "x").unwrap_err().code(), Code::PermissionDenied);
        }
        assert!(require_super(Role::Super, "x").is_ok());
    }

    fn service() -> Domains {
        // Nothing here touches the database or ais_auth: every RPC below
        // rejects an empty token before reading anything else. A lazy pool
        // and an unreachable auth address are therefore enough, and keep
        // this a unit test.
        let secrets = Secrets::load(Some(Path::new("/nonexistent/ais_domains.env")))
            .expect("a missing env file is not fatal");
        let pool = sqlx::MySqlPool::connect_lazy("mysql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");

        let mut config = Config::default();
        // Plaintext, so building the client needs no certificate on disk. The
        // address is never dialled: `connect_lazy` only registers with the
        // reactor, and no test here gets far enough to make a call.
        config.auth.grpc_addr = "http://127.0.0.1:1".to_owned();
        config.billing.grpc_addr = "http://127.0.0.1:1".to_owned();

        Domains::new(config, secrets, pool).expect("service")
    }

    /// An empty token (`access_token` or `elevated_token`, whichever the RPC
    /// reads first) is rejected before anything else happens, on every RPC
    /// this service implements -- the one check that must never depend on
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

        for (name, status) in [
            (
                "validate_freeform_vhost",
                service
                    .validate_freeform_vhost(Request::new(ValidateFreeformVhostRequest::default()))
                    .await
                    .err(),
            ),
            (
                "apply_freeform_vhost",
                service
                    .apply_freeform_vhost(Request::new(ApplyFreeformVhostRequest::default()))
                    .await
                    .err(),
            ),
            ("convert_vhost", service.convert_vhost(Request::new(ConvertVhostRequest::default())).await.err()),
            (
                "list_dns_records",
                service.list_dns_records(Request::new(ListDnsRecordsRequest::default())).await.err(),
            ),
            (
                "create_dns_record",
                service.create_dns_record(Request::new(CreateDnsRecordRequest::default())).await.err(),
            ),
            (
                "update_dns_record",
                service.update_dns_record(Request::new(UpdateDnsRecordRequest::default())).await.err(),
            ),
            (
                "delete_dns_record",
                service.delete_dns_record(Request::new(DeleteDnsRecordRequest::default())).await.err(),
            ),
            ("search_domains", service.search_domains(Request::new(SearchRequest::default())).await.err()),
            ("quote_domain", service.quote_domain(Request::new(QuoteRequest::default())).await.err()),
            ("create_order", service.create_order(Request::new(CreateOrderRequest::default())).await.err()),
            ("get_order", service.get_order(Request::new(GetOrderRequest::default())).await.err()),
            ("list_orders", service.list_orders(Request::new(ListOrdersRequest::default())).await.err()),
            ("add_domain", service.add_domain(Request::new(AddDomainRequest::default())).await.err()),
            ("get_domain", service.get_domain(Request::new(GetDomainRequest::default())).await.err()),
            ("list_domains", service.list_domains(Request::new(ListDomainsRequest::default())).await.err()),
            ("remove_domain", service.remove_domain(Request::new(RemoveDomainRequest::default())).await.err()),
            (
                "verify_domain_now",
                service.verify_domain_now(Request::new(VerifyDomainRequest::default())).await.err(),
            ),
            (
                "watch_domain",
                service.watch_domain(Request::new(WatchDomainRequest::default())).await.err(),
            ),
            ("detach_domain", service.detach_domain(Request::new(DetachDomainRequest::default())).await.err()),
            (
                "invite_domain_member",
                service.invite_domain_member(Request::new(InviteDomainMemberRequest::default())).await.err(),
            ),
            (
                "list_domain_members",
                service.list_domain_members(Request::new(ListDomainMembersRequest::default())).await.err(),
            ),
            (
                "remove_domain_member",
                service.remove_domain_member(Request::new(RemoveDomainMemberRequest::default())).await.err(),
            ),
            (
                "list_certificates",
                service.list_certificates(Request::new(ListCertificatesRequest::default())).await.err(),
            ),
            ("force_renew", service.force_renew(Request::new(ForceRenewRequest::default())).await.err()),
            ("publish_now", service.publish_now(Request::new(PublishNowRequest::default())).await.err()),
            ("list_releases", service.list_releases(Request::new(ListReleasesRequest::default())).await.err()),
            (
                "list_reserved_names",
                service.list_reserved_names(Request::new(ListReservedNamesRequest::default())).await.err(),
            ),
            (
                "add_reserved_name",
                service.add_reserved_name(Request::new(AddReservedNameRequest::default())).await.err(),
            ),
            ("check_free_name", service.check_free_name(Request::new(CheckFreeNameRequest::default())).await.err()),
            (
                "claim_free_address",
                service.claim_free_address(Request::new(ClaimFreeAddressRequest::default())).await.err(),
            ),
            (
                "remove_reserved_name",
                service.remove_reserved_name(Request::new(RemoveReservedNameRequest::default())).await.err(),
            ),
        ] {
            let status = status.unwrap_or_else(|| panic!("{name}: no token is not a valid request"));
            assert_eq!(status.code(), Code::Unauthenticated, "{name}: {}", status.message());
        }
    }
}
