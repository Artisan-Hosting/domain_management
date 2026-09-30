//! The `register` job's real body: wait for payment, then buy the domain
//! and bring it fully live.
//!
//! A small state machine driven by `domain_orders.state` (and, once
//! registration is in flight, `domain_orders.cf_workflow_state`) rather
//! than anything held in memory -- the job can be claimed, run one step,
//! and reclaimed arbitrarily many times before it finishes, and every step
//! has to be safe to repeat. Two states in particular:
//!
//! * `awaiting_payment` -- ask Billing whether the PaymentIntent it's
//!   holding for this order has resolved. Not yet -> [`JobOutcome::Waiting`],
//!   checked again soon without spending an attempt (see `super`'s module
//!   doc on why that outcome exists). Succeeded -> transition to `paid` and
//!   let the *next* claim start the registrar call, so a failure in the
//!   registration half never needs to re-derive "was this paid for."
//! * `paid` (or already `registering`) -- kick off (or poll) the
//!   registrar purchase. `cf_workflow_state` being unset is exactly how
//!   this tells "start a new registration" from "poll the one already
//!   requested" apart across separate runs -- calling `register()` twice
//!   for the same domain would be a second attempt to buy it.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;

use crate::cloudflare::registrar::{RegistrationRequest, RegistrationState};
use crate::cloudflare::{CfSuite, dns, zones};
use crate::db::{domains as domains_db, orders as orders_db};
use crate::db::orders::OrderRow;
use crate::proto::billing::PaymentIntentStatus;

use super::{Job, JobOutcome, Worker};

/// States that mean "nothing left for this job to do" -- claiming a
/// `register` job for an order already in one of these is a redundant
/// wakeup (the order finished on the runs before the job's own terminal
/// state made it back to `jobs`), not an error.
fn is_order_terminal(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "refunded")
}

impl Worker {
    pub(super) async fn run_register(&self, job: &Job) -> JobOutcome {
        let Some(order_id) = job.order_id else {
            return JobOutcome::Failed(format!("job {}: a register job with no order_id", job.id));
        };

        let order = match orders_db::find_order(&self.pool, order_id).await {
            Ok(Some(order)) => order,
            Ok(None) => return JobOutcome::Failed(format!("job {}: order {order_id} not found", job.id)),
            Err(err) => return JobOutcome::Failed(err.to_string()),
        };

        if is_order_terminal(&order.state) {
            return JobOutcome::Done;
        }

        if order.state == "awaiting_payment" {
            return self.await_payment(&order).await;
        }

        self.register_domain(&order).await
    }

    async fn await_payment(&self, order: &OrderRow) -> JobOutcome {
        if order.stripe_payment_intent_id.is_none() {
            return JobOutcome::Failed(format!("order {}: no payment intent was ever recorded", order.id));
        }

        // Asked by `(consumer, external_reference)`, not by the stored
        // Stripe id -- Billing indexes on both, and this is the pair
        // `CreateOrder` used to create the intent in the first place.
        let reference = format!("domain_management:{}", order.id);
        let payment = match self.billing.get_payment_intent(&reference).await {
            Ok(payment) => payment,
            Err(err) => return JobOutcome::Failed(format!("order {}: checking payment status: {err}", order.id)),
        };

        let status = PaymentIntentStatus::try_from(payment.status).unwrap_or(PaymentIntentStatus::Unspecified);
        match status {
            PaymentIntentStatus::Succeeded => {
                if let Err(err) = orders_db::update_state(&self.pool, order.id, "paid", None).await {
                    return JobOutcome::Failed(err.to_string());
                }
                log!(LogLevel::Info, "order {}: payment succeeded", order.id);
                // Let the next claim start registration -- keeps this
                // transition and the registrar call as two independently
                // retryable steps instead of one that does both.
                JobOutcome::Waiting
            }
            PaymentIntentStatus::Canceled => {
                let message = "payment was canceled";
                let _ = orders_db::update_state(&self.pool, order.id, "failed", Some(message)).await;
                JobOutcome::Failed(format!("order {}: {message}", order.id))
            }
            // requires_payment_method / requires_confirmation / requires_action /
            // processing / requires_capture / unspecified: still in progress
            // from the customer's side. Nothing to do but wait.
            _ => JobOutcome::Waiting,
        }
    }

    async fn register_domain(&self, order: &OrderRow) -> JobOutcome {
        let cf = match CfSuite::new(&self.config, &self.secrets) {
            Ok(cf) => cf,
            Err(err) => return JobOutcome::Failed(format!("order {}: cloudflare client: {err}", order.id)),
        };

        let registration = if order.cf_workflow_state.is_none() {
            // First time this order reaches this step: kick off the
            // purchase. `respond_async` since this worker already polls --
            // there's no reason to hold the request open for a registry
            // round trip.
            let request = RegistrationRequest::new(&order.fqdn);
            match crate::cloudflare::registrar::register(&cf.registrar, &cf.account_id, &request, true).await {
                Ok(result) => result,
                Err(err) => return JobOutcome::Failed(format!("order {}: registrar purchase: {err}", order.id)),
            }
        } else {
            match crate::cloudflare::registrar::registration_status(&cf.registrar, &cf.account_id, &order.fqdn).await
            {
                Ok(result) => result,
                Err(err) => return JobOutcome::Failed(format!("order {}: checking registration: {err}", order.id)),
            }
        };

        if let Err(err) = orders_db::set_cf_workflow_state(&self.pool, order.id, registration.state.as_str()).await {
            log!(LogLevel::Warn, "order {}: could not record workflow state: {}", order.id, err);
        }

        match registration.state {
            RegistrationState::Succeeded => self.finish_registration(order, &cf).await,
            RegistrationState::Failed => {
                let message = registration
                    .error
                    .map(|e| e.message)
                    .unwrap_or_else(|| "the registry declined this registration".to_owned());
                let _ = orders_db::update_state(&self.pool, order.id, "failed", Some(&message)).await;
                JobOutcome::Failed(format!("order {}: {message}", order.id))
            }
            // Pending / InProgress / ActionRequired / Blocked / Unknown: the
            // registry is still working on it, or Cloudflare returned a
            // state this build doesn't recognise -- either way, poll again
            // rather than guess.
            _ => JobOutcome::Waiting,
        }
    }

    /// The registry confirmed the purchase. From here it's the same
    /// zone/CNAME/certificate sequence `add_domain`'s BYO path and the
    /// existing `issue_one` CLI path already use -- nothing registrar-specific
    /// left, just "a domain this service now controls needs to start serving."
    async fn finish_registration(&self, order: &OrderRow, cf: &CfSuite) -> JobOutcome {
        let zone = match zones::ensure(&cf.zones, &cf.account_id, &order.fqdn).await {
            Ok(zone) => zone,
            Err(err) => return JobOutcome::Failed(format!("order {}: creating the zone: {err}", order.id)),
        };

        let challenge_target = self.config.challenge_target_for(&order.fqdn);
        if let Err(err) = dns::ensure_challenge_cname(&cf.zones, &zone.id, &order.fqdn, &challenge_target).await {
            return JobOutcome::Failed(format!("order {}: challenge CNAME: {err}", order.id));
        }

        let domain_id =
            match domains_db::insert_purchased(&self.pool, &order.fqdn, &order.organization_id, &zone.id, &challenge_target)
                .await
            {
                Ok(id) => id,
                Err(err) => return JobOutcome::Failed(format!("order {}: recording the domain: {err}", order.id)),
            };

        // Same core the CLI's `issue` command and `ForceRenew`/`VerifyDomainNow`
        // use -- see its own doc comment for why this is one function.
        match crate::acme::issue_and_install(&self.config, &self.secrets, &order.fqdn).await {
            Ok(_) => {}
            Err(err) => return JobOutcome::Failed(format!("order {}: issuing the certificate: {err}", order.id)),
        }

        for key_type in crate::acme::KeyType::ALL {
            if let Ok(Some(not_after)) = crate::acme::install::read_expiry(&self.config, &order.fqdn, key_type) {
                let renew_after = not_after - self.config.acme.renew_before_days * 86_400;
                if let Err(err) =
                    domains_db::record_certificate(&self.pool, domain_id, key_type.as_str(), not_after, renew_after)
                        .await
                {
                    log!(LogLevel::Warn, "order {}: could not record the {} certificate: {}", order.id, key_type, err);
                }
            }
        }

        if let Err(err) = domains_db::mark_active(&self.pool, domain_id).await {
            log!(LogLevel::Warn, "order {}: could not mark the domain active: {}", order.id, err);
        }

        // Per the resolved design: purchase only ever records the org/runner
        // assignment. Standing up a vhost is a separate, explicit
        // AttachDomain call once the caller has real backend info.
        if let Some(runner_id) = order.runner_id.as_deref().filter(|id| !id.is_empty()) {
            if let Err(err) =
                crate::db::inventory::set_assignment(&self.pool, domain_id, None, Some(Some(runner_id.to_owned())))
                    .await
            {
                log!(LogLevel::Warn, "order {}: could not record the runner assignment: {}", order.id, err);
            }
        }

        if let Err(err) = orders_db::finish_order(&self.pool, order.id, domain_id).await {
            return JobOutcome::Failed(format!("order {}: marking the order complete: {err}", order.id));
        }

        log!(LogLevel::Info, "order {}: {} registered and issued", order.id, order.fqdn);
        JobOutcome::Done
    }
}
