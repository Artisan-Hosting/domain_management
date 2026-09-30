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
//!
//! # Money
//!
//! A registration cannot be refunded once it succeeds, and the customer has
//! already paid by the time one is attempted. So:
//!
//! * The price is **re-checked immediately before** buying; a name that is gone,
//!   or dearer than the quote by more than `purchasing.max_cost_drift_cents`,
//!   is refunded instead of bought.
//! * `cf_workflow_state = 'requested'` is written **before** the registrar is
//!   called. From then on the order is only ever polled, never registered
//!   again -- a crash or a lost response can leave an order for an admin to
//!   look at, but can never buy the name twice.
//! * If the registration fails, or the registrar refused the request outright
//!   (a 4xx), the customer is refunded in full.
//! * If it needs a human (`action_required`, `blocked`), or the job runs out of
//!   attempts after the customer paid, the order goes to `needs_admin` and
//!   **keeps the money** until someone decides.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;

use crate::cloudflare::registrar::{self, RegistrationRequest, RegistrationState};
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

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Whether an order created at `created_at` has waited longer than `window_secs`.
fn payment_window_passed(created_at: i64, now: i64, window_secs: i64) -> bool {
    now.saturating_sub(created_at) > window_secs
}

/// Why the price re-check stopped a purchase.
enum Recheck {
    /// Buying would be wrong: refund the customer.
    Decline(String),
    /// Couldn't find out: try again, don't buy and don't refund yet.
    Retry(String),
}

/// Whether to go ahead at the registry's current price. Pure so the money rule
/// is testable without Cloudflare.
fn cost_verdict(registrable: bool, cost_cents: Option<i64>, quoted_cents: i64, max_drift_cents: i64) -> Result<(), String> {
    if !registrable {
        return Err("the name is no longer available".to_owned());
    }
    let Some(now) = cost_cents else {
        return Err("the registry returned no price for the name".to_owned());
    };
    if now > quoted_cents.saturating_add(max_drift_cents) {
        return Err(format!(
            "the registry's price rose from {quoted_cents}c to {now}c, past the {max_drift_cents}c we absorb"
        ));
    }
    Ok(())
}

/// Whether a failed `register()` call definitely did not buy the domain.
/// Cloudflare rejecting the request (4xx, bar a timeout or a rate limit) means
/// nothing was registered; a timeout, a 5xx or an unreadable answer might mean
/// it was, which is why those are polled for instead.
fn definitely_not_registered(err: &crate::error::Error) -> bool {
    match err {
        crate::error::Error::Cloudflare(message) => {
            message.contains("HTTP 4") && !message.contains("HTTP 408") && !message.contains("HTTP 429")
        }
        _ => false,
    }
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

        // Payment is confirmed before any registration, every time it has not
        // yet been: an order an admin re-queued out of `needs_admin` with no
        // registration started goes back through here, never straight to the
        // registrar.
        let registration_started = order.cf_workflow_state.is_some() || matches!(order.state.as_str(), "paid" | "registering");
        if order.state == "awaiting_payment" || !registration_started {
            return self.await_payment(&order).await;
        }

        self.register_domain(&order).await
    }

    async fn await_payment(&self, order: &OrderRow) -> JobOutcome {
        // Asked by `(consumer, external_reference)`, not by the stored
        // Stripe id -- Billing indexes on both, and this is the pair
        // `CreateOrder` used to create the intent in the first place.
        let reference = format!("domain_management:{}", order.id);

        if order.stripe_payment_intent_id.is_none() {
            // `create_order` died between recording the order and creating
            // its charge. Billing creates it once per (consumer, order id), so
            // making it here is safe; the customer can resume it from the
            // order.
            match self
                .billing
                .create_payment_intent(
                    "domain_management",
                    &order.id.to_string(),
                    order.price_cents,
                    &order.currency.to_lowercase(),
                    &[("fqdn", order.fqdn.as_str()), ("organization_id", order.organization_id.as_str())],
                )
                .await
            {
                Ok(payment) => {
                    if let Err(err) =
                        orders_db::set_payment_intent(&self.pool, order.id, &payment.stripe_payment_intent_id).await
                    {
                        return JobOutcome::Failed(err.to_string());
                    }
                }
                Err(err) => return JobOutcome::Failed(format!("order {}: creating the missing payment: {err}", order.id)),
            }
        }

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
                let _ = orders_db::update_state(&self.pool, order.id, "failed", Some("payment was canceled")).await;
                log!(LogLevel::Info, "order {}: payment was canceled", order.id);
                JobOutcome::Done
            }
            // requires_payment_method / requires_confirmation / requires_action /
            // processing / requires_capture / unspecified: still in progress
            // from the customer's side -- for a while.
            _ if payment_window_passed(order.created_at, now_unix(), self.config.purchasing.payment_window_secs) => {
                self.expire_unpaid(order, &reference).await
            }
            _ => JobOutcome::Waiting,
        }
    }

    /// The customer never paid. Cancel the charge so a late payment can't land
    /// on an order that is no longer being processed, and close the order. If
    /// the cancel is refused the payment probably just succeeded, so look
    /// again next time rather than assume.
    async fn expire_unpaid(&self, order: &OrderRow, reference: &str) -> JobOutcome {
        match self.billing.cancel_payment_intent(reference).await {
            Ok(_) => {
                let message = "payment was not completed in time";
                let _ = orders_db::update_state(&self.pool, order.id, "failed", Some(message)).await;
                log!(LogLevel::Info, "order {}: {message}", order.id);
                JobOutcome::Done
            }
            Err(err) => {
                log!(LogLevel::Warn, "order {}: could not cancel the unpaid charge ({err}); checking again", order.id);
                JobOutcome::Waiting
            }
        }
    }

    /// Refunds the customer in full and closes the order. Billing refunds once
    /// per payment however many times this is asked, so a retry after a crash
    /// between the refund and recording it is safe. If the refund itself fails
    /// the job is retried, and if it keeps failing the order goes to
    /// `needs_admin` with the money still held.
    async fn refund_and_close(&self, order: &OrderRow, reason: &str) -> JobOutcome {
        let reference = format!("domain_management:{}", order.id);
        let refund = match self.billing.refund_payment_intent(&reference, reason).await {
            Ok(refund) => refund,
            Err(err) => return JobOutcome::Failed(format!("order {}: refunding ({reason}): {err}", order.id)),
        };
        if let Err(err) = orders_db::mark_refunded(&self.pool, order.id, &refund.refund_id, reason).await {
            return JobOutcome::Failed(format!("order {}: refunded ({}) but could not record it: {err}", order.id, refund.refund_id));
        }
        log!(LogLevel::Warn, "order {}: refunded ({}): {reason}", order.id, refund.refund_id);
        JobOutcome::Done
    }

    /// Re-checks the registry's real-time price right before buying.
    async fn recheck_cost(&self, order: &OrderRow, cf: &CfSuite) -> Result<(), Recheck> {
        let answers = registrar::check(&cf.registrar, &cf.account_id, &[order.fqdn.clone()])
            .await
            .map_err(|err| Recheck::Retry(format!("re-checking the price: {err}")))?;
        let answer = answers
            .into_iter()
            .find(|a| a.name.eq_ignore_ascii_case(&order.fqdn))
            .ok_or_else(|| Recheck::Retry("the registry did not answer for this name".to_owned()))?;
        let cost = match answer.pricing.as_ref().map(|p| p.registration_cost_cents()).transpose() {
            Ok(cost) => cost,
            Err(err) => return Err(Recheck::Retry(format!("reading the registry's price: {err}"))),
        };
        cost_verdict(answer.registrable, cost, order.cost_cents, self.config.purchasing.max_cost_drift_cents)
            .map_err(Recheck::Decline)
    }

    async fn register_domain(&self, order: &OrderRow) -> JobOutcome {
        let cf = match CfSuite::new(&self.config, &self.secrets) {
            Ok(cf) => cf,
            Err(err) => return JobOutcome::Failed(format!("order {}: cloudflare client: {err}", order.id)),
        };

        let registration = if order.cf_workflow_state.is_none() {
            // First time this order reaches this step. The customer has paid
            // and a registration can't be undone, so: price check first...
            match self.recheck_cost(order, &cf).await {
                Ok(()) => {}
                Err(Recheck::Decline(reason)) => return self.refund_and_close(order, &reason).await,
                Err(Recheck::Retry(why)) => return JobOutcome::Failed(format!("order {}: {why}", order.id)),
            }

            // ...then write down that we are about to buy, *before* buying.
            // If this write fails nothing has been bought and the job retries.
            if let Err(err) = orders_db::begin_registration(&self.pool, order.id).await {
                return JobOutcome::Failed(format!(
                    "order {}: could not record the registration before starting it, so not registering: {err}",
                    order.id
                ));
            }

            // `respond_async` since this worker already polls -- there's no
            // reason to hold the request open for a registry round trip.
            let request = RegistrationRequest::new(&order.fqdn);
            match registrar::register(&cf.registrar, &cf.account_id, &request, true).await {
                Ok(result) => result,
                Err(err) if definitely_not_registered(&err) => {
                    return self.refund_and_close(order, &format!("the registrar refused the registration: {err}")).await;
                }
                // Timeout, 5xx, undecodable: the purchase may or may not have
                // happened. It is recorded as requested, so the next run
                // *polls* for it and never buys again.
                Err(err) => return JobOutcome::Failed(format!("order {}: registrar purchase: {err}", order.id)),
            }
        } else {
            match registrar::registration_status(&cf.registrar, &cf.account_id, &order.fqdn).await {
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
                self.refund_and_close(order, &message).await
            }
            // The registry wants something a person has to do (contact
            // verification, a block). The customer's money stays put until
            // someone decides; re-queue the job after acting to resume.
            RegistrationState::ActionRequired | RegistrationState::Blocked => {
                let detail = registration.error.map(|e| format!(": {}", e.message)).unwrap_or_default();
                let message = format!("the registry needs action ({}){detail}", registration.state.as_str());
                let _ = orders_db::mark_needs_admin(&self.pool, order.id, &message).await;
                log!(LogLevel::Warn, "order {}: {message}", order.id);
                JobOutcome::Done
            }
            // Pending / InProgress / Unknown: the registry is still working
            // on it, or returned a state this build doesn't recognise --
            // either way, poll again rather than guess.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn a_price_within_the_absorbed_drift_is_fine_and_one_past_it_is_declined() {
        assert!(cost_verdict(true, Some(1000), 1000, 100).is_ok());
        assert!(cost_verdict(true, Some(900), 1000, 100).is_ok(), "cheaper is always fine");
        assert!(cost_verdict(true, Some(1100), 1000, 100).is_ok(), "exactly the drift is fine");
        let err = cost_verdict(true, Some(1101), 1000, 100).unwrap_err();
        assert!(err.contains("rose from 1000c to 1101c"), "{err}");
    }

    #[test]
    fn a_name_that_is_gone_or_unpriced_is_declined() {
        assert!(cost_verdict(false, Some(500), 500, 100).unwrap_err().contains("no longer available"));
        assert!(cost_verdict(true, None, 500, 100).unwrap_err().contains("no price"));
    }

    #[test]
    fn the_payment_window_is_exclusive_and_tolerates_clock_skew() {
        assert!(!payment_window_passed(1000, 1000 + 3600, 3600));
        assert!(payment_window_passed(1000, 1000 + 3601, 3600));
        assert!(!payment_window_passed(5000, 1000, 3600), "an order 'from the future' is not expired");
    }

    #[test]
    fn only_a_definite_rejection_counts_as_not_registered() {
        let cf = |m: &str| Error::Cloudflare(m.to_owned());
        assert!(definitely_not_registered(&cf("registrar POST x: HTTP 400 Bad Request: domain unavailable")));
        assert!(definitely_not_registered(&cf("registrar POST x: HTTP 403 Forbidden: nope")));
        // Ambiguous: the purchase may have gone through.
        assert!(!definitely_not_registered(&cf("registrar POST x: HTTP 500 Internal Server Error: boom")));
        assert!(!definitely_not_registered(&cf("registrar POST x: HTTP 408 Request Timeout")));
        assert!(!definitely_not_registered(&cf("registrar POST x: HTTP 429 Too Many Requests")));
        assert!(!definitely_not_registered(&cf("registrar POST x: error sending request: timed out")));
        assert!(!definitely_not_registered(&Error::Billing("x".into())));
    }
}
