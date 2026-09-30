//! Talking to `Billing`.
//!
//! Stripe integration lives there and nowhere else on this platform -- this
//! service never holds a Stripe key, never talks to `api.stripe.com`
//! directly, and never verifies a Stripe webhook signature itself.
//! `proto/domains.proto` no longer even declares a `HandleStripeWebhook`
//! RPC of its own for that reason: Portal's webhook-forwarding route calls
//! Billing's `HandleStripeWebhook` directly, and anything here that needs
//! to know about a charge calls the methods below instead.
//!
//! No access token travels with these calls: Billing is reached only over
//! mTLS, and it trusts the calling service (proven by its client
//! certificate) to have already validated the end user and enforced
//! `Pricing`/`Purchasing` before ever asking Billing to create a charge --
//! see `Billing/src/grpc/service.rs`'s own module doc for the reasoning on
//! that side.

use tokio_stream::Stream;
use tonic::transport::Channel;

use crate::error::{Error, Result};
use crate::proto::billing::billing_admin_service_client::BillingAdminServiceClient;
use crate::proto::billing::billing_service_client::BillingServiceClient;
use crate::proto::billing::{
    BillingStatus, CancelPaymentIntentRequest, CreatePaymentIntentRequest, GetOrganizationBillingStatusRequest,
    GetPaymentIntentRequest, PaymentIntent, PaymentIntentStatus, RefundPaymentIntentRequest,
    RefundPaymentIntentResponse, WatchPaymentIntentRequest,
};

#[derive(Clone)]
pub struct BillingClient {
    channel: Channel,
}

impl BillingClient {
    /// Lazy connection, the same pattern `AuthClient::new` uses: no network
    /// I/O happens here, so a CLI invocation that never touches billing
    /// pays nothing for constructing this. `https://` presents this
    /// service's own client certificate (`ais_domain`) and checks
    /// Billing's certificate against the name `ais_billing` (override with
    /// `BILLING_TLS_SERVER_NAME`); `http://` is plaintext, local dev only.
    ///
    /// Must be called from inside a Tokio runtime, same caveat as
    /// `AuthClient::new`.
    pub fn new(addr: &str) -> Result<Self> {
        let config_err = |detail: String| Error::Config(format!("billing.grpc_addr {addr:?}: {detail}"));

        let mtls = if crate::mtls_client::wants_tls(addr) {
            Some(crate::mtls_client::ClientMtls::load("ais_domain").map_err(config_err)?)
        } else {
            None
        };
        let server_name = std::env::var("BILLING_TLS_SERVER_NAME").unwrap_or_else(|_| "ais_billing".to_owned());
        let channel =
            crate::mtls_client::internal_channel(addr, &server_name, mtls.as_ref()).map_err(config_err)?;

        Ok(Self { channel })
    }

    fn client(&self) -> BillingServiceClient<Channel> {
        BillingServiceClient::new(self.channel.clone())
    }

    fn admin_client(&self) -> BillingAdminServiceClient<Channel> {
        BillingAdminServiceClient::new(self.channel.clone())
    }

    /// Whether `organization_id` is in good enough standing to make a *new*
    /// purchase -- called by `create_order` before charging, fail-closed
    /// (see that call site's own comment): if Billing can't be reached at
    /// all, this returns `Err(Error::Unavailable(..))` via `status_to_error`
    /// rather than a default "fine," and the caller refuses the purchase
    /// rather than risk letting a suspended org buy something.
    pub async fn organization_permits_new_purchases(&self, organization_id: &str) -> Result<bool> {
        let response = self
            .admin_client()
            .get_organization_billing_status(GetOrganizationBillingStatusRequest {
                organization_id: organization_id.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(matches!(response.status(), BillingStatus::Active | BillingStatus::PastDue))
    }

    /// Idempotent per `(consumer, external_reference)` on Billing's own
    /// side -- calling this twice for the same pair (a retried RPC after a
    /// timeout, say) returns the existing PaymentIntent rather than
    /// creating a second Stripe charge. `consumer` should be a fixed
    /// string identifying this service (e.g. `"domain_management"`);
    /// `external_reference` is this service's own id for whatever it's
    /// charging for (a `domain_orders.id`).
    pub async fn create_payment_intent(
        &self,
        consumer: &str,
        external_reference: &str,
        amount_cents: i64,
        currency: &str,
        metadata: &[(&str, &str)],
    ) -> Result<PaymentIntent> {
        let response = self
            .client()
            .create_payment_intent(CreatePaymentIntentRequest {
                consumer: consumer.to_owned(),
                external_reference: external_reference.to_owned(),
                amount_cents,
                currency: currency.to_owned(),
                metadata: metadata.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response)
    }

    /// `id_or_reference` is either Billing's own `PaymentIntent.id`, or
    /// `"<consumer>:<external_reference>"`.
    pub async fn get_payment_intent(&self, id_or_reference: &str) -> Result<PaymentIntent> {
        let response = self
            .client()
            .get_payment_intent(GetPaymentIntentRequest {
                id_or_reference: id_or_reference.to_owned(),
                include_client_secret: false,
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response)
    }

    /// Like [`get_payment_intent`], but also returns the `client_secret` and
    /// `publishable_key` so the customer can be handed the payment form for an
    /// intent created earlier (a retried or resumed order). Billing only
    /// honours it while the intent can still be paid; the secret is fetched
    /// from Stripe each time, never stored.
    pub async fn get_payment_intent_for_checkout(&self, id_or_reference: &str) -> Result<PaymentIntent> {
        let response = self
            .client()
            .get_payment_intent(GetPaymentIntentRequest {
                id_or_reference: id_or_reference.to_owned(),
                include_client_secret: true,
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response)
    }

    /// Refunds a succeeded payment in full. Idempotent per PaymentIntent on
    /// Billing's side, so calling this again after a crash that lost the
    /// result is safe and returns the same refund.
    pub async fn refund_payment_intent(
        &self,
        id_or_reference: &str,
        reason: &str,
    ) -> Result<RefundPaymentIntentResponse> {
        let response = self
            .client()
            .refund_payment_intent(RefundPaymentIntentRequest {
                id_or_reference: id_or_reference.to_owned(),
                reason: reason.to_owned(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response)
    }

    /// Yields a new value only when Billing's own record of the payment
    /// intent's status changes, ending once it reaches a terminal state
    /// (`succeeded`/`canceled`). For a caller (the future `register` job)
    /// that wants to know the moment a charge resolves without polling
    /// [`get_payment_intent`] in its own loop.
    pub async fn watch_payment_intent(
        &self,
        id_or_reference: &str,
    ) -> Result<impl Stream<Item = Result<PaymentIntent>>> {
        let stream = self
            .client()
            .watch_payment_intent(WatchPaymentIntentRequest { id_or_reference: id_or_reference.to_owned() })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(tokio_stream::StreamExt::map(stream, |item| item.map_err(status_to_error)))
    }

    pub async fn cancel_payment_intent(&self, id_or_reference: &str) -> Result<PaymentIntent> {
        let response = self
            .client()
            .cancel_payment_intent(CancelPaymentIntentRequest { id_or_reference: id_or_reference.to_owned() })
            .await
            .map_err(status_to_error)?
            .into_inner();

        Ok(response)
    }
}

/// A raw Stripe status string, as Billing reports it via
/// [`PaymentIntentStatus`], to whichever domain-orders state this
/// service's own `OrderState`/`DomainStatus` proto enums should transition
/// to. Kept here (not in `grpc/service.rs`) since it's specifically about
/// interpreting Billing's response shape, not this service's own request
/// handling.
pub fn is_terminal(status: PaymentIntentStatus) -> bool {
    matches!(status, PaymentIntentStatus::Succeeded | PaymentIntentStatus::Canceled)
}

fn status_to_error(status: tonic::Status) -> Error {
    match status.code() {
        tonic::Code::InvalidArgument => Error::Invalid(status.message().to_owned()),
        tonic::Code::NotFound => Error::NotFound(status.message().to_owned()),
        tonic::Code::FailedPrecondition => Error::Invalid(status.message().to_owned()),
        tonic::Code::Unavailable => Error::Unavailable(format!("billing is unreachable: {}", status.message())),
        _ => Error::Billing(format!("{status}")),
    }
}
