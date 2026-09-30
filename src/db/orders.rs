//! Queries behind `domain_quotes` and `domain_orders` -- the purchasing
//! RPCs' own tables, distinct from the adoption-focused `crate::db::inventory`
//! and the lifecycle-focused `crate::db::domains` (not yet written).
//!
//! Money is stored in minor units (cents) as `BIGINT`/`i64`. No floats
//! anywhere near a charge, per the migration's own doc comment.

use sqlx::{MySqlPool, Row};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct QuoteRow {
    pub id: String,
    pub fqdn: String,
    pub organization_id: String,
    pub user_id: String,
    pub cost_cents: i64,
    pub price_cents: i64,
    pub currency: String,
    pub tier: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct OrderRow {
    pub id: u64,
    pub fqdn: String,
    pub organization_id: String,
    pub user_id: String,
    pub quote_id: Option<String>,
    pub cost_cents: i64,
    pub price_cents: i64,
    pub currency: String,
    pub state: String,
    /// The last Cloudflare registration workflow state seen
    /// (`RegistrationState`, lowercased) -- `None` until the `register`
    /// job has actually called the registrar, which is how it tells "kick
    /// off a new registration" from "poll the one already in flight"
    /// apart across separate job runs.
    pub cf_workflow_state: Option<String>,
    pub stripe_payment_intent_id: Option<String>,
    pub domain_id: Option<u64>,
    pub runner_id: Option<String>,
    pub invite_email: Option<String>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_quote(
    pool: &MySqlPool,
    id: &str,
    fqdn: &str,
    organization_id: &str,
    user_id: &str,
    cost_cents: i64,
    price_cents: i64,
    currency: &str,
    tier: &str,
    expires_at_unix: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO domain_quotes (id, fqdn, organization_id, user_id, cost_cents, price_cents, \
         currency, tier, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(?))",
    )
    .bind(id)
    .bind(fqdn)
    .bind(organization_id)
    .bind(user_id)
    .bind(cost_cents)
    .bind(price_cents)
    .bind(currency)
    .bind(tier)
    .bind(expires_at_unix)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn find_quote(pool: &MySqlPool, id: &str) -> Result<Option<QuoteRow>> {
    let row = sqlx::query(
        "SELECT id, fqdn, organization_id, user_id, cost_cents, price_cents, currency, tier, \
         UNIX_TIMESTAMP(expires_at) AS expires_at FROM domain_quotes WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| QuoteRow {
        id: row.get("id"),
        fqdn: row.get("fqdn"),
        organization_id: row.get("organization_id"),
        user_id: row.get("user_id"),
        cost_cents: row.get("cost_cents"),
        price_cents: row.get("price_cents"),
        currency: row.get("currency"),
        tier: row.get("tier"),
        expires_at: row.get("expires_at"),
    }))
}

/// Records a new order in `awaiting_payment`. Returns the new row's id.
#[allow(clippy::too_many_arguments)]
pub async fn insert_order(
    pool: &MySqlPool,
    fqdn: &str,
    organization_id: &str,
    user_id: &str,
    quote_id: &str,
    cost_cents: i64,
    price_cents: i64,
    currency: &str,
    runner_id: &str,
    invite_email: &str,
) -> Result<u64> {
    let result = sqlx::query(
        "INSERT INTO domain_orders \
         (fqdn, organization_id, user_id, quote_id, cost_cents, price_cents, currency, state, \
          runner_id, invite_email) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 'awaiting_payment', ?, ?)",
    )
    .bind(fqdn)
    .bind(organization_id)
    .bind(user_id)
    .bind(quote_id)
    .bind(cost_cents)
    .bind(price_cents)
    .bind(currency)
    .bind(none_if_empty(runner_id))
    .bind(none_if_empty(invite_email))
    .execute(pool)
    .await?;

    Ok(result.last_insert_id())
}

pub async fn set_payment_intent(pool: &MySqlPool, order_id: u64, stripe_payment_intent_id: &str) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET stripe_payment_intent_id = ? WHERE id = ?")
        .bind(stripe_payment_intent_id)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_state(pool: &MySqlPool, order_id: u64, state: &str, last_error: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET state = ?, last_error = ? WHERE id = ?")
        .bind(state)
        .bind(last_error)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_cf_workflow_state(pool: &MySqlPool, order_id: u64, cf_workflow_state: &str) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET cf_workflow_state = ? WHERE id = ?")
        .bind(cf_workflow_state)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Marks an order `completed` and links it to the domain the `register`
/// job just created -- the one write that means "this order is fully
/// done," so `run_register` treats `completed` as terminal on its next
/// (redundant, but harmless) claim.
pub async fn finish_order(pool: &MySqlPool, order_id: u64, domain_id: u64) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET state = 'completed', domain_id = ?, last_error = NULL WHERE id = ?")
        .bind(domain_id)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_order(pool: &MySqlPool, id: u64) -> Result<Option<OrderRow>> {
    let row = sqlx::query(&format!("{ORDER_SELECT} WHERE id = ?")).bind(id).fetch_optional(pool).await?;
    Ok(row.map(row_to_order))
}

pub async fn list_orders(
    pool: &MySqlPool,
    organization_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<OrderRow>> {
    let mut builder = sqlx::QueryBuilder::new(ORDER_SELECT);
    if let Some(organization_id) = organization_id {
        builder.push(" WHERE organization_id = ").push_bind(organization_id);
    }
    builder.push(" ORDER BY id DESC LIMIT ").push_bind(limit).push(" OFFSET ").push_bind(offset);

    let rows = builder.build().fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_order).collect())
}

const ORDER_SELECT: &str = "SELECT id, fqdn, organization_id, user_id, quote_id, cost_cents, price_cents, \
     currency, state, cf_workflow_state, stripe_payment_intent_id, domain_id, runner_id, invite_email, \
     last_error, UNIX_TIMESTAMP(created_at) AS created_at, UNIX_TIMESTAMP(updated_at) AS updated_at \
     FROM domain_orders";

fn row_to_order(row: sqlx::mysql::MySqlRow) -> OrderRow {
    OrderRow {
        id: row.get("id"),
        fqdn: row.get("fqdn"),
        organization_id: row.get("organization_id"),
        user_id: row.get("user_id"),
        quote_id: row.get("quote_id"),
        cost_cents: row.get("cost_cents"),
        price_cents: row.get("price_cents"),
        currency: row.get("currency"),
        state: row.get("state"),
        cf_workflow_state: row.get("cf_workflow_state"),
        stripe_payment_intent_id: row.get("stripe_payment_intent_id"),
        domain_id: row.get("domain_id"),
        runner_id: row.get("runner_id"),
        invite_email: row.get("invite_email"),
        last_error: row.get("last_error"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn none_if_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}
