//! Queries behind `domain_quotes` and `domain_orders` -- the purchasing
//! RPCs' own tables, distinct from the adoption-focused `crate::db::inventory`
//! and the lifecycle-focused `crate::db::domains` (not yet written).
//!
//! Money is stored in minor units (cents) as `BIGINT`/`i64`. No floats
//! anywhere near a charge, per the migration's own doc comment.

use sqlx::{MySqlPool, Row};

use crate::config::Purchasing;
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

/// What [`insert_order_with_job`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum NewOrder {
    Created(u64),
    /// The organization is at its daily order count or monthly spend cap.
    CapReached,
}

/// Records a new order in `awaiting_payment` **and** queues its `register`
/// job, in one transaction: an order with no job would sit waiting for a
/// payment nothing ever checks, and a job with no order is meaningless.
///
/// The organization's spending caps are checked inside the same transaction,
/// under a per-organization lock, so concurrent orders cannot each pass a cap
/// that together they would exceed.
///
/// A duplicate quote or a name already being bought fails on the unique
/// keys from migration 0007; see [`is_duplicate`].
#[allow(clippy::too_many_arguments)]
pub async fn insert_order_with_job(
    pool: &MySqlPool,
    purchasing: &Purchasing,
    fqdn: &str,
    organization_id: &str,
    user_id: &str,
    quote_id: &str,
    cost_cents: i64,
    price_cents: i64,
    currency: &str,
    runner_id: &str,
    invite_email: &str,
) -> Result<NewOrder> {
    // A named lock belongs to the connection that took it, so everything
    // below runs on this one connection and the lock is released on it.
    let mut conn = pool.acquire().await?;
    lock_org_orders(&mut *conn, organization_id).await?;
    let outcome = insert_locked(
        &mut *conn, purchasing, fqdn, organization_id, user_id, quote_id, cost_cents, price_cents, currency, runner_id,
        invite_email,
    )
    .await;
    // Released whatever happened above. If this fails the connection is
    // dropped from the pool's reuse by closing it, which frees the lock.
    if unlock_org_orders(&mut *conn, organization_id).await.is_err() {
        let _ = conn.close_on_drop();
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn insert_locked(
    conn: &mut sqlx::MySqlConnection,
    purchasing: &Purchasing,
    fqdn: &str,
    organization_id: &str,
    user_id: &str,
    quote_id: &str,
    cost_cents: i64,
    price_cents: i64,
    currency: &str,
    runner_id: &str,
    invite_email: &str,
) -> Result<NewOrder> {
    if !crate::purchasing::under_caps(&mut *conn, organization_id, price_cents, purchasing).await? {
        return Ok(NewOrder::CapReached);
    }

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;

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
    .execute(&mut *tx)
    .await?;
    let order_id = result.last_insert_id();

    sqlx::query("INSERT INTO jobs (kind, order_id) VALUES ('register', ?)")
        .bind(order_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(NewOrder::Created(order_id))
}

/// How long an order waits for another order of the same organization to
/// finish being recorded. Recording is a handful of statements, so this is
/// only ever hit if something is badly stuck.
const ORG_LOCK_WAIT_SECS: i64 = 10;

/// The lock name is hashed: MySQL caps names at 64 characters.
async fn lock_org_orders(conn: &mut sqlx::MySqlConnection, organization_id: &str) -> Result<()> {
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT('dm_orders:', MD5(?)), ?)")
        .bind(organization_id)
        .bind(ORG_LOCK_WAIT_SECS)
        .fetch_one(&mut *conn)
        .await?;
    if got != Some(1) {
        return Err(crate::error::Error::Invalid(
            "another order for this organization is being recorded; try again".to_owned(),
        ));
    }
    Ok(())
}

async fn unlock_org_orders(conn: &mut sqlx::MySqlConnection, organization_id: &str) -> Result<()> {
    sqlx::query("SELECT RELEASE_LOCK(CONCAT('dm_orders:', MD5(?)))")
        .bind(organization_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Whether `err` is MySQL's duplicate-key error (1062).
pub fn is_duplicate(err: &crate::error::Error) -> bool {
    match err {
        crate::error::Error::Database(sqlx::Error::Database(db)) => db.code().as_deref() == Some("23000") && db.message().contains("Duplicate entry"),
        _ => false,
    }
}

pub async fn find_order_by_quote(pool: &MySqlPool, quote_id: &str) -> Result<Option<OrderRow>> {
    let row = sqlx::query(&format!("{ORDER_SELECT} WHERE quote_id = ?")).bind(quote_id).fetch_optional(pool).await?;
    Ok(row.map(row_to_order))
}

/// The order that currently holds `fqdn` (any state but failed/refunded), if any.
pub async fn find_live_order_for_fqdn(pool: &MySqlPool, fqdn: &str) -> Result<Option<OrderRow>> {
    let row = sqlx::query(&format!("{ORDER_SELECT} WHERE live_fqdn = ?")).bind(fqdn).fetch_optional(pool).await?;
    Ok(row.map(row_to_order))
}

/// Written **before** the registrar is called. Once this is set the order is
/// only ever polled, never registered again, so a crash between this write and
/// the registrar call cannot lead to buying the name twice -- the worst case is
/// an order an admin has to look at.
pub async fn begin_registration(pool: &MySqlPool, order_id: u64) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET state = 'registering', cf_workflow_state = 'requested' WHERE id = ?")
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// The registry has definitively not registered this name (it refused, or
/// reported failure). Written **before** the refund is attempted, so a refund
/// that fails and is retried goes straight back to refunding instead of
/// polling the registrar for a registration that will never exist.
pub async fn record_registration_failure(pool: &MySqlPool, order_id: u64, reason: &str) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET cf_workflow_state = 'failed', last_error = ? WHERE id = ?")
        .bind(reason)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// The customer has been refunded in full.
pub async fn mark_refunded(pool: &MySqlPool, order_id: u64, refund_id: &str, reason: &str) -> Result<()> {
    sqlx::query("UPDATE domain_orders SET state = 'refunded', stripe_refund_id = ?, last_error = ? WHERE id = ?")
        .bind(refund_id)
        .bind(reason)
        .bind(order_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hands an order to a human. Only moves an order that is still in flight, so
/// it can never overwrite `completed`, `failed` or `refunded`.
pub async fn mark_needs_admin(pool: &MySqlPool, order_id: u64, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE domain_orders SET state = 'needs_admin', last_error = ? \
         WHERE id = ? AND state IN ('awaiting_payment', 'paid', 'registering')",
    )
    .bind(reason)
    .bind(order_id)
    .execute(pool)
    .await?;
    Ok(())
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
