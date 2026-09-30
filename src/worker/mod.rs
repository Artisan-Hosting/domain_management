//! The async job worker -- subsystem 3 of the three described in the crate
//! root doc.
//!
//! The gRPC service (subsystem 2) inserts a row into `jobs` instead of
//! doing the work itself whenever that work fails
//! [`crate::grpc::service`]'s "can this be retried for free" test: it
//! spends money, talks to an external registrar, or otherwise must survive
//! the request that queued it being cancelled or the process being
//! restarted mid-flight. This module is the only thing that ever reads a
//! `queued` row out of that table and the only thing that ever moves one
//! out of `running`.
//!
//! Claiming is a single `SELECT ... FOR UPDATE SKIP LOCKED` transaction
//! ([`Worker::claim_one`]): if two processes (two `Worker`s, or a crashed
//! one and its restart) reach for the same row at once, MySQL hands it to
//! exactly one of them and the other moves on to the next row (or finds
//! none). This is the property that matters most for a `register` job,
//! where running the same row twice means registering -- and charging
//! for -- the same domain twice.
//!
//! A crashed worker's claim does not linger forever: `locked_until` is set
//! when a job is claimed, and [`Worker::reap_expired`] puts any row whose
//! lock has expired back into `queued` for someone (possibly the same
//! worker, restarted) to claim again.
//!
//! Spawned from inside [`crate::grpc::serve`] today, sharing that
//! process's [`sqlx::MySqlPool`]/[`Config`]/[`Secrets`] -- see the seam
//! noted there. Splitting this into its own process later only means
//! moving where `tokio::spawn(Worker::new(...).run())` is called from; the
//! `jobs` table's own locking is what makes that split safe, not the
//! process boundary.

mod register;

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use sqlx::{MySqlPool, Row};
use std::time::Duration;

use crate::billing::BillingClient;
use crate::config::{Config, Secrets};
use crate::error::Result;

/// How long an idle worker sleeps between polls when `jobs` has nothing
/// claimable.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Backoff after a claim/dispatch error that isn't a job failure -- a
/// dropped database connection, say. Deliberately longer than the idle
/// poll: a tight retry loop against a database that just refused a
/// connection makes the outage worse, not better.
const ERROR_BACKOFF: Duration = Duration::from_secs(5);
/// A job that has failed this many times moves to `failed` instead of
/// being requeued. Small on purpose: a `register` job that keeps failing
/// is spending an organization's time (and, if the failure is on
/// Cloudflare's side after the charge went through, possibly their money)
/// on every attempt, and five tries is enough to rule out "transient" long
/// before it's enough to rule out "this will never succeed."
const MAX_ATTEMPTS: i32 = 5;
/// How long a claim holds before [`Worker::reap_expired`] considers it
/// abandoned. Generous relative to any job kind's expected runtime today
/// (a single Cloudflare or Stripe round trip), so a slow-but-alive worker
/// is never mistaken for a crashed one.
const LOCK_DURATION_SECS: i64 = 300;
/// How soon a [`JobOutcome::Waiting`] result is checked again -- short,
/// since this is polling for an external event (a Stripe payment, a
/// Cloudflare registration) resolving, not backing off from a failure.
const WAIT_POLL_SECS: i64 = 5;

/// A claimed row from `jobs`, with `attempts` already reflecting *this*
/// attempt (see [`Worker::claim_one`] -- it increments the column as part
/// of the same transaction that claims the row; [`Worker::wait`] undoes
/// that increment for the one outcome that isn't a real attempt).
#[derive(Debug, Clone)]
struct Job {
    id: u64,
    kind: String,
    #[allow(dead_code)] // read by a job kind's own handler once one exists that needs it
    domain_id: Option<u64>,
    order_id: Option<u64>,
    /// Raw JSON text, left unparsed here -- what shape it needs is a
    /// decision for whichever job kind actually reads it, not this
    /// claim/retry loop. `register` reads its order through `order_id`
    /// instead, so this stays unused for now.
    #[allow(dead_code)]
    payload: Option<String>,
    attempts: i32,
}

/// What running a job decided should happen next. Three outcomes, not two,
/// because "the customer hasn't finished paying yet" and "Cloudflare
/// rejected the request" are different kinds of not-done: one is expected
/// to resolve on its own and shouldn't cost the job an attempt or a
/// backoff delay, the other is a real failure bounded by [`MAX_ATTEMPTS`].
enum JobOutcome {
    Done,
    /// A real failure. Counts toward `MAX_ATTEMPTS`, backed off
    /// exponentially via [`backoff_seconds`].
    Failed(String),
    /// Not ready yet -- waiting on something outside this service
    /// (a payment, a registrar workflow) to resolve. Checked again soon,
    /// on a fixed short delay, and does not count as an attempt.
    Waiting,
}

pub struct Worker {
    pool: MySqlPool,
    config: Config,
    secrets: Secrets,
    /// The `register` job's own client to Billing -- checking whether an
    /// order's payment has resolved is the whole first half of that job.
    billing: BillingClient,
    /// Identifies which process holds a claim, for `locked_by` -- purely
    /// informational (a human reading the table by hand); the actual
    /// safety comes from `FOR UPDATE SKIP LOCKED`, not from this string
    /// being unique.
    worker_id: String,
}

impl Worker {
    pub fn new(pool: MySqlPool, config: Config, secrets: Secrets) -> Result<Self> {
        let billing = BillingClient::new(&config.billing.grpc_addr)?;
        Ok(Self { pool, config, secrets, billing, worker_id: format!("ais_domains-{}", std::process::id()) })
    }

    /// Runs forever: reap anything abandoned, then repeat [`run_once`]
    /// until it finds nothing left to claim, then sleep. Never returns
    /// except by being dropped (the task this runs in is aborted at
    /// shutdown, per the seam noted in `grpc::serve`).
    pub async fn run(self) {
        loop {
            if let Err(err) = self.reap_expired().await {
                log!(LogLevel::Warn, "job worker: could not reap expired claims: {}", err);
            }

            match self.run_once().await {
                // There may be more queued work; check again immediately
                // rather than sleeping between every row of a backlog.
                Ok(true) => {}
                Ok(false) => tokio::time::sleep(POLL_INTERVAL).await,
                Err(err) => {
                    log!(LogLevel::Error, "job worker: could not claim a job: {}", err);
                    tokio::time::sleep(ERROR_BACKOFF).await;
                }
            }
        }
    }

    /// Claims and runs at most one job, if one is claimable. What each
    /// iteration of [`run`]'s loop does, minus the sleep and the infinite
    /// repetition -- `pub` so an integration test (necessarily against a
    /// real database; `FOR UPDATE SKIP LOCKED` is not something a mock can
    /// stand in for) can drive the worker one step at a time and inspect
    /// `jobs` between steps.
    pub async fn run_once(&self) -> Result<bool> {
        match self.claim_one().await? {
            Some(job) => {
                self.run_job(job).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Claims one job the way [`run_once`] does, without running it.
    /// Exists so the exclusivity guarantee itself -- `FOR UPDATE SKIP
    /// LOCKED` hands a given row to at most one caller -- can be exercised
    /// directly from an integration test, separately from whatever a given
    /// job kind's handler happens to do.
    pub async fn try_claim(&self) -> Result<bool> {
        Ok(self.claim_one().await?.is_some())
    }

    /// Puts any `running` row whose lock has expired back into `queued`,
    /// immediately claimable again (no backoff -- a crash is not a
    /// judgement on whether the job itself is workable, so it doesn't cost
    /// the job an attempt or a delay the way a real failure does). `pub`
    /// for the same reason as [`try_claim`]: exercising this against a
    /// real database from an integration test.
    pub async fn reap_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE jobs SET state = 'queued', locked_by = NULL, locked_until = NULL \
             WHERE state = 'running' AND locked_until < NOW()",
        )
        .execute(&self.pool)
        .await?;

        let reaped = result.rows_affected();
        if reaped > 0 {
            log!(LogLevel::Warn, "job worker: reaped {} abandoned claim(s)", reaped);
        }
        Ok(reaped)
    }

    /// The one place a `queued` row is read and moved to `running`. Claim
    /// and increment happen in the same transaction as the `SELECT ... FOR
    /// UPDATE SKIP LOCKED`, so a second worker racing this one either sees
    /// a different row, or sees none -- never the same row this one just
    /// took.
    async fn claim_one(&self) -> Result<Option<Job>> {
        let mut tx = self.pool.begin().await?;

        // `payload` is cast to text explicitly: without the `json` feature
        // on `sqlx`'s MySQL driver (not enabled -- nothing here parses the
        // column yet, see `Job::payload`'s own doc), decoding a JSON
        // column directly into a plain `String` is not something the
        // driver's type mapping supports, but a cast to `CHAR` is
        // ordinary text as far as the wire protocol is concerned.
        let row = sqlx::query(
            "SELECT id, kind, domain_id, order_id, CAST(payload AS CHAR) AS payload, attempts FROM jobs \
             WHERE state = 'queued' AND next_run_at <= NOW() \
             ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };

        let id: u64 = row.get("id");
        let attempts: i32 = row.get("attempts");

        sqlx::query(
            "UPDATE jobs SET state = 'running', attempts = attempts + 1, locked_by = ?, \
             locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?",
        )
        .bind(&self.worker_id)
        .bind(LOCK_DURATION_SECS)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(Job {
            id,
            kind: row.get("kind"),
            domain_id: row.get("domain_id"),
            order_id: row.get("order_id"),
            payload: row.get("payload"),
            attempts: attempts + 1,
        }))
    }

    /// Dispatches on `job.kind` and moves the row to its next state
    /// depending on the outcome: `done`, back to `queued` on a short poll
    /// delay without costing an attempt ([`JobOutcome::Waiting`]), back to
    /// `queued` with a backoff delay, or `failed` once [`MAX_ATTEMPTS`] is
    /// reached.
    async fn run_job(&self, job: Job) {
        let outcome = match job.kind.as_str() {
            "register" => self.run_register(&job).await,
            other => JobOutcome::Failed(format!("job {}: unknown kind {other:?}", job.id)),
        };

        match outcome {
            JobOutcome::Done => self.finish(&job, "done", None).await,
            JobOutcome::Waiting => self.wait(&job).await,
            JobOutcome::Failed(err) if job.attempts >= MAX_ATTEMPTS => {
                log!(
                    LogLevel::Error,
                    "job {} ({}): failed permanently after {} attempt(s): {}",
                    job.id,
                    job.kind,
                    job.attempts,
                    err
                );
                self.finish(&job, "failed", Some(err)).await;
            }
            JobOutcome::Failed(err) => {
                log!(LogLevel::Warn, "job {} ({}): attempt {} failed, retrying: {}", job.id, job.kind, job.attempts, err);
                self.retry(&job, err).await;
            }
        }
    }

    async fn finish(&self, job: &Job, state: &str, last_error: Option<String>) {
        if let Err(err) = sqlx::query(
            "UPDATE jobs SET state = ?, last_error = ?, locked_by = NULL, locked_until = NULL WHERE id = ?",
        )
        .bind(state)
        .bind(last_error)
        .bind(job.id)
        .execute(&self.pool)
        .await
        {
            log!(LogLevel::Error, "job {}: could not record final state {state:?}: {}", job.id, err);
        }
    }

    async fn retry(&self, job: &Job, last_error: String) {
        let delay_secs = backoff_seconds(job.attempts);
        if let Err(err) = sqlx::query(
            "UPDATE jobs SET state = 'queued', last_error = ?, locked_by = NULL, locked_until = NULL, \
             next_run_at = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?",
        )
        .bind(last_error)
        .bind(delay_secs)
        .bind(job.id)
        .execute(&self.pool)
        .await
        {
            log!(LogLevel::Error, "job {}: could not schedule a retry: {}", job.id, err);
        }
    }

    /// Requeues on a short fixed delay, and -- unlike [`retry`] --
    /// undoes the attempt [`claim_one`] counted for this run: waiting on an
    /// external event to resolve is not a failure, so it must not spend
    /// down [`MAX_ATTEMPTS`] or trigger the exponential backoff meant for
    /// real errors. `GREATEST(attempts - 1, 0)` guards against underflow;
    /// it should never actually clamp, since a job only reaches here after
    /// `claim_one` has already incremented it to at least 1.
    async fn wait(&self, job: &Job) {
        if let Err(err) = sqlx::query(
            "UPDATE jobs SET state = 'queued', attempts = GREATEST(attempts - 1, 0), locked_by = NULL, \
             locked_until = NULL, next_run_at = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?",
        )
        .bind(WAIT_POLL_SECS)
        .bind(job.id)
        .execute(&self.pool)
        .await
        {
            log!(LogLevel::Error, "job {}: could not reschedule a wait: {}", job.id, err);
        }
    }
}

/// Exponential backoff seeded by the attempt number that just failed
/// (1-based), capped at five minutes. Pure, so it's testable without a
/// database -- the actual claim/retry loop above is not: `FOR UPDATE SKIP
/// LOCKED`'s exclusivity is a property of MySQL's own locking, not
/// something a unit test can observe without one.
fn backoff_seconds(attempt: i32) -> i64 {
    // Clamped to 9 rather than the smallest exponent that already exceeds
    // the 300s cap (8, since 1<<8 = 256): clamping at 8 would make the
    // function top out at 256 for every large attempt number and never
    // actually reach the cap it's documented to have.
    let exponent = attempt.clamp(1, 9);
    (1i64 << exponent).min(300)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_seconds(1), 2);
        assert_eq!(backoff_seconds(2), 4);
        assert_eq!(backoff_seconds(3), 8);
        assert_eq!(backoff_seconds(4), 16);
        assert_eq!(backoff_seconds(5), 32);
        // MAX_ATTEMPTS is 5, so nothing in practice ever asks for more than
        // this, but the cap still has to hold for a config that raises it.
        assert_eq!(backoff_seconds(20), 300);
    }

    #[test]
    fn backoff_never_asks_for_zero_or_negative() {
        assert_eq!(backoff_seconds(0), 2);
        assert_eq!(backoff_seconds(-3), 2);
    }
}
