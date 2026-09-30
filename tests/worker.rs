//! The job worker against a real MariaDB instance.
//!
//! `FOR UPDATE SKIP LOCKED`'s exclusivity is a property of the database,
//! not of this crate's code, so -- unlike everything else in this repo's
//! test suite -- there is no mock or in-memory stand-in that could prove
//! it. This spins up a throwaway `mariadbd` per test (its own datadir, a
//! Unix socket, `--skip-networking` so it never touches a real port,
//! killed and removed on drop) rather than assuming a shared test
//! database is configured anywhere. `have_mariadb` skips rather than
//! fails when the tooling isn't on `PATH`, the same philosophy
//! `tests/manifest_compat.rs`'s `have_python` uses for the same reason.
//!
//! There is deliberately no test here for a job reaching `done`: no job
//! kind exists yet whose handler can succeed (`"register"` is recognized
//! but not implemented until the registrar client lands). The
//! failure/retry/permanent-failure path is exercised through that same
//! `"register"` kind, which fails deterministically -- that's enough to
//! prove the state machine around it without needing real business logic
//! behind it. The `done` transition gets its first coverage once a real
//! job kind exists to earn it.

use ais_domains::worker::Worker;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{MySqlPool, Row};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn have_mariadb() -> bool {
    Command::new("mariadb-install-db").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
        && Command::new("mariadbd").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

struct TestDb {
    dir: PathBuf,
    server: Child,
    pool: MySqlPool,
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TestDb {
    async fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ais_domains_worker_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let data = dir.join("data");
        std::fs::create_dir_all(&data).unwrap();

        // `mariadb-install-db` names its own bootstrap temp tables under
        // `/var/tmp` without a per-invocation prefix, so two instances
        // running at once (the default when `cargo test` runs every test
        // in this file in parallel) collide on each other's temp files.
        // The install step is the only part that isn't already isolated
        // per test (each gets its own datadir/socket/server), so it's the
        // only part that needs serializing.
        static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let install = {
            let _guard = INSTALL_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            Command::new("mariadb-install-db")
                .arg(format!("--datadir={}", data.display()))
                .arg("--auth-root-authentication-method=normal")
                .arg("--skip-test-db")
                .output()
                .expect("run mariadb-install-db")
        };
        assert!(
            install.status.success(),
            "mariadb-install-db failed: {}",
            String::from_utf8_lossy(&install.stderr)
        );

        let socket = dir.join("mysql.sock");
        let server = Command::new("mariadbd")
            .arg(format!("--datadir={}", data.display()))
            .arg(format!("--socket={}", socket.display()))
            .arg("--skip-networking")
            .arg("--skip-grant-tables")
            .arg(format!("--pid-file={}", dir.join("mysqld.pid").display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start mariadbd");

        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(socket.exists(), "mariadbd never created its socket in time");

        let base_options = MySqlConnectOptions::new().socket(&socket).username("root");

        // The socket file can exist slightly before the server actually
        // accepts connections on it.
        let admin_pool = wait_for_connection(base_options.clone()).await;
        sqlx::query("CREATE DATABASE worker_test").execute(&admin_pool).await.expect("create test database");
        admin_pool.close().await;

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect_with(base_options.database("worker_test"))
            .await
            .expect("connect to the test database");
        ais_domains::db::migrate(&pool).await.expect("run migrations");

        Self { dir: dir.clone(), server, pool }
    }

    /// Inserts a bare job row, mirroring what a gRPC handler's enqueue
    /// would write. `kind = "register"` unless testing dispatch on an
    /// unrecognized one -- it's the only kind this crate knows about
    /// today, and it fails deterministically, which is exactly what the
    /// retry/backoff/permanent-failure tests need.
    async fn insert_job(&self, kind: &str) -> u64 {
        let result = sqlx::query("INSERT INTO jobs (kind, state, attempts) VALUES (?, 'queued', 0)")
            .bind(kind)
            .execute(&self.pool)
            .await
            .unwrap();
        result.last_insert_id()
    }

    /// Inserts a `register` job pointed at `order_id` (or none, to test the
    /// "no order_id at all" path).
    async fn insert_register_job(&self, order_id: Option<u64>) -> u64 {
        let result = sqlx::query("INSERT INTO jobs (kind, order_id, state, attempts) VALUES ('register', ?, 'queued', 0)")
            .bind(order_id)
            .execute(&self.pool)
            .await
            .unwrap();
        result.last_insert_id()
    }

    /// A minimal, otherwise-valid `domain_orders` row in the given state --
    /// enough for `run_register`'s own state-dispatch to be exercised
    /// without a real Cloudflare/Billing/ACME round trip.
    async fn insert_order(&self, state: &str) -> u64 {
        let result = sqlx::query(
            "INSERT INTO domain_orders \
             (fqdn, organization_id, user_id, cost_cents, price_cents, currency, state) \
             VALUES ('example.test', 'org-1', 'user-1', 500, 600, 'usd', ?)",
        )
        .bind(state)
        .execute(&self.pool)
        .await
        .unwrap();
        result.last_insert_id()
    }

    async fn job_row(&self, id: u64) -> JobRow {
        let row = sqlx::query(
            "SELECT state, attempts, locked_by, last_error, next_run_at > NOW() AS retry_is_in_the_future \
             FROM jobs WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap();

        JobRow {
            state: row.get("state"),
            attempts: row.get("attempts"),
            locked_by: row.get("locked_by"),
            last_error: row.get("last_error"),
            retry_is_in_the_future: row.get("retry_is_in_the_future"),
        }
    }

    fn worker(&self) -> Worker {
        Worker::new(self.pool.clone(), ais_domains::config::Config::default(), test_secrets())
            .expect("a plaintext billing.grpc_addr never touches the network to construct")
    }
}

struct JobRow {
    state: String,
    attempts: i32,
    locked_by: Option<String>,
    last_error: Option<String>,
    retry_is_in_the_future: bool,
}

fn test_secrets() -> ais_domains::config::Secrets {
    ais_domains::config::Secrets::load(Some(std::path::Path::new("/nonexistent/ais_domains.env")))
        .expect("a missing env file is not fatal")
}

async fn wait_for_connection(options: MySqlConnectOptions) -> MySqlPool {
    for _ in 0..50 {
        if let Ok(pool) = MySqlPoolOptions::new().max_connections(1).connect_with(options.clone()).await {
            return pool;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("mariadbd never accepted a connection");
}

#[tokio::test]
async fn two_workers_racing_one_job_only_one_claims_it() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("race").await;
    db.insert_job("register").await;

    let (a, b) = (db.worker(), db.worker());
    let (claimed_a, claimed_b) = tokio::join!(a.try_claim(), b.try_claim());

    let claims = [claimed_a.unwrap(), claimed_b.unwrap()];
    assert_eq!(
        claims.iter().filter(|c| **c).count(),
        1,
        "exactly one of the two racing claims must succeed, got {claims:?}"
    );
}

#[tokio::test]
async fn claiming_marks_the_row_running_and_increments_attempts() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("claim").await;
    let id = db.insert_job("register").await;

    assert!(db.worker().try_claim().await.unwrap());

    let row = db.job_row(id).await;
    assert_eq!(row.state, "running");
    assert_eq!(row.attempts, 1);
    assert!(row.locked_by.is_some());
}

#[tokio::test]
async fn a_failing_job_is_requeued_with_a_future_retry_time_and_its_error_recorded() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("retry").await;
    let id = db.insert_job("register").await;

    assert!(db.worker().run_once().await.unwrap(), "one job was queued and claimable");

    let row = db.job_row(id).await;
    assert_eq!(row.state, "queued", "a recoverable failure goes back to queued, not failed");
    assert_eq!(row.attempts, 1);
    assert!(row.locked_by.is_none(), "a requeued job releases its claim");
    assert!(row.retry_is_in_the_future, "a retry is backed off, not immediate");
    assert!(row.last_error.unwrap().contains("register"), "the failure reason is recorded");
}

#[tokio::test]
async fn a_job_that_keeps_failing_becomes_permanently_failed() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("permfail").await;
    let id = db.insert_job("register").await;
    let worker = db.worker();

    // `MAX_ATTEMPTS` is 5; force the retry clock so each attempt is
    // immediately claimable instead of waiting out its own backoff.
    for _ in 0..5 {
        sqlx::query("UPDATE jobs SET next_run_at = NOW() WHERE id = ?").bind(id).execute(&db.pool).await.unwrap();
        assert!(worker.run_once().await.unwrap());
    }

    let row = db.job_row(id).await;
    assert_eq!(row.state, "failed");
    assert_eq!(row.attempts, 5);
    assert!(row.locked_by.is_none());
}

#[tokio::test]
async fn an_unrecognized_job_kind_fails_the_job_without_crashing_the_worker() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("unknown-kind").await;
    let id = db.insert_job("some-kind-nobody-wrote-yet").await;

    assert!(db.worker().run_once().await.unwrap());

    let row = db.job_row(id).await;
    assert_eq!(row.state, "queued", "an unrecognized kind is a retryable error, not a panic");
    assert!(row.last_error.unwrap().contains("unknown kind"));
}

#[tokio::test]
async fn an_abandoned_claim_is_reaped_back_to_queued() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("reap").await;
    let result = sqlx::query(
        "INSERT INTO jobs (kind, state, attempts, locked_by, locked_until) \
         VALUES ('register', 'running', 1, 'a-worker-that-crashed', DATE_SUB(NOW(), INTERVAL 1 MINUTE))",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let id = result.last_insert_id();

    let reaped = db.worker().reap_expired().await.unwrap();
    assert_eq!(reaped, 1);

    let row = db.job_row(id).await;
    assert_eq!(row.state, "queued");
    assert!(row.locked_by.is_none());
}

#[tokio::test]
async fn a_live_claim_is_never_reaped() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("no-reap").await;
    let id = db.insert_job("register").await;
    assert!(db.worker().try_claim().await.unwrap());

    let reaped = db.worker().reap_expired().await.unwrap();
    assert_eq!(reaped, 0, "a claim whose lock has not expired must survive a reap sweep");

    let row = db.job_row(id).await;
    assert_eq!(row.state, "running");
}

#[tokio::test]
async fn a_register_job_with_no_order_id_fails_without_touching_the_network() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("register-no-order").await;
    let id = db.insert_register_job(None).await;

    assert!(db.worker().run_once().await.unwrap());

    let row = db.job_row(id).await;
    assert_eq!(row.state, "queued", "a recoverable error, not a permanent failure on the first attempt");
    let last_error = row.last_error.unwrap();
    assert!(last_error.contains("no order_id"), "{last_error}");
}

#[tokio::test]
async fn a_register_job_for_a_missing_order_fails_cleanly() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("register-missing-order").await;
    let id = db.insert_register_job(Some(999_999)).await;

    assert!(db.worker().run_once().await.unwrap());

    let row = db.job_row(id).await;
    let last_error = row.last_error.unwrap();
    assert!(last_error.contains("not found"), "{last_error}");
}

#[tokio::test]
async fn a_register_job_for_an_already_completed_order_finishes_immediately() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("register-completed").await;
    let order_id = db.insert_order("completed").await;
    let job_id = db.insert_register_job(Some(order_id)).await;

    assert!(db.worker().run_once().await.unwrap());

    let row = db.job_row(job_id).await;
    assert_eq!(row.state, "done", "a terminal order needs no further work from this job");
}

#[tokio::test]
async fn awaiting_payment_with_no_payment_intent_recorded_is_a_real_failure_not_a_wait() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("register-no-payment-intent").await;
    // No stripe_payment_intent_id -- `await_payment` must refuse to guess
    // at one rather than calling Billing with nothing to ask about. This is
    // a data problem (CreateOrder should always set one), not "not paid
    // yet," so it counts as a real attempt like any other failure.
    let order_id = db.insert_order("awaiting_payment").await;
    let job_id = db.insert_register_job(Some(order_id)).await;

    assert!(db.worker().run_once().await.unwrap());

    let row = db.job_row(job_id).await;
    assert_eq!(row.state, "queued", "a recoverable error, not a permanent failure on the first attempt");
    assert_eq!(row.attempts, 1, "a real failure counts as an attempt, unlike JobOutcome::Waiting");
    assert!(row.retry_is_in_the_future, "a real failure backs off, it does not poll immediately");
    assert!(row.last_error.unwrap().contains("no payment intent"));
}
