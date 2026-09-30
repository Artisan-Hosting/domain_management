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
        // Each instance's temp tables go in its own directory: the default,
        // /var/tmp, is shared and clobbered by other instances running at once.
        let tmp = dir.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();

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
                .arg(format!("--tmpdir={}", tmp.display()))
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
            .arg(format!("--tmpdir={}", tmp.display()))
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
        // `db::migrate` is a deliberate no-op (migrations are applied by hand
        // in production), so apply the same files the same way here.
        let mut files: Vec<_> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
            .expect("read migrations/")
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "sql"))
            .collect();
        files.sort();
        for file in files {
            let sql = std::fs::read_to_string(&file).unwrap();
            sqlx::raw_sql(&sql).execute(&pool).await.unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }

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
        let mut config = ais_domains::config::Config::default();
        config.billing.grpc_addr = "http://127.0.0.1:1".to_owned();
        Worker::new(self.pool.clone(), config, test_secrets())
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

// ---------------------------------------------------------------------------
// The purchase path: money moves here, so each way it can go wrong is pinned.
//
// A fake Billing (a real tonic server, so the worker's real client runs) and a
// mock Cloudflare (a real HTTP listener, so the real registrar client runs)
// stand in for the two services the worker talks to.
// ---------------------------------------------------------------------------

mod purchase {
    use super::*;
    use ais_domains::proto::billing::billing_service_server::{BillingService, BillingServiceServer};
    use ais_domains::proto::billing::{
        CancelPaymentIntentRequest, CreatePaymentIntentRequest, GetPaymentIntentRequest, PaymentIntent,
        PaymentIntentStatus, RefundPaymentIntentRequest, RefundPaymentIntentResponse, StripeWebhookRequest,
        StripeWebhookResponse, WatchPaymentIntentRequest,
    };
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tonic::{Request, Response, Status};

    // ----- fake Billing -----

    #[derive(Default)]
    struct BillingState {
        status: i32,
        created: Vec<String>,
        cancelled: Vec<String>,
        refunded: Vec<String>,
        fail_refunds: bool,
    }

    #[derive(Clone)]
    struct FakeBilling(Arc<Mutex<BillingState>>);

    fn payment(status: i32, reference: &str) -> PaymentIntent {
        PaymentIntent {
            id: "1".into(),
            stripe_payment_intent_id: format!("pi_{reference}"),
            consumer: "domain_management".into(),
            external_reference: reference.into(),
            amount_cents: 600,
            currency: "usd".into(),
            status,
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl BillingService for FakeBilling {
        async fn create_payment_intent(
            &self,
            request: Request<CreatePaymentIntentRequest>,
        ) -> Result<Response<PaymentIntent>, Status> {
            let req = request.into_inner();
            let mut state = self.0.lock().unwrap();
            state.created.push(req.external_reference.clone());
            Ok(Response::new(payment(state.status, &req.external_reference)))
        }

        async fn get_payment_intent(
            &self,
            request: Request<GetPaymentIntentRequest>,
        ) -> Result<Response<PaymentIntent>, Status> {
            let reference = request.into_inner().id_or_reference;
            Ok(Response::new(payment(self.0.lock().unwrap().status, &reference)))
        }

        type WatchPaymentIntentStream = std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<PaymentIntent, Status>> + Send + 'static>,
        >;

        async fn watch_payment_intent(
            &self,
            _: Request<WatchPaymentIntentRequest>,
        ) -> Result<Response<Self::WatchPaymentIntentStream>, Status> {
            Err(Status::unimplemented("not used by the worker"))
        }

        async fn cancel_payment_intent(
            &self,
            request: Request<CancelPaymentIntentRequest>,
        ) -> Result<Response<PaymentIntent>, Status> {
            let reference = request.into_inner().id_or_reference;
            let mut state = self.0.lock().unwrap();
            state.cancelled.push(reference.clone());
            state.status = PaymentIntentStatus::Canceled as i32;
            Ok(Response::new(payment(state.status, &reference)))
        }

        async fn refund_payment_intent(
            &self,
            request: Request<RefundPaymentIntentRequest>,
        ) -> Result<Response<RefundPaymentIntentResponse>, Status> {
            let reference = request.into_inner().id_or_reference;
            let mut state = self.0.lock().unwrap();
            if state.fail_refunds {
                return Err(Status::unavailable("stripe is down"));
            }
            state.refunded.push(reference);
            Ok(Response::new(RefundPaymentIntentResponse {
                refund_id: "re_test".into(),
                status: "succeeded".into(),
                amount_cents: 600,
            }))
        }

        async fn handle_stripe_webhook(
            &self,
            _: Request<StripeWebhookRequest>,
        ) -> Result<Response<StripeWebhookResponse>, Status> {
            Err(Status::unimplemented("not used by the worker"))
        }
    }

    async fn serve_billing(initial_status: PaymentIntentStatus) -> (String, FakeBilling) {
        let fake = FakeBilling(Arc::new(Mutex::new(BillingState { status: initial_status as i32, ..Default::default() })));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service = BillingServiceServer::new(fake.clone());
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (format!("http://{addr}"), fake)
    }

    // ----- mock Cloudflare -----

    /// One canned answer per route; counts how often each route was hit.
    struct Route {
        suffix: &'static str,
        status: u16,
        body: String,
    }

    #[derive(Clone, Default)]
    struct Hits(Arc<Mutex<Vec<String>>>);

    impl Hits {
        fn count(&self, suffix: &str) -> usize {
            self.0.lock().unwrap().iter().filter(|p| p.ends_with(suffix)).count()
        }
    }

    fn ok(result: &str) -> (u16, String) {
        (200, format!(r#"{{"success":true,"errors":[],"messages":[],"result":{result}}}"#))
    }

    fn rejected(code: u16, message: &str) -> (u16, String) {
        (code, format!(r#"{{"success":false,"errors":[{{"code":1000,"message":"{message}"}}],"messages":[],"result":null}}"#))
    }

    fn check_answer(registrable: bool, price: &str) -> (u16, String) {
        let pricing = if registrable {
            format!(r#","pricing":{{"currency":"USD","registration_cost":"{price}","renewal_cost":"{price}"}}"#)
        } else {
            String::new()
        };
        ok(&format!(r#"{{"domains":[{{"name":"example.test","registrable":{registrable}{pricing}}}]}}"#))
    }

    fn state_answer(state: &str) -> (u16, String) {
        let error = if state == "failed" { r#","error":{"code":"declined","message":"registry declined"}"# } else { "" };
        ok(&format!(r#"{{"completed":{},"state":"{state}"{error}}}"#, state == "succeeded" || state == "failed"))
    }

    async fn serve_cloudflare(routes: Vec<(&'static str, (u16, String))>) -> (String, Hits) {
        let routes: Vec<Route> =
            routes.into_iter().map(|(suffix, (status, body))| Route { suffix, status, body }).collect();
        let hits = Hits::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 16384];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or_default().to_owned();
                seen.0.lock().unwrap().push(path.clone());
                let (status, body) = routes
                    .iter()
                    .find(|r| path.ends_with(r.suffix))
                    .map(|r| (r.status, r.body.clone()))
                    .unwrap_or_else(|| rejected(404, "no such route").clone());
                let response = format!(
                    "HTTP/1.1 {status} status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), hits)
    }

    // ----- harness glue -----

    fn worker_for(db: &TestDb, billing_addr: &str, cloudflare_base: &str) -> Worker {
        let mut config = ais_domains::config::Config::default();
        config.billing.grpc_addr = billing_addr.to_owned();
        config.cloudflare.api_base = cloudflare_base.to_owned();
        let mut secrets = test_secrets();
        secrets.cf_account_id = "acct".into();
        secrets.cf_registrar_token = "t".into();
        secrets.cf_zones_token = "t".into();
        secrets.cf_challenge_token = "t".into();
        secrets.cf_members_token = "t".into();
        Worker::new(db.pool.clone(), config, secrets).expect("plaintext billing needs no certificates")
    }

    impl TestDb {
        /// A paid order that has not started registering (cost 500c, charged 600c).
        async fn paid_order(&self) -> (u64, u64) {
            let order = self.insert_order("paid").await;
            sqlx::query("UPDATE domain_orders SET stripe_payment_intent_id = 'pi_x' WHERE id = ?")
                .bind(order)
                .execute(&self.pool)
                .await
                .unwrap();
            (order, self.insert_register_job(Some(order)).await)
        }

        async fn order(&self, id: u64) -> (String, Option<String>, Option<String>, Option<String>) {
            let row = sqlx::query(
                "SELECT state, cf_workflow_state, stripe_refund_id, last_error FROM domain_orders WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap();
            (row.get("state"), row.get("cf_workflow_state"), row.get("stripe_refund_id"), row.get("last_error"))
        }

        async fn make_job_due(&self, job: u64) {
            sqlx::query("UPDATE jobs SET next_run_at = NOW() - INTERVAL 1 SECOND WHERE id = ?")
                .bind(job)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }

    macro_rules! need_mariadb {
        () => {
            if !have_mariadb() {
                eprintln!("skipping: mariadb-install-db/mariadbd not available");
                return;
            }
        };
    }

    const REGISTRATIONS: &str = "/registrar/registrations";
    const CHECK: &str = "/registrar/domain-check";
    const STATUS: &str = "/registration-status";

    // ----- the tests -----

    #[tokio::test]
    async fn a_price_rise_past_the_limit_refunds_instead_of_buying() {
        need_mariadb!();
        let db = TestDb::start("price-rise").await;
        let (order, job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        // Quoted at 500c cost, default drift 100c: 7.00 is past it.
        let (cf, hits) = serve_cloudflare(vec![(CHECK, check_answer(true, "7.00"))]).await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        let (state, cf_state, refund_id, why) = db.order(order).await;
        assert_eq!(state, "refunded");
        assert_eq!(refund_id.as_deref(), Some("re_test"));
        assert!(why.unwrap().contains("rose from 500c to 700c"));
        assert_eq!(cf_state, None, "the registrar was never asked");
        assert_eq!(hits.count(REGISTRATIONS), 0, "nothing was bought");
        assert_eq!(billing.0.lock().unwrap().refunded, vec![format!("domain_management:{order}")]);
        assert_eq!(db.job_row(job).await.state, "done");
    }

    #[tokio::test]
    async fn a_name_taken_since_the_quote_refunds() {
        need_mariadb!();
        let db = TestDb::start("name-taken").await;
        let (order, _job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        let (cf, hits) = serve_cloudflare(vec![(CHECK, check_answer(false, ""))]).await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        assert_eq!(db.order(order).await.0, "refunded");
        assert_eq!(hits.count(REGISTRATIONS), 0);
        assert_eq!(billing.0.lock().unwrap().refunded.len(), 1);
    }

    #[tokio::test]
    async fn the_registration_is_recorded_before_the_registrar_is_called_and_is_never_repeated() {
        need_mariadb!();
        let db = TestDb::start("record-first").await;
        let (order, job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        // The purchase call blows up with a 500 -- did it buy the name? Unknown.
        let (cf, hits) = serve_cloudflare(vec![
            (CHECK, check_answer(true, "5.00")),
            (REGISTRATIONS, rejected(500, "boom")),
            (STATUS, state_answer("in_progress")),
        ])
        .await;
        let worker = worker_for(&db, &billing_addr, &cf);

        assert!(worker.run_once().await.unwrap());
        let (state, cf_state, refund_id, _) = db.order(order).await;
        assert_eq!((state.as_str(), cf_state.as_deref()), ("registering", Some("requested")));
        assert_eq!(refund_id, None, "an ambiguous failure must not refund: the name may have been bought");
        assert_eq!(hits.count(REGISTRATIONS), 1);

        // The retry polls for the registration; it must not buy again.
        db.make_job_due(job).await;
        assert!(worker.run_once().await.unwrap());
        assert_eq!(hits.count(REGISTRATIONS), 1, "never a second purchase");
        assert_eq!(hits.count(STATUS), 1);
        assert!(billing.0.lock().unwrap().refunded.is_empty());
    }

    #[tokio::test]
    async fn a_definite_rejection_from_the_registrar_refunds() {
        need_mariadb!();
        let db = TestDb::start("rejected").await;
        let (order, _job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        let (cf, _hits) = serve_cloudflare(vec![
            (CHECK, check_answer(true, "5.00")),
            (REGISTRATIONS, rejected(400, "domain unavailable")),
        ])
        .await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        let (state, _, refund_id, why) = db.order(order).await;
        assert_eq!(state, "refunded");
        assert_eq!(refund_id.as_deref(), Some("re_test"));
        assert!(why.unwrap().contains("registrar refused"));
        assert_eq!(billing.0.lock().unwrap().refunded.len(), 1);
    }

    #[tokio::test]
    async fn a_registration_that_fails_at_the_registry_refunds() {
        need_mariadb!();
        let db = TestDb::start("registry-failed").await;
        let (order, _job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        let (cf, _hits) = serve_cloudflare(vec![
            (CHECK, check_answer(true, "5.00")),
            (REGISTRATIONS, (202, state_answer("failed").1)),
        ])
        .await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        let (state, cf_state, _, why) = db.order(order).await;
        assert_eq!((state.as_str(), cf_state.as_deref()), ("refunded", Some("failed")));
        assert_eq!(why.as_deref(), Some("registry declined"));
        assert_eq!(billing.0.lock().unwrap().refunded.len(), 1);
    }

    #[tokio::test]
    async fn action_required_holds_the_money_and_flags_an_admin() {
        need_mariadb!();
        let db = TestDb::start("action-required").await;
        let (order, job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        let (cf, _hits) = serve_cloudflare(vec![
            (CHECK, check_answer(true, "5.00")),
            (REGISTRATIONS, (202, state_answer("action_required").1)),
        ])
        .await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        let (state, _, refund_id, why) = db.order(order).await;
        assert_eq!(state, "needs_admin");
        assert_eq!(refund_id, None);
        assert!(why.unwrap().contains("action_required"));
        assert!(billing.0.lock().unwrap().refunded.is_empty(), "the customer's money is held, not returned");
        assert_eq!(db.job_row(job).await.state, "done");
    }

    #[tokio::test]
    async fn a_refund_that_fails_is_retried_and_finally_hands_the_order_to_an_admin() {
        need_mariadb!();
        let db = TestDb::start("refund-fails").await;
        let (order, job) = db.paid_order().await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::Succeeded).await;
        billing.0.lock().unwrap().fail_refunds = true;
        let (cf, _hits) = serve_cloudflare(vec![(CHECK, check_answer(false, ""))]).await;
        // Already on its last attempt.
        sqlx::query("UPDATE jobs SET attempts = 4 WHERE id = ?").bind(job).execute(&db.pool).await.unwrap();

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        let (state, _, refund_id, why) = db.order(order).await;
        assert_eq!((state.as_str(), refund_id), ("needs_admin", None));
        assert!(why.unwrap().contains("gave up after 5 attempts"));
        assert_eq!(db.job_row(job).await.state, "failed");
    }

    #[tokio::test]
    async fn an_unpaid_order_past_the_window_is_cancelled_and_failed() {
        need_mariadb!();
        let db = TestDb::start("expire").await;
        let order = db.insert_order("awaiting_payment").await;
        sqlx::query("UPDATE domain_orders SET stripe_payment_intent_id = 'pi_x', created_at = NOW() - INTERVAL 2 HOUR WHERE id = ?")
            .bind(order)
            .execute(&db.pool)
            .await
            .unwrap();
        let job = db.insert_register_job(Some(order)).await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::RequiresPaymentMethod).await;

        assert!(worker_for(&db, &billing_addr, "http://127.0.0.1:1").run_once().await.unwrap());

        let (state, _, _, why) = db.order(order).await;
        assert_eq!(state, "failed");
        assert_eq!(why.as_deref(), Some("payment was not completed in time"));
        assert_eq!(billing.0.lock().unwrap().cancelled, vec![format!("domain_management:{order}")]);
        assert_eq!(db.job_row(job).await.state, "done");
    }

    #[tokio::test]
    async fn an_unpaid_order_inside_the_window_just_waits() {
        need_mariadb!();
        let db = TestDb::start("waits").await;
        let order = db.insert_order("awaiting_payment").await;
        sqlx::query("UPDATE domain_orders SET stripe_payment_intent_id = 'pi_x' WHERE id = ?")
            .bind(order)
            .execute(&db.pool)
            .await
            .unwrap();
        let job = db.insert_register_job(Some(order)).await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::RequiresPaymentMethod).await;

        assert!(worker_for(&db, &billing_addr, "http://127.0.0.1:1").run_once().await.unwrap());

        assert_eq!(db.order(order).await.0, "awaiting_payment");
        assert!(billing.0.lock().unwrap().cancelled.is_empty());
        let row = db.job_row(job).await;
        assert_eq!((row.state.as_str(), row.attempts), ("queued", 0), "waiting costs no attempt");
    }

    #[tokio::test]
    async fn a_confirmed_payment_moves_the_order_to_paid() {
        need_mariadb!();
        let db = TestDb::start("paid").await;
        let order = db.insert_order("awaiting_payment").await;
        sqlx::query("UPDATE domain_orders SET stripe_payment_intent_id = 'pi_x' WHERE id = ?")
            .bind(order)
            .execute(&db.pool)
            .await
            .unwrap();
        db.insert_register_job(Some(order)).await;
        let (billing_addr, _billing) = serve_billing(PaymentIntentStatus::Succeeded).await;

        assert!(worker_for(&db, &billing_addr, "http://127.0.0.1:1").run_once().await.unwrap());
        assert_eq!(db.order(order).await.0, "paid");
    }

    #[tokio::test]
    async fn an_order_with_no_payment_recorded_gets_one_created() {
        need_mariadb!();
        let db = TestDb::start("missing-pi").await;
        let order = db.insert_order("awaiting_payment").await;
        db.insert_register_job(Some(order)).await;
        let (billing_addr, billing) = serve_billing(PaymentIntentStatus::RequiresPaymentMethod).await;

        assert!(worker_for(&db, &billing_addr, "http://127.0.0.1:1").run_once().await.unwrap());

        assert_eq!(billing.0.lock().unwrap().created, vec![order.to_string()]);
        let id: Option<String> = sqlx::query_scalar("SELECT stripe_payment_intent_id FROM domain_orders WHERE id = ?")
            .bind(order)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(id, Some(format!("pi_{order}")));
    }

    #[tokio::test]
    async fn a_needs_admin_order_with_no_registration_started_is_payment_checked_not_bought() {
        need_mariadb!();
        let db = TestDb::start("requeued").await;
        let (order, _job) = db.paid_order().await;
        sqlx::query("UPDATE domain_orders SET state = 'needs_admin' WHERE id = ?").bind(order).execute(&db.pool).await.unwrap();
        // Never paid.
        let (billing_addr, _billing) = serve_billing(PaymentIntentStatus::RequiresPaymentMethod).await;
        let (cf, hits) = serve_cloudflare(vec![(CHECK, check_answer(true, "5.00"))]).await;

        assert!(worker_for(&db, &billing_addr, &cf).run_once().await.unwrap());

        assert_eq!(hits.count(REGISTRATIONS), 0, "an admin re-queue must never register an unpaid order");
        assert_eq!(hits.count(CHECK), 0);
        assert_eq!(db.order(order).await.0, "needs_admin");
    }

    // ----- the order tables -----

    async fn insert(db: &TestDb, fqdn: &str, quote: &str) -> Result<u64, ais_domains::error::Error> {
        ais_domains::db::orders::insert_order_with_job(&db.pool, fqdn, "org-1", "user-1", quote, 500, 600, "USD", "", "").await
    }

    #[tokio::test]
    async fn an_order_and_its_job_are_created_together_and_a_repeat_is_refused() {
        need_mariadb!();
        let db = TestDb::start("order-insert").await;
        let id = insert(&db, "a.example", "q-1").await.unwrap();

        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE kind = 'register' AND order_id = ?")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(jobs, 1);

        // Same quote again (a double submit), and the same name on a new quote.
        let again = insert(&db, "a.example", "q-1").await.unwrap_err();
        assert!(ais_domains::db::orders::is_duplicate(&again), "{again}");
        let same_name = insert(&db, "a.example", "q-2").await.unwrap_err();
        assert!(ais_domains::db::orders::is_duplicate(&same_name), "{same_name}");

        // Neither left a stray order or job behind.
        let orders: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domain_orders").fetch_one(&db.pool).await.unwrap();
        let all_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs").fetch_one(&db.pool).await.unwrap();
        assert_eq!((orders, all_jobs), (1, 1));

        // Once the first order fails, the name can be ordered again.
        ais_domains::db::orders::update_state(&db.pool, id, "failed", Some("x")).await.unwrap();
        insert(&db, "a.example", "q-3").await.expect("a failed order releases its name");
    }
}
