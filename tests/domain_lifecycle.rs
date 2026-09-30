//! `db::domains` against a real MariaDB instance -- the read/write surface
//! behind Phase 7's `AddDomain`/`GetDomain`/`ListDomains`/`RemoveDomain`/
//! `WatchDomain`/`ForceRenew`.
//!
//! These test the database module directly rather than the gRPC handlers:
//! every handler's first step is `self.caller(...)`, which calls out to
//! `ais_auth` -- there is no mock for that in this crate's test suite (see
//! `grpc::service`'s own stub-era tests for why empty-token rejection is as
//! far as a handler-level test can go without one). What actually needs
//! proving here -- that a BYO domain round-trips, that a soft delete really
//! disappears from listings, that the certificate cooldown reads back
//! correctly -- lives entirely in `db::domains`, so that's what this
//! exercises. Same throwaway-MariaDB setup as `tests/worker.rs`, for the
//! same reason: nothing here is safe to fake with a mock.

use ais_domains::db;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::MySqlPool;
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
            "ais_domains_lifecycle_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let data = dir.join("data");
        std::fs::create_dir_all(&data).unwrap();

        // Same install-step race `tests/worker.rs` guards against: two
        // instances starting at once collide on `mariadb-install-db`'s
        // unprefixed bootstrap temp tables under `/var/tmp`.
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

        let admin_pool = wait_for_connection(base_options.clone()).await;
        sqlx::query("CREATE DATABASE lifecycle_test").execute(&admin_pool).await.expect("create test database");
        admin_pool.close().await;

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect_with(base_options.database("lifecycle_test"))
            .await
            .expect("connect to the test database");
        db::migrate(&pool).await.expect("run migrations");

        Self { dir: dir.clone(), server, pool }
    }
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

const ORG_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const ORG_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

#[tokio::test]
async fn a_byo_domain_round_trips_unverified() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("byo_round_trip").await;

    let id = db::domains::insert_byo(&db.pool, "example.com", ORG_A, "", "proof-token", "target.acme.example.net")
        .await
        .unwrap();

    let row = db::domains::find_full(&db.pool, id).await.unwrap().unwrap();
    assert_eq!(row.fqdn, "example.com");
    assert_eq!(row.organization_id.as_deref(), Some(ORG_A));
    assert_eq!(row.source, "byo");
    assert_eq!(row.status, "pending_dns");
    assert_eq!(row.ownership_token.as_deref(), Some("proof-token"));
    assert!(!row.ownership_verified, "ownership is not proven just by being added");
    assert!(!row.has_vhost);

    db::domains::mark_ownership_verified(&db.pool, id).await.unwrap();
    let verified = db::domains::find_full(&db.pool, id).await.unwrap().unwrap();
    assert!(verified.ownership_verified);
}

#[tokio::test]
async fn listing_is_scoped_by_organization_and_excludes_removed_domains() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("list_scoped").await;

    let a = db::domains::insert_byo(&db.pool, "a.example.com", ORG_A, "", "tok-a", "target-a").await.unwrap();
    let _b = db::domains::insert_byo(&db.pool, "b.example.com", ORG_B, "", "tok-b", "target-b").await.unwrap();

    let org_a_only = db::domains::list(&db.pool, Some(ORG_A), None, None, 100, 0).await.unwrap();
    assert_eq!(org_a_only.len(), 1);
    assert_eq!(org_a_only[0].fqdn, "a.example.com");

    let everything = db::domains::list(&db.pool, None, None, None, 100, 0).await.unwrap();
    assert_eq!(everything.len(), 2, "an unscoped listing (Super) sees every organization");

    // A soft delete disappears from every listing, scoped or not, without
    // losing the row -- `RemoveDomain`'s whole point.
    db::domains::soft_delete(&db.pool, a).await.unwrap();
    let after_removal = db::domains::list(&db.pool, Some(ORG_A), None, None, 100, 0).await.unwrap();
    assert!(after_removal.is_empty(), "a removed domain must not appear in a listing");
    assert!(db::domains::find_full(&db.pool, a).await.unwrap().is_some(), "but the row itself survives");
}

#[tokio::test]
async fn status_filtering_matches_only_the_requested_state() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("list_status").await;

    let pending = db::domains::insert_byo(&db.pool, "pending.example.com", ORG_A, "", "t1", "target1").await.unwrap();
    let active = db::domains::insert_byo(&db.pool, "active.example.com", ORG_A, "", "t2", "target2").await.unwrap();
    db::domains::set_status(&db.pool, active, "active", None).await.unwrap();

    let pending_only = db::domains::list(&db.pool, Some(ORG_A), None, Some("pending_dns"), 100, 0).await.unwrap();
    assert_eq!(pending_only.len(), 1);
    assert_eq!(pending_only[0].id, pending);

    let active_only = db::domains::list(&db.pool, Some(ORG_A), None, Some("active"), 100, 0).await.unwrap();
    assert_eq!(active_only.len(), 1);
    assert_eq!(active_only[0].id, active);
}

#[tokio::test]
async fn poll_statuses_reflects_a_direct_status_change() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("poll_statuses").await;

    let id = db::domains::insert_byo(&db.pool, "watched.example.com", ORG_A, "", "t", "target").await.unwrap();

    let before = db::domains::poll_statuses(&db.pool, Some(id), None).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].status, "pending_dns");

    db::domains::set_status(&db.pool, id, "active", None).await.unwrap();

    let after = db::domains::poll_statuses(&db.pool, Some(id), None).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].status, "active");

    // A removed domain drops out of polling too, same as a listing --
    // `WatchDomain` must not keep reporting on something that no longer
    // exists as far as any other read surface is concerned.
    db::domains::soft_delete(&db.pool, id).await.unwrap();
    let removed = db::domains::poll_statuses(&db.pool, Some(id), None).await.unwrap();
    assert!(removed.is_empty());
}

#[tokio::test]
async fn certificate_cooldown_is_none_until_one_is_recorded() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("cooldown").await;

    let id = db::domains::insert_byo(&db.pool, "cert.example.com", ORG_A, "", "t", "target").await.unwrap();

    assert!(
        db::domains::seconds_since_last_issuance(&db.pool, id).await.unwrap().is_none(),
        "no certificate has ever been issued yet"
    );

    let not_after = chrono::Utc::now().timestamp() + 90 * 86_400;
    db::domains::record_certificate(&db.pool, id, "ecc", not_after, not_after - 30 * 86_400).await.unwrap();

    let age = db::domains::seconds_since_last_issuance(&db.pool, id).await.unwrap();
    assert!(age.is_some_and(|age| (0..5).contains(&age)), "just issued, so the age should be a few seconds at most");

    let certs = db::domains::certificates_for(&db.pool, id).await.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].key_type, "ecc");
    assert_eq!(certs[0].not_after, Some(not_after));

    // Re-recording the same key type updates in place rather than adding a
    // second row -- `certificates_domain_key`'s unique key is what
    // `ON DUPLICATE KEY UPDATE` relies on here.
    db::domains::record_certificate(&db.pool, id, "ecc", not_after + 1, not_after - 30 * 86_400 + 1).await.unwrap();
    let certs_again = db::domains::certificates_for(&db.pool, id).await.unwrap();
    assert_eq!(certs_again.len(), 1, "the same key type updates in place");
}

#[tokio::test]
async fn a_byo_domain_missing_its_ownership_token_is_a_data_bug_verify_domain_now_can_detect() {
    // `AddDomain` always sets a token, so this is a defensive check on data
    // that should never occur in practice -- but the handler has to do
    // something sane if it ever does, and this proves the row shape it
    // reads back supports telling the difference (`None` vs a real token)
    // without needing to touch the network to find out.
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("missing_token").await;

    let id = db::domains::insert_byo(&db.pool, "broken.example.com", ORG_A, "", "t", "target").await.unwrap();
    sqlx::query("UPDATE domains SET ownership_token = NULL WHERE id = ?")
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();

    let row = db::domains::find_full(&db.pool, id).await.unwrap().unwrap();
    assert_eq!(row.source, "byo");
    assert!(!row.ownership_verified);
    assert!(row.ownership_token.is_none(), "the handler's `let Some(token) = ... else` branch is what this proves");
}

#[tokio::test]
async fn a_purchased_domain_never_needs_ownership_proof() {
    if !have_mariadb() {
        eprintln!("skipping: mariadb-install-db/mariadbd not available");
        return;
    }
    let db = TestDb::start("purchased").await;

    let id = db::domains::insert_purchased(&db.pool, "bought.example.com", ORG_A, "cf-zone-1", "target").await.unwrap();
    let row = db::domains::find_full(&db.pool, id).await.unwrap().unwrap();

    assert_eq!(row.source, "purchased");
    assert!(row.ownership_token.is_none());
    assert!(!row.ownership_verified, "irrelevant for a purchased domain, but not spuriously true either");
}
