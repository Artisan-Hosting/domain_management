//! Database access.
//!
//! This service owns its schema and runs its own migrations at startup
//! (`migrations/`), which is the one place it deliberately breaks with
//! ais_auth -- that service applies schema changes by hand because its tables
//! predate it. Nothing here predates anything.
//!
//! [`connect`] is called once per subsystem, not once total: the CLI
//! (subsystem 1) opens a fresh pool for the lifetime of a single
//! invocation and drops it on exit; the gRPC service (subsystem 2) opens
//! one long-lived pool in `main.rs::serve` and holds it for as long as the
//! process runs; the future job worker (subsystem 3) is handed a *clone*
//! of that same [`sqlx::MySqlPool`] rather than opening its own, because a
//! pool is a cheap handle to a shared set of connections, not a connection
//! itself -- see the seam noted in `grpc::serve`. [`migrate`] is safe to
//! call from any of the three (it's idempotent, tracked by `sqlx`'s own
//! migrations table), which is why both the CLI's `migrate`/`apply`
//! commands and `serve` call it independently rather than assuming
//! whichever one ran last already did.

pub mod dns_records;
pub mod domains;
pub mod freeform;
pub mod inventory;
pub mod orders;
pub mod releases;

use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use std::time::Duration;

use crate::error::{Error, Result};

pub async fn connect(database_url: &str) -> Result<MySqlPool> {
    if database_url.is_empty() {
        return Err(Error::Config(
            "DATABASE_URL is not set (env file or environment)".to_owned(),
        ));
    }

    MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
        .map_err(Error::Database)
}

pub async fn migrate(pool: &MySqlPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await.map_err(Error::Migrate)
}
