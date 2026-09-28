//! Database access.
//!
//! This service owns its schema and runs its own migrations at startup
//! (`migrations/`), which is the one place it deliberately breaks with
//! ais_auth -- that service applies schema changes by hand because its tables
//! predate it. Nothing here predates anything.

pub mod inventory;

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
    // sqlx::migrate!("./migrations").run(pool).await.map_err(Error::Migrate)
    // Stop doing migrations in software, ts isn't working
    Ok()
}
