//! One error type for the service, plus the mapping to gRPC statuses.
//!
//! The mapping matters on the far side: Portal turns a `tonic::Status` back
//! into an `ApiResponse` error code (`status_to_error_code` in
//! `portal/src/api/handler/admin.rs`), so choosing the right code here is
//! what makes the dashboard show "not allowed" instead of "something broke".

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),

    #[error("database: {0}")]
    Database(#[from] sqlx::Error),

    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("cloudflare: {0}")]
    Cloudflare(String),

    #[error("billing: {0}")]
    Billing(String),

    #[error("acme: {0}")]
    Acme(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("nginx: {0}")]
    Nginx(String),

    #[error("publish: {0}")]
    Publish(String),

    #[error("{0} not found")]
    NotFound(String),

    #[error("not permitted: {0}")]
    Forbidden(String),

    #[error("invalid request: {0}")]
    Invalid(String),

    #[error("unauthenticated: {0}")]
    Unauthenticated(String),

    /// A service this one depends on (ais_auth) could not be reached. Kept
    /// distinct from `Invalid` so a caller can tell "the policy engine is
    /// down, retry" from "you sent nonsense" -- a denial and an outage must
    /// never look the same.
    #[error("unavailable: {0}")]
    Unavailable(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::Unauthenticated(msg) => tonic::Status::unauthenticated(msg),
            Error::Unavailable(msg) => tonic::Status::unavailable(msg),
            Error::Forbidden(msg) => tonic::Status::permission_denied(msg),
            Error::Invalid(msg) => tonic::Status::invalid_argument(msg),
            Error::NotFound(what) => tonic::Status::not_found(format!("{what} not found")),
            // Everything else is ours to fix, not the caller's. The detail
            // stays in the message because every caller is internal.
            other => tonic::Status::internal(other.to_string()),
        }
    }
}
