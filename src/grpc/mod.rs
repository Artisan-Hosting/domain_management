//! The gRPC server.
//!
//! Binds the private network only (see `config::Grpc::bind`): Portal is the
//! platform's single public entry point and forwards everything here, the
//! same shape ais_auth and ais_secretserver already have.

pub mod authz;
pub mod service;

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use artisan_middleware::mtls::{MtlsConfig, load_mtls_material};
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tonic::transport::Server;

use crate::config::{Config, Secrets};
use crate::error::{Error, Result};
use crate::proto::domains::FILE_DESCRIPTOR_SET;
use crate::proto::domains::domain_service_server::DomainServiceServer;

pub async fn serve(config: Config, secrets: Secrets, pool: MySqlPool) -> Result<()> {
    let addr: SocketAddr = config
        .grpc
        .bind
        .parse()
        .map_err(|e| Error::Config(format!("grpc.bind {:?}: {e}", config.grpc.bind)))?;

    // Load mTLS material from environment variables with defaults
    let mtls_cert_path = std::env::var("MTLS_CERT_PATH").unwrap_or_else(|_| "/etc/artisan/tls/ais_domain.crt".into());
    let mtls_key_path = std::env::var("MTLS_KEY_PATH").unwrap_or_else(|_| "/etc/artisan/tls/ais_domain.key".into());
    let mtls_ca_path = std::env::var("MTLS_CA_PATH").unwrap_or_else(|_| "/etc/artisan/tls/ca.crt".into());

    let mtls_config = MtlsConfig {
        cert_path: std::path::PathBuf::from(mtls_cert_path),
        key_path: std::path::PathBuf::from(mtls_key_path),
        ca_cert_path: std::path::PathBuf::from(mtls_ca_path),
    };

    let mtls_material = load_mtls_material(&mtls_config)
        .map_err(|e| Error::Config(format!("failed to load mTLS material: {e}")))?;

    let identity = tonic::transport::Identity::from_pem(&mtls_material.cert_pem, &mtls_material.key_pem);
    let ca_cert = tonic::transport::Certificate::from_pem(&mtls_material.ca_pem);
    let tls_config = tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    let reflection_enabled = config.grpc.reflection;
    let service = service::Domains::new(config, secrets, pool)?;

    let mut builder = Server::builder()
        .tls_config(tls_config)
        .map_err(|e| Error::Config(format!("failed to configure TLS: {e}")))?;

    let mut router = builder.add_service(DomainServiceServer::new(service));

    if reflection_enabled {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .map_err(|e| Error::Config(format!("reflection: {e}")))?;
        router = router.add_service(reflection);
    }

    log!(LogLevel::Info, "gRPC listening on {}", addr);

    router
        .serve_with_shutdown(addr, shutdown_signal())
        .await
        .map_err(|e| Error::Config(format!("gRPC server: {e}")))
}

/// SIGINT or SIGTERM. systemd sends SIGTERM, so ignoring it means every
/// restart is a kill.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => log!(LogLevel::Error, "cannot listen for SIGTERM: {}", err),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => log!(LogLevel::Info, "SIGINT received, shutting down"),
        _ = terminate => log!(LogLevel::Info, "SIGTERM received, shutting down"),
    }
}
