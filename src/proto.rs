//! The generated `domains` protobuf module.
//!
//! Portal compiles its own vendored copy of `proto/domains.proto` with an
//! older tonic; only the wire format has to agree between the two, the same
//! arrangement it already has with `accounts.proto` and
//! `secret_service.proto`.

pub mod domains {
    tonic::include_proto!("domains");

    /// Fed to tonic-reflection so `grpcurl -plaintext <addr> list` works.
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("domains_descriptor");
}

/// The generated `accounts` module -- ais_auth's `AccountInternal` service,
/// client side only. This service is a consumer of that API, never a
/// provider of it.
pub mod accounts {
    tonic::include_proto!("accounts");
}
