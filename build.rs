use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/domains.proto");

    // The descriptor set feeds tonic-reflection, so `grpcurl -plaintext
    // <addr> list` works against a running service the same way it does for
    // ais_auth and ais_secretserver.
    let descriptor_path = PathBuf::from(env::var("OUT_DIR")?).join("domains_descriptor.bin");

    tonic_prost_build::configure()
        .build_server(true)
        // The client is built too: the `ais_domains` CLI subcommands and the
        // integration tests talk to the running service through it. Portal
        // keeps its own vendored copy of the proto (see Portal's build.rs),
        // compiled by its own older tonic -- only the wire format has to
        // agree between the two.
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/domains.proto"], &["proto"])?;

    // === accounts.proto, vendored from ais_auth ===
    //
    // Organizations and runners are read from ais_auth and nowhere else --
    // this service never touches that schema directly. The copy here is what
    // actually compiles; it does NOT auto-sync, so run `make sync-proto`
    // after editing ais_auth's copy. Same arrangement Portal has (see
    // portal/build.rs), and for the same reason: reaching into a sibling
    // checkout at build time only works when both happen to be side by side.
    println!("cargo:rerun-if-changed=proto/accounts.proto");

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/accounts.proto"], &["proto"])?;

    // === billing.proto, vendored from the Billing crate ===
    //
    // Stripe integration lives in `Billing` and nowhere else -- this service
    // never holds a Stripe key. Same vendoring arrangement as
    // accounts.proto: does NOT auto-sync, run `make sync-proto` after
    // editing Billing's copy.
    println!("cargo:rerun-if-changed=proto/billing.proto");

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/billing.proto"], &["proto"])?;

    Ok(())
}
