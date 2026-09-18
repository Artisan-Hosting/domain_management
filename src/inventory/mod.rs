//! Seeing what already exists.
//!
//! The live setup predates this service: domains in a flat text file, vhosts
//! written by hand, certificate directories nobody tracked, organization
//! assignments made directly in the database. Nothing here changes any of
//! that on its own -- it reads, cross-references, and reports, and every
//! change is something a person ticked in a plan file first.

pub mod apply;
pub mod attic;
pub mod certs;
pub mod domains_txt;
pub mod model;
pub mod nginx;
pub mod plan;
pub mod scan;
