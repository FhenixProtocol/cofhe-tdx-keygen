//! `cofhe-keys` — the shared, portable key-distribution core.
//!
//! The keygen binary uses the *write* side; consumers embed the *read* side
//! (`reader`). This crate is the single source of truth for the on-the-wire
//! format (`serialization`) so the writer and any reader hash byte-identical
//! material and cannot drift.

// Unconditional: the baked env SOURCE is shared by BOTH the writer (enclave image,
// built with `writer` only) and the reader. `reader` re-exports it so consumer
// `cofhe_keys::reader::{lookup, env_names, EnvConfig, EnvPartner}` paths are unchanged.
pub mod envs;
pub mod gcp_auth;
pub mod gcs;
#[cfg(feature = "writer")]
pub mod keygen;
#[cfg(feature = "reader")]
pub mod reader;
pub mod secrets;
pub mod serialization;
pub mod shamir;
pub mod tls;
