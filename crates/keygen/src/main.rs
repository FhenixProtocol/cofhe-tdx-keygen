// Binary-local modules; the reusable cloud clients, keygen and reader live in the
// lib crate (`cofhe_keys`).
#[cfg(not(feature = "mock"))]
mod attestation;
#[cfg(not(feature = "mock"))]
mod gcp_auth;

#[cfg(not(feature = "mock"))]
mod ceremony;
#[cfg(not(feature = "mock"))]
mod config;
#[cfg(not(feature = "mock"))]
mod publish;
#[cfg(not(feature = "mock"))]
mod reshare;
#[cfg(all(test, not(feature = "mock")))]
mod test_support;
#[cfg(not(feature = "mock"))]
mod write;

#[cfg(feature = "mock")]
mod mock;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(not(feature = "mock"))]
use crate::attestation::AttestationClient;
#[cfg(not(feature = "mock"))]
use crate::ceremony::run_ceremony;
#[cfg(not(feature = "mock"))]
use crate::config::{Config, Mode};
#[cfg(not(feature = "mock"))]
use crate::gcp_auth::{GcpAuth, MetadataClient};
#[cfg(not(feature = "mock"))]
use crate::reshare::run_reshare;
#[cfg(not(feature = "mock"))]
use cofhe_keys::{gcs::GcsClient, secrets::SecretManager};

// Service endpoint constants — intentionally NOT read from the environment.
// If an attacker with compute.instances.setMetadata could override these,
// they could redirect the STS exchange to an endpoint they control, capture
// the genuine TDX-attested JWT, and replay it to real STS to impersonate
// the SA. Holding these in code (and excluding them from the launcher's
// allow_env_override LABEL) closes that path.
#[cfg(not(feature = "mock"))]
const ATTESTATION_SOCKET: &str = "/run/container_launcher/teeserver.sock";
#[cfg(not(feature = "mock"))]
const STS_URL: &str = "https://sts.googleapis.com/v1/token";
#[cfg(not(feature = "mock"))]
const SM_URL: &str = "https://secretmanager.googleapis.com";
#[cfg(not(feature = "mock"))]
const GCS_URL: &str = "https://storage.googleapis.com";
#[cfg(not(feature = "mock"))]
const METADATA_URL: &str = "http://metadata.google.internal";
// Audience for the provenance token. Not consumed by STS (only echoed into the
// signed JWT alongside eat_nonce). The token is stamped for wire-format
// compatibility but no consumer reads it — distinct from the partner WIP audience
// used for the write.
#[cfg(not(feature = "mock"))]
const PROVENANCE_AUDIENCE: &str = "cofhe-keygen-provenance";

// The two per-audience partner secret names, same in EVERY partner project (each
// holds that partner's share): TeeCryptor's FHE priv + decrypt signer, and the ZK
// verifier's signer. Network-wide fixed ids — the consumers read the SAME names —
// so they are compile-time constants, not operator-settable.
#[cfg(not(feature = "mock"))]
const WRITE_SECRET_FHE_PRIV: &str = "cofhe-tee-fhe-priv";
#[cfg(not(feature = "mock"))]
const WRITE_SECRET_ZK_SIGNER: &str = "cofhe-tee-zk-signer";

// The keygen's reader name at each source partner: the `keygen-reader` provider.
// It is enabled only for a reshare the partner approves (`grant_reshare_read`), so
// the keygen image can read shares only during that window.
#[cfg(not(feature = "mock"))]
const KEYGEN_READER: &str = "keygen";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .json()
        .init();

    // Process-wide TLS posture: TLS 1.3 + X25519MLKEM768 only. Installing
    // explicitly also prevents the lazy-init panic now that both ring and
    // aws-lc-rs are in the dep tree.
    cofhe_keys::tls::provider()
        .install_default()
        .expect("install pinned rustls crypto provider");

    #[cfg(not(feature = "mock"))]
    real_boot().await?;
    #[cfg(feature = "mock")]
    mock::boot()?;

    info!("keygen complete; exiting");
    Ok(())
}

// Production boot: one-shot, then exit. A ceremony generates a new keyset; a
// reshare splits the live keyset again for a new partner set. Both write every
// partner's shares FIRST and publish the manifest LAST, so the manifest's presence
// is a reliable signal that all shares were delivered. Any failure on the write
// side crashes the run (via `?`) before the manifest changes.
#[cfg(not(feature = "mock"))]
async fn real_boot() -> Result<()> {
    let cfg = Config::from_env()?;
    info!(
        reshare = matches!(cfg.mode, Mode::Reshare(_)),
        partners = cfg.partners.len(),
        shares = cfg.shares,
        threshold = cfg.threshold,
        fhe_priv_secret = %cfg.write_secret_fhe_priv,
        zk_signer_secret = %cfg.write_secret_zk_signer,
        public_bucket = %cfg.env.public_bucket,
        public_prefix = %cfg.env.public_prefix,
        zone = cfg.env.public_zone,
        share_version = %cfg.env.share_version,
        manifest = %cfg.env.manifest_object(),
        "keygen starting"
    );
    let run = Run {
        attest: AttestationClient::new(ATTESTATION_SOCKET),
        auth: GcpAuth::new(STS_URL),
        sm: SecretManager::new(SM_URL),
        gcs: GcsClient::new(GCS_URL),
        metadata: MetadataClient::new(METADATA_URL),
    };
    match cfg.mode {
        Mode::Ceremony => run_ceremony(&cfg, &run).await,
        Mode::Reshare(r) => run_reshare(&cfg, r, &run).await,
    }
}

// The cloud clients one run uses. The GCS bearer is the VM's attached service
// account (in-project, no cross-project hop); partner bearers are per partner.
#[cfg(not(feature = "mock"))]
struct Run {
    attest: AttestationClient,
    auth: GcpAuth,
    sm: SecretManager,
    gcs: GcsClient,
    // A fresh GCS bearer is fetched for each phase: a run can outlast one token.
    metadata: MetadataClient,
}

// Attest for one audience and exchange the token at STS. Each partner gets its
// OWN attestation and federated token; a token is never reused across partners.
#[cfg(not(feature = "mock"))]
async fn federate(run: &Run, audience: &str) -> Result<String> {
    let jwt = run.attest.fetch_token(audience).await?;
    run.auth.exchange(audience, &jwt).await
}
