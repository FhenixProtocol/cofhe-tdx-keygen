// Writer-only modules (binary-local); the reusable cloud clients + keygen live
// in the lib crate (`cofhe_keys`) so the consumer reader can share them.
#[cfg(not(feature = "mock"))]
mod attestation;
#[cfg(not(feature = "mock"))]
mod gcp_auth;

#[cfg(not(feature = "mock"))]
mod config;
#[cfg(not(feature = "mock"))]
mod publish;
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
use crate::config::{Config, Mode};
#[cfg(not(feature = "mock"))]
use crate::gcp_auth::{GcpAuth, MetadataClient};
#[cfg(not(feature = "mock"))]
use crate::publish::{object_path, OBJ_CRS, OBJ_MANIFEST, OBJ_PUBLIC_KEY, OBJ_SERVER_KEY};
#[cfg(not(feature = "mock"))]
use crate::write::write_secret;
#[cfg(not(feature = "mock"))]
use anyhow::bail;
#[cfg(not(feature = "mock"))]
use cofhe_keys::{gcs::GcsClient, keygen, secrets::SecretManager};

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

// Production boot: generate + Shamir-split the keyset in-enclave -> for EACH
// partner (attestation -> STS -> write its two share envelopes to its Secret
// Manager) -> only then publish the public material + its provenance to our GCS
// bucket -> exit. Secrets first across the WHOLE N×2 write set so the public
// material is published only once every partner's (critical, cross-project,
// attestation-gated) share delivery has succeeded. Each partner uses its OWN
// attestation/federated token (no cross-partner token reuse). This is a one-shot
// ceremony, not a long-running server. Direct federated grant: each attested federated
// principal holds secretVersionAdder directly on its secrets, so the STS federated
// token is used as the SM bearer as-is (no service-account impersonation).
#[cfg(not(feature = "mock"))]
async fn real_boot() -> Result<()> {
    let cfg = Config::from_env()?;
    if let Mode::Reshare(r) = cfg.mode {
        info!(share_version = %cfg.env.share_version, source_manifest = %r.manifest_object(cfg.env), "reshare target");
        for s in r.partners {
            info!(partner = %s.partner.project_id, share_version = %r.version_for(s.partner.project_id), "reshare source");
        }
        bail!(
            "reshare image: this build validates a reshare config ({} sources, T={}, live signers {} and {}) but cannot run one",
            r.partners.len(),
            r.shamir_threshold,
            r.decrypt_signer_address,
            r.zk_signer_address
        );
    }
    info!(
        partners = cfg.partners.len(),
        shares = cfg.shares,
        threshold = cfg.threshold,
        fhe_priv_secret = %cfg.write_secret_fhe_priv,
        zk_signer_secret = %cfg.write_secret_zk_signer,
        public_bucket = %cfg.public_bucket,
        public_prefix = %cfg.public_prefix,
        zone = cfg.zone,
        "keygen ceremony starting"
    );

    // Generate the full network keyset in-enclave (never leaves TDX memory
    // unencrypted): FHE keys + decrypt_signer (TN) + zk_signer (ZK/verifier),
    // Shamir-split N-of-T across the partners — one share pair per partner, index
    // i → partners[i].
    info!("step 1: generating + splitting network keyset in-enclave");
    let partner_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let (partner_shares, artifacts, public) =
        keygen::generate(&partner_ids, cfg.shares, cfg.threshold)?;

    // Deliver the SECRET shares to EVERY partner FIRST — the cross-project,
    // attestation-gated writes are the critical part. Each partner gets its own
    // share of each per-audience secret, written to its OWN Secret Manager secret
    // with its own provenance token (eat_nonce = SHA-256(share)), so the partner can
    // grant each consumer least-privilege read via IAM: TeeCryptor reads fhe-priv
    // (FHE priv + decrypt signer); the ZK verifier reads zk-signer. See
    // CONSUMER-INTEGRATION.md.
    //
    // Per-partner attestation/token ISOLATION: each partner gets its OWN attestation
    // (its wip_audience) → its OWN federated STS token, used as the SM bearer for
    // ONLY that partner's two writes. A co-resident partner's token is never reused
    // for another partner's project.
    //
    // Secrets-first invariant across the WHOLE N×2 write set: the public material is
    // published only AFTER every partner's writes succeed (below). Any attestation /
    // STS / SM failure crashes the run (via `?`) before anything is published, so the
    // public material's presence is a reliable signal that all shares were delivered.
    let attest = AttestationClient::new(ATTESTATION_SOCKET);
    let auth = GcpAuth::new(STS_URL);
    let sm = SecretManager::new(SM_URL);
    let total = cfg.partners.len();
    for (i, (partner, shares)) in cfg.partners.iter().zip(&partner_shares).enumerate() {
        let n = i + 1;
        info!(partner = %partner.project_id, step = %format!("{n}/{total}"), "fetching attestation token for partner");
        let jwt = attest.fetch_token(&partner.wip_audience).await?;

        info!(partner = %partner.project_id, "exchanging attestation for partner federated token");
        let federated = auth.exchange(&partner.wip_audience, &jwt).await?;

        info!(partner = %partner.project_id, secret = %cfg.write_secret_fhe_priv, "writing FHE-priv share (priv + decrypt signer)");
        write_secret(
            &attest,
            &sm,
            &federated,
            &partner.project_id,
            &cfg.write_secret_fhe_priv,
            shares.fhe_priv_share.clone(),
        )
        .await?;

        info!(partner = %partner.project_id, secret = %cfg.write_secret_zk_signer, "writing ZK-signer share");
        write_secret(
            &attest,
            &sm,
            &federated,
            &partner.project_id,
            &cfg.write_secret_zk_signer,
            shares.zk_signer_share.clone(),
        )
        .await?;
    }

    // All partner shares delivered — now publish the PUBLIC material to OUR bucket
    // via the VM's compute SA (metadata token). The three FHE artifacts go to
    // SEPARATE objects, named + laid out exactly as cofhe mounts them
    // (keys/versionized/{zone}/…), so a cofhe stack reads this ceremony's keyset
    // directly as files. The manifest (per-artifact + per-secret digests + signer
    // addresses) sits alongside for the consumer reader; the provenance sidecar is
    // still written but unread (kept for wire-format compatibility).
    let sa_token = MetadataClient::new(METADATA_URL).token().await?;
    let gcs = GcsClient::new(GCS_URL);

    for (name, bytes) in [
        (OBJ_SERVER_KEY, &artifacts.server_key),
        (OBJ_PUBLIC_KEY, &artifacts.compact_public_key),
        (OBJ_CRS, &artifacts.crs),
    ] {
        let object = object_path(&cfg.public_prefix, cfg.zone, name);
        info!(object = %object, bytes = bytes.len(), "publishing public FHE artifact");
        let written = gcs
            .upload(&sa_token, &cfg.public_bucket, &object, bytes)
            .await?;
        info!(object = %written, "public FHE artifact written");
    }

    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    let public_bytes = public.to_canonical_bytes();
    info!(object = %manifest_object, "publishing public-material manifest");
    let written = gcs
        .upload(
            &sa_token,
            &cfg.public_bucket,
            &manifest_object,
            &public_bytes,
        )
        .await?;
    info!(object = %written, "public-material manifest written to our GCS bucket");

    // Provenance for the manifest: mint an attestation whose eat_nonce binds
    // SHA-256(manifest) and store it as a sidecar. Consumers no longer verify this
    // sidecar (that check was removed — see the AGENTS.md invariant); the manifest's
    // integrity now rests on the bucket's write IAM. Still written for wire-format
    // compatibility.
    let public_hash = hex::encode(public.hash());
    info!(public_hash = %public_hash, "minting public-material provenance (eat_nonce = SHA-256(manifest))");
    let public_provenance_jwt = attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[public_hash])
        .await?;
    let prov_object = format!("{manifest_object}.provenance");
    let written = gcs
        .upload(
            &sa_token,
            &cfg.public_bucket,
            &prov_object,
            public_provenance_jwt.as_bytes(),
        )
        .await?;
    info!(object = %written, "public-material provenance written to our GCS bucket");

    info!(
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "keygen ceremony complete"
    );
    Ok(())
}
