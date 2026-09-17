// Writer-only modules (binary-local); the reusable cloud clients + keygen live
// in the lib crate (`cofhe_keys`) so the consumer reader can share them.
#[cfg(not(feature = "mock"))]
mod attestation;
#[cfg(not(feature = "mock"))]
mod gcp_auth;

#[cfg(feature = "mock")]
mod mock;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(not(feature = "mock"))]
use crate::attestation::AttestationClient;
#[cfg(not(feature = "mock"))]
use crate::gcp_auth::{GcpAuth, MetadataClient};
#[cfg(not(feature = "mock"))]
use anyhow::{bail, Context};
#[cfg(not(feature = "mock"))]
use cofhe_keys::serialization::{sha256, SecretEnvelope};
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

// Public GCS object layout under the baked `{public_prefix}/{public_zone}/`. The three FHE artifacts
// use cofhe's exact mounted file names, so a cofhe stack pointed at this bucket
// reads this ceremony's keyset directly as files
// (keys/versionized/{zone}/{computation_key,public_key,crs}). The manifest sits
// alongside for the consumer reader; the provenance sidecar is still written but
// unread (kept for wire-format compatibility).
#[cfg(not(feature = "mock"))]
const OBJ_SERVER_KEY: &str = "computation_key";
#[cfg(not(feature = "mock"))]
const OBJ_PUBLIC_KEY: &str = "public_key";
#[cfg(not(feature = "mock"))]
const OBJ_CRS: &str = "crs";
#[cfg(not(feature = "mock"))]
const OBJ_MANIFEST: &str = "public-material";

// Object key under the per-zone prefix, e.g. keys/versionized/0/computation_key.
#[cfg(not(feature = "mock"))]
fn object_path(prefix: &str, zone: u32, name: &str) -> String {
    format!("{}/{}/{}", prefix.trim_end_matches('/'), zone, name)
}

// One partner of the Shamir ceremony: its GCP project (the cross-project write
// target) and its keygen WRITE audience (the attestation/STS audience for that
// project). Sourced from the baked `EnvConfig`; partner `i` receives share `i` of
// each split secret.
#[cfg(not(feature = "mock"))]
#[derive(Debug, Clone)]
struct PartnerCfg {
    project_id: String,
    wip_audience: String,
}

// The two per-audience partner secret names, same in EVERY partner project (each
// holds that partner's share): TeeCryptor's FHE priv + decrypt signer, and the ZK
// verifier's signer. Network-wide fixed ids — the consumers read the SAME names —
// so they are compile-time constants, not operator-settable.
#[cfg(not(feature = "mock"))]
const WRITE_SECRET_FHE_PRIV: &str = "cofhe-tee-fhe-priv";
#[cfg(not(feature = "mock"))]
const WRITE_SECRET_ZK_SIGNER: &str = "cofhe-tee-zk-signer";

// The ceremony shape is BAKED per environment (partners + their write audiences,
// N/T, public bucket + layout) in `cofhe_keys::envs`, selected by `COFHE_ENV` — the
// only operator-settable input besides `RUST_LOG`, and it is constrained to the
// baked environments (fail-closed). Nothing here is settable via a VM metadata
// override. `partners` is the partner set the Shamir shares are written to (share
// i → partner i); `shares` (N) equals the partner count; `threshold` (T) is the
// reconstruction threshold. Direct federated grant: each partner's attested
// federated principal holds secretVersionAdder directly on its secrets, so there is
// no service account to impersonate (no SA_EMAIL).
#[cfg(not(feature = "mock"))]
struct Config {
    partners: Vec<PartnerCfg>,
    shares: u8,
    threshold: u8,
    write_secret_fhe_priv: String,
    write_secret_zk_signer: String,
    public_bucket: String,
    // Prefix + security zone under which the public objects are laid out, matching
    // cofhe's mounted key path (keys/versionized/{zone}/…), so a cofhe stack reads
    // this ceremony's keyset directly.
    public_prefix: String,
    zone: u32,
}

#[cfg(not(feature = "mock"))]
impl Config {
    // `COFHE_ENV` is the ONLY operator-settable ceremony input (besides `RUST_LOG`,
    // honored by tracing) — it selects a BAKED environment and nothing else. Everything
    // else is compiled in, so a VM metadata override cannot redirect the write set,
    // weaken the threshold, or repoint the public bucket.
    fn from_env() -> Result<Self> {
        let env = std::env::var("COFHE_ENV").context(
            "env var COFHE_ENV not set (baked-environment selector: staging | testnet | mainnet)",
        )?;
        Self::for_env(&env)
    }

    // Build the ceremony config from a baked environment. Fails closed on any env not
    // in `cofhe_keys::envs`' map (no default, no fallback). N (shares) is the baked
    // partner count; T (threshold), the partner write audiences, the public bucket and
    // its layout are all baked; the two partner secret ids are network-wide constants.
    fn for_env(env: &str) -> Result<Self> {
        let ec = cofhe_keys::envs::lookup(env)?;
        // Fail before a single key is generated. A placeholder audience would
        // otherwise abort the run mid-ceremony, after earlier partners are written.
        ec.ensure_partners_complete()
            .with_context(|| format!("environment {env:?} cannot run a ceremony"))?;
        let partners: Vec<PartnerCfg> = ec
            .partners
            .iter()
            .map(|p| PartnerCfg {
                project_id: p.project_id.to_string(),
                wip_audience: p.keygen_write_audience.to_string(),
            })
            .collect();

        let cfg = Config {
            shares: partners.len() as u8,
            threshold: ec.shamir_threshold,
            partners,
            write_secret_fhe_priv: WRITE_SECRET_FHE_PRIV.to_string(),
            write_secret_zk_signer: WRITE_SECRET_ZK_SIGNER.to_string(),
            public_bucket: ec.public_bucket.to_string(),
            public_prefix: ec.public_prefix.to_string(),
            zone: ec.public_zone,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    // Fail-closed validation of the ceremony shape. The N-partners ↔ N-shares
    // invariant (share i → partner i) and distinct partner ids are load-bearing:
    // the per-partner digest lists key by partner identity, so a duplicate id would
    // make two entries collide, and a count mismatch would leave a partner without a
    // share (or a share without a home). These now guard the baked env config.
    fn validate(&self) -> Result<()> {
        if self.partners.is_empty() {
            bail!("baked environment lists no partners");
        }
        if self.partners.len() != self.shares as usize {
            bail!(
                "share count ({}) must equal the partner count ({}): one share per partner",
                self.shares,
                self.partners.len()
            );
        }
        if self.threshold < cofhe_keys::shamir::MIN_THRESHOLD || self.threshold > self.shares {
            bail!(
                "threshold T ({}) must satisfy {} <= T <= N ({})",
                self.threshold,
                cofhe_keys::shamir::MIN_THRESHOLD,
                self.shares
            );
        }
        for (i, p) in self.partners.iter().enumerate() {
            // Empty fields would mean a malformed baked env entry; reject at startup
            // rather than fail later with an opaque attestation/STS 403.
            if p.project_id.is_empty() {
                bail!("baked partner #{i} has an empty project_id");
            }
            if p.wip_audience.is_empty() {
                bail!("baked partner {:?} has an empty wip_audience", p.project_id);
            }
            for q in &self.partners[i + 1..] {
                if p.project_id == q.project_id {
                    bail!("duplicate baked partner project_id {:?}", p.project_id);
                }
            }
        }
        Ok(())
    }
}

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

/// Mint a provenance token binding `SHA-256(payload)`, wrap it in a
/// [`SecretEnvelope`], and write it as a new version of `secret`. Access pattern
/// B: the federated token is the Secret Manager bearer directly.
#[cfg(not(feature = "mock"))]
async fn write_secret(
    attest: &AttestationClient,
    sm: &SecretManager,
    federated: &str,
    project_id: &str,
    secret: &str,
    payload: Vec<u8>,
) -> Result<()> {
    let payload_hash = hex::encode(sha256(&payload));
    info!(secret = %secret, payload_hash = %payload_hash, "minting provenance (eat_nonce = SHA-256(payload))");
    let provenance_jwt = attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[payload_hash])
        .await?;
    let envelope = SecretEnvelope {
        payload,
        provenance_jwt,
    };
    let version = sm
        .add_version(
            federated,
            project_id,
            secret,
            &envelope.to_canonical_bytes(),
        )
        .await?;
    info!(secret = %secret, version = %version, "secret written to partner Secret Manager");
    Ok(())
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;

    fn partner(id: &str) -> PartnerCfg {
        PartnerCfg {
            project_id: id.to_string(),
            wip_audience: format!("//iam/{id}/wip"),
        }
    }

    fn cfg(partners: Vec<PartnerCfg>, shares: u8, threshold: u8) -> Config {
        Config {
            partners,
            shares,
            threshold,
            write_secret_fhe_priv: "fhe".to_string(),
            write_secret_zk_signer: "zk".to_string(),
            public_bucket: "bucket".to_string(),
            public_prefix: "keys/versionized".to_string(),
            zone: 0,
        }
    }

    // The baked staging env yields a valid 5-partner / 2-of-5 ceremony whose write
    // audiences point at the keygen pool+provider (NOT the reader pool) and whose
    // secret ids + public layout are the baked constants.
    #[test]
    fn builds_staging_from_baked_env() {
        let cfg = Config::for_env("staging").unwrap();
        assert_eq!(cfg.partners.len(), 5);
        assert_eq!(cfg.shares, 5);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.partners[0].project_id, "cofhe-tee-partner-1");
        assert!(cfg.partners[0]
            .wip_audience
            .contains("/workloadIdentityPools/cofhe-tee-keygen-pool/"));
        assert!(cfg.partners[0]
            .wip_audience
            .ends_with("/providers/cofhe-tee-keygen-provider"));
        assert_eq!(cfg.write_secret_fhe_priv, "cofhe-tee-fhe-priv");
        assert_eq!(cfg.write_secret_zk_signer, "cofhe-tee-zk-signer");
        assert_eq!(cfg.public_bucket, "localcofhenix");
        assert_eq!(cfg.public_prefix, "generator/keys/versionized");
        assert_eq!(cfg.zone, 0);
    }

    #[test]
    fn builds_testnet_from_baked_env() {
        let cfg = Config::for_env("testnet").unwrap();
        assert_eq!(cfg.partners.len(), 3);
        assert_eq!(cfg.shares, 3);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.public_bucket, "fhenix-testnet-v2");
    }

    #[test]
    // The mainnet set is baked at its real shape (N=6, T=3) with three slots still to
    // fill, so a ceremony must refuse to start. Check the baked shape directly, then
    // the refusal.
    fn mainnet_refuses_a_ceremony_while_partner_slots_are_open() {
        let ec = cofhe_keys::envs::lookup("mainnet").unwrap();
        assert_eq!(ec.partners.len(), 6);
        assert_eq!(ec.shamir_threshold, 3);
        assert_eq!(ec.partners[0].project_id, "fhenix-507307");
        assert!(ec.partners[0]
            .keygen_write_audience
            .ends_with("/providers/cofhe-tee-keygen-provider"));
        assert_eq!(ec.public_bucket, "fhenix-mainnet-keys");

        // `Config` is not `Debug` (it carries the write audiences), so match rather
        // than `expect_err`.
        let err = match Config::for_env("mainnet") {
            Ok(_) => panic!("an incomplete partner set must not build a ceremony config"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("cannot run a ceremony"), "{err}");
    }

    // Fail-closed: an env outside the baked map is rejected before any network call.
    #[test]
    fn unknown_env_fails_closed() {
        assert!(Config::for_env("prod").is_err());
        assert!(Config::for_env("").is_err());
    }

    #[test]
    fn rejects_empty_partners() {
        assert!(cfg(vec![], 0, 0).validate().is_err());
    }

    #[test]
    fn rejects_partner_count_share_mismatch() {
        let partners = (0..3).map(|i| partner(&format!("p{i}"))).collect();
        assert!(cfg(partners, 5, 2).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_project_ids() {
        let partners = vec![partner("dup"), partner("p1"), partner("dup")];
        assert!(cfg(partners, 3, 2).validate().is_err());
    }

    #[test]
    fn rejects_empty_wip_audience() {
        let mut partners: Vec<PartnerCfg> = (0..5).map(|i| partner(&format!("p{i}"))).collect();
        partners[2].wip_audience = String::new();
        assert!(cfg(partners, 5, 2).validate().is_err());
    }

    #[test]
    fn rejects_empty_project_id() {
        let mut partners: Vec<PartnerCfg> = (0..5).map(|i| partner(&format!("p{i}"))).collect();
        partners[0].project_id = String::new();
        assert!(cfg(partners, 5, 2).validate().is_err());
    }

    #[test]
    fn rejects_threshold_above_shares() {
        let partners = (0..5).map(|i| partner(&format!("p{i}"))).collect();
        assert!(cfg(partners, 5, 6).validate().is_err());
    }

    #[test]
    fn rejects_zero_threshold() {
        let partners = (0..5).map(|i| partner(&format!("p{i}"))).collect();
        assert!(cfg(partners, 5, 0).validate().is_err());
    }

    #[test]
    fn rejects_single_partner() {
        // T = N = 1 is no longer valid: Gf256::combine_array needs >= 2 shares.
        assert!(cfg(vec![partner("solo")], 1, 1).validate().is_err());
    }

    #[test]
    fn accepts_minimum_two_of_two() {
        cfg(vec![partner("a"), partner("b")], 2, 2)
            .validate()
            .unwrap();
    }
}
