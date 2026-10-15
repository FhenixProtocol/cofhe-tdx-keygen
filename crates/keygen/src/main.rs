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
use cofhe_keys::envs::{EnvConfig, ReshareSource};
#[cfg(not(feature = "mock"))]
use cofhe_keys::serialization::{sha256, SecretEnvelope};
#[cfg(not(feature = "mock"))]
use cofhe_keys::{gcs::GcsClient, keygen, secrets::SecretManager};
#[cfg(not(feature = "mock"))]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "mock"))]
use std::num::NonZeroU64;

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

// One of the two per-audience secrets, as `RESHARE_SOURCE_VERSIONS` names it.
// Each secret numbers its versions on its own, so a pin names the secret too.
#[cfg(not(feature = "mock"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Secret {
    FhePriv,
    ZkSigner,
}

// The source side of a reshare. `versions` pins the Secret Manager version to
// read for one secret at one partner; a secret it does not name is read at
// `latest`. Pinning is the recovery path after a run that stopped mid-write:
// `latest` at a staying partner then holds a share that no published manifest
// describes. `src` is the baked source: partners, threshold and the live-signer
// anchor.
#[cfg(not(feature = "mock"))]
struct ReshareCfg {
    src: &'static ReshareSource,
    versions: BTreeMap<(String, Secret), NonZeroU64>,
}

#[cfg(not(feature = "mock"))]
enum Mode {
    Ceremony,
    Reshare(ReshareCfg),
}

// The run shape is baked per env in `cofhe_keys::envs` (see `from_env` for the
// operator inputs). Share i goes to `partners[i]`; N = the partner count; T =
// `threshold`. No SA_EMAIL: each partner's attested federated principal holds
// secretVersionAdder on its secrets directly.
#[cfg(not(feature = "mock"))]
struct Config {
    mode: Mode,
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
    // `COFHE_ENV` selects a BAKED environment. `KEYGEN_MODE` (default `ceremony`)
    // must agree with it. `RESHARE_SOURCE_VERSIONS` (default empty) pins source
    // versions in reshare mode. Everything else is compiled in, so a VM metadata
    // override cannot redirect the write set, weaken the threshold, or repoint the
    // public bucket.
    fn from_env() -> Result<Self> {
        let env = std::env::var("COFHE_ENV").context(
            "env var COFHE_ENV not set (baked-environment selector: staging | testnet | mainnet)",
        )?;
        let mode = optional_env("KEYGEN_MODE")?.unwrap_or_else(|| MODE_CEREMONY.to_string());
        let versions = optional_env("RESHARE_SOURCE_VERSIONS")?.unwrap_or_default();
        Self::for_env_mode(&env, &mode, &versions)
    }

    // Fails closed on any env not in `cofhe_keys::envs`' map (no default, no
    // fallback).
    fn for_env_mode(env: &str, mode: &str, versions: &str) -> Result<Self> {
        let ec = cofhe_keys::envs::lookup(env)?;
        Self::from_env_config(ec, mode, versions)
            .with_context(|| format!("environment {env:?} cannot run in mode {mode:?}"))
    }

    // N (shares) is the baked target partner count; T, the partner write
    // audiences, the reshare source, the public bucket and its layout are all
    // baked; the two partner secret ids are network-wide constants.
    fn from_env_config(ec: &'static EnvConfig, mode: &str, versions: &str) -> Result<Self> {
        // Fail before a single key is generated or read. A placeholder audience would
        // otherwise abort the run mid-write, after earlier partners are written.
        ec.ensure_partners_complete()?;
        let mode = match (mode, &ec.reshare_from) {
            (MODE_CEREMONY, None) => {
                if !versions.is_empty() {
                    bail!("RESHARE_SOURCE_VERSIONS is set, but a ceremony reads no shares");
                }
                Mode::Ceremony
            }
            (MODE_CEREMONY, Some(_)) => bail!(
                "the baked env carries a reshare source; a ceremony would replace the live \
                 keyset. Run KEYGEN_MODE=reshare, or remove reshare_from to run a ceremony"
            ),
            (MODE_RESHARE, Some(src)) => Mode::Reshare(ReshareCfg {
                src,
                versions: parse_versions(versions)?,
            }),
            (MODE_RESHARE, None) => {
                bail!("KEYGEN_MODE=reshare, but the baked env has no reshare source")
            }
            (other, _) => bail!(
                "unknown KEYGEN_MODE {other:?} (expected {MODE_CEREMONY:?} or {MODE_RESHARE:?})"
            ),
        };
        let partners: Vec<PartnerCfg> = ec
            .partners
            .iter()
            .map(|p| PartnerCfg {
                project_id: p.project_id.to_string(),
                wip_audience: p.keygen_write_audience.to_string(),
            })
            .collect();

        let cfg = Config {
            mode,
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

    // Fail-closed validation of the run shape. The N-partners ↔ N-shares
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
        check_threshold("threshold", self.threshold, self.shares as usize)?;
        for (i, p) in self.partners.iter().enumerate() {
            // Empty fields would mean a malformed baked env entry; reject at startup
            // rather than fail later with an opaque attestation/STS 403.
            if p.project_id.is_empty() {
                bail!("baked partner #{i} has an empty project_id");
            }
            if p.wip_audience.is_empty() {
                bail!("baked partner {:?} has an empty wip_audience", p.project_id);
            }
        }
        check_distinct(self.partners.iter().map(|p| p.project_id.as_str()))?;
        if let Mode::Reshare(r) = &self.mode {
            self.validate_reshare(r)?;
        }
        Ok(())
    }

    fn validate_reshare(&self, r: &ReshareCfg) -> Result<()> {
        if r.src.partners.is_empty() {
            bail!("the reshare source lists no partners");
        }
        check_threshold(
            "reshare source threshold",
            r.src.shamir_threshold,
            r.src.partners.len(),
        )?;
        // An empty audience would fail later as an opaque STS 403, like a target's.
        if r.src
            .partners
            .iter()
            .any(|s| s.project_id.is_empty() || s.wip_pool_audience.is_empty())
        {
            bail!("a reshare source partner has an empty project_id or wip_pool_audience");
        }
        check_distinct(r.src.partners.iter().map(|s| s.project_id)).context("reshare source")?;
        for (id, _) in r.versions.keys() {
            if !r.src.partners.iter().any(|s| s.project_id == id) {
                bail!(
                    "RESHARE_SOURCE_VERSIONS names {id:?}, which is not a reshare source partner"
                );
            }
        }
        for (what, address) in [
            ("decrypt_signer_address", r.src.decrypt_signer_address),
            ("zk_signer_address", r.src.zk_signer_address),
        ] {
            let hex = address.strip_prefix("0x").unwrap_or_default();
            if hex.len() != 40
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                bail!("the reshare anchor {what} {address:?} is not a lowercase 0x-prefixed EVM address");
            }
        }
        let source: BTreeSet<&str> = r.src.partners.iter().map(|s| s.project_id).collect();
        let target: BTreeSet<&str> = self
            .partners
            .iter()
            .map(|p| p.project_id.as_str())
            .collect();
        if source == target && r.src.shamir_threshold == self.threshold {
            bail!(
                "the reshare source equals the target set with the same threshold: nothing to do"
            );
        }
        Ok(())
    }
}

#[cfg(not(feature = "mock"))]
const MODE_CEREMONY: &str = "ceremony";
#[cfg(not(feature = "mock"))]
const MODE_RESHARE: &str = "reshare";

#[cfg(not(feature = "mock"))]
fn check_threshold(what: &str, t: u8, n: usize) -> Result<()> {
    if t < cofhe_keys::shamir::MIN_THRESHOLD || t as usize > n {
        bail!(
            "{what} T ({t}) must satisfy {} <= T <= N ({n})",
            cofhe_keys::shamir::MIN_THRESHOLD
        );
    }
    Ok(())
}

#[cfg(not(feature = "mock"))]
fn check_distinct<'a>(ids: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            bail!("duplicate baked partner project_id {id:?}");
        }
    }
    Ok(())
}

// `RESHARE_SOURCE_VERSIONS` is `id/secret=N,…` with secret `fhe-priv` or
// `zk-signer`. The parse is strict: no spaces, no empty entries, no repeated pin,
// and N >= 1. A typo must stop the run, not fall back to `latest`. An id that is
// not a source partner fails in `validate_reshare`.
#[cfg(not(feature = "mock"))]
fn parse_versions(s: &str) -> Result<BTreeMap<(String, Secret), NonZeroU64>> {
    let mut out = BTreeMap::new();
    if s.is_empty() {
        return Ok(out);
    }
    for entry in s.split(',') {
        let shape = || format!("RESHARE_SOURCE_VERSIONS entry {entry:?} is not id/secret=N");
        let (key, n) = entry.split_once('=').with_context(shape)?;
        let (id, secret) = key.split_once('/').with_context(shape)?;
        let secret = match secret {
            "fhe-priv" => Secret::FhePriv,
            "zk-signer" => Secret::ZkSigner,
            _ => bail!(
                "RESHARE_SOURCE_VERSIONS entry {entry:?}: the secret must be fhe-priv or zk-signer"
            ),
        };
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            bail!("RESHARE_SOURCE_VERSIONS entry {entry:?} has an invalid version");
        }
        let n: NonZeroU64 = n.parse().with_context(|| {
            format!("RESHARE_SOURCE_VERSIONS entry {entry:?}: version must be >= 1")
        })?;
        if out.insert((id.to_string(), secret), n).is_some() {
            bail!("RESHARE_SOURCE_VERSIONS pins {key:?} twice");
        }
    }
    Ok(out)
}

// An env var that may be absent. Absent gives `None`. A value that is set but not
// UTF-8 is an error: a fallback would hide a corrupted setting.
#[cfg(not(feature = "mock"))]
fn optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("env var {name}")),
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
    if let Mode::Reshare(r) = &cfg.mode {
        for s in r.src.partners {
            info!(partner = %s.project_id, fhe_priv_version = ?r.versions.get(&(s.project_id.to_string(), Secret::FhePriv)), zk_signer_version = ?r.versions.get(&(s.project_id.to_string(), Secret::ZkSigner)), "reshare source");
        }
        bail!(
            "KEYGEN_MODE=reshare: this build validates a reshare config ({} sources, T={}, live signers {} and {}) but cannot run one",
            r.src.partners.len(),
            r.src.shamir_threshold,
            r.src.decrypt_signer_address,
            r.src.zk_signer_address
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
    use cofhe_keys::envs::EnvPartner;

    fn partner(id: &str) -> PartnerCfg {
        PartnerCfg {
            project_id: id.to_string(),
            wip_audience: format!("//iam/{id}/wip"),
        }
    }

    fn cfg(partners: Vec<PartnerCfg>, shares: u8, threshold: u8) -> Config {
        Config {
            mode: Mode::Ceremony,
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
        let cfg = Config::for_env_mode("staging", "ceremony", "").unwrap();
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
        let cfg = Config::for_env_mode("testnet", "ceremony", "").unwrap();
        assert_eq!(cfg.partners.len(), 3);
        assert_eq!(cfg.shares, 3);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.public_bucket, "fhenix-testnet-v2");
    }

    #[test]
    // The mainnet partner set is complete, so it builds a real 3-of-6 ceremony whose
    // write audiences point at the keygen pool+provider, not the reader pool.
    fn builds_mainnet_from_baked_env() {
        let cfg = Config::for_env_mode("mainnet", "ceremony", "")
            .expect("the mainnet partner set is complete");
        assert_eq!(cfg.partners.len(), 6);
        assert_eq!(cfg.shares, 6);
        assert_eq!(cfg.threshold, 3);
        assert_eq!(cfg.partners[0].project_id, "fhenix-507307");
        assert_eq!(cfg.public_bucket, "fhenix-mainnet-keys");
        for p in &cfg.partners {
            assert!(
                p.wip_audience
                    .ends_with("/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider"),
                "partner {} must write through the keygen pool, got {}",
                p.project_id,
                p.wip_audience
            );
        }
    }

    // Fail-closed: an env outside the baked map is rejected before any network call.
    #[test]
    fn unknown_env_fails_closed() {
        assert!(Config::for_env_mode("prod", "ceremony", "").is_err());
        assert!(Config::for_env_mode("", "ceremony", "").is_err());
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

    // ---- reshare mode -------------------------------------------------------

    fn env_partner(id: &'static str, num: &'static str) -> EnvPartner {
        EnvPartner {
            project_id: id,
            wip_pool_audience: Box::leak(
                format!("//iam.googleapis.com/projects/{num}/locations/global/workloadIdentityPools/cofhe-tee-reader-pool")
                    .into_boxed_str(),
            ),
            keygen_write_audience: Box::leak(
                format!("//iam.googleapis.com/projects/{num}/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider")
                    .into_boxed_str(),
            ),
        }
    }

    fn set(ids: &[(&'static str, &'static str)]) -> &'static [EnvPartner] {
        Box::leak(
            ids.iter()
                .map(|(id, n)| env_partner(id, n))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    const P1: (&str, &str) = ("p-1", "111111111111");
    const P2: (&str, &str) = ("p-2", "222222222222");
    const P3: (&str, &str) = ("p-3", "333333333333");
    const P4: (&str, &str) = ("p-4", "444444444444");

    const LIVE_DECRYPT: &str = "0x1111111111111111111111111111111111111111";
    const LIVE_ZK: &str = "0x2222222222222222222222222222222222222222";

    fn env(
        target: &'static [EnvPartner],
        t: u8,
        source: Option<(&'static [EnvPartner], u8)>,
    ) -> &'static EnvConfig {
        Box::leak(Box::new(EnvConfig {
            partners: target,
            public_bucket: "b",
            public_object: "p/0/public-material",
            public_prefix: "p",
            public_zone: 0,
            shamir_threshold: t,
            reshare_from: source.map(|(partners, shamir_threshold)| ReshareSource {
                partners,
                shamir_threshold,
                decrypt_signer_address: LIVE_DECRYPT,
                zk_signer_address: LIVE_ZK,
            }),
        }))
    }

    // 2-of-3 on p1..p3 → 2-of-3 on p1, p2, p4: replace p3 with p4.
    fn replace_env() -> &'static EnvConfig {
        env(set(&[P1, P2, P4]), 2, Some((set(&[P1, P2, P3]), 2)))
    }

    #[test]
    fn reshare_builds_source_and_target_sets() {
        let cfg = Config::from_env_config(replace_env(), "reshare", "").unwrap();
        let Mode::Reshare(r) = &cfg.mode else {
            panic!("expected reshare mode")
        };
        let ids: Vec<&str> = r.src.partners.iter().map(|s| s.project_id).collect();
        assert_eq!(ids, ["p-1", "p-2", "p-3"]);
        assert_eq!(r.src.shamir_threshold, 2);
        let targets: Vec<&str> = cfg.partners.iter().map(|p| p.project_id.as_str()).collect();
        assert_eq!(targets, ["p-1", "p-2", "p-4"]);
        assert!(r.versions.is_empty());
    }

    // The mode must agree with the baked env. A ceremony on an env that carries a
    // reshare source would overwrite the live keyset with a new one.
    #[test]
    fn mode_must_agree_with_the_baked_env() {
        assert!(Config::from_env_config(replace_env(), "ceremony", "").is_err());
        let plain = env(set(&[P1, P2, P3]), 2, None);
        assert!(Config::from_env_config(plain, "reshare", "").is_err());
        assert!(Config::from_env_config(plain, "ceremony", "").is_ok());
    }

    #[test]
    fn unknown_mode_fails_closed() {
        for bad in ["", "Reshare", "rotate", "reshare ", "ceremony\n"] {
            assert!(
                Config::from_env_config(replace_env(), bad, "").is_err(),
                "mode {bad:?} must fail closed"
            );
        }
    }

    #[test]
    fn ceremony_rejects_source_versions() {
        let plain = env(set(&[P1, P2, P3]), 2, None);
        assert!(Config::from_env_config(plain, "ceremony", "p-1=3").is_err());
    }

    #[test]
    fn reshare_parses_per_secret_source_versions() {
        let cfg = Config::from_env_config(
            replace_env(),
            "reshare",
            "p-1/fhe-priv=3,p-1/zk-signer=4,p-3/zk-signer=12",
        )
        .unwrap();
        let Mode::Reshare(r) = &cfg.mode else {
            panic!("expected reshare mode")
        };
        let get = |id: &str, s: Secret| r.versions.get(&(id.to_string(), s)).map(|v| v.get());
        assert_eq!(get("p-1", Secret::FhePriv), Some(3));
        assert_eq!(get("p-1", Secret::ZkSigner), Some(4));
        assert_eq!(get("p-3", Secret::ZkSigner), Some(12));
        assert_eq!(get("p-3", Secret::FhePriv), None);
        assert_eq!(r.versions.len(), 3);
    }

    #[test]
    fn malformed_source_versions_fail_closed() {
        for bad in [
            "p-1",
            "p-1=3",
            "p-1/fhe-priv",
            "p-1/fhe-priv=",
            "/fhe-priv=3",
            "p-1/=3",
            "p-1/other=3",
            "p-1/fhe-priv=0",
            "p-1/fhe-priv=-1",
            "p-1/fhe-priv=x",
            "p-1/fhe-priv=3,",
            ",p-1/fhe-priv=3",
            "p-1/fhe-priv=3,,p-2/fhe-priv=4",
            "p-1 /fhe-priv=3",
            "p-1/fhe-priv= 3",
            "p-1/fhe-priv=3, p-2/fhe-priv=4",
            "p-1/fhe-priv=3,p-1/fhe-priv=4",
            "p-4/fhe-priv=3",
            "nobody/zk-signer=3",
        ] {
            assert!(
                Config::from_env_config(replace_env(), "reshare", bad).is_err(),
                "versions {bad:?} must fail closed"
            );
        }
    }

    // The baked anchor pins the live keyset by its public signer addresses. A
    // malformed anchor must stop the build of the config, not the run.
    #[test]
    fn reshare_requires_a_well_formed_live_anchor() {
        for bad in [
            "",
            "0x",
            "11",
            "0x1111",
            &format!("0x{}", "G".repeat(40)),
            &format!("0x{}", "AB".repeat(20)),
        ] {
            let bad: &'static str = Box::leak(bad.to_string().into_boxed_str());
            for (decrypt, zk) in [(bad, LIVE_ZK), (LIVE_DECRYPT, bad)] {
                let e = Box::leak(Box::new(EnvConfig {
                    reshare_from: Some(ReshareSource {
                        partners: set(&[P1, P2, P3]),
                        shamir_threshold: 2,
                        decrypt_signer_address: decrypt,
                        zk_signer_address: zk,
                    }),
                    ..*env(set(&[P1, P2, P4]), 2, None)
                }));
                assert!(
                    Config::from_env_config(e, "reshare", "").is_err(),
                    "anchor ({decrypt:?}, {zk:?}) must fail closed"
                );
            }
        }
    }

    // A value that is set but not UTF-8 must stop the run. A fallback to the
    // default would turn a corrupted KEYGEN_MODE into a ceremony.
    #[test]
    fn optional_env_fails_on_a_value_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let name = "KEYGEN_TEST_OPTIONAL_ENV_NOT_UTF8";
        std::env::set_var(name, std::ffi::OsStr::from_bytes(&[0x66, 0xff]));
        assert!(optional_env(name).is_err());
        std::env::set_var(name, "reshare");
        assert_eq!(optional_env(name).unwrap().as_deref(), Some("reshare"));
        std::env::remove_var(name);
        assert_eq!(optional_env(name).unwrap(), None);
    }

    #[test]
    fn reshare_rejects_a_no_op() {
        let same = env(set(&[P1, P2, P3]), 2, Some((set(&[P3, P2, P1]), 2)));
        assert!(Config::from_env_config(same, "reshare", "").is_err());
        // Same set with a new T is a real change.
        let new_t = env(set(&[P1, P2, P3]), 3, Some((set(&[P1, P2, P3]), 2)));
        assert!(Config::from_env_config(new_t, "reshare", "").is_ok());
    }

    #[test]
    fn reshare_validates_the_source_set() {
        let empty = env(set(&[P1, P2]), 2, Some((set(&[]), 2)));
        assert!(Config::from_env_config(empty, "reshare", "").is_err());
        let dup = env(set(&[P1, P2]), 2, Some((set(&[P1, P1, P3]), 2)));
        assert!(Config::from_env_config(dup, "reshare", "").is_err());
        let t_high = env(set(&[P1, P2]), 2, Some((set(&[P1, P3]), 3)));
        assert!(Config::from_env_config(t_high, "reshare", "").is_err());
        let t_low = env(set(&[P1, P2]), 2, Some((set(&[P1, P3]), 1)));
        assert!(Config::from_env_config(t_low, "reshare", "").is_err());
        let src: &'static [EnvPartner] = Box::leak(Box::new([
            env_partner(P1.0, P1.1),
            EnvPartner {
                project_id: "p-9",
                wip_pool_audience: "",
                keygen_write_audience: "",
            },
        ]));
        let empty_audience = env(set(&[P1, P2]), 2, Some((src, 2)));
        assert!(Config::from_env_config(empty_audience, "reshare", "").is_err());
    }

    // The CI gate for baked config: every baked env must be valid in exactly one
    // mode. A bad reshare source, or a forgotten one, then fails CI and never
    // reaches a release.
    #[test]
    fn every_baked_env_validates_in_its_one_mode() {
        for name in cofhe_keys::envs::env_names() {
            // A declared but unfilled partner slot fails both modes on purpose.
            let env = cofhe_keys::envs::lookup(name).unwrap();
            if env.ensure_partners_complete().is_err() {
                assert!(Config::for_env_mode(name, "ceremony", "").is_err());
                assert!(Config::for_env_mode(name, "reshare", "").is_err());
                continue;
            }
            let ceremony = Config::for_env_mode(name, "ceremony", "");
            let reshare = Config::for_env_mode(name, "reshare", "");
            assert!(
                ceremony.is_ok() != reshare.is_ok(),
                "env {name:?} must be valid in exactly one mode: ceremony={:?} reshare={:?}",
                ceremony.err().map(|e| format!("{e:#}")),
                reshare.err().map(|e| format!("{e:#}")),
            );
        }
    }
}
