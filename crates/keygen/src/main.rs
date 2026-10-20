// Binary-local modules; the reusable cloud clients, keygen and reader live in the
// lib crate (`cofhe_keys`).
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
use cofhe_keys::envs::{EnvConfig, EnvPartner, ReshareSource};
#[cfg(not(feature = "mock"))]
use cofhe_keys::reader::{self, PartnerAccess, PartnerRef, ReaderContext};
#[cfg(not(feature = "mock"))]
use cofhe_keys::serialization::{sha256, PublicMaterial, SecretEnvelope};
#[cfg(not(feature = "mock"))]
use cofhe_keys::{gcs::GcsClient, keygen, secrets::SecretManager};
#[cfg(not(feature = "mock"))]
use std::collections::BTreeSet;
#[cfg(not(feature = "mock"))]
use tracing::warn;

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

// The keygen's reader name at each source partner: the `keygen-reader` provider.
// It is enabled only for a reshare the partner approves (`grant_reshare_read`), so
// the keygen image can read shares only during that window.
#[cfg(not(feature = "mock"))]
const KEYGEN_READER: &str = "keygen";

// Which run this image does, from the baked env alone: an env with `reshare_from`
// builds a reshare image, any other env a ceremony image. No runtime input can
// change it.
#[cfg(not(feature = "mock"))]
enum Mode {
    Ceremony,
    Reshare(&'static ReshareSource),
}

// The run shape is baked per env in `cofhe_keys::envs`. Share i goes to
// `partners[i]`; N = the partner count; T = `threshold`. No SA_EMAIL: each
// partner's attested federated principal holds secretVersionAdder on its secrets
// directly.
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
    // A ceremony may replace a live keyset only when the env bakes this.
    replace_live_keyset: bool,
}

#[cfg(not(feature = "mock"))]
impl Config {
    // `COFHE_ENV` is the ONLY operator-settable input (besides `RUST_LOG`, honored by
    // tracing) — it selects a BAKED environment and nothing else. Everything else,
    // the run mode and the recovery pins included, is compiled in, so a VM metadata
    // override cannot redirect the write set, weaken the threshold, repoint the
    // public bucket, or turn a reshare into a ceremony.
    fn from_env() -> Result<Self> {
        let env = std::env::var("COFHE_ENV").context(
            "env var COFHE_ENV not set (baked-environment selector: staging | testnet | mainnet)",
        )?;
        Self::for_env(&env)
    }

    // Fails closed on any env not in `cofhe_keys::envs`' map (no default, no
    // fallback).
    fn for_env(env: &str) -> Result<Self> {
        let ec = cofhe_keys::envs::lookup(env)?;
        Self::from_env_config(ec).with_context(|| format!("environment {env:?} cannot run"))
    }

    // N (shares) is the baked target partner count; T, the partner write
    // audiences, the reshare source, the public bucket and its layout are all
    // baked; the two partner secret ids are network-wide constants.
    fn from_env_config(ec: &'static EnvConfig) -> Result<Self> {
        // Fail before a single key is generated or read. A placeholder audience would
        // otherwise abort the run mid-write, after earlier partners are written.
        ec.ensure_partners_complete()?;
        // The ceremony writes the manifest at `{prefix}/{zone}`; consumers read
        // `public_object`. Both must name the same object.
        let manifest = object_path(ec.public_prefix, ec.public_zone, OBJ_MANIFEST);
        if ec.public_object != manifest {
            bail!(
                "public_object {:?} is not the manifest path {manifest:?}",
                ec.public_object
            );
        }
        let mode = match &ec.reshare_from {
            None => Mode::Ceremony,
            Some(_) if ec.replace_live_keyset => {
                bail!("replace_live_keyset is set, but a reshare keeps the live keyset")
            }
            Some(src) => Mode::Reshare(src),
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
            replace_live_keyset: ec.replace_live_keyset,
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
        if let Mode::Reshare(src) = self.mode {
            self.validate_reshare(src)?;
        }
        Ok(())
    }

    fn validate_reshare(&self, r: &ReshareSource) -> Result<()> {
        check_threshold(
            "reshare source threshold",
            r.shamir_threshold,
            r.partners.len(),
        )?;
        // An empty audience would fail later as an opaque STS 403, like a target's.
        if r.partners
            .iter()
            .any(|s| s.project_id.is_empty() || s.wip_pool_audience.is_empty())
        {
            bail!("a reshare source partner has an empty project_id or wip_pool_audience");
        }
        check_distinct(r.partners.iter().map(|s| s.project_id)).context("reshare source")?;
        for pin in r.pins {
            if !r.partners.iter().any(|s| s.project_id == pin.project_id) {
                bail!(
                    "a reshare pin names {:?}, which is not a reshare source partner",
                    pin.project_id
                );
            }
            // A pin that names no version would read `latest`, the orphan share it
            // exists to skip.
            if pin.fhe_priv.is_none() && pin.zk_signer.is_none() {
                bail!("the reshare pin for {:?} pins no version", pin.project_id);
            }
        }
        check_distinct(r.pins.iter().map(|p| p.project_id)).context("reshare pins")?;
        for (what, address) in [
            ("decrypt_signer_address", r.decrypt_signer_address),
            ("zk_signer_address", r.zk_signer_address),
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
        let source: BTreeSet<&str> = r.partners.iter().map(|s| s.project_id).collect();
        let target: BTreeSet<&str> = self
            .partners
            .iter()
            .map(|p| p.project_id.as_str())
            .collect();
        if source == target && r.shamir_threshold == self.threshold {
            bail!(
                "the reshare source equals the target set with the same threshold: nothing to do"
            );
        }
        Ok(())
    }
}

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
            bail!("duplicate project_id {id:?}");
        }
    }
    Ok(())
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
        public_bucket = %cfg.public_bucket,
        public_prefix = %cfg.public_prefix,
        zone = cfg.zone,
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

// Ceremony: generate the full network keyset in-enclave (never leaves TDX memory
// unencrypted): FHE keys + decrypt_signer (TN) + zk_signer (ZK/verifier),
// Shamir-split N-of-T across the partners — one share pair per partner, index i →
// partners[i]. Then deliver, then publish the artifacts and the manifest.
#[cfg(not(feature = "mock"))]
async fn run_ceremony(cfg: &Config, run: &Run) -> Result<()> {
    // An image built from the wrong env must not replace a live network key. Only a
    // deliberate key rotation bakes `replace_live_keyset`.
    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    let token = run.metadata.token().await?;
    let live = run
        .gcs
        .exists(&token, &cfg.public_bucket, &manifest_object)
        .await?;
    check_replace_guard(cfg.replace_live_keyset, live)
        .with_context(|| format!("gs://{}/{manifest_object}", cfg.public_bucket))?;

    info!("step 1: generating + splitting network keyset in-enclave");
    let partner_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let (partner_shares, artifacts, public) =
        keygen::generate(&partner_ids, cfg.shares, cfg.threshold)?;

    let order: Vec<usize> = (0..cfg.partners.len()).collect();
    deliver_shares(cfg, run, &order, &partner_shares).await?;

    let token = run.metadata.token().await?;
    // The three FHE artifacts go to SEPARATE objects, named + laid out exactly as
    // cofhe mounts them (keys/versionized/{zone}/…), so a cofhe stack reads this
    // ceremony's keyset directly as files.
    for (name, bytes) in [
        (OBJ_SERVER_KEY, &artifacts.server_key),
        (OBJ_PUBLIC_KEY, &artifacts.compact_public_key),
        (OBJ_CRS, &artifacts.crs),
    ] {
        let object = object_path(&cfg.public_prefix, cfg.zone, name);
        info!(object = %object, bytes = bytes.len(), "publishing public FHE artifact");
        let written = run
            .gcs
            .upload(&token, &cfg.public_bucket, &object, bytes)
            .await?;
        info!(object = %written, "public FHE artifact written");
    }
    publish_manifest(cfg, run, &public).await?;
    info!(
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "keygen ceremony complete"
    );
    Ok(())
}

// Reshare: rebuild the live keyset from the source set, prove it is the key
// behind the live public data, split it again for the target set, deliver, and
// publish a manifest that differs only in the per-share digests. The public
// artifacts stay as they are: their bytes cannot be regenerated, and they do not
// change.
#[cfg(not(feature = "mock"))]
async fn run_reshare(cfg: &Config, r: &ReshareSource, run: &Run) -> Result<()> {
    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    info!(object = %manifest_object, "step 1: reading the live manifest and public artifacts");
    let token = run.metadata.token().await?;
    let live_bytes = run
        .gcs
        .download(&token, &cfg.public_bucket, &manifest_object)
        .await
        .context("read the live manifest (a reshare needs a published keyset)")?;
    let live =
        PublicMaterial::from_canonical_bytes(&live_bytes).context("decode the live manifest")?;
    check_live_anchor(&live, r)?;
    let mut artifacts = keygen::PublicArtifacts::default();
    for (name, slot) in [
        (OBJ_SERVER_KEY, &mut artifacts.server_key),
        (OBJ_PUBLIC_KEY, &mut artifacts.compact_public_key),
        (OBJ_CRS, &mut artifacts.crs),
    ] {
        let object = object_path(&cfg.public_prefix, cfg.zone, name);
        *slot = run
            .gcs
            .download(&token, &cfg.public_bucket, &object)
            .await
            .with_context(|| format!("read public artifact {object}"))?;
    }

    // A source partner that does not federate (for example, a partner that leaves
    // and does not set the read flag) is excluded here. The rebuild below needs
    // only the old threshold of good shares.
    info!(
        sources = r.partners.len(),
        threshold = r.shamir_threshold,
        "step 2: reading the live shares from the source set"
    );
    // One token per source partner reads both secrets; the two ref lists share
    // the partner order.
    let fhe_refs = reader::partner_refs_for(r.partners, KEYGEN_READER, &cfg.write_secret_fhe_priv);
    let zk_refs = reader::partner_refs_for(r.partners, KEYGEN_READER, &cfg.write_secret_zk_signer);
    let mut tokens = Vec::with_capacity(fhe_refs.len());
    for (i, p) in fhe_refs.iter().enumerate() {
        match federate(run, &p.wip_audience).await {
            Ok(t) => tokens.push((i, t)),
            Err(e) => {
                warn!(partner = %p.project_id, error = %format!("{e:#}"), "source partner did not federate; excluding")
            }
        }
    }
    // The consumer reader rebuilds each secret; it logs each source share version
    // it read (pin these to rerun after a failed write).
    let ctx = ReaderContext {
        sm: &run.sm,
        gcs: &run.gcs,
        gcs_token: &token,
        public_bucket: &cfg.public_bucket,
        public_object: &manifest_object,
    };
    let fhe_priv = reader::read_fhe_priv_at(
        &ctx,
        &source_access(&fhe_refs, &tokens),
        r.shamir_threshold,
        &|p| r.version_of(p, |pin| pin.fhe_priv),
    )
    .await?;
    let zk_signer = reader::read_zk_signer_at(
        &ctx,
        &source_access(&zk_refs, &tokens),
        r.shamir_threshold,
        &|p| r.version_of(p, |pin| pin.zk_signer),
    )
    .await?;

    // Order matters from here: the key is checked before any write, `.prev` is
    // copied before the first share write, and the manifest is published last.
    info!("step 3: checking the rebuilt key against the live public data");
    keygen::verify_against_public(&fhe_priv, &zk_signer, &live, &artifacts)?;

    info!(
        shares = cfg.shares,
        threshold = cfg.threshold,
        "step 4: splitting the live keyset for the target set"
    );
    let target_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let split = keygen::split_for_partners(
        &fhe_priv,
        &zk_signer,
        &target_ids,
        cfg.shares,
        cfg.threshold,
    )?;

    // Keep a copy of the manifest this run verified, before the first write, for the
    // emergency rollback. The name carries the manifest's own digest, so a rerun
    // rewrites the same copy and no later run overwrites the copy of an older one.
    let prev_object = format!(
        "{manifest_object}.prev.{}",
        hex::encode(sha256(&live_bytes))
    );
    info!(object = %prev_object, "keeping a copy of the live manifest");
    let token = run.metadata.token().await?;
    run.gcs
        .upload(&token, &cfg.public_bucket, &prev_object, &live_bytes)
        .await?;

    let order = write_order(&cfg.partners, r.partners);
    deliver_shares(cfg, run, &order, &split.partner_shares).await?;

    let public =
        live.with_share_digests(split.fhe_priv_share_digests, split.zk_signer_share_digests);
    publish_manifest(cfg, run, &public).await?;
    info!(
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "keygen reshare complete: same keyset, new shares"
    );
    Ok(())
}

// The federated source partners, paired with their tokens, for one secret.
#[cfg(not(feature = "mock"))]
fn source_access<'a>(
    refs: &'a [PartnerRef],
    tokens: &'a [(usize, String)],
) -> Vec<PartnerAccess<'a>> {
    tokens
        .iter()
        .map(|(i, sm_token)| PartnerAccess {
            partner: &refs[*i],
            sm_token,
        })
        .collect()
}

// The manifest in the bucket must describe the keyset and the share set the env
// was baked for. All later checks are relative to this manifest. Without the
// signer anchor, a bucket writer could restore an older keyset's manifest and have
// this run split that older key. The share-set check stops a rerun after a
// completed publish that changed the partner set.
#[cfg(not(feature = "mock"))]
fn check_live_anchor(live: &PublicMaterial, r: &ReshareSource) -> Result<()> {
    let (decrypt, zk) = (r.decrypt_signer_address, r.zk_signer_address);
    if live.decrypt_signer_address != decrypt || live.zk_signer_address != zk {
        bail!(
            "the live manifest names signers ({}, {}), but the baked reshare source names ({decrypt}, {zk}): this is not the live keyset",
            live.decrypt_signer_address,
            live.zk_signer_address
        );
    }
    let source: BTreeSet<&str> = r.partners.iter().map(|p| p.project_id).collect();
    for digests in [&live.fhe_priv_share_digests, &live.zk_signer_share_digests] {
        let listed: BTreeSet<&str> = digests.iter().map(|(id, _)| id.as_str()).collect();
        if listed != source {
            bail!(
                "the live manifest lists shares for {listed:?}, but the baked reshare source is {source:?}: \
                 this reshare already ran, or the env is wrong"
            );
        }
    }
    Ok(())
}

// A ceremony writes a new keyset. Over a live one that is a key rotation, which
// the env must bake on purpose.
#[cfg(not(feature = "mock"))]
fn check_replace_guard(replace_live_keyset: bool, live_manifest_exists: bool) -> Result<()> {
    if live_manifest_exists && !replace_live_keyset {
        bail!(
            "a live manifest exists: this ceremony would replace the live keyset. A key \
             rotation bakes replace_live_keyset: true in the env"
        );
    }
    Ok(())
}

// Attest for one audience and exchange the token at STS. Each partner gets its
// OWN attestation and federated token; a token is never reused across partners.
#[cfg(not(feature = "mock"))]
async fn federate(run: &Run, audience: &str) -> Result<String> {
    let jwt = run.attest.fetch_token(audience).await?;
    run.auth.exchange(audience, &jwt).await
}

// Write order for a reshare: partners that hold no live share first, partners in
// the source set last. A stop mid-write then leaves the most source partners with
// an untouched `latest`.
#[cfg(not(feature = "mock"))]
fn write_order(targets: &[PartnerCfg], sources: &[EnvPartner]) -> Vec<usize> {
    let is_source = |p: &PartnerCfg| sources.iter().any(|s| s.project_id == p.project_id);
    let (staying, new): (Vec<usize>, Vec<usize>) =
        (0..targets.len()).partition(|&i| is_source(&targets[i]));
    new.into_iter().chain(staying).collect()
}

// Deliver the SECRET shares to every target partner, in `order`. Each partner gets
// its share of each per-audience secret, written to its OWN Secret Manager secret
// with its own provenance token (eat_nonce = SHA-256(share)), so the partner can
// grant each consumer least-privilege read via IAM: TeeCryptor reads fhe-priv
// (FHE priv + decrypt signer); the ZK verifier reads zk-signer. See
// CONSUMER-INTEGRATION.md.
#[cfg(not(feature = "mock"))]
async fn deliver_shares(
    cfg: &Config,
    run: &Run,
    order: &[usize],
    partner_shares: &[keygen::PartnerShares],
) -> Result<()> {
    let total = order.len();
    for (step, &i) in order.iter().enumerate() {
        let (partner, shares) = (&cfg.partners[i], &partner_shares[i]);
        info!(partner = %partner.project_id, step = %format!("{}/{total}", step + 1), "federating with partner for the write");
        let federated = federate(run, &partner.wip_audience).await?;

        info!(partner = %partner.project_id, secret = %cfg.write_secret_fhe_priv, "writing FHE-priv share (priv + decrypt signer)");
        write_secret(
            &run.attest,
            &run.sm,
            &federated,
            &partner.project_id,
            &cfg.write_secret_fhe_priv,
            shares.fhe_priv_share.clone(),
        )
        .await?;

        info!(partner = %partner.project_id, secret = %cfg.write_secret_zk_signer, "writing ZK-signer share");
        write_secret(
            &run.attest,
            &run.sm,
            &federated,
            &partner.project_id,
            &cfg.write_secret_zk_signer,
            shares.zk_signer_share.clone(),
        )
        .await?;
    }
    Ok(())
}

// Publish the manifest and its provenance sidecar. Consumers do not verify the
// sidecar; it stays for wire-format compatibility (see AGENTS.md).
#[cfg(not(feature = "mock"))]
async fn publish_manifest(cfg: &Config, run: &Run, public: &PublicMaterial) -> Result<()> {
    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    info!(object = %manifest_object, "publishing public-material manifest");
    let token = run.metadata.token().await?;
    let written = run
        .gcs
        .upload(
            &token,
            &cfg.public_bucket,
            &manifest_object,
            &public.to_canonical_bytes(),
        )
        .await?;
    info!(object = %written, "public-material manifest written to our GCS bucket");

    let public_hash = hex::encode(public.hash());
    info!(public_hash = %public_hash, "minting public-material provenance (eat_nonce = SHA-256(manifest))");
    let public_provenance_jwt = run
        .attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[public_hash])
        .await?;
    let prov_object = format!("{manifest_object}.provenance");
    let written = run
        .gcs
        .upload(
            &token,
            &cfg.public_bucket,
            &prov_object,
            public_provenance_jwt.as_bytes(),
        )
        .await?;
    info!(object = %written, "public-material provenance written to our GCS bucket");
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
    use cofhe_keys::envs::{EnvPartner, SourcePin};
    use std::num::NonZeroU64;

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
            replace_live_keyset: false,
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
    // The mainnet partner set is complete, so it builds a real 3-of-6 ceremony whose
    // write audiences point at the keygen pool+provider, not the reader pool.
    fn builds_mainnet_from_baked_env() {
        let cfg = Config::for_env("mainnet").expect("the mainnet partner set is complete");
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
                pins: &[],
            }),
            replace_live_keyset: false,
        }))
    }

    // 2-of-3 on p1..p3 → 2-of-3 on p1, p2, p4: replace p3 with p4.
    fn replace_env() -> &'static EnvConfig {
        env(set(&[P1, P2, P4]), 2, Some((set(&[P1, P2, P3]), 2)))
    }

    #[test]
    fn reshare_builds_source_and_target_sets() {
        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(r) = &cfg.mode else {
            panic!("expected reshare mode")
        };
        let ids: Vec<&str> = r.partners.iter().map(|s| s.project_id).collect();
        assert_eq!(ids, ["p-1", "p-2", "p-3"]);
        assert_eq!(r.shamir_threshold, 2);
        assert_eq!(
            reader::partner_refs_for(r.partners, KEYGEN_READER, "s")[2].wip_audience,
            "//iam.googleapis.com/projects/333333333333/locations/global/workloadIdentityPools/cofhe-tee-reader-pool/providers/keygen-reader"
        );
        let targets: Vec<&str> = cfg.partners.iter().map(|p| p.project_id.as_str()).collect();
        assert_eq!(targets, ["p-1", "p-2", "p-4"]);
        assert!(r.pins.is_empty());
    }

    // An env without a reshare source builds a ceremony image.
    #[test]
    fn mode_comes_from_the_baked_env() {
        let plain = env(set(&[P1, P2, P3]), 2, None);
        assert!(matches!(
            Config::from_env_config(plain).unwrap().mode,
            Mode::Ceremony
        ));
    }

    // A reshare keeps the live keyset, so the replace flag on a reshare env is a
    // baked mistake.
    #[test]
    fn replace_live_keyset_is_refused_on_a_reshare() {
        let src = replace_env().reshare_from.as_ref().unwrap();
        let e = Box::leak(Box::new(EnvConfig {
            replace_live_keyset: true,
            reshare_from: Some(ReshareSource { ..*src }),
            ..*replace_env()
        }));
        assert!(Config::from_env_config(e).is_err());
    }

    fn with_pins(pins: &'static [SourcePin]) -> &'static EnvConfig {
        let src = replace_env().reshare_from.as_ref().unwrap();
        Box::leak(Box::new(EnvConfig {
            reshare_from: Some(ReshareSource { pins, ..*src }),
            ..*replace_env()
        }))
    }

    // A pin applies to the one partner and secret it names; everything else reads
    // `latest`.
    #[test]
    fn reshare_pins_default_to_latest() {
        let e = with_pins(Box::leak(Box::new([SourcePin {
            project_id: "p-1",
            fhe_priv: NonZeroU64::new(3),
            zk_signer: None,
        }])));
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(r) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let v = |id, pick: fn(&SourcePin) -> Option<NonZeroU64>| r.version_of(id, pick).to_string();
        assert_eq!(v("p-1", |p| p.fhe_priv), "3");
        assert_eq!(v("p-1", |p| p.zk_signer), "latest");
        assert_eq!(v("p-2", |p| p.fhe_priv), "latest");
    }

    #[test]
    fn bad_pins_fail_closed() {
        let pin = |id: &'static str, fhe: u64| SourcePin {
            project_id: id,
            fhe_priv: NonZeroU64::new(fhe),
            zk_signer: None,
        };
        for pins in [
            vec![pin("p-4", 3)],
            vec![pin("nobody", 3)],
            vec![pin("p-1", 3), pin("p-1", 4)],
            vec![pin("p-1", 0)],
        ] {
            let pins: &'static [SourcePin] = Box::leak(pins.into_boxed_slice());
            assert!(Config::from_env_config(with_pins(pins)).is_err());
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
                        pins: &[],
                    }),
                    ..*env(set(&[P1, P2, P4]), 2, None)
                }));
                assert!(
                    Config::from_env_config(e).is_err(),
                    "anchor ({decrypt:?}, {zk:?}) must fail closed"
                );
            }
        }
    }

    #[test]
    fn reshare_rejects_a_no_op() {
        let same = env(set(&[P1, P2, P3]), 2, Some((set(&[P3, P2, P1]), 2)));
        assert!(Config::from_env_config(same).is_err());
        // Same set with a new T is a real change.
        let new_t = env(set(&[P1, P2, P3]), 3, Some((set(&[P1, P2, P3]), 2)));
        assert!(Config::from_env_config(new_t).is_ok());
    }

    #[test]
    fn reshare_validates_the_source_set() {
        let empty = env(set(&[P1, P2]), 2, Some((set(&[]), 2)));
        assert!(Config::from_env_config(empty).is_err());
        let dup = env(set(&[P1, P2]), 2, Some((set(&[P1, P1, P3]), 2)));
        assert!(Config::from_env_config(dup).is_err());
        let t_high = env(set(&[P1, P2]), 2, Some((set(&[P1, P3]), 3)));
        assert!(Config::from_env_config(t_high).is_err());
        let t_low = env(set(&[P1, P2]), 2, Some((set(&[P1, P3]), 1)));
        assert!(Config::from_env_config(t_low).is_err());
        let src: &'static [EnvPartner] = Box::leak(Box::new([
            env_partner(P1.0, P1.1),
            EnvPartner {
                project_id: "p-9",
                wip_pool_audience: "",
                keygen_write_audience: "",
            },
        ]));
        let empty_audience = env(set(&[P1, P2]), 2, Some((src, 2)));
        assert!(Config::from_env_config(empty_audience).is_err());
    }

    // The run writes the manifest at `{prefix}/{zone}`, and consumers read
    // `public_object`. An env where they differ is refused, so the replace guard
    // always checks the object consumers read.
    #[test]
    fn public_object_must_be_the_manifest_path() {
        let e = Box::leak(Box::new(EnvConfig {
            public_object: "p/1/public-material",
            reshare_from: None,
            ..*env(set(&[P1, P2, P3]), 2, None)
        }));
        assert!(Config::from_env_config(e).is_err());
    }

    // A mocked cloud for one run: GCS serves the live manifest and the three
    // artifacts, Secret Manager serves each source share, STS and the metadata
    // server hand out tokens, and a Unix socket plays the attestation launcher.
    // Each test mounts its own write mocks.
    struct World {
        server: wiremock::MockServer,
        run: Run,
        _dir: tempfile::TempDir,
    }

    async fn reshare_world(
        live: &PublicMaterial,
        artifacts: [Vec<u8>; 3],
        ids: &[String],
        shares: &[keygen::PartnerShares],
    ) -> World {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let [server_key, public_key, crs] = artifacts;
        for (name, body) in [
            (OBJ_MANIFEST, live.to_canonical_bytes()),
            (OBJ_SERVER_KEY, server_key),
            (OBJ_PUBLIC_KEY, public_key),
            (OBJ_CRS, crs),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/storage/v1/b/b/o/p%2F0%2F{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(&server)
                .await;
        }
        for (id, share) in ids.iter().zip(shares) {
            for (secret, bytes) in [
                (WRITE_SECRET_FHE_PRIV, &share.fhe_priv_share),
                (WRITE_SECRET_ZK_SIGNER, &share.zk_signer_share),
            ] {
                let envelope = SecretEnvelope {
                    payload: bytes.clone(),
                    provenance_jwt: String::new(),
                };
                let data =
                    base64::engine::general_purpose::STANDARD.encode(envelope.to_canonical_bytes());
                Mock::given(method("GET"))
                    .and(path(format!(
                        "/v1/projects/{id}/secrets/{secret}/versions/latest:access"
                    )))
                    .respond_with(ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "name": "v", "payload": { "data": data } }),
                    ))
                    .mount(&server)
                    .await;
            }
        }
        Mock::given(method("POST"))
            .and(path("/sts"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "federated" })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "sa" })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = "attested.jwt.sig";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        let run = Run {
            attest: AttestationClient::new(&sock),
            auth: GcpAuth::new(format!("{}/sts", server.uri())),
            sm: SecretManager::new(server.uri()),
            gcs: GcsClient::new(server.uri()),
            metadata: MetadataClient::new(server.uri()),
        };
        World {
            server,
            run,
            _dir: dir,
        }
    }

    // Writes are refused: any Secret Manager write or GCS upload fails the test.
    async fn forbid_writes(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        for write in [":addVersion$", "^/upload/"] {
            Mock::given(method("POST"))
                .and(path_regex(write))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(server)
                .await;
        }
    }

    // The safety of a reshare rests on its order: the key is checked before any
    // write. Here the shares rebuild and the anchor holds, but a published artifact
    // does not match the manifest. The run must stop with no Secret Manager write
    // and no GCS upload, so not even `.prev` is written. One source partner also
    // fails to federate: the run drops it and still rebuilds from the other two.
    #[tokio::test]
    async fn reshare_writes_nothing_when_the_key_check_fails() {
        use cofhe_keys::serialization::{FhePrivShare, ZkSignerShare};
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let fhe = FhePrivShare {
            client_key: vec![1; 40],
            decrypt_signer_priv: vec![2; 32],
        };
        let zk = ZkSignerShare {
            zk_signer_priv: vec![3; 32],
        };
        let ids: Vec<String> = ["p-1", "p-2", "p-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let split = keygen::split_for_partners(&fhe, &zk, &ids, 3, 2).unwrap();
        let live = PublicMaterial {
            server_key_digest: sha256(b"server key"),
            compact_public_key_digest: sha256(b"public key"),
            crs_digest: sha256(b"not the published crs"),
            decrypt_signer_address: LIVE_DECRYPT.to_string(),
            zk_signer_address: LIVE_ZK.to_string(),
            fhe_priv_digest: fhe.hash(),
            zk_signer_digest: zk.hash(),
            fhe_priv_share_digests: split.fhe_priv_share_digests,
            zk_signer_share_digests: split.zk_signer_share_digests,
        };
        let artifacts = [
            b"server key".to_vec(),
            b"public key".to_vec(),
            b"crs".to_vec(),
        ];
        let w = reshare_world(&live, artifacts, &ids, &split.partner_shares).await;
        // p-3's audience carries its project number: its STS exchange fails.
        Mock::given(method("POST"))
            .and(path("/sts"))
            .and(body_string_contains("333333333333"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(1)
            .mount(&w.server)
            .await;
        forbid_writes(&w.server).await;

        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let err = run_reshare(&cfg, src, &w.run).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("crs digest mismatch"),
            "{err:#}"
        );
        w.server.verify().await;
    }

    // The ceremony's replace guard is wired before keygen: with a live manifest in
    // the bucket, the run stops and writes nothing.
    #[tokio::test]
    async fn ceremony_stops_before_keygen_over_a_live_manifest() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let w = reshare_world(
            &PublicMaterial {
                server_key_digest: [0; 32],
                compact_public_key_digest: [0; 32],
                crs_digest: [0; 32],
                decrypt_signer_address: String::new(),
                zk_signer_address: String::new(),
                fhe_priv_digest: [0; 32],
                zk_signer_digest: [0; 32],
                fhe_priv_share_digests: vec![],
                zk_signer_share_digests: vec![],
            },
            Default::default(),
            &[],
            &[],
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/b/o"))
            .and(query_param("prefix", "p/0/public-material"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "items": [{ "name": "p/0/public-material" }] }),
                ),
            )
            .mount(&w.server)
            .await;
        forbid_writes(&w.server).await;

        let cfg = Config::from_env_config(env(set(&[P1, P2, P3]), 2, None)).unwrap();
        let err = run_ceremony(&cfg, &w.run).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("live manifest exists"),
            "{err:#}"
        );
        w.server.verify().await;
    }

    // The whole reshare on a real keyset: `.prev` first, new partners before
    // source partners, the manifest last with only the share digests changed, and
    // the new shares rebuild the same secrets. Slow, so CI skips it; run it with
    // `cargo test -p keygen -- --ignored`.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn reshare_writes_in_order_and_keeps_the_keyset() {
        use base64::Engine as _;
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let ids: Vec<String> = ["p-1", "p-2", "p-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (shares, artifacts, live) = keygen::generate(&ids, 3, 2).unwrap();
        let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
        let e = Box::leak(Box::new(EnvConfig {
            reshare_from: Some(ReshareSource {
                partners: set(&[P1, P2, P3]),
                shamir_threshold: 2,
                decrypt_signer_address: leak(&live.decrypt_signer_address),
                zk_signer_address: leak(&live.zk_signer_address),
                pins: &[],
            }),
            ..*env(set(&[P1, P2, P4]), 2, None)
        }));
        let w = reshare_world(
            &live,
            [
                artifacts.server_key.clone(),
                artifacts.compact_public_key.clone(),
                artifacts.crs.clone(),
            ],
            &ids,
            &shares,
        )
        .await;
        Mock::given(method("POST"))
            .and(path_regex(":addVersion$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "name": "projects/1/secrets/s/versions/2" }),
                ),
            )
            .mount(&w.server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("^/upload/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "name": "o", "generation": "1" })),
            )
            .mount(&w.server)
            .await;

        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        run_reshare(&cfg, src, &w.run).await.unwrap();

        let requests = w.server.received_requests().await.unwrap();
        let writes: Vec<(String, &Vec<u8>)> = requests
            .iter()
            .filter(|r| r.method.as_str() == "POST" && r.url.path() != "/sts")
            .map(|r| {
                let label = match r.url.query_pairs().find(|(k, _)| k == "name") {
                    Some((_, name)) => format!("upload {name}"),
                    None => r.url.path().trim_start_matches("/v1/projects/").to_string(),
                };
                (label, &r.body)
            })
            .collect();
        let prev = format!(
            "upload p/0/public-material.prev.{}",
            hex::encode(sha256(&live.to_canonical_bytes()))
        );
        let labels: Vec<&str> = writes.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            [
                prev.as_str(),
                "p-4/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-4/secrets/cofhe-tee-zk-signer:addVersion",
                "p-1/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-1/secrets/cofhe-tee-zk-signer:addVersion",
                "p-2/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-2/secrets/cofhe-tee-zk-signer:addVersion",
                "upload p/0/public-material",
                "upload p/0/public-material.provenance",
            ]
        );
        assert_eq!(writes[0].1, &live.to_canonical_bytes());

        let published = PublicMaterial::from_canonical_bytes(writes[7].1).unwrap();
        let ids_of =
            |d: &[(String, [u8; 32])]| d.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        assert_eq!(
            ids_of(&published.fhe_priv_share_digests),
            ["p-1", "p-2", "p-4"]
        );
        assert_eq!(
            PublicMaterial {
                fhe_priv_share_digests: live.fhe_priv_share_digests.clone(),
                zk_signer_share_digests: live.zk_signer_share_digests.clone(),
                ..published.clone()
            },
            live
        );

        // Any two new shares rebuild the live secrets.
        let payload = |body: &Vec<u8>| -> Vec<u8> {
            let json: serde_json::Value = serde_json::from_slice(body).unwrap();
            let data = json["payload"]["data"].as_str().unwrap();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap();
            SecretEnvelope::from_canonical_bytes(&raw).unwrap().payload
        };
        for (first, digest) in [(1, live.fhe_priv_digest), (2, live.zk_signer_digest)] {
            let pair = [payload(writes[first].1), payload(writes[first + 2].1)];
            let secret = cofhe_keys::shamir::reconstruct(&pair, 2).unwrap();
            assert_eq!(sha256(&secret), digest);
        }
    }

    // A ceremony over a live keyset runs only when the env bakes the replace flag.
    #[test]
    fn ceremony_replaces_a_live_keyset_only_when_baked() {
        check_replace_guard(false, false).unwrap();
        check_replace_guard(true, true).unwrap();
        check_replace_guard(true, false).unwrap();
        assert!(check_replace_guard(false, true).is_err());
    }

    // A stop mid-write must leave as many source partners as possible with an
    // untouched `latest`, so source partners are written last.
    #[test]
    fn write_order_puts_source_partners_last() {
        let targets = vec![
            partner("p-1"),
            partner("p-4"),
            partner("p-2"),
            partner("p-5"),
        ];
        let sources = set(&[P1, P2, P3]);
        assert_eq!(write_order(&targets, sources), vec![1, 3, 0, 2]);
    }

    // The live manifest must name the baked live signers. Anything else is another
    // keyset, for example an older one restored into the bucket.
    #[test]
    fn reshare_refuses_a_manifest_of_another_keyset() {
        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(r) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let shares = |ids: &[&str]| -> Vec<(String, [u8; 32])> {
            ids.iter().map(|id| (id.to_string(), [0; 32])).collect()
        };
        let manifest = |decrypt: &str, zk: &str| PublicMaterial {
            server_key_digest: [0; 32],
            compact_public_key_digest: [0; 32],
            crs_digest: [0; 32],
            decrypt_signer_address: decrypt.to_string(),
            zk_signer_address: zk.to_string(),
            fhe_priv_digest: [0; 32],
            zk_signer_digest: [0; 32],
            fhe_priv_share_digests: shares(&["p-1", "p-2", "p-3"]),
            zk_signer_share_digests: shares(&["p-1", "p-2", "p-3"]),
        };
        check_live_anchor(&manifest(LIVE_DECRYPT, LIVE_ZK), r).unwrap();
        assert!(check_live_anchor(&manifest(LIVE_ZK, LIVE_ZK), r).is_err());
        assert!(check_live_anchor(&manifest(LIVE_DECRYPT, LIVE_DECRYPT), r).is_err());
        // The manifest stores what the keygen derived: lowercase. Compare exactly.
        let upper = LIVE_DECRYPT.replace("0x", "0X");
        assert!(check_live_anchor(&manifest(&upper, LIVE_ZK), r).is_err());
        // After a completed publish the manifest lists the target set: a rerun stops.
        let mut done = manifest(LIVE_DECRYPT, LIVE_ZK);
        done.fhe_priv_share_digests = shares(&["p-1", "p-2", "p-4"]);
        done.zk_signer_share_digests = shares(&["p-1", "p-2", "p-4"]);
        assert!(check_live_anchor(&done, r).is_err());
        done.fhe_priv_share_digests = shares(&["p-1", "p-2", "p-3"]);
        assert!(check_live_anchor(&done, r).is_err());
    }

    // The CI gate for baked config: every baked env with a complete partner set must
    // build. Each env runs exactly one mode by construction, so a bad reshare source
    // or pin fails CI and never reaches a release. A declared but unfilled partner
    // slot fails on purpose.
    #[test]
    fn every_baked_env_validates() {
        for name in cofhe_keys::envs::env_names() {
            let env = cofhe_keys::envs::lookup(name).unwrap();
            let cfg = Config::for_env(name);
            assert_eq!(
                cfg.is_ok(),
                env.ensure_partners_complete().is_ok(),
                "env {name:?}: {:?}",
                cfg.err().map(|e| format!("{e:#}"))
            );
        }
    }
}
