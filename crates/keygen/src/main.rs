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
use cofhe_keys::secrets::SecretVersion;
#[cfg(not(feature = "mock"))]
use cofhe_keys::serialization::PublicMaterial;
#[cfg(not(feature = "mock"))]
use cofhe_keys::serialization::{sha256, SecretEnvelope};
#[cfg(not(feature = "mock"))]
use cofhe_keys::{gcs::GcsClient, keygen, secrets::SecretManager};
#[cfg(not(feature = "mock"))]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "mock"))]
use std::num::NonZeroU64;
#[cfg(not(feature = "mock"))]
use tracing::warn;
#[cfg(not(feature = "mock"))]
use zeroize::{Zeroize, Zeroizing};

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
// A partner creates it only for a reshare it approves (`grant_reshare_read`), so
// the keygen image can read shares only during that window.
#[cfg(not(feature = "mock"))]
const KEYGEN_READER: &str = "keygen";

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
impl ReshareCfg {
    fn version_of(&self, project_id: &str, secret: Secret) -> SecretVersion {
        self.versions
            .get(&(project_id.to_string(), secret))
            .map_or(SecretVersion::Latest, |n| SecretVersion::Number(*n))
    }
}

#[cfg(not(feature = "mock"))]
enum Mode {
    Ceremony,
    Reshare(ReshareCfg),
}

#[cfg(not(feature = "mock"))]
impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::Ceremony => MODE_CEREMONY,
            Mode::Reshare(_) => MODE_RESHARE,
        }
    }
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

// Production boot: one-shot, then exit. A ceremony generates a new keyset; a
// reshare splits the live keyset again for a new partner set. Both write every
// partner's shares FIRST and publish the manifest LAST, so the manifest's presence
// is a reliable signal that all shares were delivered. Any attestation / STS / SM
// failure crashes the run (via `?`) before the manifest changes.
#[cfg(not(feature = "mock"))]
async fn real_boot() -> Result<()> {
    let cfg = Config::from_env()?;
    info!(
        mode = cfg.mode.name(),
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
    match &cfg.mode {
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
    metadata: MetadataClient,
}

#[cfg(not(feature = "mock"))]
impl Run {
    // A fresh GCS bearer for each phase: a run can outlast one token.
    async fn gcs_token(&self) -> Result<String> {
        self.metadata.token().await
    }
}

// Ceremony: generate the full network keyset in-enclave (never leaves TDX memory
// unencrypted): FHE keys + decrypt_signer (TN) + zk_signer (ZK/verifier),
// Shamir-split N-of-T across the partners — one share pair per partner, index i →
// partners[i]. Then deliver, then publish the artifacts and the manifest.
#[cfg(not(feature = "mock"))]
async fn run_ceremony(cfg: &Config, run: &Run) -> Result<()> {
    info!("step 1: generating + splitting network keyset in-enclave");
    let partner_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let (partner_shares, artifacts, public) =
        keygen::generate(&partner_ids, cfg.shares, cfg.threshold)?;
    let partner_shares = Zeroizing::new(partner_shares);

    let order: Vec<usize> = (0..cfg.partners.len()).collect();
    deliver_shares(cfg, run, &order, &partner_shares).await?;

    let token = run.gcs_token().await?;
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
    publish_manifest(cfg, run, &public, None).await?;
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
async fn run_reshare(cfg: &Config, r: &ReshareCfg, run: &Run) -> Result<()> {
    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    info!(object = %manifest_object, "step 1: reading the live manifest and public artifacts");
    let token = run.gcs_token().await?;
    let (live_bytes, live_generation) = run
        .gcs
        .download_generation(&token, &cfg.public_bucket, &manifest_object)
        .await
        .context("read the live manifest (a reshare needs a published keyset)")?;
    let live =
        PublicMaterial::from_canonical_bytes(&live_bytes).context("decode the live manifest")?;
    check_live_anchor(&live, r)?;
    let mut artifacts = keygen::PublicArtifacts {
        server_key: Vec::new(),
        compact_public_key: Vec::new(),
        crs: Vec::new(),
    };
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
        sources = r.src.partners.len(),
        threshold = r.src.shamir_threshold,
        "step 2: reading the live shares from the source set"
    );
    // One token per source partner reads both secrets; the two ref lists share
    // the partner order.
    let fhe_refs =
        reader::partner_refs_for(r.src.partners, KEYGEN_READER, &cfg.write_secret_fhe_priv);
    let zk_refs =
        reader::partner_refs_for(r.src.partners, KEYGEN_READER, &cfg.write_secret_zk_signer);
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
    let fhe_priv = Zeroizing::new(
        reader::read_fhe_priv_at(
            &ctx,
            &source_access(&fhe_refs, &tokens),
            r.src.shamir_threshold,
            &|p| r.version_of(p, Secret::FhePriv),
        )
        .await?,
    );
    let zk_signer = Zeroizing::new(
        reader::read_zk_signer_at(
            &ctx,
            &source_access(&zk_refs, &tokens),
            r.src.shamir_threshold,
            &|p| r.version_of(p, Secret::ZkSigner),
        )
        .await?,
    );

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
    // Our copies of the full key are not needed past this point; wipe them before
    // the network writes.
    drop((fhe_priv, zk_signer));
    let partner_shares = Zeroizing::new(split.partner_shares);

    // Keep a copy of the manifest this run verified, before the first write, for the
    // emergency rollback. The name carries the generation it copies, so no later run
    // can overwrite the copy of an older manifest.
    let prev_object = format!("{manifest_object}.prev.{live_generation}");
    info!(object = %prev_object, "keeping a copy of the live manifest");
    let token = run.gcs_token().await?;
    run.gcs
        .upload(&token, &cfg.public_bucket, &prev_object, &live_bytes)
        .await?;

    let order = write_order(&cfg.partners, r.src.partners);
    deliver_shares(cfg, run, &order, &partner_shares).await?;

    let public =
        live.with_share_digests(split.fhe_priv_share_digests, split.zk_signer_share_digests);
    publish_manifest(cfg, run, &public, Some(live_generation)).await?;
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
fn check_live_anchor(live: &PublicMaterial, r: &ReshareCfg) -> Result<()> {
    let (decrypt, zk) = (r.src.decrypt_signer_address, r.src.zk_signer_address);
    if live.decrypt_signer_address != decrypt || live.zk_signer_address != zk {
        bail!(
            "the live manifest names signers ({}, {}), but the baked reshare source names ({decrypt}, {zk}): this is not the live keyset",
            live.decrypt_signer_address,
            live.zk_signer_address
        );
    }
    let source: BTreeSet<&str> = r.src.partners.iter().map(|p| p.project_id).collect();
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
// sidecar; it stays for wire-format compatibility (see AGENTS.md). A reshare
// passes the generation it read, so the publish fails if another run replaced the
// manifest in the meantime.
#[cfg(not(feature = "mock"))]
async fn publish_manifest(
    cfg: &Config,
    run: &Run,
    public: &PublicMaterial,
    if_generation: Option<u64>,
) -> Result<()> {
    let manifest_object = object_path(&cfg.public_prefix, cfg.zone, OBJ_MANIFEST);
    info!(object = %manifest_object, "publishing public-material manifest");
    let bytes = public.to_canonical_bytes();
    let token = run.gcs_token().await?;
    let written = match if_generation {
        None => {
            run.gcs
                .upload(&token, &cfg.public_bucket, &manifest_object, &bytes)
                .await?
        }
        Some(g) => run
            .gcs
            .upload_if_generation(&token, &cfg.public_bucket, &manifest_object, &bytes, g)
            .await
            .context("the live manifest changed after this run read it")?,
    };
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
    let payload = Zeroizing::new(payload);
    let payload_hash = hex::encode(sha256(&payload));
    info!(secret = %secret, payload_hash = %payload_hash, "minting provenance (eat_nonce = SHA-256(payload))");
    let provenance_jwt = attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[payload_hash])
        .await?;
    let mut envelope = SecretEnvelope {
        payload: payload.to_vec(),
        provenance_jwt,
    };
    let bytes = Zeroizing::new(envelope.to_canonical_bytes());
    envelope.payload.zeroize();
    let version = sm
        .add_version(federated, project_id, secret, &bytes)
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
        assert_eq!(
            reader::partner_refs_for(r.src.partners, KEYGEN_READER, "s")[2].wip_audience,
            "//iam.googleapis.com/projects/333333333333/locations/global/workloadIdentityPools/cofhe-tee-reader-pool/providers/keygen-reader"
        );
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
        // A ceremony-shaped call with no sources keeps the baked order.
        assert_eq!(write_order(&targets, &[]), vec![0, 1, 2, 3]);
    }

    // The live manifest must name the baked live signers. Anything else is another
    // keyset, for example an older one restored into the bucket.
    #[test]
    fn reshare_refuses_a_manifest_of_another_keyset() {
        let cfg = Config::from_env_config(replace_env(), "reshare", "").unwrap();
        let Mode::Reshare(r) = &cfg.mode else {
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
