//! Baked environment source — the compile-time key SOURCE shared by BOTH sides of
//! the crate: the producer keygen (write side, `writer` feature) and the consumer
//! reader (read side, `reader` feature). It is deliberately UNCONDITIONAL (no
//! feature gate) so the write-only enclave image — built `--no-default-features`
//! with just `writer` — can still resolve its env via [`lookup`] without pulling in
//! the reader's async fetch stack. The `reader` module re-exports these items, so
//! existing `cofhe_keys::reader::{lookup, env_names, EnvConfig, EnvPartner}` paths
//! keep working for read-side consumers unchanged.

use anyhow::{anyhow, Result};
use std::num::NonZeroU64;

mod mainnet;
mod staging;
mod testnet;

use mainnet::MAINNET;
use staging::STAGING;
use testnet::TESTNET;

/// The reader's key SOURCE is baked at compile time — never operator-settable.
/// One entry per blessed env. Onboarding an env, and changing a partner SET within
/// one, are both rebuilds by design; a same-set reshare changes only the versions.
#[derive(Clone, Copy)]
pub struct EnvPartner {
    pub project_id: &'static str,
    /// Pool-level audience at this partner:
    /// `//iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/cofhe-tee-reader-pool`
    /// The consumer-specific provider suffix is derived in [`crate::reader::partner_refs`]
    /// (fixed ids: `providers/<consumer>-reader`) — audiences are PER-CONSUMER.
    pub wip_pool_audience: &'static str,
    /// Full keygen WRITE audience at this partner (producer side only):
    /// `//iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider`.
    /// A DIFFERENT pool + provider from the reader audience above (same partner
    /// project number). Baked verbatim rather than derived so the keygen ceremony
    /// writes to exactly the partner set the consumers read from — the two cannot
    /// drift. Consumers never touch this (read-only).
    pub keygen_write_audience: &'static str,
}

/// One blessed environment's key source: the partner set holding the Shamir
/// shares, the share version, the public-material location, and the
/// reconstruction threshold. Shared by the consumer readers (which read
/// [`EnvConfig::manifest_object`] and the shares at `share_version`, then
/// reconstruct with `shamir_threshold`) and the producer keygen (which writes to
/// `keygen_write_audience` and lays out `{public_prefix}/{public_zone}/…`), so
/// producer and consumer agree on the partner set, the version and T by
/// construction.
pub struct EnvConfig {
    pub partners: &'static [EnvPartner],
    pub public_bucket: &'static str,
    /// Producer-side layout: the ceremony writes
    /// `{public_prefix}/{public_zone}/{computation_key,public_key,crs}` and the
    /// manifest at [`EnvConfig::manifest_object`].
    pub public_prefix: &'static str,
    pub public_zone: u32,
    /// Shamir reconstruction threshold (T). Baked once here so the producer's split
    /// and every consumer's reconstruct agree on T (N is the partner count).
    pub shamir_threshold: u8,
    /// Target version: every partner holds both shares at this number.
    pub share_version: NonZeroU64,
    /// The partner set that holds the live shares, when the next keygen run is a
    /// reshare. `partners` and `shamir_threshold` above are then the target set.
    /// Consumers read no shares from this set, but their placeholder gate still
    /// checks it (`ensure_partners_complete`). The keygen image built from an env
    /// with this field can only reshare; without it, only a ceremony. Remove it once
    /// the reshare is done.
    pub reshare_from: Option<ReshareSource>,
    /// Set this only for a deliberate new keyset (a key rotation). It has no
    /// meaning for a reshare.
    pub replace_live_keyset: bool,
}

/// The source of a reshare: the partner set that holds the live shares, the
/// threshold and version those shares were written with, and an anchor on the
/// live keyset.
///
/// The anchor is the two signer addresses of the live keyset. They are public and
/// on-chain. The reshare refuses a manifest whose addresses differ, so a bucket
/// writer cannot swap in an older keyset's manifest, and with it an older key, for
/// the run to split again.
pub struct ReshareSource {
    pub partners: &'static [SourcePartner],
    pub shamir_threshold: u8,
    pub share_version: NonZeroU64,
    /// The staging migration to unity versions only: the source manifest has the
    /// legacy unversioned name, and the run also writes that name.
    pub legacy_manifest: bool,
    pub decrypt_signer_address: &'static str,
    pub zk_signer_address: &'static str,
}

/// One source partner and the version its two shares sit at.
pub struct SourcePartner {
    pub partner: EnvPartner,
    /// None = ReshareSource.share_version.
    pub share_version: Option<NonZeroU64>,
}

/// Builds a baked share version. The env files write every version as `v(N)`,
/// because scripts outside this crate parse that literal.
pub const fn v(n: u64) -> NonZeroU64 {
    match NonZeroU64::new(n) {
        Some(v) => v,
        None => panic!("a share version is >= 1"),
    }
}

impl ReshareSource {
    /// The version of both secrets at one source partner.
    pub fn version_for(&self, project_id: &str) -> NonZeroU64 {
        self.partners
            .iter()
            .find(|s| s.partner.project_id == project_id)
            .and_then(|s| s.share_version)
            .unwrap_or(self.share_version)
    }

    /// The manifest that lists the source shares.
    pub fn manifest_object(&self, env: &EnvConfig) -> String {
        if self.legacy_manifest {
            env.legacy_manifest_object()
        } else {
            env.manifest_at(self.share_version)
        }
    }
}

/// Marks a partner slot that is declared but not yet filled in. A slot keeps the
/// real shape (so N and T are honest from the start) while the operator's project
/// number is outstanding.
pub const PARTNER_PLACEHOLDER: &str = "FILL-ME-";

impl EnvConfig {
    /// The folder that holds the public objects: `{public_prefix}/{public_zone}`.
    pub fn manifest_dir(&self) -> String {
        format!("{}/{}", self.public_prefix, self.public_zone)
    }

    /// The manifest of the keyset at `share_version`.
    pub fn manifest_object(&self) -> String {
        self.manifest_at(self.share_version)
    }

    /// The manifest of the keyset at `version`: `{dir}/public-material.v{version}`.
    pub fn manifest_at(&self, version: NonZeroU64) -> String {
        format!("{}/public-material.v{version}", self.manifest_dir())
    }

    /// The manifest name from before share versions. Only the staging migration
    /// reads it.
    pub fn legacy_manifest_object(&self) -> String {
        format!("{}/public-material", self.manifest_dir())
    }

    /// FAIL-CLOSED: every version a reshare reads is below the target, so every
    /// reshare writes new versions and never overwrites what readers use. An
    /// override equal to the source version is a no-op that hides a typo.
    pub fn check_versions(&self) -> Result<()> {
        let Some(r) = &self.reshare_from else {
            return Ok(());
        };
        let target = self.share_version;
        if r.share_version >= target {
            return Err(anyhow!(
                "the reshare source share_version {} is not below the target share_version {target}",
                r.share_version
            ));
        }
        for s in r.partners {
            let Some(x) = s.share_version else { continue };
            if x >= target {
                return Err(anyhow!(
                    "source partner {:?} share_version {x} is not below the target share_version {target}",
                    s.partner.project_id
                ));
            }
            if x == r.share_version {
                return Err(anyhow!(
                    "source partner {:?} overrides share_version with {x}, which equals the source share_version",
                    s.partner.project_id
                ));
            }
        }
        Ok(())
    }

    /// FAIL-CLOSED: `Err` while any partner slot is still a placeholder.
    ///
    /// This is deliberately NOT enforced in [`lookup`]. An incomplete env still has a
    /// valid public-material location, and tooling that only needs the bucket/prefix
    /// (the CI TF drift check) must keep resolving it. The gate belongs on the two
    /// paths that actually touch the partner set: the ceremony's config build and the
    /// reader's reconstruct. Both call this.
    pub fn ensure_partners_complete(&self) -> Result<()> {
        let sources = self
            .reshare_from
            .iter()
            .flat_map(|r| r.partners.iter().map(|s| &s.partner));
        let pending: Vec<&str> = self
            .partners
            .iter()
            .chain(sources)
            .filter(|p| {
                p.project_id.starts_with(PARTNER_PLACEHOLDER)
                    || p.wip_pool_audience.contains(PARTNER_PLACEHOLDER)
                    || p.keygen_write_audience.contains(PARTNER_PLACEHOLDER)
            })
            .map(|p| p.project_id)
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        Err(anyhow!(
            "partner set is incomplete: {pending:?} still {} a placeholder. Fill the \
             real project id and number in envs/<env>.rs and rebuild (fail-closed: a \
             placeholder audience would abort a ceremony only after the keyset is \
             generated and the earlier partners are already written)",
            if pending.len() == 1 { "is" } else { "are" }
        ))
    }
}

/// The baked environments.
const ENVIRONMENTS: &[(&str, &EnvConfig)] = &[
    ("staging", &STAGING),
    ("testnet", &TESTNET),
    ("mainnet", &MAINNET),
];

/// Every baked environment name, in declaration order. Lets tooling — the CI
/// TF↔reader drift check (`scripts/check-tf-reader-drift.sh`) — enumerate envs
/// straight from this map instead of re-listing them, so a newly-baked env is
/// automatically in scope for the drift comparison.
pub fn env_names() -> Vec<&'static str> {
    ENVIRONMENTS.iter().map(|(name, _)| *name).collect()
}

/// FAIL-CLOSED: returns `Err` on any env not in the baked map (`"staging"` |
/// `"testnet"` | `"mainnet"`). Never defaults, never falls back.
pub fn lookup(env: &str) -> Result<&'static EnvConfig> {
    ENVIRONMENTS
        .iter()
        .find(|(name, _)| *name == env)
        .map(|(_, cfg)| *cfg)
        .ok_or_else(|| {
            anyhow!(
                "unknown environment {env:?} — baked environments: {:?} (fail-closed: no default, no fallback)",
                ENVIRONMENTS.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_fails_closed_on_unknown_env() {
        assert!(lookup("staging").is_ok());
        assert!(lookup("testnet").is_ok());
        assert!(lookup("mainnet").is_ok());
        // Fail-closed: anything else errors — no default, no fallback.
        for bad in ["", "prod", "Staging", "staging\n", "Mainnet", "mainnet\n"] {
            assert!(lookup(bad).is_err(), "must fail closed on {bad:?}");
        }
    }

    // The mainnet entry is baked from the gitops keygen var-file. A `FILL-ME-`
    // placeholder that reached a build would publish or read the keyset at a path
    // nothing else agrees on, so fail here instead of at ceremony time.
    #[test]
    fn baked_envs_have_no_placeholder_locations() {
        for (name, cfg) in ENVIRONMENTS {
            assert!(
                !cfg.public_bucket.contains(PARTNER_PLACEHOLDER)
                    && !cfg.manifest_object().contains(PARTNER_PLACEHOLDER),
                "env {name:?} still has a placeholder public bucket/object"
            );
        }
    }

    #[test]
    fn mainnet_is_six_partners_at_threshold_three() {
        let env = lookup("mainnet").unwrap();
        assert_eq!(env.partners.len(), 6);
        assert_eq!(env.shamir_threshold, 3);
        for p in env.partners {
            assert!(p
                .wip_pool_audience
                .ends_with("/workloadIdentityPools/cofhe-tee-reader-pool"));
            assert!(p
                .keygen_write_audience
                .ends_with("/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider"));
        }
    }

    /// Returns the `projects/<n>` segment of an audience.
    fn project_number_of(audience: &str) -> &str {
        audience
            .split("/projects/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .expect("audience carries a projects/<n> segment")
    }

    // A partner's two audiences are separate strings carrying the SAME project
    // number. The ceremony only ever exercises the write one, so a typo in the reader
    // audience would surface as nothing worse than one silently excluded partner at
    // consumer boot. Catch it here instead.
    #[test]
    fn each_partner_uses_one_project_number_for_both_audiences() {
        for (name, cfg) in ENVIRONMENTS {
            for p in cfg.partners {
                let read = project_number_of(p.wip_pool_audience);
                let write = project_number_of(p.keygen_write_audience);
                assert_eq!(
                    read, write,
                    "env {name:?} partner {:?}: reader audience uses project {read}, write audience uses {write}",
                    p.project_id
                );
                assert!(
                    read.starts_with(PARTNER_PLACEHOLDER)
                        || read.bytes().all(|b| b.is_ascii_digit()),
                    "env {name:?} partner {:?}: project number {read:?} is not numeric",
                    p.project_id
                );
            }
        }
    }

    // The gate is tested against fixtures, never against whichever env happens to be
    // incomplete today. Filling a real slot must never turn a test red — an operator
    // editing a guard test during a ceremony is how a guard gets removed.
    fn partner(project_id: &'static str, num: &'static str) -> EnvPartner {
        EnvPartner {
            project_id,
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

    fn env_with(partners: &'static [EnvPartner]) -> EnvConfig {
        EnvConfig {
            partners,
            public_bucket: "b",
            public_prefix: "p",
            public_zone: 0,
            shamir_threshold: 2,
            share_version: v(1),
            reshare_from: None,
            replace_live_keyset: false,
        }
    }

    // Partners p1..p3 on both sides; `source` is (version, overrides, legacy_manifest).
    type Source = Option<(u64, &'static [(&'static str, u64)], bool)>;

    fn env_with_versions(target: u64, source: Source) -> &'static EnvConfig {
        let ps: &'static [EnvPartner] = Box::leak(
            vec![
                partner("p1", "111111111111"),
                partner("p2", "222222222222"),
                partner("p3", "333333333333"),
            ]
            .into_boxed_slice(),
        );
        let mut env = env_with(ps);
        env.share_version = v(target);
        env.reshare_from = source.map(|(version, overrides, legacy_manifest)| ReshareSource {
            partners: Box::leak(
                ps.iter()
                    .map(|&partner| SourcePartner {
                        partner,
                        share_version: overrides
                            .iter()
                            .find(|(id, _)| *id == partner.project_id)
                            .map(|&(_, n)| v(n)),
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            shamir_threshold: 2,
            share_version: v(version),
            legacy_manifest,
            decrypt_signer_address: "0x1111111111111111111111111111111111111111",
            zk_signer_address: "0x2222222222222222222222222222222222222222",
        });
        Box::leak(Box::new(env))
    }

    #[test]
    fn manifest_names_carry_the_version() {
        let e = env_with_versions(9, None);
        assert_eq!(e.manifest_object(), "p/0/public-material.v9");
        assert_eq!(e.legacy_manifest_object(), "p/0/public-material");
    }

    #[test]
    fn a_source_partner_override_wins() {
        let e = env_with_versions(9, Some((5, &[("p1", 8)], true)));
        let r = e.reshare_from.as_ref().unwrap();
        assert_eq!(r.version_for("p1").get(), 8);
        assert_eq!(r.version_for("p2").get(), 5);
        assert_eq!(r.manifest_object(e), "p/0/public-material");
    }

    #[test]
    fn versions_must_climb() {
        assert!(env_with_versions(5, Some((5, &[], false)))
            .check_versions()
            .is_err());
        assert!(env_with_versions(8, Some((5, &[("p1", 8)], false)))
            .check_versions()
            .is_err());
        assert!(env_with_versions(9, Some((5, &[("p1", 5)], false)))
            .check_versions()
            .is_err());
        assert!(env_with_versions(9, Some((5, &[("p1", 8)], true)))
            .check_versions()
            .is_ok());
    }

    #[test]
    fn every_baked_env_has_climbing_versions() {
        for name in env_names() {
            lookup(name).unwrap().check_versions().unwrap();
        }
    }

    #[test]
    fn an_open_project_id_slot_fails_the_gate() {
        let ps: &'static [EnvPartner] = Box::leak(
            vec![
                partner("real-1", "111111111111"),
                partner("FILL-ME-PARTNER-2", "222222222222"),
            ]
            .into_boxed_slice(),
        );
        let err = env_with(ps)
            .ensure_partners_complete()
            .expect_err("an open slot must fail closed")
            .to_string();
        assert!(err.contains("FILL-ME-PARTNER-2"), "{err}");
    }

    // The id and the project number arrive as separate fields of the partner's form,
    // so one can be filled while the other is not. That must still fail.
    #[test]
    fn a_filled_id_with_an_open_project_number_fails_the_gate() {
        let ps: &'static [EnvPartner] = Box::leak(
            vec![
                partner("real-1", "111111111111"),
                partner("real-2", "FILL-ME-PROJECT-NUMBER-2"),
            ]
            .into_boxed_slice(),
        );
        assert!(env_with(ps).ensure_partners_complete().is_err());
    }

    // A reshare reads from the source set, so an open slot there must fail too.
    #[test]
    fn an_open_slot_in_the_reshare_source_fails_the_gate() {
        let target: &'static [EnvPartner] = Box::leak(
            vec![
                partner("real-1", "111111111111"),
                partner("real-2", "222222222222"),
            ]
            .into_boxed_slice(),
        );
        let source: &'static [SourcePartner] = Box::leak(
            [
                partner("real-1", "111111111111"),
                partner("FILL-ME-PARTNER-3", "333333333333"),
            ]
            .map(|partner| SourcePartner {
                partner,
                share_version: None,
            })
            .into(),
        );
        let mut env = env_with(target);
        env.reshare_from = Some(ReshareSource {
            partners: source,
            shamir_threshold: 2,
            share_version: v(1),
            legacy_manifest: false,
            decrypt_signer_address: "0x1111111111111111111111111111111111111111",
            zk_signer_address: "0x2222222222222222222222222222222222222222",
        });
        let err = env
            .ensure_partners_complete()
            .expect_err("an open source slot must fail closed")
            .to_string();
        assert!(err.contains("FILL-ME-PARTNER-3"), "{err}");
    }

    #[test]
    fn a_fully_filled_set_passes_the_gate() {
        let ps: &'static [EnvPartner] = Box::leak(
            vec![
                partner("real-1", "111111111111"),
                partner("real-2", "222222222222"),
            ]
            .into_boxed_slice(),
        );
        assert!(env_with(ps).ensure_partners_complete().is_ok());
    }

    // The gate is on the partner set, NOT on `lookup`. An incomplete env still has a
    // complete public-material location, and the CI TF drift check resolves every env
    // for exactly that. Breaking this would break the drift check.
    #[test]
    fn lookup_still_resolves_an_env_with_placeholder_partners() {
        let env = lookup("mainnet").expect("lookup must not gate on partner slots");
        assert_eq!(env.public_bucket, "fhenix-mainnet-keys");
        assert_eq!(env.public_prefix, "generator/keys/versionized");
    }

    #[test]
    fn complete_partner_sets_pass_the_gate() {
        for name in ["staging", "testnet"] {
            assert!(lookup(name).unwrap().ensure_partners_complete().is_ok());
        }
    }
}
