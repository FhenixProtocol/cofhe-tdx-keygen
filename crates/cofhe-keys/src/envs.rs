//! Baked environment source — the compile-time key SOURCE shared by BOTH sides of
//! the crate: the producer keygen (write side, `writer` feature) and the consumer
//! reader (read side, `reader` feature). It is deliberately UNCONDITIONAL (no
//! feature gate) so the write-only enclave image — built `--no-default-features`
//! with just `writer` — can still resolve its env via [`lookup`] without pulling in
//! the reader's async fetch stack. The `reader` module re-exports these items, so
//! existing `cofhe_keys::reader::{lookup, env_names, EnvConfig, EnvPartner}` paths
//! keep working for read-side consumers unchanged.

use anyhow::{anyhow, Result};

/// The reader's key SOURCE is baked at compile time — never operator-settable.
/// One entry per blessed env. Onboarding an env, and changing a partner SET within
/// one, are both rebuilds by design; a same-set reshare touches nothing here.
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
/// shares, the public-material location, and the reconstruction threshold. Shared
/// by the consumer readers (which read `public_object` + reconstruct with
/// `shamir_threshold`) and the producer keygen (which writes to `keygen_write_audience`
/// and lays out `{public_prefix}/{public_zone}/…`), so producer and consumer agree
/// on the partner set and T by construction.
pub struct EnvConfig {
    pub partners: &'static [EnvPartner],
    pub public_bucket: &'static str,
    /// The consumer's read path to the manifest =
    /// `{public_prefix}/{public_zone}/public-material`.
    pub public_object: &'static str,
    /// Producer-side layout: the ceremony writes
    /// `{public_prefix}/{public_zone}/{computation_key,public_key,crs,public-material}`.
    pub public_prefix: &'static str,
    pub public_zone: u32,
    /// Shamir reconstruction threshold (T). Baked once here so the producer's split
    /// and every consumer's reconstruct agree on T (N is the partner count).
    pub shamir_threshold: u8,
}

const STAGING: EnvConfig = EnvConfig {
    partners: &[
        EnvPartner {
            project_id: "cofhe-tee-partner-1",
            wip_pool_audience: "//iam.googleapis.com/projects/719732368646/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/719732368646/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "cofhe-tee-partner-2",
            wip_pool_audience: "//iam.googleapis.com/projects/558994189066/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/558994189066/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "cofhe-tee-partner-3",
            wip_pool_audience: "//iam.googleapis.com/projects/499488488731/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/499488488731/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "cofhe-tee-partner-4",
            wip_pool_audience: "//iam.googleapis.com/projects/467122964772/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/467122964772/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "cofhe-tee-partner-5",
            wip_pool_audience: "//iam.googleapis.com/projects/926992419891/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/926992419891/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
    ],
    public_bucket: "localcofhenix",
    public_object: "generator/keys/versionized/0/public-material",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
};

const TESTNET: EnvConfig = EnvConfig {
    partners: &[
        EnvPartner {
            project_id: "fhenix-testnet-tee-partner-1",
            wip_pool_audience: "//iam.googleapis.com/projects/1075523748493/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/1075523748493/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "fhenix-testnet-tee-partner-2",
            wip_pool_audience: "//iam.googleapis.com/projects/114880301918/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/114880301918/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "fhenix-testnet-tee-partner-3",
            wip_pool_audience: "//iam.googleapis.com/projects/513013593200/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/513013593200/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
    ],
    public_bucket: "fhenix-testnet-v2",
    public_object: "generator/keys/versionized/0/public-material",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
};

/// The mainnet partner set: six key-share holders, threshold 3. Each runs the partner
/// stack in its own GCP project, and reconstructing a secret needs 3 of the 6, so no
/// single operator holds a usable secret.
///
/// The set is complete: every slot holds a real project id and project number, so
/// [`EnvConfig::ensure_partners_complete`] passes. The gate stays in place for a slot
/// vacated later — it blocks the ceremony ([`crate::envs`] consumers call it at config
/// build) and the read side ([`crate::reader::partner_refs`]).
///
/// Every slot is one operator, one project, and all six are treated identically here.
/// A project name is chosen by its operator and identifies no one — do not read
/// ownership, or a guarantee of third-party independence, off these strings.
///
/// Changing the partner set is NOT a config change. It is: edit the entries below,
/// rebuild every consumer (the source is compile-time), re-pin the new consumer
/// digests in the env's `keygen-partners` var-file, and have all six partners
/// re-apply the partner stack. Plan for that sequence — there is no shortcut that
/// skips the rebuild.
const MAINNET: EnvConfig = EnvConfig {
    partners: &[
        EnvPartner {
            project_id: "fhenix-507307",
            wip_pool_audience: "//iam.googleapis.com/projects/5428800810/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/5428800810/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "fhenix-508321",
            wip_pool_audience: "//iam.googleapis.com/projects/262617433943/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/262617433943/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "nodes-fhenix",
            wip_pool_audience: "//iam.googleapis.com/projects/442786234206/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/442786234206/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "fhenix-mainnet-key-share",
            wip_pool_audience: "//iam.googleapis.com/projects/772683464839/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/772683464839/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "validator-fhenix",
            wip_pool_audience: "//iam.googleapis.com/projects/581791888267/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/581791888267/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
        EnvPartner {
            project_id: "fhenix-508914",
            wip_pool_audience: "//iam.googleapis.com/projects/902597681407/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
            keygen_write_audience: "//iam.googleapis.com/projects/902597681407/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
        },
    ],
    // This is the single source of truth for the mainnet public location;
    // public_object = "{public_prefix}/{public_zone}/public-material". terraform/service
    // mirrors public_bucket + public_prefix in local.public_material only to scope the
    // read grant's IAM condition, and CI (check-tf-reader-drift.sh) enforces the match —
    // the ceremony lays out the path from what is baked here.
    public_bucket: "fhenix-mainnet-keys",
    public_object: "generator/keys/versionized/0/public-material",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 3,
};

/// Marks a partner slot that is declared but not yet filled in. A slot keeps the
/// real shape (so N and T are honest from the start) while the operator's project
/// number is outstanding.
pub const PARTNER_PLACEHOLDER: &str = "FILL-ME-";

impl EnvConfig {
    /// FAIL-CLOSED: `Err` while any partner slot is still a placeholder.
    ///
    /// This is deliberately NOT enforced in [`lookup`]. An incomplete env still has a
    /// valid public-material location, and tooling that only needs the bucket/prefix
    /// (the CI TF drift check) must keep resolving it. The gate belongs on the two
    /// paths that actually touch the partner set: the ceremony's config build and the
    /// reader's reconstruct. Both call this.
    pub fn ensure_partners_complete(&self) -> Result<()> {
        let pending: Vec<&str> = self
            .partners
            .iter()
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
             real project id and number in envs.rs and rebuild (fail-closed: a \
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
                    && !cfg.public_object.contains(PARTNER_PLACEHOLDER),
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
            public_object: "p/0/public-material",
            public_prefix: "p",
            public_zone: 0,
            shamir_threshold: 2,
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
