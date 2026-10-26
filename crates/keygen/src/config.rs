use crate::{WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER};
use anyhow::{bail, Context, Result};
use cofhe_keys::envs::{EnvConfig, ReshareSource};
use std::collections::BTreeSet;

// One partner of the Shamir ceremony: its GCP project (the cross-project write
// target) and its keygen WRITE audience (the attestation/STS audience for that
// project). Sourced from the baked `EnvConfig`; partner `i` receives share `i` of
// each split secret.
#[cfg(not(feature = "mock"))]
#[derive(Debug, Clone)]
pub(crate) struct PartnerCfg {
    pub(crate) project_id: String,
    pub(crate) wip_audience: String,
}

// Which run this image does, from the baked env alone: an env with `reshare_from`
// builds a reshare image, any other env a ceremony image. No runtime input can
// change it.
#[cfg(not(feature = "mock"))]
pub(crate) enum Mode {
    Ceremony,
    Reshare(&'static ReshareSource),
}

// The run shape is baked per env in `cofhe_keys::envs`. Share i goes to
// `partners[i]`; N = the partner count; T = `threshold`. No SA_EMAIL: each
// partner's attested federated principal holds secretVersionAdder on its secrets
// directly.
#[cfg(not(feature = "mock"))]
pub(crate) struct Config {
    pub(crate) mode: Mode,
    pub(crate) partners: Vec<PartnerCfg>,
    pub(crate) shares: u8,
    pub(crate) threshold: u8,
    pub(crate) write_secret_fhe_priv: String,
    pub(crate) write_secret_zk_signer: String,
    // The baked env: every target partner gets both shares at its `share_version`,
    // and a ceremony may replace a live keyset only when it bakes
    // `replace_live_keyset`. The public bucket and its layout are read from it.
    pub(crate) env: &'static EnvConfig,
}

#[cfg(not(feature = "mock"))]
impl Config {
    // `COFHE_ENV` is the ONLY operator-settable input (besides `RUST_LOG`, honored by
    // tracing) — it selects a BAKED environment and nothing else. Everything else,
    // the run mode and the share versions included, is compiled in, so a VM metadata
    // override cannot redirect the write set, weaken the threshold, repoint the
    // public bucket, or turn a reshare into a ceremony.
    pub(crate) fn from_env() -> Result<Self> {
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
    pub(crate) fn from_env_config(ec: &'static EnvConfig) -> Result<Self> {
        // Fail before a single key is generated or read. A placeholder audience would
        // otherwise abort the run mid-write, after earlier partners are written.
        ec.ensure_partners_complete()?;
        ec.check_versions()?;
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
            env: ec,
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
            .any(|s| s.partner.project_id.is_empty() || s.partner.wip_pool_audience.is_empty())
        {
            bail!("a reshare source partner has an empty project_id or wip_pool_audience");
        }
        check_distinct(r.partners.iter().map(|s| s.partner.project_id))
            .context("reshare source")?;
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

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::KEYGEN_READER;
    use cofhe_keys::envs::{v, EnvPartner};
    use cofhe_keys::reader;

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
            env: cofhe_keys::envs::lookup("testnet").unwrap(),
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
        assert_eq!(cfg.env.public_bucket, "localcofhenix");
        assert_eq!(cfg.env.public_prefix, "generator/keys/versionized");
        assert_eq!(cfg.env.public_zone, 0);
    }

    #[test]
    fn builds_testnet_from_baked_env() {
        let cfg = Config::for_env("testnet").unwrap();
        assert_eq!(cfg.partners.len(), 3);
        assert_eq!(cfg.shares, 3);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.env.public_bucket, "fhenix-testnet-v2");
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
        assert_eq!(cfg.env.public_bucket, "fhenix-mainnet-keys");
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

    #[test]
    fn reshare_builds_source_and_target_sets() {
        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(r) = &cfg.mode else {
            panic!("expected reshare mode")
        };
        let ids: Vec<&str> = r.partners.iter().map(|s| s.partner.project_id).collect();
        assert_eq!(ids, ["p-1", "p-2", "p-3"]);
        assert_eq!(r.shamir_threshold, 2);
        assert_eq!(
            reader::partner_refs_for(
                &r.partners.iter().map(|s| s.partner).collect::<Vec<_>>(),
                KEYGEN_READER,
                "s"
            )[2]
            .wip_audience,
            "//iam.googleapis.com/projects/333333333333/locations/global/workloadIdentityPools/cofhe-tee-reader-pool/providers/keygen-reader"
        );
        let targets: Vec<&str> = cfg.partners.iter().map(|p| p.project_id.as_str()).collect();
        assert_eq!(targets, ["p-1", "p-2", "p-4"]);
        assert_eq!(cfg.env.share_version.get(), 2);
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
                        partners: sources(set(&[P1, P2, P3])),
                        shamir_threshold: 2,
                        share_version: v(1),
                        legacy_manifest: false,
                        decrypt_signer_address: decrypt,
                        zk_signer_address: zk,
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

    // Source < target makes every reshare write new versions, so a same-set,
    // same-T reshare is a real change: it moves the shares to a new version.
    #[test]
    fn a_same_set_reshare_to_a_new_version_is_allowed() {
        let same = env(set(&[P1, P2, P3]), 2, Some((set(&[P3, P2, P1]), 2)));
        assert!(Config::from_env_config(same).is_ok());
    }

    // The env refuses a source version at or above the target before any read.
    #[test]
    fn a_source_version_at_the_target_is_refused() {
        let src = replace_env().reshare_from.as_ref().unwrap();
        let e = Box::leak(Box::new(EnvConfig {
            reshare_from: Some(ReshareSource {
                share_version: v(2),
                ..*src
            }),
            ..*replace_env()
        }));
        assert!(Config::from_env_config(e).is_err());
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

    // The CI gate for baked config: every baked env with a complete partner set must
    // build. Each env runs exactly one mode by construction, so a bad reshare source
    // or share version fails CI and never reaches a release. A declared but unfilled partner
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
