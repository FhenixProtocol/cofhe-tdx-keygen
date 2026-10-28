use cofhe_keys::envs::{v, EnvConfig, EnvPartner, ReshareSource, SourcePartner};

pub(crate) fn env_partner(id: &'static str, num: &'static str) -> EnvPartner {
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

pub(crate) fn set(ids: &[(&'static str, &'static str)]) -> &'static [EnvPartner] {
    Box::leak(
        ids.iter()
            .map(|(id, n)| env_partner(id, n))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

pub(crate) fn sources(partners: &[EnvPartner]) -> &'static [SourcePartner] {
    Box::leak(
        partners
            .iter()
            .map(|&partner| SourcePartner {
                partner,
                share_version: None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

pub(crate) const P1: (&str, &str) = ("p-1", "111111111111");
pub(crate) const P2: (&str, &str) = ("p-2", "222222222222");
pub(crate) const P3: (&str, &str) = ("p-3", "333333333333");
pub(crate) const P4: (&str, &str) = ("p-4", "444444444444");

pub(crate) const LIVE_DECRYPT: &str = "0x1111111111111111111111111111111111111111";
pub(crate) const LIVE_ZK: &str = "0x2222222222222222222222222222222222222222";

pub(crate) fn env(
    target: &'static [EnvPartner],
    t: u8,
    source: Option<(&'static [EnvPartner], u8)>,
) -> &'static EnvConfig {
    Box::leak(Box::new(EnvConfig {
        partners: target,
        public_bucket: "b",
        public_prefix: "p",
        public_zone: 0,
        shamir_threshold: t,
        share_version: v(2),
        reshare_from: source.map(|(partners, shamir_threshold)| ReshareSource {
            partners: sources(partners),
            shamir_threshold,
            share_version: v(1),
            legacy_manifest: false,
            decrypt_signer_address: LIVE_DECRYPT,
            zk_signer_address: LIVE_ZK,
        }),
        replace_live_keyset: false,
    }))
}

// 2-of-3 on p1..p3 → 2-of-3 on p1, p2, p4: replace p3 with p4.
pub(crate) fn replace_env() -> &'static EnvConfig {
    env(set(&[P1, P2, P4]), 2, Some((set(&[P1, P2, P3]), 2)))
}
