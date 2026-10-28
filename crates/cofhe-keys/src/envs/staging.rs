use super::*;

pub(super) const PARTNERS: &[EnvPartner] = &[
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
];

pub(super) const STAGING: EnvConfig = EnvConfig {
    partners: PARTNERS,
    public_bucket: "localcofhenix",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
    share_version: v(9),
    // The migration to share versions: partner-1 holds v8 and partners 2-5 hold
    // v5, all listed by the legacy unversioned manifest. The source entries index
    // `PARTNERS` only because this migration keeps the same set. For a set change,
    // write them in full: an edit of `PARTNERS` would change them too.
    reshare_from: Some(ReshareSource {
        partners: &[
            SourcePartner {
                partner: PARTNERS[0],
                share_version: Some(v(8)),
            },
            SourcePartner {
                partner: PARTNERS[1],
                share_version: None,
            },
            SourcePartner {
                partner: PARTNERS[2],
                share_version: None,
            },
            SourcePartner {
                partner: PARTNERS[3],
                share_version: None,
            },
            SourcePartner {
                partner: PARTNERS[4],
                share_version: None,
            },
        ],
        shamir_threshold: 2,
        share_version: v(5),
        legacy_manifest: true,
        decrypt_signer_address: "0x78727a198308732baadd7db5339ed95d50110b76",
        zk_signer_address: "0xe12a73f5aaca9ae79bda8754a485fe99fef3fac3",
    }),
    replace_live_keyset: false,
};
