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
];

pub(super) const STAGING: EnvConfig = EnvConfig {
    partners: PARTNERS,
    public_bucket: "localcofhenix",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
    share_version: v(10),
    // Drill pass 1: partner-5 leaves. The sources are the five partners at v9,
    // written in full because partner-5 is no longer in `PARTNERS`.
    reshare_from: Some(ReshareSource {
        partners: &[
            SourcePartner {
                partner: EnvPartner {
                    project_id: "cofhe-tee-partner-1",
                    wip_pool_audience: "//iam.googleapis.com/projects/719732368646/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                    keygen_write_audience: "//iam.googleapis.com/projects/719732368646/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
                },
                share_version: None,
            },
            SourcePartner {
                partner: EnvPartner {
                    project_id: "cofhe-tee-partner-2",
                    wip_pool_audience: "//iam.googleapis.com/projects/558994189066/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                    keygen_write_audience: "//iam.googleapis.com/projects/558994189066/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
                },
                share_version: None,
            },
            SourcePartner {
                partner: EnvPartner {
                    project_id: "cofhe-tee-partner-3",
                    wip_pool_audience: "//iam.googleapis.com/projects/499488488731/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                    keygen_write_audience: "//iam.googleapis.com/projects/499488488731/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
                },
                share_version: None,
            },
            SourcePartner {
                partner: EnvPartner {
                    project_id: "cofhe-tee-partner-4",
                    wip_pool_audience: "//iam.googleapis.com/projects/467122964772/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                    keygen_write_audience: "//iam.googleapis.com/projects/467122964772/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
                },
                share_version: None,
            },
            SourcePartner {
                partner: EnvPartner {
                    project_id: "cofhe-tee-partner-5",
                    wip_pool_audience: "//iam.googleapis.com/projects/926992419891/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                    keygen_write_audience: "//iam.googleapis.com/projects/926992419891/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
                },
                share_version: None,
            },
        ],
        shamir_threshold: 2,
        share_version: v(9),
        legacy_manifest: false,
        decrypt_signer_address: "0x78727a198308732baadd7db5339ed95d50110b76",
        zk_signer_address: "0xe12a73f5aaca9ae79bda8754a485fe99fef3fac3",
    }),
    replace_live_keyset: false,
};
