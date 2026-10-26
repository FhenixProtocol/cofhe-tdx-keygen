use super::*;

pub(super) const PARTNERS: &[EnvPartner] = &[
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
];

pub(super) const TESTNET: EnvConfig = EnvConfig {
    partners: PARTNERS,
    public_bucket: "fhenix-testnet-v2",
    public_object: "generator/keys/versionized/0/public-material",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
    reshare_from: None,
    replace_live_keyset: false,
};
