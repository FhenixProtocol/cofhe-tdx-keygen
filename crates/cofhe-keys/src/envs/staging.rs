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
    public_object: "generator/keys/versionized/0/public-material",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 2,
    reshare_from: None,
    replace_live_keyset: false,
};
