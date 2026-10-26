use super::*;

pub(super) const PARTNERS: &[EnvPartner] = &[
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
];

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
/// Changing the partner set is NOT a config change. It is: put the current set in
/// `reshare_from`, edit the entries below to the new set, raise `share_version`,
/// and run a reshare. CEREMONY.md §5 gives the full sequence, with tags A and B.
/// For a set change, write the source entries in full in `reshare_from`, not as
/// `PARTNERS[i]`: an edit of `PARTNERS` to the target set would change them too.
pub(super) const MAINNET: EnvConfig = EnvConfig {
    partners: PARTNERS,
    // This is the single source of truth for the mainnet public location; the
    // manifest is EnvConfig::manifest_object(). terraform/service
    // mirrors public_bucket + public_prefix in local.public_material only to scope the
    // read grant's IAM condition, and CI (check-tf-reader-drift.sh) enforces the match —
    // the ceremony lays out the path from what is baked here.
    public_bucket: "fhenix-mainnet-keys",
    public_prefix: "generator/keys/versionized",
    public_zone: 0,
    shamir_threshold: 3,
    share_version: v(1),
    reshare_from: None,
    replace_live_keyset: false,
};
