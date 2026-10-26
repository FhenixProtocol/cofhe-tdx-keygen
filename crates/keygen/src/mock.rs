use anyhow::{ensure, Result};
use cofhe_keys::keygen;
use cofhe_keys::serialization::{sha256, FhePrivShare, ZkSignerShare};
use cofhe_keys::shamir;
use tracing::{info, warn};

/// Local-dev boot path, compiled only under the `mock` feature.
///
/// Stands in for the production attestation chain
/// (attestation -> STS -> Secret Manager write). It generates the key material
/// in-process and skips both the attestation and the cross-project write, so the
/// keygen path can be exercised on a laptop without TDX or GCP. It has no trust
/// boundary, so it serves local development only.
pub fn boot() -> Result<()> {
    warn!("MOCK MODE: no attestation, no Secret Manager write — keys generated in-process. Local development only.");

    // Synthetic 2-of-3 ceremony: exercises the real generate-and-split path
    // (T < N, the fault-tolerant shape) without GCP/TDX or a real PARTNERS config.
    // Threshold is >= 2 — the Gf256 backend does not support T=1.
    let partner_ids = vec![
        "mock-partner-1".to_string(),
        "mock-partner-2".to_string(),
        "mock-partner-3".to_string(),
    ];
    let (partner_shares, artifacts, public) = keygen::generate(&partner_ids, 3, 2)?;
    info!(
        partners = partner_shares.len(),
        fhe_priv_share_bytes = partner_shares[0].fhe_priv_share.len(),
        zk_signer_share_bytes = partner_shares[0].zk_signer_share.len(),
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "MOCK: real keyset generated and split; no write performed"
    );

    // Synthetic reshare of the same keyset: 2-of-3 → 3-of-4, in the order the real
    // run uses: rebuild, check against the public data, split again, rebuild from
    // three new shares. The manifest keeps every field except the share digests.
    let rebuild =
        |set: &[&keygen::PartnerShares], t, pick: fn(&keygen::PartnerShares) -> &Vec<u8>| {
            shamir::reconstruct(&set.iter().map(|s| pick(s).clone()).collect::<Vec<_>>(), t)
        };
    let old = [&partner_shares[0], &partner_shares[2]];
    let fhe = FhePrivShare::from_canonical_bytes(&rebuild(&old, 2, |s| &s.fhe_priv_share)?)?;
    let zk = ZkSignerShare::from_canonical_bytes(&rebuild(&old, 2, |s| &s.zk_signer_share)?)?;
    keygen::verify_against_public(&fhe, &zk, &public, &artifacts)?;
    let target: Vec<String> = (1..=4).map(|i| format!("mock-target-{i}")).collect();
    let split = keygen::split_for_partners(&fhe, &zk, &target, 4, 3)?;
    let resharded =
        public.with_share_digests(split.fhe_priv_share_digests, split.zk_signer_share_digests);
    let new: Vec<&keygen::PartnerShares> = split.partner_shares[1..].iter().collect();
    ensure!(
        sha256(&rebuild(&new, 3, |s| &s.fhe_priv_share)?) == resharded.fhe_priv_digest,
        "reshare changed the FHE-priv secret"
    );
    ensure!(
        sha256(&rebuild(&new, 3, |s| &s.zk_signer_share)?) == resharded.zk_signer_digest,
        "reshare changed the ZK-signer secret"
    );
    info!(
        decrypt_signer = %resharded.decrypt_signer_address,
        "MOCK: reshare 2-of-3 → 3-of-4 kept the same key; no write performed"
    );
    Ok(())
}
