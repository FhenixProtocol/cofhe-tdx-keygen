use anyhow::Result;
use cofhe_keys::keygen;
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
    let (partner_shares, _artifacts, public) = keygen::generate(&partner_ids, 3, 2)?;
    info!(
        partners = partner_shares.len(),
        fhe_priv_share_bytes = partner_shares[0].fhe_priv_share.len(),
        zk_signer_share_bytes = partner_shares[0].zk_signer_share.len(),
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "MOCK: real keyset generated and split; no write performed"
    );
    Ok(())
}
