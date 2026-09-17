//! In-enclave generation of the full network keyset.
//!
//! Produces, with production parameters (matching the TN preprocessor + fhe-engine,
//! tfhe =1.5.1): the FHE ClientKey (`priv`), CompressedServerKey, CompactPublicKey,
//! and CRS — plus the **two** independent secp256k1 signers. The TN preprocessor
//! keygen generates only the FHE keys and NO signers (the decrypt signer is born
//! in the dispatcher, the zk signer in zk-verifier), so this service mints both:
//!   - decrypt_signer = TN / decrypt-result signer (consumed by teecryptor/dispatcher)
//!   - zk_signer      = ZK / verifier signer (consumed by zk-verifier)
//!
//! Returns the secret share (→ partner Secret Manager) and the public material
//! (→ our GCS bucket).

use anyhow::{bail, Context, Result};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as CPK_PARAMS;
use tfhe::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as CASTING_PARAMS;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, CompactPublicKey, CompressedServerKey, ConfigBuilder};
use tracing::info;

use crate::serialization::{sha256, FhePrivShare, PublicMaterial, ZkSignerShare};
use crate::shamir;

/// One partner's pair of Shamir share blobs (index-aligned to the `partner_ids`
/// passed to [`generate`]): the partner gets share `i` of the FHE-priv secret and
/// share `i` of the ZK-signer secret. Each blob is the canonical bytes of a
/// `Gf256` share (1 participant-id byte + GF(256) y-bytes), written into that
/// partner's two Secret Manager secrets and never combined inside the enclave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerShares {
    pub fhe_priv_share: Vec<u8>,
    pub zk_signer_share: Vec<u8>,
}

/// The PUBLIC FHE artifacts (identical for all partners): the `safe_serialize`d
/// bytes of the ServerKey, CompactPublicKey, and CRS. Written to GCS as SEPARATE
/// objects laid out exactly as cofhe mounts them (`computation_key` / `public_key`
/// / `crs`), so the cofhe stack reads this ceremony's keyset directly as files.
/// Their SHA-256 digests are published in the attested [`PublicMaterial`] manifest,
/// so a consumer reading a file can verify it fail-closed
/// ([`crate::serialization::verify_artifact`]) — the bytes never transit the
/// manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicArtifacts {
    pub server_key: Vec<u8>,
    pub compact_public_key: Vec<u8>,
    pub crs: Vec<u8>,
}

/// tfhe safe-serialization size limit (matches rust-common: 1 GiB).
const SAFE_SER_LIMIT: u64 = 1 << 30;

/// CRS size for key generation (verification-only consumers use a smaller CRS).
const CRS_SIZE: usize = 1024;

fn safe_ser<T>(value: &T) -> Result<Vec<u8>>
where
    T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(value, &mut buf, SAFE_SER_LIMIT)
        .map_err(|e| anyhow::anyhow!("safe_serialize: {e}"))?;
    Ok(buf)
}

/// EVM address = keccak256(uncompressed_pubkey[1..65])[12..32], `0x`-prefixed.
fn evm_address(sk: &SigningKey) -> String {
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Coherence self-test: encrypt a probe under the `CompactPublicKey`, expand it
/// (expansion uses the `ServerKey`'s casting key), and decrypt with the
/// `ClientKey` — proving the three keys are a consistent set. Catches a key-wiring
/// / serialization mistake in [`generate`] that a byte digest cannot.
fn self_test_coherent(
    client_key: &ClientKey,
    public_key: &CompactPublicKey,
    server_key: &CompressedServerKey,
) -> Result<()> {
    use tfhe::prelude::*;
    const PROBE: u8 = 0xA5;

    tfhe::set_server_key(server_key.decompress());
    let compact = tfhe::CompactCiphertextList::builder(public_key)
        .push(PROBE)
        .build();
    let expanded = compact
        .expand()
        .map_err(|e| anyhow::anyhow!("expand compact ciphertext: {e}"))?;
    let ct: tfhe::FheUint8 = expanded
        .get(0)
        .map_err(|e| anyhow::anyhow!("read expanded ciphertext: {e}"))?
        .context("expanded ciphertext list is empty")?;
    let got: u8 = ct.decrypt(client_key);
    if got != PROBE {
        bail!("coherence self-test: encrypted {PROBE} under CompactPublicKey but decrypted {got} with ClientKey");
    }
    Ok(())
}

/// Generate the keyset and Shamir-split each per-audience secret component across
/// the partners.
///
/// Builds the [`FhePrivShare`] (FHE priv + decrypt signer → TeeCryptor) and
/// [`ZkSignerShare`] (zk signer → ZK verifier) exactly as a single-partner run
/// would, then splits each one's canonical bytes into `shares` blobs (T-of-N,
/// `threshold`) with a fresh OS-seeded CSPRNG. Share `i` of each secret is paired
/// with `partner_ids[i]` (index → identity), so the returned `Vec<PartnerShares>`
/// is index-aligned to `partner_ids` and ready for per-partner distribution.
///
/// The [`PublicMaterial`] carries the full-secret digests (`fhe_priv_digest` /
/// `zk_signer_digest`, the reconstruction-validation anchor) AND the per-partner
/// `(partner_id, SHA-256(that partner's share blob))` lists, so a reconstructing
/// consumer can drop a tampered/stale partner's share UP FRONT (plain Shamir does
/// not error-correct).
///
/// `partner_ids.len()` must equal `shares` (N partners ↔ N shares); the caller
/// (`Config`) validates that and the distinctness of the ids.
pub fn generate(
    partner_ids: &[String],
    shares: u8,
    threshold: u8,
) -> Result<(Vec<PartnerShares>, PublicArtifacts, PublicMaterial)> {
    if partner_ids.len() != shares as usize {
        bail!(
            "generate: {} partner ids but {} shares (must be equal)",
            partner_ids.len(),
            shares
        );
    }

    // Production FHE parameters — must match the rest of the network exactly.
    let config = ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
        .use_dedicated_compact_public_key_parameters((CPK_PARAMS, CASTING_PARAMS))
        .build();

    info!("keygen: generating FHE ClientKey (priv)");
    let client_key = ClientKey::generate(config);
    info!("keygen: deriving CompressedServerKey");
    let server_key = CompressedServerKey::new(&client_key);
    info!("keygen: deriving CompactPublicKey");
    let public_key = CompactPublicKey::new(&client_key);
    info!(crs_size = CRS_SIZE, "keygen: generating CRS");
    let crs = CompactPkeCrs::from_config(config, CRS_SIZE).context("generate CRS")?;

    // Coherence self-test: prove the generated ClientKey actually decrypts what the
    // CompactPublicKey encrypts (expansion exercises the ServerKey's casting key) —
    // i.e. the three keys are a consistent set. This catches a key-wiring or
    // serialization bug in THIS function before anything is distributed; the byte
    // digests can't (they hash whatever bytes we put there, self-consistently).
    info!("keygen: coherence self-test (encrypt → expand → decrypt)");
    self_test_coherent(&client_key, &public_key, &server_key)
        .context("keygen coherence self-test")?;

    // Two independent signers (the gap vs the TN keygen, which mints neither).
    let decrypt_signer = SigningKey::random(&mut OsRng); // TN / decrypt-result
    let zk_signer = SigningKey::random(&mut OsRng); // ZK / verifier
    let decrypt_signer_address = evm_address(&decrypt_signer);
    let zk_signer_address = evm_address(&zk_signer);
    info!(
        decrypt_signer = %decrypt_signer_address,
        zk_signer = %zk_signer_address,
        "keygen: generated decrypt + zk signers"
    );

    // TeeCryptor's component: FHE priv + the decrypt-path signer.
    let fhe_priv = FhePrivShare {
        client_key: safe_ser(&client_key).context("serialize ClientKey")?,
        decrypt_signer_priv: decrypt_signer.to_bytes().to_vec(),
    };
    // The ZK verifier's component: just its signer.
    let zk_share = ZkSignerShare {
        zk_signer_priv: zk_signer.to_bytes().to_vec(),
    };

    // Shamir-split each secret's canonical bytes into N blobs (T-of-N). One CSPRNG
    // per split — OS-seeded once and reused across the many bytes a ~40 KB split
    // draws (see `shamir::new_csprng`). Share `i` belongs to `partner_ids[i]`.
    info!(
        shares,
        threshold,
        partners = partner_ids.len(),
        "keygen: Shamir-splitting per-audience secrets"
    );
    let fhe_blobs = shamir::split(
        &fhe_priv.to_canonical_bytes(),
        shares,
        threshold,
        &mut shamir::new_csprng(),
    )
    .context("split FHE-priv secret")?;
    let zk_blobs = shamir::split(
        &zk_share.to_canonical_bytes(),
        shares,
        threshold,
        &mut shamir::new_csprng(),
    )
    .context("split ZK-signer secret")?;

    // Per-partner digests key SHA-256(share blob) by partner IDENTITY (not position),
    // so a reconstructing consumer can exclude a tampered/stale partner UP FRONT.
    let fhe_priv_share_digests: Vec<(String, [u8; 32])> = partner_ids
        .iter()
        .zip(&fhe_blobs)
        .map(|(id, blob)| (id.clone(), sha256(blob)))
        .collect();
    let zk_signer_share_digests: Vec<(String, [u8; 32])> = partner_ids
        .iter()
        .zip(&zk_blobs)
        .map(|(id, blob)| (id.clone(), sha256(blob)))
        .collect();

    // safe_serialize the three public artifacts once; their bytes go to standalone
    // GCS objects and their SHA-256 digests go into the attested manifest below.
    let artifacts = PublicArtifacts {
        server_key: safe_ser(&server_key).context("serialize ServerKey")?,
        compact_public_key: safe_ser(&public_key).context("serialize CompactPublicKey")?,
        crs: safe_ser(&crs).context("serialize CRS")?,
    };

    let public = PublicMaterial {
        // SHA-256 of each artifact object's bytes — a consumer reading the file
        // verifies it against these, inheriting the manifest's attestation.
        server_key_digest: sha256(&artifacts.server_key),
        compact_public_key_digest: sha256(&artifacts.compact_public_key),
        crs_digest: sha256(&artifacts.crs),
        decrypt_signer_address,
        zk_signer_address,
        // SHA-256 of each secret's canonical payload — the reconstruction-validation
        // anchor a consumer checks after assembling/reconstructing its key.
        fhe_priv_digest: fhe_priv.hash(),
        zk_signer_digest: zk_share.hash(),
        // Per-partner `(project_id, SHA-256(share))` lists for the split ceremony.
        fhe_priv_share_digests,
        zk_signer_share_digests,
    };

    // Pair each partner's two share blobs, index-aligned to `partner_ids`.
    let partner_shares: Vec<PartnerShares> = fhe_blobs
        .into_iter()
        .zip(zk_blobs)
        .map(|(fhe_priv_share, zk_signer_share)| PartnerShares {
            fhe_priv_share,
            zk_signer_share,
        })
        .collect();

    info!(
        client_key_bytes = fhe_priv.client_key.len(),
        server_key_bytes = artifacts.server_key.len(),
        compact_public_key_bytes = artifacts.compact_public_key.len(),
        crs_bytes = artifacts.crs.len(),
        partners = partner_shares.len(),
        "keygen: keyset generated and split"
    );

    Ok((partner_shares, artifacts, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The per-share digest population the multi-partner ceremony will do (a
    // follow-up PR), exercised here on a small synthetic payload so it's covered
    // without touching the live ceremony / main.rs: split N/T, SHA-256 each share
    // blob, and confirm those digests gate reconstruction.
    #[test]
    fn per_share_digests_match_split_shares() {
        use crate::serialization::sha256;
        use crate::shamir;

        let payload = b"synthetic secret payload".to_vec();
        let (n, t) = (5u8, 2u8);
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, n, t, &mut rng).unwrap();

        let digests: Vec<[u8; 32]> = shares.iter().map(|s| sha256(s)).collect();
        assert_eq!(digests.len(), n as usize);
        for (share, digest) in shares.iter().zip(&digests) {
            assert_eq!(sha256(share), *digest);
        }
        // The digests gate reconstruction: any T good shares reconstruct the secret.
        assert_eq!(
            shamir::reconstruct(&shares[..t as usize], t).unwrap(),
            payload
        );
    }

    // Slow: generates a real keyset (FHE keygen + CRS) and splits it 5 ways.
    // Validates the recipe, the per-partner digest lists, and the 64 KiB Secret
    // Manager fit for each per-audience share envelope.
    #[test]
    fn generates_real_keyset() {
        use crate::serialization::sha256;
        use crate::shamir;

        let partner_ids: Vec<String> = (0..5).map(|i| format!("partner-project-{i}")).collect();
        let (n, t) = (5u8, 2u8);

        // generate() also runs the coherence self-test internally; reaching here
        // means encrypt → expand → decrypt round-tripped.
        let (partner_shares, artifacts, public) = generate(&partner_ids, n, t).unwrap();
        assert_eq!(partner_shares.len(), n as usize);

        // The per-partner digest lists are populated, length N, keyed by the given
        // partner ids in order, and each equals SHA-256 of that partner's share blob.
        assert_eq!(public.fhe_priv_share_digests.len(), n as usize);
        assert_eq!(public.zk_signer_share_digests.len(), n as usize);
        for (i, ps) in partner_shares.iter().enumerate() {
            let (fhe_id, fhe_digest) = &public.fhe_priv_share_digests[i];
            assert_eq!(fhe_id, &partner_ids[i]);
            assert_eq!(*fhe_digest, sha256(&ps.fhe_priv_share));
            let (zk_id, zk_digest) = &public.zk_signer_share_digests[i];
            assert_eq!(zk_id, &partner_ids[i]);
            assert_eq!(*zk_digest, sha256(&ps.zk_signer_share));
        }

        // The full-secret digests still bind the reconstructed payloads: take any T
        // share blobs, reconstruct, and confirm the recovered share hashes to the
        // published full digest. This also proves the components round-trip and have
        // well-formed signer scalars.
        let fhe_blobs: Vec<Vec<u8>> = partner_shares
            .iter()
            .take(t as usize)
            .map(|p| p.fhe_priv_share.clone())
            .collect();
        let fhe_bytes = shamir::reconstruct(&fhe_blobs, t).unwrap();
        assert_eq!(public.fhe_priv_digest, sha256(&fhe_bytes));
        let fhe_priv = FhePrivShare::from_canonical_bytes(&fhe_bytes).unwrap();
        assert!(!fhe_priv.client_key.is_empty());
        assert_eq!(fhe_priv.decrypt_signer_priv.len(), 32);

        let zk_blobs: Vec<Vec<u8>> = partner_shares
            .iter()
            .take(t as usize)
            .map(|p| p.zk_signer_share.clone())
            .collect();
        let zk_bytes = shamir::reconstruct(&zk_blobs, t).unwrap();
        assert_eq!(public.zk_signer_digest, sha256(&zk_bytes));
        let zk_share = ZkSignerShare::from_canonical_bytes(&zk_bytes).unwrap();
        assert_eq!(zk_share.zk_signer_priv.len(), 32);

        // Public artifacts are well-formed and the manifest digests bind them.
        assert!(!artifacts.server_key.is_empty());
        assert!(!artifacts.compact_public_key.is_empty());
        assert!(!artifacts.crs.is_empty());
        assert_eq!(public.server_key_digest, sha256(&artifacts.server_key));
        assert_eq!(
            public.compact_public_key_digest,
            sha256(&artifacts.compact_public_key)
        );
        assert_eq!(public.crs_digest, sha256(&artifacts.crs));
        // Two distinct EVM addresses.
        assert_eq!(public.decrypt_signer_address.len(), 42);
        assert!(public.decrypt_signer_address.starts_with("0x"));
        assert_ne!(public.decrypt_signer_address, public.zk_signer_address);

        eprintln!(
            "sizes: client_key={} server_key={} compact_public_key={} crs={} fhe_share={} zk_share={}",
            fhe_priv.client_key.len(),
            artifacts.server_key.len(),
            artifacts.compact_public_key.len(),
            artifacts.crs.len(),
            partner_shares[0].fhe_priv_share.len(),
            partner_shares[0].zk_signer_share.len(),
        );

        // What lands in Secret Manager is the ENVELOPE (one share blob + provenance
        // JWT). Assert the larger one — an FHE-priv share — fits the 64 KiB cap with
        // a generous 12 KiB placeholder for the real (few-KB) token.
        let fhe_envelope = crate::serialization::SecretEnvelope {
            payload: partner_shares[0].fhe_priv_share.clone(),
            provenance_jwt: "x".repeat(12 * 1024),
        };
        let env_bytes = fhe_envelope.to_canonical_bytes();
        assert!(
            env_bytes.len() < 64 * 1024,
            "fhe-priv share envelope {} bytes exceeds the 64 KiB Secret Manager cap",
            env_bytes.len()
        );
    }
}
