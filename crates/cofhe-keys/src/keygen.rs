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

use crate::serialization::{sha256, verify_artifact, FhePrivShare, PublicMaterial, ZkSignerShare};
use crate::shamir;

/// One partner's pair of Shamir share blobs (index-aligned to the `partner_ids`
/// passed to [`split_for_partners`]): the partner gets share `i` of the FHE-priv
/// secret and share `i` of the ZK-signer secret. Each blob is the canonical bytes
/// of a `Gf256` share (1 participant-id byte + GF(256) y-bytes), written into that
/// partner's two Secret Manager secrets.
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// Production FHE parameters. They must match the rest of the network exactly.
fn fhe_config() -> tfhe::Config {
    ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
        .use_dedicated_compact_public_key_parameters((CPK_PARAMS, CASTING_PARAMS))
        .build()
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
/// `partner_ids.len()` must equal `shares` (N partners ↔ N shares), and the ids
/// must be distinct; [`split_for_partners`] checks both.
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

    let config = fhe_config();

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

    let split = split_for_partners(&fhe_priv, &zk_share, partner_ids, shares, threshold)?;

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
        fhe_priv_share_digests: split.fhe_priv_share_digests,
        zk_signer_share_digests: split.zk_signer_share_digests,
    };
    let partner_shares = split.partner_shares;

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

/// One partner set's shares of both secrets, with the per-partner digest lists the
/// manifest publishes. Index `i` of every field belongs to `partner_ids[i]`.
pub struct SplitOutput {
    pub partner_shares: Vec<PartnerShares>,
    pub fhe_priv_share_digests: Vec<(String, [u8; 32])>,
    pub zk_signer_share_digests: Vec<(String, [u8; 32])>,
}

/// Shamir-split both secrets for one partner set, T-of-N. A ceremony calls this on
/// a new keyset; a reshare calls it on the live keyset with the target set. Each
/// split draws a fresh OS-seeded CSPRNG, so new shares have no relation to any
/// earlier split of the same secret.
pub fn split_for_partners(
    fhe_priv: &FhePrivShare,
    zk_share: &ZkSignerShare,
    partner_ids: &[String],
    shares: u8,
    threshold: u8,
) -> Result<SplitOutput> {
    if partner_ids.len() != shares as usize {
        bail!(
            "split: {} partner ids but {} shares (must be equal)",
            partner_ids.len(),
            shares
        );
    }
    // Two shares under one id would land in one partner secret, the second over the
    // first, and leave the set one share short.
    let mut seen = std::collections::HashSet::new();
    if !partner_ids.iter().all(|id| seen.insert(id)) {
        bail!("split: partner ids must be distinct");
    }
    info!(
        shares,
        threshold,
        partners = partner_ids.len(),
        "keygen: Shamir-splitting per-audience secrets"
    );
    // One CSPRNG per split — OS-seeded once and reused across the many bytes a
    // ~40 KB split draws (see `shamir::new_csprng`). Share `i` belongs to
    // `partner_ids[i]`.
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
    let digests = |blobs: &[Vec<u8>]| -> Vec<(String, [u8; 32])> {
        partner_ids
            .iter()
            .zip(blobs)
            .map(|(id, blob)| (id.clone(), sha256(blob)))
            .collect()
    };
    let fhe_priv_share_digests = digests(&fhe_blobs);
    let zk_signer_share_digests = digests(&zk_blobs);

    let partner_shares = fhe_blobs
        .into_iter()
        .zip(zk_blobs)
        .map(|(fhe_priv_share, zk_signer_share)| PartnerShares {
            fhe_priv_share,
            zk_signer_share,
        })
        .collect();
    Ok(SplitOutput {
        partner_shares,
        fhe_priv_share_digests,
        zk_signer_share_digests,
    })
}

/// Prove that a reconstructed key is the key behind the live public data, before a
/// reshare writes anything. The public artifacts cannot be regenerated byte for
/// byte (their keygen is randomized, and the CRS does not depend on the key), so
/// the check is in four parts:
///
/// 1. Each artifact's SHA-256 matches its manifest digest.
/// 2. Each secret's SHA-256 matches its full-key manifest digest.
/// 3. Both signer addresses derive from the private scalars.
/// 4. The reconstructed ClientKey decrypts what the published CompactPublicKey
///    encrypts. It also decrypts a homomorphic add under the published ServerKey.
///    The add runs a PBS, so it covers the bootstrapping key and not only the
///    casting key.
pub fn verify_against_public(
    fhe_priv: &FhePrivShare,
    zk_share: &ZkSignerShare,
    public: &PublicMaterial,
    artifacts: &PublicArtifacts,
) -> Result<()> {
    verify_artifact(
        &artifacts.server_key,
        &public.server_key_digest,
        "server key",
    )?;
    verify_artifact(
        &artifacts.compact_public_key,
        &public.compact_public_key_digest,
        "compact public key",
    )?;
    verify_artifact(&artifacts.crs, &public.crs_digest, "crs")?;
    if fhe_priv.hash() != public.fhe_priv_digest {
        bail!("the FHE-priv secret does not match its full-key manifest digest");
    }
    if zk_share.hash() != public.zk_signer_digest {
        bail!("the ZK-signer secret does not match its full-key manifest digest");
    }
    for (name, scalar, address) in [
        (
            "decrypt signer",
            &fhe_priv.decrypt_signer_priv,
            &public.decrypt_signer_address,
        ),
        (
            "zk signer",
            &zk_share.zk_signer_priv,
            &public.zk_signer_address,
        ),
    ] {
        let sk = SigningKey::from_slice(scalar).with_context(|| format!("decode {name}"))?;
        if evm_address(&sk) != *address {
            bail!("the {name} scalar does not derive the published {name} address");
        }
    }

    let client_key: ClientKey = safe_de(&fhe_priv.client_key).context("decode ClientKey")?;
    let public_key: CompactPublicKey =
        safe_de(&artifacts.compact_public_key).context("decode published CompactPublicKey")?;
    let server_key: CompressedServerKey =
        safe_de(&artifacts.server_key).context("decode published ServerKey")?;
    self_test_coherent(&client_key, &public_key, &server_key)
        .context("the reconstructed ClientKey does not match the published public keys")?;
    self_test_bootstrap(&client_key)
        .context("the reconstructed ClientKey does not match the published ServerKey")?;
    Ok(())
}

fn safe_de<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
{
    tfhe::safe_serialization::safe_deserialize(bytes, SAFE_SER_LIMIT)
        .map_err(|e| anyhow::anyhow!("safe_deserialize: {e}"))
}

/// Add two ciphertexts under the server key that `self_test_coherent` installed.
/// The carry propagation runs a PBS, which fails to decrypt correctly when the
/// bootstrapping key belongs to another ClientKey.
fn self_test_bootstrap(client_key: &ClientKey) -> Result<()> {
    use tfhe::prelude::*;
    let a = tfhe::FheUint8::encrypt(117u8, client_key);
    let b = tfhe::FheUint8::encrypt(58u8, client_key);
    let sum: u8 = (&a + &b).decrypt(client_key);
    if sum != 117u8.wrapping_add(58) {
        bail!("homomorphic add decrypted to {sum}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_VERSION;

    // A rebuilt secret that is not the one the manifest names stops the check
    // before any key is decoded. Synthetic bytes: the artifact digests match, so
    // only the full-key digest can fail.
    #[test]
    fn verify_against_public_refuses_a_secret_the_manifest_does_not_name() {
        let fhe = FhePrivShare {
            client_key: vec![1; 8],
            decrypt_signer_priv: vec![2; 32],
        };
        let zk = ZkSignerShare {
            zk_signer_priv: vec![3; 32],
        };
        let artifacts = PublicArtifacts {
            server_key: b"sk".to_vec(),
            compact_public_key: b"pk".to_vec(),
            crs: b"crs".to_vec(),
        };
        let public = PublicMaterial {
            server_key_digest: sha256(b"sk"),
            compact_public_key_digest: sha256(b"pk"),
            crs_digest: sha256(b"crs"),
            decrypt_signer_address: String::new(),
            zk_signer_address: String::new(),
            fhe_priv_digest: fhe.hash(),
            zk_signer_digest: zk.hash(),
            fhe_priv_share_digests: vec![],
            zk_signer_share_digests: vec![],
        };
        for (wrong, which) in [
            (
                PublicMaterial {
                    fhe_priv_digest: [0; 32],
                    ..public.clone()
                },
                "FHE-priv",
            ),
            (
                PublicMaterial {
                    zk_signer_digest: [0; 32],
                    ..public.clone()
                },
                "ZK-signer",
            ),
        ] {
            let err = verify_against_public(&fhe, &zk, &wrong, &artifacts).unwrap_err();
            assert!(format!("{err:#}").contains(which), "{err:#}");
        }
    }

    #[test]
    fn split_for_partners_round_trips_with_a_new_n_and_t() {
        let fhe = FhePrivShare {
            client_key: b"synthetic client key".to_vec(),
            decrypt_signer_priv: vec![7u8; 32],
        };
        let zk = ZkSignerShare {
            zk_signer_priv: vec![9u8; 32],
        };
        let ids: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let out = split_for_partners(&fhe, &zk, &ids, 4, 3).unwrap();
        assert_eq!(out.partner_shares.len(), 4);
        let listed: Vec<&str> = out
            .fhe_priv_share_digests
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(listed, ["a", "b", "c", "d"]);
        // Any 3 of the 4 new shares rebuild the same payload.
        let blobs: Vec<Vec<u8>> = out.partner_shares[1..]
            .iter()
            .map(|p| p.fhe_priv_share.clone())
            .collect();
        assert_eq!(
            shamir::reconstruct(&blobs, 3).unwrap(),
            fhe.to_canonical_bytes()
        );
        let blobs: Vec<Vec<u8>> = out.partner_shares[..3]
            .iter()
            .map(|p| p.zk_signer_share.clone())
            .collect();
        assert_eq!(
            shamir::reconstruct(&blobs, 3).unwrap(),
            zk.to_canonical_bytes()
        );
        // A count mismatch and a repeated id are rejected.
        assert!(split_for_partners(&fhe, &zk, &ids, 3, 2).is_err());
        let repeated = ["a", "a", "b", "c"].map(String::from);
        assert!(split_for_partners(&fhe, &zk, &repeated, 4, 3).is_err());
    }

    // Slow: generates a real keyset (FHE keygen + CRS) and splits it 5 ways. The one
    // real keyset of the suite, so it also runs the live-key checks a reshare runs
    // before it writes, and a ceremony-then-reshare round trip through the reader.
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

        check_live_key(&fhe_priv, &zk_share, &public, &artifacts);
        #[cfg(feature = "reader")]
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(reshare_round_trip(&fhe_priv, &zk_share, &public));
    }

    // The key matches the published keys and signers, and each kind of mismatch is
    // caught before a reshare writes anything.
    fn check_live_key(
        fhe: &FhePrivShare,
        zk: &ZkSignerShare,
        public: &PublicMaterial,
        artifacts: &PublicArtifacts,
    ) {
        verify_against_public(fhe, zk, public, artifacts).unwrap();

        let mut swapped = artifacts.clone();
        std::mem::swap(&mut swapped.crs, &mut swapped.compact_public_key);
        assert!(verify_against_public(fhe, zk, public, &swapped).is_err());

        let mut wrong_signer = public.clone();
        wrong_signer.zk_signer_address = public.decrypt_signer_address.clone();
        assert!(verify_against_public(fhe, zk, &wrong_signer, artifacts).is_err());

        // A ClientKey from another keyset, with a manifest that claims it. Only the
        // check against the published keys can catch this.
        let other_ck = ClientKey::generate(fhe_config());
        let other = FhePrivShare {
            client_key: safe_ser(&other_ck).unwrap(),
            decrypt_signer_priv: fhe.decrypt_signer_priv.clone(),
        };
        let mut claims_other = public.clone();
        claims_other.fhe_priv_digest = other.hash();
        let err = verify_against_public(&other, zk, &claims_other, artifacts)
            .expect_err("a foreign ClientKey must not match the published keys");
        assert!(
            format!("{err:#}").contains("ClientKey does not match the published"),
            "{err:#}"
        );

        // The bootstrap check alone: the live ClientKey under another keyset's
        // ServerKey. The add runs a PBS with the wrong bootstrapping key, so the sum
        // must not decrypt. A wrong sum still lands on the right value 1 time in 256,
        // so three tries keep the test from flaking.
        tfhe::set_server_key(CompressedServerKey::new(&other_ck).decompress());
        let ck: ClientKey = safe_de(&fhe.client_key).unwrap();
        assert!((0..3).any(|_| self_test_bootstrap(&ck).is_err()));
    }

    // The design's end-to-end check: this ceremony's keyset, resharded to a new
    // 3-of-4 set. The reader on the new set returns both secrets byte for byte.
    #[cfg(feature = "reader")]
    async fn reshare_round_trip(fhe: &FhePrivShare, zk: &ZkSignerShare, live: &PublicMaterial) {
        use crate::gcs::GcsClient;
        use crate::reader::{
            read_fhe_priv, read_zk_signer, PartnerAccess, PartnerRef, ReaderContext,
        };
        use crate::secrets::SecretManager;
        use base64::Engine as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let ids: Vec<String> = ["b", "c", "d", "e"].iter().map(|s| s.to_string()).collect();
        let split = split_for_partners(fhe, zk, &ids, 4, 3).unwrap();
        let resharded =
            live.with_share_digests(split.fhe_priv_share_digests, split.zk_signer_share_digests);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/bucket/o/public-material"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(resharded.to_canonical_bytes()))
            .mount(&server)
            .await;
        for (id, share) in ids.iter().zip(&split.partner_shares) {
            for (secret, bytes) in [
                ("fhe", &share.fhe_priv_share),
                ("zk", &share.zk_signer_share),
            ] {
                let envelope = crate::serialization::SecretEnvelope {
                    payload: bytes.clone(),
                    provenance_jwt: String::new(),
                };
                let data =
                    base64::engine::general_purpose::STANDARD.encode(envelope.to_canonical_bytes());
                Mock::given(method("GET"))
                    .and(path(format!(
                        "/v1/projects/{id}/secrets/{secret}/versions/{TEST_VERSION}:access"
                    )))
                    .respond_with(ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "name": "v", "payload": { "data": data } }),
                    ))
                    .mount(&server)
                    .await;
            }
        }
        let refs = |secret: &str| -> Vec<PartnerRef> {
            ids.iter()
                .map(|id| PartnerRef {
                    project_id: id.clone(),
                    secret_id: secret.to_string(),
                    wip_audience: String::new(),
                })
                .collect()
        };
        let (fhe_refs, zk_refs) = (refs("fhe"), refs("zk"));
        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());
        let ctx = ReaderContext {
            sm: &sm,
            gcs: &gcs,
            gcs_token: "t",
            public_bucket: "bucket",
            public_object: "public-material",
        };
        fn access(refs: &[PartnerRef]) -> Vec<PartnerAccess<'_>> {
            refs.iter()
                .map(|partner| PartnerAccess {
                    partner,
                    sm_token: "t",
                })
                .collect()
        }
        let got_fhe = read_fhe_priv(&ctx, &access(&fhe_refs), 3, &|_| TEST_VERSION)
            .await
            .unwrap();
        let got_zk = read_zk_signer(&ctx, &access(&zk_refs), 3, &|_| TEST_VERSION)
            .await
            .unwrap();
        assert_eq!(got_fhe.to_canonical_bytes(), fhe.to_canonical_bytes());
        assert_eq!(got_zk.to_canonical_bytes(), zk.to_canonical_bytes());
    }
}
