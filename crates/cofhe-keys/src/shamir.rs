//! Shamir Secret Sharing over GF(256) — the split/reconstruct primitives shared
//! by the writer (split a secret into N shares) and the reader (reconstruct from
//! any T). We split the serialized secret payloads directly (no envelope): the
//! `FhePrivShare` / `ZkSignerShare` canonical bytes.
//!
//! Backed by `vsss-rs`'s `Gf256` split/combine. We always supply our own OS-seeded
//! `ChaCha20Rng`, never an internal `thread_rng()`. In a TDX enclave `getrandom`
//! is RDRAND/RDSEED-backed; we seed the ChaCha20Rng once and reuse it, since
//! splitting a ~40 KB payload draws a lot of randomness.
//!
//! Minimum threshold is 2: `Gf256::combine_array` requires >= 2 shares, so the
//! degenerate `T = 1` case is not supported.

use anyhow::{bail, Result};
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use vsss_rs::Gf256;

/// Minimum reconstruction threshold: `Gf256::combine_array` requires at least 2
/// shares, so `T = 1` is unsupported.
pub const MIN_THRESHOLD: u8 = 2;

/// A fresh OS-seeded CSPRNG for the producer's split. Seeded once from OS entropy
/// (`getrandom`; RDRAND/RDSEED-backed under TDX) and then reused across the many
/// random bytes a large split consumes — never reseeded per byte.
pub fn new_csprng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

/// Split `payload` into `shares` Shamir shares with reconstruction threshold
/// `threshold` (T-of-N), drawing randomness from the caller's CSPRNG. Returns one
/// serialized share blob per share (`Gf256`'s `Vec<u8>` encoding: 1 participant-id
/// byte + the GF(256) y-bytes).
pub fn split(
    payload: &[u8],
    shares: u8,
    threshold: u8,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<Vec<u8>>> {
    if threshold < MIN_THRESHOLD {
        bail!("shamir threshold must be >= {MIN_THRESHOLD}");
    }
    if shares < threshold {
        bail!(
            "shamir shares ({}) must be >= threshold ({})",
            shares,
            threshold
        );
    }
    Gf256::split_array(threshold as usize, shares as usize, payload, &mut *rng)
        .map_err(|e| anyhow::anyhow!("shamir split: {e}"))
}

/// Reconstruct the secret payload from share blobs. `shares` must contain at least
/// `threshold` valid blobs; `Gf256` interpolates exactly the shares given (plain
/// Shamir does NOT error-correct), so the CALLER is responsible for passing only
/// shares it has already validated (e.g. via the per-share digest filter in the
/// reader). `threshold` must match the value used to split.
pub fn reconstruct(shares: &[Vec<u8>], threshold: u8) -> Result<Vec<u8>> {
    if threshold < MIN_THRESHOLD {
        bail!("shamir threshold must be >= {MIN_THRESHOLD}");
    }
    if shares.len() < threshold as usize {
        bail!(
            "shamir reconstruct needs >= {} shares, got {}",
            threshold,
            shares.len()
        );
    }
    Gf256::combine_array(shares).map_err(|e| anyhow::anyhow!("shamir recover: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_reconstruct_round_trip_small() {
        let mut rng = new_csprng();
        let secret = b"the quick brown fox".to_vec();
        let shares = split(&secret, 5, 2, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);
        assert_eq!(reconstruct(&shares[..2], 2).unwrap(), secret);
    }

    #[test]
    fn split_reconstruct_round_trip_40kb() {
        let mut rng = new_csprng();
        // A ~40 KB payload, the size of the serialized FhePrivShare.
        let secret: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let shares = split(&secret, 5, 2, &mut rng).unwrap();
        assert_eq!(reconstruct(&shares[..2], 2).unwrap(), secret);
    }

    // ANY T-of-N subset reconstructs the identical secret.
    #[test]
    fn any_threshold_subset_reconstructs() {
        let mut rng = new_csprng();
        let secret = b"shamir is linear".to_vec();
        let shares = split(&secret, 5, 3, &mut rng).unwrap();
        // Every 3-of-5 subset.
        let n = shares.len();
        for a in 0..n {
            for b in (a + 1)..n {
                for c in (b + 1)..n {
                    let subset = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(reconstruct(&subset, 3).unwrap(), secret);
                }
            }
        }
    }

    // A garbage share among the T yields the WRONG bytes (no error): Lagrange
    // interpolates exactly the points given. This is why the per-share digest gate
    // in the reader is load-bearing — Shamir alone cannot tell a good share from a
    // tampered one.
    #[test]
    fn wrong_share_yields_wrong_bytes() {
        let mut rng = new_csprng();
        let secret = b"reconstruct me exactly".to_vec();
        let shares = split(&secret, 5, 2, &mut rng).unwrap();

        let mut tampered = shares[1].clone();
        // Flip a y-byte (index 0 is the x-coordinate; corrupt a payload byte).
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;

        let bad = vec![shares[0].clone(), tampered];
        let got = reconstruct(&bad, 2).unwrap();
        assert_ne!(got, secret);
    }

    #[test]
    fn split_rejects_bad_params() {
        let mut rng = new_csprng();
        assert!(split(b"x", 5, 0, &mut rng).is_err()); // threshold < MIN_THRESHOLD
        assert!(split(b"x", 5, 1, &mut rng).is_err()); // T=1 unsupported (< MIN_THRESHOLD)
        assert!(split(b"x", 1, 2, &mut rng).is_err()); // shares < threshold
    }

    #[test]
    fn reconstruct_rejects_too_few_shares() {
        let mut rng = new_csprng();
        let shares = split(b"secret", 5, 3, &mut rng).unwrap();
        assert!(reconstruct(&shares[..2], 3).is_err());
    }

    #[test]
    fn reconstruct_rejects_garbage_blob() {
        // Pass MIN_THRESHOLD shares so the count guard is satisfied and the blobs
        // actually reach Gf256::combine_array's validation. Blobs too short to be
        // valid shares (id byte only, no y-bytes) are rejected...
        assert!(reconstruct(&[vec![1u8], vec![2u8]], 2).is_err());
        // ...as are shares of mismatched length.
        assert!(reconstruct(&[vec![1u8, 2, 3], vec![2u8, 3]], 2).is_err());
    }
}
