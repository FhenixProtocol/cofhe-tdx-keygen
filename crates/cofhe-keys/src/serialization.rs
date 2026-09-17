//! Canonical, deterministic serialization of the keyset material.
//!
//! Both the writer (keygen) and the reader (consumer) encode/decode through this
//! module, so the digest bytes are byte-identical on both sides.
//! Framing is a 1-byte version followed by length-prefixed fields (u32 BE).
//!
//! Split mirrors the distribution model — each SECRET component goes to its own
//! Secret Manager secret (least-privilege per consumer; see CONSUMER-INTEGRATION.md):
//! - [`FhePrivShare`] — the FHE ClientKey (`priv`) + the decrypt_signer scalar
//!   (TN/decrypt), written to the TeeCryptor secret.
//! - [`ZkSignerShare`] — the zk_signer scalar (ZK/verifier), written to the ZK secret.
//! - [`PublicMaterial`] — PUBLIC, written to our GCS bucket: ServerKey,
//!   CompactPublicKey, CRS, and the two signer EVM addresses (public IDs).
//!
//! Each secret payload is wrapped in a [`SecretEnvelope`] with its provenance token.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const ENVELOPE_VERSION: u8 = 1;
// Monotonic single-byte version (semver buys nothing here: the decoder is strict and
// non-extensible, so every format change is breaking — bump this integer each time).
// Bumped 1 -> 2 when the per-share digest fields were added; 2 -> 3 when
// the heavy artifact bytes (ServerKey/CompactPublicKey/CRS) were pulled OUT of the
// manifest and replaced by their SHA-256 digests — the artifacts now ship as
// separate GCS objects (read by cofhe as mounted files), so the manifest carries
// only digests + addresses. An old PublicMaterial now fails with a clear
// "unsupported version". Pre-production every run regenerates all artifacts, so
// there's no deployed format to stay compatible with; the strict decoder
// (`expect_consumed`) rejects stale bytes.
const PUBLIC_VERSION: u8 = 3;

/// Upper bound on a single length-prefixed field, well above the largest
/// legitimate field (the ServerKey, ~30 MB). A length above this is rejected
/// rather than allocated, bounding memory on a hostile/corrupt buffer.
const MAX_FIELD_LEN: usize = 256 * 1024 * 1024;

fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    debug_assert!(
        field.len() <= u32::MAX as usize,
        "field length {} does not fit the u32 length prefix",
        field.len()
    );
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn get_field(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    // Compare via subtraction (never addition) so an attacker-influenced length
    // can't overflow `*pos + len` on a 32-bit target and slip past the bound,
    // panicking on the slice. `*pos <= buf.len()` is the invariant every advance
    // below preserves.
    if buf.len() - *pos < 4 {
        bail!("truncated length prefix");
    }
    let len = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    if len > MAX_FIELD_LEN {
        bail!("field length {} exceeds maximum {}", len, MAX_FIELD_LEN);
    }
    *pos += 4;
    if buf.len() - *pos < len {
        bail!("truncated field body");
    }
    let field = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(field)
}

/// Convert a decoded length-prefixed field into a fixed 32-byte digest, rejecting
/// any other length.
fn digest32(field: Vec<u8>, name: &str) -> Result<[u8; 32]> {
    field
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{} must be 32 bytes, got {}", name, v.len()))
}

/// Upper bound on the per-partner digest list length — far above any plausible
/// partner count (N), so a hostile/corrupt buffer can't drive a huge allocation
/// via the count prefix.
const MAX_DIGESTS: usize = 1024;

/// Write a count-prefixed list of `(partner_id, 32-byte digest)` pairs.
fn put_digest_list(out: &mut Vec<u8>, digests: &[(String, [u8; 32])]) {
    debug_assert!(
        digests.len() <= u32::MAX as usize,
        "digest list length does not fit the u32 prefix"
    );
    out.extend_from_slice(&(digests.len() as u32).to_be_bytes());
    for (id, d) in digests {
        put_field(out, id.as_bytes());
        out.extend_from_slice(d);
    }
}

/// Read a count-prefixed list of `(partner_id, 32-byte digest)` pairs, bounding the
/// count and enforcing each digest is exactly 32 bytes. Subtraction-based bounds
/// match [`get_field`] so an attacker-influenced count/length can't overflow the
/// position. (Integrity of the list rests on the bucket's write IAM — only the
/// keygen producer can write the manifest.)
fn get_digest_list(buf: &[u8], pos: &mut usize, name: &str) -> Result<Vec<(String, [u8; 32])>> {
    if buf.len() - *pos < 4 {
        bail!("truncated {} count prefix", name);
    }
    let count = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    if count > MAX_DIGESTS {
        bail!("{} count {} exceeds maximum {}", name, count, MAX_DIGESTS);
    }
    *pos += 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let id = String::from_utf8(get_field(buf, pos)?)
            .with_context(|| format!("{name} partner id not UTF-8"))?;
        if buf.len() - *pos < 32 {
            bail!("truncated {} digest", name);
        }
        let digest: [u8; 32] = buf[*pos..*pos + 32].try_into().unwrap();
        *pos += 32;
        out.push((id, digest));
    }
    Ok(out)
}

/// After all expected fields are read, the decoder must have consumed the whole
/// buffer — a strict inverse of the encoder. Trailing bytes mean a malformed or
/// tampered payload, so we reject rather than silently ignore them.
fn expect_consumed(pos: usize, buf: &[u8]) -> Result<()> {
    if pos != buf.len() {
        bail!(
            "{} trailing byte(s) after the framed fields",
            buf.len() - pos
        );
    }
    Ok(())
}

// The secret material is split per audience into separate Secret Manager secrets
// (see CONSUMER-INTEGRATION.md): the FHE priv + decrypt signer go to TeeCryptor,
// the zk signer to the ZK verifier — so IAM, not trust, enforces least privilege.
//
// These are plain `Vec<u8>` (no zeroize-on-drop) by design: the keygen is a
// one-shot in a TDX enclave (microsecond window between use and exit, encrypted
// memory, no untrusted swap), and consumers hold the keys for their whole
// lifetime — so zeroize-on-drop would only fire at shutdown ≈ process death,
// where the OS reclaims memory anyway. It would buy nothing concrete here.

const FHE_PRIV_VERSION: u8 = 1;
const ZK_SIGNER_VERSION: u8 = 1;

/// TeeCryptor's audience component: the FHE ClientKey (`priv`) plus the
/// decrypt-path signer scalar. Written to its **own** Secret Manager secret so
/// only TeeCryptor's reader is granted access — the ZK verifier never sees the
/// decryption key. See `CONSUMER-INTEGRATION.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FhePrivShare {
    pub client_key: Vec<u8>,
    pub decrypt_signer_priv: Vec<u8>,
}

impl FhePrivShare {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![FHE_PRIV_VERSION];
        put_field(&mut out, &self.client_key);
        put_field(&mut out, &self.decrypt_signer_priv);
        out
    }

    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self> {
        let version = *buf.first().context("empty fhe-priv share bytes")?;
        if version != FHE_PRIV_VERSION {
            bail!("unsupported fhe-priv share version {}", version);
        }
        let mut pos = 1;
        let client_key = get_field(buf, &mut pos)?;
        let decrypt_signer_priv = get_field(buf, &mut pos)?;
        expect_consumed(pos, buf)?;
        Ok(Self {
            client_key,
            decrypt_signer_priv,
        })
    }

    /// SHA-256 over the canonical bytes — what this secret's provenance binds.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.to_canonical_bytes());
        h.finalize().into()
    }
}

/// The ZK verifier's audience component: only its signer scalar. Written to its
/// **own** Secret Manager secret; the verifier never receives the FHE priv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkSignerShare {
    pub zk_signer_priv: Vec<u8>,
}

impl ZkSignerShare {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![ZK_SIGNER_VERSION];
        put_field(&mut out, &self.zk_signer_priv);
        out
    }

    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self> {
        let version = *buf.first().context("empty zk-signer share bytes")?;
        if version != ZK_SIGNER_VERSION {
            bail!("unsupported zk-signer share version {}", version);
        }
        let mut pos = 1;
        let zk_signer_priv = get_field(buf, &mut pos)?;
        expect_consumed(pos, buf)?;
        Ok(Self { zk_signer_priv })
    }

    /// SHA-256 over the canonical bytes — what this secret's provenance binds.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.to_canonical_bytes());
        h.finalize().into()
    }
}

/// The PUBLIC keyset MANIFEST (identical for all partners), written to our GCS
/// bucket as the `public-material` object; its integrity rests on the bucket's
/// write IAM (only the keygen producer can write it). Addresses are `0x`-prefixed hex.
///
/// It carries only digests + public IDs — NOT the heavy key bytes. The FHE
/// artifacts (ServerKey/CompactPublicKey/CRS) ship as SEPARATE GCS objects laid out
/// exactly as cofhe mounts them (`keys/versionized/{zone}/{computation_key,
/// public_key,crs}`), so the cofhe stack reads this ceremony's keyset directly as
/// files. `server_key_digest` / `compact_public_key_digest` / `crs_digest` are the
/// `SHA-256` of each artifact object's bytes; a consumer that reads an artifact file
/// verifies it against its digest ([`verify_artifact`]), so the manifest's integrity
/// (bucket IAM) transitively covers the artifact without the bytes ever transiting
/// the manifest.
///
/// `fhe_priv_digest` / `zk_signer_digest` are `SHA-256` of each SECRET's canonical
/// payload (the [`FhePrivShare`] / [`ZkSignerShare`] bytes). Published here so a
/// consumer can validate the key it **assembles/reconstructs** matches what the
/// enclave produced. At N=1 each equals a single share's `payload_hash`; once the
/// secret is Shamir-split the per-share digests no longer cover the reconstructed
/// whole, so this full-key digest is the reconstruction-validation anchor.
///
/// `fhe_priv_share_digests` / `zk_signer_share_digests` are `(partner_project_id,
/// SHA-256(that partner's share))` pairs. Keying by partner IDENTITY (not list
/// position) lets a reconstructing consumer detect a tampered/lying/stale partner
/// UP FRONT — exclude any share whose digest doesn't match its partner's published
/// entry before interpolation — since plain Shamir does not error-correct. Empty
/// when the secret is not split (N=1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMaterial {
    pub server_key_digest: [u8; 32],
    pub compact_public_key_digest: [u8; 32],
    pub crs_digest: [u8; 32],
    pub decrypt_signer_address: String,
    pub zk_signer_address: String,
    pub fhe_priv_digest: [u8; 32],
    pub zk_signer_digest: [u8; 32],
    pub fhe_priv_share_digests: Vec<(String, [u8; 32])>,
    pub zk_signer_share_digests: Vec<(String, [u8; 32])>,
}

impl PublicMaterial {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![PUBLIC_VERSION];
        put_field(&mut out, &self.server_key_digest);
        put_field(&mut out, &self.compact_public_key_digest);
        put_field(&mut out, &self.crs_digest);
        put_field(&mut out, self.decrypt_signer_address.as_bytes());
        put_field(&mut out, self.zk_signer_address.as_bytes());
        put_field(&mut out, &self.fhe_priv_digest);
        put_field(&mut out, &self.zk_signer_digest);
        put_digest_list(&mut out, &self.fhe_priv_share_digests);
        put_digest_list(&mut out, &self.zk_signer_share_digests);
        out
    }

    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self> {
        let version = *buf.first().context("empty public-material bytes")?;
        if version != PUBLIC_VERSION {
            bail!("unsupported public-material version {}", version);
        }
        let mut pos = 1;
        let server_key_digest = digest32(get_field(buf, &mut pos)?, "server_key_digest")?;
        let compact_public_key_digest =
            digest32(get_field(buf, &mut pos)?, "compact_public_key_digest")?;
        let crs_digest = digest32(get_field(buf, &mut pos)?, "crs_digest")?;
        let decrypt_signer_address = String::from_utf8(get_field(buf, &mut pos)?)
            .context("decrypt_signer_address not UTF-8")?;
        let zk_signer_address =
            String::from_utf8(get_field(buf, &mut pos)?).context("zk_signer_address not UTF-8")?;
        let fhe_priv_digest = digest32(get_field(buf, &mut pos)?, "fhe_priv_digest")?;
        let zk_signer_digest = digest32(get_field(buf, &mut pos)?, "zk_signer_digest")?;
        let fhe_priv_share_digests = get_digest_list(buf, &mut pos, "fhe_priv_share_digests")?;
        let zk_signer_share_digests = get_digest_list(buf, &mut pos, "zk_signer_share_digests")?;
        expect_consumed(pos, buf)?;
        Ok(Self {
            server_key_digest,
            compact_public_key_digest,
            crs_digest,
            decrypt_signer_address,
            zk_signer_address,
            fhe_priv_digest,
            zk_signer_digest,
            fhe_priv_share_digests,
            zk_signer_share_digests,
        })
    }

    /// SHA-256 over the canonical bytes — the manifest hash the producer stamps into
    /// the (now-unread) public-material provenance sidecar, and the value a consumer
    /// recomputes to tie an artifact file to this manifest.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.to_canonical_bytes());
        h.finalize().into()
    }
}

/// SHA-256 of arbitrary bytes — used by the reader to recompute the
/// public-material hash from the exact bytes it downloaded (without re-parsing
/// the structure), so it matches whatever the writer uploaded and bound.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Verify a downloaded public artifact (the ServerKey / CompactPublicKey / CRS
/// object) against its `expected` digest from [`PublicMaterial`], fail-closed.
///
/// The artifacts ship as standalone GCS objects (so cofhe mounts them as files),
/// while their digests live in the manifest. A file that matches its manifest digest
/// therefore inherits the manifest's integrity (bucket IAM) — this is how a consumer
/// ties a file-served artifact to the published manifest without the bytes ever
/// passing through it. `name` is used only for the error message.
pub fn verify_artifact(bytes: &[u8], expected: &[u8; 32], name: &str) -> Result<()> {
    let got = sha256(bytes);
    if got != *expected {
        bail!(
            "{} digest mismatch: served object hashes to {} but the manifest published {}",
            name,
            hex::encode(got),
            hex::encode(expected)
        );
    }
    Ok(())
}

/// What we store in one Secret Manager secret: an opaque component **payload**
/// (the canonical bytes of one audience component, e.g. [`FhePrivShare`] or
/// [`ZkSignerShare`]) plus the provenance token the producer stamps over it. The
/// envelope is **audience-agnostic** — it carries bytes + a token; the consumer that
/// owns the secret decodes the payload into the component type it expects. The reader
/// no longer verifies the token (that consumer-side check was removed — see
/// `DESIGN.md` §7); share authenticity rests on the partner's attested write-gate,
/// and reconstruction is validated fail-closed against the published digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEnvelope {
    pub payload: Vec<u8>,
    pub provenance_jwt: String,
}

impl SecretEnvelope {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![ENVELOPE_VERSION];
        put_field(&mut out, &self.payload);
        put_field(&mut out, self.provenance_jwt.as_bytes());
        out
    }

    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self> {
        let version = *buf.first().context("empty envelope bytes")?;
        if version != ENVELOPE_VERSION {
            bail!("unsupported envelope version {}", version);
        }
        let mut pos = 1;
        let payload = get_field(buf, &mut pos)?;
        let jwt_bytes = get_field(buf, &mut pos)?;
        expect_consumed(pos, buf)?;
        Ok(Self {
            payload,
            provenance_jwt: String::from_utf8(jwt_bytes).context("provenance_jwt not UTF-8")?,
        })
    }

    /// SHA-256 over the payload — what this secret's provenance `eat_nonce` binds.
    pub fn payload_hash(&self) -> [u8; 32] {
        sha256(&self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_round_trips() {
        let p = PublicMaterial {
            server_key_digest: [0x01; 32],
            compact_public_key_digest: [0x02; 32],
            crs_digest: [0x03; 32],
            decrypt_signer_address: "0xaaaa".to_string(),
            zk_signer_address: "0xbbbb".to_string(),
            fhe_priv_digest: [0xab; 32],
            zk_signer_digest: [0xcd; 32],
            fhe_priv_share_digests: vec![],
            zk_signer_share_digests: vec![],
        };
        let bytes = p.to_canonical_bytes();
        assert_eq!(PublicMaterial::from_canonical_bytes(&bytes).unwrap(), p);

        // A non-32-byte digest field is rejected.
        let mut bad = bytes.clone();
        bad[0] = PUBLIC_VERSION; // keep version; corrupt by truncating the last digest
        bad.truncate(bad.len() - 1);
        assert!(PublicMaterial::from_canonical_bytes(&bad).is_err());
    }

    #[test]
    fn verify_artifact_accepts_match_and_rejects_mismatch() {
        let artifact = b"safe_serialized server key bytes";
        let digest = sha256(artifact);
        verify_artifact(artifact, &digest, "server_key").unwrap();
        // One flipped byte in the served object is caught fail-closed.
        let mut tampered = artifact.to_vec();
        tampered[0] ^= 0xff;
        assert!(verify_artifact(&tampered, &digest, "server_key").is_err());
    }

    #[test]
    fn public_round_trips_with_share_digests() {
        let p = PublicMaterial {
            server_key_digest: [0x01; 32],
            compact_public_key_digest: [0x02; 32],
            crs_digest: [0x03; 32],
            decrypt_signer_address: "0xaaaa".to_string(),
            zk_signer_address: "0xbbbb".to_string(),
            fhe_priv_digest: [0xab; 32],
            zk_signer_digest: [0xcd; 32],
            fhe_priv_share_digests: vec![
                ("p0".to_string(), [0x11; 32]),
                ("p1".to_string(), [0x22; 32]),
                ("p2".to_string(), [0x33; 32]),
                ("p3".to_string(), [0x44; 32]),
                ("p4".to_string(), [0x55; 32]),
            ],
            zk_signer_share_digests: vec![
                ("p0".to_string(), [0x66; 32]),
                ("p1".to_string(), [0x77; 32]),
                ("p2".to_string(), [0x88; 32]),
                ("p3".to_string(), [0x99; 32]),
                ("p4".to_string(), [0xaa; 32]),
            ],
        };
        let bytes = p.to_canonical_bytes();
        assert_eq!(PublicMaterial::from_canonical_bytes(&bytes).unwrap(), p);

        // A tampered byte anywhere is caught: hash differs, and (here) the strict
        // decoder rejects the trailing-byte / length mismatch when we truncate.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        if let Ok(decoded) = PublicMaterial::from_canonical_bytes(&tampered) {
            assert_ne!(decoded.hash(), p.hash());
        }

        // Truncating one byte breaks the strict framing and is rejected.
        let mut truncated = bytes.clone();
        truncated.truncate(truncated.len() - 1);
        assert!(PublicMaterial::from_canonical_bytes(&truncated).is_err());

        // Trailing bytes after the framed fields are rejected.
        let mut trailing = bytes;
        trailing.push(0x00);
        assert!(PublicMaterial::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn public_rejects_oversized_digest_count() {
        let p = PublicMaterial {
            server_key_digest: [0; 32],
            compact_public_key_digest: [0; 32],
            crs_digest: [0; 32],
            decrypt_signer_address: "0x".to_string(),
            zk_signer_address: "0x".to_string(),
            fhe_priv_digest: [0; 32],
            zk_signer_digest: [0; 32],
            fhe_priv_share_digests: vec![],
            zk_signer_share_digests: vec![],
        };
        let mut bytes = p.to_canonical_bytes();
        // Overwrite the fhe_priv_share_digests count prefix (just after the two
        // 32-byte full digests) with a huge value; it must be rejected by the cap.
        let count_pos = bytes.len() - 8; // two empty u32 count prefixes at the tail
        bytes[count_pos..count_pos + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(PublicMaterial::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn envelope_round_trips() {
        let e = SecretEnvelope {
            payload: vec![0xab; 64],
            provenance_jwt: "header.payload.sig".to_string(),
        };
        let bytes = e.to_canonical_bytes();
        let back = SecretEnvelope::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.payload_hash(), sha256(&e.payload));
    }

    #[test]
    fn envelope_rejects_trailing_and_unknown_version() {
        let mut trailing = SecretEnvelope {
            payload: vec![1, 2, 3],
            provenance_jwt: "a.b.c".to_string(),
        }
        .to_canonical_bytes();
        trailing.push(0x00);
        assert!(SecretEnvelope::from_canonical_bytes(&trailing).is_err());

        let mut bad_version = SecretEnvelope {
            payload: vec![1],
            provenance_jwt: "x".to_string(),
        }
        .to_canonical_bytes();
        bad_version[0] = 99;
        assert!(SecretEnvelope::from_canonical_bytes(&bad_version).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = FhePrivShare {
            client_key: vec![1; 8],
            decrypt_signer_priv: vec![2; 32],
        }
        .to_canonical_bytes();
        bytes[0] = 99;
        assert!(FhePrivShare::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(FhePrivShare::from_canonical_bytes(&[FHE_PRIV_VERSION, 0, 0]).is_err());
    }

    #[test]
    fn fhe_priv_share_round_trips() {
        let s = FhePrivShare {
            client_key: vec![0xab; 128],
            decrypt_signer_priv: vec![0x22; 32],
        };
        let bytes = s.to_canonical_bytes();
        assert_eq!(FhePrivShare::from_canonical_bytes(&bytes).unwrap(), s);
    }

    #[test]
    fn zk_signer_share_round_trips() {
        let s = ZkSignerShare {
            zk_signer_priv: vec![0x33; 32],
        };
        let bytes = s.to_canonical_bytes();
        assert_eq!(ZkSignerShare::from_canonical_bytes(&bytes).unwrap(), s);
    }

    #[test]
    fn audience_shares_are_content_bound_and_strict() {
        // hash is content-bound
        let a = FhePrivShare {
            client_key: vec![1; 16],
            decrypt_signer_priv: vec![2; 32],
        };
        let mut b = a.clone();
        b.decrypt_signer_priv[0] ^= 0xff;
        assert_ne!(a.hash(), b.hash());

        // trailing bytes rejected
        let mut t = a.to_canonical_bytes();
        t.push(0x00);
        assert!(FhePrivShare::from_canonical_bytes(&t).is_err());

        // unknown version rejected
        let mut z = ZkSignerShare {
            zk_signer_priv: vec![7; 32],
        }
        .to_canonical_bytes();
        z[0] = 99;
        assert!(ZkSignerShare::from_canonical_bytes(&z).is_err());
    }

    #[test]
    fn rejects_oversized_field_length() {
        // version + a u32 length prefix of 0xFFFFFFFF (4 GiB) > MAX_FIELD_LEN —
        // rejected by the cap before any allocation, and without overflowing.
        let bytes = [FHE_PRIV_VERSION, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(FhePrivShare::from_canonical_bytes(&bytes).is_err());
    }
}
