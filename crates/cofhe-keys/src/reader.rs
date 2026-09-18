//! Consumer-side reader: read a secret from Secret Manager and return its payload
//! bytes for the consumer to decode into the component it expects. The public
//! material has an analogous read. This is the portable half of the crate —
//! consumers (ZeeK, TeeCryptor) embed it; the keygen repo also uses it to validate
//! round-trips.
//!
//! Share authenticity rests on the partner's attested-WIF write-gate (only the
//! attested enclave can write a partner's Secret Manager version); public-material
//! integrity rests on the bucket's IAM. Consumers additionally filter liars and
//! validate the reconstructed secret against the published digests below, so a
//! bad/stale share cannot silently corrupt the result. See `DESIGN.md` for the
//! trust model and `CONSUMER-INTEGRATION.md` for the producer↔consumer split.
//!
//! Auth-agnostic by design: the caller passes already-obtained access tokens (the
//! consumer authenticates with its own identity — e.g. attested SA impersonation),
//! so this code carries no attestation/impersonation logic.
//!
//! Multi-partner Shamir: the secret is split T-of-N across partner
//! projects. A consumer reads its shard from EACH partner, filters liars against
//! the published per-share digests, and reconstructs from any T good shares. The
//! gather is fault-tolerant — a partner whose fetch fails is excluded by project
//! id (logged, non-fatal), never aborting the batch, so a single bad/absent
//! partner can be overcome while ≥ T good shares remain. [`read_shares`] is the
//! strict (abort-on-first) gather kept as a primitive; [`read_fhe_priv`] /
//! [`read_zk_signer`] route through the fault-tolerant path.

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroize;

use std::collections::BTreeSet;
use std::time::Duration;

use crate::gcs::GcsClient;
use crate::secrets::SecretManager;
use crate::serialization::{self, FhePrivShare, PublicMaterial, SecretEnvelope, ZkSignerShare};
use crate::shamir;

/// Per-partner fetch timeout for the fault-tolerant read gather. A hung partner
/// times out and is excluded; we reconstruct from the other T good shares. 30s is
/// generous vs a healthy sub-second read; worst case a dead partner delays the
/// (startup, then cached) read by this much. Distinct from the keygen write side,
/// which uses a much longer HTTP-client timeout (all-or-nothing, no tolerance).
const READ_TIMEOUT: Duration = Duration::from_secs(30);

// The baked environment source (`EnvPartner`, `EnvConfig`, `env_names`, `lookup`)
// lives in the unconditional `crate::envs` module so the write-only enclave image
// can resolve its env without the reader stack. Re-exported here so existing
// `cofhe_keys::reader::{…}` consumer paths are unchanged.
pub use crate::envs::{env_names, lookup, EnvConfig, EnvPartner};

/// One secret to read: the partner project that holds it + the secret id.
pub struct PartnerRef {
    pub project_id: String,
    pub secret_id: String,
    /// Full per-consumer WIF audience (`{wip_pool_audience}/providers/{consumer}-reader`).
    /// Carried as DATA only — the reader stays auth-agnostic; the caller uses it to
    /// obtain that partner's SM bearer. Empty when the caller authenticates another
    /// way (e.g. the verify CLI's operator token).
    pub wip_audience: String,
}

/// Builds the [`PartnerRef`]s for one consumer from the baked env: stamps the
/// per-binary `secret_id` and derives the per-consumer audience.
///
/// FAIL-CLOSED on an incomplete partner set. This is the only place the read side
/// still sees the DECLARED set. Everything downstream works on a filtered list —
/// both consumers drop a partner they could not federate with — so a gate placed
/// any later cannot tell "3 of 3" from "3 of a declared 6" and would pass an open
/// slot that simply failed to federate.
pub fn partner_refs(env: &EnvConfig, consumer: &str, secret_id: &str) -> Result<Vec<PartnerRef>> {
    env.ensure_partners_complete()
        .context("refusing to build partner references")?;
    Ok(env
        .partners
        .iter()
        .map(|p| PartnerRef {
            project_id: p.project_id.to_string(),
            secret_id: secret_id.to_string(),
            wip_audience: format!("{}/providers/{consumer}-reader", p.wip_pool_audience),
        })
        .collect())
}

/// One partner + the caller-obtained SM bearer for THAT partner. SM tokens are
/// per-partner on the read side: each partner gates reads behind its own attested
/// WIF provider, so the caller federates once per partner and pairs each token
/// with its partner here.
pub struct PartnerAccess<'a> {
    pub partner: &'a PartnerRef,
    pub sm_token: &'a str,
}

/// Read one partner's secret envelope and return its **payload bytes** (one
/// audience component's canonical bytes). Share authenticity rests on the
/// partner's attested-WIF write-gate (only the attested enclave can write the
/// secret version); the caller then filters liars and validates the reconstructed
/// secret against the published digests.
///
/// CONSUMER CONTRACT: decode the returned payload with the matching
/// `cofhe_keys::serialization` type (`FhePrivShare` / `ZkSignerShare`). When
/// deserializing the inner tfhe blobs (the FHE-priv secret's `client_key`), use
/// tfhe's `safe_deserialize` with a bounded size limit (the keygen writes with a
/// 1 GiB limit) — never the unbounded `deserialize` — so a corrupt blob can't
/// drive an unbounded allocation in the consumer.
pub async fn read_share(
    sm: &SecretManager,
    sm_token: &str,
    partner: &PartnerRef,
) -> Result<Vec<u8>> {
    let raw = sm
        .access(sm_token, &partner.project_id, &partner.secret_id)
        .await
        .with_context(|| {
            format!(
                "read secret {} for partner {}",
                partner.secret_id, partner.project_id
            )
        })?;
    let envelope = SecretEnvelope::from_canonical_bytes(raw.as_slice())
        .with_context(|| format!("decode envelope for partner {}", partner.project_id))?;
    Ok(envelope.payload)
}

/// Strict gather: read the SAME audience secret from EACH partner and return the
/// per-partner payloads in order. Any partner failing aborts the whole read. This
/// is the abort-on-first primitive; the Shamir entry points use the fault-tolerant
/// [`fetch_all`] gather instead, which tolerates per-partner failure so a single
/// bad partner can be overcome.
pub async fn read_shares(
    sm: &SecretManager,
    partners: &[PartnerAccess<'_>],
) -> Result<Vec<Vec<u8>>> {
    let mut payloads = Vec::with_capacity(partners.len());
    for a in partners {
        payloads.push(read_share(sm, a.sm_token, a.partner).await?);
    }
    Ok(payloads)
}

/// Read the public material from our bucket and return its bytes. Integrity rests
/// on the bucket's IAM; the reconstructed secret is validated downstream against
/// the digests this material carries (see [`reconstruct_and_validate`]).
pub async fn read_public(
    gcs: &GcsClient,
    gcs_token: &str,
    public_bucket: &str,
    public_object: &str,
) -> Result<Vec<u8>> {
    gcs.download(gcs_token, public_bucket, public_object)
        .await
        .context("download public material")
}

/// Fault-tolerant fetch-all-N: read every partner's share INDEPENDENTLY and
/// tolerate per-partner failure. A partner whose fetch fails is recorded as failed
/// (by project id) rather than aborting the batch — otherwise a single bad/absent
/// partner would block the whole read and we could never overcome it. Returns
/// `(successes, failed)` where `successes` is `(partner_project_id, share_bytes)`
/// and `failed` is the excluded partner ids.
///
/// Uses [`futures::future::join_all`] (NOT `try_join_all`, which fails fast) so all
/// results come back before partitioning. [`read_share`] remains the per-partner
/// unit; bad/stale share bytes are caught downstream by the per-share digest filter.
async fn fetch_all(
    sm: &SecretManager,
    partners: &[PartnerAccess<'_>],
) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let results = futures::future::join_all(partners.iter().map(|a| async move {
        // Per-partner timeout: a hung partner must not stall the whole gather. On
        // timeout it's treated as a failure -> excluded, and we reconstruct from the
        // other T good shares (join_all still waits for the rest, capped at this).
        let r =
            match tokio::time::timeout(READ_TIMEOUT, read_share(sm, a.sm_token, a.partner)).await {
                Ok(res) => res,
                Err(_) => Err(anyhow!("partner fetch timed out after {READ_TIMEOUT:?}")),
            };
        (a.partner.project_id.clone(), r)
    }))
    .await;

    let mut successes = Vec::with_capacity(results.len());
    let mut failed = Vec::new();
    for (project_id, res) in results {
        match res {
            Ok(share) => successes.push((project_id, share)),
            Err(e) => {
                tracing::warn!(partner = %project_id, error = %e, "partner fetch/verify failed; excluding");
                failed.push(project_id);
            }
        }
    }
    (successes, failed)
}

/// The partners whose fetched share failed its published per-share digest — a
/// lying/tampered/stale partner, or a fetch that returned the wrong bytes. Named by
/// partner project id. Reported on success (liars were overcome, but logged) and
/// named in the error on failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiarReport {
    pub liars: Vec<String>,
}

/// Reconstruct a Shamir-split secret, filtering liars via the published per-share
/// digests BEFORE interpolating — plain Shamir can't error-correct, so one bad
/// share among the chosen T silently corrupts the result. `fetched` is
/// `(partner_project_id, share)` with DISTINCT ids (duplicates are rejected);
/// `per_share_digests` maps each partner id to its expected share digest;
/// `full_digest` is the published reconstruction anchor; `threshold` (T) must be
/// ≥ 2 (`shamir::MIN_THRESHOLD`). A partner whose share fails its digest is excluded (logged, non-fatal)
/// while ≥ T good shares remain. Errors when fewer than T pass (unrecoverable;
/// names the liars), or — distinctly — when T digest-passing shares reconstruct to
/// the wrong full digest (a producer bug, not a partner's fault). Our intermediate
/// share copies are zeroized on every exit.
pub fn reconstruct_and_validate(
    fetched: &[(String, Vec<u8>)],
    per_share_digests: &[(String, [u8; 32])],
    full_digest: &[u8; 32],
    threshold: u8,
) -> Result<(Vec<u8>, LiarReport)> {
    if threshold < shamir::MIN_THRESHOLD {
        bail!("shamir threshold must be >= {}", shamir::MIN_THRESHOLD);
    }
    // Distinct partners only: a duplicated id would let one partner's share occupy
    // two reconstruction slots (same Shamir x-coordinate), which can never form T
    // distinct points — reject up front rather than fail opaquely later.
    let mut seen = std::collections::HashSet::with_capacity(fetched.len());
    for (id, _) in fetched {
        if !seen.insert(id.as_str()) {
            bail!("duplicate partner id {id} in fetched shares");
        }
    }

    let mut good: Vec<Vec<u8>> = Vec::with_capacity(fetched.len());
    let mut report = LiarReport::default();
    for (id, share) in fetched {
        if per_share_digests
            .iter()
            .any(|(pid, d)| pid == id && serialization::sha256(share) == *d)
        {
            good.push(share.clone());
        } else {
            tracing::warn!(partner = %id, "share failed its per-share digest; excluding");
            report.liars.push(id.clone());
        }
    }
    if good.len() < threshold as usize {
        let passed = good.len();
        good.iter_mut().for_each(Zeroize::zeroize);
        bail!(
            "unrecoverable: {} share(s) passed their digest, need {}; liars: {:?}",
            passed,
            threshold,
            report.liars
        );
    }
    // T of these clones reconstruct the whole secret — zeroize them on every exit
    // (success or failure), since they are transient copies we own.
    let recovered = shamir::reconstruct(&good[..threshold as usize], threshold);
    good.iter_mut().for_each(Zeroize::zeroize);
    let payload = recovered?;
    if serialization::sha256(&payload) != *full_digest {
        bail!("producer/internal inconsistency: digest-passing shares reconstruct to a payload missing the full digest");
    }
    Ok((payload, report))
}

/// The stable wiring a consumer holds for the lifetime of a read: the Secret
/// Manager + GCS clients, the GCS access token, and the public-material location.
/// Bundled so the entry points take few arguments and the per-call inputs
/// (`partners`, `threshold`) stay explicit.
///
/// SM tokens are PER-PARTNER on the read side (each partner gates reads behind
/// its own attested WIF provider), so they ride with each partner in
/// [`PartnerAccess`] rather than here. `gcs_token` stays: the public material is
/// non-secret and read with a single caller-owned token.
pub struct ReaderContext<'a> {
    pub sm: &'a SecretManager,
    pub gcs: &'a GcsClient,
    pub gcs_token: &'a str,
    pub public_bucket: &'a str,
    pub public_object: &'a str,
}

/// Read + verify the public material, fault-tolerantly gather every partner's
/// share, reconstruct the T-of-N Shamir secret filtering liars by published digest,
/// and validate against the published full digest. `select_share_digests` /
/// `select_full_digest` pick the per-secret anchors; `label` names the secret.
///
/// Excluded partners come from TWO sources: those whose fetch failed
/// ([`fetch_all`]) and those whose share failed its per-share digest
/// ([`reconstruct_and_validate`]'s [`LiarReport`]). On success we `warn!` the
/// merged set (served despite them). On the unrecoverable error we surface BOTH
/// sets so every bad/absent partner is named — no silent failures.
async fn read_reconstruct_validate(
    ctx: &ReaderContext<'_>,
    partners: &[PartnerAccess<'_>],
    threshold: u8,
    select_share_digests: impl Fn(&PublicMaterial) -> Vec<(String, [u8; 32])>,
    select_full_digest: impl Fn(&PublicMaterial) -> [u8; 32],
    label: &str,
) -> Result<Vec<u8>> {
    // Fail-closed on an unfilled partner slot. Without this the tolerant gather would
    // simply drop the placeholder partners and reconstruct from whatever real ones
    // remain — silently running at a smaller N than the env declares.
    // Defence in depth behind `partner_refs`, which is the gate that actually sees
    // the declared set. This catches a hand-built list that never went through it.
    // Same predicate as `EnvConfig::ensure_partners_complete`: id AND audience, since
    // the id and the project number come from separate fields of the partner's form.
    if let Some(p) = partners.iter().find(|p| {
        p.partner
            .project_id
            .contains(crate::envs::PARTNER_PLACEHOLDER)
            || p.partner
                .wip_audience
                .contains(crate::envs::PARTNER_PLACEHOLDER)
    }) {
        bail!(
            "{label}: partner {:?} is an unfilled placeholder slot; refusing to \
             reconstruct from a partial set",
            p.partner.project_id
        );
    }

    let public_bytes =
        read_public(ctx.gcs, ctx.gcs_token, ctx.public_bucket, ctx.public_object).await?;
    let public =
        PublicMaterial::from_canonical_bytes(&public_bytes).context("decode public material")?;

    let (mut successes, fetch_failed) = fetch_all(ctx.sm, partners).await;

    let share_digests = select_share_digests(&public);
    let full_digest = select_full_digest(&public);

    let result = reconstruct_and_validate(&successes, &share_digests, &full_digest, threshold);
    // Wipe our gathered share copies (secret material) on EVERY path —
    // `reconstruct_and_validate` already zeroized its own working set; this clears
    // the gather's. The bytes are no longer needed once reconstruction has run.
    successes.iter_mut().for_each(|(_, s)| s.zeroize());

    match result {
        Ok((payload, report)) => {
            // Merge fetch-failed (absent/unverified) with digest-liars (bad bytes):
            // every partner we served despite, named once, deduplicated/sorted.
            let excluded: BTreeSet<&str> = fetch_failed
                .iter()
                .chain(report.liars.iter())
                .map(String::as_str)
                .collect();
            if !excluded.is_empty() {
                tracing::warn!(
                    secret = label,
                    excluded = ?excluded,
                    "reconstructed {label} despite excluded partners (fetch-failed ∪ digest-liars)"
                );
            }
            Ok(payload)
        }
        Err(e) => {
            // Unrecoverable: name BOTH the digest-liars (already in `e`) and the
            // fetch-failed partners (absent from the reconstruct call) so the log
            // accounts for every bad/absent partner.
            bail!("{label}: {e}; fetch-failed partners: {fetch_failed:?}");
        }
    }
}

/// TeeCryptor entry point: read + verify + Shamir-reconstruct the FHE-priv secret,
/// validate it against the published digest, and return the typed component (the
/// caller feeds `client_key` to its `KeyStore` and `decrypt_signer_priv` to its
/// signer). See `CONSUMER-INTEGRATION.md`.
pub async fn read_fhe_priv(
    ctx: &ReaderContext<'_>,
    partners: &[PartnerAccess<'_>],
    threshold: u8,
) -> Result<FhePrivShare> {
    let payload = read_reconstruct_validate(
        ctx,
        partners,
        threshold,
        |p| p.fhe_priv_share_digests.clone(),
        |p| p.fhe_priv_digest,
        "fhe-priv",
    )
    .await?;
    FhePrivShare::from_canonical_bytes(&payload).context("decode FhePrivShare")
}

/// ZK verifier entry point: same pipeline for the zk-signer secret (the caller
/// feeds `zk_signer_priv` to its `SigningKey`).
pub async fn read_zk_signer(
    ctx: &ReaderContext<'_>,
    partners: &[PartnerAccess<'_>],
    threshold: u8,
) -> Result<ZkSignerShare> {
    let payload = read_reconstruct_validate(
        ctx,
        partners,
        threshold,
        |p| p.zk_signer_share_digests.clone(),
        |p| p.zk_signer_digest,
        "zk-signer",
    )
    .await?;
    ZkSignerShare::from_canonical_bytes(&payload).context("decode ZkSignerShare")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::{sha256, FhePrivShare, PublicMaterial, ZkSignerShare};
    use base64::Engine as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // The baked ENVIRONMENTS map + `lookup` are tested in `crate::envs`.

    #[test]
    fn partner_refs_stamps_secret_and_consumer_audience() {
        let env = lookup("staging").unwrap();
        let refs = partner_refs(env, "teecryptor", "cofhe-tee-fhe-priv").unwrap();
        assert_eq!(refs.len(), 5);
        assert_eq!(refs[0].project_id, "cofhe-tee-partner-1");
        assert_eq!(refs[0].secret_id, "cofhe-tee-fhe-priv");
        assert!(refs[0]
            .wip_audience
            .ends_with("/providers/teecryptor-reader"));
        assert!(refs[0]
            .wip_audience
            .contains("/workloadIdentityPools/cofhe-tee-reader-pool/"));
    }

    // The gate that actually protects the read side. An env with an open slot must
    // fail HERE, before any federation: both consumers drop a partner they could not
    // federate with, so a placeholder that got this far would simply vanish from the
    // list and the reconstruct would succeed at a silently reduced N.
    #[test]
    fn partner_refs_refuses_an_incomplete_partner_set() {
        // A fixture, not a baked env: every baked env is complete now.
        let partners: &'static [crate::envs::EnvPartner] = Box::leak(
            vec![crate::envs::EnvPartner {
                project_id: "FILL-ME-PARTNER-9",
                wip_pool_audience: "//iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/cofhe-tee-reader-pool",
                keygen_write_audience: "//iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider",
            }]
            .into_boxed_slice(),
        );
        let fixture = EnvConfig {
            partners,
            public_bucket: "b",
            public_object: "p/0/public-material",
            public_prefix: "p",
            public_zone: 0,
            shamir_threshold: 2,
        };
        let env = &fixture;
        // `PartnerRef` is deliberately not `Debug`, so match rather than `expect_err`.
        let err = match partner_refs(env, "teecryptor", "cofhe-tee-fhe-priv") {
            Ok(_) => panic!("an open partner slot must fail closed"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("refusing to build partner references"),
            "{err}"
        );
    }

    // The reader ignores `provenance_jwt`; envelopes carry an empty one.
    fn envelope_b64(payload: Vec<u8>) -> String {
        let env = SecretEnvelope {
            payload,
            provenance_jwt: String::new(),
        };
        base64::engine::general_purpose::STANDARD.encode(env.to_canonical_bytes())
    }

    // Round-trip: serialize a component as the writer would, wrap it in an
    // envelope, serve it from a mock Secret Manager, and confirm the reader reads
    // and returns the payload that decodes back to the component.
    #[tokio::test]
    async fn reads_share() {
        let fhe = FhePrivShare {
            client_key: vec![0xab; 128],
            decrypt_signer_priv: vec![0x22; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let encoded = envelope_b64(payload.clone());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-1/secrets/cofhe-tee-fhe-priv/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/x/secrets/cofhe-tee-fhe-priv/versions/3",
                "payload": { "data": encoded }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let partner = PartnerRef {
            project_id: "partner-1".to_string(),
            secret_id: "cofhe-tee-fhe-priv".to_string(),
            wip_audience: String::new(),
        };
        let got = read_share(&sm, "sm-tok", &partner).await.unwrap();
        assert_eq!(got, payload);
        assert_eq!(FhePrivShare::from_canonical_bytes(&got).unwrap(), fhe);
    }

    #[tokio::test]
    async fn reads_public() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/our-bucket/o/public-material"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PUBLIC".to_vec()))
            .mount(&server)
            .await;

        let gcs = GcsClient::new(server.uri());
        let bytes = read_public(&gcs, "gcs-tok", "our-bucket", "public-material")
            .await
            .unwrap();
        assert_eq!(bytes, b"PUBLIC");
    }

    // Multi-partner gather (the Shamir-ready primitive): reads each partner's
    // secret in order and returns one payload per partner.
    #[tokio::test]
    async fn read_shares_gathers_all_partners() {
        let p1 = FhePrivShare {
            client_key: vec![1; 64],
            decrypt_signer_priv: vec![2; 32],
        }
        .to_canonical_bytes();
        let p2 = ZkSignerShare {
            zk_signer_priv: vec![3; 32],
        }
        .to_canonical_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-1/secrets/cofhe-tee-fhe-priv/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "v",
                "payload": { "data": envelope_b64(p1.clone()) }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-2/secrets/cofhe-tee-zk-signer/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "v",
                "payload": { "data": envelope_b64(p2.clone()) }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let partners = [
            PartnerRef {
                project_id: "partner-1".to_string(),
                secret_id: "cofhe-tee-fhe-priv".to_string(),
                wip_audience: String::new(),
            },
            PartnerRef {
                project_id: "partner-2".to_string(),
                secret_id: "cofhe-tee-zk-signer".to_string(),
                wip_audience: String::new(),
            },
        ];
        let got = read_shares(&sm, &same_token(&partners, "tok"))
            .await
            .unwrap();
        assert_eq!(got, vec![p1, p2]);
    }

    // Any single partner failing aborts the whole gather (no partial vec) — the
    // fail-closed invariant a threshold reconstruction depends on. Here partner-2
    // returns bytes that aren't a valid envelope.
    #[tokio::test]
    async fn read_shares_aborts_if_one_partner_fails() {
        let good = FhePrivShare {
            client_key: vec![1; 64],
            decrypt_signer_priv: vec![2; 32],
        }
        .to_canonical_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-1/secrets/cofhe-tee-fhe-priv/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "v",
                "payload": { "data": envelope_b64(good.clone()) }
            })))
            .mount(&server)
            .await;
        // partner-2 returns non-envelope bytes → its read fails → the gather aborts.
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-2/secrets/cofhe-tee-zk-signer/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "v",
                "payload": { "data": base64::engine::general_purpose::STANDARD.encode(b"not-an-envelope") }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let partners = [
            PartnerRef {
                project_id: "partner-1".to_string(),
                secret_id: "cofhe-tee-fhe-priv".to_string(),
                wip_audience: String::new(),
            },
            PartnerRef {
                project_id: "partner-2".to_string(),
                secret_id: "cofhe-tee-zk-signer".to_string(),
                wip_audience: String::new(),
            },
        ];
        assert!(read_shares(&sm, &same_token(&partners, "tok"))
            .await
            .is_err());
    }

    // A secret whose bytes aren't a valid envelope is rejected (not a panic).
    #[tokio::test]
    async fn read_share_rejects_malformed_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/partner-1/secrets/cofhe-tee-fhe-priv/versions/latest:access",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "v",
                "payload": { "data": base64::engine::general_purpose::STANDARD.encode(b"not-an-envelope") }
            })))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        let partner = PartnerRef {
            project_id: "partner-1".to_string(),
            secret_id: "cofhe-tee-fhe-priv".to_string(),
            wip_audience: String::new(),
        };
        assert!(read_share(&sm, "tok", &partner).await.is_err());
    }

    // ---- reconstruct_and_validate: the LOCKED liar-detection flow ------------

    // (fetched (partner_id, share) pairs, per-partner share digest map, full digest).
    type SplitFixture = (Vec<(String, Vec<u8>)>, Vec<(String, [u8; 32])>, [u8; 32]);

    // Split a payload N/T, keying each share by partner id `partner-{i}`, so each
    // test can inject tampering at will.
    fn split_fixture(payload: &[u8], n: u8, t: u8) -> SplitFixture {
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(payload, n, t, &mut rng).unwrap();
        let ids: Vec<String> = (0..shares.len()).map(|i| format!("partner-{i}")).collect();
        let per_share: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();
        let full = sha256(payload);
        let fetched = ids.into_iter().zip(shares).collect();
        (fetched, per_share, full)
    }

    #[test]
    fn rcv_zero_liars_reconstructs() {
        let payload = b"no liars here".to_vec();
        let (fetched, per_share, full) = split_fixture(&payload, 5, 2);
        let (got, report) = reconstruct_and_validate(&fetched, &per_share, &full, 2).unwrap();
        assert_eq!(got, payload);
        assert!(report.liars.is_empty());
    }

    #[test]
    fn rcv_rejects_duplicate_partner_id() {
        let payload = b"dup id".to_vec();
        let (mut fetched, per_share, full) = split_fixture(&payload, 5, 2);
        // One partner cannot fill two reconstruction slots.
        fetched.push(fetched[1].clone());
        let err = reconstruct_and_validate(&fetched, &per_share, &full, 2)
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate partner id"), "got: {err}");
    }

    #[test]
    fn rcv_rejects_zero_threshold() {
        let payload = b"t=0".to_vec();
        let (fetched, per_share, full) = split_fixture(&payload, 5, 2);
        assert!(reconstruct_and_validate(&fetched, &per_share, &full, 0).is_err());
    }

    #[test]
    fn rcv_one_liar_overcome_and_recorded() {
        let payload = b"one tampered share".to_vec();
        let (mut fetched, per_share, full) = split_fixture(&payload, 5, 2);
        // Tamper partner-0's share (flip a payload byte).
        let last = fetched[0].1.len() - 1;
        fetched[0].1[last] ^= 0xff;

        let (got, report) = reconstruct_and_validate(&fetched, &per_share, &full, 2).unwrap();
        assert_eq!(got, payload, "the 4 honest shares still reconstruct");
        assert_eq!(report.liars, vec!["partner-0".to_string()]);
    }

    #[test]
    fn rcv_n_minus_t_liars_overcome() {
        // N=5, T=2 → up to N-T=3 liars survivable.
        let payload = b"three liars, two honest".to_vec();
        let (mut fetched, per_share, full) = split_fixture(&payload, 5, 2);
        for f in fetched.iter_mut().take(3) {
            let last = f.1.len() - 1;
            f.1[last] ^= 0xff;
        }
        let (got, report) = reconstruct_and_validate(&fetched, &per_share, &full, 2).unwrap();
        assert_eq!(got, payload);
        assert_eq!(
            report.liars,
            vec![
                "partner-0".to_string(),
                "partner-1".to_string(),
                "partner-2".to_string(),
            ]
        );
    }

    #[test]
    fn rcv_more_than_n_minus_t_liars_fails_naming_all() {
        // N=5, T=2 → 4 liars leaves only 1 honest share < T: unrecoverable.
        let payload = b"too many liars".to_vec();
        let (mut fetched, per_share, full) = split_fixture(&payload, 5, 2);
        for f in fetched.iter_mut().take(4) {
            let last = f.1.len() - 1;
            f.1[last] ^= 0xff;
        }
        let err = reconstruct_and_validate(&fetched, &per_share, &full, 2)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unrecoverable"), "got: {err}");
        // All four liars are named.
        for i in 0..4 {
            let id = format!("partner-{i}");
            assert!(err.contains(&id), "liar {id} missing from: {err}");
        }
    }

    #[test]
    fn rcv_producer_inconsistency_distinct_error() {
        // All shares pass their per-share digest, but the published FULL digest is
        // wrong → producer/internal inconsistency, NOT a partner's fault.
        let payload = b"valid shares, bad full digest".to_vec();
        let (fetched, per_share, _full) = split_fixture(&payload, 5, 2);
        let wrong_full = [0xab; 32];
        let err = reconstruct_and_validate(&fetched, &per_share, &wrong_full, 2)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("producer/internal inconsistency"),
            "got: {err}"
        );
    }

    #[test]
    fn rcv_unknown_partner_id_is_a_liar() {
        let payload = b"unknown id".to_vec();
        let (mut fetched, per_share, full) = split_fixture(&payload, 5, 2);
        // Relabel one fetched share to a partner with no published digest entry.
        fetched[0].0 = "ghost-partner".to_string();
        let (got, report) = reconstruct_and_validate(&fetched, &per_share, &full, 2).unwrap();
        assert_eq!(got, payload);
        assert_eq!(report.liars, vec!["ghost-partner".to_string()]);
    }

    // ---- Multi-partner Shamir entry point (read_fhe_priv) --------------------

    // How a partner should respond when its fhe-priv secret is fetched.
    enum Serve {
        // Serve the given share bytes wrapped in an envelope — the bytes match the
        // partner's published per-share digest.
        ShareOk(Vec<u8>),
        // Serve bytes that do NOT match the partner's published per-share digest (a
        // stale/swapped share): the fetch succeeds but the bytes are filtered as a
        // digest-liar during reconstruction.
        WrongBytes(Vec<u8>),
        // Return HTTP 500: the fetch itself fails.
        FetchFails,
    }

    // Start a mock server and mount the public material (carrying the published
    // full + per-share fhe-priv digests for the real split). Shared by the fhe-priv
    // split helpers.
    async fn serve_public_material(
        full_digest: [u8; 32],
        share_digests: Vec<(String, [u8; 32])>,
    ) -> MockServer {
        let public = PublicMaterial {
            server_key_digest: [1u8; 32],
            compact_public_key_digest: [2u8; 32],
            crs_digest: [3u8; 32],
            decrypt_signer_address: "0xaa".to_string(),
            zk_signer_address: "0xbb".to_string(),
            fhe_priv_digest: full_digest,
            zk_signer_digest: [0u8; 32],
            fhe_priv_share_digests: share_digests,
            zk_signer_share_digests: vec![],
        };
        let public_bytes = public.to_canonical_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/our-bucket/o/public-material"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(public_bytes.clone()))
            .mount(&server)
            .await;
        server
    }

    // Build the partner refs + a server that serves the public material (carrying
    // the published full + per-share digests for the real split) and serves each
    // partner's fhe-priv secret per its `Serve` directive.
    async fn serve_fhe_priv_split(
        full_digest: [u8; 32],
        share_digests: Vec<(String, [u8; 32])>,
        partners: &[(String, Serve)],
    ) -> (MockServer, Vec<PartnerRef>) {
        let server = serve_public_material(full_digest, share_digests).await;

        let mut refs = Vec::with_capacity(partners.len());
        for (pid, serve) in partners {
            let p = format!("/v1/projects/{pid}/secrets/cofhe-tee-fhe-priv/versions/latest:access");
            let template = match serve {
                Serve::ShareOk(bytes) | Serve::WrongBytes(bytes) => ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "name": "v", "payload": { "data":
                        envelope_b64(bytes.clone()) } })),
                Serve::FetchFails => ResponseTemplate::new(500),
            };
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(template)
                .mount(&server)
                .await;
            refs.push(PartnerRef {
                project_id: pid.clone(),
                secret_id: "cofhe-tee-fhe-priv".to_string(),
                wip_audience: String::new(),
            });
        }
        (server, refs)
    }

    fn ctx<'a>(sm: &'a SecretManager, gcs: &'a GcsClient) -> ReaderContext<'a> {
        ReaderContext {
            sm,
            gcs,
            gcs_token: "gtok",
            public_bucket: "our-bucket",
            public_object: "public-material",
        }
    }

    // Wrap each ref in a [`PartnerAccess`] carrying the SAME token — the shape for
    // tests that don't exercise per-partner tokens (the mock SM ignores bearers).
    fn same_token<'a>(refs: &'a [PartnerRef], token: &'a str) -> Vec<PartnerAccess<'a>> {
        refs.iter()
            .map(|p| PartnerAccess {
                partner: p,
                sm_token: token,
            })
            .collect()
    }

    // 5 partners, T=2, all-good → reconstructs to the original secret with an empty
    // excluded set.
    #[tokio::test]
    async fn read_fhe_priv_5_partners_all_good() {
        let fhe = FhePrivShare {
            client_key: vec![0xab; 128],
            decrypt_signer_priv: vec![0x22; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, 5, 2, &mut rng).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("partner-{i}")).collect();
        let digests: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();

        let partners: Vec<(String, Serve)> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), Serve::ShareOk(s.clone())))
            .collect();
        let (server, refs) = serve_fhe_priv_split(sha256(&payload), digests, &partners).await;
        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());

        let got = read_fhe_priv(&ctx(&sm, &gcs), &same_token(&refs, "tok"), 2)
            .await
            .unwrap();
        assert_eq!(got, fhe);
    }

    // Per-partner SM tokens: each partner is wrapped in a PartnerAccess carrying a
    // DISTINCT token, and each partner's mock SM ONLY answers when called with THAT
    // partner's bearer (`.and(header("authorization", "Bearer tok-{i}"))`). If the
    // reader collapsed to a single shared token, four of the five mocks would go
    // unmatched (404 → fetch failure) and only 1 good share < T=2 would remain,
    // failing reconstruction. Passing therefore proves each partner's read is
    // issued with ITS OWN token threaded through fetch_all.
    #[tokio::test]
    async fn read_fhe_priv_uses_per_partner_tokens() {
        let fhe = FhePrivShare {
            client_key: vec![0x09; 96],
            decrypt_signer_priv: vec![0x0a; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, 5, 2, &mut rng).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("partner-{i}")).collect();
        let digests: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();
        let tokens: Vec<String> = (0..5).map(|i| format!("tok-{i}")).collect();

        // Public material, then one partner mock each that is gated on
        // the partner's OWN bearer token.
        let server = serve_public_material(sha256(&payload), digests).await;
        let mut refs = Vec::with_capacity(ids.len());
        for ((id, share), token) in ids.iter().zip(&shares).zip(&tokens) {
            let p = format!("/v1/projects/{id}/secrets/cofhe-tee-fhe-priv/versions/latest:access");
            Mock::given(method("GET"))
                .and(path(p))
                .and(header("authorization", format!("Bearer {token}").as_str()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "v",
                    "payload": { "data": envelope_b64(share.clone()) }
                })))
                .mount(&server)
                .await;
            refs.push(PartnerRef {
                project_id: id.clone(),
                secret_id: "cofhe-tee-fhe-priv".to_string(),
                wip_audience: String::new(),
            });
        }

        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());

        let accesses: Vec<PartnerAccess> = refs
            .iter()
            .zip(&tokens)
            .map(|(partner, t)| PartnerAccess {
                partner,
                sm_token: t,
            })
            .collect();
        let got = read_fhe_priv(&ctx(&sm, &gcs), &accesses, 2).await.unwrap();
        assert_eq!(got, fhe);
    }

    // One partner's fetch fails (HTTP 500) → overcome by the other 4, the key is
    // still correct.
    #[tokio::test]
    async fn read_fhe_priv_one_fetch_failure_overcome() {
        let fhe = FhePrivShare {
            client_key: vec![0x01; 64],
            decrypt_signer_priv: vec![0x02; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, 5, 2, &mut rng).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("partner-{i}")).collect();
        let digests: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();

        let mut partners: Vec<(String, Serve)> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), Serve::ShareOk(s.clone())))
            .collect();
        partners[0].1 = Serve::FetchFails; // partner-0 down

        let (server, refs) = serve_fhe_priv_split(sha256(&payload), digests, &partners).await;
        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());

        let got = read_fhe_priv(&ctx(&sm, &gcs), &same_token(&refs, "tok"), 2)
            .await
            .unwrap();
        assert_eq!(got, fhe);
    }

    // One partner serves bytes that don't match its published per-share digest
    // (a stale/swapped share) → excluded as a digest-liar, overcome by the rest.
    #[tokio::test]
    async fn read_fhe_priv_one_digest_liar_overcome() {
        let fhe = FhePrivShare {
            client_key: vec![0x05; 80],
            decrypt_signer_priv: vec![0x06; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, 5, 2, &mut rng).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("partner-{i}")).collect();
        let digests: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();

        // partner-2 serves tampered bytes: the fetch succeeds but the bytes fail
        // partner-2's published per-share digest.
        let mut tampered = shares[2].clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let mut partners: Vec<(String, Serve)> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), Serve::ShareOk(s.clone())))
            .collect();
        partners[2].1 = Serve::WrongBytes(tampered);

        let (server, refs) = serve_fhe_priv_split(sha256(&payload), digests, &partners).await;
        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());

        let got = read_fhe_priv(&ctx(&sm, &gcs), &same_token(&refs, "tok"), 2)
            .await
            .unwrap();
        assert_eq!(got, fhe);
    }

    // More than N−T partners are bad (4 of 5: a fetch failure and three
    // digest-liars) → only 1 good share < T=2: unrecoverable, and the error names
    // every bad/absent partner (both fetch-failed and digest-liars).
    #[tokio::test]
    async fn read_fhe_priv_too_many_bad_fails_naming_all() {
        let fhe = FhePrivShare {
            client_key: vec![0x07; 64],
            decrypt_signer_priv: vec![0x08; 32],
        };
        let payload = fhe.to_canonical_bytes();
        let mut rng = shamir::new_csprng();
        let shares = shamir::split(&payload, 5, 2, &mut rng).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("partner-{i}")).collect();
        let digests: Vec<(String, [u8; 32])> = ids
            .iter()
            .zip(&shares)
            .map(|(id, s)| (id.clone(), sha256(s)))
            .collect();

        let tamper = |s: &Vec<u8>| {
            let mut t = s.clone();
            let last = t.len() - 1;
            t[last] ^= 0xff;
            t
        };
        let partners: Vec<(String, Serve)> = vec![
            (ids[0].clone(), Serve::FetchFails),                     // absent
            (ids[1].clone(), Serve::WrongBytes(tamper(&shares[1]))), // liar
            (ids[2].clone(), Serve::WrongBytes(tamper(&shares[2]))), // liar
            (ids[3].clone(), Serve::WrongBytes(tamper(&shares[3]))), // liar
            (ids[4].clone(), Serve::ShareOk(shares[4].clone())),     // lone good
        ];

        let (server, refs) = serve_fhe_priv_split(sha256(&payload), digests, &partners).await;
        let sm = SecretManager::new(server.uri());
        let gcs = GcsClient::new(server.uri());

        let err = read_fhe_priv(&ctx(&sm, &gcs), &same_token(&refs, "tok"), 2)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unrecoverable"), "got: {err}");
        // Every bad/absent partner is named (fetch-failed ∪ digest-liars).
        for i in 0..4 {
            let id = format!("partner-{i}");
            assert!(err.contains(&id), "bad partner {id} missing from: {err}");
        }
    }
}
