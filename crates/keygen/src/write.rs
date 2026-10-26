use crate::attestation::AttestationClient;
use crate::config::{Config, Mode};
use crate::{federate, Run, PROVENANCE_AUDIENCE};
use anyhow::{bail, Context, Result};
use cofhe_keys::keygen;
use cofhe_keys::secrets::{self, SecretManager};
use cofhe_keys::serialization::{sha256, SecretEnvelope};
use std::num::NonZeroU64;
use tracing::info;

// The payload of a filler version. It is not an envelope, so a read of a filler
// fails closed.
#[cfg(not(feature = "mock"))]
const FILLER: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

// Deliver the SECRET shares to every target partner, each at the baked
// `share_version`. Each partner gets its share of each per-audience secret, written
// to its OWN Secret Manager secret with its own provenance token (eat_nonce =
// SHA-256(share)), so the partner can grant each consumer least-privilege read via
// IAM: TeeCryptor reads fhe-priv (FHE priv + decrypt signer); the ZK verifier reads
// zk-signer. See CONSUMER-INTEGRATION.md.
//
// The precheck runs on every partner before any write, and every filler before any
// share, so a stop before the shares leaves the target version free.
#[cfg(not(feature = "mock"))]
pub(crate) async fn deliver_shares(
    cfg: &Config,
    run: &Run,
    partner_shares: &[keygen::PartnerShares],
    written: &mut Vec<Written>,
) -> Result<()> {
    let target = cfg.env.share_version.get();
    let secret_ids = [&cfg.write_secret_fhe_priv, &cfg.write_secret_zk_signer];

    // Destroyed versions are listed too, and their numbers are never reused.
    let mut checked = Vec::with_capacity(cfg.partners.len());
    for partner in &cfg.partners {
        let p = &partner.project_id;
        info!(partner = %p, "federating with partner for the write");
        // Reused for this partner's fillers and shares; if it expires mid-run, the
        // next add fails closed.
        let token = federate(run, &partner.wip_audience).await?;
        let mut newest = [0; 2];
        for (slot, s) in newest.iter_mut().zip(secret_ids) {
            *slot = run
                .sm
                .newest_version(&token, p, s)
                .await?
                .map_or(0, NonZeroU64::get);
            if *slot >= target {
                return Err(anyhow::anyhow!(
                    "partner {p} secret {s} is already at version {slot}; the target is {target}. Bake a higher share_version"
                )
                .context(PrecheckStop));
            }
        }
        checked.push((partner, token, newest));
    }

    for (partner, token, newest) in &checked {
        let p = &partner.project_id;
        for (s, &n) in secret_ids.into_iter().zip(newest) {
            for expected in n + 1..target {
                info!(partner = %p, secret = %s, version = expected, "writing filler");
                let name = run
                    .sm
                    .add_version(token, p, s, FILLER)
                    .await
                    .map_err(|e| e.context(AddFailed))?;
                let got = secrets::version_number(&name)?.get();
                record(written, p, s, expected, got, true)?;
            }
        }
    }

    for ((partner, token, _), shares) in checked.iter().zip(partner_shares) {
        let p = &partner.project_id;
        for (s, share) in secret_ids
            .into_iter()
            .zip([&shares.fhe_priv_share, &shares.zk_signer_share])
        {
            info!(partner = %p, secret = %s, version = target, "writing share");
            let name = write_secret(&run.attest, &run.sm, token, p, s, share.clone()).await?;
            let got = secrets::version_number(&name).context(AddFailed)?.get();
            record(written, p, s, target, got, false)?;
        }
    }
    Ok(())
}

// Record a version this run wrote, then stop if Secret Manager gave it another
// number than the one expected (a timed-out add can still create a version).
#[cfg(not(feature = "mock"))]
fn record(
    written: &mut Vec<Written>,
    partner: &str,
    secret: &str,
    expected: u64,
    got: u64,
    filler: bool,
) -> Result<()> {
    written.push(Written {
        partner: partner.to_string(),
        secret: secret.to_string(),
        version: got,
        filler,
    });
    if got != expected {
        bail!(
            "partner {partner} secret {secret}: expected version {expected}, Secret Manager returned {got}"
        );
    }
    Ok(())
}

// One version this run wrote: a real share, or a filler below the target.
#[cfg(not(feature = "mock"))]
pub(crate) struct Written {
    partner: String,
    secret: String,
    version: u64,
    filler: bool,
}

// Marks an error from a Secret Manager add: the add may still have created the
// version, so the report cannot promise that the target is free.
#[cfg(not(feature = "mock"))]
#[derive(Debug)]
struct AddFailed;

#[cfg(not(feature = "mock"))]
impl std::fmt::Display for AddFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a Secret Manager add failed")
    }
}

// Marks the precheck stop: nothing is written, and the error itself says what to
// do, so it gets no recovery report.
#[cfg(not(feature = "mock"))]
#[derive(Debug)]
struct PrecheckStop;

#[cfg(not(feature = "mock"))]
impl std::fmt::Display for PrecheckStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the precheck stopped the run before any write")
    }
}

// A stop after the first write changes what recovery needs, and what a consumer
// that restarts now can read. Say it in the error, from what this run knows.
#[cfg(not(feature = "mock"))]
pub(crate) fn with_report(
    e: anyhow::Error,
    cfg: &Config,
    written: &[Written],
    published: &[String],
) -> anyhow::Error {
    if e.downcast_ref::<PrecheckStop>().is_some() {
        return e;
    }
    let in_add = e.downcast_ref::<AddFailed>().is_some();
    let report = recovery_report(cfg, written, published, in_add);
    tracing::error!(report = %report, "run stopped; recovery report");
    e.context(report)
}

// What a stopped run leaves behind, and how to rerun. `published` lists the
// public-material objects this run already wrote; `in_add` says the run stopped
// inside an add.
#[cfg(not(feature = "mock"))]
fn recovery_report(
    cfg: &Config,
    written: &[Written],
    published: &[String],
    in_add: bool,
) -> String {
    let target = cfg.env.share_version.get();
    let mut lines = vec![match cfg.mode {
        _ if cfg.env.replace_live_keyset => "This run replaces the live keyset: the shared public artifacts may already be overwritten. Rotation recovery is out of scope.".to_string(),
        // The legacy manifest is what legacy consumers read, and this run overwrites
        // it; a lost upload response can hide a finished publish.
        Mode::Reshare(r) if r.legacy_manifest => format!(
            "This run also writes the legacy manifest. Compare {} with {} (md5 or bytes). \
             If they are equal, the run published: do not rerun. \
             Legacy consumers read the newest share version, so they may already see version {target}.",
            cfg.env.legacy_manifest_object(),
            cfg.env.manifest_object(),
        ),
        _ => "The old version and its manifest are untouched, so consumers that read the baked version are not affected.".to_string(),
    }];
    let mut fillers: Vec<(&str, &str, usize)> = Vec::new();
    for w in written {
        if !w.filler {
            lines.push(format!(
                "  {} {} version {} (share)",
                w.partner, w.secret, w.version
            ));
        } else if let Some(f) = fillers
            .iter_mut()
            .find(|f| (f.0, f.1) == (w.partner.as_str(), w.secret.as_str()))
        {
            f.2 += 1;
        } else {
            fillers.push((&w.partner, &w.secret, 1));
        }
    }
    for (partner, secret, k) in fillers {
        lines.push(format!("  {partner} {secret}: {k} filler version(s)"));
    }
    if !published.is_empty() {
        lines.push("This run already wrote these public-material objects:".to_string());
        lines.extend(published.iter().map(|o| format!("  {o}")));
        if matches!(cfg.mode, Mode::Ceremony) {
            lines.push("The replace guard now sees them: a rerun of this ceremony needs replace_live_keyset: true.".to_string());
        }
    }
    match written.iter().map(|w| w.version).max() {
        Some(highest) if highest >= target => lines.push(format!(
            "These versions are orphans that no reader reads. To rerun, build a new image whose share_version is above {highest}."
        )),
        _ if in_add => lines.push(
            "Rerun the same image: the target version is still free — unless the last write \
             timed out; then the precheck stops, and a higher share_version is needed."
                .to_string(),
        ),
        _ => lines.push("Rerun the same image: the target version is still free.".to_string()),
    }
    lines.join("\n")
}

/// Mint a provenance token binding `SHA-256(payload)`, wrap it in a
/// [`SecretEnvelope`], and write it as a new version of `secret`. Access pattern
/// B: the federated token is the Secret Manager bearer directly.
#[cfg(not(feature = "mock"))]
async fn write_secret(
    attest: &AttestationClient,
    sm: &SecretManager,
    federated: &str,
    project_id: &str,
    secret: &str,
    payload: Vec<u8>,
) -> Result<String> {
    let payload_hash = hex::encode(sha256(&payload));
    info!(secret = %secret, payload_hash = %payload_hash, "minting provenance (eat_nonce = SHA-256(payload))");
    let provenance_jwt = attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[payload_hash])
        .await?;
    let envelope = SecretEnvelope {
        payload,
        provenance_jwt,
    };
    let version = sm
        .add_version(
            federated,
            project_id,
            secret,
            &envelope.to_canonical_bytes(),
        )
        .await
        .map_err(|e| e.context(AddFailed))?;
    info!(secret = %secret, version = %version, "secret written to partner Secret Manager");
    Ok(version)
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER};
    use cofhe_keys::envs::{v, EnvConfig, ReshareSource};

    // A p-1, p-2 ceremony config that writes at `target`, with each partner's
    // newest version of both secrets mocked.
    async fn write_setup(target: u64, newest: [Option<u64>; 2]) -> (World, Config) {
        let w = write_world().await;
        for (p, n) in ["p-1", "p-2"].into_iter().zip(newest) {
            for s in [WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER] {
                list_mock(&w.server, p, s, n).await;
            }
        }
        let e = Box::leak(Box::new(EnvConfig {
            share_version: NonZeroU64::new(target).unwrap(),
            reshare_from: None,
            ..*env(set(&[P1, P2]), 2, None)
        }));
        (w, Config::from_env_config(e).unwrap())
    }

    fn dummy_shares() -> Vec<keygen::PartnerShares> {
        (0..2)
            .map(|i| keygen::PartnerShares {
                fhe_priv_share: vec![i; 8],
                zk_signer_share: vec![i + 10; 8],
            })
            .collect()
    }

    // The received addVersion calls, as `project secret`, with their bodies.
    async fn adds(server: &wiremock::MockServer) -> Vec<(String, Vec<u8>)> {
        use base64::Engine as _;
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().ends_with(":addVersion"))
            .map(|r| {
                let label = r
                    .url
                    .path()
                    .trim_start_matches("/v1/projects/")
                    .trim_end_matches(":addVersion")
                    .replace("/secrets/", " ");
                let json: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                let data = base64::engine::general_purpose::STANDARD
                    .decode(json["payload"]["data"].as_str().unwrap())
                    .unwrap();
                (label, data)
            })
            .collect()
    }

    // D3: a partner at or past the target stops the run before any write.
    #[tokio::test]
    async fn precheck_stops_before_any_write() {
        for p2 in [3, 4] {
            let (w, cfg) = write_setup(3, [Some(1), Some(p2)]).await;
            let mut written = Vec::new();
            let err = deliver_shares(&cfg, &w.run, &dummy_shares(), &mut written)
                .await
                .unwrap_err();
            assert!(adds(&w.server).await.is_empty());
            assert!(written.is_empty());
            // The run wraps the stop as it wraps any write stop: it must come back
            // without the rerun advice, which would be wrong here.
            let err = format!("{:#}", with_report(err, &cfg, &written, &[]));
            assert!(
                err.contains(&format!(
                    "p-2 secret cofhe-tee-fhe-priv is already at version {p2}"
                )),
                "{err}"
            );
            assert!(err.contains("Bake a higher share_version"), "{err}");
            assert!(!err.contains("Rerun the same image"), "{err}");
        }
    }

    // §5.3: fillers only below target−1, every filler before any share.
    #[tokio::test]
    async fn fillers_only_where_needed_and_all_before_any_share() {
        let (w, cfg) = write_setup(3, [Some(2), None]).await;
        for s in [WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER] {
            add_mock(&w.server, "p-1", s, &[3]).await;
            add_mock(&w.server, "p-2", s, &[1, 2, 3]).await;
        }
        let mut written = Vec::new();
        deliver_shares(&cfg, &w.run, &dummy_shares(), &mut written)
            .await
            .unwrap();
        let got = adds(&w.server).await;
        let labels: Vec<&str> = got.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            [
                "p-2 cofhe-tee-fhe-priv",
                "p-2 cofhe-tee-fhe-priv",
                "p-2 cofhe-tee-zk-signer",
                "p-2 cofhe-tee-zk-signer",
                "p-1 cofhe-tee-fhe-priv",
                "p-1 cofhe-tee-zk-signer",
                "p-2 cofhe-tee-fhe-priv",
                "p-2 cofhe-tee-zk-signer",
            ]
        );
        for (_, body) in &got[..4] {
            assert_eq!(body, &[0xde, 0xad, 0xbe, 0xef]);
        }
        let versions: Vec<(u64, bool)> = written.iter().map(|w| (w.version, w.filler)).collect();
        assert_eq!(
            versions,
            [
                (1, true),
                (2, true),
                (1, true),
                (2, true),
                (3, false),
                (3, false),
                (3, false),
                (3, false)
            ]
        );
    }

    // D9: a filler that gets an unexpected number stops the run.
    #[tokio::test]
    async fn a_number_jump_stops_the_run() {
        let (w, cfg) = write_setup(3, [Some(1), Some(2)]).await;
        add_mock(&w.server, "p-1", WRITE_SECRET_FHE_PRIV, &[3]).await;
        let mut written = Vec::new();
        let err = deliver_shares(&cfg, &w.run, &dummy_shares(), &mut written)
            .await
            .unwrap_err();
        let err = format!("{err:#}");
        for s in ["p-1", "expected version 2", "returned 3"] {
            assert!(err.contains(s), "{err}");
        }
        assert_eq!(written.len(), 1);
        assert!(written[0].filler && written[0].version == 3);
    }

    // D9: a share that lands off the target stops the run, and the report sees it.
    #[tokio::test]
    async fn a_share_off_target_stops_the_run() {
        let (w, cfg) = write_setup(2, [Some(1), Some(1)]).await;
        add_mock(&w.server, "p-1", WRITE_SECRET_FHE_PRIV, &[4]).await;
        let mut written = Vec::new();
        deliver_shares(&cfg, &w.run, &dummy_shares(), &mut written)
            .await
            .unwrap_err();
        assert_eq!(written.len(), 1);
        assert!(!written[0].filler && written[0].version == 4);
    }

    // A share add that returns a name without a version number may still have
    // created the target, so the report must not promise a free target.
    #[tokio::test]
    async fn a_bad_name_after_a_share_add_is_an_add_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let (w, cfg) = write_setup(2, [Some(1), Some(1)]).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/projects/p-1/secrets/{WRITE_SECRET_FHE_PRIV}:addVersion"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "name": "x" })),
            )
            .mount(&w.server)
            .await;
        let mut written = Vec::new();
        let err = deliver_shares(&cfg, &w.run, &dummy_shares(), &mut written)
            .await
            .unwrap_err();
        let err = format!("{:#}", with_report(err, &cfg, &written, &[]));
        assert!(err.contains("not a numbered secret version name"), "{err}");
        assert!(err.contains("unless the last write timed out"), "{err}");
    }

    // D5: a stop before any real share reruns the same image; a stop after one
    // needs a higher target.
    #[test]
    fn recovery_report_says_how_to_rerun() {
        let w = |version, filler| Written {
            partner: "p1".to_string(),
            secret: WRITE_SECRET_FHE_PRIV.to_string(),
            version,
            filler,
        };
        // The common line starts a sentence, so match it without case.
        let untouched = "the old version and its manifest are untouched";
        let at5 = |base: &'static EnvConfig, replace| {
            let reshare_from = base.reshare_from.as_ref().map(|r| ReshareSource { ..*r });
            Config::from_env_config(Box::leak(Box::new(EnvConfig {
                share_version: v(5),
                replace_live_keyset: replace,
                reshare_from,
                ..*base
            })))
            .unwrap()
        };
        let ceremony = at5(env(set(&[P1, P2]), 2, None), false);

        let fillers_only = recovery_report(&ceremony, &[w(4, true)], &[], false);
        assert!(
            fillers_only.contains("Rerun the same image: the target version is still free."),
            "{fillers_only}"
        );
        assert!(!fillers_only.contains("timed out"), "{fillers_only}");
        assert!(
            fillers_only.to_lowercase().contains(untouched),
            "{fillers_only}"
        );

        // A failed add may still have created the version, so the plain rerun
        // advice gets its exception.
        let add_failed = recovery_report(&ceremony, &[w(4, true)], &[], true);
        assert!(
            add_failed.contains(
                "Rerun the same image: the target version is still free — unless the last write \
                 timed out; then the precheck stops, and a higher share_version is needed."
            ),
            "{add_failed}"
        );

        let with_share = recovery_report(&ceremony, &[w(4, true), w(5, false)], &[], true);
        for s in [
            "p1 cofhe-tee-fhe-priv version 5 (share)",
            "1 filler version(s)",
            "To rerun, build a new image whose share_version is above 5",
        ] {
            assert!(with_share.contains(s), "{with_share}");
        }
        assert!(
            with_share.to_lowercase().contains(untouched),
            "{with_share}"
        );
        assert!(!with_share.contains("Rerun the same image"), "{with_share}");

        // Any public-material object trips the replace guard of a ceremony rerun; a
        // reshare has no guard.
        let sidecar = ["p/0/public-material.v5.provenance".to_string()];
        let guard = "a rerun of this ceremony needs replace_live_keyset: true";
        let half_published = recovery_report(&ceremony, &[w(5, false)], &sidecar, false);
        assert!(half_published.contains(&sidecar[0]), "{half_published}");
        assert!(half_published.contains(guard), "{half_published}");
        let reshare = at5(replace_env(), false);
        let half_published = recovery_report(&reshare, &[w(5, false)], &sidecar, false);
        assert!(half_published.contains(&sidecar[0]), "{half_published}");
        assert!(!half_published.contains(guard), "{half_published}");

        // A rotation may already have overwritten the shared artifacts.
        let rotation = recovery_report(
            &at5(env(set(&[P1, P2]), 2, None), true),
            &[w(5, false)],
            &[],
            false,
        );
        assert!(!rotation.to_lowercase().contains(untouched), "{rotation}");
        assert!(
            rotation.contains("may already be overwritten"),
            "{rotation}"
        );
    }

    // The staging migration also writes the legacy manifest, which legacy consumers
    // read. A lost upload response can hide a finished publish, so the report must
    // not promise an untouched manifest there.
    #[test]
    fn a_legacy_manifest_run_says_how_to_check_the_publish() {
        let r = replace_env().reshare_from.as_ref().unwrap();
        let cfg = |legacy_manifest| {
            Config::from_env_config(Box::leak(Box::new(EnvConfig {
                reshare_from: Some(ReshareSource {
                    legacy_manifest,
                    ..*r
                }),
                ..*replace_env()
            })))
            .unwrap()
        };
        let untouched = "untouched";
        let compare = "Compare p/0/public-material with p/0/public-material.v2 (md5 or bytes). \
             If they are equal, the run published: do not rerun.";
        let legacy = recovery_report(&cfg(true), &[], &[], false);
        assert!(!legacy.contains(untouched), "{legacy}");
        assert!(!legacy.contains("not affected"), "{legacy}");
        assert!(legacy.contains(compare), "{legacy}");
        assert!(legacy.contains("may already see version 2"), "{legacy}");
        let normal = recovery_report(&cfg(false), &[], &[], false);
        assert!(normal.contains(untouched), "{normal}");
        assert!(!normal.contains("Compare"), "{normal}");
    }
}
