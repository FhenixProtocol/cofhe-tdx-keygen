use crate::config::Config;
use crate::publish::{object_path, publish_manifest, OBJ_CRS, OBJ_PUBLIC_KEY, OBJ_SERVER_KEY};
use crate::write::{deliver_shares, with_report};
use crate::Run;
use anyhow::{bail, Result};
use cofhe_keys::keygen;
use tracing::info;

// Ceremony: generate the full network keyset in-enclave (never leaves TDX memory
// unencrypted): FHE keys + decrypt_signer (TN) + zk_signer (ZK/verifier),
// Shamir-split N-of-T across the partners — one share pair per partner, index i →
// partners[i]. Then deliver, then publish the artifacts and the manifest.
pub(crate) async fn run_ceremony(cfg: &Config, run: &Run) -> Result<()> {
    // An image built from the wrong env must not replace a live network key. Only a
    // deliberate key rotation bakes `replace_live_keyset`. The legacy name is the
    // prefix of every versioned name, so one listing finds a manifest of any version.
    let token = run.metadata.token().await?;
    let live = run
        .gcs
        .first_with_prefix(
            &token,
            cfg.env.public_bucket,
            &cfg.env.legacy_manifest_object(),
        )
        .await?;
    check_replace_guard(
        cfg.env.replace_live_keyset,
        live.map(|name| format!("gs://{}/{name}", cfg.env.public_bucket)),
    )?;

    info!("step 1: generating + splitting network keyset in-enclave");
    let partner_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let (partner_shares, artifacts, public) =
        keygen::generate(&partner_ids, cfg.shares, cfg.threshold)?;

    let mut written = Vec::new();
    if let Err(e) = deliver_shares(cfg, run, &partner_shares, &mut written).await {
        return Err(with_report(e, cfg, &written, &[]));
    }

    // The three FHE artifacts go to SEPARATE objects, named + laid out exactly as
    // cofhe mounts them (keys/versionized/{zone}/…), so a cofhe stack reads this
    // ceremony's keyset directly as files.
    let mut published = Vec::new();
    let uploaded: Result<()> = async {
        let token = run.metadata.token().await?;
        for (name, bytes) in [
            (OBJ_SERVER_KEY, &artifacts.server_key),
            (OBJ_PUBLIC_KEY, &artifacts.compact_public_key),
            (OBJ_CRS, &artifacts.crs),
        ] {
            let object = object_path(cfg.env.public_prefix, cfg.env.public_zone, name);
            info!(object = %object, bytes = bytes.len(), "publishing public FHE artifact");
            let written = run
                .gcs
                .upload(&token, cfg.env.public_bucket, &object, bytes)
                .await?;
            info!(object = %written, "public FHE artifact written");
        }
        Ok(())
    }
    .await;
    if let Err(e) = uploaded {
        return Err(with_report(e, cfg, &written, &published));
    }
    if let Err(e) = publish_manifest(
        cfg,
        run,
        &public,
        &[cfg.env.manifest_object()],
        &mut published,
    )
    .await
    {
        return Err(with_report(e, cfg, &written, &published));
    }
    info!(
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "keygen ceremony complete"
    );
    Ok(())
}

// A ceremony writes a new keyset. Over a live one that is a key rotation, which
// the env must bake on purpose.
fn check_replace_guard(replace_live_keyset: bool, live_manifest: Option<String>) -> Result<()> {
    if let (Some(name), false) = (live_manifest, replace_live_keyset) {
        bail!(
            "a live manifest exists ({name}): this ceremony would replace the live keyset. A key \
             rotation bakes replace_live_keyset: true in the env"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER};

    // The ceremony's replace guard is wired before keygen: any manifest under the
    // prefix (a versioned one at another version, or the legacy name) is a live
    // keyset, so the run stops, names it, and writes nothing.
    #[tokio::test]
    async fn ceremony_stops_over_any_live_manifest() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        for live in ["p/0/public-material.v1", "p/0/public-material"] {
            let w = write_world().await;
            Mock::given(method("GET"))
                .and(path("/storage/v1/b/b/o"))
                .and(query_param("prefix", "p/0/public-material"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "items": [{ "name": live }] })),
                )
                .mount(&w.server)
                .await;
            forbid_writes(&w.server).await;

            // The env is baked at v2, so a `.v1` manifest is not this run's name.
            let cfg = Config::from_env_config(env(set(&[P1, P2, P3]), 2, None)).unwrap();
            assert_eq!(cfg.env.share_version.get(), 2);
            let err = format!("{:#}", run_ceremony(&cfg, &w.run).await.unwrap_err());
            assert!(err.contains("live manifest exists"), "{err}");
            assert!(err.contains(&format!("gs://b/{live}")), "{err}");
            w.server.verify().await;
        }
    }

    // The ceremony writes through the same path, so a stop inside a write carries
    // the same report. Slow: the ceremony generates a real keyset first.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn a_ceremony_write_failure_carries_the_report() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let w = write_world().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/b/o"))
            .and(query_param("prefix", "p/0/public-material"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&w.server)
            .await;
        // Both partners are new: a v1 filler each, then the v2 share of p-1 fails.
        for p in ["p-1", "p-2"] {
            for s in [WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER] {
                list_mock(&w.server, p, s, None).await;
                add_mock(&w.server, p, s, &[1]).await;
            }
        }
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/p-1/secrets/cofhe-tee-fhe-priv:addVersion",
            ))
            .respond_with(ResponseTemplate::new(500))
            .mount(&w.server)
            .await;
        let cfg = Config::from_env_config(env(set(&[P1, P2]), 2, None)).unwrap();
        let err = format!("{:#}", run_ceremony(&cfg, &w.run).await.unwrap_err());
        for s in [
            "p-2 cofhe-tee-zk-signer: 1 filler version(s)",
            "Rerun the same image: the target version is still free — unless the last write timed out",
        ] {
            assert!(err.contains(s), "{err}");
        }
    }

    // A ceremony over a live keyset runs only when the env bakes the replace flag.
    #[test]
    fn ceremony_replaces_a_live_keyset_only_when_baked() {
        let live = || Some("p/0/public-material.v1".to_string());
        check_replace_guard(false, None).unwrap();
        check_replace_guard(true, live()).unwrap();
        check_replace_guard(true, None).unwrap();
        let err = check_replace_guard(false, live()).unwrap_err().to_string();
        assert!(err.contains("p/0/public-material.v1"), "{err}");
    }
}
