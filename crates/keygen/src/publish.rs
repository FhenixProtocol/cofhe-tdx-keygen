use crate::config::Config;
use crate::{Run, PROVENANCE_AUDIENCE};
use anyhow::Result;
use cofhe_keys::gcs::AlreadyExists;
use cofhe_keys::serialization::PublicMaterial;
use tracing::info;

// Public GCS object layout under the baked `{public_prefix}/{public_zone}/`. The three FHE artifacts
// use cofhe's exact mounted file names, so a cofhe stack pointed at this bucket
// reads this ceremony's keyset directly as files
// (keys/versionized/{zone}/{computation_key,public_key,crs}). The manifest sits
// alongside for the consumer reader; the provenance sidecar is still written but
// unread (kept for wire-format compatibility).
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_SERVER_KEY: &str = "computation_key";
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_PUBLIC_KEY: &str = "public_key";
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_CRS: &str = "crs";

// Object key under the per-zone prefix, e.g. keys/versionized/0/computation_key.
#[cfg(not(feature = "mock"))]
pub(crate) fn object_path(prefix: &str, zone: u32, name: &str) -> String {
    format!("{}/{}/{}", prefix.trim_end_matches('/'), zone, name)
}

// Upload one object. With `versioned` (the manifest it belongs to), the upload is
// create-only, and an existing object stops the run.
async fn put(
    run: &Run,
    token: &str,
    bucket: &str,
    name: &str,
    data: &[u8],
    versioned: Option<&str>,
) -> Result<String> {
    let Some(manifest) = versioned else {
        return run.gcs.upload(token, bucket, name, data).await;
    };
    run.gcs
        .create(token, bucket, name, data)
        .await
        .map_err(|e| {
            if e.is::<AlreadyExists>() {
                e.context(format!(
                    "a live manifest exists at {manifest}; this run never replaces it"
                ))
            } else {
                e
            }
        })
}

// Publish the provenance sidecar and the manifest under each of `objects`, and
// record each object in `published` after its upload. Consumers do not
// verify the sidecar; it stays for wire-format compatibility (see AGENTS.md).
#[cfg(not(feature = "mock"))]
pub(crate) async fn publish_manifest(
    cfg: &Config,
    run: &Run,
    public: &PublicMaterial,
    objects: &[String],
    published: &mut Vec<String>,
) -> Result<()> {
    let bytes = public.to_canonical_bytes();
    let public_hash = hex::encode(public.hash());
    info!(public_hash = %public_hash, "minting public-material provenance (eat_nonce = SHA-256(manifest))");
    let public_provenance_jwt = run
        .attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[public_hash])
        .await?;
    let token = run.metadata.token().await?;
    // The sidecar goes first, so a stop never leaves a manifest without it.
    for object in objects {
        // No run writes one version twice, so a versioned manifest that exists is a
        // live one: never replace it. The legacy name is rewritten on purpose.
        let versioned = (*object != cfg.env.legacy_manifest_object()).then_some(object.as_str());
        let sidecar = format!("{object}.provenance");
        let written = put(
            run,
            &token,
            cfg.env.public_bucket,
            &sidecar,
            public_provenance_jwt.as_bytes(),
            versioned,
        )
        .await?;
        published.push(sidecar);
        info!(object = %written, "public-material provenance written to our GCS bucket");
        info!(object = %object, "publishing public-material manifest");
        let written = put(
            run,
            &token,
            cfg.env.public_bucket,
            object,
            &bytes,
            versioned,
        )
        .await?;
        published.push(object.clone());
        info!(object = %written, "public-material manifest written to our GCS bucket");
    }
    Ok(())
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::write::with_report;

    // A first ceremony that stops in the publish step: the sidecar is already up,
    // so the report names it, and the rerun needs the replace flag.
    #[tokio::test]
    async fn a_stop_in_publish_records_the_sidecar() {
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let w = write_world().await;
        for (name, status) in [
            ("p/0/public-material.v2.provenance", 200),
            ("p/0/public-material.v2", 500),
        ] {
            Mock::given(method("POST"))
                .and(query_param("name", name))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({ "name": name, "generation": "1" })),
                )
                .mount(&w.server)
                .await;
        }
        let cfg = Config::from_env_config(env(set(&[P1, P2]), 2, None)).unwrap();
        let mut published = Vec::new();
        let err = publish_manifest(
            &cfg,
            &w.run,
            &zero_public(),
            &[cfg.env.manifest_object()],
            &mut published,
        )
        .await
        .unwrap_err();
        assert_eq!(published, ["p/0/public-material.v2.provenance"]);
        let err = format!("{:#}", with_report(err, &cfg, &[], &published));
        assert!(err.contains("p/0/public-material.v2.provenance"), "{err}");
        assert!(err.contains("needs replace_live_keyset: true"), "{err}");
    }

    // A versioned manifest and its sidecar are create-only, so a run never replaces
    // a live manifest. The legacy name keeps a plain upload.
    #[tokio::test]
    async fn a_live_versioned_manifest_is_never_replaced() {
        use wiremock::matchers::{method, query_param, query_param_is_missing};
        use wiremock::{Mock, ResponseTemplate};

        let ok = |name: &str| {
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "name": name, "generation": "1" }))
        };
        let cfg = Config::from_env_config(env(set(&[P1, P2]), 2, None)).unwrap();
        let objects = [cfg.env.manifest_object(), cfg.env.legacy_manifest_object()];

        let w = write_world().await;
        for name in [
            "p/0/public-material.v2.provenance",
            "p/0/public-material.v2",
        ] {
            Mock::given(method("POST"))
                .and(query_param("name", name))
                .and(query_param("ifGenerationMatch", "0"))
                .respond_with(ok(name))
                .mount(&w.server)
                .await;
        }
        for name in ["p/0/public-material.provenance", "p/0/public-material"] {
            Mock::given(method("POST"))
                .and(query_param("name", name))
                .and(query_param_is_missing("ifGenerationMatch"))
                .respond_with(ok(name))
                .mount(&w.server)
                .await;
        }
        let mut published = Vec::new();
        publish_manifest(&cfg, &w.run, &zero_public(), &objects, &mut published)
            .await
            .unwrap();
        assert_eq!(published.len(), 4);

        let w = write_world().await;
        Mock::given(method("POST"))
            .and(query_param("name", "p/0/public-material.v2.provenance"))
            .and(query_param("ifGenerationMatch", "0"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&w.server)
            .await;
        let mut published = Vec::new();
        let err = publish_manifest(&cfg, &w.run, &zero_public(), &objects, &mut published)
            .await
            .unwrap_err();
        assert!(published.is_empty());
        let err = format!("{err:#}");
        assert!(
            err.contains("a live manifest exists at p/0/public-material.v2"),
            "{err}"
        );
    }
}
