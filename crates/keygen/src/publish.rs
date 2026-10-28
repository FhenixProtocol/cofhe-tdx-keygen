use crate::config::Config;
use crate::{Run, PROVENANCE_AUDIENCE};
use anyhow::Result;
use cofhe_keys::serialization::PublicMaterial;
use tracing::info;

// Public GCS object layout under the baked `{public_prefix}/{public_zone}/`. The three FHE artifacts
// use cofhe's exact mounted file names, so a cofhe stack pointed at this bucket
// reads this ceremony's keyset directly as files
// (keys/versionized/{zone}/{computation_key,public_key,crs}). The manifest sits
// alongside for the consumer reader; the provenance sidecar is still written but
// unread (kept for wire-format compatibility).
pub(crate) const OBJ_SERVER_KEY: &str = "computation_key";
pub(crate) const OBJ_PUBLIC_KEY: &str = "public_key";
pub(crate) const OBJ_CRS: &str = "crs";

// Object key under the per-zone prefix, e.g. keys/versionized/0/computation_key.
pub(crate) fn object_path(prefix: &str, zone: u32, name: &str) -> String {
    format!("{}/{}/{}", prefix.trim_end_matches('/'), zone, name)
}

// Publish the provenance sidecar and the manifest under each of `objects`, and
// record each object in `published` after its upload. Consumers do not
// verify the sidecar; it stays for wire-format compatibility (see AGENTS.md).
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
        let sidecar = format!("{object}.provenance");
        let written = run
            .gcs
            .upload(
                &token,
                cfg.env.public_bucket,
                &sidecar,
                public_provenance_jwt.as_bytes(),
            )
            .await?;
        published.push(sidecar);
        info!(object = %written, "public-material provenance written to our GCS bucket");
        info!(object = %object, "publishing public-material manifest");
        let written = run
            .gcs
            .upload(&token, cfg.env.public_bucket, object, &bytes)
            .await?;
        published.push(object.clone());
        info!(object = %written, "public-material manifest written to our GCS bucket");
    }
    Ok(())
}

#[cfg(test)]
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
}
