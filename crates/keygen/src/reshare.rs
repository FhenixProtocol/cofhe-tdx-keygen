use crate::config::Config;
use crate::publish::{object_path, publish_manifest, OBJ_CRS, OBJ_PUBLIC_KEY, OBJ_SERVER_KEY};
use crate::write::{deliver_shares, with_report};
use crate::{federate, Run, KEYGEN_READER};
use anyhow::{bail, Context, Result};
use cofhe_keys::envs::ReshareSource;
use cofhe_keys::keygen;
use cofhe_keys::reader::{self, PartnerAccess, PartnerRef, ReaderContext};
use cofhe_keys::serialization::PublicMaterial;
use std::collections::BTreeSet;
use tracing::{info, warn};

// Reshare: rebuild the live keyset from the source set, prove it is the key
// behind the live public data, split it again for the target set, deliver, and
// publish a manifest that differs only in the per-share digests. The public
// artifacts stay as they are: their bytes cannot be regenerated, and they do not
// change.
#[cfg(not(feature = "mock"))]
pub(crate) async fn run_reshare(cfg: &Config, r: &ReshareSource, run: &Run) -> Result<()> {
    let manifest_object = r.manifest_object(cfg.env);
    info!(object = %manifest_object, "step 1: reading the live manifest and public artifacts");
    let token = run.metadata.token().await?;
    let live_bytes = run
        .gcs
        .download(&token, cfg.env.public_bucket, &manifest_object)
        .await
        .context("read the live manifest (a reshare needs a published keyset)")?;
    let live =
        PublicMaterial::from_canonical_bytes(&live_bytes).context("decode the live manifest")?;
    check_live_anchor(&live, r)?;
    let mut artifacts = keygen::PublicArtifacts::default();
    for (name, slot) in [
        (OBJ_SERVER_KEY, &mut artifacts.server_key),
        (OBJ_PUBLIC_KEY, &mut artifacts.compact_public_key),
        (OBJ_CRS, &mut artifacts.crs),
    ] {
        let object = object_path(cfg.env.public_prefix, cfg.env.public_zone, name);
        *slot = run
            .gcs
            .download(&token, cfg.env.public_bucket, &object)
            .await
            .with_context(|| format!("read public artifact {object}"))?;
    }

    // A source partner that does not federate (for example, a partner that leaves
    // and does not set the read flag) is excluded here. The rebuild below needs
    // only the old threshold of good shares.
    info!(
        sources = r.partners.len(),
        threshold = r.shamir_threshold,
        "step 2: reading the live shares from the source set"
    );
    // One token per source partner reads both secrets; the two ref lists share
    // the partner order.
    let sources = r.partners.iter().map(|s| s.partner).collect::<Vec<_>>();
    let fhe_refs = reader::partner_refs_for(&sources, KEYGEN_READER, &cfg.write_secret_fhe_priv);
    let zk_refs = reader::partner_refs_for(&sources, KEYGEN_READER, &cfg.write_secret_zk_signer);
    let mut tokens = Vec::with_capacity(fhe_refs.len());
    for (i, p) in fhe_refs.iter().enumerate() {
        match federate(run, &p.wip_audience).await {
            Ok(t) => tokens.push((i, t)),
            Err(e) => {
                warn!(partner = %p.project_id, error = %format!("{e:#}"), "source partner did not federate; excluding")
            }
        }
    }
    // The consumer reader rebuilds each secret from the baked source versions.
    let ctx = ReaderContext {
        sm: &run.sm,
        gcs: &run.gcs,
        gcs_token: &token,
        public_bucket: cfg.env.public_bucket,
        public_object: &manifest_object,
    };
    let fhe_priv = reader::read_fhe_priv(
        &ctx,
        &source_access(&fhe_refs, &tokens),
        r.shamir_threshold,
        &|p| r.version_for(p),
    )
    .await?;
    let zk_signer = reader::read_zk_signer(
        &ctx,
        &source_access(&zk_refs, &tokens),
        r.shamir_threshold,
        &|p| r.version_for(p),
    )
    .await?;

    // Order matters from here: the key is checked before any write, and the
    // manifest is published last.
    info!("step 3: checking the rebuilt key against the live public data");
    keygen::verify_against_public(&fhe_priv, &zk_signer, &live, &artifacts)?;

    info!(
        shares = cfg.shares,
        threshold = cfg.threshold,
        "step 4: splitting the live keyset for the target set"
    );
    let target_ids: Vec<String> = cfg.partners.iter().map(|p| p.project_id.clone()).collect();
    let split = keygen::split_for_partners(
        &fhe_priv,
        &zk_signer,
        &target_ids,
        cfg.shares,
        cfg.threshold,
    )?;

    let mut written = Vec::new();
    let public =
        live.with_share_digests(split.fhe_priv_share_digests, split.zk_signer_share_digests);
    if let Err(e) = deliver_shares(cfg, run, &split.partner_shares, &mut written).await {
        return Err(with_report(e, cfg, &written, &[]));
    }
    // The migration run also writes the legacy name, which the source readers use.
    let mut objects = vec![cfg.env.manifest_object()];
    if r.legacy_manifest {
        objects.push(cfg.env.legacy_manifest_object());
    }
    let mut published = Vec::new();
    if let Err(e) = publish_manifest(cfg, run, &public, &objects, &mut published).await {
        return Err(with_report(e, cfg, &written, &published));
    }
    info!(
        decrypt_signer = %public.decrypt_signer_address,
        zk_signer = %public.zk_signer_address,
        "keygen reshare complete: same keyset, new shares"
    );
    Ok(())
}

// The federated source partners, paired with their tokens, for one secret.
#[cfg(not(feature = "mock"))]
fn source_access<'a>(
    refs: &'a [PartnerRef],
    tokens: &'a [(usize, String)],
) -> Vec<PartnerAccess<'a>> {
    tokens
        .iter()
        .map(|(i, sm_token)| PartnerAccess {
            partner: &refs[*i],
            sm_token,
        })
        .collect()
}

// The manifest in the bucket must describe the keyset and the share set the env
// was baked for. All later checks are relative to this manifest. Without the
// signer anchor, a bucket writer could restore an older keyset's manifest and have
// this run split that older key. The share-set check catches an env whose source
// set is not the set the live manifest lists.
#[cfg(not(feature = "mock"))]
fn check_live_anchor(live: &PublicMaterial, r: &ReshareSource) -> Result<()> {
    let (decrypt, zk) = (r.decrypt_signer_address, r.zk_signer_address);
    if live.decrypt_signer_address != decrypt || live.zk_signer_address != zk {
        bail!(
            "the live manifest names signers ({}, {}), but the baked reshare source names ({decrypt}, {zk}): this is not the live keyset",
            live.decrypt_signer_address,
            live.zk_signer_address
        );
    }
    let source: BTreeSet<&str> = r.partners.iter().map(|s| s.partner.project_id).collect();
    for digests in [&live.fhe_priv_share_digests, &live.zk_signer_share_digests] {
        let listed: BTreeSet<&str> = digests.iter().map(|(id, _)| id.as_str()).collect();
        if listed != source {
            bail!(
                "the live manifest lists shares for {listed:?}, but the baked source is {source:?}: \
                 the env is wrong"
            );
        }
    }
    Ok(())
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::test_support::*;
    use crate::{WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER};
    use cofhe_keys::envs::{v, EnvConfig};
    use cofhe_keys::serialization::{sha256, SecretEnvelope};
    use std::num::NonZeroU64;

    // The safety of a reshare rests on its order: the key is checked before any
    // write. Here the shares rebuild and the anchor holds, but a published artifact
    // does not match the manifest. The run must stop with no Secret Manager write
    // and no GCS upload. One source partner also
    // fails to federate: the run drops it and still rebuilds from the other two.
    #[tokio::test]
    async fn reshare_writes_nothing_when_the_key_check_fails() {
        use cofhe_keys::serialization::{FhePrivShare, ZkSignerShare};
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let fhe = FhePrivShare {
            client_key: vec![1; 40],
            decrypt_signer_priv: vec![2; 32],
        };
        let zk = ZkSignerShare {
            zk_signer_priv: vec![3; 32],
        };
        let ids: Vec<String> = ["p-1", "p-2", "p-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let split = keygen::split_for_partners(&fhe, &zk, &ids, 3, 2).unwrap();
        let live = PublicMaterial {
            server_key_digest: sha256(b"server key"),
            compact_public_key_digest: sha256(b"public key"),
            crs_digest: sha256(b"not the published crs"),
            decrypt_signer_address: LIVE_DECRYPT.to_string(),
            zk_signer_address: LIVE_ZK.to_string(),
            fhe_priv_digest: fhe.hash(),
            zk_signer_digest: zk.hash(),
            fhe_priv_share_digests: split.fhe_priv_share_digests,
            zk_signer_share_digests: split.zk_signer_share_digests,
        };
        let artifacts = [
            b"server key".to_vec(),
            b"public key".to_vec(),
            b"crs".to_vec(),
        ];
        let w = reshare_world(&live, artifacts, &ids, &split.partner_shares).await;
        // p-3's audience carries its project number: its STS exchange fails.
        Mock::given(method("POST"))
            .and(path("/sts"))
            .and(body_string_contains("333333333333"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(1)
            .mount(&w.server)
            .await;
        forbid_writes(&w.server).await;

        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let err = run_reshare(&cfg, src, &w.run).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("crs digest mismatch"),
            "{err:#}"
        );
        w.server.verify().await;
    }

    // A real 2-of-3 keyset on p-1..p-3, a reshare env to p-1, p-2, p-4 anchored on
    // it, and a mocked cloud where every write succeeds unless a test mounts a
    // failure first.
    async fn real_reshare_world() -> (World, &'static EnvConfig, PublicMaterial) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let ids: Vec<String> = ["p-1", "p-2", "p-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (shares, artifacts, live) = keygen::generate(&ids, 3, 2).unwrap();
        let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
        let e: &'static EnvConfig = Box::leak(Box::new(EnvConfig {
            reshare_from: Some(ReshareSource {
                partners: sources(set(&[P1, P2, P3])),
                shamir_threshold: 2,
                share_version: v(1),
                legacy_manifest: false,
                decrypt_signer_address: leak(&live.decrypt_signer_address),
                zk_signer_address: leak(&live.zk_signer_address),
            }),
            ..*env(set(&[P1, P2, P4]), 2, None)
        }));
        let w = reshare_world(
            &live,
            [
                artifacts.server_key.clone(),
                artifacts.compact_public_key.clone(),
                artifacts.crs.clone(),
            ],
            &ids,
            &shares,
        )
        .await;
        // The target is v2: p-1 and p-2 hold v1, and the new p-4 gets a v1 filler.
        for (p, newest, adds) in [
            ("p-1", Some(1), &[2][..]),
            ("p-2", Some(1), &[2]),
            ("p-4", None, &[1, 2]),
        ] {
            for s in [WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER] {
                list_mock(&w.server, p, s, newest).await;
                add_mock(&w.server, p, s, adds).await;
            }
        }
        Mock::given(method("POST"))
            .and(path_regex("^/upload/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "name": "o", "generation": "1" })),
            )
            .mount(&w.server)
            .await;
        (w, e, live)
    }

    // A share write fails at p-2, after the p-4 fillers and three shares. The error
    // carries the recovery report: the shares are orphans, and a rerun needs a
    // higher target. Slow; run with `cargo test -p keygen -- --ignored`.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn reshare_stopped_mid_write_reports_how_to_recover() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (w, e, _) = real_reshare_world().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/p-2/secrets/cofhe-tee-zk-signer:addVersion",
            ))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(1)
            .mount(&w.server)
            .await;
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let err = format!("{:#}", run_reshare(&cfg, src, &w.run).await.unwrap_err());
        for s in [
            "p-2 cofhe-tee-fhe-priv version 2 (share)",
            "p-4 cofhe-tee-zk-signer: 1 filler version(s)",
            "share_version is above 2",
        ] {
            assert!(err.contains(s), "{err}");
        }
    }

    // The whole reshare on a real keyset: fillers first, then every share at the
    // target, the manifest last with only the share digests changed, and
    // the new shares rebuild the same secrets. Slow, so CI skips it; run it with
    // `cargo test -p keygen -- --ignored`.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn reshare_writes_in_order_and_keeps_the_keyset() {
        use base64::Engine as _;

        let (w, e, live) = real_reshare_world().await;
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        run_reshare(&cfg, src, &w.run).await.unwrap();

        let requests = w.server.received_requests().await.unwrap();
        let writes: Vec<(String, &Vec<u8>)> = requests
            .iter()
            .filter(|r| r.method.as_str() == "POST" && r.url.path() != "/sts")
            .map(|r| {
                let label = match r.url.query_pairs().find(|(k, _)| k == "name") {
                    Some((_, name)) => format!("upload {name}"),
                    None => r.url.path().trim_start_matches("/v1/projects/").to_string(),
                };
                (label, &r.body)
            })
            .collect();
        let labels: Vec<&str> = writes.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            [
                "p-4/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-4/secrets/cofhe-tee-zk-signer:addVersion",
                "p-1/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-1/secrets/cofhe-tee-zk-signer:addVersion",
                "p-2/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-2/secrets/cofhe-tee-zk-signer:addVersion",
                "p-4/secrets/cofhe-tee-fhe-priv:addVersion",
                "p-4/secrets/cofhe-tee-zk-signer:addVersion",
                "upload p/0/public-material.v2.provenance",
                "upload p/0/public-material.v2",
            ]
        );
        let published = PublicMaterial::from_canonical_bytes(writes[9].1).unwrap();
        let ids_of =
            |d: &[(String, [u8; 32])]| d.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        assert_eq!(
            ids_of(&published.fhe_priv_share_digests),
            ["p-1", "p-2", "p-4"]
        );
        assert_eq!(
            PublicMaterial {
                fhe_priv_share_digests: live.fhe_priv_share_digests.clone(),
                zk_signer_share_digests: live.zk_signer_share_digests.clone(),
                ..published.clone()
            },
            live
        );

        // Any two new shares rebuild the live secrets, the new partner's (p-4) too.
        let payload = |body: &Vec<u8>| -> Vec<u8> {
            let json: serde_json::Value = serde_json::from_slice(body).unwrap();
            let data = json["payload"]["data"].as_str().unwrap();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap();
            SecretEnvelope::from_canonical_bytes(&raw).unwrap().payload
        };
        // Shares at 2 (p-1), 4 (p-2), 6 (p-4); the zk share is the next write.
        for (offset, digest) in [(0, live.fhe_priv_digest), (1, live.zk_signer_digest)] {
            for (a, b) in [(2, 4), (2, 6), (4, 6)] {
                let pair = [payload(writes[a + offset].1), payload(writes[b + offset].1)];
                let secret = cofhe_keys::shamir::reconstruct(&pair, 2).unwrap();
                assert_eq!(sha256(&secret), digest, "shares {a}, {b}");
            }
        }
    }

    // Serve what a finished run wrote: each uploaded manifest (not its sidecar)
    // and each partner's newest add at `version`, so a reader can read them back.
    async fn serve_published(server: &wiremock::MockServer, version: u64) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let mut newest = std::collections::BTreeMap::new();
        for r in server.received_requests().await.unwrap() {
            if r.method.as_str() != "POST" {
                continue;
            }
            if let Some((_, name)) = r.url.query_pairs().find(|(k, _)| k == "name") {
                if !name.ends_with(".provenance") {
                    Mock::given(method("GET"))
                        .and(path(format!(
                            "/storage/v1/b/b/o/{}",
                            name.replace('/', "%2F")
                        )))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(r.body.clone()))
                        .with_priority(1)
                        .mount(server)
                        .await;
                }
            } else if let Some(secret) = r.url.path().strip_suffix(":addVersion") {
                let json: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                newest.insert(secret.to_string(), json["payload"]["data"].clone());
            }
        }
        for (secret, data) in newest {
            Mock::given(method("GET"))
                .and(path(format!("{secret}/versions/{version}:access")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "name": "v", "payload": { "data": data } }),
                    ),
                )
                .with_priority(1)
                .mount(server)
                .await;
        }
    }

    // A consumer reader of `object` at `version` over `partners`, T = 2. Returns
    // the digests of the two secrets it rebuilds.
    async fn read_back(
        w: &World,
        object: &str,
        partners: &[(&'static str, &'static str)],
        version: u64,
    ) -> ([u8; 32], [u8; 32]) {
        let set = set(partners);
        let fhe_refs = reader::partner_refs_for(set, "teecryptor", WRITE_SECRET_FHE_PRIV);
        let zk_refs = reader::partner_refs_for(set, "zk", WRITE_SECRET_ZK_SIGNER);
        let all: Vec<_> = (0..set.len())
            .map(|i| (i, "federated".to_string()))
            .collect();
        let ctx = ReaderContext {
            sm: &w.run.sm,
            gcs: &w.run.gcs,
            gcs_token: "sa",
            public_bucket: "b",
            public_object: object,
        };
        let at = NonZeroU64::new(version).unwrap();
        let fhe = reader::read_fhe_priv(&ctx, &source_access(&fhe_refs, &all), 2, &|_| at)
            .await
            .unwrap();
        let zk = reader::read_zk_signer(&ctx, &source_access(&zk_refs, &all), 2, &|_| at)
            .await
            .unwrap();
        (fhe.hash(), zk.hash())
    }

    // The overlap (§4): after a reshare from v1 to v2, an old reader at v1 with
    // `.v1` and a new reader at v2 with `.v2` rebuild the same key. Slow; run with
    // `cargo test -p keygen -- --ignored`.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn old_and_new_readers_both_work_after_publish() {
        let (w, e, live) = real_reshare_world().await;
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        assert!(!src.legacy_manifest);
        run_reshare(&cfg, src, &w.run).await.unwrap();
        serve_published(&w.server, 2).await;

        let keys = (live.fhe_priv_digest, live.zk_signer_digest);
        let old = read_back(&w, "p/0/public-material.v1", &[P1, P2, P3], 1).await;
        let new = read_back(&w, "p/0/public-material.v2", &[P1, P2, P4], 2).await;
        assert_eq!(old, keys);
        assert_eq!(new, keys);
        // The new partner's share alone with one old partner's is enough.
        assert_eq!(
            read_back(&w, "p/0/public-material.v2", &[P1, P4], 2).await,
            keys
        );
    }

    // The staging migration (§6): the source manifest has the legacy name. The run
    // writes the same bytes to `.v2` and to the legacy name, and a reader at v2
    // with the legacy name rebuilds the key. Slow; run with `--ignored`.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn legacy_migration_writes_both_names() {
        // A `latest` reader cannot exist in this code; the staging drill proves that
        // today's consumers keep working.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (w, e, live) = real_reshare_world().await;
        let src = e.reshare_from.as_ref().unwrap();
        let e: &'static EnvConfig = Box::leak(Box::new(EnvConfig {
            reshare_from: Some(ReshareSource {
                legacy_manifest: true,
                ..*src
            }),
            ..*e
        }));
        // Only the legacy name holds the source manifest.
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/b/o/p%2F0%2Fpublic-material"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(live.to_canonical_bytes()))
            .mount(&w.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/b/o/p%2F0%2Fpublic-material.v1"))
            .respond_with(ResponseTemplate::new(404))
            .with_priority(1)
            .mount(&w.server)
            .await;
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        run_reshare(&cfg, src, &w.run).await.unwrap();

        let uploads: Vec<(String, Vec<u8>)> = w
            .server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter_map(|r| {
                let name = r
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "name")?
                    .1
                    .to_string();
                Some((name, r.body))
            })
            .collect();
        let names: Vec<&str> = uploads.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "p/0/public-material.v2.provenance",
                "p/0/public-material.v2",
                "p/0/public-material.provenance",
                "p/0/public-material",
            ]
        );
        assert_eq!(uploads[0].1, uploads[2].1);
        assert_eq!(uploads[1].1, uploads[3].1);

        serve_published(&w.server, 2).await;
        assert_eq!(
            read_back(&w, "p/0/public-material", &[P1, P2, P4], 2).await,
            (live.fhe_priv_digest, live.zk_signer_digest)
        );
    }

    // The shares are delivered, then the manifest upload fails. The error carries
    // the report: the shares are orphans and a rerun needs a higher target. Slow;
    // a reshare reaches the publish only after the real key check.
    #[tokio::test]
    #[ignore = "slow: generates a real keyset; run with --ignored"]
    async fn a_publish_failure_carries_the_report() {
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let (w, e, _) = real_reshare_world().await;
        Mock::given(method("POST"))
            .and(query_param("name", "p/0/public-material.v2"))
            .respond_with(ResponseTemplate::new(500))
            .with_priority(1)
            .mount(&w.server)
            .await;
        let cfg = Config::from_env_config(e).unwrap();
        let Mode::Reshare(src) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let err = format!("{:#}", run_reshare(&cfg, src, &w.run).await.unwrap_err());
        for s in [
            "GCS upload 500",
            "p-4 cofhe-tee-zk-signer version 2 (share)",
            "share_version is above 2",
        ] {
            assert!(err.contains(s), "{err}");
        }
        // The sidecar went up before the failed manifest, and a reshare has no guard.
        assert!(err.contains("p/0/public-material.v2.provenance"), "{err}");
        assert!(!err.contains("replace_live_keyset"), "{err}");
    }

    // The live manifest must name the baked live signers. Anything else is another
    // keyset, for example an older one restored into the bucket.
    #[test]
    fn reshare_refuses_a_manifest_of_another_keyset() {
        let cfg = Config::from_env_config(replace_env()).unwrap();
        let Mode::Reshare(r) = cfg.mode else {
            panic!("expected reshare mode")
        };
        let shares = |ids: &[&str]| -> Vec<(String, [u8; 32])> {
            ids.iter().map(|id| (id.to_string(), [0; 32])).collect()
        };
        let manifest = |decrypt: &str, zk: &str| PublicMaterial {
            server_key_digest: [0; 32],
            compact_public_key_digest: [0; 32],
            crs_digest: [0; 32],
            decrypt_signer_address: decrypt.to_string(),
            zk_signer_address: zk.to_string(),
            fhe_priv_digest: [0; 32],
            zk_signer_digest: [0; 32],
            fhe_priv_share_digests: shares(&["p-1", "p-2", "p-3"]),
            zk_signer_share_digests: shares(&["p-1", "p-2", "p-3"]),
        };
        check_live_anchor(&manifest(LIVE_DECRYPT, LIVE_ZK), r).unwrap();
        assert!(check_live_anchor(&manifest(LIVE_ZK, LIVE_ZK), r).is_err());
        assert!(check_live_anchor(&manifest(LIVE_DECRYPT, LIVE_DECRYPT), r).is_err());
        // The manifest stores what the keygen derived: lowercase. Compare exactly.
        let upper = LIVE_DECRYPT.replace("0x", "0X");
        assert!(check_live_anchor(&manifest(&upper, LIVE_ZK), r).is_err());
        // A manifest of another share set means the env is wrong.
        let mut other = manifest(LIVE_DECRYPT, LIVE_ZK);
        other.zk_signer_share_digests = shares(&["p-1", "p-2", "p-4"]);
        let err = check_live_anchor(&other, r).unwrap_err().to_string();
        assert!(err.contains("the env is wrong"), "{err}");
    }
}
