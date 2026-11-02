use crate::attestation::AttestationClient;
use crate::gcp_auth::{GcpAuth, MetadataClient};
use crate::publish::{OBJ_CRS, OBJ_PUBLIC_KEY, OBJ_SERVER_KEY};
use crate::{Run, WRITE_SECRET_FHE_PRIV, WRITE_SECRET_ZK_SIGNER};
use cofhe_keys::envs::{v, EnvConfig, EnvPartner, ReshareSource, SourcePartner};
use cofhe_keys::gcs::GcsClient;
use cofhe_keys::keygen;
use cofhe_keys::secrets::SecretManager;
use cofhe_keys::serialization::{PublicMaterial, SecretEnvelope};
use std::num::NonZeroU64;

// The default mocked Secret Manager version; tests that prove an exact version use their own literal.
pub(crate) const TEST_VERSION: NonZeroU64 = NonZeroU64::MIN;

pub(crate) fn env_partner(id: &'static str, num: &'static str) -> EnvPartner {
    EnvPartner {
        project_id: id,
        wip_pool_audience: Box::leak(
            format!("//iam.googleapis.com/projects/{num}/locations/global/workloadIdentityPools/cofhe-tee-reader-pool")
                .into_boxed_str(),
        ),
        keygen_write_audience: Box::leak(
            format!("//iam.googleapis.com/projects/{num}/locations/global/workloadIdentityPools/cofhe-tee-keygen-pool/providers/cofhe-tee-keygen-provider")
                .into_boxed_str(),
        ),
    }
}

pub(crate) fn set(ids: &[(&'static str, &'static str)]) -> &'static [EnvPartner] {
    Box::leak(
        ids.iter()
            .map(|(id, n)| env_partner(id, n))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

pub(crate) fn sources(partners: &[EnvPartner]) -> &'static [SourcePartner] {
    Box::leak(
        partners
            .iter()
            .map(|&partner| SourcePartner {
                partner,
                share_version: None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

pub(crate) const P1: (&str, &str) = ("p-1", "111111111111");
pub(crate) const P2: (&str, &str) = ("p-2", "222222222222");
pub(crate) const P3: (&str, &str) = ("p-3", "333333333333");
pub(crate) const P4: (&str, &str) = ("p-4", "444444444444");

pub(crate) const LIVE_DECRYPT: &str = "0x1111111111111111111111111111111111111111";
pub(crate) const LIVE_ZK: &str = "0x2222222222222222222222222222222222222222";

pub(crate) fn env(
    target: &'static [EnvPartner],
    t: u8,
    source: Option<(&'static [EnvPartner], u8)>,
) -> &'static EnvConfig {
    Box::leak(Box::new(EnvConfig {
        partners: target,
        public_bucket: "b",
        public_prefix: "p",
        public_zone: 0,
        shamir_threshold: t,
        share_version: v(2),
        reshare_from: source.map(|(partners, shamir_threshold)| ReshareSource {
            partners: sources(partners),
            shamir_threshold,
            share_version: v(1),
            legacy_manifest: false,
            decrypt_signer_address: LIVE_DECRYPT,
            zk_signer_address: LIVE_ZK,
        }),
        replace_live_keyset: false,
    }))
}

// 2-of-3 on p1..p3 → 2-of-3 on p1, p2, p4: replace p3 with p4.
pub(crate) fn replace_env() -> &'static EnvConfig {
    env(set(&[P1, P2, P4]), 2, Some((set(&[P1, P2, P3]), 2)))
}

// A mocked cloud for one run: GCS serves the live manifest and the three
// artifacts, Secret Manager serves each source share, STS and the metadata
// server hand out tokens, and a Unix socket plays the attestation launcher.
// Each test mounts its own write mocks.
pub(crate) struct World {
    pub(crate) server: wiremock::MockServer,
    pub(crate) run: Run,
    _dir: tempfile::TempDir,
}

pub(crate) async fn reshare_world(
    live: &PublicMaterial,
    artifacts: [Vec<u8>; 3],
    ids: &[String],
    shares: &[keygen::PartnerShares],
) -> World {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let [server_key, public_key, crs] = artifacts;
    for (name, body) in [
        ("public-material.v1", live.to_canonical_bytes()),
        (OBJ_SERVER_KEY, server_key),
        (OBJ_PUBLIC_KEY, public_key),
        (OBJ_CRS, crs),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/storage/v1/b/b/o/p%2F0%2F{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
    }
    for (id, share) in ids.iter().zip(shares) {
        for (secret, bytes) in [
            (WRITE_SECRET_FHE_PRIV, &share.fhe_priv_share),
            (WRITE_SECRET_ZK_SIGNER, &share.zk_signer_share),
        ] {
            let envelope = SecretEnvelope {
                payload: bytes.clone(),
                provenance_jwt: String::new(),
            };
            let data =
                base64::engine::general_purpose::STANDARD.encode(envelope.to_canonical_bytes());
            Mock::given(method("GET"))
                .and(path(format!(
                    "/v1/projects/{id}/secrets/{secret}/versions/{TEST_VERSION}:access"
                )))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "name": "v", "payload": { "data": data } }),
                    ),
                )
                .mount(&server)
                .await;
        }
    }
    Mock::given(method("POST"))
        .and(path("/sts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "access_token": "federated" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "access_token": "sa" })),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("teeserver.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = "attested.jwt.sig";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });
    let run = Run {
        attest: AttestationClient::new(&sock),
        auth: GcpAuth::new(format!("{}/sts", server.uri())),
        sm: SecretManager::new(server.uri()),
        gcs: GcsClient::new(server.uri()),
        metadata: MetadataClient::new(server.uri()),
    };
    World {
        server,
        run,
        _dir: dir,
    }
}

// Writes are refused: any Secret Manager write or GCS upload fails the test.
pub(crate) async fn forbid_writes(server: &wiremock::MockServer) {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, ResponseTemplate};
    for write in [":addVersion$", "^/upload/"] {
        Mock::given(method("POST"))
            .and(path_regex(write))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(server)
            .await;
    }
}

// Secret Manager lists `newest` as the newest version of `secret`.
pub(crate) async fn list_mock(
    server: &wiremock::MockServer,
    project: &str,
    secret: &str,
    newest: Option<u64>,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let versions: Vec<_> = newest
        .map(|n| serde_json::json!({ "name": format!("projects/1/secrets/{secret}/versions/{n}") }))
        .into_iter()
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/projects/{project}/secrets/{secret}/versions"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "versions": versions })),
        )
        .mount(server)
        .await;
}

// Each add to `secret` returns the next number of `returns`, in order.
pub(crate) async fn add_mock(
    server: &wiremock::MockServer,
    project: &str,
    secret: &str,
    returns: &[u64],
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    for n in returns {
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/projects/{project}/secrets/{secret}:addVersion"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "name": format!("projects/1/secrets/{secret}/versions/{n}") }),
            ))
            .up_to_n_times(1)
            .mount(server)
            .await;
    }
}

pub(crate) fn zero_public() -> PublicMaterial {
    PublicMaterial {
        server_key_digest: [0; 32],
        compact_public_key_digest: [0; 32],
        crs_digest: [0; 32],
        decrypt_signer_address: String::new(),
        zk_signer_address: String::new(),
        fhe_priv_digest: [0; 32],
        zk_signer_digest: [0; 32],
        fhe_priv_share_digests: vec![],
        zk_signer_share_digests: vec![],
    }
}

// A world with no reshare source data: tokens and attestation only.
pub(crate) async fn write_world() -> World {
    reshare_world(&zero_public(), Default::default(), &[], &[]).await
}
