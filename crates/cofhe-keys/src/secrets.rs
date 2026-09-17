use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use zeroize::Zeroizing;

/// Generous HTTP timeout backstop so a hung partner never makes a request wait
/// forever. The keygen write path relies on this for clean all-or-nothing abort
/// (10–15 min fuse, well above any healthy call incl. multi-MB transfers); the
/// reader caps its per-partner reads far shorter via its own `READ_TIMEOUT`.
const HTTP_TIMEOUT: Duration = Duration::from_secs(900);

pub struct SecretManager {
    base_url: String,
    http: Client,
}

#[derive(Deserialize)]
struct AccessResponse {
    payload: Payload,
}

#[derive(Deserialize)]
struct Payload {
    data: String,
}

#[derive(Deserialize)]
struct AddVersionResponse {
    name: String,
}

impl SecretManager {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: crate::tls::http_client(HTTP_TIMEOUT),
        }
    }

    // Read path: used by the consumer `reader` to fetch a partner's secret
    // envelope (the keygen write path itself never reads).
    pub async fn access(
        &self,
        access_token: &str,
        project_id: &str,
        secret_name: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions/latest:access",
            self.base_url, project_id, secret_name
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("secret manager request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("secret manager {} — {}", status, text);
        }
        let parsed: AccessResponse = resp.json().await.context("parse secret response")?;
        let decoded = STANDARD
            .decode(parsed.payload.data)
            .context("base64 decode")?;
        Ok(Zeroizing::new(decoded))
    }

    /// Add a new version to an existing secret (Secret Manager `addVersion`).
    /// This is the cross-project WRITE counterpart to `access`: the keygen
    /// enclave impersonates the partner's writer SA and pushes the generated
    /// key bytes as a new version into the partner's Secret Manager.
    /// Returns the created version's resource name.
    pub async fn add_version(
        &self,
        access_token: &str,
        project_id: &str,
        secret_name: &str,
        data: &[u8],
    ) -> Result<String> {
        let url = format!(
            "{}/v1/projects/{}/secrets/{}:addVersion",
            self.base_url, project_id, secret_name
        );
        let body = serde_json::json!({ "payload": { "data": STANDARD.encode(data) } });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .context("secret manager addVersion request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("secret manager addVersion {} — {}", status, text);
        }
        let parsed: AddVersionResponse = resp.json().await.context("parse addVersion response")?;
        Ok(parsed.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn decodes_base64_payload() {
        let server = MockServer::start().await;
        let raw = b"\x11\x22\x33\x44";
        let encoded = STANDARD.encode(raw);
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/test-project/secrets/k1/versions/latest:access",
            ))
            .and(header("authorization", "Bearer sa-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/.../secrets/k1/versions/1",
                "payload": { "data": encoded }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let bytes = sm.access("sa-xyz", "test-project", "k1").await.unwrap();
        assert_eq!(bytes.as_slice(), raw);
    }

    #[tokio::test]
    async fn errors_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        assert!(sm.access("t", "p", "n").await.is_err());
    }

    #[tokio::test]
    async fn add_version_posts_base64_payload_and_returns_name() {
        let server = MockServer::start().await;
        let raw = b"\xde\xad\xbe\xef";
        let encoded = STANDARD.encode(raw);
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/cofhe-tee-partner-1/secrets/bundle:addVersion",
            ))
            .and(header("authorization", "Bearer writer-tok"))
            .and(body_json(
                serde_json::json!({ "payload": { "data": encoded } }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/719/secrets/bundle/versions/1"
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let name = sm
            .add_version("writer-tok", "cofhe-tee-partner-1", "bundle", raw)
            .await
            .unwrap();
        assert_eq!(name, "projects/719/secrets/bundle/versions/1");
    }

    #[tokio::test]
    async fn add_version_errors_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        assert!(sm.add_version("t", "p", "n", b"x").await.is_err());
    }
}
