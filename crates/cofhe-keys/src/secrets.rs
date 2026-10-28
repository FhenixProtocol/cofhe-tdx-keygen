use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::Deserialize;
use std::num::NonZeroU64;
use std::time::Duration;
use zeroize::Zeroizing;

/// Generous HTTP timeout backstop so a hung partner never makes a request wait
/// forever. The keygen write path relies on this for clean all-or-nothing abort
/// (well above any healthy call incl. multi-MB transfers); the reader caps its
/// per-partner reads far shorter via its own `READ_TIMEOUT`. There is no retry:
/// a retried add can create a second version and break the version numbers.
const HTTP_TIMEOUT: Duration = Duration::from_secs(1800);

pub struct SecretManager {
    base_url: String,
    http: Client,
}

#[derive(Deserialize)]
struct AccessResponse {
    name: String,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListVersionsResponse {
    #[serde(default)]
    versions: Vec<AddVersionResponse>,
    next_page_token: Option<String>,
}

/// The number at the end of a `.../versions/N` resource name. Fails on zero,
/// `latest` or any other shape.
pub fn version_number(name: &str) -> Result<NonZeroU64> {
    name.rsplit_once("/versions/")
        .and_then(|(_, n)| n.parse().ok())
        .with_context(|| format!("not a numbered secret version name: {name}"))
}

impl SecretManager {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: crate::tls::http_client(HTTP_TIMEOUT),
        }
    }

    /// Read one exact version of a secret; there is no `latest`. Secret Manager
    /// numbers versions from 1, so a zero version cannot be expressed. Returns the
    /// version resource name with the payload.
    pub async fn access_version(
        &self,
        access_token: &str,
        project_id: &str,
        secret_name: &str,
        version: NonZeroU64,
    ) -> Result<(String, Zeroizing<Vec<u8>>)> {
        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions/{}:access",
            self.base_url, project_id, secret_name, version
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
        Ok((parsed.name, Zeroizing::new(decoded)))
    }

    /// The newest version number of a secret in any state, or `None` when the
    /// secret has no versions. It reads every page and takes the max: the API does
    /// not promise an order, and a destroyed number is still never reused.
    pub async fn newest_version(
        &self,
        access_token: &str,
        project_id: &str,
        secret_name: &str,
    ) -> Result<Option<NonZeroU64>> {
        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions",
            self.base_url, project_id, secret_name
        );
        let mut newest = None;
        let mut page_token = None;
        loop {
            let mut req = self
                .http
                .get(&url)
                .query(&[("pageSize", "1000")])
                .bearer_auth(access_token);
            if let Some(t) = &page_token {
                req = req.query(&[("pageToken", t)]);
            }
            let resp = req
                .send()
                .await
                .context("secret manager list versions request failed")?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("secret manager list versions {} — {}", status, text);
            }
            let parsed: ListVersionsResponse =
                resp.json().await.context("parse list versions response")?;
            for v in &parsed.versions {
                newest = newest.max(Some(version_number(&v.name)?));
            }
            match parsed.next_page_token.filter(|t| !t.is_empty()) {
                Some(t) => page_token = Some(t),
                None => return Ok(newest),
            }
        }
    }

    /// Add a version with the caller's federated token; returns the version resource name.
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
    use crate::TEST_VERSION;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn decodes_base64_payload() {
        let server = MockServer::start().await;
        let raw = b"\x11\x22\x33\x44";
        let encoded = STANDARD.encode(raw);
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/test-project/secrets/k1/versions/7:access",
            ))
            .and(header("authorization", "Bearer sa-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/123/secrets/k1/versions/7",
                "payload": { "data": encoded }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let (name, bytes) = sm
            .access_version("sa-xyz", "test-project", "k1", NonZeroU64::new(7).unwrap())
            .await
            .unwrap();
        assert_eq!(name, "projects/123/secrets/k1/versions/7");
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
        assert!(sm
            .access_version("t", "p", "n", TEST_VERSION)
            .await
            .is_err());
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

    // Every state counts, and the list order is not trusted: the max wins.
    #[tokio::test]
    async fn newest_version_is_the_max_in_any_order() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/s/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [
                    { "name": "projects/1/secrets/s/versions/1", "state": "ENABLED" },
                    { "name": "projects/1/secrets/s/versions/8", "state": "DESTROYED" },
                    { "name": "projects/1/secrets/s/versions/3", "state": "DISABLED" }
                ]
            })))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        let newest = sm.newest_version("t", "p", "s").await.unwrap().unwrap();
        assert_eq!(newest.get(), 8);
    }

    // The max can sit on a later page.
    #[tokio::test]
    async fn newest_version_reads_every_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/s/versions"))
            .and(query_param("pageToken", "next"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{ "name": "projects/1/secrets/s/versions/9" }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/s/versions"))
            .and(query_param("pageSize", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{ "name": "projects/1/secrets/s/versions/2" }],
                "nextPageToken": "next"
            })))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        let newest = sm.newest_version("t", "p", "s").await.unwrap().unwrap();
        assert_eq!(newest.get(), 9);
    }

    #[tokio::test]
    async fn newest_version_is_none_for_an_empty_secret_and_fails_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/empty/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/denied/versions"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        assert!(sm
            .newest_version("t", "p", "empty")
            .await
            .unwrap()
            .is_none());
        assert!(sm.newest_version("t", "p", "denied").await.is_err());
    }

    #[test]
    fn version_number_parses_and_fails_closed() {
        assert_eq!(
            version_number("projects/1/secrets/s/versions/12")
                .unwrap()
                .get(),
            12
        );
        assert!(version_number("projects/1/secrets/s/versions/0").is_err());
        assert!(version_number("projects/1/secrets/s/versions/abc").is_err());
        assert!(version_number("projects/1/secrets/s").is_err());
    }
}
