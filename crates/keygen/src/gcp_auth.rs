use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Generous HTTP timeout backstop for the keygen write path (STS exchange +
/// metadata token). Above any healthy call; a hung endpoint aborts the
/// all-or-nothing ceremony cleanly rather than hanging the VM forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(900);

pub struct GcpAuth {
    sts_url: String,
    http: Client,
}

#[derive(Serialize)]
struct StsRequest<'a> {
    audience: &'a str,
    grant_type: &'static str,
    requested_token_type: &'static str,
    scope: &'static str,
    subject_token_type: &'static str,
    subject_token: &'a str,
}

#[derive(Deserialize)]
struct StsResponse {
    access_token: String,
}

impl GcpAuth {
    pub fn new(sts_url: impl Into<String>) -> Self {
        Self {
            sts_url: sts_url.into(),
            http: cofhe_keys::tls::http_client(HTTP_TIMEOUT),
        }
    }

    /// Exchange the attestation JWT for a federated access token. The partner grants
    /// the attested federated principal `secretVersionAdder` directly on the secret,
    /// so this token is used as the SM bearer as-is — no service-account
    /// impersonation hop.
    pub async fn exchange(&self, audience: &str, subject_jwt: &str) -> Result<String> {
        let body = StsRequest {
            audience,
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
            scope: "https://www.googleapis.com/auth/cloud-platform",
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
            subject_token: subject_jwt,
        };
        let resp = self
            .http
            .post(&self.sts_url)
            .json(&body)
            .send()
            .await
            .context("STS request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("STS {} — {}", status, text);
        }
        let parsed: StsResponse = resp.json().await.context("parse STS response")?;
        Ok(parsed.access_token)
    }
}

/// Fetches the VM's attached service-account access token from the GCE metadata
/// server. Used for writes to OUR project's resources (the public-material GCS
/// bucket) — distinct from the STS federated token, which is what authorizes the
/// cross-project write into the partner's Secret Manager.
pub struct MetadataClient {
    base_url: String,
    http: Client,
}

#[derive(Deserialize)]
struct MetadataToken {
    access_token: String,
}

impl MetadataClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: cofhe_keys::tls::http_client(HTTP_TIMEOUT),
        }
    }

    pub async fn token(&self) -> Result<String> {
        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/default/token",
            self.base_url
        );
        let resp = self
            .http
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .context("metadata token request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("metadata server {} — {}", status, text);
        }
        let parsed: MetadataToken = resp.json().await.context("parse metadata token")?;
        Ok(parsed.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exchange_returns_federated_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fed-abc",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let auth = GcpAuth::new(format!("{}/v1/token", server.uri()));
        let tok = auth.exchange("//audience", "subject-jwt").await.unwrap();
        assert_eq!(tok, "fed-abc");
    }

    #[tokio::test]
    async fn metadata_token_returns_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .and(header("metadata-flavor", "Google"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "meta-abc",
                "expires_in": 3599,
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let mc = MetadataClient::new(server.uri());
        assert_eq!(mc.token().await.unwrap(), "meta-abc");
    }
}
