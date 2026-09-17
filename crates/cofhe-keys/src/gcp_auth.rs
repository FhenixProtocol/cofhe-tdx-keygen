//! GCP auth helpers shared by consumers. `MetadataClient` fetches the VM's
//! attached (compute) service-account OAuth token from the GCE instance
//! metadata server; `GcpAuth` exchanges an attestation JWT for a federated
//! access token via STS. The reader stays auth-agnostic — consumers use these
//! helpers to obtain the token they then pass to the read path explicitly.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The GCE instance metadata server. Compile-time constant on purpose — never
/// env-overridable (a redirected metadata endpoint would hand out attacker
/// tokens).
pub const DEFAULT_METADATA_URL: &str = "http://metadata.google.internal";

/// The Google STS token-exchange endpoint. Compile-time constant on purpose —
/// never env-overridable (a redirected STS endpoint would capture the
/// attestation JWT and hand out attacker tokens).
pub const DEFAULT_STS_URL: &str = "https://sts.googleapis.com/v1/token";

/// A boot-time metadata fetch should fail fast: the server is link-local and
/// answers in milliseconds when present, so a short timeout distinguishes
/// "not on GCE / misconfigured" from a healthy call quickly.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Exchanges an attestation JWT for a federated access token via the Google
/// STS token-exchange endpoint. The attested federated
/// principal is granted IAM directly, so this token is used as the bearer
/// as-is — no service-account impersonation hop.
///
/// Consumers do this small per-partner exchange at boot, so it shares
/// `MetadataClient`'s short [`HTTP_TIMEOUT`]: a hung STS endpoint fails fast
/// rather than stalling the consumer's boot.
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
            http: crate::tls::http_client(HTTP_TIMEOUT),
        }
    }

    /// Exchange the attestation JWT for a federated access token.
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
            http: crate::tls::http_client(HTTP_TIMEOUT),
        }
    }

    /// Fetch the attached service account's OAuth access token.
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

    #[tokio::test]
    async fn metadata_error_status_bails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let mc = MetadataClient::new(server.uri());
        assert!(mc.token().await.is_err());
    }
}
