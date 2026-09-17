use anyhow::{bail, Context, Result};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Characters to percent-encode in a GCS object name when placing it in the URL
/// path. Everything non-alphanumeric is encoded EXCEPT the RFC 3986 unreserved
/// marks, so `/` becomes `%2F` (GCS requires this in the single path segment) while
/// readable names like `keys/versionized/0/public-material` stay legible in logs.
const OBJECT_PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode an object name for the GCS download URL path segment.
fn encode_object(object_name: &str) -> String {
    utf8_percent_encode(object_name, OBJECT_PATH).to_string()
}

/// Generous HTTP timeout backstop (above any healthy call incl. the multi-MB
/// public-material transfer) so a hung endpoint can't make a request wait forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(900);

/// Cap on a downloaded object, well above the legitimate public material
/// (~33 MB). An object whose declared size exceeds this is rejected before its
/// body is buffered — bounding memory on the fail-closed read path if the bucket
/// were ever compromised to serve a giant object.
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

pub struct GcsClient {
    base_url: String,
    http: Client,
}

#[derive(Deserialize)]
struct ObjectResponse {
    name: String,
    // GCS always returns `generation`; default defensively so a missing field
    // can't turn a successful upload into a post-write parse error that aborts
    // the ceremony after the object already landed.
    #[serde(default)]
    generation: String,
}

impl GcsClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: crate::tls::http_client(HTTP_TIMEOUT),
        }
    }

    /// Upload an object via the GCS JSON API media upload. Returns
    /// `<name>#<generation>` for logging/audit. With bucket object versioning
    /// enabled, re-uploading the same name archives the prior generation rather
    /// than destroying it — so each run's public material supersedes the last,
    /// `latest` is current, and history is retained.
    pub async fn upload(
        &self,
        access_token: &str,
        bucket: &str,
        object_name: &str,
        data: &[u8],
    ) -> Result<String> {
        let url = format!("{}/upload/storage/v1/b/{}/o", self.base_url, bucket);
        let resp = self
            .http
            .post(&url)
            .query(&[("uploadType", "media"), ("name", object_name)])
            .bearer_auth(access_token)
            .header("content-type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .context("GCS upload request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCS upload {} — {}", status, text);
        }
        let parsed: ObjectResponse = resp.json().await.context("parse GCS upload response")?;
        Ok(format!("{}#{}", parsed.name, parsed.generation))
    }

    /// Download an object's bytes (latest live generation) via the GCS JSON API
    /// media download. Used by the consumer reader to fetch the public material.
    /// `object_name` is percent-encoded into the single path segment, so names
    /// containing `/` (e.g. `keys/versionized/0/public-material`) resolve to the
    /// right object rather than being split across path segments.
    pub async fn download(
        &self,
        access_token: &str,
        bucket: &str,
        object_name: &str,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.base_url,
            bucket,
            encode_object(object_name)
        );
        let resp = self
            .http
            .get(&url)
            .query(&[("alt", "media")])
            .bearer_auth(access_token)
            .send()
            .await
            .context("GCS download request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCS download {} — {}", status, text);
        }
        if let Some(len) = resp.content_length() {
            if len > MAX_DOWNLOAD_BYTES {
                bail!(
                    "GCS object is {} bytes, exceeds the {} byte cap",
                    len,
                    MAX_DOWNLOAD_BYTES
                );
            }
        }
        let bytes = resp.bytes().await.context("read GCS object body")?;
        if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
            bail!(
                "GCS object is {} bytes, exceeds the {} byte cap",
                bytes.len(),
                MAX_DOWNLOAD_BYTES
            );
        }
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn upload_posts_media_and_returns_name_generation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/our-bucket/o"))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", "public-material"))
            .and(header("authorization", "Bearer sa-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "public-material",
                "bucket": "our-bucket",
                "generation": "1700000000000001"
            })))
            .mount(&server)
            .await;

        let gcs = GcsClient::new(server.uri());
        let r = gcs
            .upload("sa-tok", "our-bucket", "public-material", b"hi")
            .await
            .unwrap();
        assert_eq!(r, "public-material#1700000000000001");
    }

    #[tokio::test]
    async fn upload_errors_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;
        let gcs = GcsClient::new(server.uri());
        assert!(gcs.upload("t", "b", "o", b"x").await.is_err());
    }

    #[tokio::test]
    async fn download_returns_object_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/b/our-bucket/o/public-material"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer sa-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PUBLIC_BYTES".to_vec()))
            .mount(&server)
            .await;

        let gcs = GcsClient::new(server.uri());
        let bytes = gcs
            .download("sa-tok", "our-bucket", "public-material")
            .await
            .unwrap();
        assert_eq!(bytes, b"PUBLIC_BYTES");
    }

    #[test]
    fn encode_object_percent_encodes_slashes_only() {
        assert_eq!(
            encode_object("keys/versionized/0/public-material"),
            "keys%2Fversionized%2F0%2Fpublic-material"
        );
        // A flat name is unchanged.
        assert_eq!(encode_object("public-material"), "public-material");
    }

    #[tokio::test]
    async fn download_encodes_slashed_object_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/storage/v1/b/our-bucket/o/keys%2Fversionized%2F0%2Fpublic-material",
            ))
            .and(query_param("alt", "media"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"MANIFEST".to_vec()))
            .mount(&server)
            .await;

        let gcs = GcsClient::new(server.uri());
        let bytes = gcs
            .download("sa-tok", "our-bucket", "keys/versionized/0/public-material")
            .await
            .unwrap();
        assert_eq!(bytes, b"MANIFEST");
    }

    #[tokio::test]
    async fn download_errors_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let gcs = GcsClient::new(server.uri());
        assert!(gcs.download("t", "b", "o").await.is_err());
    }
}
