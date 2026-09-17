use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// The launcher socket is local and trusted, but a hung launcher must not block
/// this one-shot forever, and the response (a JWT, a few KB) must not be allowed
/// to grow unbounded.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 1 << 20; // 1 MiB — far above any real token.

pub struct AttestationClient {
    socket_path: PathBuf,
}

impl AttestationClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Write-gate token: no nonce. Presented to STS for the cross-project write.
    pub async fn fetch_token(&self, audience: &str) -> Result<String> {
        self.request_token(audience, &[]).await
    }

    /// Provenance token: `nonces` are echoed verbatim into the signed token's
    /// `eat_nonce` claim. The keygen passes `[hex(SHA-256(share))]`, stamping the
    /// share's origin into the wire format. The consumer reader no longer verifies
    /// this token (see the AGENTS.md invariant); it is kept for wire-format
    /// compatibility.
    pub async fn fetch_token_with_nonces(
        &self,
        audience: &str,
        nonces: &[String],
    ) -> Result<String> {
        self.request_token(audience, nonces).await
    }

    async fn request_token(&self, audience: &str, nonces: &[String]) -> Result<String> {
        let mut req = serde_json::json!({
            "audience": audience,
            "token_type": "OIDC",
        });
        if !nonces.is_empty() {
            req["nonces"] = serde_json::json!(nonces);
        }
        let body = req.to_string();

        let request = format!(
            "POST /v1/token HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        // The whole exchange (connect → write → read) is bounded by one timeout,
        // and the read is capped at MAX_RESPONSE_BYTES.
        let response = timeout(REQUEST_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .with_context(|| format!("connect to {:?}", self.socket_path))?;
            stream
                .write_all(request.as_bytes())
                .await
                .context("write attestation request")?;
            let mut response = Vec::new();
            stream
                .take(MAX_RESPONSE_BYTES)
                .read_to_end(&mut response)
                .await
                .context("read attestation response")?;
            Ok::<_, anyhow::Error>(response)
        })
        .await
        .context("attestation request timed out")??;

        let response_str =
            std::str::from_utf8(&response).context("attestation response not UTF-8")?;

        let status_line = response_str
            .split("\r\n")
            .next()
            .context("empty response")?;
        // Parse the numeric status code (the second whitespace-separated token of
        // "HTTP/1.x <code> <reason>") rather than substring-matching " 200 ".
        let status_code = status_line.split_whitespace().nth(1);
        if status_code != Some("200") {
            anyhow::bail!("teeserver returned: {}", status_line.trim());
        }

        let body_start = response_str
            .find("\r\n\r\n")
            .context("malformed HTTP response (no body separator)")?
            + 4;
        let raw_body = response_str[body_start..].trim();
        Ok(raw_body.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Spawns a tiny HTTP server on a Unix socket that returns `body` for any POST.
    async fn spawn_unix_server(socket: PathBuf, body: &'static str, status: u16) {
        let listener = UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
    }

    #[tokio::test]
    async fn returns_token_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_unix_server(sock.clone(), "eyJhbGciOi.payload.sig", 200).await;
        // Give the listener a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AttestationClient::new(&sock);
        let token = client.fetch_token("//test-audience").await.unwrap();
        assert_eq!(token, "eyJhbGciOi.payload.sig");
    }

    #[tokio::test]
    async fn errors_on_non_200() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_unix_server(sock.clone(), "boom", 500).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AttestationClient::new(&sock);
        assert!(client.fetch_token("//aud").await.is_err());
    }

    #[tokio::test]
    async fn includes_nonces_in_request() {
        use std::sync::{Arc, Mutex};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        let captured = Arc::new(Mutex::new(String::new()));
        let cap = captured.clone();
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                *cap.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = "tok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AttestationClient::new(&sock);
        let tok = client
            .fetch_token_with_nonces("//aud", &["deadbeef".to_string()])
            .await
            .unwrap();
        assert_eq!(tok, "tok");

        let req = captured.lock().unwrap().clone();
        assert!(req.contains("nonces"), "request missing nonces: {req}");
        assert!(
            req.contains("deadbeef"),
            "request missing nonce value: {req}"
        );
    }
}
