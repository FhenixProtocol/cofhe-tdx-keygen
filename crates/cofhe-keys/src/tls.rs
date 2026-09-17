//! Hardened TLS for every outbound googleapis connection (Secret Manager, STS,
//! GCS). Policy: TLS 1.3 only, key exchange pinned to the X25519MLKEM768
//! hybrid post-quantum group — fail-closed, no classical fallback. The
//! payloads on these connections are FHE key shares; classical-only key
//! exchange leaves them open to harvest-now-decrypt-later, so a peer that
//! cannot do hybrid PQ must break the connection loudly rather than downgrade.
//!
//! ML-KEM requires the aws-lc-rs rustls provider (ring has no ML-KEM and never
//! will). Binaries should also install [`provider`] as the process default so
//! any other rustls user in the dep tree inherits the same posture instead of
//! lazy-picking a provider (which panics when two providers are in the tree).

use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::{ClientConfig, RootCertStore};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// Built once per process — several clients are constructed at boot and the
/// provider + root-store assembly is not free.
static TLS_CONFIG: LazyLock<ClientConfig> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tls_config_with_roots(roots)
});

/// The aws-lc-rs provider restricted to the X25519MLKEM768 key-exchange group.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    }
}

/// TLS 1.3-only client config with the pinned key exchange and webpki roots.
/// Deliberately private: [`http_client`] is the single choke point — exposing
/// the raw config would let callers build connectors that miss any hardening
/// added there (e.g. the redirect-downgrade refusal).
fn tls_config() -> ClientConfig {
    TLS_CONFIG.clone()
}

fn tls_config_with_roots(roots: RootCertStore) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("aws-lc-rs supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // reqwest is built without the `http2` feature, so advertise HTTP/1.1 only —
    // an h2 ALPN offer the client can't actually speak would break on servers
    // that select it.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// A reqwest client carrying the hardened TLS config. Every outbound HTTPS
/// client in this workspace must be built through here; plain-HTTP endpoints
/// (the link-local metadata server, test mocks) are unaffected.
pub fn http_client(timeout: Duration) -> reqwest::Client {
    http_client_with_config(tls_config(), timeout)
}

fn http_client_with_config(config: ClientConfig, timeout: Duration) -> reqwest::Client {
    // reqwest's default policy follows redirects across a scheme downgrade;
    // an https->http hop would silently strip the pinned posture (and leak
    // bearer tokens in cleartext), so refuse it. Same 10-hop cap as default.
    let no_downgrade = reqwest::redirect::Policy::custom(|attempt| {
        let downgrade = attempt.url().scheme() == "http"
            && attempt
                .previous()
                .last()
                .is_some_and(|prev| prev.scheme() == "https");
        if downgrade {
            attempt.error("refusing redirect from https to plain http")
        } else if attempt.previous().len() >= 10 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    });
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .redirect(no_downgrade)
        .timeout(timeout)
        .build()
        .expect("build hardened HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{crypto::aws_lc_rs, NamedGroup, ProtocolVersion, ServerConfig};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    struct TestPki {
        server_config_base: (
            Vec<rustls::pki_types::CertificateDer<'static>>,
            PrivatePkcs8KeyDer<'static>,
        ),
        roots: RootCertStore,
    }

    fn test_pki() -> TestPki {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        TestPki {
            server_config_base: (vec![cert], key),
            roots,
        }
    }

    fn server_config(
        pki: &TestPki,
        kx: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<ServerConfig> {
        let provider = CryptoProvider {
            kx_groups: kx,
            ..aws_lc_rs::default_provider()
        };
        let (certs, key) = &pki.server_config_base;
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key().into())
            .unwrap();
        Arc::new(config)
    }

    /// Spawn a one-shot TLS server; returns its address. The server accepts a
    /// single connection and attempts the handshake (result intentionally
    /// ignored — the assertions live on the client side).
    async fn spawn_server(config: Arc<ServerConfig>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = TlsAcceptor::from(config).accept(stream).await;
        });
        addr
    }

    async fn client_handshake(
        roots: RootCertStore,
        addr: std::net::SocketAddr,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let connector = TlsConnector::from(Arc::new(tls_config_with_roots(roots)));
        let tcp = TcpStream::connect(addr).await?;
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
    }

    #[tokio::test]
    async fn negotiates_tls13_with_x25519mlkem768() {
        let pki = test_pki();
        let addr = spawn_server(server_config(
            &pki,
            vec![aws_lc_rs::kx_group::X25519MLKEM768],
            &[&rustls::version::TLS13],
        ))
        .await;

        let stream = client_handshake(pki.roots, addr)
            .await
            .expect("handshake against an ML-KEM-capable TLS 1.3 server must succeed");

        let (_, conn) = stream.get_ref();
        assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(
            conn.negotiated_key_exchange_group().map(|g| g.name()),
            Some(NamedGroup::X25519MLKEM768)
        );
    }

    #[tokio::test]
    async fn refuses_server_without_mlkem() {
        let pki = test_pki();
        let addr = spawn_server(server_config(
            &pki,
            vec![aws_lc_rs::kx_group::X25519],
            &[&rustls::version::TLS13],
        ))
        .await;

        client_handshake(pki.roots, addr)
            .await
            .expect_err("classical-only key exchange must be refused, not downgraded to");
    }

    #[tokio::test]
    async fn refuses_tls12_only_server() {
        let pki = test_pki();
        let addr = spawn_server(server_config(
            &pki,
            vec![aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
            &[&rustls::version::TLS12],
        ))
        .await;

        client_handshake(pki.roots, addr)
            .await
            .expect_err("a TLS 1.2-only server must be refused");
    }

    /// End-to-end through reqwest: catches config-plumbing mistakes the raw
    /// handshake tests can't see (ALPN mismatch, `use_preconfigured_tls`
    /// downcast/version drift).
    #[tokio::test]
    async fn reqwest_client_speaks_to_mlkem_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pki = test_pki();
        let config = server_config(
            &pki,
            vec![aws_lc_rs::kx_group::X25519MLKEM768],
            &[&rustls::version::TLS13],
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(config).accept(stream).await.unwrap();
            // Read the full request head — it may arrive split across TLS
            // records; responding early would race the client's writes.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tls.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed before finishing the request head");
                req.extend_from_slice(&buf[..n]);
            }
            tls.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        let client =
            http_client_with_config(tls_config_with_roots(pki.roots), Duration::from_secs(5));
        let resp = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .expect("reqwest request over pinned TLS must succeed");
        assert_eq!(resp.status(), 204);
        server.await.expect("server task panicked");
    }

    /// A redirect from https to plain http must be refused — following it would
    /// silently strip the entire pinned posture (and leak bearer tokens).
    #[tokio::test]
    async fn refuses_https_to_http_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Plain-HTTP endpoint that would happily answer if the client followed.
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = plain.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
        });

        let pki = test_pki();
        let config = server_config(
            &pki,
            vec![aws_lc_rs::kx_group::X25519MLKEM768],
            &[&rustls::version::TLS13],
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(config).accept(stream).await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tls.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed before finishing the request head");
                req.extend_from_slice(&buf[..n]);
            }
            let resp = format!(
                "HTTP/1.1 301 Moved Permanently\r\nlocation: http://127.0.0.1:{}/leak\r\ncontent-length: 0\r\n\r\n",
                plain_addr.port()
            );
            tls.write_all(resp.as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let client =
            http_client_with_config(tls_config_with_roots(pki.roots), Duration::from_secs(5));
        client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .expect_err("an https->http redirect must be refused, not followed");
    }
}
