use crate::attestation::AttestationClient;
use crate::PROVENANCE_AUDIENCE;
use anyhow::Result;
use cofhe_keys::secrets::SecretManager;
use cofhe_keys::serialization::{sha256, SecretEnvelope};
use tracing::info;

/// Mint a provenance token binding `SHA-256(payload)`, wrap it in a
/// [`SecretEnvelope`], and write it as a new version of `secret`. Access pattern
/// B: the federated token is the Secret Manager bearer directly.
#[cfg(not(feature = "mock"))]
pub(crate) async fn write_secret(
    attest: &AttestationClient,
    sm: &SecretManager,
    federated: &str,
    project_id: &str,
    secret: &str,
    payload: Vec<u8>,
) -> Result<()> {
    let payload_hash = hex::encode(sha256(&payload));
    info!(secret = %secret, payload_hash = %payload_hash, "minting provenance (eat_nonce = SHA-256(payload))");
    let provenance_jwt = attest
        .fetch_token_with_nonces(PROVENANCE_AUDIENCE, &[payload_hash])
        .await?;
    let envelope = SecretEnvelope {
        payload,
        provenance_jwt,
    };
    let version = sm
        .add_version(
            federated,
            project_id,
            secret,
            &envelope.to_canonical_bytes(),
        )
        .await?;
    info!(secret = %secret, version = %version, "secret written to partner Secret Manager");
    Ok(())
}
