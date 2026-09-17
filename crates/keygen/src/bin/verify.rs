//! Manual acceptance tool: read a partner's `SecretEnvelope` from Secret Manager
//! and check the secret's payload against the published digest in the public
//! material (the reconstruction anchor a consumer validates against). Doubles as
//! the round-trip validator for a real run.
//!
//! Each per-audience secret is checked independently (run once per secret):
//!   verify --project cofhe-tee-partner-1 --secret cofhe-tee-fhe-priv \
//!     --token "$(gcloud auth print-access-token)" \
//!     --bucket <name> --public-object keys/versionized/0/public-material

use anyhow::{bail, Context, Result};
use cofhe_keys::gcs::GcsClient;
use cofhe_keys::reader::{
    lookup, partner_refs, read_fhe_priv, read_zk_signer, PartnerAccess, PartnerRef, ReaderContext,
};
use cofhe_keys::secrets::SecretManager;
use cofhe_keys::serialization::{self, SecretEnvelope};

const SM_URL: &str = "https://secretmanager.googleapis.com";
const GCS_URL: &str = "https://storage.googleapis.com";

struct Args {
    project: String,
    secret: String,
    token: String,
    sm_url: String,
    bucket: Option<String>,
    public_object: String,
    gcs_url: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: verify --project <p> --secret <s> --token <access_token> \\\n  \
         [--bucket <name>] [--public-object <name>] [--sm-url <url>] [--gcs-url <url>]\n\n\
         Reads the secret envelope and, with --bucket, checks its payload against\n\
         the published fhe_priv_digest / zk_signer_digest in the public material."
    );
    std::process::exit(2);
}

fn req_val(argv: &[String], i: usize) -> Result<String> {
    argv.get(i + 1)
        .cloned()
        .with_context(|| format!("missing value for {}", argv[i]))
}

/// The endpoint URLs carry a gcloud bearer token; a plain-http URL (typo or
/// otherwise) would send it in cleartext and bypass the pinned TLS posture
/// entirely, so refuse anything that isn't https.
fn require_https(flag: &str, url: String) -> Result<String> {
    if !url.starts_with("https://") {
        bail!("{flag} must be an https:// URL, got {url:?}");
    }
    Ok(url)
}

/// Object path of a sibling of the public-material manifest (the FHE artifacts live
/// alongside it under the same prefix, e.g. `keys/versionized/0/computation_key`).
fn sibling_object(public_object: &str, name: &str) -> String {
    match public_object.rfind('/') {
        Some(i) => format!("{}/{}", &public_object[..i], name),
        None => name.to_string(),
    }
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut project = None;
    let mut secret = None;
    let mut token = None;
    let mut sm_url = SM_URL.to_string();
    let mut bucket = None;
    let mut public_object = "keys/versionized/0/public-material".to_string();
    let mut gcs_url = GCS_URL.to_string();

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--project" => project = Some(req_val(&argv, i)?),
            "--secret" => secret = Some(req_val(&argv, i)?),
            "--token" => token = Some(req_val(&argv, i)?),
            "--sm-url" => sm_url = req_val(&argv, i)?,
            "--bucket" => bucket = Some(req_val(&argv, i)?),
            "--public-object" => public_object = req_val(&argv, i)?,
            "--gcs-url" => gcs_url = req_val(&argv, i)?,
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {}", other),
        }
        i += 2;
    }

    Ok(Args {
        project: project.context("--project is required")?,
        secret: secret.context("--secret is required")?,
        token: token.context("--token is required")?,
        sm_url: require_https("--sm-url", sm_url)?,
        bucket,
        public_object,
        gcs_url: require_https("--gcs-url", gcs_url)?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Same pinned TLS posture as the ceremony binary (TLS 1.3 + X25519MLKEM768).
    cofhe_keys::tls::provider()
        .install_default()
        .expect("install pinned rustls crypto provider");

    // `verify reconstruct …` exercises the live Shamir read path (fetch all N
    // shares → reconstruct from T → validate full digest → name liars); the
    // default (no subcommand) checks one secret against the published digest.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("reconstruct") {
        return reconstruct_main(&argv).await;
    }

    let args = parse_args()?;

    let sm = SecretManager::new(&args.sm_url);
    let raw = sm
        .access(&args.token, &args.project, &args.secret)
        .await
        .context("read envelope from Secret Manager")?;
    let envelope =
        SecretEnvelope::from_canonical_bytes(raw.as_slice()).context("decode SecretEnvelope")?;
    let hash = envelope.payload_hash();
    println!(
        "OK  secret envelope decoded — SHA-256(payload) = {}",
        hex::encode(hash)
    );

    // With --bucket, check the payload against the published per-secret digest —
    // the reconstruction anchor a consumer validates against.
    if let Some(bucket) = &args.bucket {
        let gcs = GcsClient::new(&args.gcs_url);
        let public_material = gcs
            .download(&args.token, bucket, &args.public_object)
            .await
            .context("download public material")?;
        let public = serialization::PublicMaterial::from_canonical_bytes(&public_material)
            .context("decode public material")?;
        if hash == public.fhe_priv_digest {
            println!("OK  published fhe_priv_digest matches this secret's payload");
        } else if hash == public.zk_signer_digest {
            println!("OK  published zk_signer_digest matches this secret's payload");
        } else {
            bail!("this secret's payload matches NEITHER published digest in the public material");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `verify reconstruct` — live Shamir read path
//
// Thin CLI over `cofhe_keys::reader`: fetch every partner's share, reconstruct
// each secret from T good shares, and validate against the published full digest
// (the exact path a consumer runs). The partner set is BAKED per environment —
// --env selects it fail-closed; --threshold picks T.
// ---------------------------------------------------------------------------

/// Wrap each ref in a [`PartnerAccess`] carrying the operator token. Repeating the
/// SAME token across partners is valid here: the CLI authenticates as the operator
/// (whose identity each partner granted directly), not per-partner.
fn operator_access<'a>(refs: &'a [PartnerRef], token: &'a str) -> Vec<PartnerAccess<'a>> {
    refs.iter()
        .map(|partner| PartnerAccess {
            partner,
            sm_token: token,
        })
        .collect()
}

struct ReconArgs {
    env: String,
    threshold: u8,
    token: String,
    // Optional operator OVERRIDES: default to the baked env source. An
    // explicit flag still wins, for testing against an ad-hoc bucket/object.
    bucket: Option<String>,
    sm_url: String,
    gcs_url: String,
    public_object: Option<String>,
    secret_fhe_priv: String,
    secret_zk_signer: String,
}

fn recon_usage() -> ! {
    eprintln!(
        "usage: verify reconstruct --env <staging|testnet|mainnet> --threshold <T> \\\n  \
         --token <access_token> \\\n  \
         [--bucket <name>] [--public-object <name>] \\\n  \
         [--secret-fhe-priv <s>] [--secret-zk-signer <s>] \\\n  \
         [--sm-url <url>] [--gcs-url <url>]\n\n\
         The partner set AND the public-material bucket/object are BAKED per\n\
         environment — --env selects them and fails closed on anything\n\
         else. --bucket / --public-object are optional OVERRIDES for testing against\n\
         an ad-hoc location; omitted, they default to the baked env source. Fetches\n\
         each partner's share, reconstructs both secrets from T good shares, and\n\
         validates them against the published full digests."
    );
    std::process::exit(2);
}

fn parse_reconstruct_args(argv: &[String]) -> Result<ReconArgs> {
    let mut env = None;
    let mut threshold = None;
    let mut token = None;
    let mut bucket = None;
    let mut sm_url = SM_URL.to_string();
    let mut gcs_url = GCS_URL.to_string();
    let mut public_object = None;
    let mut secret_fhe_priv = "cofhe-tee-fhe-priv".to_string();
    let mut secret_zk_signer = "cofhe-tee-zk-signer".to_string();

    let mut i = 2; // skip argv[0] and the "reconstruct" subcommand
    while i < argv.len() {
        match argv[i].as_str() {
            "--env" => env = Some(req_val(argv, i)?),
            "--threshold" => threshold = Some(req_val(argv, i)?.parse().context("--threshold")?),
            "--token" => token = Some(req_val(argv, i)?),
            "--bucket" => bucket = Some(req_val(argv, i)?),
            "--sm-url" => sm_url = req_val(argv, i)?,
            "--gcs-url" => gcs_url = req_val(argv, i)?,
            "--public-object" => public_object = Some(req_val(argv, i)?),
            "--secret-fhe-priv" => secret_fhe_priv = req_val(argv, i)?,
            "--secret-zk-signer" => secret_zk_signer = req_val(argv, i)?,
            "-h" | "--help" => recon_usage(),
            other => bail!("unknown argument: {}", other),
        }
        i += 2;
    }

    Ok(ReconArgs {
        env: env.context("--env is required")?,
        threshold: threshold.context("--threshold is required")?,
        token: token.context("--token is required")?,
        bucket,
        sm_url: require_https("--sm-url", sm_url)?,
        gcs_url: require_https("--gcs-url", gcs_url)?,
        public_object,
        secret_fhe_priv,
        secret_zk_signer,
    })
}

async fn reconstruct_main(argv: &[String]) -> Result<()> {
    // Surface the reader's excluded-partner / liar `warn!`s on the console.
    let _ = tracing_subscriber::fmt().try_init();

    let a = parse_reconstruct_args(argv)?;
    // Fail-closed env selection: the partner set is baked per
    // environment; an unknown --env aborts before any network call.
    let env_cfg = lookup(&a.env)?;
    if a.threshold < cofhe_keys::shamir::MIN_THRESHOLD {
        bail!(
            "--threshold must be >= {}",
            cofhe_keys::shamir::MIN_THRESHOLD
        );
    }
    if a.threshold as usize > env_cfg.partners.len() {
        bail!(
            "--threshold ({}) exceeds the number of partners ({})",
            a.threshold,
            env_cfg.partners.len()
        );
    }

    // Default the public-material location to the BAKED env source so verify is
    // consistent-by-default with what the consumers read; an explicit --bucket /
    // --public-object still wins (operator testing against an ad-hoc bucket).
    let public_bucket = a.bucket.as_deref().unwrap_or(env_cfg.public_bucket);
    let public_object = a.public_object.as_deref().unwrap_or(env_cfg.public_object);

    let sm = SecretManager::new(&a.sm_url);
    let gcs = GcsClient::new(&a.gcs_url);

    let ctx = ReaderContext {
        sm: &sm,
        gcs: &gcs,
        gcs_token: &a.token,
        public_bucket,
        public_object,
    };

    let n = env_cfg.partners.len();

    // Audiences are stamped by partner_refs but UNUSED here — the CLI
    // authenticates with the operator token, not per-partner federation.
    let fhe_partners = partner_refs(env_cfg, "teecryptor", &a.secret_fhe_priv)?;
    let fhe = read_fhe_priv(&ctx, &operator_access(&fhe_partners, &a.token), a.threshold)
        .await
        .context("reconstruct fhe-priv")?;
    println!(
        "OK  fhe-priv reconstructed {}-of-{} — client_key {} B, decrypt_signer_priv {} B (validated vs published full digest)",
        a.threshold, n, fhe.client_key.len(), fhe.decrypt_signer_priv.len()
    );

    let zk_partners = partner_refs(env_cfg, "zee-k", &a.secret_zk_signer)?;
    let zk = read_zk_signer(&ctx, &operator_access(&zk_partners, &a.token), a.threshold)
        .await
        .context("reconstruct zk-signer")?;
    println!(
        "OK  zk-signer reconstructed {}-of-{} — zk_signer_priv {} B (validated vs published full digest)",
        a.threshold, n, zk.zk_signer_priv.len()
    );

    // The reconstruct path validated each secret against the manifest's published
    // full digest. Re-read the manifest to check the three public FHE artifacts —
    // served as separate objects, the layout cofhe mounts — each against its
    // manifest digest, the same check a file-reading consumer runs.
    let manifest = gcs
        .download(&a.token, public_bucket, public_object)
        .await
        .context("download public-material manifest")?;
    let public = serialization::PublicMaterial::from_canonical_bytes(&manifest)
        .context("decode public-material manifest")?;
    for (name, digest, label) in [
        ("computation_key", &public.server_key_digest, "server_key"),
        (
            "public_key",
            &public.compact_public_key_digest,
            "compact_public_key",
        ),
        ("crs", &public.crs_digest, "crs"),
    ] {
        let obj = sibling_object(public_object, name);
        let bytes = gcs
            .download(&a.token, public_bucket, &obj)
            .await
            .with_context(|| format!("download {label} artifact {obj}"))?;
        serialization::verify_artifact(&bytes, digest, label)
            .with_context(|| format!("verify {label} artifact"))?;
        println!(
            "OK  {label} artifact ({obj}) matches its manifest digest ({} B)",
            bytes.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod url_guard_tests {
    use super::require_https;

    #[test]
    fn accepts_https_url() {
        let url = require_https(
            "--sm-url",
            "https://secretmanager.googleapis.com".to_string(),
        )
        .expect("https URL must be accepted");
        assert_eq!(url, "https://secretmanager.googleapis.com");
    }

    #[test]
    fn rejects_plain_http_url() {
        let err = require_https(
            "--sm-url",
            "http://secretmanager.googleapis.com".to_string(),
        )
        .expect_err("plain http must be rejected");
        assert!(
            err.to_string().contains("--sm-url"),
            "error names the flag: {err}"
        );
    }
}
