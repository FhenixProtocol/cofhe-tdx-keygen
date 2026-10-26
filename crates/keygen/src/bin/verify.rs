//! Manual acceptance tool: read a partner's `SecretEnvelope` from Secret Manager
//! and check the secret's payload (one Shamir share) against that partner's
//! per-share digest in the public material. `verify reconstruct` checks the full
//! key. Doubles as the round-trip validator for a real run.
//!
//! Each per-audience secret is checked independently (run once per secret):
//!   verify --project cofhe-tee-partner-1 --secret cofhe-tee-fhe-priv --version <N> \
//!     --token "$(gcloud auth print-access-token)" \
//!     --bucket <name> --public-object <manifest of version N>

use anyhow::{bail, Context, Result};
use cofhe_keys::gcs::GcsClient;
use cofhe_keys::keygen;
use cofhe_keys::reader::{
    lookup, partner_refs, read_fhe_priv, read_zk_signer, PartnerAccess, PartnerRef, ReaderContext,
};
use cofhe_keys::secrets::SecretManager;
use cofhe_keys::serialization::{self, SecretEnvelope};
use std::num::NonZeroU64;

const SM_URL: &str = "https://secretmanager.googleapis.com";
const GCS_URL: &str = "https://storage.googleapis.com";

struct Args {
    project: String,
    secret: String,
    version: NonZeroU64,
    token: String,
    sm_url: String,
    bucket: Option<String>,
    public_object: String,
    gcs_url: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: verify --project <p> --secret <s> --version <N> --token <access_token> \\\n  \
         --public-object <name> [--bucket <name>] [--sm-url <url>] [--gcs-url <url>]\n\n\
         Reads the secret envelope at version N (there is no latest) and, with\n\
         --bucket, checks its payload (one share) against the per-share digest\n\
         published for --project in --public-object, the manifest of that version."
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
    let mut version = None;
    let mut token = None;
    let mut sm_url = SM_URL.to_string();
    let mut bucket = None;
    let mut public_object = None;
    let mut gcs_url = GCS_URL.to_string();

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--project" => project = Some(req_val(&argv, i)?),
            "--secret" => secret = Some(req_val(&argv, i)?),
            "--version" => version = Some(req_val(&argv, i)?.parse().context("--version")?),
            "--token" => token = Some(req_val(&argv, i)?),
            "--sm-url" => sm_url = req_val(&argv, i)?,
            "--bucket" => bucket = Some(req_val(&argv, i)?),
            "--public-object" => public_object = Some(req_val(&argv, i)?),
            "--gcs-url" => gcs_url = req_val(&argv, i)?,
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {}", other),
        }
        i += 2;
    }

    Ok(Args {
        project: project.context("--project is required")?,
        secret: secret.context("--secret is required")?,
        version: version.context("--version is required")?,
        token: token.context("--token is required")?,
        sm_url: require_https("--sm-url", sm_url)?,
        bucket,
        public_object: public_object.context("--public-object is required")?,
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
    let (_, raw) = sm
        .access_version(&args.token, &args.project, &args.secret, args.version)
        .await
        .context("read envelope from Secret Manager")?;
    let envelope =
        SecretEnvelope::from_canonical_bytes(raw.as_slice()).context("decode SecretEnvelope")?;
    let hash = envelope.payload_hash();
    println!(
        "OK  secret envelope decoded — SHA-256(payload) = {}",
        hex::encode(hash)
    );

    // With --bucket, check the payload against this partner's published per-share
    // digest, the same liar filter a consumer runs.
    if let Some(bucket) = &args.bucket {
        let gcs = GcsClient::new(&args.gcs_url);
        let public_material = gcs
            .download(&args.token, bucket, &args.public_object)
            .await
            .context("download public material")?;
        let public = serialization::PublicMaterial::from_canonical_bytes(&public_material)
            .context("decode public material")?;
        let matched = published_digest_for(&public, &args.project, &hash)?;
        println!(
            "OK  {project}'s entry in the published {matched} matches this secret's payload",
            project = args.project
        );
    }

    Ok(())
}

// One secret version holds one Shamir share, never the full key, so it matches
// only its own partner's entry in a per-share digest list. The full-key digests
// are checked by `verify reconstruct`.
fn published_digest_for(
    public: &serialization::PublicMaterial,
    project: &str,
    hash: &[u8; 32],
) -> Result<&'static str> {
    for (label, digests) in [
        ("fhe_priv_share_digests", &public.fhe_priv_share_digests),
        ("zk_signer_share_digests", &public.zk_signer_share_digests),
    ] {
        if digests.iter().any(|(id, d)| id == project && d == hash) {
            return Ok(label);
        }
    }
    bail!("this secret's payload matches NEITHER per-share digest published for partner {project}");
}

#[cfg(test)]
mod share_digest_tests {
    use super::published_digest_for;
    use cofhe_keys::serialization::PublicMaterial;

    fn manifest() -> PublicMaterial {
        PublicMaterial {
            server_key_digest: [0; 32],
            compact_public_key_digest: [0; 32],
            crs_digest: [0; 32],
            decrypt_signer_address: String::new(),
            zk_signer_address: String::new(),
            fhe_priv_digest: [1; 32],
            zk_signer_digest: [2; 32],
            fhe_priv_share_digests: vec![("p-1".into(), [11; 32]), ("p-2".into(), [12; 32])],
            zk_signer_share_digests: vec![("p-1".into(), [21; 32]), ("p-2".into(), [22; 32])],
        }
    }

    #[test]
    fn a_correct_share_matches_its_partner_digest() {
        let m = manifest();
        assert_eq!(
            published_digest_for(&m, "p-2", &[12; 32]).unwrap(),
            "fhe_priv_share_digests"
        );
        assert_eq!(
            published_digest_for(&m, "p-1", &[21; 32]).unwrap(),
            "zk_signer_share_digests"
        );
    }

    #[test]
    fn a_wrong_payload_fails() {
        let m = manifest();
        assert!(published_digest_for(&m, "p-1", &[9; 32]).is_err());
        // Another partner's share is not this partner's share.
        assert!(published_digest_for(&m, "p-1", &[12; 32]).is_err());
    }
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
    version: NonZeroU64,
    token: String,
    // Optional operator OVERRIDES: default to the baked env source. An
    // explicit flag still wins, for testing against an ad-hoc bucket/object.
    bucket: Option<String>,
    sm_url: String,
    gcs_url: String,
    public_object: Option<String>,
    secret_fhe_priv: String,
    secret_zk_signer: String,
    check_keys: bool,
}

fn recon_usage() -> ! {
    eprintln!(
        "usage: verify reconstruct --env <staging|testnet|mainnet> --threshold <T> \\\n  \
         --version <N> --token <access_token> \\\n  \
         [--bucket <name>] [--public-object <name>] \\\n  \
         [--secret-fhe-priv <s>] [--secret-zk-signer <s>] \\\n  \
         [--sm-url <url>] [--gcs-url <url>] [--check-keys]\n\n\
         The partner set AND the public-material bucket/object are BAKED per\n\
         environment — --env selects them and fails closed on anything\n\
         else. --bucket / --public-object are optional OVERRIDES for testing against\n\
         an ad-hoc location; omitted, they default to the baked env source. Fetches\n\
         each partner's share at version N (there is no latest), reconstructs both\n\
         secrets from T good shares, and validates them against the published full\n\
         digests. --check-keys also proves the rebuilt key is the key behind the\n\
         published public keys and signers (the check a reshare runs before it writes)."
    );
    std::process::exit(2);
}

fn parse_reconstruct_args(argv: &[String]) -> Result<ReconArgs> {
    let mut env = None;
    let mut threshold = None;
    let mut version = None;
    let mut token = None;
    let mut bucket = None;
    let mut sm_url = SM_URL.to_string();
    let mut gcs_url = GCS_URL.to_string();
    let mut public_object = None;
    let mut secret_fhe_priv = "cofhe-tee-fhe-priv".to_string();
    let mut secret_zk_signer = "cofhe-tee-zk-signer".to_string();
    let mut check_keys = false;

    let mut i = 2; // skip argv[0] and the "reconstruct" subcommand
    while i < argv.len() {
        if argv[i] == "--check-keys" {
            check_keys = true;
            i += 1;
            continue;
        }
        match argv[i].as_str() {
            "--env" => env = Some(req_val(argv, i)?),
            "--threshold" => threshold = Some(req_val(argv, i)?.parse().context("--threshold")?),
            "--version" => version = Some(req_val(argv, i)?.parse().context("--version")?),
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
        version: version.context("--version is required")?,
        token: token.context("--token is required")?,
        bucket,
        sm_url: require_https("--sm-url", sm_url)?,
        gcs_url: require_https("--gcs-url", gcs_url)?,
        public_object,
        secret_fhe_priv,
        secret_zk_signer,
        check_keys,
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
    let fhe = read_fhe_priv(
        &ctx,
        &operator_access(&fhe_partners, &a.token),
        a.threshold,
        &|_| a.version,
    )
    .await
    .context("reconstruct fhe-priv")?;
    println!(
        "OK  fhe-priv reconstructed {}-of-{} — client_key {} B, decrypt_signer_priv {} B (validated vs published full digest)",
        a.threshold, n, fhe.client_key.len(), fhe.decrypt_signer_priv.len()
    );

    let zk_partners = partner_refs(env_cfg, "zee-k", &a.secret_zk_signer)?;
    let zk = read_zk_signer(
        &ctx,
        &operator_access(&zk_partners, &a.token),
        a.threshold,
        &|_| a.version,
    )
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
    let mut artifacts = keygen::PublicArtifacts::default();
    for (slot, name, digest, label) in [
        (
            &mut artifacts.server_key,
            "computation_key",
            &public.server_key_digest,
            "server_key",
        ),
        (
            &mut artifacts.compact_public_key,
            "public_key",
            &public.compact_public_key_digest,
            "compact_public_key",
        ),
        (&mut artifacts.crs, "crs", &public.crs_digest, "crs"),
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
        *slot = bytes;
    }

    if a.check_keys {
        keygen::verify_against_public(&fhe, &zk, &public, &artifacts)
            .context("check the rebuilt key against the published keys")?;
        println!("OK  the rebuilt key matches the published public keys and signers");
    }

    Ok(())
}

#[cfg(test)]
mod reconstruct_args_tests {
    use super::parse_reconstruct_args;

    fn argv(extra: &[&str]) -> Vec<String> {
        [
            "verify",
            "reconstruct",
            "--env",
            "staging",
            "--threshold",
            "2",
            "--version",
            "1",
            "--token",
            "t",
        ]
        .iter()
        .chain(extra)
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn check_keys_is_a_flag_without_a_value() {
        assert!(!parse_reconstruct_args(&argv(&[])).unwrap().check_keys);
        let a = parse_reconstruct_args(&argv(&["--check-keys", "--bucket", "b"])).unwrap();
        assert!(a.check_keys);
        assert_eq!(a.bucket.as_deref(), Some("b"));
    }
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
