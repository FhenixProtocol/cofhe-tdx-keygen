#!/usr/bin/env bash
#
# Fail if terraform/service `local.public_material` drifts from the baked source of
# truth in cofhe_keys::reader (per-env public bucket + object prefix).
#
# reader.rs OWNS these values: the ceremony publishes where the baked map says, and
# every consumer reads from there. The Terraform local is only a hand-authored
# mirror — TF needs the same bucket/prefix to place the write grant and to scope the
# consumer read condition to `${public_prefix}/`. The two are authored in different
# toolchains and can silently diverge:
#   - a BUCKET mismatch fails a deploy loudly (403 / wrong bucket), but
#   - a PREFIX mismatch is silent-security: the read grant's IAM condition would be
#     scoped to a prefix nothing publishes to, or worse widened past the published
#     material toward the plaintext source keyset (on testnet that keyset co-lives in
#     the same bucket at keys/versionized, so a widened prefix would expose it).
# This check makes the mirror un-driftable.
#
# reader side  : `cargo run --example emit_public_material` -> {env:{bucket,prefix}}.
# terraform side: `terraform console` jsonencodes local.public_material. The config
#   pins `backend "gcs"`, and console insists on an initialized backend even with
#   -backend=false — so we evaluate against an ISOLATED copy of the *.tf with a
#   local-backend _override.tf. That needs no GCS creds/state and never touches the
#   real terraform/service state (the repo's hard rule). `env` only has to satisfy
#   the variable validation; local.public_material is the whole env-keyed map.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

reader_norm="$(cargo run --quiet -p keygen --example emit_public_material | jq -Sc .)"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cp terraform/service/*.tf "$workdir"/
cat > "$workdir/zz_drift_backend_override.tf" <<'EOF'
# Drift-check only: replace the gcs backend so `terraform console` can evaluate
# locals without GCP creds or remote state. Never applied.
terraform {
  backend "local" {}
}
EOF

tf_raw="$(
  cd "$workdir"
  terraform init -input=false >/dev/null
  TF_VAR_service_project_id=drift-check \
  TF_VAR_image_reference=drift-check \
  TF_VAR_env=staging \
    terraform console <<<'jsonencode(local.public_material)'
)"
# console prints the jsonencoded value as a quoted JSON string literal; `jq -r`
# unwraps that one layer, then `jq -Sc` normalizes for comparison.
tf_norm="$(jq -r . <<<"$tf_raw" | jq -Sc .)"

if [[ "$reader_norm" != "$tf_norm" ]]; then
  echo "DRIFT: terraform/service local.public_material != cofhe_keys::reader" >&2
  echo "  reader.rs  : $reader_norm" >&2
  echo "  terraform  : $tf_norm" >&2
  echo "Fix the Terraform local (or reader.rs — whichever is wrong) so they match." >&2
  exit 1
fi

echo "ok: terraform local.public_material matches cofhe_keys::reader"
echo "    $reader_norm"
