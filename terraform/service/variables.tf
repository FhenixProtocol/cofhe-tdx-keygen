variable "service_project_id" {
  type        = string
  description = "Our keygen service's compute project where the TDX VM runs (e.g. fhenix-dev)."
}

variable "region" {
  type    = string
  default = "europe-west4"
}

variable "zone" {
  type    = string
  default = "europe-west4-b"
}

variable "image_reference" {
  type        = string
  description = "Full image reference incl. tag, e.g. europe-west4-docker.pkg.dev/fhenix-artifacts-registry/cofhe-tee-keygen/keygen:dev. The image lives in the shared fhenix-artifacts-registry project (created + pushed out-of-band, like teecryptor/zee-k-verifier); this service only pulls it."
}

variable "env" {
  type        = string
  description = "Baked-environment selector passed to the ceremony VM as COFHE_ENV. The keygen binary resolves the partner set + write audiences, N/T, and the public layout from its compiled-in map (cofhe_keys::reader) and fails closed on anything else — this only picks which baked env."
  validation {
    # Every value here must have a triplet in cofhe-keys' ENVIRONMENTS map, or the
    # binary fails closed at boot. Adding one is a rebuild by design.
    condition     = contains(["staging", "testnet", "mainnet"], var.env)
    error_message = "env must be one of the blessed environments: staging | testnet | mainnet."
  }
}

variable "run_ceremony" {
  type    = bool
  default = false
  # Gates the one-shot keygen VM. Default false: a routine apply of the standing
  # infra (IAM + the public-bucket write grant) leaves the VM absent. Set true ONLY
  # to run once in keygen_mode (a ceremony writes a NEW keyset; a reshare splits
  # the live one again), then set back to false to tear the VM down. A rerun needs
  # false then true again: the VM runs its container only once. See CEREMONY.md.
  description = "When true, create the one-shot TDX keygen VM and run it in keygen_mode. Keep false for routine infra applies."
}

variable "keygen_mode" {
  type    = string
  default = "ceremony"
  # A mismatch with the baked env stops the VM at boot, before any read or write.
  description = "What the keygen VM runs: ceremony (a new keyset) or reshare (the live keyset, split again for the baked target set). Passed as KEYGEN_MODE."
  validation {
    condition     = contains(["ceremony", "reshare"], var.keygen_mode)
    error_message = "keygen_mode must be ceremony or reshare."
  }
}

variable "reshare_source_versions" {
  type    = map(number)
  default = {}
  # Recovery only. After a reshare stops mid-write, latest at a staying partner
  # holds a share that no manifest describes. Pin each such secret to the number
  # at the end of the `version` field of the failed run's "read share" log line
  # (projects/…/versions/N). The two secrets number their
  # versions apart, so each key names one secret. Every pinned share must still
  # match the live manifest, so a wrong value only stops the run.
  description = "Reshare only: \"<source partner project id>/<fhe-priv|zk-signer>\" -> Secret Manager version to read instead of latest. Passed as RESHARE_SOURCE_VERSIONS."
  validation {
    condition     = alltrue([for v in values(var.reshare_source_versions) : v >= 1 && floor(v) == v])
    error_message = "each reshare source version must be a whole number >= 1."
  }
  validation {
    condition     = alltrue([for k in keys(var.reshare_source_versions) : can(regex("^[a-z0-9-]+/(fhe-priv|zk-signer)$", k))])
    error_message = "each key must be \"<partner project id>/fhe-priv\" or \"<partner project id>/zk-signer\"."
  }
  validation {
    condition     = length(var.reshare_source_versions) == 0 || var.keygen_mode == "reshare"
    error_message = "reshare_source_versions applies only with keygen_mode = reshare."
  }
}

variable "public_material_anonymous_read" {
  type        = bool
  default     = false
  description = "When true, grant allUsers objectViewer on a managed folder over the public-material prefix, so anyone can read the published keys and nothing else in the bucket. The bucket must not have public access prevention enforced."
}

variable "public_material_readers" {
  type        = list(string)
  default     = []
  description = "Consumer compute SAs granted objectViewer on the public bucket so the reader VMs (teecryptor / zee-k) can fetch the public material with their attached SA. Leave empty where the bucket is allUsers-readable (staging: localcofhenix); set for IAM-gated public buckets (testnet: fhenix-testnet-v2). Fully-qualified members, e.g. \"serviceAccount:teecryptor@fhenix-testnet.iam.gserviceaccount.com\"."
}

