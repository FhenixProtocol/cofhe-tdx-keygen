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
  # infra (IAM + the public-bucket write grant) leaves the VM absent and never
  # regenerates the keyset. Set true ONLY to deliberately run a ceremony (which
  # generates a NEW keyset and overwrites the partner shares + public material),
  # then set back to false to tear the VM down. See CEREMONY.md Step 4.
  description = "When true, create the one-shot TDX keygen VM and run a ceremony. Keep false for routine infra applies."
}

variable "public_material_readers" {
  type        = list(string)
  default     = []
  description = "Consumer compute SAs granted objectViewer on the public bucket so the reader VMs (teecryptor / zee-k) can fetch the public material with their attached SA. Leave empty where the bucket is allUsers-readable (staging: localcofhenix); set for IAM-gated public buckets (testnet: fhenix-testnet-v2). Fully-qualified members, e.g. \"serviceAccount:teecryptor@fhenix-testnet.iam.gserviceaccount.com\"."
}

