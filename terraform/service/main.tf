terraform {
  required_version = ">= 1.9"
  # Remote state in the per-env tfstate bucket; bucket + prefix passed at init:
  #   terraform init -reconfigure \
  #     -backend-config="bucket=fhenix-dev-tfstate" \
  #     -backend-config="prefix=cofhe-tdx-keygen/service"   (env VM state)
  #   ... prefix="cofhe-tdx-keygen/keygen-project"           (shared cofhe-tee-keygen)
  backend "gcs" {}
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.service_project_id
  region  = var.region
  zone    = var.zone
}

# Public-material bucket + object prefix, selected by the SAME `env` the binary uses
# — a Terraform-side mirror of `cofhe_keys::reader`'s per-env `public_bucket` /
# `public_prefix`. These are NOT operator inputs: the ceremony writes to the baked
# layout, and TF only needs them to grant the compute SA write + scope the consumers'
# prefixed read to the matching bucket/prefix. Keep in lockstep with reader.rs (the
# binary writes where the baked map says; TF grants there). Terraform can't read the
# Rust consts, so this is the minimal env-keyed representation on the TF side — and
# CI proves it never drifts (scripts/check-tf-reader-drift.sh diffs this map against
# cofhe_keys::reader on every push). A prefix drift is silent-security: it scopes the
# consumer read condition below, so an edit here that misses reader.rs fails the build.
locals {
  public_material = {
    staging = { bucket = "localcofhenix", prefix = "generator/keys/versionized" }
    testnet = { bucket = "fhenix-testnet-v2", prefix = "generator/keys/versionized" }
    mainnet = { bucket = "fhenix-mainnet-keys", prefix = "generator/keys/versionized" }
  }
  public_bucket = local.public_material[var.env].bucket
  public_prefix = local.public_material[var.env].prefix
}

# Our keygen service's compute side. Runs the TDX Confidential Space VM, which
# attests and writes the generated key bundle into the partner's Secret Manager.
#
# Direct federated grant: there is NO writer service account to impersonate — the
# attested federated principal holds secretVersionAdder directly (the partner's
# WIP CEL gates it), so the federated token is used as the SM bearer as-is.
#
# The workload is a one-shot ceremony: it attests, writes the key bundle to the
# partner's Secret Manager, and exits — no inbound service, so no firewall is
# needed (egress to googleapis uses the VM's external IP).
#
# The keygen image lives in the shared fhenix-artifacts-registry project
# (created + pushed out-of-band via GitHub Actions, exactly like teecryptor /
# zee-k-verifier). It is allUsers-readable, so the VM pulls it with no grant.
# The public material is written to a pre-existing bucket in THIS project
# (local.public_bucket) — cofhe reads its keyset from the same bucket.

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "artifactregistry.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# --- Compute SA: attached to the VM, used by the CS launcher ------------
resource "google_service_account" "compute" {
  account_id   = "cofhe-tee-keygen-vm"
  display_name = "CoFHE TEE keygen — compute SA"
  description  = "Attached to the TEE VM. Pulls image, writes logs, calls CC API. Does NOT touch partner keys directly."
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "log_writer" {
  project = var.service_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

resource "google_project_iam_member" "confidential_workload" {
  project = var.service_project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

# Compute SA writes public material to the pre-existing bucket. objectAdmin (not
# just objectCreator) so a run can overwrite the object; bucket versioning (owned
# by the bucket, not managed here) retains history. The bucket itself is NOT
# created here — it is cofhe's existing bucket in this project.
resource "google_storage_bucket_iam_member" "public_writer" {
  bucket = local.public_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.compute.email}"
}

# Read grant for the CONSUMER compute SAs (teecryptor / zee-k) so their reader VMs
# can fetch the public material with their attached SA. These SAs are created in
# the consumer compute stacks, not here, so they are passed as plain member
# strings. Default empty => NOTHING granted (correct for a bucket that is already
# allUsers-readable, e.g. staging's localcofhenix); populate for an IAM-gated
# public bucket (e.g. testnet's fhenix-testnet-v2).
#
# The grant is CONDITION-SCOPED to the public-material prefix, never bucket-wide.
# On testnet the public bucket also holds the plaintext source keyset (the import
# ceremony's `keys/versionized`); a bucket-wide objectViewer would let a consumer
# read the full key and defeat the threshold split. The condition confines the
# read to `${public_prefix}/` so only the published public material is reachable.
resource "google_storage_bucket_iam_member" "public_material_reader" {
  for_each = toset(var.public_material_readers)
  bucket   = local.public_bucket
  role     = "roles/storage.objectViewer"
  member   = each.value

  condition {
    title       = "public-material-read"
    description = "read only the published public material prefix (not the source keyset)"
    expression  = "resource.name.startsWith(\"projects/_/buckets/${local.public_bucket}/objects/${local.public_prefix}/\")"
  }
}

# --- The Confidential VM ------------------------------------------------
# The keygen ceremony is a ONE-SHOT: this VM should exist only while a ceremony
# is deliberately being run. It is gated behind `run_ceremony` (default false) so
# a routine apply of the standing infra (IAM + the public-bucket write grant)
# never re-creates a torn-down VM — which would boot the launcher and regenerate
# the entire keyset (new FHE keys + signers), silently overwriting the partner
# shares and public material. Flip `run_ceremony=true` to run a ceremony, then
# back to false to tear the VM down. See CEREMONY.md Step 4.
resource "google_compute_instance" "keygen_vm" {
  count = var.run_ceremony ? 1 : 0

  name         = "cofhe-tee-keygen-vm"
  zone         = var.zone
  machine_type = "c3-standard-4"

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "TDX"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  boot_disk {
    initialize_params {
      image = "projects/confidential-space-images/global/images/family/confidential-space"
      size  = 20
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  service_account {
    email  = google_service_account.compute.email
    scopes = ["cloud-platform"]
  }

  # Env vars:
  #   COFHE_ENV — baked-environment selector. The ceremony resolves the partner set +
  #         write audiences, N/T, the public bucket, and the layout from its
  #         compiled-in map (cofhe_keys::reader) keyed by this. Nothing else is
  #         passed: those values are baked into the image, NOT operator-settable.
  # COFHE_ENV is the only tee-env-* here and must appear in the Dockerfile's
  # allow_env_override LABEL (alongside RUST_LOG) or the launcher rejects it.
  # Direct federated grant: no SA_EMAIL — the attested federated principal holds the
  # write role directly, so the federated token is used as the SM bearer as-is.
  metadata = {
    "tee-image-reference"        = var.image_reference
    "tee-restart-policy"         = "Never"
    "tee-container-log-redirect" = "true"
    "tee-env-COFHE_ENV"          = var.env
  }

  depends_on = [
    google_project_iam_member.log_writer,
    google_project_iam_member.confidential_workload,
    google_storage_bucket_iam_member.public_writer,
  ]
}

# null when no ceremony VM is running (run_ceremony = false).
output "vm_internal_ip" {
  value = one(google_compute_instance.keygen_vm[*].network_interface[0].network_ip)
}

output "vm_external_ip" {
  value = one(google_compute_instance.keygen_vm[*].network_interface[0].access_config[0].nat_ip)
}

output "compute_sa_email" {
  value = google_service_account.compute.email
}
