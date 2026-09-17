# cofhe-tdx-keygen

In-enclave **full key creation** for the CoFHE FHE network. A one-shot service runs
inside an Intel TDX / GCP Confidential Space enclave. It generates the network's
keyset and distributes it:

- each partner's secret share goes into that partner's Secret Manager, gated by the
  partner's attestation CEL — only the attested enclave can write a share;
- the public material goes into our GCS bucket, where bucket IAM protects its
  integrity.

The enclave also stamps an attestation token into each secret's wire format. No
consumer reads that token (see `DESIGN.md` §7).

> **Status:** bootstrap/genesis scope, shipped end-to-end. Shamir threshold
> splitting is live: each secret splits into one share per partner, and a threshold
> of shares reconstructs it. The partner count (N) and threshold (T) are baked per
> environment in `crates/cofhe-keys/src/envs.rs`. The cloud round-trip and the
> consumer wiring both run on real Confidential Space (Intel TDX) — staging since
> 2026-07-21, testnet since 2026-07-30. See `CONSUMER-INTEGRATION.md`.

## Read these first

- **`DESIGN.md`** — the architecture, the security model, the custody invariant, and
  every key decision with its rationale.
- **`CEREMONY.md`** — how a ceremony runs: the mental model, the steps in order, the
  production checklist, and what changes between development and production.
- **`CONSUMER-INTEGRATION.md`** — the integrator guide: the per-audience split, the
  reader API, and what embedding `cofhe-keys` imposes on your build and egress.

## Layout

| Path | What |
|------|------|
| `crates/cofhe-keys/` | Portable library (lib name `cofhe_keys`): serialization, reader, secrets, gcs, keygen. Consumers embed this. |
| `crates/keygen/` | Binaries: `keygen` (the ceremony) and `verify` (acceptance CLI). Depends on `cofhe-keys`. |
| `terraform/service/` | Terraform for **our** project: the TDX VM, the compute service account, and its write grant on the public-material bucket. The partner set and Shamir N/T are baked into the image per environment, not set here. |
| — | The partner side (`partner/`, `access/`, the onboarding module) lives in [`key-share-holders`](https://github.com/FhenixProtocol/key-share-holders), the public repo a partner clones. State stays in the partner's own `gs://<partner-project>-tfstate`. |
| `.github/workflows/build-keygen-tdx.yml` | **Primary** image build: keyless (GitHub WIF), amd64, pushes to the shared `fhenix-artifacts-registry` project. |
| `Dockerfile` | The amd64 image build. |

## Local dev

The `Makefile` owns the local dev loop: `make run-local` runs a one-shot keygen with
the mock feature (no cloud), and `make check` runs the CI-equivalent gates.

You drive the cloud path by hand, per `CEREMONY.md`: build the image, apply
`terraform/service` (the TDX VM runs the ceremony), then verify with the `verify`
CLI, whose `reconstruct` command does the live threshold read.
