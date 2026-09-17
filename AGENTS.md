# AGENTS.md

cofhe-tdx-keygen is a one-shot, in-enclave key generator for the CoFHE network.
It runs inside Intel TDX / Confidential Space: it generates the keyset, writes
each partner's Shamir share into that partner's Secret Manager (gated by the
partner's attestation), and publishes the public material. It is the producer;
ZeeK Verifier and TeeCryptor are the consumers that read what it produces.

Start here:

- `DESIGN.md` — architecture, security model, and every decision with rationale.
- `CEREMONY.md` — how a ceremony runs: mental model, steps, dev vs prod.
- `CONSUMER-INTEGRATION.md` — the per-audience split and the reader API consumers embed.

Layout:

- `crates/cofhe-keys/` — the portable library consumers embed (serialization,
  reader, secrets, gcs, keygen).
- `crates/keygen/` — the `keygen` ceremony binary and the `verify` acceptance CLI.
- The partner-side Terraform lives in a separate public repo,
  `FhenixProtocol/key-share-holders`, not here.

Build and test: `make run-local` (mock, no cloud), `make test`, `make check`
(fmt + clippy + tests). The toolchain is pinned in `rust-toolchain.toml`.

Invariants — do not break these (see `DESIGN.md` for the rationale behind each):

- tfhe versions are pinned exactly and must match the rest of CoFHE byte-for-byte.
- Endpoint URLs are compile-time consts, not env-overridable — this blocks an
  STS-redirect attack.
- Reconstruction is fail-closed: a bad share is excluded, and fewer than T good
  shares aborts the run.
- The wire format is the single source of truth; the writer and reader hash
  byte-identical bytes.
- Each run is a fresh keyset, all-or-nothing.

Writing docs and comments: active voice, present tense, one idea per sentence,
simple words. State operator cautions as instructions, not alarms. Never claim an
audit that has not happened.
