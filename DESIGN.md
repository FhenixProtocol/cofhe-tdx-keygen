# Design — CoFHE TDX Keygen

Status: implemented (bootstrap scope). Audience: engineers who work on, or integrate
with, the CoFHE key-distribution path.

## 1. Purpose

The CoFHE network runs on a single FHE keyset plus two signing keys. Whoever can
observe the secret decryption key as it is generated can decrypt anything on the
network. Generation must therefore happen where no operator, cloud administrator or
co-resident process can read it.

This service generates the network's keyset **inside a hardware-isolated enclave**
(Intel TDX under GCP Confidential Space) and distributes it. Each partner receives
their secret share into their own Secret Manager, and the public material is published
to our bucket. This service is the **producer**; the threshold-network parties, the
verifier and the cryptor are **consumers** that read what it produces.

It is a one-shot program: boot → attest → generate → distribute → exit.

## 2. Goals and non-goals

**Goals**
- Generate the production FHE keyset (the tfhe version is pinned in
  `crates/cofhe-keys/Cargo.toml`) and both signer keys in-enclave, and never expose
  secret material outside encrypted enclave memory.
- Deliver each partner their secret share with no standing credential anywhere. A
  fresh, unforgeable attestation of the exact published image is the only gate.
- Give consumers a fail-closed way to reconstruct their keys from authentic shares
  (the partner attested-WIF write-gate) and to reject a corrupted result (the published
  per-share and full digests). The consumer-side attestation-token check was removed —
  see §7.

**Threshold / N>1 Shamir split — done.** Each secret splits into one share per partner,
and a threshold of shares reconstructs it. The partner count (N) and threshold (T) are
baked per environment in `crates/cofhe-keys/src/envs.rs`. The write loop is "broadcast
public + per-partner share", and the reader gathers, reconstructs and validates
fault-tolerantly. Proven end-to-end on real Confidential Space (§14).

**Non-goals (separate tickets)**
- **Live key rotation** (tracked separately). This service is bootstrap/genesis only.
  Rotating a live network invalidates existing ciphertexts, and is a migration story of
  its own.
- **Embedding the reader into the live consumer services.** The portable library is in
  scope. Wiring it into ZeeK Verifier and TeeCryptor (config plus per-secret read
  grants) is separate — see `CONSUMER-INTEGRATION.md`.

## 3. Architecture

Two GCP projects hold two trust domains, joined only by a fresh attestation.

```
   OUR project (compute)                    PARTNER project (vault)
  ┌────────────────────────────┐          ┌──────────────────────────────────┐
  │ TDX enclave (Confidential   │          │ Secret Manager secret (the share) │
  │ Space VM) — the ceremony     │  attest  │ Workload Identity Pool + Provider │
  │                              │ ───────▶ │ CEL gate (attribute_condition)    │
  │ public-material GCS bucket   │          │ IAM: secretVersionAdder → us      │
  └────────────────────────────┘          └──────────────────────────────────┘
```

The gate lives in the **partner's** project. The partner controls the rule that
constrains us, and we cannot reach in and loosen it. That separation of duties is the
security model: the constrained party does not own its own constraint.

### Components

- **`keygen` (binary)** — the write side: the six-step ceremony.
- **`cofhe-keys` (library)** — the portable core: canonical serialization, the consumer
  reader (gather → reconstruct → digest-validate), and the GCP clients. Consumers embed
  this. The writer and every reader share it, so they hash byte-identical material and
  cannot drift.
- **Partner onboarding (Terraform module)** — the entire partner side. Onboarding a
  partner is one `terraform apply`, and there is no software to run on the partner side.

## 4. Key material

Each run generates one keyset, split by destination.

| Material | Contents | Destination | Size |
|----------|----------|-------------|------|
| **Secret share** | FHE ClientKey (`priv`) + decrypt-signer + zk-signer private scalars | partner Secret Manager | ~40 KB |
| **Public artifacts** | ServerKey, CompactPublicKey, CRS — one `safe_serialize`d object each | our GCS bucket, `keys/versionized/{zone}/{computation_key,public_key,crs}` | ~33 MB |
| **Public manifest** | both signer EVM addresses + SHA-256 digests of each artifact and each split secret | our GCS bucket, `.../public-material` (+ `.provenance`) | ~1 KB |

Secret Manager's 64 KiB per-secret limit forces the secret/public split: the share
fits, and the artifacts do not (ServerKey alone is ~30 MB). The public artifacts are
identical for every partner, are not secret, and are consumed by the compute side. They
therefore live in one shared bucket in our project, not in each partner's project.

We write them as **separate objects**, under cofhe's own key file names
(`computation_key`, `public_key`, `crs`) in `keys/versionized/{zone}/`. A cofhe stack
pointed at the bucket then mounts this ceremony's keyset directly as files. The small
`public-material` **manifest** beside them carries only the signer addresses and the
SHA-256 digests, of each artifact and each split secret. A consumer that reads an
artifact file checks it against the manifest digest, so artifact integrity rests on the
manifest. The bucket's write IAM protects the manifest itself (§7).

**Two signers.** The threshold-network keygen produces no signers — one is born in the
dispatcher, the other in the verifier — so this service mints both: the
**decrypt-signer** (threshold-network decrypt results) and the **zk-signer** (the
verifier). Their public identities are EVM addresses, derived from the secp256k1 public
keys.

## 5. Distribution model

**Direct write to the partner's Secret Manager**, via Confidential Space cross-project
Workload Identity Federation, gated by the partner's attestation CEL. This reuses the
attest → token-exchange → Secret Manager chain the sibling services already use for
reads, pointed at writes instead. We considered an mTLS pull-server model and dropped
it.

**Direct federated grant.** The write role (`secretmanager.secretVersionAdder`) is
granted **directly** to the attested federated principal, a `principalSet` scoped by
`gce_project_id`. There is no intermediate service account to impersonate, and
therefore no standing credential that could leak. The only key to the vault is a fresh
attestation of exactly what code is running. The role is "add a version", never
"access", so the enclave can deliver new material but cannot read existing material.

> The alternative we rejected was an intermediate writer service account for the
> enclave to impersonate. It adds a standing credential and buys nothing.

**Shamir N-of-T split.** Each secret payload splits into one share per partner, and a
threshold of shares reconstructs it. No single partner holds the whole secret. The
primitive lives in `crates/cofhe-keys/src/shamir.rs`, and N and T are baked per
environment in `envs.rs`. The threshold has a hard floor of 2: the Shamir backend cannot
reconstruct from a single share, so the degenerate T=1 case is unsupported and rejected.
The public material carries a per-share digest list keyed by partner `project_id`, which
anchors reconstruction validation and liar attribution on the read side.

**All-or-nothing (write side).** Generate the full keyset first, split it, then write
each partner their share. **Any** partner write that fails crashes the whole run, so no
partial ceremony is ever advertised: the public material is published only after every
write succeeds. Each run is a fresh keyset, and runs append a new Secret Manager version
(history is retained, and consumers read `latest`). Read-side reconstruction is the
opposite. It is **fault-tolerant**: a hung or lying partner is excluded, and
reconstruction proceeds from any T good shares.

## 6. Attestation and access control

1. The enclave requests an attestation token from the Confidential Space launcher. It
   is a Google-signed JWT that carries `hwmodel` (GCP_INTEL_TDX), `swname`
   (CONFIDENTIAL_SPACE), `image_digest` and `gce_project_id`.
2. It presents the token to Google STS, naming the partner's WIP as audience.
3. STS evaluates the **partner's CEL**: genuine TDX, Confidential Space, STABLE
   support, our project, and optionally the exact `image_digest`. On pass it returns a
   short-lived federated access token. On fail it returns nothing.
4. The enclave uses that token directly as the Secret Manager bearer.

Writing the **public** material to our own bucket uses a different token: the VM's
attached service-account token from the metadata server. That call is in-project, with
no cross-project hop.

**Endpoint constants are compile-time, not env-overridable.** An attacker with
`setMetadata` therefore cannot redirect the STS exchange to capture a genuine attested
token.

## 7. Integrity of the produced material

Three controls protect what this service produces. The consumer verifies no attestation
token on any of them.

1. **Share authenticity — the partner write-gate.** Only the attested enclave holds
   `secretVersionAdder` on a partner's secret. A share version can therefore only come
   from the enclave that the partner's CEL accepts.
2. **Public-material integrity — bucket IAM.** Only the keygen producer may write the
   public objects. Keep that write IAM tight: a principal who can write the bucket can
   swap the manifest and the artifacts together.
3. **Correctness of the reconstructed secret — two digest tiers.** The reader validates
   every share, and then the reconstructed result, against the published digests. It
   fails closed.

### Two digest tiers for Shamir reconstruction

A genuine share does not prove that reconstructing T shares yields the right key. Plain
Shamir cannot error-correct, so one bad share among the chosen T silently corrupts the
result. `PublicMaterial` therefore carries two kinds of SHA-256 digest, and the reader
checks both (`reader::reconstruct_and_validate`):

- **Per-share digests** — `Vec<(partner_project_id, SHA-256(share))>` per secret. The
  reader hashes each fetched share and matches it against *that partner's* published
  digest **before** interpolation. A mismatch excludes that partner as a named liar. The
  exclusion is non-fatal while at least T good shares remain, so the reader both
  overcomes and attributes a lying partner.
- **Full-key digest** — `SHA-256(full payload)` per secret. After reconstructing from T
  digest-passing shares, the reader hashes the reassembled payload and matches it against
  this digest. A mismatch, when the shares individually passed, is a fatal producer or
  internal inconsistency.

Both digest lists are fields of `PublicMaterial`, so they publish inside the manifest.
Their integrity rests on the bucket's write IAM (control 2): only the producer can write
the manifest. Hashes of high-entropy keys are safe to publish. They are preimage-
resistant, and useful only to someone who already holds the key.

**One place pins the digest: the partner CEL (the write gate).** It learns a new digest on
each image rebuild. The consumer-side digest allowlist that used to mirror it was removed.
Consumers anchor the source through the baked per-environment map plus on-chain signature
verification instead.

### The consumer-side provenance check was removed

The reader in `cofhe-keys` used to verify a Confidential Space attestation token over each
share and over the public material. **That check no longer exists.** It fetched Google's
*live* JWKS to validate an *archival* token, so a signing-key (`kid`) rotation between the
ceremony and a read crashed every consumer fail-closed. It was also redundant with the
partner write-gate, which already limits writes to the attested enclave.

The producer still stamps `SecretEnvelope.provenance_jwt`, and still writes the
`public-material.provenance` sidecar. **No consumer reads either one.** Both are kept for
wire-format compatibility. Neither is a control today, so do not present them as one, and
do not re-introduce a JWKS-dependent verify path.

Removing the check is sound on the current design, because the reader's source map is
baked and the keygen-origin allowlist is dropped. `PARTNERS` and `PUBLIC_BUCKET` are no
longer operator-settable, so the redirect attack the allowlist guarded is gone. We
deliberately did **not** add an on-chain commitment anchor: it would add an
RPC-poisoning surface and a second trust root. The trust root today is GCP IAM, in the two
places named above.

**Why not a decrypt-on-load self-test?** Keys are fresh every run, so a consumer has no
pre-trusted key to anchor a test against. An attacker would ship a self-consistent rogue
keypair that passes its own test. The write-gate and the published digests rule that out
instead. Decrypt-on-load is at best an optional smoke test, never a security control.

## 8. Wire format

Digest validation requires the writer and every reader to agree byte-for-byte, because
both hash the same bytes. The serialization is deliberately explicit: a 1-byte version,
then each field length-prefixed (u32 BE), and tfhe types through the library's versioned
`safe_serialize`. This format lives in one module of `cofhe-keys` that both sides import.
They cannot drift, because they are the same code.

## 9. Consumer integration

`cofhe-keys::reader` is the consumer entry point. The Shamir entry points
`read_fhe_priv` and `read_zk_signer` do the whole job: they gather every partner's share
fault-tolerantly (`fetch_all`, with a per-partner timeout), then call
`reconstruct_and_validate` (per-share digest filter → reconstruct from T → full-key
digest check). `read_share` is the single-secret unit, and `read_public` downloads and
checks the public material. The reader is auth-agnostic: the caller passes tokens it
obtained with its own identity, so the library carries no attestation or write
machinery. The `verify reconstruct` CLI is a thin wrapper over these entry points, for
operator round-trips.

We write **two per-audience secrets** per partner, so that IAM enforces least privilege:
`cofhe-tee-fhe-priv` (FHE priv + decrypt signer → TeeCryptor) and `cofhe-tee-zk-signer`
(zk signer → ZK verifier). A single combined secret would be all-or-nothing. Secret
Manager access is per-secret and we do not encrypt-to-consumer, so the ZK verifier would
otherwise be able to read the decryption key. See
[`CONSUMER-INTEGRATION.md`](CONSUMER-INTEGRATION.md) for the full design and the
consumer-side work that remains.

## 10. Security model

- **No standing credential.** A fresh attestation of the measured image is the only
  thing that unlocks a write. There is nothing on disk to steal.
- **Append-only.** The enclave holds `secretVersionAdder`, not `secretAccessor`, so it
  cannot read existing key material.
- **No encrypt-to-partner-key.** The partner's own GCP IAM and Secret Manager
  encryption-at-rest protect the secret material. A partner admin with `secretAccessor`
  can read it, so the confidentiality boundary is the partner's IAM.
- **Shamir reduces the blast radius.** No single partner holds a usable secret. A
  partner admin with `secretAccessor` sees only their share, so breaking
  confidentiality requires colluding `secretAccessor` on **T** distinct partner
  projects.
- **Two published digest tiers validate what the reader loads.** The per-share digests
  make a lying or stale share detectable and attributable. The full-key digest proves
  the reconstructed secret is the one the ceremony produced. Both checks fail closed,
  and the bucket's write IAM protects the digest lists themselves (§7).
- **Post-quantum egress (fail-closed).** Every outbound googleapis connection (Secret
  Manager, STS, GCS) requires TLS 1.3 with the X25519MLKEM768 hybrid key exchange. There
  is no classical fallback, and https→http redirects are refused (`cofhe_keys::tls`, the
  single client choke point). The payloads are FHE key shares, and classical-only key
  exchange leaves recorded traffic open to harvest-now-decrypt-later. A peer or
  middlebox that cannot do hybrid PQ breaks the connection loudly instead of
  downgrading. Note the consequence: a TLS-intercepting proxy, for example on an
  operator laptop running `verify`, fails the handshake by design.
- **Ephemeral secret material in memory.** The keyset, the Shamir polynomial
  coefficients and the shares live in RAM during the ceremony, and are not proactively
  zeroized. That is consistent with the writer-side stance throughout keygen. The
  ceremony is one-shot, it runs inside a memory-encrypted TDX enclave with no untrusted
  swap, and the VM is destroyed at teardown. Proactive wiping therefore buys nothing
  concrete: the material never leaves encrypted RAM, and it dies with the process.
  Consumers are long-lived, so they do zeroize their working copies on the read side.

### The operator-permission invariant

**No Fhenix principal holds a permission that reaches a partner's share.** The
attestation gates above are worth nothing if a human can grant themselves read access
around them, so this is a first-class claim of the model, and it is enforced by which
roles exist rather than by policy.

Two permissions reach a share. `secretmanager.versions.access` returns the bytes. And —
the part that is easy to get wrong — `secretmanager.secrets.setIamPolicy` lets its holder
grant themselves `secretAccessor` and then read the value, so it is an escalation path,
not an administrative convenience. The partner Terraform needs `setIamPolicy`, because
setting per-secret IAM is its whole job. Hence the resolution: **the partner runs that
Terraform themselves**, and we never hold the permission. The ceremony does not need it
either. The enclave authenticates with TDX attestation against the partner's own CEL, so
no human credential sits in the security path.

Fhenix operators hold two predefined read-only roles in a partner project:
`roles/secretmanager.viewer` and `roles/iam.workloadIdentityPoolViewer`. Together they are
enough to verify the deployed CEL, the IAM bindings, and that a ceremony landed — version
**metadata**, never bytes. They are predefined rather than custom on purpose, so a partner
audits two Google-documented roles instead of a hand-written permission list. What the
grant deliberately excludes:

| Not granted | Why |
|---|---|
| `secretmanager.versions.access` / `.add` | reading or writing a share value is the enclave's job, never an operator's |
| `secretmanager.secrets.setIamPolicy` | an escalation path to the share; this is why the partner runs their own stack |
| create / update / delete on secrets or WIF | the partner owns their own gates |
| storage on the partner state bucket | operators do not touch partner Terraform state |
| `roles/secretmanager.admin`, `roles/editor`, `roles/owner` | supersets that carry version access or `setIamPolicy` |

**Time-boxing the permission does not work, so do not propose it.** The tempting version
is "bind the write-capable role only while the secrets are still empty, so the window is
harmless". Every IAM resource here is an additive `*_iam_member` binding. A binding
planted out-of-band during that window is not in Terraform state, so no later apply
removes it. It survives the downgrade and goes live the moment a share is written. The
boundary cannot be time. It has to be never holding the permission.

Note the scoping. **Somebody** can always reach a share: whoever runs the partner stack
has admin on those secrets, and in production that is the partner. A partner owner can
read their own share, and the design does not pretend otherwise. It gains them **one**
share, and reconstruction needs **T**. That is what the threshold is for. So the question
to check is never "can anyone reach a share here", it is "**can a Fhenix principal**".

An environment where Fhenix owns the partner projects therefore **demonstrates** the
model rather than enforcing it, and the keysets there are disposable for exactly that
reason. The earlier custodian model — a plain service account holding `secretAccessor`
with no attestation gate — is gone from the onboarding module, and every read of a share
now passes the partner's digest-pinned attested-reader gate.

## 11. Key decisions

| Decision | Rationale |
|----------|-----------|
| Direct write, not serve | Reuses the existing attest→exchange→SM chain; near-zero net-new vs. an mTLS server |
| Direct federated grant | No service account, no impersonation, no leakable standing credential |
| Public material in our bucket | Identical for all, not secret, consumed by compute; partners read only their share |
| No encrypt-to-partner-key | Confidentiality rests on the partner's IAM; keeps the design simple |
| Versions, not new secrets | History retained; consumers read `latest`; no name churn per run |
| Stamp provenance, do not consume it | The token stays in the wire format for compatibility; the write-gate and bucket IAM carry integrity (§7) |
| Fresh keys, all-or-nothing | No persistence/resume; any partner failure crashes the run |
| Digest-pin the partner CEL (production) | Partner explicitly approves each exact image via TF apply; only that digest can write. Re-apply per image rotation is intended (explicit per-image consent), not a cost. Chosen over Cosign-fingerprint pinning, which is looser ("anything our key signs"). |
| Keyless Cosign + SLSA, checked at pin time | A signature gates nothing at *runtime* under a digest pin, so it gates the *pin* instead. The build signs the digest keylessly (OIDC → Fulcio → public Rekor); the partner asserts digest + commit + repo + workflow before approving the digest. Keyless, so there is no Fhenix key to trust or rotate. See §13. |
| TLS 1.3 + X25519MLKEM768 only, fail-closed | Key shares must resist harvest-now-decrypt-later; only the ML-KEM hybrid addresses it. aws-lc-rs provider (rustls's default; ring has no ML-KEM, graviola too young for key material; leaving rustls would put a C TLS stack in the distroless image). Enforcement lives in the clients (`cofhe_keys::tls`), so consumers inherit it on rev bump with no config. Cost: aws-lc-sys needs cmake at build time. |

## 12. Operational model

- **Run:** a one-shot ceremony on a Confidential Space VM. It logs each step and prints
  the two signer addresses, which an operator broadcasts on-chain manually for the MVP.
- **Partner onboarding:** the partner runs the Terraform module once and returns
  `{partner_project_id, wip_audience, secret_ids}`, and we register them.
- **Image rotation:** production **pins `image_digest`** in the partner CEL, so a new
  image requires the partner to re-apply with the new digest. That is by design: only
  the exact image the partner has approved can write to their vault, which is explicit
  per-image consent. The partner CEL is the only place the digest is pinned — the
  consumer-side `allowed_image_digests` mirror was removed (§7) — so rotation touches
  the partners only, not the consumers. Development leaves it unpinned by default, for
  iteration speed.

## 13. Image build and the production gate

- **The build is keyless.** `build-keygen-tdx.yml` builds the image and pushes it to the
  shared `fhenix-artifacts-registry` project through GitHub Workload Identity Federation,
  impersonating a keyless publisher service account. No service-account key and no
  operator credential is involved. The provider and that service account are bootstrapped
  in the registry project, out of band from this repo.
- **The production gate is the image-digest pin** (§11/§12). The partner CEL pins the
  exact `image_digest`, and the write grant is scoped to the same digest, so each release
  needs a partner re-apply. We chose that for explicit per-image consent. The alternative
  was Cosign-fingerprint pinning, which lets us rotate freely but weakens the gate to
  "anything our key signs".
- **The image is signed, keylessly.** The build workflow signs the pushed digest with
  Cosign. It also attests SLSA build provenance. Both use the workflow's OIDC token and
  get a short-lived certificate from Fulcio. Both go to the public Rekor log. No signing
  key exists. The certificate names the repository, the workflow, the ref and the commit.
- **The image registry is public, on purpose.** The Artifact Registry repository grants
  `allUsers` the reader role. The source is public, so the image holds no secret, and open
  images support the trust story. Cosign stores the signature beside the image, so a
  partner reads it with no credential and no account. **The partner check depends on that
  grant.** Do not remove it without a replacement path for the signature.
- **The partner verifies before it pins.** A signature gates nothing at run time under a
  digest pin. It gates the *pin*. The partner runs `cosign verify` on its own machine,
  against public Rekor. The command asserts the exact digest and the exact commit. A
  non-zero exit means the partner does not pin. This is where the commit↔digest↔repo proof
  holds, because the CEL cannot carry it. The tooling lives in `key-share-holders`.
- **The handoff per release is two values:** `{image_digest, source_sha}`. The registry,
  the OIDC issuer, the workflow identity and the ref are public constants. The partner
  bakes them once per image.
- **Consumer wiring is live.** Both consumers embed the reader and read
  partner-enforced attested shares; see
  [`CONSUMER-INTEGRATION.md`](CONSUMER-INTEGRATION.md).

## 14. Validation

The full path is proven end-to-end on real Confidential Space. The single-partner
round-trip (attest → keygen → SM write + GCS public + provenance tokens → `verify`
against the real Google RS256 token) was validated 2026-06-21, when the consumer-side
token check still existed. The **5-partner Shamir round-trip** was validated 2026-06-28
(image `:5_partners`): the ceremony wrote a fresh share to all 5 partners
(all-or-nothing), and `verify reconstruct` rebuilt both secrets from **2-of-5**,
including disjoint pairs, each validated against the published full digest, with a
single share at T=2 correctly rejected. [`CEREMONY.md`](CEREMONY.md) outlines the
round-trip that proves it.

### Testing

Four layers, cheapest first. The first three run on a laptop with no cloud.

1. **Static gates**, on every change, in `.github/workflows/ci.yml`: `cargo fmt --check`,
   `cargo clippy --workspace --all-targets -D warnings`, a release build of the
   workspace, and a `--no-default-features` build of the writer-only image profile, which
   is what the enclave ships. CI also runs `scripts/check-tf-reader-drift.sh`, which fails
   if the Terraform public-material map and the baked map in `cofhe-keys` disagree — the
   two are duplicated by necessity, so a drift check replaces trust.
2. **Unit tests** (`cargo test --workspace`) cover the parts a cloud run cannot isolate:
   the canonical wire format round-trips and rejects an unknown version or a truncated
   input; Shamir split and reconstruct hold for any T-of-N subset and reject a threshold
   below 2; the reader gathers from a mock Secret Manager and GCS, excludes a liar by
   per-share digest and **names** it, excludes a hung partner on timeout, and fails closed
   on a full-key digest mismatch; and one slow test generates the real tfhe keyset and
   asserts each share fits Secret Manager's 64 KiB cap.
3. **A mock run** (`make run-local`) runs the real `generate()` end to end on a laptop,
   with no attestation and no writes.
4. **The cloud round-trip** is the acceptance gate before a production deploy, because it
   is the only layer with real Intel TDX, real Google-signed attestation tokens, the
   per-partner federated writes, and a live T-of-N reconstruct. `CEREMONY.md` outlines it.
