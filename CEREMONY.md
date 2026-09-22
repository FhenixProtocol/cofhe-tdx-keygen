# Ceremony — how a CoFHE keyset is created

A **ceremony** is one run of this service. A Confidential Space VM boots, generates the
network's keyset inside an Intel TDX enclave, splits each secret across the partner
projects, publishes the public material, and exits. It is bootstrap and genesis scope:
a ceremony creates keys, so you run one to stand an environment up, and not again.

This page is the public outline: the mental model, the steps in order, the production
checklist, and what changes between a development run and a production run. It carries
no environment project names and no copy-pasteable operator commands. The trust model
behind each step is in [`DESIGN.md`](DESIGN.md), and the consumer read path is in
[`CONSUMER-INTEGRATION.md`](CONSUMER-INTEGRATION.md).

**Shipping a new consumer image into an environment that already runs is not a
ceremony.** That path re-pins a digest and rolls the consumers. It needs no new keys, so
the keyset, both signer addresses and the client-key hash all stay byte-identical.

---

## 1. Mental model

A ceremony spans two kinds of GCP project, and the split is the security model.

| Project | Role | Holds |
|---|---|---|
| the compute project | **producer** | the TDX VM and the public-material bucket that the compute side reads its keyset from |
| one project per partner (N of them) | **vault** | that partner's two secrets, its Workload Identity Pool, and the **CEL** that gates our attestation |

Each partner project holds **two per-audience secrets**: one carries the FHE private key
plus the decrypt signer, the other carries the zk signer. IAM then enforces least
privilege per consumer, rather than trust in consumer code (`DESIGN.md` §9).

The gate lives in the **partner's** project. The partner owns the rule that constrains
us, and we cannot reach in and loosen it.

**The ceremony in one pass.** The VM boots in the compute project. It generates the
keyset in-enclave, Shamir-splits each secret into N shares, and then, for each partner,
attests to that partner's audience, exchanges the attestation for a federated token, and
writes that partner's share to that partner's Secret Manager. After every write
succeeds, it publishes the public material and the per-share digests to our bucket, and
exits. Nothing here is a long-running server.

**Two integrity rules, one per side.**

- **The write is all-or-nothing.** Any partner write that fails crashes the whole run,
  so no half-finished ceremony is ever advertised. The public material is published only
  after every share lands.
- **The read is fault-tolerant.** A consumer fetches all N shares, excludes and logs any
  partner that hangs or returns a bad or stale share, and reconstructs from any T good
  shares. The per-share digests in the published material name the liars.

**Two identities, on purpose.** The **federated attested token**, minted per partner,
authorizes the cross-project write to that partner's Secret Manager — a direct grant to
the attested principal, with no service account to impersonate. The **VM's own
compute-SA token** authorizes the write to our public bucket, which is an in-project
call with no attestation hop.

One share goes to each partner, and a threshold of shares reconstructs the secret. The
partner count (N) and threshold (T) are baked per environment in
`crates/cofhe-keys/src/envs.rs`. The threshold is always at least 2, because the Shamir
backend has no meaningful single-share case.

---

## 2. Step outline

### Step 1 — Each partner onboards their own project

The partner applies the onboarding Terraform in
[`key-share-holders`](https://github.com/FhenixProtocol/key-share-holders), the public
repo a partner clones. One `terraform apply` creates the two secrets, the Workload
Identity Pool and provider with the attestation CEL, and a direct
`secretmanager.secretVersionAdder` grant to the attested principal on each secret. There
is no partner-side software to run.

The partner returns their `{project_id, wip_audience}`, and we register them in the
environment's partner set.

**Write access is opt-in and the partner controls it.** `grant_write_access` defaults to
`false`, which is the steady state, because key creation is bootstrap-only. A partner
passes `true` for the ceremony apply and drops it afterwards, which re-freezes the
secrets and keeps both the secret and the pool in place.

### Step 2 — Build the image through the release workflow

`.github/workflows/build-keygen-tdx.yml` builds the container for `linux/amd64` and
pushes it to the shared `fhenix-artifacts-registry` project, which holds the images for
this service and its two consumers. It authenticates to GCP through GitHub Workload
Identity Federation and impersonates a keyless publisher service account, so there is no
long-lived key anywhere in the build. The workflow prints the image digest in its run
summary.

The workflow runs from `main` only. Its provider CEL pins this repository plus the
workflow's `job_workflow_ref`, so a branch dispatch fails federation by design.
Confidential Space is amd64, and a release build of tfhe under emulation on an arm64
laptop is slow and prone to OOM, so the runner builds natively.

For pre-merge iteration, build the same Dockerfile with Cloud Build or `docker buildx`
under your own credentials. Both paths push to the same registry, and a production gate
pins one exact digest, so a dev image is never accepted. An image built outside the
workflow carries **no provenance**, so a partner's check on it fails — correctly, but the
message reads like tampering.

**The partner check does not tell a dev image from a release.** A dispatch from `main`
with a tag like `dev-alice` produces a genuine attestation, and the check passes. It
proves only "our workflow, on main, built this digest from this commit". Choosing which
commit is a release stays a human decision. Never hand a partner a digest you did not
mean to release.

**Record the `(source commit, image digest)` pair.** Both come from the run summary.
The commit is not just an audit reference: the partner proves the pair against the
public log before it pins anything, so a wrong or missing commit blocks the release.
The digest is what the runtime gate enforces.

### Step 3 — Each partner pins the blessed digest

For any non-development run, each partner re-applies their onboarding module with the
released image digest **and** the source commit (`image_digest` and `source_sha`; see
[`key-share-holders`](https://github.com/FhenixProtocol/key-share-holders)). Their CEL
then accepts only that exact image, and the write grant is scoped to the same digest.

This is the production gate. A new image needs a partner re-apply, which is explicit
per-image consent, not a cost to work around (`DESIGN.md` §11).

### Step 4 — Run the ceremony

`terraform/service` creates the compute service account, grants it write on the
public-material bucket, and creates the TDX VM. On boot, the launcher pulls the pinned
image and runs the ceremony once.

The stack gates the VM behind a `run_ceremony` flag that defaults to **false**, so
routine infrastructure applies never re-create the VM and regenerate the keyset. Running
a ceremony is an explicit opt-in: turn the flag on for the run, then turn it back off.

The partner set, the Shamir N and T, the secret ids, and the public bucket and prefix are
**baked into the image per environment** and resolved from a single `COFHE_ENV` selector.
They are not deployment variables. Changing any of them is a rebuild plus a partner
re-pin. The selector fails closed on any value outside the baked map.

Inside the VM, the run does five things, and each is visible in the log: fetch the
attestation token, generate the keyset, Shamir-split each secret, write one share per
partner through that partner's gate, and publish the public material and digests. It
then logs `keygen ceremony complete` and exits.

On a clean exit the launcher shuts the VM down, so the instance ends up `TERMINATED`.
That is success. A crash looks the same from outside the VM, so confirm the run through
the log and the new secret versions.

### Step 5 — Read the log

The workload writes JSON lines, and the launcher ships them to Cloud Logging. Expect one
attest → exchange → write block per partner, each naming its `project_id` and the
`share_hash` it wrote, and then the completion line with the two signer addresses.

We log **only public data**: sizes, signer addresses, secret and bucket names, and
per-share hashes. Key bytes are never logged.

### Step 6 — Verify the result

Verification has two layers, and the `verify` CLI runs both.

**A. Per-partner envelope decode.** Read one partner's share back, decode the envelope,
and hash the payload. The hash must equal the `share_hash` that the VM logged for that
partner and the per-share digest in the published material. `verify` fetches no JWKS and
verifies no attestation token: that consumer-side check was removed, and share
authenticity rests on the partner's write-gate instead (`DESIGN.md` §7).

> **Reading a share is a break-glass step.** The keygen principal is add-only, and this
> check reads, so it needs a human `secretAccessor` grant on the secret. Such a grant is
> the one thing the custody model exists to prevent, and T of them together reconstruct
> the network key. Use it only where the keyset is disposable and every partner project
> is our own. Remove each grant as soon as the check no longer needs it, and confirm the
> removal rather than assuming it.

> **On a real network, verify without reading.** The ceremony is all-or-nothing, so the
> completion line already proves every write landed. Version **metadata** confirms one
> new version per partner. The end-to-end proof is a consumer booting, reconstructing
> T-of-N in-enclave, and matching the published signer address.

**B. Live T-of-N reconstruct** (`verify reconstruct`). This is the consumer-side check.
It wraps the same reader the consumers embed, so it fetches all N shares, filters liars
by per-share digest, reconstructs from T, and validates the result against the published
full-key digest. The partner set comes from the baked environment map, selected with
`--env`, and there is no flag that points the CLI at an ad-hoc partner list.

What the two layers prove, in order:

1. each share was written by the partner's attested write-gate, because only the attested
   enclave holds `secretVersionAdder` on that secret;
2. each share matches its per-share digest, which is the liar filter;
3. the reconstructed payload matches the published full-key digest.

The bucket's write IAM protects the digest lists themselves: only the producer can write
the manifest (`DESIGN.md` §7).

### Step 7 — Teardown

The VM is the only billable piece. Turn the ceremony flag back off, which destroys the
VM and leaves configuration and reality in step, so no later apply tries to "fix" drift
by re-running the ceremony. The partner projects hold only Secret Manager and IAM, so
leave them applied. Secret versions are retained.

---

## 3. Production checklist

The shipped defaults suit development. A real deployment adds all four.

1. **Pin `image_digest` in every partner CEL, and give `source_sha` beside it.** The
   module ships the digest empty, which is a development default, and an unpinned CEL
   accepts any attested Confidential Space workload in our compute project. A pinned
   digest without its commit fails the partner's apply: the provenance check cannot run
   without both.
2. **Deploy by digest, never by a mutable tag.** The service stack's image reference uses
   the `@sha256:` form and matches the pinned digest. A tag can move, and a VM whose
   image does not match the pin is correctly rejected at the write.
3. **Build through the release workflow** on `main`, and pin that CI-built digest in both
   places above.
4. **Re-pin every partner to the blessed image** before the run, with both values from
   that run's summary.

## 4. Development versus production

- **Digest pinning.** Development leaves `image_digest` empty, so a rebuild forces no
  re-apply. Production pins it in every partner CEL, and the digest pin is the
  enforcement that decides which image can write. Production also carries `source_sha`,
  which the partner proves before it pins; it never enters the CEL.
- **Write access.** `grant_write_access` stays `false` outside a ceremony apply, and the
  partner is the one who turns it on.
- **Who runs the partner stack.** In production the partner runs it in their own project.
  An environment where we own the partner projects **demonstrates** the model; it does
  not enforce it, because we are owners there.
- **Live key rotation is future work.** Today a re-run appends a fresh keyset as a new
  secret version across all partners, which invalidates existing ciphertexts.
