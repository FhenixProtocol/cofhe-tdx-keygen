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
ceremony.** That path uses tags A and B (§5): it re-pins a digest and rolls the
consumers. It needs no new keys, so
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
`crates/cofhe-keys/src/envs/`. The threshold is always at least 2, because the Shamir
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
secrets and keeps both the secret and the pool in place. While the flag is on, the
module also binds `roles/secretmanager.viewer` on both secrets to the same principal.
The run uses it to list version numbers before any write. It never reads a payload.

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

**The workflow runs the pushed image before it attests it.**
`scripts/check-image-boots.sh` starts the exact digest with no network and no
`COFHE_ENV`, and requires the keygen's own "COFHE_ENV not set" error. Provenance
proves who built an image, not that it starts: an image whose binary cannot load
passes every provenance check and fails only at ceremony time. If this step fails,
the workflow does not attest the digest, so no partner can pin it. CI runs the same
check on every commit, and the workflow refuses a commit without green CI.

For pre-merge iteration, build the same Dockerfile with Cloud Build or `docker buildx`
under your own credentials, and run `scripts/check-image-boots.sh` on it. Both paths
push to the same registry, and a production gate pins one exact digest, so a dev image
is never accepted. An image built outside the workflow carries **no provenance**, so a
partner's check on it fails — correctly, but the message reads like tampering.

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

A ceremony refuses to run while any object exists under the `public-material` prefix
at that bucket and zone (the legacy name or any `.v{N}`). So an image built from the
wrong env cannot replace a live keyset. A deliberate key
rotation bakes `replace_live_keyset: true` in the env, and that needs review like any
other env change. After the rotation, set it back to `false` and release, so the
guard is on again for the next image.

Inside the VM, the run does five things, and each is visible in the log: fetch the
attestation token, generate the keyset, Shamir-split each secret, write one share per
partner through that partner's gate, and publish the public material and digests. It
then logs `keygen ceremony complete` and exits.

Each share goes to the env's baked `share_version`, the same number at every partner.
Secret Manager does not let a writer choose a number, so the write path is:

1. **Precheck.** List both secrets at every partner, all states. If any newest number
   is at or above the target, stop before any write.
2. **Fillers.** Where the newest number is below target−1, add filler versions (the
   bytes `de ad be ef`) up to target−1. A filler is not an envelope, so a read of one
   fails closed.
3. **Shares.** Write each real share at the target.

Every returned number is checked, and a wrong one stops the run. There is no retry,
and the Secret Manager timeout is 1800 s. Run one keygen per env at a time: two
runs at once both pass the precheck, and the last manifest wins. The manifest goes last, to
`public-material.v{N}`. Its `.provenance` sidecar goes just before it, so a stop
never leaves a manifest without its sidecar.

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
partner and the per-share digest in the published material. This default `verify` mode
needs `--version <N>` and `--public-object <manifest of version N>`; it has no default
and no `latest`. `verify` fetches no JWKS and
verifies no attestation token: that consumer-side check was removed, and share
authenticity rests on the partner's write-gate instead (`DESIGN.md` §7).

> **Reading a share is a break-glass step.** The keygen principal is add-only, and this
> check reads, so it needs a human `secretAccessor` grant on the secret. Such a grant is
> the one thing the custody model exists to prevent, and T of them together reconstruct
> the network key. Use it only where the keyset is disposable and every partner project
> is our own. Remove each grant as soon as the check no longer needs it, and confirm the
> removal rather than assuming it.

> **On a real network, verify without reading.** The ceremony is all-or-nothing, so the
> completion line already proves every write landed. Version **metadata** confirms the
> result: on every partner, the newest version of both secrets equals the baked
> `share_version`. Read the baked number from `share_version: v(N)` in
> `crates/cofhe-keys/src/envs/<env>.rs` at the released commit, or from the
> `keygen starting` log line. Then, for each partner and each secret, run
> `gcloud secrets versions list <secret> --project=<partner project> --sort-by=~createTime --limit=1 --format='value(name.basename())'`.
> Each output must equal N.
> The end-to-end proof is a consumer booting, reconstructing
> T-of-N in-enclave, and matching the published signer address.

**B. Live T-of-N reconstruct** (`verify reconstruct`). This is the consumer-side check.
It wraps the same reader the consumers embed, so it fetches all N shares, filters liars
by per-share digest, reconstructs from T, and validates the result against the published
full-key digest. The partner set comes from the baked environment map, selected with
`--env`, and there is no flag that points the CLI at an ad-hoc partner list. The CLI
reads the env's baked `share_version` and its manifest `public-material.v{N}`.
`--version <N>` reads version N and its own manifest `public-material.v{N}`.
`--public-object` overrides the manifest. There is no `latest`.

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
   that run's summary. Cutting the release that carries them is one dispatch; see
   [`RELEASING.md`](https://github.com/FhenixProtocol/key-share-holders/blob/main/RELEASING.md)
   in `key-share-holders`.

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
- **A re-run over a live keyset is refused** (Step 4). A deliberate key rotation writes
  a fresh keyset to all partners, which invalidates existing ciphertexts.

## 5. Reshare — change the partner set, keep the keyset

Use a reshare to add or replace a key-share holder. Do not use it after a suspected
leak: old shares still rebuild the key. Run a new ceremony instead.

A reshare reads the shares at version N on the source partners. It writes version M
on the target partners and publishes `public-material.v{M}`. It never deletes
`public-material.v{N}`. So old consumers (vN) and new consumers (vM) run side by side,
and a restart works for both. There is no maintenance window. The rationale is in
[`DESIGN.md`](DESIGN.md) §5.

1. **Bake the change** in `crates/cofhe-keys/src/envs/<env>.rs`:
   - Copy the live set into `reshare_from`, with its threshold, its `share_version`
     and the two live signer addresses (they are on-chain). Write the source entries
     in full. Do not point them at `PARTNERS`: you edit `PARTNERS` to the target set.
   - A source partner at another version gets
     `SourcePartner { partner, share_version: Some(v(N)) }`.
   - Set `partners` and `shamir_threshold` to the target set.
   - Raise `share_version` to the target. It must be above every source version.

   An env with `reshare_from` builds a reshare-only image: it can never run a
   ceremony. CI checks the env, and fails if any env's `share_version` goes down
   against `main`. Release the image (Step 2).
2. **Rebuild the consumers** with the new `cofhe-keys`. They read the new
   `share_version` and its manifest. Do not deploy them yet.
3. **Tag A.** Cut a `key-share-holders` release with `keep_previous_readers = true`.
   Each reader then allows its running digest and its new digest. Partners apply it:
   - A source partner that stays: `grant_reshare_read = true` and
     `grant_write_access = true`.
   - A source partner that leaves: `grant_reshare_read = true`. This is optional: the
     run needs only the old threshold of sources.
   - A source partner's read needs `grant_read_access = true` too: that flag is the
     read brake, and it also disables the keygen gate.
   - A new partner: onboard (Step 1) with `grant_write_access = true`.
   - Every partner pins the new keygen digest (Step 3).
4. **Run** with `run_ceremony = true`. The image runs the reshare. The log names
   each source share version it read (`"read share"` lines). Before it writes, the
   run checks the rebuilt key against the published keys and signers. To check the
   source shares by hand first, build `verify` from the `main` commit that the live
   consumers were built from (before the env change):
   - A unity build (it has `--version`):
     `verify reconstruct --env <env> --threshold <old T> --token "$(gcloud auth print-access-token)" --check-keys`.
   - A pre-unity build has no `--version` and no `--check-keys`. It reads each
     partner's newest version and the legacy manifest, and checks the digests only:
     `verify reconstruct --env <env> --threshold <old T> --token "$(gcloud auth print-access-token)"`.

   For a same-set change, the new build also works with `--version <N>`. It then
   reads `public-material.v{N}`; give `--public-object` for another name. In the
   staging migration, use `--version 5 --public-object <prefix>/<zone>/public-material`.
   One `--version` cannot express the partner-1 override (v8), so partner-1 drops
   out as a liar. The check still passes on the other 4 partners (T=2). The run then
   writes at M as in §2 Step 4, and publishes `public-material.v{M}` last.
5. **Roll the consumers** to the rebuilt images. Old pods keep working on vN and
   `.vN` until they are replaced. Confirm a decrypt and a ZK verification.
6. **Tag B.** Set `run_ceremony = false`. Cut a release with
   `keep_previous_readers = false`, and partners set `grant_reshare_read` and
   `grant_write_access` back to `false`. The old digests lose their read, and the
   keygen loses its read, list and write. Remove `reshare_from` and release.
7. **Keep the old versions and manifests.** No partner destroys a secret version, and
   no one deletes a manifest. Recovery and rollback need them. If Fhenix later wants
   an old share gone, it asks that partner explicitly, and the partner removes it by
   hand.

A plain consumer image upgrade uses the same tags A and B, with the reshare flags off.

**An open overlap keeps its running image.** While a reader lists two digests, the
older one stays until a tag B retires it. A new tag A (a rerun or a fix-forward) then
gives `[new, running]`, so the running consumers keep their read. Apply tag B only
after a successful roll, and before the next upgrade.

**Do not delete a pinned image** from the registry. Every partner apply proves each
pinned digest against its public provenance.

**Rules for every env:**

- Deploy a unity consumer only after its env has `public-material.v{share_version}`.
- Roll all consumers to unity images before the env's first non-legacy reshare. That
  reshare does not update the legacy `public-material`, so a legacy reader would fail.

### Recovery

A run that stops after its first write ends with an error that carries a recovery
report (also logged as `run stopped; recovery report`). The report lists each share
the run wrote with its version, the filler count per partner and secret, and each
`public-material` object (manifest or sidecar) it already published. The old version and its manifest are
untouched. So, for a reshare and for a first ceremony, consumers that read the baked
version are not affected, and a restart works. A
`replace_live_keyset` rotation says instead that the shared artifacts may already be
overwritten: rotation recovery is out of scope here.

A first ceremony that stopped in the publish step left a `public-material` object, so
the replace guard stops its rerun: bake `replace_live_keyset: true` for the rerun, then
set it back to `false`.

A precheck stop gets no report. Nothing is written, and the error says what to do:
bake a higher `share_version`.

In the staging migration, a stop can fall between `public-material.v9` and the legacy
`public-material`. A rerun at a higher version publishes both names again. This run
overwrites the legacy `public-material` that legacy consumers read, so its report
does not say "untouched". Compare `public-material` with `public-material.v9` by md5.
If they are equal, the run published: do not rerun. Legacy consumers that read
`latest` may already see v9.

| The report says | What to do |
|---|---|
| no share written | Rerun the same image: the fillers stop at target−1, so the target is still free. If the last write timed out, it can still have created a version; then the precheck stops the rerun, and you need a higher `share_version`. |
| shares written | They are orphans: no reader reads M before an image with M is deployed. Build a new image whose `share_version` is above the highest version listed, and rerun. A version number is never reused. |

The VM runs its container once, so a rerun is `run_ceremony = false`, apply, then
`run_ceremony = true`, apply. A new image needs a new tag A first, so partners pin
the new keygen digest (Step 3). A reshare rerun rebuilds the key from vN again,
splits it with fresh randomness, and writes at the new target. The orphans stay as
older versions that no reader uses.

**A rerun of a finished run** stops at the precheck: every partner is already at the
target.

Do not disable or destroy a secret version to recover. Every reader reads an exact
number, and the run never reuses one.

**To roll back** after a finished reshare, repin the old consumer digests (a
`key-share-holders` release with them). They read vN and `.vN`, which still exist. A
removed partner must still hold its secret and its read gate for this. A reshare back
(`reshare_from` = the new set, `partners` = the old set, a higher `share_version`)
also works and uses the same path.

### Migration to unity versions (one time per env)

- **Testnet and mainnet: no reshare.** All partners are at v1. The env bakes
  `share_version: v(1)` with no `reshare_from`. An operator copies `public-material`
  to `public-material.v1`, and `public-material.provenance` to
  `public-material.v1.provenance`, once. The bytes are the same. No share and no
  existing object changes, so today's readers keep working. The commands are in
  the gitops `tee/cofhe-tdx-keygen/CLOUD_RUNBOOK.md`, Step 6c.
- **Staging: one migration reshare.** The same partner set, source v5, a partner-1
  override of v8, target v9, and `legacy_manifest: true`. It reads the legacy
  `public-material`, writes v9 at all partners, publishes `public-material.v9`, and
  writes the same bytes to `public-material`.
  - Do not restart a consumer from the first filler to the publish. In that window,
    a legacy consumer's `latest` is a filler or a share that the legacy manifest does
    not list.
  - If the run stops, rerun at once with a higher `share_version`.
