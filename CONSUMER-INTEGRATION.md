# Consumer integration & per-audience key split

How consumers (ZeeK Verifier, TeeCryptor) read the key material this service
produces, and the per-audience secret split that lets each consumer read **only the
secret it needs**. IAM enforces that split, not trust.

> Status: **shipped end-to-end.** The producer side (two per-audience secrets, N-of-T
> Shamir, the wire format, digest validation) and the consumer side (embedded
> `cofhe-keys`, partner-enforced attested reads) are both live — staging 2026-07-21,
> testnet 2026-07-30.

---

## 1. What we produce

We generate the keyset in-enclave and write **two per-audience secrets** per partner
into Secret Manager. Each one wraps one component's canonical bytes in an
audience-agnostic envelope: the FHE priv plus its decrypt signer go to the TeeCryptor
secret, and the zk signer goes to the ZK verifier secret. The exact envelope and
component types live in `crates/cofhe-keys/src/serialization.rs`.

The producer stamps a provenance token, and **no consumer reads it**. It stays in the wire
format for compatibility only, so do not treat it as a control. `DESIGN.md` §7 explains
why the consumer-side attestation check was removed and what carries integrity instead.

The **consumers embed** the portable reader
(`crates/cofhe-keys/src/reader.rs`). `read_fhe_priv` and `read_zk_signer` do the whole
Shamir job: they gather every partner's share fault-tolerantly, filter liars by
per-share digest fail-closed, reconstruct from T, validate against the published full
digest, and return the typed component. (`read_share` is the single-secret unit;
`read_public` reads the public material.)

---

## 2. Why the material is split

Secret Manager access control is **per-secret**: `secretAccessor` grants read of the
*entire* payload. We also **deliberately do not encrypt-to-consumer**, because
confidentiality rests on the partner's IAM (`DESIGN.md` §11).

A single combined secret would therefore be **all-or-nothing**: granting ZK accessor to
read its signer would also expose the raw `client_key`, and ZK could then decrypt.
Returning only the requested field in code is an API convenience, **not a security
boundary**. The boundary is Secret Manager plus IAM, and one secret cannot express "ZK
may read the signer but not the priv". Differential least privilege therefore needs
separate secrets, which is what we write.

---

## 3. The split

| Secret | Contents | Reader | Must NOT be able to read |
|---|---|---|---|
| `cofhe-tee-zk-signer` | `zk_signer_priv` | ZK verifier | the FHE `client_key` — it must never be able to decrypt |
| `cofhe-tee-fhe-priv` | `client_key` + `decrypt_signer_priv` | TeeCryptor | the ZK signer |

TeeCryptor reads the FHE priv **and** its decrypt-path signer, bundled, because it
consumes both. ZK reads only its signer. Both sizes sit comfortably inside the 64 KiB
per-version cap (each signer is 32 B, `client_key` is ~40 KB).

**GCP IAM enforces least privilege**, not the in-process struct and not trust in
consumer code. A consumer granted on one secret physically cannot obtain the other
audience's bytes.

---

## 4. How a consumer reads: attested federation per partner

The read path mirrors the keygen **write** path. There is no shared service account, no
impersonation, and no standing credential.

**Identity (per partner).** Each partner project runs a reader Workload Identity Pool
`cofhe-tee-reader-pool`, with one provider per consumer (`teecryptor-reader`,
`zee-k-reader`). The consumer's TDX enclave attests, exchanges the attestation for a
federated token at *that partner's* audience, and reads *that partner's* share. It
repeats that per partner, then reconstructs. The provider's CEL lives in the
**partner's** project, so we cannot weaken it. It admits only a genuine Intel TDX
Confidential Space workload with STABLE support, debug disabled since boot, running in
the consumer's compute project under the consumer's exact image digest. The exact CEL
is in the `partner-onboarding` module in
[`key-share-holders`](https://github.com/FhenixProtocol/key-share-holders).

`secretAccessor` is granted directly to the digest-scoped attested principal
(`principalSet://…/attribute.image_digest/<digest>`) on **only** that consumer's
secret. There is no unpinned fallback, so **rotating a consumer image requires a
partner re-apply with the new digest**. That is explicit per-image consent, the same as
the keygen write pin. The module pins **one** digest per consumer, so the moment a
partner re-applies, the old image loses read access there. A running instance keeps
serving from memory, but it could no longer boot, so keep the gap between the re-pin and
the roll short. The onboarding input is the module's `attested_readers` map; see
`partner/modules/partner-onboarding/README.md` in
[`key-share-holders`](https://github.com/FhenixProtocol/key-share-holders).

**Source (baked, not configurable).** A compile-time environment map in `cofhe-keys`
decides *which* partners and *which* public bucket a consumer reads. Each entry names
the partner set, its audiences, and the public-material location. That map, and the set
of environment names it defines, is the single source of truth in
`crates/cofhe-keys/src/envs.rs`. Adding an env is a code change plus a consumer rebuild,
by design.

> **The `mainnet` entry holds the real partner set: six key-share holders, threshold
> 3.** Every slot holds a real project id and number, so a consumer builds its partner
> list and reads normally. Changing a holder is an `envs.rs` edit → consumer rebuild →
> new digests re-pinned in the `keygen-partners` var-file → all six partners re-apply
> `partner/`. There is no path that skips the rebuild.
>
> Do not gate on the partner count you see at build time. Call `partner_refs` and
> propagate its error; it is the only place the read side sees the declared set. Every
> later stage works on a filtered list, because a partner that fails to federate is
> dropped, so a check further down cannot tell a reduced set from a complete one.

The **only** operator input is a `COFHE_ENV` selector (`tee-env-COFHE_ENV` metadata),
and `lookup(env)` **fails closed** on anything outside the map. There is no default and
no fallback. `PARTNERS`, `PUBLIC_BUCKET` and `PUBLIC_OBJECT` are not env vars or tfvars
anywhere.

That closes the redirect attack an operator with `setMetadata` would otherwise have.
The selector can only pick one of our own blessed environments, and the reader CEL's
compute-project pin refuses even a wrong-env pick at the partner.

> **Rebuild triggers.** Onboarding a new env (adding its triplet) and changing a
> partner *set* within an env are code changes → consumer rebuild → new digests →
> partner re-apply. A same-set re-share needs no rebuild.

**Division of labour:** the consumer owns its identity and its image rotation. We own
the wire format, the gather, the reconstruction and the validation. A consumer must not
roll its own decode. Getting threshold reconstruction or fail-closed digest validation
subtly wrong is a security bug, so there is one implementation
(`reconstruct_and_validate`) and consumers call it.

**Public material** (`ServerKey`, `CompactPublicKey`, CRS and the manifest) is
non-secret. A consumer reads it with its **own compute-SA metadata token**, not a
federated one, because it sits in our bucket rather than a partner's. Per env:

| Env | Public bucket | Access |
|---|---|---|
| staging | `localcofhenix` | world-readable (`allUsers` → `objectViewer`); no per-SA grant |
| testnet | `fhenix-testnet-v2` | IAM-gated; `public_material_reader` grant to each consumer's compute SA, **prefix-conditioned** to `${public_prefix}/` so read stays scoped to the published material |
| mainnet | `fhenix-mainnet-keys` | world-readable (`allUsers` → `objectViewer`); no per-SA grant, so `public_material_readers` stays empty. A dedicated bucket that holds nothing but the published public material, so no prefix-conditioned grant is needed. |

Its integrity rests on the bucket's **write** IAM: only the keygen producer may write
these objects. It does not rest on a consumer-verified attestation, which was removed
(`DESIGN.md` §7). Keep the write IAM tight, because a principal who can write the
bucket can swap the manifest and the artifacts together. `public_key` and `server_key`
have a functional backstop: results computed against substituted keys do not match the
network's real keys, and a relying party that checks a signed output detects that.
**The CRS has no such backstop.**

### What embedding `cofhe-keys` imposes on your build and egress

Two things arrive with the crate. There is no opt-in and no configuration.

- **Egress TLS posture.** Every googleapis call the crate makes (Secret Manager, STS,
  GCS) requires TLS 1.3 with the X25519MLKEM768 hybrid post-quantum key exchange, and
  it fails closed. A classical-only peer, or a TLS-intercepting middlebox on the egress
  path, breaks the handshake — you see a generic connect error, so check the middlebox
  before the code. The crate also refuses https→http redirects. For the rationale, see
  keygen `DESIGN.md` §10. The crate's clients carry this enforcement with an explicit
  crypto provider, so it does **not** depend on your process's default rustls provider.
  An existing `ring::default_provider().install_default()` in your binary keeps working,
  and keeps governing your own non-`cofhe-keys` TLS.
- **Build prerequisite.** The crate pulls `aws-lc-sys` (the ML-KEM provider), which
  needs `cmake` and a C compiler at build time. Add `cmake` to your builder image
  alongside `build-essential`.

---

## 5. Validating what you reconstruct

`reconstruct_and_validate` checks the two published digest tiers, and both fail closed: a
per-share digest that names a lying or stale partner and excludes it, and a full-key
digest over the reassembled payload. `DESIGN.md` §7 carries the reasoning, including why
a genuine share alone does not prove that reconstruction yields the right key.

A consumer calls that one implementation and does not roll its own decode.

**Keep one asymmetry in mind.** The keygen **write** is all-or-nothing: any partner write
that fails crashes the run, so no half-finished ceremony is ever advertised. The **read**
is fault-tolerant: a hung, stale or lying partner is excluded and logged, and
reconstruction proceeds from any T good shares.

**Live key rotation is future work.** Today a re-run appends a fresh keyset as a new
version across all partners.
