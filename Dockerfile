# syntax=docker/dockerfile:1.7
# Base images are pinned by digest (not just tag) for a reproducible build and to
# remove the mutable-tag supply-chain risk. Trade-off: a pinned base no longer
# receives automatic security patches — bump these digests deliberately (track
# the tag for CVE fixes and update on a cadence). Tags kept alongside the digest
# for readability; Docker resolves by digest. Both are the multi-arch index
# digest, so the amd64 Confidential Space build still selects the amd64 manifest.
#
# Rust >= tfhe 1.5.1 MSRV (1.91.1). build-essential (cc) + cmake are required by
# aws-lc-sys — the rustls crypto provider carrying ML-KEM for the pinned
# TLS 1.3 + X25519MLKEM768 egress posture; rust:slim ships neither.
#
# The build stage and the runtime stage must use the SAME Debian release. The
# binary links against the glibc of the build stage, and a newer glibc can add
# symbol versions that an older runtime does not have. The plain `rust:*-slim`
# tag follows the newest Debian: a trixie (glibc 2.41) build of this binary
# needed GLIBC_2.38, and the debian12 runtime (glibc 2.36) refused to load it.
# So name the release in the tag. scripts/check-image-boots.sh runs the built
# image in CI and before every release attestation.
FROM rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin keygen --no-default-features && \
    cp target/release/keygen /keygen

FROM gcr.io/distroless/cc-debian12@sha256:d703b626ba455c4e6c6fbe5f36e6f427c85d51445598d564652a2f334179f96e
COPY --from=build /keygen /keygen
# Only the baked-environment selector (ENV) and log level (RUST_LOG) may be
# overridden by an operator. The partner set + write audiences, N/T, the secret
# ids, and the public bucket + layout are compiled in per-env (see cofhe_keys::reader)
# and are NOT in this allowlist, so a VM metadata override cannot change them.
LABEL "tee.launch_policy.allow_env_override"="COFHE_ENV,RUST_LOG"
LABEL "tee.launch_policy.log_redirect"="always"
ENTRYPOINT ["/keygen"]
