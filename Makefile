# CoFHE TDX keygen — dev Makefile.
#
# The cloud deploy lives in terraform/ and is driven by hand per the ceremony
# outline (CEREMONY.md), not from here. These targets are the local dev loop only.

.PHONY: run-local test build fmt clippy check

# Local dev (no GCP/TDX): runs the one-shot keygen ceremony with the `mock`
# feature — keys are generated in-process and the cloud writes are stubbed.
run-local:
	cargo run -p keygen --features mock --bin keygen

# Unit tests across the workspace (the lib carries the suite; no cloud needed).
test:
	cargo test --workspace

build:
	cargo build --workspace --bins

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -Dwarnings

# Everything CI-equivalent in one shot.
check: fmt clippy test
