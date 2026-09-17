# Security Policy

## Trust model

CoFHE TDX Keygen's security claim is simple: the network's key material only
ever materializes inside an attested Intel TDX enclave. Each partner's secret
share is written through that partner's own attested write-gate — only the
exact pinned image, verified by attestation, can write a share — and only the
public material is published. The design is built to be verified, not trusted:
this repository is public so anyone can review the source behind the pinned
digest. The architecture, threat model, and every key decision with its
rationale are documented in [DESIGN.md](./DESIGN.md).

## Reporting a vulnerability

Report security issues **privately** — do not open a public issue or PR.

- Preferred: GitHub private vulnerability reporting (the repository's
  **Security** tab → "Report a vulnerability").

Include a description, reproduction steps, and impact. We acknowledge reports
promptly and coordinate disclosure with you.

## Security review

This codebase is under continuous security review: every change to a security
control gets adversarial review before it lands, and findings are tracked to
resolution. An independent third-party audit is planned ahead of mainnet, and
its results will be published here.
