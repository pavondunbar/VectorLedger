# VectorLedger Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@vectorguardlabs.com**.
For sensitive disclosures, encrypt your report using our PGP key
(fingerprint published at https://vectorguardlabs.com/pgp-key.asc).

Include the following in your report:
- A description of the vulnerability
- Reproduction steps (minimal proof-of-concept preferred)
- The version(s) of VectorLedger affected
- Your assessment of impact and severity
- Any suggested mitigations

## Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgement | 2 business days |
| Initial assessment | 5 business days |
| Fix or mitigation plan | 30 days for critical, 90 days for others |
| Public disclosure | Coordinated with the reporter |

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
We will credit researchers who report valid vulnerabilities unless they
prefer to remain anonymous.

## Scope

**In scope:**
- `vledger` binary and all crates in this repository
- Official client SDKs (`clients/python`, `clients/typescript`, `clients/go`)
- The WAL, crypto, ledger, server, pgwire, replication, and HSM subsystems
- Authentication and authorization logic
- Cryptographic implementation correctness (key derivation, encryption,
  signing, hash chains)

**Out of scope:**
- Third-party libraries (report vulnerabilities directly to their maintainers
  and to the Rust Advisory Database at https://rustsec.org)
- Deployments not operated by VectorGuard Labs
- Social engineering attacks against VectorGuard Labs personnel
- Physical attacks against hardware

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
scoring system for severity classification:

| Score | Severity | Response target |
|---|---|---|
| 9.0–10.0 | Critical | 7 days |
| 7.0–8.9 | High | 30 days |
| 4.0–6.9 | Medium | 60 days |
| 0.1–3.9 | Low | 90 days |

## Secure Release Process

Every release is:
1. Built from a tagged commit on the `main` branch
2. Signed with cosign (keyless, GitHub Actions OIDC identity)
3. Accompanied by a SHA-256 checksums file
4. Accompanied by a CycloneDX SBOM

Verify a release:
```bash
cosign verify-blob \
  --certificate vledger-v0.1.0-checksums.txt.sig.pem \
  --signature   vledger-v0.1.0-checksums.txt.sig \
  --certificate-identity "https://github.com/vectorguardlabs/vectorledger/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vledger-v0.1.0-checksums.txt
```

## Known Limitations

The following known limitations are **by design** and are **not** security
vulnerabilities:

- `WalSyncMode::NoSync` provides no durability guarantee and must never be
  used in production. The server refuses to start with existing data in this
  mode.
- Self-signed TLS certificates are accepted for loopback connections only.
  Non-loopback connections require a CA-signed certificate via `--ca-cert`.
- The `file` key source stores the master key on disk in hex. This is
  documented as a development-only option and the server emits a loud
  warning at startup.
