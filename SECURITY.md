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
- The MCP server (`crates/vledger-mcp`, `vledger mcp` subcommand, `vledger-mcp` binary)
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

## Bug Fixes

**Merkle root display truncation fixed (v1.0.39)**

The Merkle root displayed in three places — after `SELECT * FROM ledger` (inline
proof display), after `verify-proof`, and in `verify-audit-package` output — was
silently truncated to the first 32 hex characters (16 bytes) of the 32-byte BLAKE3
hash. This was a display-only bug caused by `&root_hex[..root_hex.len().min(32)]`
in three sites in `crates/vledger/src/main.rs`. The underlying hash was always
computed and stored correctly; only the terminal printout was shortened.

All three sites now print the full 64-character hash. This fixes a potential
confusion where a human operator comparing the inline display against
`SELECT MERKLE_ROOT()` output would see apparent mismatches.

**`MERKLE_ROOT()` single-argument form added (v1.0.37)**

`to_seq` is now optional — `MERKLE_ROOT(seq)` is equivalent to
`MERKLE_ROOT(seq, seq)`. Previously a single argument returned an error.

**Column projection fixed (v1.0.38)**

`SELECT specific, columns FROM ledger` now returns only the requested
columns. Previously all 12 columns were always returned regardless of the
SELECT list. Works for all column types and all three tables (`ledger`,
`ledger_lines`, `accounts`). `SELECT *` is unchanged.

**`MERKLE_ROOT(from_seq, to_seq)` SQL function added (v1.0.36)**

VectorLedger now exposes the BLAKE3 Merkle root as a first-class SQL function.
Any client with `admin`, `operator`, or `auditor` role can call:

```sql
SELECT MERKLE_ROOT(1, 100000);
```

Returns `from_seq`, `to_seq`, `entry_count`, and `merkle_root` (64-char BLAKE3
hex). The `readonly` role is blocked by the privilege check. The function uses
the same leaf inputs (`content_hash` per entry) as the `--with-proofs` query
engine and the audit package CLI, so roots produced by all three methods are
directly comparable. `MERKLE_ROOT()` does not require the server to be started
with any special flag — it is available at all times.

**pgwire `--with-proofs` parameter silently ignored (fixed in v1.0.35)**

The `execute_query` function in `crates/vledger-pgwire/src/server.rs` declared its
`attach_proofs` argument as `_attach_proofs` and always called `Executor::new()`
regardless of the flag value. As a consequence:

1. All SELECT queries via the pgwire path always used a write lock, blocking
   concurrent reads unnecessarily.
2. `ReadExecutor::with_proofs()` was never called, so `qr.proof` was always `None`
   and no Merkle root was ever computed or sent to pgwire clients — even when the
   server was started with `--with-proofs`.

Fixed by: renaming the parameter, routing read plans through `ReadExecutor` on a read
lock (with or without proofs depending on the flag), and emitting the Merkle root as a
pgwire `NoticeResponse` after the data rows when a proof is present.

This was a correctness bug, not a security vulnerability. No data was exposed and no
integrity guarantee was weakened — the Merkle root simply wasn't being delivered to
pgwire clients. The native JSON protocol (port 5433) was unaffected and always sent
proofs correctly when `--with-proofs` was set.

## Known Limitations

The following known limitations are **by design** and are **not** security
vulnerabilities:

- `WalSyncMode::NoSync` provides no durability guarantee and must never be
  used in production. As of v1.0.32, `NoSync` does not exist in the type
  system of a standard release build — it is gated behind
  `--features dev-no-sync` at compile time. A release binary cannot accept
  `--wal-sync-mode=no_sync` regardless of configuration.
- Self-signed TLS certificates are accepted for loopback connections only.
  Non-loopback connections require a CA-signed certificate via `--ca-cert`.
- The `file` key source stores the master key on disk in hex. This is
  documented as a development-only option and the server emits a loud
  warning at startup.
- The MCP server (`vledger mcp` / `vledger-mcp`) does **not** implement TLS.
  It should be bound to `127.0.0.1` (the default) or placed behind a
  TLS-terminating reverse proxy when accessed over a network. All MCP tool
  calls go through the same RBAC enforcement as direct SQL; the MCP server
  itself does not bypass any access control. The `--ask` flag sends the
  natural-language question and the ledger schema context to a third-party
  LLM endpoint — do not include sensitive data in the question text.
  No ledger data is sent to the LLM; only the schema description and the
  user's question string are transmitted.

## Fuzz-Found Vulnerabilities (fixed)

The following vulnerabilities were discovered by the VectorLedger fuzz test
suite and fixed before any public exposure:

**WAL reader unbounded allocation (fixed in v1.0.32)**
The WAL segment reader allocated a buffer of `payload_len` bytes before
attempting any read. A WAL record header with `payload_len = 0xFFFFFFFF`
triggered a 4 GiB allocation attempt and killed the process. The same
issue existed for `ct_len` in the encrypted record path. Fixed by capping
both fields at `MAX_RECORD_PAYLOAD = 64 MiB` before any allocation.
Severity: an attacker with write access to the WAL directory could prevent
the server from starting.

**SQL planner index-out-of-bounds panic (fixed in v1.0.32)**
The SQL query planner indexed directly into the `VALUES` list without
checking that the value count matched the column count. An `INSERT`
statement with fewer values than columns caused a panic. Fixed by replacing
`vals[idx]` with `vals.get(idx)` returning a typed error. Severity: any
authenticated client could crash the query planner with a single malformed
`INSERT` statement.

**Fuzz harness bincode unbounded allocation (fixed in v1.0.32)**
The `fuzz_transaction` harness fed raw bytes directly to
`bincode::serde::decode_from_slice` without an allocation limit. Fixed by
adding `.with_limit::<{1 MiB}>()` to the decode config. This was a
harness-only issue — not a vulnerability in production code, which validates
payload sizes at the WAL reader layer before reaching bincode.
