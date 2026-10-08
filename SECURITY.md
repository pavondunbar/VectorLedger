# VectorLedger Security Policy

**Version:** 1.5.6  
**Published by:** VectorGuard Labs  
**Security contact:** security@vectorguardlabs.com

---

## Table of Contents

1. [Reporting a Vulnerability](#1-reporting-a-vulnerability)
2. [Response Timeline and Severity Classification](#2-response-timeline-and-severity-classification)
3. [Supported Versions](#3-supported-versions)
4. [Scope](#4-scope)
5. [Cryptographic Primitives and Algorithms](#5-cryptographic-primitives-and-algorithms)
6. [Hash Chain Integrity](#6-hash-chain-integrity)
7. [Merkle Commitments](#7-merkle-commitments)
8. [Key Management](#8-key-management)
9. [HSM Support](#9-hsm-support)
10. [Secrets Management Backends](#10-secrets-management-backends)
11. [Four-Eyes Approval Workflow](#11-four-eyes-approval-workflow)
12. [Audit Trail](#12-audit-trail)
13. [Compliance Engine](#13-compliance-engine)
14. [Authentication and Session Security](#14-authentication-and-session-security)
15. [Transport Security](#15-transport-security)
16. [RBAC and Authorization](#16-rbac-and-authorization)
17. [Threat Model](#17-threat-model)
18. [Secure Release Process](#18-secure-release-process)
19. [Bug Fixes and Security Advisories](#19-bug-fixes-and-security-advisories)
20. [Known Limitations](#20-known-limitations)
21. [Fuzz-Found Vulnerabilities (Fixed)](#21-fuzz-found-vulnerabilities-fixed)

---

## 1. Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@vectorguardlabs.com**.  
For sensitive disclosures, encrypt your report using our PGP key, fingerprint published at https://vectorguardlabs.com/pgp-key.asc.

Include in your report:
- A description of the vulnerability
- Reproduction steps (minimal proof-of-concept preferred)
- The version(s) of VectorLedger affected
- Your assessment of impact and severity
- Any suggested mitigations

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will credit researchers who report valid vulnerabilities unless they prefer to remain anonymous.

---

## 2. Response Timeline and Severity Classification

We use [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) for severity classification.

| Milestone | Target |
|---|---|
| Acknowledgement | 2 business days |
| Initial assessment | 5 business days |
| Fix or mitigation plan (critical) | 30 days |
| Fix or mitigation plan (others) | 90 days |
| Public disclosure | Coordinated with the reporter |

| CVSS Score | Severity | Fix Target |
|---|---|---|
| 9.0–10.0 | Critical | 7 days |
| 7.0–8.9 | High | 30 days |
| 4.0–6.9 | Medium | 60 days |
| 0.1–3.9 | Low | 90 days |

---

## 3. Supported Versions

| Version | Status |
|---|---|
| 1.5.6 | ✅ Current — security fixes backported here |
| 1.5.5 | ✅ Supported |
| 1.5.x (< 1.5.5) | ⚠ Security fixes only — upgrade to 1.5.6 recommended |
| 1.4.x | ⚠ Security fixes only |
| < 1.4.0 | ❌ End of life — upgrade strongly recommended |

---

## 4. Scope

**In scope:**
- `vledger` binary and all crates in this repository
- Official client SDKs (`clients/python`, `clients/typescript`, `clients/go`)
- The WAL, crypto, ledger, server, pgwire, replication, and HSM subsystems
- The MCP server (`crates/vledger-mcp`, `vledger mcp` subcommand)
- All 15 MCP tools, including the 5 financial reasoning tools (`explain_balance`, `reconcile_account`, `find_policy_violations`, `summarize_period`, `audit_report`), the identity enforcement tool (`resolve_account`), and the correction workflow tools (`propose_correction`, `execute_correction`)
- Authentication and authorization logic
- Cryptographic implementation correctness (key derivation, encryption, signing, hash chains)
- The four-eyes dual-control approval workflow
- The compliance engine and audit log
- The secrets manager backends

**Out of scope:**
- Third-party libraries (report to their maintainers and the [Rust Advisory Database](https://rustsec.org))
- Deployments not operated by VectorGuard Labs
- Social engineering attacks against VectorGuard Labs personnel
- Physical attacks against hardware

---

## 5. Cryptographic Primitives and Algorithms

All cryptographic primitives are centralized in `crates/vledger-crypto/` — a single, auditable location.

| Algorithm | Usage | Notes |
|---|---|---|
| **BLAKE3** | Content hashing, hash chain, Merkle tree, session tokens, WAL checksums, HMAC | 256-bit output |
| **AES-256-GCM** | Encryption at rest (page store, WAL), backup encryption | 256-bit key, 96-bit nonce, 128-bit auth tag; format: `nonce(12B) \|\| ciphertext_with_tag` |
| **Ed25519** | WAL commit signing, database signing key, license signature verification | 32-byte private key, 64-byte signature; via `ed25519-dalek` |
| **HKDF-SHA256** | Key derivation from master key | 256-bit output; context strings: `vgdb/table/{id}/encrypt`, `vgdb/table/{id}/sign`, `vgdb/table/{id}/row/{row_id}`, `vgdb/wal/sign` |
| **Argon2id** | Password hashing | 64 MiB memory / 3 iterations / 4 lanes — above OWASP minimum |
| **X25519** | Key exchange | via `x25519-dalek` |
| **HMAC-SHA256** | AWS KMS cache integrity, webhook verification | 256-bit output |
| **BLAKE3-keyed-MAC** | Replication challenge-response authentication | 256-bit output |
| **CRC-32** | WAL record integrity check | via `crc32fast`; secondary to AES-GCM auth tag |

**TLS implementation:** TLS 1.3 via `rustls` with `aws-lc-rs` provider (`rustls = 0.23.27`). `tokio-rustls` for async. `rcgen` for self-signed certificate generation at `vledger init`. `webpki-roots` for CA certificate roots. Plain-text connections are structurally rejected — there is no runtime flag to disable TLS.

**Memory safety:** All sensitive key material uses `ZeroizeOnDrop` via the `zeroize` crate. Private keys, session keys, and the master key are cleared from memory when dropped.

**Overflow protection:** `Amount` arithmetic operators (`Neg`, `Add`, `Sub`) use `checked_neg`, `checked_add`, `checked_sub`. A silent overflow in financial arithmetic is a compile-time error (v1.0.34+).

---

## 6. Hash Chain Integrity

### Ledger Hash Chain

Every journal entry's `chain_hash` is computed as:

```
chain_hash = BLAKE3(sequence_le64 || prev_chain_hash || content_hash)
```

where:
```
content_hash = BLAKE3(canonical_bytes_of_entry)
```

The chain starts with `ZERO_HASH` (32 zero bytes) as the sentinel `prev_hash` for the first entry (sequence 1).

**Tamper detection:** Any modification to any historical entry's content changes its `content_hash`, which changes its `chain_hash`, which breaks every subsequent chain link — immediately detectable by `VERIFY_CHAIN()`. Even a single bit flip in any historical record produces a detectable chain break at that position.

**Verification:**
```sql
-- Full chain verification
SELECT VERIFY_CHAIN();

-- Range verification
SELECT VERIFY_CHAIN(1, 100000);

-- Single entry
SELECT VERIFY_ENTRY(786295);
```

`verify_chain(entries)` iterates the slice, checking both internal consistency (recomputed `chain_hash` matches stored `chain_hash`) and linkage (`prev_hash` matches the prior entry's `chain_hash`).

**WAL commit signing:** Every WAL commit record is Ed25519-signed via `SignedCommit::new(data, signing_key)`. Verified on WAL replay with `verify_against(trusted_key)` — signature forgery without the private key is computationally infeasible.

### Audit Log Hash Chain

The WORM audit log (`audit/audit.log`) maintains its own **independent** BLAKE3 hash chain:

```
content_hash = BLAKE3(event_json_bytes)
chain_hash   = BLAKE3(prev_chain_hash || content_hash)
```

Every event is fsync'd before returning. The audit chain is independent of the ledger chain — compromising one does not compromise the other.

Events recorded: `ServerStarted`, `AuthEvent` (every login attempt — success and failure), `QueryExecuted`, `EntryPosted`, `AccountCreated`, `AccountClosed`, `KeyRotated`, `ReplicationEvent`, `FourEyesSubmitted`, `FourEyesApproved`, `FourEyesRejected`, `BackupCreated`, `KeyRotationStarted`.

---

## 7. Merkle Commitments

VectorLedger implements a standard binary Merkle tree using BLAKE3 with domain separation:

- **Leaf hashing:** `hash_leaf(data)` = BLAKE3(`0x00` prefix || data)
- **Node hashing:** `hash_node(left, right)` = BLAKE3(`0x01` prefix || left || right)
- **Odd leaves:** last leaf is duplicated at each level
- **Empty set:** returns `ZERO_HASH` (all 32 bytes zero)

The `0x00` / `0x01` domain separation prevents second-preimage attacks where an internal node could be misinterpreted as a leaf.

### Three Ways to Obtain a Merkle Root

1. **SQL function** (any time, no server flag):
   ```sql
   SELECT MERKLE_ROOT(1, 100000);    -- range
   SELECT MERKLE_ROOT(786295);       -- single entry
   ```

2. **Audit package** (Ed25519-signed commitment):
   ```bash
   vledger audit-package --output commitment.json
   ```
   Produces an O(n) pass over all entries with an Ed25519-signed root — a durable, off-system cryptographic commitment.

3. **pgwire `--with-proofs`** (per-query automatic proof):
   When the server is started with `--with-proofs`, every SELECT result includes a `NoticeResponse` with the Merkle root over the returned rows.

### Verification Without a Running Server

`vledger verify-audit-package --file <PATH>` checks:
- Root Ed25519 signature against the baked-in public key
- Content hashes of all entries
- Hash-chain linkage across all events
- Merkle inclusion proofs (if embedded)

No database access, server, or credentials are required — any auditor can verify a package independently.

---

## 8. Key Management

### Master Key Architecture

The master key is a 32-byte (256-bit) symmetric key. It never touches the VectorLedger host in the recommended production deployment (Model 2 HSM). All per-table and per-WAL-segment keys are derived from it via HKDF-SHA256 with unique context strings:

```
table_encrypt_key = HKDF-SHA256(master_key, context="vgdb/table/{table_id}/encrypt")
table_sign_key    = HKDF-SHA256(master_key, context="vgdb/table/{table_id}/sign")
row_key           = HKDF-SHA256(master_key, context="vgdb/table/{table_id}/row/{row_id}")
wal_sign_key      = HKDF-SHA256(master_key, context="vgdb/wal/sign")
```

Compromising one derived key does not expose the master key or any other derived key.

### Key Configuration File

`keys/key_source.json` contains **only metadata** — never the key itself. Example:

```json
{
  "backend": "remote_py_hsm",
  "endpoint": "https://pyhsm.internal.example.com:8443",
  "ca_cert": "/etc/vledger/pyhsm-ca.pem",
  "client_cert": "/opt/vledger/certs/client.crt",
  "client_key": "/opt/vledger/certs/client.key",
  "timeout_ms": 5000,
  "max_retries": 3,
  "caller_id": "vledger",
  "key_id": "vledger.master-key"
}
```

### Key Rotation

`vledger rotate-keys` performs non-destructive key rotation:
- Existing ciphertext remains decryptable with the archived key version
- New writes use the new key immediately after rotation
- Every rotation event is recorded in the WORM audit log (`KeyRotated`, `KeyRotationStarted`)
- Requires Enterprise tier (HSM license feature)

### Database Signing Key

At `vledger init`, an Ed25519 signing keypair is generated:
- `keys/db_signing_pubkey.hex` — public key (mode 0o644)
- `keys/db_signing_key.hex` — private key (mode 0o600)

Private key material is **excluded** from backups. Audit packages are signed with the private key and verified with the baked-in VectorGuard Labs public key.

---

## 9. HSM Support

HSM support is an Enterprise tier feature. VectorLedger supports two deployment models:

### Model 1 — Local PyHSM (Development and Single-Server Production)

The PyHSM daemon runs on the same server as VectorLedger, communicating via a Unix domain socket (`/tmp/pyhsm.sock` by default, overridable via `PYHSM_SOCKET_PATH` or `--pyhsm-socket`). The master key is sealed inside an AES-256-GCM-SIV encrypted keystore within PyHSM. Zero network overhead.

```bash
vledger init --key-source pyhsm --pyhsm-socket /tmp/pyhsm.sock
```

### Model 2 — Remote PyHSM (Recommended for Production)

The PyHSM daemon runs on a separate dedicated server in the same region's private subnet. Communication uses TLS 1.3 + mutual TLS (mTLS). Raw key material is **never accessible from the VectorLedger host** — the master key exists only inside PyHSM.

```bash
vledger init \
  --key-source remote-pyhsm \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --pyhsm-client-cert /etc/vledger/client.crt \
  --pyhsm-client-key /etc/vledger/client.key \
  --pyhsm-caller-id vledger
```

### Cloud HSM Backends

VectorLedger supports two additional hardware HSM backends via bridge sidecars:

- **AWS CloudHSM** — `AwsCloudHsmProvider`
- **Azure Dedicated HSM** (Thales Luna Network HSM 7) — `AzureHsmProvider`

Both are exposed through the `Pkcs11Provider` trait.

### Startup Behavior

VectorLedger **fails closed** if the configured HSM is unreachable at startup. The server will not start without key access. This is intentional — it prevents a degraded startup with no encryption.

---

## 10. Secrets Management Backends

`vledger-secrets` crate provides the `MasterKeyProvider` async trait with six backends:

| Backend | Tag | Security Level | Use Case |
|---|---|---|---|
| `EnvVarProvider` | `env` | Low | Dev/CI — reads `VectorLedger_MASTER_KEY` env var |
| `FileProvider` | `file` | Low | Dev/CI only — server emits a loud warning at startup |
| `HashiCorpVaultProvider` | `vault` | High | Vault KV v2 via HTTPS; `VAULT_TOKEN` read at runtime |
| `AwsKmsProvider` | `aws_kms` | High | AWS KMS `GenerateDataKey`; ciphertext blob cached with HMAC-SHA256 integrity |
| `PyHsm` | `py_hsm` | Very High | Local Unix socket (Model 1) |
| `RemotePyHsm` | `remote_py_hsm` | Very High | mTLS HTTPS to dedicated server (Model 2) — key never on VectorLedger host |

The `env` and `file` backends are **not recommended for production**. PCI-DSS Req 3.5 compliance check fails for these backends. The `file` backend triggers a startup warning visible in all log outputs.

The 32-byte master key is wrapped in `zeroize::Zeroizing` — cleared from memory when dropped.

---

## 11. Four-Eyes Approval Workflow

For accounts with `require_four_eyes = true`, every entry goes through mandatory dual-control:

1. **Submit:** A principal calls `post_entry`, which routes to `FourEyesQueue::submit(...)`. Returns an `ApprovalRecord` with a UUID `approval_id` and sets entry status to `PendingApproval`. The entry is **not posted** to the ledger.

2. **Approve:** A second, **different** principal calls `FourEyesQueue::approve(approval_id, approver_id, post_fn)`.
   - Self-approval returns `FourEyesError::SelfApproval` — structurally prevented.
   - `post_fn` (which is `LedgerStore::post_entry`) is called with the original entry bytes.
   - All state changes are fsynced before returning.

3. **Reject:** Any principal may call `FourEyesQueue::reject(approval_id, approver_id, reason)` — entry is NOT posted.

**Idempotency guard:** `approve()` checks `approved.jsonl` before calling `post_fn`, making crash recovery safe against double-posting.

**Persistence:** JSONL files at `vledger-data/foureyes/` (mode 0o600): `pending.jsonl`, `approved.jsonl`, `rejected.jsonl`.

**Audit events:** `FourEyesSubmitted`, `FourEyesApproved`, `FourEyesRejected` are written to the WORM audit log on every state change.

**PCI-DSS mapping:** Four-eyes enforcement is evaluated as PCI-DSS v4 Req 7.1 (dual-control) in the compliance report.

---

## 12. Audit Trail

### WORM Audit Log

The audit log (`audit/audit.log`) is written via `O_APPEND` — no seek or truncate is possible at the filesystem level. Each event is:

1. Serialized to a JSON line
2. BLAKE3-hashed to produce `content_hash`
3. Linked to the previous event via `chain_hash = BLAKE3(prev_chain_hash || content_hash)`
4. fsync'd before returning

The audit log has its own independent hash chain, separate from the ledger chain.

### Export

```bash
# JSON export for a date range
vledger audit-export \
  --format json \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --output audit-september.json

# CSV export
vledger audit-export --format csv --output audit.csv
```

Export range limits by tier: Free (30 days), Starter (90 days), Growth/Enterprise (unlimited).

### Cryptographic Audit Packages

`vledger audit-package` generates a three-tier cryptographic evidence package:

1. **Commitment package** (default): O(n) Merkle root pass → Ed25519-signed JSON. Fast at any scale.
2. **On-demand entry proof** (`vledger audit-proof --sequence N`): single `MerkleProof` JSON proving one entry belongs to the committed root.
3. **Full export** (`--include-entries`): all entries + per-entry Merkle proofs (for small ledgers ≤ ~10K entries).

**Independent verification** (no server or credentials needed):
```bash
vledger verify-audit-package --file commitment.json
```

Checks: root Ed25519 signature, content hashes, hash-chain linkage, Merkle inclusion proofs.

---

## 13. Compliance Engine

`ComplianceEngine::generate_report(standard, range)` runs checks against the **real filesystem state** — not pre-written documentation.

```bash
# SOC 2 Type II report
vledger compliance-report --standard soc2 --format markdown --output soc2-report.md

# PCI-DSS v4 report
vledger compliance-report --standard pci-dss --format json --output pci-report.json
```

### SOC 2 Type II Controls (8 controls)

| Control | Check Performed |
|---|---|
| CC6.1 | Verifies `catalog/VERSION` exists (TLS always enabled via rustls) |
| CC6.2 | Verifies `audit/audit.log` exists with byte count |
| CC6.3 | Verifies WAL dir exists (account close mechanism present) |
| CC6.6 | Verifies `pages/` dir exists (AES-256-GCM encryption at rest) |
| CC6.7 | Checks for `keys/server.crt`; WARN if self-signed only |
| CC7.2 | Calls `AuditLog::verify_chain()` and reports event count |
| CC8.1 | Verifies WAL dir exists and reports segment count |
| A1.1 | Checks `replication.json` exists; WARN if absent (single-node) |

### PCI-DSS v4 Controls (9 controls)

| Requirement | Check Performed |
|---|---|
| Req 2.2 | FAIL if `MASTER_KEY_PLACEHOLDER.txt` present |
| Req 3.4 | Verifies `pages/` dir exists (encryption at rest) |
| Req 3.5 | Parses `keys/key_source.json`; PASS for py_hsm/remote_py_hsm/vault/aws_kms; FAIL for env/file |
| Req 4.2 | Checks for CA-signed TLS certificate |
| Req 7.1 | Verifies `catalog/VERSION` (four-eyes enforcement active) |
| Req 10.2 | Audit log exists |
| Req 10.3 | Calls `AuditLog::verify_chain()` |
| Req 10.5 | WAL exists |
| Req 11.5 | `pages/` exists (hash chain maintained) |

> **Scope note:** VectorLedger generates technical evidence *supporting* a compliance audit. It does not by itself make an organization compliant. Organizational compliance requires additional controls, policies, and independent auditor assessment.

---

## 14. Authentication and Session Security

### Password Hashing

Passwords are hashed with **Argon2id** at 64 MiB memory / 3 iterations / 4 lanes — above the OWASP recommended minimum. Lazy rehash upgrades passwords to the current parameters on login.

### Brute-Force Lockout

- 5 failed attempts trigger a 5-minute account lockout
- Exponential backoff delay: 200ms–3s per failed attempt
- Lockout events recorded in the WORM audit log

### Session Tokens

Session tokens are generated as:
```
BLAKE3(server_secret || username || role || 32-byte OsRng nonce)
```

- No sequential or timestamp-based tokens — each token is cryptographically unpredictable
- Session store is bounded at 4,096 entries
- 5-minute idle timeout (server connections)
- Authentication must complete within 30 seconds of TCP connection

### Auth Bypass

`--features dev-no-auth` is a compile-time feature gate. The auth bypass variant does not exist in the release binary type system. A release binary cannot disable authentication regardless of configuration.

---

## 15. Transport Security

### Native Protocol (Port 5433)

TLS 1.3 via `rustls` + `aws-lc-rs`. Mandatory — no plain-text fallback. At `vledger init`, a self-signed certificate is generated via `rcgen`. For production:

```bash
# Place CA-signed cert/key, then start with:
vledger start --tls-cert-path /etc/vledger/server.crt \
              --tls-key-path /etc/vledger/server.key
```

Self-signed certificates are accepted for loopback connections only. Non-loopback clients must pass `--ca-cert <PATH>`.

### PostgreSQL Wire Protocol (Port 5432, Starter+)

SSL negotiation → mandatory TLS 1.3 upgrade. Plain-text connections are rejected. Authentication is cleartext password **inside** TLS, verified against Argon2id hashes in the `UserStore`.

### Replication (Port 5434, Growth+)

Three independent security layers:

1. **TLS 1.3** on the replication channel
2. **Optional mTLS** — primary can require a client certificate from replica
3. **BLAKE3-keyed HMAC challenge-response** before any WAL data is exchanged:
   ```
   Primary → Replica: AuthChallenge { nonce: "<64 hex>" }
   Replica → Primary: AuthResponse  { mac: "<64 hex>" }  -- BLAKE3-keyed(secret, nonce_bytes)
   Primary → Replica: AuthResult    { ok: true | false }
   ```
   Shared secret: 32-byte file at `vledger-data/replication_secret.hex` (mode 0o600).

Every received WAL record is BLAKE3-verified before being applied on the replica.

### MCP Server (Port 3000)

The MCP server **does not implement TLS**. It must be bound to `127.0.0.1` (the default) or placed behind a TLS-terminating reverse proxy when accessed over a network. All MCP tool calls go through the same RBAC enforcement as direct SQL — the MCP server does not bypass any access control.

### Per-IP Rate Limiting

Token bucket rate limiter on the server: burst = 10 requests, refill rate = 2 requests/second per IP. Prevents brute-force and denial-of-service from a single source.

---

## 16. RBAC and Authorization

Four roles:

| Role | Capabilities |
|---|---|
| `admin` | All operations including user management |
| `operator` | Read, write (post entries, create accounts), verify, Merkle root |
| `auditor` | Read, verify, Merkle root, compliance reports, audit export — no writes |
| `readonly` | Read-only SELECT queries only |

RBAC is enforced on the resolved **logical query plan** — not the raw SQL text string. This makes the authorization check immune to comment injection, whitespace manipulation, or other SQL text bypass techniques.

The `readonly` role cannot call `post_entry`, `execute_correction`, `MERKLE_ROOT()`, or `VERIFY_CHAIN()` via any path including MCP tools.

---

## 17. Threat Model

VectorLedger is designed to be **tamper-detectable even by internal privileged actors**.

### What VectorLedger Prevents

- **Data modification by any actor**: any change to a historical record breaks the BLAKE3 hash chain at that entry and every subsequent entry — detectable by `VERIFY_CHAIN()`.
- **Log scrubbing**: the audit log is O_APPEND-only with its own independent hash chain. Deletions or modifications break the chain immediately.
- **Transaction forgery**: WAL commits are Ed25519-signed; forgery requires the private signing key.
- **Duplicate entries**: idempotency key enforcement prevents double-posting.
- **Unauthorized high-value writes**: four-eyes workflow prevents single-actor posting to protected accounts.
- **SQL injection**: all three client SDKs validate account identifiers via allowlist before interpolation; RBAC enforced on logical plan, not raw SQL; MCP layer uses ISO-8601 timestamp validation (`validate_iso8601_timestamp`) and LIKE-pattern escaping (`escape_like`) for all user-supplied filter values; FTS5 query inputs have operator characters stripped before phrase-quoting (v1.5.5+).

### What a Privileged Attacker With WAL Directory Access Could Do

- Prevent server startup by writing a WAL record with a crafted `payload_len` — the server would detect this as a torn write and stop recovery (the OOM vector was fixed in v1.0.32).
- The chain break would be immediately detectable by `VERIFY_CHAIN()`.

A privileged attacker **cannot** silently modify historical data without leaving a detectable chain break — provided that `VERIFY_CHAIN()` verification checkpoints are independently recorded and protected (which the HSM architecture is designed to enforce).

### What VectorLedger Does Not Prevent

- An attacker who compromises both the database and all independently stored Merkle checkpoints
- Organizational process failures outside the scope of the ledger engine
- Physical access to the machine running a Model 1 (local) HSM

### MCP and AI Agent Security

- All 15 MCP tools execute through the same `parse → plan → privilege-check → execute` pipeline as direct SQL. No tool bypasses RBAC.
- `AGENT_SYSTEM_PROMPT` is a static string constant with no secrets. It is safe to return in the `initialize` response.
- `--ask` sends only the user's question text and the static schema context to the configured LLM endpoint. No ledger data, credentials, or key material is transmitted to the LLM provider.
- The Agent Query counter (`mcp_queries.json`) is a commercial metering mechanism, not a security control. A user with write access to the data directory could reset it.

---

## 18. Secure Release Process

Every release is:

1. Built from a tagged commit on the `main` branch via GitHub Actions
2. Signed with cosign (keyless, GitHub Actions OIDC identity)
3. Accompanied by a `SHA256SUMS` file
4. Accompanied by a CycloneDX SBOM

**Verify a release:**
```bash
# Verify checksum
sha256sum -c vledger-v1.5.6-checksums.txt

# Verify cosign signature
cosign verify-blob \
  --certificate vledger-v1.5.6-checksums.txt.sig.pem \
  --signature   vledger-v1.5.6-checksums.txt.sig \
  --certificate-identity "https://github.com/pavondunbar/VectorLedger/.github/workflows/release.yml@refs/tags/v1.5.6" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vledger-v1.5.6-checksums.txt
```

---

## 19. Bug Fixes and Security Advisories

### execute_correction concurrency race (investigated in v1.5.6 — no exploitable bug found)

**Severity:** Informational — investigation confirmed the race window exists but the idempotency gate prevents any duplicate entries.

**Affected versions:** All versions. No patch required.

**Components:** `crates/vledger-mcp/src/tools.rs`, `crates/vledger-mcp/src/network.rs`, `crates/vledger-ledger/src/store.rs`, `crates/vledger-ledger/src/correction_concurrency_tests.rs` (new)

#### Background

Community review (October 2026) identified that `execute_correction` in both the embedded (`tools.rs`) and network (`network.rs`) MCP modes follows a three-phase pattern where each SQL call independently acquires and releases the `Arc<RwLock<LedgerStore>>` write lock:

```
Phase 1 — Pre-flight reads  (2 × read lock acquired, released)
Phase 2 — Reversal INSERT   (write lock acquired, released)
Phase 3 — Correction INSERT (write lock acquired, released)
```

There is no spanning lock across all four operations. Two concurrent callers can both observe "nothing applied yet" during Phase 1 and both proceed to Phase 2, creating a classic TOCTOU (Time-Of-Check Time-Of-Use) window.

#### Why no duplicate entries occur

The protection is `post_entry`'s idempotency key check, which executes atomically while holding `&mut LedgerStore` (the exclusive write lock). Because `execute_correction` always sets `idempotency_key = 'reversal-of-<orig_entry_id>'` and `idempotency_key = 'correction-of-<orig_entry_id>'`, the second concurrent caller's INSERT returns the first caller's sequence number silently — no new entry is written.

Critically, this protection depends entirely on the idempotency key being set. There is no `UNIQUE` constraint on `external_ref` or `idempotency_key` columns in SQLite — only non-unique indexes. If a future code path calls `post_entry` without setting the idempotency key, this backstop would not fire.

#### What the loser receives

Per design: the losing concurrent caller receives the winner's existing `(reversal_seq, correction_seq)` — not an error — so the agent has no reason to retry. This was explicitly verified in testing.

#### Concurrency tests added (v1.5.6)

Five new tests in `crates/vledger-ledger/src/correction_concurrency_tests.rs` formally document and enforce the guarantee:

| Test | What it proves |
|---|---|
| `concurrent_correction_idempotency` | 20 tasks from a Tokio barrier → exactly 3 entries, never duplicates |
| `correction_loser_receives_winner_result_not_error` | Loser gets winner's sequences, not an error |
| `partial_correction_recovery_only_missing_half_written` | Crash between phases 2 and 3 → retry posts only the missing correction |
| `correction_does_not_disturb_unrelated_entries` | Append-only: `content_hash` and `chain_hash` of unrelated entries are not mutated |
| `high_concurrency_correction_stress_50_tasks` | 50 concurrent tasks → 3 entries, all 50 return same result, chain intact |

All 523 tests pass (518 pre-existing + 5 new).

#### Recommendations

- Do not remove the `idempotency_key` assignment from `execute_correction` — it is a load-bearing correctness property, not cosmetic.
- Any future correction or reversal tool must set `idempotency_key` on both writes.
- Consider adding a `UNIQUE` constraint on `idempotency_key` in a future schema migration as defense-in-depth. This would promote the application-layer guarantee to a database-layer guarantee.

---

### MCP SQL injection via unescaped date strings and LIKE wildcards (fixed in v1.5.5)

**Severity:** Medium — filter bypass; no data destruction or schema modification possible.

**Affected versions:** All versions through v1.5.4.

**Components:** `crates/vledger-mcp/src/tools.rs`, `crates/vledger-mcp/src/network.rs`, `crates/vledger-ledger/src/entry_db.rs`

#### CVE-1: Unescaped date strings in `tool_summarize_period` and `tool_audit_report`

The MCP tools `summarize_period` and `audit_report` built SQL `WHERE` clauses by directly interpolating the user-supplied `from` and `to` date string parameters without any sanitization. The `domain` parameter was correctly escaped with `replace('\'', "''")`, but the date fields were not.

A caller supplying `from = "2026-01-01' OR '1'='1"` would produce SQL like:
```sql
SELECT COUNT(sequence) FROM ledger WHERE effective_at >= '2026-01-01' OR '1'='1' AND ...
```
The injected `OR '1'='1'` predicate makes the condition always true, bypassing the intended date range and domain filters. The most significant practical consequence was cross-tenant data exposure in multi-domain deployments — financial summary counts and audit report entry sets could be made to span all domains rather than the requested one.

Destructive DDL (`DROP`, `DELETE`, `UPDATE`) was not achievable because the custom SQL planner enforces a statement-type whitelist and single-statement enforcement as a hard backstop.

**Fix:** A `validate_iso8601_timestamp()` function whitelists only the characters valid in ISO-8601 date/datetime values (`0-9`, `-`, `:`, `T`, `Z`, `+`). Inputs containing any other character are rejected with an error before any SQL string is constructed. Applied in both `tools.rs` (embedded/direct mode) and `network.rs` (network proxy mode).

#### CVE-2: LIKE wildcard injection in `tool_resolve_account` metadata search

The `resolve_account` tool searched ledger metadata via `WHERE metadata LIKE '%{value}%'`. The `value` was escaped for single-quotes (`replace('\'', "''")`) but the LIKE metacharacters `%` and `_` were not escaped, and no `ESCAPE` clause was present.

An attacker could pass `%` to match all entries, or construct patterns to widen the search beyond the intended account name lookup.

**Fix:** An `escape_like()` helper escapes `\`, `%`, and `_` from user input and the SQL clause now includes `ESCAPE '\'`.

#### CVE-3: FTS5 query operator injection in `search_metadata`

`search_metadata` in `entry_db.rs` wrapped user input in FTS5 double-quote phrase syntax (`"input"`) and escaped embedded double-quotes. However, the FTS5 operator characters `*` (prefix wildcard), `^` (boost), and `-` (negation) were not filtered. These characters have syntactic meaning inside an FTS5 phrase expression and could be used to manipulate which entries the search returned — for example, using `-word` negation to suppress expected results or `*` suffix to broaden matching beyond the intended scope.

The SQL statement itself was not injectable (the FTS5 query was passed as a bound `?1` parameter), but FTS5 query logic could be manipulated.

**Fix:** The FTS5 operator characters `*`, `^`, and `-` are now filtered from the user input before phrase-quoting. All other characters are preserved; multi-word phrases like `"Elizabeth Cadet"` continue to work correctly.

---

### Feature gating for paid tiers fixed (v1.5.0)

`require_feature()` was only checking the explicit `features` list in `license.json`, not the tier's default features. Licenses issued for paid tiers were incorrectly blocked from features that their tier includes by default. Fixed by checking both the explicit list and tier default features. No security impact — this was an over-blocking bug, not an under-blocking one.

### Agent Query metering and AgenticAI gate (v1.4.8–v1.5.0)

The MCP server and `vledger sql --ask` are now gated behind `Feature::AgenticAi`, available on Starter, Growth, and Enterprise tiers. Monthly limits enforced: Starter 10, Growth 100, Enterprise unlimited.

Security note: the counter file is a commercial metering mechanism, not a security control.

### `resolve_account` identity enforcement (v1.4.4)

Without this tool, an agent could assign arbitrary Suspense accounts to named individuals — producing entries that were cryptographically correct but semantically wrong. `resolve_account` enforces a mandatory identity gate: `NOT_FOUND` or `MULTIPLE_FOUND` results halt the operation. All lookups are subject to the caller's RBAC session.

### `propose_correction` / `execute_correction` write safety (v1.4.5)

Both tools post new reversal and correction entries through the normal `post_entry` pipeline, subject to the same RBAC and all 16 financial invariants. Neither tool can modify or delete existing entries.

### Merkle root display truncation (v1.0.39)

The inline Merkle root at three display sites was truncated to 32 hex characters (16 bytes) due to `&root_hex[..root_hex.len().min(32)]`. Display-only bug — no data integrity issue. All three sites now show the full 64-character BLAKE3 hash.

### pgwire `--with-proofs` silently ignored (v1.0.35)

`execute_query` in `crates/vledger-pgwire/src/server.rs` declared `_attach_proofs` (underscore prefix) and always called `Executor::new()` regardless of the flag. Consequence: (1) all SELECT queries via pgwire acquired the write lock unnecessarily, blocking concurrent reads; (2) Merkle root was never computed or sent to pgwire clients. Fixed by routing read plans through `ReadExecutor` on a read lock and emitting the Merkle root as a pgwire `NoticeResponse`. This was a correctness bug — no integrity guarantee was weakened. The native JSON protocol (port 5433) was unaffected.

---

## 20. Known Limitations

The following are **by design** and are **not** security vulnerabilities:

- **`WalSyncMode::NoSync`** provides no durability guarantee and must never be used in production. As of v1.0.32, `NoSync` does not exist in the type system of a release build — it is gated behind `--features dev-no-sync` at compile time.

- **Self-signed TLS certificates** are accepted for loopback connections only. Non-loopback connections require a CA-signed certificate passed via `--ca-cert`.

- **The `file` key source** stores the master key on disk in hex. Documented as development-only; the server emits a loud warning at every startup.

- **The MCP server does not implement TLS.** Bind to `127.0.0.1` (the default) or use a TLS-terminating reverse proxy for any non-loopback access.

- **The Agent Query counter** (`mcp_queries.json`) is a commercial metering mechanism, not a security boundary. A user with write access to the data directory can reset it.

- **`resolve_account`** enforces semantic correctness (right account → right person) but cannot substitute for organizational authorization policies outside the ledger engine.

- **Compliance reports** generate technical evidence supporting an audit. They do not by themselves make an organization compliant.

---

## 21. Fuzz-Found Vulnerabilities (Fixed)

The following vulnerabilities were discovered by VectorLedger's fuzz test suite and fixed before any public exposure. 12 fuzz targets are maintained, run continuously against the codebase.

### WAL reader unbounded allocation — OOM (fixed in v1.0.32)

**Severity:** An attacker with write access to the WAL directory could prevent the server from starting.

The WAL segment reader in `crates/vledger-wal/src/reader.rs` allocated a buffer of `payload_len` bytes before attempting any read. A WAL record header with `payload_len = 0xFFFFFFFF` (4 GiB) triggered a 4 GiB allocation attempt, crashing the process. The same issue existed for `ct_len` in the encrypted record path.

**Fix:** `MAX_RECORD_PAYLOAD = 64 MiB` (matching `DEFAULT_SEGMENT_SIZE`) is checked against both fields before any allocation. Records claiming a larger payload are treated as torn writes and stop recovery cleanly.

Found by `fuzz_wal_recovery` with input `RLWE\xff\xff...\xff`.

### SQL planner index-out-of-bounds panic (fixed in v1.0.32)

**Severity:** Any authenticated client could crash the query planner with a single malformed `INSERT` statement.

The SQL query planner in `crates/vledger-sql/src/planner.rs` indexed directly into the `VALUES` list (`vals[idx]`) without verifying that the value count matched the column count. An `INSERT INTO ledger` or `INSERT INTO accounts` statement with fewer values than columns caused an index-out-of-bounds panic.

**Fix:** Replaced `vals[idx]` with `vals.get(idx)` returning `SqlError::MissingField` with a descriptive message.

Found by `fuzz_sql_parser`.

### Fuzz harness bincode allocation cap (fixed in v1.0.32)

**Severity:** Harness-only issue — not a vulnerability in production code.

The `fuzz_transaction` harness fed raw bytes directly to `bincode::serde::decode_from_slice` without an allocation limit. Fixed by adding `.with_limit::<{1 MiB}>()` to the decode config. Production code validates payload sizes at the WAL reader layer before reaching bincode.

Found by `fuzz_transaction`.
