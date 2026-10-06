# VectorLedger — Production Operations Runbook

**Version:** 1.5.1  
**Audience:** System administrators and on-call engineers responsible for deployed VectorLedger instances.

This is the operator bible for VectorLedger. Read it end-to-end before going to production.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Installation and Upgrade Procedures](#2-installation-and-upgrade-procedures)
3. [Starting and Stopping](#3-starting-and-stopping)
4. [Configuration Reference](#4-configuration-reference)
5. [CLI Command Reference](#5-cli-command-reference)
6. [Health Checks and Monitoring](#6-health-checks-and-monitoring)
7. [Backup and Restore](#7-backup-and-restore)
8. [Key Rotation](#8-key-rotation)
9. [Replication Setup](#9-replication-setup)
10. [HSM Integration](#10-hsm-integration)
11. [pgwire Setup](#11-pgwire-setup)
12. [MCP Server Setup](#12-mcp-server-setup)
13. [User Management](#13-user-management)
14. [License Management](#14-license-management)
15. [Compliance Rules and Reports](#15-compliance-rules-and-reports)
16. [Audit Report Generation and Log Management](#16-audit-report-generation-and-log-management)
17. [Self-Test](#17-self-test)
18. [Security Hardening Checklist](#18-security-hardening-checklist)
19. [Performance Tuning](#19-performance-tuning)
20. [Failure Modes and Recovery](#20-failure-modes-and-recovery)
21. [SQL Syntax Notes and Client Compatibility](#21-sql-syntax-notes-and-client-compatibility)
22. [Recovery Point and Time Objectives](#22-recovery-point-and-time-objectives)

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│  vledger process                                         │
│                                                          │
│  Port 5433 — Native TLS (JSON protocol)                  │
│  Port 5432 — PostgreSQL wire protocol (--pgwire)         │
│  Port 9090 — Prometheus metrics (--metrics-addr)         │
│  Port 5434 — WAL replication (if replication.json exists)│
│  Port 3000 — MCP server HTTP+SSE (vledger mcp)           │
└──────────────────┬───────────────────────────────────────┘
                   │
   ┌───────────────┴────────────────────┐
   │  vledger-data/                     │
   │  ├── wal/          WAL segments    │
   │  ├── pages/        Encrypted pages │
   │  ├── indexes/      SQLite indexes  │
   │  ├── catalog/      Users, metadata │
   │  ├── audit/        WORM log        │
   │  ├── keys/         Key config      │
   │  ├── foureyes/     Approval queue  │
   │  └── snapshots/    Backups         │
   └────────────────────────────────────┘
                   │
   ┌───────────────┴────────────────┐
   │  PyHSM daemon (port 8443 mTLS) │
   │  Master key sealed inside      │
   └────────────────────────────────┘
```

### Key Invariants

- Only one `vledger` process may open a data directory at a time (enforced by an advisory file lock).
- PyHSM must be reachable before `vledger start` — startup **fails closed** if PyHSM is down. This is intentional.
- The WORM audit log is append-only and fsync'd on every write.
- TLS 1.3 is mandatory on all connections (native and pgwire). Plain-text is rejected.

### Data Flow

```
Client → TLS 1.3 → vledger-server → SQL parse/plan/execute → vledger-ledger
                                                              ↓
                                                         vledger-wal (fsync)
                                                              ↓
                                                         vledger-pages (AES-256-GCM)
                                                              ↓
                                                         vledger-audit (WORM)
```

---

## 2. Installation and Upgrade Procedures

### Install via Script

**macOS / Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex
```

### Install from Release Binary

Download from the [GitHub Releases page](https://github.com/pavondunbar/VectorLedger/releases/tag/v1.5.1):

| Platform | Binary Archive |
|---|---|
| Linux x86_64 | `vledger-v1.5.1-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `vledger-v1.5.1-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `vledger-v1.5.1-x86_64-apple-darwin.tar.gz` |
| macOS ARM64 | `vledger-v1.5.1-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `vledger-v1.5.1-x86_64-pc-windows-msvc.zip` |

**Verify before deploying:**
```bash
sha256sum -c vledger-v1.5.1-checksums.txt

cosign verify-blob \
  --certificate vledger-v1.5.1-checksums.txt.sig.pem \
  --signature   vledger-v1.5.1-checksums.txt.sig \
  --certificate-identity "https://github.com/pavondunbar/VectorLedger/.github/workflows/release.yml@refs/tags/v1.5.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vledger-v1.5.1-checksums.txt
```

### Build from Source

Prerequisites: Rust toolchain 1.80+

```bash
git clone https://github.com/pavondunbar/VectorLedger.git
cd VectorLedger
cargo build --release
# Binary: target/release/vledger
```

### Upgrade Procedure

1. **Stop the server gracefully:**
   ```bash
   kill -TERM $(cat /var/run/vledger.pid)
   timeout 60 tail --pid=$(cat /var/run/vledger.pid) -f /dev/null
   ```

2. **Take a backup before upgrading:**
   ```bash
   ./vledger backup --data-dir /var/lib/vledger/data \
     --output /var/lib/vledger/backups/pre-upgrade-$(date +%Y%m%d).tar
   ```

3. **Replace the binary:**
   ```bash
   cp target/release/vledger /opt/vledger/bin/vledger
   ```

4. **Run migrations if needed** (check release notes):
   ```bash
   # Only required when upgrading from pre-SQLite-index versions
   vledger migrate-to-sqlite --data-dir /var/lib/vledger/data
   ```

5. **Start the server and verify:**
   ```bash
   vledger start --data-dir /var/lib/vledger/data --pgwire &
   vledger sql --username admin --query "SELECT VERIFY_CHAIN()"
   ```

---

## 3. Starting and Stopping

### Recommended Production Start Command

```bash
nohup /opt/vledger/bin/vledger start \
  --data-dir /var/lib/vledger/data \
  --bind 0.0.0.0:5433 \
  --pgwire \
  --wal-sync-mode group_commit \
  --group-commit-delay-ms 2 \
  --max-connections 200 \
  --query-timeout-ms 30000 \
  --metrics-addr 0.0.0.0:9090 \
  >> /var/log/vledger/server.log 2>&1 &

echo $! > /var/run/vledger.pid
```

> ⚠ **Network binding security notice:** Binding to `0.0.0.0` is required in many deployment architectures (behind a load balancer, inside a VPC) but must be paired with firewall rules.
>
> **Never expose ports 5432, 5433, 5434, or 9090 directly to the public Internet.**
> See [Security Hardening Checklist](#18-security-hardening-checklist) for required firewall rules.

> **Note on `--with-proofs`:** The `MERKLE_ROOT(from_seq, to_seq)` SQL function is available at all times without any server flag. The `--with-proofs` flag is a separate, optional feature that causes every SELECT to automatically append a Merkle proof `NOTICE`. Add it only if you want automatic per-query proofs on every SELECT result.

### Graceful Stop

```bash
kill -TERM $(cat /var/run/vledger.pid)

# Wait for clean shutdown (up to 60 seconds)
timeout 60 tail --pid=$(cat /var/run/vledger.pid) -f /dev/null
echo "Server stopped"
```

### Immediate Stop (data loss risk)

```bash
# Only use if graceful stop is stuck
kill -KILL $(cat /var/run/vledger.pid)
```

> ⚠ SIGKILL bypasses graceful shutdown, leaving WAL records not yet fsynced. WAL recovery will replay on next start, but transactions in the group-commit buffer may be lost. Never use SIGKILL in production unless the process is hung.

### Verify Server is Running

```bash
vledger status --data-dir /var/lib/vledger/data
```

---

## 4. Configuration Reference

### Directory Layout (after `vledger init`)

| Path | Contents |
|---|---|
| `vledger-data/wal/` | WAL segment files (64 MiB each, default) |
| `vledger-data/pages/` | AES-256-GCM encrypted database pages |
| `vledger-data/indexes/` | SQLite secondary indexes for sequence-range scans |
| `vledger-data/catalog/` | User accounts, metadata, VERSION file |
| `vledger-data/audit/` | WORM audit log (`audit.log`) |
| `vledger-data/keys/` | Key source config (`key_source.json`), TLS cert/key |
| `vledger-data/foureyes/` | Four-eyes approval queue (JSONL files) |
| `vledger-data/snapshots/` | Backup archives |

### `keys/key_source.json`

Metadata-only file — never contains the key itself.

**Environment variable backend (dev/CI only):**
```json
{ "backend": "env" }
```
Reads key from `VectorLedger_MASTER_KEY` environment variable.

**File backend (dev/CI only — server warns loudly at startup):**
```json
{ "backend": "file", "path": "./vledger-data/keys/master_key.hex" }
```

**HashiCorp Vault KV v2:**
```json
{
  "backend": "vault",
  "addr": "https://vault.internal.example.com:8200",
  "mount": "secret",
  "path": "vledger/master_key"
}
```
Reads `VAULT_TOKEN` from environment at runtime.

**AWS KMS:**
```json
{
  "backend": "aws_kms",
  "key_id": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123",
  "region": "us-east-1"
}
```

**PyHSM Model 1 (local Unix socket):**
```json
{
  "backend": "py_hsm",
  "socket_path": "/tmp/pyhsm.sock",
  "caller_id": "vledger",
  "timeout_ms": 5000,
  "max_retries": 3
}
```

**PyHSM Model 2 (remote mTLS — recommended for production):**
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

### `replication.json`

Place in the data directory to activate replication.

**Primary:**
```json
{
  "role": "primary",
  "replication_addr": "0.0.0.0:5434",
  "ack_timeout_ms": 5000,
  "heartbeat_interval_ms": 1000,
  "send_buffer_bytes": 67108864,
  "secret_path": null,
  "tls": {
    "enabled": true,
    "server_cert": "/etc/vledger/replication.crt",
    "server_key": "/etc/vledger/replication.key",
    "server_hostname": "vledger-primary",
    "ca_cert": null,
    "client_cert": null,
    "client_key": null
  }
}
```

**Replica:**
```json
{
  "role": "replica",
  "primary_addr": "10.0.1.10:5434",
  "reconnect_delay_ms": 500,
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary",
    "ca_cert": "/etc/vledger/replication-ca.pem"
  }
}
```

### `license.json`

```json
{
  "licensee": "acme-corp",
  "email": "ops@acme.com",
  "tier": "growth",
  "issued_at": "2026-08-06",
  "expires_at": "2027-08-06",
  "features": ["pgwire", "replication", "compliance_report", "audit_export_unlimited", "agentic_ai"],
  "signature": "<hex Ed25519 signature>"
}
```

Checked at startup and at UTC midnight daily via a background watcher. Downgrade/expiry takes effect at the next midnight tick without a restart.

### `catalog/retention_policy.json`

```json
{ "days": 0, "domain": null }
```

`0` = keep forever. Set a positive integer to enforce a retention period in days.

### `catalog/accounting_rules.json`

Array of rule versions:
```json
[
  { "version": "1.0", "description": "Initial rules", "effective_date": "2026-01-01" }
]
```

### Server Runtime Flags

| Flag | Default | Description |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:5433` | Native TLS bind address |
| `--pgwire` | off | Enable PostgreSQL wire protocol on port 5432 |
| `--with-proofs` | off | Attach BLAKE3 Merkle proof NOTICE to every SELECT |
| `--wal-sync-mode <MODE>` | `group_commit` | `per_record` \| `group_commit` |
| `--group-commit-delay-ms <MS>` | `2` | Flush interval for group_commit |
| `--query-timeout-ms <MS>` | `30000` | Max query execution time |
| `--metrics-addr <ADDR>` | `127.0.0.1:9090` | Prometheus metrics bind address |
| `--max-connections <N>` | `128` | Max concurrent native connections |
| `-d, --data-dir <PATH>` | `./vledger-data` | Data directory |
| `-l, --log-level <LEVEL>` | `info` | Log level |

---

## 5. CLI Command Reference

Global flags (apply to all subcommands):
- `-d, --data-dir <PATH>` — data directory (default: `./vledger-data`)
- `-l, --log-level <LEVEL>` — log level (default: `info`)

---

### `vledger init`

Initialize a new database. Creates subdirectories, generates Ed25519 signing keypair, writes `catalog/VERSION`, initializes key source.

```bash
vledger init --data-dir ./vledger-data --key-source file
```

| Flag | Default | Description |
|---|---|---|
| `--force` | — | Overwrite existing directory |
| `--key-source <SOURCE>` | `pyhsm` | `pyhsm` \| `env` \| `file` \| `vault` \| `aws_kms` \| `remote-pyhsm` |
| `--vault-addr <URL>` | `http://127.0.0.1:8200` | Vault server address |
| `--vault-mount <MOUNT>` | `secret` | Vault KV v2 mount |
| `--vault-path <PATH>` | `vledger/master_key` | Vault secret path |
| `--kms-key-id <ID>` | — | AWS KMS key ARN or alias |
| `--kms-region <REGION>` | `us-east-1` | AWS region |
| `--pyhsm-socket <PATH>` | — | PyHSM Unix socket (overrides `PYHSM_SOCKET_PATH`) |
| `--pyhsm-caller-id <ID>` | `vledger` | Caller ID for PyHSM audit log |
| `--pyhsm-endpoint <URL>` | — | Remote PyHSM HTTPS endpoint (selects `remote-pyhsm`) |
| `--pyhsm-ca-cert <PATH>` | — | CA cert PEM for remote PyHSM TLS |
| `--pyhsm-client-cert <PATH>` | — | mTLS client certificate PEM |
| `--pyhsm-client-key <PATH>` | — | mTLS client private key PEM |
| `--pyhsm-timeout-ms <MS>` | `5000` | Per-request timeout |
| `--pyhsm-max-retries <N>` | `3` | Max retries on transient errors |

---

### `vledger start`

Start the TLS 1.3 server. Also starts: daily license watcher, hourly background `VERIFY_CHAIN`, WAL replication shipper (if `replication.json` present).

```bash
vledger start \
  --data-dir /var/lib/vledger/data \
  --bind 0.0.0.0:5433 \
  --pgwire \
  --wal-sync-mode group_commit \
  --max-connections 200
```

| Flag | Default | Description |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:5433` | Bind address |
| `--pgwire` | off | Enable pgwire on port 5432 (Starter+) |
| `--with-proofs` | off | Attach Merkle proof NOTICE to every SELECT |
| `--wal-sync-mode <MODE>` | `group_commit` | `per_record` \| `group_commit` |
| `--group-commit-delay-ms <MS>` | `2` | Group commit flush interval |
| `--query-timeout-ms <MS>` | `30000` | Query timeout |
| `--metrics-addr <ADDR>` | `127.0.0.1:9090` | Prometheus metrics |
| `--max-connections <N>` | `128` | Max concurrent native connections |

---

### `vledger status`

Show database status, version, and license info.

```bash
vledger status --data-dir ./vledger-data
```

---

### `vledger verify`

Verify WAL and ledger chain integrity.

```bash
# Live chain check (database must not be running)
vledger verify --data-dir ./vledger-data

# Full isolated self-test
vledger verify --data-dir ./vledger-data --self-test

# Self-test with custom entry count
vledger verify --data-dir ./vledger-data --self-test --entries 1000000

# Keep self-test data for inspection
vledger verify --data-dir ./vledger-data --self-test --keep-data
```

| Flag | Default | Description |
|---|---|---|
| `--self-test` | off | Run full integrity self-test against a fresh isolated database |
| `--entries <N>` | `100000` | Number of entries for self-test (presets: 10000, 100000, 1000000) |
| `--keep-data` | off | Keep self-test database after completion |

---

### `vledger sql`

Run SQL — interactive REPL or single statement via a running server or direct.

```bash
# Interactive REPL (prompts for password)
vledger sql --username admin --server 127.0.0.1:5433

# Single query
vledger sql --username admin --query "SELECT VERIFY_CHAIN()"

# Natural-language query (AgenticAI license required)
export OPENAI_API_KEY=sk-...
vledger sql --ask "show me all payments over \$10,000 last week"
```

| Flag | Default | Description |
|---|---|---|
| `-q, --query <SQL>` | — | SQL statement (omit for REPL) |
| `--ask <QUESTION>` | — | Natural-language query (requires `OPENAI_API_KEY`) |
| `-u, --username <USER>` | — | Falls back to `VLEDGER_CLI_USER` env var |
| `-p, --password <PASS>` | — | Falls back to `VLEDGER_CLI_PASSWORD` (interactive prompt preferred) |
| `--server <HOST:PORT>` | `127.0.0.1:5433` | Running server address |
| `--ca-cert <PATH>` | — | CA cert PEM for non-loopback TLS verification |

Natural-language query environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — | Required |
| `OPENAI_MODEL` | `gpt-4o` | LLM model |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Override for Ollama, Groq, etc. |

---

### `vledger self-test`

Run Phase 2 self-test suite (deterministic recovery tests: power_loss_mid_commit, segment_boundary_crash, checkpoint_deleted/corrupted, concurrent_open_refused, multi_entry_batch_spanning_segment).

```bash
vledger self-test --data-dir ./vledger-data
```

---

### `vledger self-test-phase3`

Run Phase 3 production-hardening self-test suite.

```bash
vledger self-test-phase3 --data-dir ./vledger-data
```

---

### `vledger mcp`

Start the MCP server (AgenticAI license feature). Auto-detects a running `vledger start` on port 5433 and switches to network mode.

```bash
# Embedded (auto-detects vledger start)
vledger mcp --bind 127.0.0.1:3000

# Explicit network mode
vledger mcp \
  --bind 127.0.0.1:3000 \
  --server 127.0.0.1:5433 \
  --username admin
```

| Flag | Default | Description |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:3000` | MCP server bind address |
| `--server <HOST:PORT>` | — | Proxy to a running `vledger start` instance |
| `--ca-cert <PATH>` | — | CA cert for non-loopback TLS |
| `-u, --username <USER>` | — | Falls back to `VLEDGER_CLI_USER` |
| `-p, --password <PASS>` | — | Falls back to `VLEDGER_CLI_PASSWORD` |

---

### `vledger backup`

Create an AES-256-GCM encrypted point-in-time backup. Produces a `.tar` archive and a `.tar.key` sidecar — **keep both together**.

```bash
vledger backup \
  --data-dir /var/lib/vledger/data \
  --output /var/lib/vledger/backups/vledger-backup-$(date +%Y%m%d).tar
```

| Flag | Default | Description |
|---|---|---|
| `--output <PATH>` | `./vledger-backup-<timestamp>.tar` | Output archive path |

---

### `vledger restore`

Restore a backup snapshot. Decrypts every file, verifies BLAKE3 hashes against the manifest.

```bash
vledger restore \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar \
  --target /var/lib/vledger/data-restored \
  --force
```

| Flag | Default | Description |
|---|---|---|
| `--from <PATH>` | — | **Required.** Backup archive path |
| `--target <PATH>` | — | Target directory for restore |
| `--force` | off | Overwrite existing target directory |

**Always verify the restored database before making it live:**
```bash
vledger verify --data-dir /var/lib/vledger/data-restored
```

---

### `vledger backup-verify`

Verify a backup archive without restoring (manifest and hash check).

```bash
vledger backup-verify \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar
```

| Flag | Default | Description |
|---|---|---|
| `--from <PATH>` | — | **Required.** Backup archive path |
| `--decrypt <bool>` | `true` | Decrypt and verify content hashes |

---

### `vledger rotate-keys`

Rotate all HSM key slots (Enterprise tier — HSM license feature required). Non-destructive: existing ciphertext remains decryptable. Records audit events.

```bash
# Model 1 — local PyHSM
vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --caller-id ops-team

# Model 2 — remote PyHSM
vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --pyhsm-client-cert /etc/vledger/client.crt \
  --pyhsm-client-key /etc/vledger/client.key \
  --caller-id ops-team
```

| Flag | Default | Description |
|---|---|---|
| `--hsm-socket <PATH>` | — | Local PyHSM socket path |
| `--caller-id <ID>` | `vledger-admin` | Audit log identifier |
| `--pyhsm-endpoint <URL>` | — | Remote PyHSM HTTPS endpoint |
| `--pyhsm-ca-cert <PATH>` | — | CA cert PEM |
| `--pyhsm-client-cert <PATH>` | — | mTLS client cert |
| `--pyhsm-client-key <PATH>` | — | mTLS client key |
| `--pyhsm-timeout-ms <MS>` | `5000` | Per-request timeout |
| `--pyhsm-max-retries <N>` | `3` | Max retries |

---

### `vledger audit-export`

Export the WORM audit log to JSON or CSV.

```bash
vledger audit-export \
  --data-dir /var/lib/vledger/data \
  --format json \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --output /tmp/audit-september-2026.json
```

| Flag | Default | Description |
|---|---|---|
| `--format <json\|csv>` | `json` | Output format |
| `-o, --output <PATH>` | stdout | Output file |
| `--from <RFC3339>` | — | Start of date range |
| `--to <RFC3339>` | — | End of date range |

Export range limits: Free = 30 days, Starter = 90 days, Growth/Enterprise = unlimited.

---

### `vledger audit-package`

Generate a cryptographic audit evidence package. O(n) Merkle root pass over all entries → Ed25519-signed JSON commitment.

```bash
vledger audit-package \
  --data-dir /var/lib/vledger/data \
  --tenant "Acme Corp" \
  --description "Q3 2026 audit package" \
  --period-start 2026-07-01 \
  --period-end 2026-09-30 \
  --output /var/lib/vledger/audit/q3-2026-commitment.json
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output <PATH>` | `./vledger-audit-package-<timestamp>.json` | Output file |
| `--include-entries` | off | Embed all entries + per-entry Merkle proofs (small ledgers only) |
| `--tenant <NAME>` | — | Organization name for package metadata |
| `--description <TEXT>` | — | Human-readable description |
| `--period-start <DATE>` | — | Reporting period start (YYYY-MM-DD or RFC 3339) |
| `--period-end <DATE>` | — | Reporting period end |

---

### `vledger audit-proof`

Generate a single-entry Merkle inclusion proof against a commitment package.

```bash
vledger audit-proof \
  --data-dir /var/lib/vledger/data \
  --commitment /var/lib/vledger/audit/q3-2026-commitment.json \
  --sequence 786295 \
  --output entry-786295-proof.json
```

| Flag | Default | Description |
|---|---|---|
| `--commitment <PATH>` | — | **Required.** Commitment package JSON |
| `--sequence <N>` | — | **Required.** Entry sequence number |
| `--output <PATH>` | — | Output proof file |

---

### `vledger verify-audit-package`

Verify an audit package or entry proof. Checks root signature, content hashes, chain linkage, and Merkle inclusion proofs. No database access, server, or credentials required.

```bash
vledger verify-audit-package --file /var/lib/vledger/audit/q3-2026-commitment.json
vledger verify-audit-package --file entry-786295-proof.json
```

| Flag | Default | Description |
|---|---|---|
| `--file <PATH>` | — | **Required.** Audit package or proof JSON |

---

### `vledger compliance-report`

Generate a SOC 2 Type II or PCI-DSS v4 compliance evidence report.

```bash
# SOC 2 Markdown report
vledger compliance-report \
  --data-dir /var/lib/vledger/data \
  --standard soc2 \
  --format markdown \
  --output /tmp/soc2-report.md

# PCI-DSS JSON report
vledger compliance-report \
  --data-dir /var/lib/vledger/data \
  --standard pci-dss \
  --format json \
  --output /tmp/pci-report.json
```

| Flag | Default | Description |
|---|---|---|
| `--standard <soc2\|pci-dss>` | `soc2` | Compliance standard |
| `--format <json\|markdown>` | `markdown` | Output format |
| `-o, --output <PATH>` | stdout | Output file |

---

### `vledger user <action>`

Manage user accounts. When the server is stopped, operates directly on the data directory. When connected to a running server, use `--server`.

```bash
# Create user
vledger user create \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --role operator
# (password prompted interactively)

# Change password
vledger user set-password \
  --data-dir /var/lib/vledger/data \
  --username alice

# Disable account
vledger user set-enabled \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --enabled false

# Change role
vledger user set-role \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --role auditor

# List users
vledger user list --data-dir /var/lib/vledger/data

# Delete user
vledger user delete --data-dir /var/lib/vledger/data --username alice
```

Roles: `admin`, `operator`, `auditor`, `readonly`

All `user` subcommands accept `--ca-cert <PATH>` for non-loopback TLS when operating in network mode.

---

### `vledger license`

Show active license tier, features, and expiry date.

```bash
vledger license --data-dir /var/lib/vledger/data
```

---

### `vledger migrate-to-sqlite`

One-time migration to populate the SQLite entry index from WAL records. Crash-safe and resumable. Run only when upgrading from a version before the SQLite index was introduced.

```bash
vledger migrate-to-sqlite --data-dir /var/lib/vledger/data
```

Performance: ~45,000 entries/sec. 25 million records ≈ 75 minutes.

---

### `vledger seed`

Seed the database with randomly generated test journal entries.

```bash
vledger seed \
  --data-dir ./vledger-data \
  --entries 10000 \
  --accounts 20
```

| Flag | Default | Description |
|---|---|---|
| `--entries <N>` | `10000` | Number of entries to generate |
| `--accounts <N>` | `20` | Number of accounts |
| `--seed <SEED>` | — | Deterministic RNG seed |
| `--progress <N>` | — | Print progress every N entries |

---

### `vledger import`

Import journal entries from CSV or JSON. Crash-safe with checkpoint/resume.

```bash
vledger import \
  --data-dir ./vledger-data \
  --file transactions.csv \
  --format csv \
  --domain main \
  --default-currency USD \
  --create-accounts \
  --batch-size 1000 \
  --on-error collect \
  --manifest import-manifest.json
```

| Flag | Default | Description |
|---|---|---|
| `--file <PATH>` | — | **Required.** Input file |
| `--format <csv\|json>` | auto | Auto-detected from file extension |
| `--dry-run` | off | Validate only, no writes |
| `--map <SRC=TARGET>` | — | Column mapping (repeatable) |
| `--mapping-file <PATH>` | — | JSON mapping file |
| `--domain <D>` | `main` | Default domain |
| `--default-currency <C>` | `USD` | Default currency |
| `--id-column <COL>` | — | Column for idempotency key (BLAKE3 hash of row if omitted) |
| `--on-error <abort\|skip\|collect>` | `abort` | Error handling |
| `--batch-size <N>` | `1000` | Checkpoint every N rows |
| `--state-file <PATH>` | `import-state.json` | Checkpoint state file |
| `--resume` | off | Resume interrupted import |
| `--progress <N>` | `10000` | Print progress every N rows |
| `--manifest <PATH>` | `import-manifest.json` | Cryptographic import manifest output |
| `--create-accounts` | off | Auto-create missing accounts as Suspense type |
| `--metadata-columns <COLS>` | — | Comma-separated columns to pack into metadata JSON |
| `--wal-sync-mode <MODE>` | `group_commit` | WAL sync mode for import |

Target field mappings: `debit_account`, `credit_account`, `amount`, `description`, `currency`, `domain`, `effective_date`, `external_ref`, `idempotency_key`.

---

### `vledger reconcile`

Reconcile all accounts. Recomputes balances from ledger lines and compares against cached balances. Exits non-zero on discrepancy.

```bash
vledger reconcile --data-dir ./vledger-data --format text
```

| Flag | Default | Description |
|---|---|---|
| `--format <text\|json>` | `text` | Output format |
| `--output <PATH>` | stdout | Output file |

---

### `vledger settle`

Transition a journal entry through the settlement lifecycle.

```bash
vledger settle \
  --data-dir ./vledger-data \
  --entry-id 550e8400-e29b-41d4-a716-446655440000 \
  --status settled \
  --notes "ACH confirmed"
```

| Flag | Default | Description |
|---|---|---|
| `--entry-id <UUID>` | — | **Required.** Entry UUID |
| `--status <pending\|settled\|failed>` | — | **Required.** New status |
| `--notes <TEXT>` | — | Optional settlement notes |

---

### `vledger start-primary`

Start a WAL replication primary (Growth+ license). Reads `replication.json` from the data directory.

```bash
vledger start-primary \
  --data-dir /var/lib/vledger/data \
  --bind 0.0.0.0:5434
```

---

### `vledger start-replica`

Start a WAL replication replica (Growth+ license). Reads `replication.json` from the data directory.

```bash
vledger start-replica \
  --data-dir /var/lib/vledger/data \
  --primary 10.0.1.10:5434
```

---

### `vledger retention <action>`

Manage data retention policies.

```bash
# Show current policy
vledger retention show --data-dir ./vledger-data

# Set 365-day retention for the 'main' domain
vledger retention set --data-dir ./vledger-data --days 365 --domain main

# Set unlimited retention
vledger retention set --data-dir ./vledger-data --days 0

# Clear policy (revert to keep-forever)
vledger retention clear --data-dir ./vledger-data
```

---

### `vledger hold <action>`

Manage legal holds on accounts. Held accounts block all new entries, reversals, and settlement transitions.

```bash
# Place a legal hold
vledger hold place --data-dir ./vledger-data --account CASH

# Lift a legal hold
vledger hold lift --data-dir ./vledger-data --account CASH

# List all held accounts
vledger hold list --data-dir ./vledger-data
```

---

### `vledger rules <action>`

Manage accounting rule versions.

```bash
# Show current version
vledger rules show --data-dir ./vledger-data

# Set a new version
vledger rules set \
  --data-dir ./vledger-data \
  --version "2.0" \
  --description "Updated exposure limits" \
  --effective-date 2027-01-01

# View history
vledger rules history --data-dir ./vledger-data
```

---

## 6. Health Checks and Monitoring

### TCP Connectivity

```bash
nc -z 127.0.0.1 5433 && echo "port 5433 open" || echo "port 5433 CLOSED"
nc -z 127.0.0.1 5432 && echo "port 5432 open" || echo "port 5432 CLOSED"
```

### SQL Health Check

```bash
vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT sequence, status FROM ledger WHERE sequence = 1"
```

### Hash Chain Integrity

```bash
vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT VERIFY_CHAIN()"
```

Expected output: `status = OK`. Run after every restart and as a daily cron job.

### Merkle Root Spot-Check

```bash
vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT MERKLE_ROOT(1, 100000)"
```

Record the root alongside the sequence range and timestamp. Re-run at a future point — if the root changes for the same range, the ledger has been tampered with.

```bash
# Single entry
vledger sql --server 127.0.0.1:5433 --username admin \
  --query "SELECT MERKLE_ROOT(786295)"
```

### MCP Server Health

```bash
curl http://127.0.0.1:3000/health
# {"ok":true,"service":"vledger-mcp","version":"1.5.1","tools":15,...}
```

### Prometheus Metrics

```bash
curl -s http://127.0.0.1:9090/metrics | grep vledger
```

### Recommended Alert Thresholds

| Metric | Warning | Critical | Action |
|---|---|---|---|
| `VERIFY_CHAIN()` result | — | `status != OK` | Page on-call immediately — chain is broken |
| Server process not running | — | Process absent | Restart immediately |
| Disk usage on data dir | 70% | 85% | Expand volume or archive WAL segments |
| WAL segment count | > 100 | > 500 | Run `vledger backup` and consider WAL archiving |
| Audit log chain broken | — | Any break | Page on-call — potential tampering |
| Replication lag | > 10s | > 60s | Check replica connectivity and disk |
| License expiry | 30 days | 7 days | Contact pavon@vectorguardlabs.com |

### Recommended Cron Jobs

```cron
# Daily chain integrity check — 2 AM UTC
0 2 * * * /opt/vledger/bin/vledger sql --server 127.0.0.1:5433 \
  --username admin --query "SELECT VERIFY_CHAIN()" \
  >> /var/log/vledger/chain-check.log 2>&1

# Daily Merkle root snapshot — 2:05 AM UTC
5 2 * * * /opt/vledger/bin/vledger sql --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT MERKLE_ROOT(1, (SELECT MAX(sequence) FROM ledger))" \
  >> /var/log/vledger/merkle-root.log 2>&1

# Daily backup — 3 AM UTC
0 3 * * * /opt/vledger/scripts/daily-backup.sh >> /var/log/vledger/backup.log 2>&1

# Weekly audit package commitment — Sunday 4 AM UTC
0 4 * * 0 /opt/vledger/bin/vledger audit-package \
  --data-dir /var/lib/vledger/data \
  --tenant "Acme Corp" \
  --output /var/lib/vledger/audit/weekly-$(date +%Y%m%d).json \
  >> /var/log/vledger/audit-package.log 2>&1

# License expiry check — daily 8 AM UTC
0 8 * * * /opt/vledger/bin/vledger license \
  --data-dir /var/lib/vledger/data \
  >> /var/log/vledger/license-check.log 2>&1
```

### Daily Backup Script

Save as `/opt/vledger/scripts/daily-backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

DATA_DIR="/var/lib/vledger/data"
BACKUP_DIR="/var/lib/vledger/backups"
DATE=$(date +%Y%m%d-%H%M%S)
OUTPUT="$BACKUP_DIR/vledger-backup-$DATE.tar"

mkdir -p "$BACKUP_DIR"

/opt/vledger/bin/vledger backup \
  --data-dir "$DATA_DIR" \
  --output "$OUTPUT"

echo "Backup complete: $OUTPUT"

# Retain last 30 daily backups
find "$BACKUP_DIR" -name "vledger-backup-*.tar" -mtime +30 -delete
echo "Old backups pruned"
```

---

## 7. Backup and Restore

### Create a Backup

```bash
vledger backup \
  --data-dir /var/lib/vledger/data \
  --output /var/lib/vledger/backups/vledger-backup-$(date +%Y%m%d).tar
```

The backup creates:
- An AES-256-GCM encrypted `.tar` archive (per-backup key derived from master key via HKDF-SHA256)
- A BLAKE3 manifest hash for each archived file
- A `.tar.key` sidecar file alongside the archive

> ⚠ **Keep the `.tar` and `.tar.key` files together.** The archive cannot be decrypted without its sidecar. Private key material is excluded from backups — only the public signing key is archived.

The backup event is recorded in the WORM audit log.

### Verify a Backup (Without Restoring)

```bash
vledger backup-verify \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar
```

Verifies manifest and BLAKE3 content hashes without writing to disk.

### Restore a Backup

```bash
# 1. Stop the server
kill -TERM $(cat /var/run/vledger.pid)
sleep 10

# 2. Restore to a staging directory
vledger restore \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar \
  --target /var/lib/vledger/data-restored \
  --force

# 3. Verify integrity before going live
vledger verify --data-dir /var/lib/vledger/data-restored

# 4. Swap directories
mv /var/lib/vledger/data /var/lib/vledger/data-old
mv /var/lib/vledger/data-restored /var/lib/vledger/data

# 5. Restart
nohup vledger start --data-dir /var/lib/vledger/data --pgwire &
```

### Quarterly Restore Drill

A backup that has never been tested in a restore is not a verified backup. Perform a documented restore drill at least quarterly and after any material change to the backup or restore subsystem. Record:

- Date and time of drill
- Backup file used (name, date, size)
- Restore duration (wall clock time)
- Transaction/sequence count after restore
- `VERIFY_CHAIN()` result
- `vledger verify` result
- Operator who performed the drill
- Any issues encountered and how they were resolved

---

## 8. Key Rotation

Key rotation requires Enterprise tier (HSM license feature).

```bash
# Model 1 — local PyHSM
vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --caller-id ops-team

# Model 2 — remote PyHSM
vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --pyhsm-client-cert /etc/vledger/client.crt \
  --pyhsm-client-key /etc/vledger/client.key \
  --caller-id ops-team
```

Key rotation is **non-destructive**:
- Existing ciphertext remains decryptable with the archived key version
- New writes use the new key immediately after rotation
- Every rotation event is recorded in the WORM audit log as `KeyRotated` and `KeyRotationStarted`

---

## 9. Replication Setup

Replication requires Growth or Enterprise tier.

### Architecture

```
Primary: post_entry() → WAL commit → WalShipper::ship(record) → waits for ACK → returns Ok
Replica: WalReceiver receives records → writes to local WAL → sends ACK(lsn) → ReplicaApplier applies
```

Failover is **manual only** — there is no automatic primary election.

### Configure the Primary

Create `/var/lib/vledger/data/replication.json`:

```json
{
  "role": "primary",
  "replication_addr": "0.0.0.0:5434",
  "ack_timeout_ms": 5000,
  "heartbeat_interval_ms": 1000,
  "tls": {
    "enabled": true,
    "server_cert": "/etc/vledger/replication.crt",
    "server_key": "/etc/vledger/replication.key",
    "server_hostname": "vledger-primary"
  }
}
```

Then `vledger start` automatically activates the WAL shipper on port 5434.

### Configure the Replica

Create `/var/lib/vledger/data/replication.json` on the replica:

```json
{
  "role": "replica",
  "primary_addr": "10.0.1.10:5434",
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary",
    "ca_cert": "/etc/vledger/replication-ca.pem"
  }
}
```

### Copy the Replication Secret

```bash
# Run on primary after first start
scp /var/lib/vledger/data/replication_secret.hex \
  ubuntu@replica-host:/var/lib/vledger/data/replication_secret.hex

# Set permissions on replica
ssh ubuntu@replica-host \
  "chmod 600 /var/lib/vledger/data/replication_secret.hex"
```

### Start the Replica

```bash
vledger start-replica \
  --data-dir /var/lib/vledger/data \
  --primary 10.0.1.10:5434
```

### Check Replication Lag

Compare row counts on primary and replica:

```bash
# On primary
vledger sql --server 127.0.0.1:5433 --username admin \
  --query "SELECT COUNT(*) FROM ledger"

# On replica
vledger sql --server 10.0.1.11:5433 --username admin \
  --query "SELECT COUNT(*) FROM ledger"
```

### Manual Failover

1. Confirm primary is down and will not restart automatically
2. Stop `vledger start-replica` on the replica
3. Update `replication.json` on the replica (change `"role"` to `"primary"` or remove the file)
4. Start the replica as the new primary:
   ```bash
   vledger start --data-dir /var/lib/vledger/data --pgwire &
   ```
5. Update load balancer/DNS to point to the new primary
6. Notify clients of the failover

> ⚠ Ensure only one node is ever acting as primary at any time. Split-brain (two nodes acting as primary) will produce divergent chains that cannot be automatically reconciled.

---

## 10. HSM Integration

HSM is an Enterprise tier feature.

### Model 1 — Local PyHSM

PyHSM daemon on the same server; Unix socket transport.

```bash
# Initialize with local PyHSM
vledger init \
  --data-dir /var/lib/vledger/data \
  --key-source pyhsm \
  --pyhsm-socket /tmp/pyhsm.sock \
  --pyhsm-caller-id vledger

# Override socket path via environment variable
export PYHSM_SOCKET_PATH=/tmp/pyhsm.sock
```

### Model 2 — Remote PyHSM (Recommended for Production)

PyHSM on a separate dedicated server in the same region's private subnet. Raw key material never accessible from the VectorLedger host.

```bash
vledger init \
  --data-dir /var/lib/vledger/data \
  --key-source remote-pyhsm \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --pyhsm-client-cert /etc/vledger/client.crt \
  --pyhsm-client-key /etc/vledger/client.key \
  --pyhsm-caller-id vledger \
  --pyhsm-timeout-ms 5000 \
  --pyhsm-max-retries 3
```

### AWS CloudHSM

Configure as `aws_kms` backend with the CloudHSM bridge sidecar. See AWS CloudHSM documentation for bridge sidecar setup.

### Azure Dedicated HSM (Thales Luna Network HSM 7)

Configure via the Azure Dedicated HSM bridge sidecar. The bridge exposes the PKCS#11 interface to VectorLedger.

### Startup Behavior

VectorLedger **fails closed** if the configured HSM is unreachable at startup. Verify PyHSM is running before starting VectorLedger:

```bash
ls -la /tmp/pyhsm.sock      # Model 1
curl -k https://pyhsm.internal.example.com:8443/health  # Model 2
```

---

## 11. pgwire Setup

pgwire requires Starter or higher license.

### Enable pgwire

```bash
vledger start --data-dir ./vledger-data --pgwire
```

Binds on port 5432. TLS 1.3 is mandatory — plain-text connections are rejected.

### Connect with psql

```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

> **Use `host=127.0.0.1`** rather than `host=localhost`. On many systems `localhost` resolves to `::1` (IPv6), which may not route through SSH tunnels.

### Connect with DBeaver

1. Create a new **PostgreSQL** connection
2. Host: `127.0.0.1`, Port: `5432`, Database: `vledger`
3. Under **Driver Properties**: set `assumeMinServerVersion=9.0`
4. Click **Connect** (not **Test Connection** — see DBeaver note below)

**DBeaver connection note:** The **Test Connection** button shows `SQL Error [02000]` because DBeaver runs catalog introspection queries (`pg_catalog.*`) that VectorLedger doesn't implement. This is cosmetic — the TCP connection and authentication succeeded. Dismiss the error and open a SQL editor; queries work normally.

### Merkle Proofs via pgwire

Start with `--with-proofs --pgwire`:

```bash
vledger start --data-dir ./vledger-data --pgwire --with-proofs
```

Every SELECT result includes a PostgreSQL `NoticeResponse` with the BLAKE3 Merkle root:

```
NOTICE:  Merkle root: 5a8b9ce38e7e95d66070c74d889fbe1811d9a19e459889839fc2384780a366f4 (1 leaf, verified: true)
```

> **Note:** `MERKLE_ROOT()` SQL function is always available without `--with-proofs`. The flag only adds automatic per-query proof notices to every SELECT.

---

## 12. MCP Server Setup

MCP requires AgenticAI license feature (Starter, Growth, or Enterprise).

### Start the MCP Server

```bash
# With a running vledger start (auto-detects port 5433, recommended)
vledger mcp --bind 127.0.0.1:3000

# Standalone with explicit server target
vledger-mcp \
  --data-dir ./vledger-data \
  --bind 127.0.0.1:3000 \
  --server 127.0.0.1:5433 \
  --username admin
```

### MCP Client Configuration

Add to your AI assistant's MCP config:

```json
{
  "mcpServers": {
    "vledger": {
      "url": "http://127.0.0.1:3000/sse"
    }
  }
}
```

### Kiro Configuration

```json
{
  "mcpServers": {
    "vledger": {
      "url": "http://127.0.0.1:3000/sse"
    }
  }
}
```

### All 15 MCP Tools

| Tool | Category | Description |
|---|---|---|
| `query_ledger` | Query | Run any SELECT, BALANCE(), VERIFY_CHAIN(), MERKLE_ROOT() |
| `post_entry` | Write | Record a new double-entry journal entry |
| `get_balance` | Query | Current balance of any account |
| `list_accounts` | Query | All accounts with balances (optional domain/currency filter, default limit 500) |
| `query_ledger_lines` | Query | Individual debit/credit lines |
| `verify_chain` | Integrity | Verify the BLAKE3 hash chain |
| `merkle_root` | Integrity | BLAKE3 Merkle commitment over a sequence range |
| `explain_balance` | Reasoning | Why is an account at its current balance? |
| `reconcile_account` | Reasoning | Does stored balance match sum(posted lines)? |
| `find_policy_violations` | Reasoning | Large transactions, pending-too-long, missing refs, failures |
| `summarize_period` | Reasoning | Natural-language period summary with Merkle commitment |
| `audit_report` | Reasoning | Full cryptographic audit evidence report |
| `resolve_account` | Identity | Resolve name/code/UUID → authoritative account ID |
| `propose_correction` | Correction | Show reversal+correction plan (writes nothing) |
| `execute_correction` | Correction | Execute confirmed reversal + correction |

All tools execute through the same RBAC pipeline as direct SQL — no tool bypasses authorization.

### Agent Query Billing and Session Expiry

**One Agent Query** is counted per `initialize` JSON-RPC request (one conversation).

**Session idle timeout:** 30 minutes (`session_timeout_secs` in MCP config). After 30 minutes of inactivity, the next question starts a new Agent Query.

| Tier | Monthly Limit |
|---|---|
| Free | Disabled |
| Starter | 10 |
| Growth | 100 |
| Enterprise | Unlimited |

Counter stored in `<data_dir>/mcp_queries.json`. Resets automatically on the first day of each UTC month — no restart required.

### MCP Security Note

The MCP server does not implement TLS. Bind to `127.0.0.1` (default) or place behind a TLS-terminating reverse proxy for non-loopback access.

---

## 13. User Management

### Create Users

```bash
vledger user create \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --role operator
# Password prompted interactively
```

### Roles and Capabilities

| Role | Read | Write | Verify / Merkle | Compliance | User Management |
|---|---|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `operator` | ✓ | ✓ | ✓ | — | — |
| `auditor` | ✓ | — | ✓ | ✓ | — |
| `readonly` | ✓ | — | — | — | — |

### Common Operations

```bash
# Change password (revokes all active sessions for that user)
vledger user set-password --data-dir /var/lib/vledger/data --username alice

# Disable compromised account (revokes all active sessions immediately)
vledger user set-enabled --data-dir /var/lib/vledger/data \
  --username alice --enabled false

# Change role
vledger user set-role --data-dir /var/lib/vledger/data \
  --username alice --role auditor

# List all users
vledger user list --data-dir /var/lib/vledger/data

# Delete user
vledger user delete --data-dir /var/lib/vledger/data --username alice
```

### Initial Admin Credentials

After `vledger init`, an initial credential file is written at:
```
vledger-data/catalog/.admin_initial_credentials
```

**Delete this file after first login:**
```bash
rm /var/lib/vledger/data/catalog/.admin_initial_credentials
```

---

## 14. License Management

### Check Current License

```bash
vledger license --data-dir /var/lib/vledger/data
```

### Install or Renew a License

```bash
# Copy the license.json provided by VectorGuard Labs
cp /path/to/new-license.json /var/lib/vledger/data/license.json

# The daily license watcher picks it up at the next UTC midnight.
# To apply immediately, restart the server:
kill -TERM $(cat /var/run/vledger.pid)
nohup vledger start --data-dir /var/lib/vledger/data --pgwire &
```

### License Expiry Behavior

- Checked at startup and at UTC midnight daily via a background watcher
- Paid features are disabled at the next midnight tick on expiry — no restart required
- Free tier operates indefinitely with no license file

Contact **pavon@vectorguardlabs.com** at least 30 days before expiry.

### License Tiers

| Tier | Features | Price |
|---|---|---|
| **Free** | Core ledger, single node, 30-day audit export | Free |
| **Starter** | + PgWire, AgenticAI, 90-day audit export | $499/mo |
| **Growth** | + Replication, ComplianceReport, AuditExportUnlimited, AgenticAI | $2,499/mo |
| **Enterprise** | All features + HSM, MultiNode, AgenticAI | From $4,999/mo |

---

## 15. Compliance Rules and Reports

### Generate a Report

```bash
# SOC 2 Type II
vledger compliance-report \
  --data-dir /var/lib/vledger/data \
  --standard soc2 \
  --format markdown \
  --output soc2-$(date +%Y%m%d).md

# PCI-DSS v4
vledger compliance-report \
  --data-dir /var/lib/vledger/data \
  --standard pci-dss \
  --format json \
  --output pci-$(date +%Y%m%d).json
```

Reports check real filesystem state — not pre-written documentation. See [SECURITY.md](./SECURITY.md) for the full list of controls evaluated.

### Key Findings That Cause PCI-DSS FAIL

| Finding | Remediation |
|---|---|
| `MASTER_KEY_PLACEHOLDER.txt` present | Remove the placeholder file; configure a real key source |
| Key source is `env` or `file` | Migrate to `vault`, `aws_kms`, or PyHSM (Req 3.5) |
| No CA-signed TLS certificate | Replace self-signed cert with CA-signed cert |

### Accounting Rules Versioning

```bash
# View current version
vledger rules show --data-dir ./vledger-data

# Set a new version
vledger rules set \
  --data-dir ./vledger-data \
  --version "2.0" \
  --description "Updated exposure limits" \
  --effective-date 2027-01-01

# View history
vledger rules history --data-dir ./vledger-data
```

Rule versions provide an immutable audit trail of accounting policy changes.

---

## 16. Audit Report Generation and Log Management

### WORM Audit Log

Written to `audit/audit.log` via O_APPEND. Every event is BLAKE3-hashed into an independent chain and fsync'd before returning.

All security-relevant events recorded:

| Event | Trigger |
|---|---|
| `server_started` | Every `vledger start` |
| `auth_event` | Every login attempt (success and failure) |
| `query_executed` | Every SQL statement |
| `entry_posted` | Every committed journal entry |
| `account_created` | Every new account |
| `account_closed` | Every account closure |
| `key_rotated` | Every key rotation |
| `replication_event` | Replica connect/disconnect |
| `four_eyes_submitted` | Four-eyes entry submitted |
| `four_eyes_approved` | Four-eyes entry approved |
| `four_eyes_rejected` | Four-eyes entry rejected |
| `backup_created` | Every backup |
| `key_rotation_started` | Start of key rotation |

### Export the Audit Log

```bash
# JSON export for a date range
vledger audit-export \
  --data-dir /var/lib/vledger/data \
  --format json \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --output /tmp/audit-september-2026.json

# CSV export
vledger audit-export \
  --data-dir /var/lib/vledger/data \
  --format csv \
  --output /tmp/audit.csv
```

### Generate a Cryptographic Audit Package

```bash
vledger audit-package \
  --data-dir /var/lib/vledger/data \
  --tenant "Acme Corp" \
  --description "Q3 2026 audit package" \
  --period-start 2026-07-01 \
  --period-end 2026-09-30 \
  --output /var/lib/vledger/audit/q3-2026-commitment.json
```

### Generate an Entry-Level Proof

```bash
vledger audit-proof \
  --data-dir /var/lib/vledger/data \
  --commitment /var/lib/vledger/audit/q3-2026-commitment.json \
  --sequence 786295 \
  --output entry-786295-proof.json
```

### Verify a Package (No Server Required)

```bash
vledger verify-audit-package --file q3-2026-commitment.json
vledger verify-audit-package --file entry-786295-proof.json
```

An external auditor can verify a package without access to the database, server, or credentials.

---

## 17. Self-Test

Run all three phases before every production deployment.

### Phase 1 — Chain Integrity Self-Test

```bash
# Default (100,000 entries)
vledger verify --data-dir ./vledger-data --self-test

# Development-scale (10,000 entries)
vledger verify --data-dir ./vledger-data --self-test --entries 10000

# Enterprise-scale (1,000,000 entries)
vledger verify --data-dir ./vledger-data --self-test --entries 1000000
```

Creates a fresh isolated database, writes N random entries, verifies the full chain, and cleans up. Never touches production data.

### Phase 2 — Recovery Self-Test

```bash
vledger self-test --data-dir ./vledger-data
```

Runs deterministic recovery scenarios: power_loss_mid_commit, segment_boundary_crash, checkpoint_deleted, checkpoint_corrupted, concurrent_open_refused, multi_entry_batch_spanning_segment.

### Phase 3 — Production Hardening Self-Test

```bash
vledger self-test-phase3 --data-dir ./vledger-data
```

All three phases must pass before deploying a new build to production.

---

## 18. Security Hardening Checklist

Run through this entire checklist before going to production:

**File system permissions:**
- [ ] `chmod 700 /var/lib/vledger/data`
- [ ] `chmod 700 /var/lib/vledger/data/keys/`
- [ ] `chmod 700 /var/lib/vledger/data/catalog/`

**Key management:**
- [ ] Remove `keys/MASTER_KEY_PLACEHOLDER.txt` if present
- [ ] Switch from `file` or `env` key source to PyHSM, Vault, or KMS
- [ ] Confirm Model 2 (remote mTLS) PyHSM for production

**TLS:**
- [ ] Replace self-signed TLS certificate with a CA-signed one:
  ```bash
  cp /path/to/server.crt /var/lib/vledger/data/keys/server.crt
  cp /path/to/server.key /var/lib/vledger/data/keys/server.key
  ```

**User accounts:**
- [ ] Change the default admin password:
  ```bash
  vledger user set-password --data-dir /var/lib/vledger/data --username admin
  ```
- [ ] Delete the initial credential file:
  ```bash
  rm /var/lib/vledger/data/catalog/.admin_initial_credentials
  ```
- [ ] Create per-user accounts with minimum required roles (principle of least privilege)

**Firewall:**
- [ ] Port 5433 accessible only to application servers
- [ ] Port 5432 accessible only to application servers
- [ ] Port 5434 (replication) accessible only to replica hosts
- [ ] Port 9090 (metrics) accessible only to monitoring infrastructure
- [ ] Port 3000 (MCP) accessible only from 127.0.0.1 unless behind a TLS reverse proxy

**License:**
- [ ] Install a valid `license.json`
- [ ] `vledger license` shows no warnings
- [ ] License expiry is more than 30 days out

**Testing:**
- [ ] Run all three self-test phases and confirm they pass
- [ ] Run `SELECT VERIFY_CHAIN()` and confirm `status = OK`
- [ ] Schedule daily `VERIFY_CHAIN()` cron job
- [ ] Schedule daily backup cron job
- [ ] Perform a documented restore drill from a real backup before going live

**CI/CD verification:**
```bash
cargo test --package vledger-ledger --package vledger-sql \
           --package vledger-server --package vledger-audit \
           --package vledger-replication --package vledger-compliance \
           --package vledger-foureyes --package vledger-hsm \
           --package vledger-license --package vledger-crypto \
           --package vledger-wal
```
All tests must pass before deploying a new build to production.

---

## 19. Performance Tuning

### WAL Sync Mode

| Mode | Durability | TPS (relative) | When to Use |
|---|---|---|---|
| `group_commit` (default) | Up to 1 flush interval (default 2ms) | Highest | Most deployments |
| `per_record` | Zero data loss on crash | ~30–50% lower | Strict regulatory (e.g. PCI-DSS per_record requirement) |

```bash
# Group commit (default — 2ms flush interval)
--wal-sync-mode group_commit --group-commit-delay-ms 2

# Higher throughput (larger flush window)
--wal-sync-mode group_commit --group-commit-delay-ms 10

# Zero data loss
--wal-sync-mode per_record
```

> `WalSyncMode::NoSync` is not available in release binaries. It is gated behind `--features dev-no-sync` at compile time.

### Connection Limits

Default: 128 native + 64 pgwire. Increase for high-concurrency deployments:

```bash
--max-connections 500
```

### Query Timeout

Default: 30 seconds. Reduce for stricter SLAs:

```bash
--query-timeout-ms 10000
```

### Storage

| Storage Type | Use Case | Notes |
|---|---|---|
| Local NVMe (e.g. AWS i4i) | Highest TPS | Best fsync latency |
| EBS gp3 | Most deployments | Adequate, simpler ops |
| EBS io2 | per_record workloads | 10,000+ IOPS recommended |

Minimum recommended free disk space: 20% of data directory size at all times.

### Memory Allocator

VectorLedger uses jemalloc on Linux and macOS (`tikv-jemallocator`) to prevent ~7 GB RSS accumulation during large WAL recovery. No configuration needed — it is the default allocator in the release binary.

---

## 20. Failure Modes and Recovery

### Server Won't Start

| Error Message | Cause | Fix |
|---|---|---|
| `Data directory not found` | Wrong `--data-dir` path | Check path; run `vledger init` if new install |
| `cannot lock data directory` | Another `vledger` process is running | `pkill vledger`; check for stale PID files |
| `HSM daemon not reachable` | PyHSM is down | Start PyHSM; check socket/endpoint |
| `Feature 'pgwire' is not available` | License tier too low | Remove `--pgwire` or upgrade license |
| `Audit log cannot be opened` | Permissions or disk full | Check disk space; `chmod 700 data/audit/` |

### Hash Chain Broken (`VERIFY_CHAIN()` Returns Non-OK)

This is a critical incident. **Do not accept new writes until resolved.**

1. Stop the server: `kill -TERM $(cat /var/run/vledger.pid)`
2. Run: `vledger verify --data-dir /var/lib/vledger/data`
3. Note the sequence number where the chain breaks
4. Do not modify any files in the data directory
5. Contact `pavon@vectorguardlabs.com` immediately
6. Restore from the most recent verified backup

### WAL Corruption on Startup

**Symptom:** Log shows `torn_write_detected=true` during recovery.

1. The server automatically truncates at the corruption point and continues
2. Transactions after the last clean checkpoint are discarded
3. Run `VERIFY_CHAIN()` after startup to confirm integrity
4. The number of discarded transactions is logged as `discarded=N`
5. If `discarded > 0`, notify affected clients of the data loss

### Disk Full

1. Stop the server gracefully
2. Expand the volume or free space
3. Verify: `df -h /var/lib/vledger`
4. Restart the server

### PyHSM Unreachable at Startup

The server will refuse to start if PyHSM is configured but unreachable (fail-closed behavior).

1. Check PyHSM daemon: `systemctl status pyhsm` or `ls -la /tmp/pyhsm.sock`
2. Start PyHSM before restarting VectorLedger

### Replica Lagging or Disconnected

1. Check replica logs for `Replication error:` entries
2. Verify network connectivity from replica to primary port 5434
3. Verify `replication_secret.hex` matches on both nodes
4. If replica has diverged significantly, reseed from a backup:

```bash
# On primary
vledger backup --data-dir /var/lib/vledger/data --output /tmp/reseed.tar
scp /tmp/reseed.tar ubuntu@replica:/tmp/
scp /var/lib/vledger/data/replication_secret.hex \
  ubuntu@replica:/var/lib/vledger/data/

# On replica
pkill vledger
vledger restore --from /tmp/reseed.tar \
  --target /var/lib/vledger/data --force
# Restart vledger start-replica
```

### Forgotten Admin Password

1. Stop the server
2. Check for the initial credential file:
   ```bash
   cat /var/lib/vledger/data/catalog/.admin_initial_credentials
   ```
3. If the file is gone, reset the password in direct mode:
   ```bash
   vledger user set-password \
     --data-dir /var/lib/vledger/data \
     --username admin
   ```
   This works only when the server is stopped.

---

## 21. SQL Syntax Notes and Client Compatibility

### Quoting Rules

```sql
-- Numeric literal: no quotes
SELECT * FROM ledger WHERE sequence = 45289;

-- String literal: single quotes only (standard)
SELECT * FROM ledger WHERE description = 'Payment to Jeremy Tamura';

-- Non-standard: double-quoted string literals
-- Do NOT use this form — behavior may change without notice
SELECT * FROM ledger WHERE description = "Payment to Jeremy Tamura";  -- avoid
```

Use single quotes for string values at all times. Double-quote string acceptance is a parser quirk, not a supported feature, and will break if the query is run against a standard PostgreSQL instance.

### Unsupported Features

| Feature | Notes |
|---|---|
| `pg_catalog.*` | System catalog tables do not exist |
| `information_schema.*` | Not implemented |
| `\dt`, `\d`, `\l` psql meta-commands | Query `pg_catalog` internally — not supported |
| `CREATE TABLE`, `DROP TABLE` | Fixed schema, append-only |
| `UPDATE`, `DELETE` | Immutable by design |
| `CREATE INDEX`, `ALTER TABLE` | Not supported |

### Recommended SQL Clients

| Tool | Notes |
|---|---|
| `psql` | Use `sslmode=require` and `host=127.0.0.1` (force IPv4) |
| DBeaver Community | Set `assumeMinServerVersion=9.0`; dismiss Test Connection error |
| TablePlus | Works without special configuration |
| DataGrip | Works without special configuration |

### Connecting via psql

```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

---

## 22. Recovery Point and Time Objectives

| Scenario | RPO | RTO |
|---|---|---|
| Process crash (WAL replay) | 0 committed transactions | Minutes |
| Hard power loss (group_commit) | Up to 1 flush interval (default 2ms) | Minutes |
| Hard power loss (per_record) | 0 committed transactions | Minutes |
| Manual replica failover | 0 (replica is synchronous) | Minutes (manual steps) |
| Full restore from backup | Equals backup interval (typically 24h) | Depends on data size — measure quarterly |

**Minimum recommended practices:**
- Daily backups
- Quarterly restore drills (documented)
- Daily `VERIFY_CHAIN()` health checks
- Retain at least 30 days of backup archives

Measure your actual RTO by timing a restore drill on a representative dataset. Do not rely on estimates — time it.
