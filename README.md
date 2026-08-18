# VectorLedger

**A cryptographically verifiable database engine built for institutions that can't afford to trust their own database.**

VectorLedger is a purpose-built, append-only financial ledger written entirely in Rust. Every journal entry is linked by a tamper-evident BLAKE3 hash chain, every page of data is encrypted at rest with AES-256-GCM, and every query result can carry a cryptographic Merkle proof that the returned data has not been modified since it was written. Historical tampering is **cryptographically detectable** — any modification to a past record invalidates every hash in the chain from that point to the present, provided that verification checkpoints are independently protected (which the HSM architecture is specifically designed to enforce).

Built by [VectorGuard Labs](https://vectorguardlabs.com).

---

## Why VectorLedger?

Traditional relational databases treat audit trails as an afterthought: triggers that can be disabled, log tables that can be truncated, and backup files that can be silently replaced. For organizations operating under SOC 2, PCI-DSS, financial regulation, or internal zero-trust policies, this is not good enough.

VectorLedger makes tampering **cryptographically detectable**:

- A row written five years ago cannot be changed without invalidating every hash in the chain from that point to the present.
- Every SELECT response optionally carries a Merkle proof that any client can independently verify.
- The audit log is WORM-append-only — each event is hashed into the next, forming a second independent tamper-evident chain.
- The compliance engine generates machine-generated **technical evidence supporting SOC 2 Type II and PCI-DSS v4 control assessments** — not pre-written documentation. This evidence supports an auditor's work; it does not by itself make an organization compliant. Organizational compliance requires additional controls, policies, and independent auditor assessment beyond what any database engine can provide.

---

## Feature Overview

### Core Ledger Engine
- **Double-entry accounting** enforced at the type level — every journal entry must balance (debits == credits) before it is accepted
- **Append-only storage** — entries are never modified or deleted; corrections are made through reversal entries that are themselves chained entries
- **BLAKE3 hash chain** — every journal entry contains `H(sequence || prev_hash || content_hash)`, forming an unbroken chain from first entry to last
- **Idempotency keys** — duplicate submissions for the same financial event are detected and returned without double-posting
- **Exposure limits** and **non-negative balance enforcement** configurable per account
- **Multi-domain** support — each account and entry is tagged to a legal entity or business domain

### Cryptographic Security
- **AES-256-GCM** encryption at rest, with per-table keys derived via HKDF-SHA256 from a master key — compromising one table key does not expose others
- **Ed25519** commit signing on every WAL commit record — any external auditor can verify the transaction log without trusting the server
- **Argon2id** password hashing (64 MiB / 3 iterations / 4 lanes — above OWASP minimum)
- **Merkle proofs** on every SELECT response — clients can verify the exact set of rows returned matches the committed database state
- All sensitive key material uses `ZeroizeOnDrop` — private keys are erased from memory when dropped

### Write-Ahead Log (WAL)
- **Per-record mode** fsyncs every WAL record before returning `Ok` — zero data loss on crash
- **Group-commit mode** (default) flushes the WAL on a configurable background interval (default 2 ms); up to one flush window of writes may be lost on a hard crash
- **CRC-32** integrity check on every WAL record plus a **BLAKE3** hash on every row payload — two independent integrity layers
- **Crash recovery** replays committed transactions and discards uncommitted ones deterministically
- **Torn write detection** — recovery stops at the point of corruption rather than applying partial records

### Network Servers
- **Native TLS 1.3 server** (port 5433, JSON protocol) — every connection is authenticated before any SQL executes
- **PostgreSQL wire-protocol server** (port 5432) — compatible with `psql`, pgAdmin, DBeaver, Metabase, and any PostgreSQL client library
- Both listeners share the same `UserStore`, session state, and role enforcement
- **Mutual TLS (mTLS)** support on both listeners and the replication channel
- **Self-signed certificates** generated at startup and persisted across restarts; replaceable with CA-signed certificates

### Authentication and Authorization
- Four built-in roles: `admin`, `operator`, `auditor`, `read_only`
- Privilege enforcement is applied to the **resolved query plan**, not raw SQL text — immune to comment/whitespace bypass attacks
- **Brute-force protection**: 5-attempt lockout with 5-minute cooldown and exponential back-off delay (200 ms–3 s per attempt)
- Session tokens use `BLAKE3(server_secret || username || role || 32-byte OsRng nonce)` — no sequential or timestamp-based tokens
- Session store bounded at 4,096 entries with two-phase eviction; background purge every 60 seconds
- Auth bypass (`require_auth = false`) is **compile-gated** behind `--features dev-no-auth` — impossible to ship an unauthenticated production binary

### Connection Resource Controls
| Control | Native (5433) | PgWire (5432) |
|---|---|---|
| `max_connections` semaphore | 128 | 64 |
| Per-IP token bucket (burst=10, refill=2/s) | Yes | Yes |
| Auth timeout | 30 s | 30 s |
| Idle timeout | 5 min | 5 min |
| Request frame size limit | 4 MiB | 16 MiB |
| Graceful shutdown drain | Yes | Yes |

### Four-Eyes (Dual-Control) Workflow
- Accounts can be flagged `require_four_eyes = true`
- Entries to those accounts go into a durable approval queue instead of posting immediately
- A second, **different** principal must approve — self-approval is explicitly rejected at the server layer
- All approvals, rejections, and the original submission are recorded in the audit log

### WORM Audit Log
- Every security-relevant event is written as a signed JSON line to `audit/audit.log`
- Each event is BLAKE3-hashed into the next, forming a tamper-evident chain independent of the ledger chain
- Events include: `query_executed`, `entry_posted`, `auth_event`, `key_rotated`, `four_eyes_approved`, `backup_created`, and more
- Export to JSON or CSV with optional date-range filtering via `vledger audit-export`

### HSM Integration
- Pluggable `Pkcs11Provider` trait with three backends:
  - **SoftHSM** — PyHSM Unix socket daemon (development and CI)
  - **AWS CloudHSM** — via bridge sidecar
  - **Azure Dedicated HSM** — via bridge sidecar (Thales Luna Network HSM 7)
- Raw key material never leaves the HSM — all cryptographic operations run inside the device
- Key rotation via `vledger rotate-keys` — old key version is archived for decryption of existing data; new version used for all new writes
- **Two deployment models supported:**
  - **Model 1 — Local PyHSM** (same server): Unix domain socket transport, zero network overhead, ideal for development and single-server production
  - **Model 2 — Remote PyHSM** (same-region, separate server): TLS 1.3 + mutual TLS (mTLS) transport over a private subnet; the HSM runs on a dedicated server, PyHSM's private key material is never accessible from the VectorLedger host

### Secrets Management
- Master key can be sourced from:
  - Environment variable (`VectorLedger_MASTER_KEY`)
  - File on disk (development only)
  - **HashiCorp Vault KV v2** (`VAULT_TOKEN` read at runtime; TTL checked and logged at startup)
  - **AWS KMS** `GenerateDataKey` (ciphertext blob cached with HMAC-SHA256 integrity check)
  - **PyHSM — local** (Model 1): Unix socket, master key sealed inside local PyHSM daemon
  - **PyHSM — remote** (Model 2): mTLS, master key sealed inside remote PyHSM daemon on a separate server
- Configuration file (`key_source.json`) contains only metadata — the key itself never appears in config

### Replication

> **License requirement:** WAL replication requires a **Growth or Enterprise** license. Running `vledger start-primary` or `vledger start-replica` on a Free or Starter license returns a feature-not-entitled error.

Synchronous hot-standby WAL replication with three independent security layers:

1. **TLS 1.3** on the replication channel (self-signed by default; CA-signed recommended for production)
2. **Optional mTLS** — the primary can require a client certificate from each replica
3. **BLAKE3-keyed HMAC challenge-response** inside TLS before any WAL data is exchanged

Additional integrity guarantees:
- Replica verifies BLAKE3 hash of every received WAL record before applying it — a tampered record is rejected and the connection closed
- Exponential reconnect backoff (500 ms → 30 s) with faster escalation on auth failures (max 60 s)
- Replication secret generated from `OsRng`, stored at mode `0o600`
- **Divergence detection** via periodic `DivergenceCheckpoint` messages carrying a rolling BLAKE3 WAL chain hash — a mismatch means the replica must be re-seeded

#### Setting up replication

**Step 1 — On the primary node, start the WAL shipper**

```bash
# Option A — integrated mode (recommended):
# If replication.json is present with role=primary, vledger start
# automatically activates the WAL shipper alongside the SQL server.
vledger start --data-dir ./vledger-data

# Option B — standalone shipper only (no SQL server):
vledger start-primary --data-dir ./vledger-data

# Override the bind address:
vledger start-primary --data-dir ./vledger-data --bind 0.0.0.0:5434
```

In integrated mode (`vledger start`), every committed journal entry is shipped to connected replicas automatically — no separate process required. The shipper binds the address in `replication.json` alongside the SQL server.

On first run, if no `replication.json` exists in the data directory, a default config file is written and the server starts with it. Review and adjust the file before deploying to production.

The primary auto-generates a 32-byte HMAC secret at `vledger-data/replication_secret.hex` (mode `0o600`) on first run. This secret must be copied to every replica.

**Step 2 — Copy the secret to the replica node**

```bash
# From the primary, copy the secret securely to the replica
scp vledger-data/replication_secret.hex replica-host:/path/to/vledger-data/replication_secret.hex
```

**Step 3 — Create `replication.json` on the replica**

Create `vledger-data/replication.json` on the replica node:

```json
{
  "role": "replica",
  "replication_addr": "<primary-host>:5434",
  "ack_timeout_ms": 5000,
  "heartbeat_interval_ms": 1000,
  "send_buffer_bytes": 67108864,
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary",
    "ca_cert": "/path/to/replication-ca.pem"
  }
}
```

For development on a single machine with a self-signed primary cert, set `"ca_cert": null` and build with the `dev-insecure-replication` Cargo feature. Do not do this in production.

**Step 4 — Start the replica**

```bash
# Start the replica (connects to primary and streams WAL continuously)
vledger start-replica --data-dir ./vledger-data

# Override the primary address
vledger start-replica --data-dir ./vledger-data --primary <primary-host>:5434
```

The replica connects to the primary, performs the HMAC handshake, and begins streaming WAL records. It reconnects automatically on disconnection.

#### `replication.json` reference

| Field | Default | Description |
|---|---|---|
| `role` | `"primary"` | `"primary"` or `"replica"` |
| `replication_addr` | `"127.0.0.1:5434"` | Primary: bind address. Replica: primary's `host:port` |
| `ack_timeout_ms` | `5000` | How long the primary waits for a replica ACK (ms) |
| `heartbeat_interval_ms` | `1000` | Heartbeat frequency (ms) |
| `send_buffer_bytes` | `67108864` | Max bytes buffered per replica connection (64 MiB) |
| `secret_path` | `null` | Path to HMAC secret; `null` = `<data_dir>/replication_secret.hex` |
| `tls.enabled` | `true` | Enable TLS on the replication channel |
| `tls.server_cert` | `null` | Primary TLS cert PEM; `null` = auto-generate self-signed |
| `tls.server_key` | `null` | Primary TLS key PEM; `null` = auto-generate |
| `tls.server_hostname` | `"vledger-primary"` | SNI hostname used by replica to verify the primary's cert |
| `tls.ca_cert` | `null` | Replica: CA cert PEM to verify the primary. Required in production |
| `tls.client_cert` | `null` | Replica client cert PEM for mTLS (optional) |
| `tls.client_key` | `null` | Replica client key PEM for mTLS (optional) |

#### Known limitations

- **Failover promotion is manual.** There is no automatic primary election. If the primary crashes, an operator must explicitly reconfigure a replica as the new primary and restart it. Automated promotion via consensus (Raft/Paxos) is planned but not yet implemented.
- **Split-brain prevention is network-layer only.** VectorLedger relies on network segmentation (e.g. AWS security groups, private subnets) to prevent two nodes from simultaneously acting as primary. There is no fencing or STONITH mechanism.
- **Replica lag is observable but not bounded.** Heartbeat ACKs carry the replica's last applied LSN, allowing the primary to compute lag. There is no automatic write-pause when lag exceeds a threshold.

These limitations do not affect the WAL integrity or tamper-evidence guarantees.

### Compliance Reporting

> **Important scope note:** VectorLedger generates machine-generated technical evidence supporting SOC 2 and PCI-DSS control assessments. This evidence is a technical input to an audit — it does not by itself make an organization compliant. Organizational compliance requires additional policies, procedures, personnel controls, and independent auditor assessment that are outside the scope of any database engine.

- **SOC 2 Type II** controls: CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.2, CC8.1, A1.1
- **PCI-DSS v4** controls: Req 2.2, 3.4, 3.5, 4.2, 7.1, 10.2, 10.3, 10.5, 11.5
- Reports are generated by running checks against real filesystem state — not pre-written text
- Output as Markdown or JSON; piped to a file with `--output`

### Backup and Restore
- Point-in-time backup creates a `.tar` archive with a BLAKE3 manifest
- Private key material is **excluded** from backups — only public keys are archived; the HSM holds the private material
- Restore verifies every file's BLAKE3 hash against the manifest before completing
- `--force` required to overwrite an existing data directory

### Client SDKs
Native client libraries are included for three languages, all in `clients/`:

| Language | Location |
|---|---|
| Python | `clients/python/` |
| TypeScript / Node.js | `clients/typescript/` |
| Go | `clients/go/` |

---

## Performance

Benchmarked on Apple Silicon (MacBook, macOS) running in `group_commit`
WAL mode with a mixed read/write workload (10 concurrent clients,
1,000 transactions each, 70% INSERT / 30% SELECT):

| Metric | Value |
|---|---|
| Throughput | **430 TPS** |
| Min latency | **311 µs** |
| p50 latency | 23 ms |
| p95 latency | 36 ms |
| p99 latency | **42 ms** |
| Errors | 0 / 10,000 |

These numbers represent a **conservative baseline on development hardware**.
Production performance has not yet been independently characterized on server-class hardware.
The primary bottleneck in the write path is fsync latency, which varies significantly
between storage devices and operating systems.

> **Do not use the 430 TPS figure for production capacity planning.** It was measured on a single MacBook with 10 concurrent clients. Server-class NVMe storage, higher concurrency, and network-attached clients will produce materially different numbers — in both directions depending on workload shape.

### Benchmark environment matrix

The table below will be populated as benchmarks are run on server-class hardware. Contributions and independent reproduction are welcome.

| Environment | Storage | Concurrency | TPS | p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| Apple M-series (dev baseline) | NVMe | 10 | 430 | 23 ms | 36 ms | 42 ms |
| AWS Graviton3 (c7g) | EBS gp3 | 10 | — | — | — | — |
| AWS Graviton3 (c7g) | EBS gp3 | 100 | — | — | — | — |
| AWS x86 (c6i) | EBS gp3 | 10 | — | — | — | — |
| AWS x86 (c6i) | EBS gp3 | 100 | — | — | — | — |
| AWS x86 (c6i) | EBS gp3 | 1 000 | — | — | — | — |
| Bare metal | NVMe | 100 | — | — | — | — |
| Bare metal | NVMe | 1 000 | — | — | — | — |

All measurements use `--wal-sync-mode group_commit` (default) with a 70 % INSERT / 30 % SELECT mixed workload unless noted otherwise. `per_record` mode will show lower TPS and lower p99.

### WAL sync modes

VectorLedger ships with three WAL sync modes selectable at startup:

| Mode | Durability | Typical use |
|---|---|---|
| `group_commit` | Up to one flush window of data loss on hard crash | **Default — recommended for most deployments** |
| `per_record` | Zero data loss — every write fsynced immediately | Strict regulatory environments |
| `no_sync` | None | Development and CI only |

```bash
# Start with default group commit (2 ms flush interval)
vledger start

# Start with per-record fsync (safest, lower TPS)
vledger start --wal-sync-mode per_record

# Tune the flush interval (lower = less exposure, higher TPS tradeoff)
vledger start --wal-sync-mode group_commit --group-commit-delay-ms 5
```

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                        vledger binary                        │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │  TLS Server  │    │   PostgreSQL Wire Protocol       │   │
│  │  port 5433   │    │   port 5432                      │   │
│  │  JSON proto  │    │   psql / pgAdmin compatible      │   │
│  └──────┬───────┘    └──────────────┬───────────────────┘   │
│         │                           │                        │
│         └──────────────┬────────────┘                        │
│                        │                                      │
│              ┌─────────▼──────────┐                         │
│              │  UserStore (auth)  │  Argon2id · RBAC        │
│              │  4-role RBAC       │  Brute-force protection  │
│              └─────────┬──────────┘                         │
│                        │                                      │
│              ┌─────────▼──────────┐                         │
│              │  SQL Engine        │  SELECT · INSERT        │
│              │  Parser · Planner  │  BALANCE · VERIFY_CHAIN │
│              │  Executor          │  Joins · Aggregates      │
│              └─────────┬──────────┘                         │
│                        │                                      │
│              ┌─────────▼──────────┐                         │
│              │  LedgerStore       │  Hash chain             │
│              │  Double-entry      │  Idempotency            │
│              │  accounting core   │  Four-eyes enforcement  │
│              └──────┬──────┬──────┘                         │
│                     │      │                                  │
│          ┌──────────▼──┐ ┌─▼────────────┐                  │
│          │  WAL Writer  │ │  Page Store  │                  │
│          │  group_commit│ │  AES-256-GCM │                  │
│          │  (default)   │ │  per-table   │                  │
│          │  CRC-32      │ │  encryption  │                  │
│          └─────────────┘ └──────────────┘                  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Audit Log   │  │  HSM Client  │  │  Replication     │  │
│  │  WORM BLAKE3 │  │  Model 1 or  │  │  WAL streaming   │  │
│  │  chain       │  │  Model 2     │  │  TLS + HMAC      │  │
│  └──────────────┘  └──────┬───────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             │
             ┌───────────────┴───────────────┐
             │                               │
   Model 1 — same server          Model 2 — separate server
                                   (same-region private subnet)
             │                               │
   ┌─────────▼─────────┐         ┌──────────▼──────────┐
   │  PyHSM daemon     │         │  PyHSM daemon        │
   │  Unix socket      │         │  TLS 1.3 + mTLS      │
   │  /tmp/pyhsm.sock  │         │  port 8443           │
   │                   │         │  private subnet only │
   │  dev / CI /       │         │                      │
   │  single-server    │         │  production          │
   │  production       │         │  recommended         │
   └───────────────────┘         └─────────────────────┘
```

### PyHSM Deployment Models

VectorLedger supports two HSM deployment models. Choose based on your security requirements and infrastructure.

**Model 1 — Local PyHSM (same server)**

PyHSM and VectorLedger run on the same host. Communication uses a Unix domain socket. Zero network overhead. Suitable for development, CI, and single-server production deployments.

```
┌──────────────────────────────┐
│  Server                      │
│                              │
│  VectorLedger                │
│       │                      │
│       ▼  /tmp/pyhsm.sock    │
│  PyHSM daemon                │
└──────────────────────────────┘
```

**Model 2 — Remote PyHSM (same-region, separate server)**

PyHSM runs on a dedicated server in the same region's private subnet. VectorLedger connects over TLS 1.3 with mutual certificate authentication (mTLS). PyHSM's private key material is never accessible from the VectorLedger host. Recommended for production.

```
  Private subnet (e.g. AWS VPC)

  ┌────────────────────┐              ┌────────────────────┐
  │  Server A          │              │  Server B          │
  │                    │              │                    │
  │  VectorLedger      │              │  PyHSM daemon      │
  │  encrypted data    │──TLS 1.3 ───▶│  encrypted         │
  │  WAL               │   + mTLS     │  keystore          │
  │  application       │              │  port 8443         │
  │  traffic           │              │  no public IP      │
  └────────────────────┘              └────────────────────┘

  Security group: allows VectorLedger → PyHSM only
  No public endpoint on PyHSM server
```

The `endpoint` field in `key_source.json` can point at a load balancer VIP or AWS NLB in front of multiple PyHSM instances — the transport is cluster-ready at the network layer without any code change.

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Rust toolchain | 1.80 | Install via [rustup.rs](https://rustup.rs) |
| macOS, Linux, or Windows | — | macOS and Linux are fully supported; Windows 10/11 and Windows Server 2019/2022 (x86_64 and ARM64) are supported |
| Git | Any recent | To clone the repository |

No other runtime dependencies are required. All cryptographic libraries are statically linked via Cargo.

---

## Installation

### Option 1 — Install via curl (recommended)

The fastest way to install VectorLedger. The installer detects your OS and
architecture, downloads the correct pre-built binary, verifies its SHA-256
checksum, and places `vledger` on your `PATH`.

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
```

**Install a specific version:**

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh \
  | VLEDGER_VERSION=v0.1.0 bash
```

**Install to a custom directory:**

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh \
  | VLEDGER_INSTALL_DIR="$HOME/.local/bin" bash
```

The installer supports macOS and Linux on x86_64 and aarch64. If no pre-built
binary is available for your platform it automatically falls back to building
from source using Cargo (Rust 1.80+ required).

**Installer environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VLEDGER_VERSION` | latest | Release tag to install, e.g. `v0.1.0` |
| `VLEDGER_INSTALL_DIR` | `/usr/local/bin` | Directory to place the `vledger` binary |
| `VLEDGER_NO_MODIFY_PATH` | `0` | Set to `1` to skip adding the install dir to your shell profile |

After installation, verify it works:

```bash
vledger --version
vledger self-test
```

---

### Windows (PowerShell)

Run this in PowerShell 5.1+ or PowerShell 7+:

```powershell
irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex
```

The installer detects your architecture (x86_64 or ARM64), downloads the signed release zip, verifies its SHA-256 checksum, installs `vledger.exe` to `%LOCALAPPDATA%\vledger\bin`, and adds it to your user `PATH`.

**Install a specific version:**

```powershell
$env:VLEDGER_VERSION = "v0.1.0"
irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex
```

**Install to a custom directory (with parameters):**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1))) `
    -InstallDir "C:\Tools\vledger"
```

**Installer parameters:**

| Parameter | Default | Description |
|---|---|---|
| `-Version` | latest | Release tag, e.g. `v0.1.0`. Also reads `$env:VLEDGER_VERSION`. |
| `-InstallDir` | `%LOCALAPPDATA%\vledger\bin` | Directory to install `vledger.exe` |
| `-NoPathUpdate` | off | Skip adding the install dir to your user `PATH` |

After installation, verify it works in a new terminal:

```powershell
vledger --version
vledger self-test
```

**Windows-specific notes:**

- PyHSM uses **TCP** instead of a Unix socket on Windows. Start the PyHSM daemon with `$env:PYHSM_TCP_PORT = 7777` and pass `--pyhsm-socket 127.0.0.1:7777` to `vledger init`.
- File permissions (`0o600`) are not set on Windows — protect your data directory using NTFS ACLs or store it inside a user-only folder.
- Graceful shutdown responds to `CTRL-C`. `SIGTERM` is Unix-only; use `Stop-Process` or the service manager on Windows.

---

### Option 2 — Build from source

### Step 1 — Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version   # should be 1.80 or newer
cargo --version
```

### Step 2 — Clone the repository

```bash
git clone https://github.com/pavondunbar/VectorLedger.git
cd VectorLedger
```

### Step 3 — Build

For a development build:

```bash
cargo build
```

For an optimized production binary:

```bash
cargo build --release
```

The binary is written to:
- Development: `target/debug/vledger`
- Release: `target/release/vledger`

Install the binary to your `PATH` so you can run `vledger` from any directory:

```bash
cargo install --path crates/vledger
```

This places the binary in `~/.cargo/bin/`, which the Rust toolchain adds to your `PATH` automatically. Alternatively, copy it manually:

```bash
# macOS / Linux
sudo cp target/release/vledger /usr/local/bin/vledger
```

### Step 4 — Verify the build

Run the built-in self-test suite to confirm everything works:

```bash
./target/release/vledger self-test
./target/release/vledger self-test-phase3
```

Expected output:

```
── VectorLedger Phase 2 Self-Test ───────────────
  [1/7] Hash chain             ... ✓
  [2/7] AES-256-GCM encryption ... ✓
  [3/7] Merkle proofs          ... ✓
  [4/7] WAL-backed ledger      ... ✓
  [5/7] Page encryption        ... ✓
  [6/7] SQL engine             ... ✓
  [7/7] Verifiable query proof  ... ✓

✓ All Phase 2 self-tests passed.
```

```
── VectorLedger Phase 3 Self-Test ───────────────
  [1/7] Audit log (WORM + chain)     ... ✓
  [2/7] Four-eyes workflow           ... ✓
  [3/7] Compliance report (SOC 2)    ... ✓
  [4/7] Compliance report (PCI-DSS)  ... ✓
  [5/7] Backup & restore round-trip  ... ✓
  [6/7] PgWire message encoding      ... ✓
  [7/7] SQL optimizer (agg + window) ... ✓

✓ All Phase 3 self-tests passed.
```

---

## Quick Start

VectorLedger uses [PyHSM](https://github.com/pavondunbar/PyHSM) — a VectorGuard Labs product — as its default key management backend. PyHSM acts as a local software HSM: VectorLedger's master encryption key is sealed inside PyHSM's encrypted keystore and never touches disk in plaintext.

The steps below walk through the full setup from scratch. If you are not using PyHSM and prefer a different key backend, skip to [Key Source Backends](#key-source-backends).

### 1. Install and start PyHSM

PyHSM ships as both a Python package and a TypeScript daemon. **VectorLedger connects to the TypeScript daemon** via a Unix domain socket — the Python package is a separate key management CLI and is not required for VectorLedger integration.

**Install Node.js (18+) if you don't have it:**

```bash
# macOS with Homebrew
brew install node

# Or download from https://nodejs.org
```

**Clone PyHSM and install its dependencies:**

```bash
git clone https://github.com/pavondunbar/PyHSM.git ~/PyHSM
cd ~/PyHSM/pyhsm-ts
npm install
```

**Generate a PyHSM master password and store it in your secrets manager.**

This password protects PyHSM's own internal keystore. It must be supplied every time the daemon starts. Treat it with the same care as a database root password — if it is lost, the keystore cannot be unlocked.

```bash
# Generate a strong password — save this somewhere safe before running vledger
openssl rand -base64 32
```

**Start the PyHSM daemon:**

```bash
cd ~/PyHSM
PYHSM_MASTER_PASSWORD="<your-password>" \
PYHSM_KEYSTORE_PATH="$HOME/PyHSM/pyhsm-keystore.enc" \
PYHSM_AUDIT_LOG_PATH="$HOME/PyHSM/pyhsm-audit.jsonl" \
npx tsx pyhsm-ts/process.ts
```

Expected output:

```
[PyHSM] Process started (PID 12345)
[PyHSM] Listening on /tmp/pyhsm.sock
```

**Confirm the socket is ready** (new terminal):

```bash
ls -la /tmp/pyhsm.sock
# srw-------  1 you  wheel  0 Aug 7 15:28 /tmp/pyhsm.sock
```

The socket must exist and have mode `srw-------` (0600) before proceeding. If it is not present, the daemon did not start successfully — check the terminal running PyHSM for errors.

> **Important:** PyHSM must always start **before** VectorLedger. If the daemon is not running when `vledger start` is called, startup will fail with a clear error. Never start VectorLedger without PyHSM running.

### 2. Initialise the database

With PyHSM running, initialise VectorLedger from your VectorLedger directory:

```bash
cd /path/to/VectorLedger
vledger init --data-dir ./vledger-data --key-source pyhsm
```

Correct output looks like this:

```
Key source : pyhsm
PyHSM: socket=/tmp/pyhsm.sock  wrapping-key=vledger.master-key
✓ VectorLedger initialised at: ./vledger-data
  Signing key (first 16 hex): 7d596f8e1ecfaebd
    wal
    pages
    indexes
    catalog
    snapshots
    keys
    audit

  Master key source stored in: keys/key_source.json
```

**Verify the backend was recorded correctly:**

```bash
cat vledger-data/keys/key_source.json
```

Must contain `"backend": "py_hsm"`:

```json
{
  "backend": "py_hsm",
  "socket_path": "/tmp/pyhsm.sock",
  "caller_id": "vledger",
  "key_id": "vledger.master-key"
}
```

If it shows `"backend": "env"`, the PyHSM socket was not found during init and VectorLedger fell back silently. Delete the data directory, confirm the socket exists, and re-run init.

> **Never run `vledger init` without `--key-source pyhsm` (or `--key-source remote-pyhsm` for Model 2) in production.** The default without this flag uses an environment variable backend which stores key material in your shell environment.

### 3. Lock down the data directory

```bash
chmod 700 vledger-data/
chmod 700 vledger-data/keys/
chmod 700 vledger-data/catalog/
chmod 700 vledger-data/audit/
chmod 700 vledger-data/wal/
chmod 700 vledger-data/pages/
```

### 4. Start the server

```bash
vledger start --data-dir ./vledger-data
```

The first start generates an initial admin password and writes it to a restricted file — it is **not** printed to the terminal (to prevent it appearing in log aggregators):

```
╔══════════════════════════════════════════════════════╗
║  VectorLedger — Initial Admin Credentials            ║
║                                                      ║
║  Credentials written to (mode 0o600):                ║
║  ./vledger-data/catalog/.admin_initial_credentials   ║
║                                                      ║
║  Read the file, change the password, then delete it. ║
╚══════════════════════════════════════════════════════╝
── VectorLedger ────────────────────────────────
  Listening  : 127.0.0.1:5433  (TLS 1.3)
  Data dir   : ./vledger-data
  Protocol   : newline-delimited JSON
  WAL sync   : group_commit  (flush every 2 ms)
──────────────────────────────────────────────────
```

### 5. Change the admin password

In a new terminal, read the credential file, change the password, and delete the file:

```bash
# Read the generated password
cat vledger-data/catalog/.admin_initial_credentials

# Change it immediately
vledger user set-password --username admin --data-dir ./vledger-data

# Delete the credential file — it must not persist
rm vledger-data/catalog/.admin_initial_credentials

# Confirm it is gone
ls vledger-data/catalog/
```

The `.admin_initial_credentials` file must not exist after this step.

### 6. Verify integrity

```bash
vledger verify --data-dir ./vledger-data
```

Expected output:

```
── VectorLedger Integrity Verification ─────────
  WAL integrity            ... ✓ (0 committed txns)
  Ledger hash chain        ... ✓ (0 entries, tip=0000000000000000)

✓ Verification complete
```

### 7. Run your first queries

With the server running in one terminal, open a second terminal and use the built-in SQL REPL. When the server is running, the CLI automatically connects to it over TLS — you do not need to stop the server first:

```bash
vledger sql --data-dir ./vledger-data --username admin
# Password: <your initial password>
```

If you ever need to connect to a server on a different address, use `--server`:

```bash
vledger sql --server 10.0.0.1:5433 --username admin
```

Change the admin password immediately after first login:

```bash
vledger user set-password --username admin
# New password: <type new password>
# Confirm password: <type again>
```

Once in the REPL, use `\x` to toggle expanded (vertical) display — useful for wide rows like ledger entries:

```
vledger> \x
Expanded display is on.

vledger (expanded)> SELECT * FROM ledger;
─────────────────────── [ row 1 ]
     sequence │ 1
           id │ a509b39c-a6af-4ca8-afe2-851ec6f21cce
       status │ Posted
  description │ Customer payment
       domain │ main
 effective_at │ 2026-08-06T22:52:52+00:00
    posted_at │ 2026-08-06T22:52:52+00:00
 content_hash │ 30f3516a...
   chain_hash │ 0523670d...
        lines │ ...: Debit 100000 USD; ...: Credit 100000 USD
── 1 rows
```

Toggle back with `\x` again. Use `\?` inside the REPL to see all available meta-commands.

```sql
-- Create accounts
INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('CASH', 'Cash - USD', 'asset', 'USD', 'main');

INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('REVENUE', 'Revenue', 'income', 'USD', 'main');

-- Post a journal entry
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain)
VALUES ('Customer payment', 'CASH', 'REVENUE', 100000, 'USD', 'main');

-- Check balance (amounts are in minor units — cents for USD)
SELECT BALANCE('CASH');
-- balance
-- -------
-- 100000

-- Verify the hash chain
SELECT VERIFY_CHAIN();
-- status | entries_verified
-- -------+-----------------
-- OK     | 1

-- Query all entries (one row per entry)
SELECT * FROM ledger;

-- Query entries in traditional accounting format (one row per debit/credit line)
SELECT * FROM ledger_lines LIMIT 10;
-- date       | sequence | description      | account_id | dr_cr  | amount | currency | domain
-- -----------+----------+------------------+------------+--------+--------+----------+-------
-- 2026-08-17 |        1 | Customer payment | <uuid>     | Debit  |   1.00 | USD      | main
-- 2026-08-17 |        1 | Customer payment | <uuid>     | Credit |   1.00 | USD      | main
```

### 8. Also start the PostgreSQL wire-protocol listener

```bash
vledger start --data-dir ./vledger-data --pgwire
```

Then connect with any PostgreSQL client:

```bash
psql "host=127.0.0.1 port=5432 user=admin sslmode=require"
```

Or with pgAdmin, DBeaver, or Metabase using standard PostgreSQL connection settings.

---

## Reset / Starting Over

If you lose the admin password, or need to wipe the database and start fresh, delete the data directory and re-initialise. **Make sure PyHSM is running before you init.**

```bash
# Stop the server first (Ctrl-C in the terminal where it is running)

rm -rf ./vledger-data

vledger init --data-dir ./vledger-data --key-source pyhsm
vledger start --data-dir ./vledger-data
```

The first `start` after a fresh `init` writes a new admin credential file. Read it, change the password, and delete the file before doing anything else (see [Step 5](#5-change-the-admin-password) above).

---

## SQL Reference

VectorLedger supports a financial-ledger SQL dialect over both the native TLS connection (port 5433) and the PostgreSQL wire protocol (port 5432). It is **PostgreSQL-compatible** — not PostgreSQL — so standard PostgreSQL system catalog queries (`\l`, `\dt`, `pg_catalog.*`) are not supported. Use the commands below for all introspection.

### Scan Safety — Default Row Cap

Unbounded full-table scans on a large ledger load all matching rows into memory before returning, which can exhaust server RAM and cause the OS to kill the process. VectorLedger protects against this with an automatic **10,000-entry cap** on non-point-lookup queries that have no explicit `LIMIT`.

| Query pattern | Behaviour |
|---|---|
| `SELECT * FROM ledger WHERE sequence = N` | No cap — returns exactly 1 entry |
| `SELECT * FROM ledger WHERE external_ref = 'X'` | No cap — point lookup |
| `SELECT * FROM ledger LIMIT 500` | Exactly 500 rows — explicit limit honoured |
| `SELECT * FROM ledger` | Capped at 10,000 rows + pagination notice |
| `SELECT * FROM ledger WHERE domain = 'x'` | Capped at 10,000 rows + pagination notice |
| `SELECT * FROM ledger WHERE status = 'Posted'` | Capped at 10,000 rows + pagination notice |

When the cap fires, the result message tells you what happened:
```
10000 rows (capped at 10000 — use LIMIT n or WHERE sequence = x to paginate)
```

**To page through a large dataset**, use sequence-based pagination:
```sql
-- Page 1: entries 1 – 10,000
SELECT * FROM ledger LIMIT 10000;

-- Page 2: entries 10,001 – 20,000
SELECT * FROM ledger WHERE sequence > 10000 LIMIT 10000;

-- Page 3: entries 20,001 – 30,000
SELECT * FROM ledger WHERE sequence > 20000 LIMIT 10000;
```

The same cap and pagination pattern applies to `ledger_lines`.

---

### Tables

#### `ledger` — one row per journal entry
```sql
-- Point lookups (no cap — always safe)
SELECT * FROM ledger WHERE sequence = 406340;
SELECT * FROM ledger WHERE external_ref = 'TXN-001';

-- Bounded queries (always safe)
SELECT * FROM ledger LIMIT 100;
SELECT * FROM ledger WHERE domain = 'main' LIMIT 500;

-- Full scans (auto-capped at 10,000 — paginate for more)
SELECT * FROM ledger;
SELECT * FROM ledger WHERE domain = 'main';
SELECT * FROM ledger WHERE status = 'Posted';
```

Columns: `sequence`, `id`, `status`, `description`, `domain`, `effective_at`, `posted_at`, `external_ref`, `content_hash`, `chain_hash`, `lines`

The `lines` column contains all debit and credit lines as a single semicolon-separated string. Use `ledger_lines` (below) for the traditional accounting view.

#### `ledger_lines` — one row per debit/credit line
```sql
-- Point lookups (no cap — always safe)
SELECT * FROM ledger_lines WHERE sequence = 406340;

-- Bounded queries (always safe)
SELECT * FROM ledger_lines LIMIT 100;
SELECT * FROM ledger_lines WHERE domain = 'main' LIMIT 500;
SELECT * FROM ledger_lines WHERE status = 'Posted' LIMIT 50;

-- Full scans (auto-capped at 10,000 entries — paginate for more)
SELECT * FROM ledger_lines;
SELECT * FROM ledger_lines WHERE domain = 'main';
SELECT * FROM ledger_lines WHERE status = 'Posted';
```

Returns each debit and credit as its own row — the standard double-entry accounting view that accountants expect:

```
date       | sequence | entry_id | description      | domain | account_id | dr_cr  | amount | currency | status
-----------+----------+----------+------------------+--------+------------+--------+--------+----------+-------
2026-08-17 |        1 | <uuid>   | Customer payment | main   | <uuid>     | Debit  |   1.00 | USD      | Posted
2026-08-17 |        1 | <uuid>   | Customer payment | main   | <uuid>     | Credit |   1.00 | USD      | Posted
```

Columns: `date`, `sequence`, `entry_id`, `description`, `domain`, `account_id`, `dr_cr`, `amount`, `currency`, `status`

Amounts are displayed as decimals (e.g. `1.00`) rather than minor units. The cap applies to the number of **entries** before line expansion — a cap of 10,000 entries yields up to 20,000 rows (two lines per entry) for a standard two-line transaction.

#### `accounts` — chart of accounts
```sql
SELECT * FROM accounts;
SELECT * FROM accounts WHERE domain = 'main';
```

Columns: `id`, `code`, `name`, `account_type`, `currency`, `status`, `domain`, `balance`

---

### Write Commands

#### Post a journal entry
```sql
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain)
VALUES ('Wire transfer', 'CASH', 'REVENUE', 100000, 'USD', 'main');
```

- `amount` is in **minor units** (cents for USD — 100000 = $1,000.00)
- `debit_account` and `credit_account` accept either account `code` or UUID
- Optional fields: `external_ref`, `idempotency_key`
- Entries are **append-only** — `UPDATE` and `DELETE` are not supported

#### Create an account
```sql
INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('CASH', 'Cash - USD', 'asset', 'USD', 'main');
```

Account types: `asset`, `liability`, `equity`, `income`, `expense`

#### Post a correction (reversal)
Corrections are made by posting a new reversal entry, never by modifying the original:
```sql
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain)
VALUES ('Reversal of TXN-001', 'REVENUE', 'CASH', 100000, 'USD', 'main');
```

---

### Financial Functions

```sql
-- Account balance (returns minor units)
SELECT BALANCE('CASH');
SELECT BALANCE('account-uuid-here');

-- Verify the entire BLAKE3 hash chain
SELECT VERIFY_CHAIN();

-- Verify a range of entries
SELECT VERIFY_CHAIN(1, 100000);
SELECT VERIFY_CHAIN(1000000);

-- Verify a single entry's content and chain hashes
SELECT VERIFY_ENTRY(406340);
```

---

### Aggregates and Window Functions

```sql
SELECT COUNT(sequence) FROM ledger;
SELECT SUM(amount) FROM ledger GROUP BY domain;
SELECT AVG(amount) FROM ledger;
SELECT MIN(sequence), MAX(sequence) FROM ledger;
SELECT ROW_NUMBER() OVER () AS rn FROM ledger;
SELECT RANK() OVER () FROM ledger;
```

---

### Joins

```sql
SELECT * FROM ledger JOIN accounts ON ledger.domain = accounts.domain;
```

Supports `INNER JOIN` and `LEFT OUTER JOIN`.

---

### Compatibility Queries (ORM / connection pooler health checks)

```sql
SELECT 1;
SELECT version();
SELECT current_user();
SELECT current_database();
```

---

### What is NOT supported

| Operation | Why |
|---|---|
| `UPDATE` | Append-only — entries are permanent |
| `DELETE` | Append-only — entries are permanent |
| `CREATE TABLE` / `DROP TABLE` | Schema is fixed |
| `pg_catalog.*` system tables | Not PostgreSQL internally |
| `\l`, `\dt`, `\du` psql meta-commands | Rely on `pg_catalog` |
| Multiple databases or schemas | Single-database engine |
| Stored procedures, triggers, sequences | Not implemented |

---

## CLI Reference

### `vledger init`

Initialise a new database.

```bash
vledger init [OPTIONS]
  --data-dir <PATH>          Data directory (default: ./vledger-data)
  --force                    Reinitialise an existing database
  --key-source <BACKEND>     env | file | vault | aws_kms | pyhsm | remote-pyhsm
                             (default: pyhsm)
  --vault-addr <URL>         Vault server address
  --vault-mount <MOUNT>      Vault KV v2 mount path (default: secret)
  --vault-path <PATH>        Vault secret path (default: vledger/master_key)
  --kms-key-id <ARN>         AWS KMS key ARN or alias
  --kms-region <REGION>      AWS region (default: us-east-1)

  # Model 1 — local PyHSM (same server)
  --pyhsm-socket <PATH>      PyHSM Unix socket path (default: /tmp/pyhsm.sock)
  --pyhsm-caller-id <ID>     Caller ID written to PyHSM audit log (default: vledger)

  # Model 2 — remote PyHSM (same-region, separate server)
  --pyhsm-endpoint <URL>     Remote PyHSM HTTPS endpoint; selects remote-pyhsm
                             automatically when set
                             Example: https://pyhsm.internal.example.com:8443
                             Env: PYHSM_ENDPOINT
  --pyhsm-ca-cert <PATH>     CA certificate PEM to verify the PyHSM server
                             Env: PYHSM_CA_CERT
  --pyhsm-client-cert <PATH> mTLS client certificate PEM (VectorLedger's identity)
                             Env: PYHSM_CLIENT_CERT
  --pyhsm-client-key <PATH>  mTLS client private key PEM
                             Env: PYHSM_CLIENT_KEY
  --pyhsm-timeout-ms <MS>    Per-request timeout in ms (default: 5000)
                             Env: PYHSM_TIMEOUT_MS
  --pyhsm-max-retries <N>    Max retries on transient errors (default: 3)
```

### `vledger start`

Start the server.

```bash
vledger start [OPTIONS]
  --data-dir <PATH>        Data directory (default: ./vledger-data)
  --bind <ADDR>            Bind address (default: 127.0.0.1:5433)
  --pgwire                 Also start the PostgreSQL wire-protocol listener on port 5432
  --with-proofs            Attach Merkle proofs to every SELECT response
```

Responds to `SIGTERM` and `CTRL-C` with a graceful drain — in-flight connections are allowed to complete before the process exits.

### `vledger sql`

Interactive SQL REPL or single-statement execution.

```bash
vledger sql [OPTIONS]
  --data-dir <PATH>   Data directory
  --query <SQL>       Run a single statement and exit (omit for interactive mode)
  --username <USER>   Username (or set VLEDGER_CLI_USER)
  --password <PASS>   Password (or set VLEDGER_CLI_PASSWORD, or enter interactively)
  --server <ADDR>     Connect to a running server at host:port instead of opening
                      the data directory directly (auto-detected if server is
                      reachable at 127.0.0.1:5433)
```

When `vledger start` is running, the CLI automatically detects it and connects over TLS. Use `--server` to point at a non-default address. If no server is reachable, the CLI opens the data directory directly (safe only when the server is stopped).

#### REPL meta-commands

These commands are handled locally by the REPL — they do not send a request to the server:

| Command | Description |
|---|---|
| `\x` | Toggle expanded (vertical) display. Useful for wide rows. |
| `\q` or `exit` | Quit the REPL. |
| `\?` or `\help` | Show available meta-commands. |

In normal display mode, columns are auto-sized to fit their widest value and separated with `│`. In expanded mode, each row is printed as a vertical key-value block:

```
─────────────────────── [ row 1 ]
     sequence │ 1
           id │ a509b39c-...
  description │ Customer payment
       status │ Posted
        lines │ ...: Debit 100000 USD; ...: Credit 100000 USD
```

The prompt changes to `vledger (expanded)>` while expanded mode is active as a visual reminder.

### `vledger verify`

Verify WAL integrity and the ledger hash chain.

```bash
vledger verify --data-dir <PATH>
```

### `vledger status`

Show database version, WAL segment count, and active segment.

```bash
vledger status --data-dir <PATH>
```

### `vledger backup`

Create a point-in-time backup archive with a BLAKE3 manifest.

```bash
vledger backup --data-dir <PATH> [--output <FILE.tar>]
```

### `vledger restore`

Restore a backup archive. Verifies every file's hash before completing.

```bash
vledger restore --from <FILE.tar> [--target <PATH>] [--force]
```

### `vledger rotate-keys`

Rotate all HSM key slots and record audit events.

```bash
vledger rotate-keys [OPTIONS]
  --data-dir <PATH>          Data directory (default: ./vledger-data)
  --caller-id <ID>           Caller ID written to audit log (default: vledger-admin)

  # Model 1 — local PyHSM
  --hsm-socket <PATH>        PyHSM Unix socket path (default: /tmp/pyhsm.sock)

  # Model 2 — remote PyHSM (--pyhsm-endpoint selects this automatically)
  --pyhsm-endpoint <URL>     Remote PyHSM HTTPS endpoint
                             Env: PYHSM_ENDPOINT
  --pyhsm-ca-cert <PATH>     CA certificate PEM (required with --pyhsm-endpoint)
                             Env: PYHSM_CA_CERT
  --pyhsm-client-cert <PATH> mTLS client certificate PEM
                             Env: PYHSM_CLIENT_CERT
  --pyhsm-client-key <PATH>  mTLS client private key PEM
                             Env: PYHSM_CLIENT_KEY
  --pyhsm-timeout-ms <MS>    Per-request timeout in ms (default: 5000)
  --pyhsm-max-retries <N>    Max retries on transient errors (default: 3)
```

### `vledger audit-export`

Export the WORM audit log.

```bash
vledger audit-export --data-dir <PATH> [--format json|csv] [--output <FILE>]
                     [--from <RFC3339>] [--to <RFC3339>]
```

### `vledger compliance-report`

Generate a SOC 2 or PCI-DSS compliance evidence report.

```bash
vledger compliance-report --data-dir <PATH> [--standard soc2|pci-dss]
                          [--format markdown|json] [--output <FILE>]
```

Example — generate a PCI-DSS report as Markdown:

```bash
vledger compliance-report --data-dir ./vledger-data \
  --standard pci-dss \
  --format markdown \
  --output pci-report.md
```

### `vledger license`

Show the active license tier, features, and expiry.

```bash
vledger license --data-dir <PATH>
```

Place the signed `license.json` file provided by VectorGuard Labs into your data directory to unlock paid features. If no file is present, the engine runs in Free tier. See the [Licensing](#licensing) section for the full tier comparison, feature list, and pricing.

### `vledger start-primary`

Start a WAL replication primary listener (**Growth+ license required**).

```bash
vledger start-primary [OPTIONS]
  --data-dir <PATH>   Data directory (default: ./vledger-data)
  --bind <ADDR>       Bind address for the WAL shipper
                      (overrides replication.json; default: 127.0.0.1:5434)
```

Reads `<data-dir>/replication.json`. If the file does not exist, a default config is written on first run. The primary auto-generates `replication_secret.hex` (mode `0o600`) on first start — copy this file to every replica before starting them.

> **Tip:** In most deployments you don't need this command. If `replication.json` exists with `role=primary`, `vledger start` automatically activates the WAL shipper and ships every committed entry to replicas — no separate process required. Use `start-primary` only when you want a shipper without a SQL server.

Responds to `SIGTERM` and `CTRL-C` with a graceful shutdown.

### `vledger start-replica`

Start a WAL replication replica (**Growth+ license required**).

```bash
vledger start-replica [OPTIONS]
  --data-dir <PATH>     Data directory (default: ./vledger-data)
  --primary <ADDR>      Primary host:port to connect to
                        (overrides replication.json)
```

Requires `<data-dir>/replication.json` to exist. The `replication_secret.hex` file must already be present (copied from the primary) before this command will succeed.

The replica connects to the primary, performs the BLAKE3 HMAC handshake, and streams WAL records continuously. It reconnects automatically on disconnection with exponential backoff.

Responds to `SIGTERM` and `CTRL-C` with a graceful shutdown.

### `vledger user`

Manage user accounts. All subcommands read the user store directly from the data directory — the server does not need to be running.

```bash
vledger user set-password   # change a user's password (revokes all active sessions)
vledger user create         # create a new user account
vledger user list           # list all accounts
vledger user set-enabled    # enable or disable an account
vledger user delete         # delete an account
```

**Change a password:**

```bash
vledger user set-password --data-dir <PATH> [--username <USER>]
# Prompts for new password and confirmation interactively.
# Or non-interactively:
vledger user set-password --data-dir <PATH> --username admin --new-password 'NewP@ss!'
```

**Create a user:**

```bash
vledger user create --data-dir <PATH> --username alice --role operator
# Roles: admin, operator, auditor, readonly
```

**List users:**

```bash
vledger user list --data-dir <PATH>
```

**Disable an account:**

```bash
vledger user set-enabled --data-dir <PATH> --username alice --enabled false
```

**Delete an account:**

```bash
vledger user delete --data-dir <PATH> --username alice
```

---

## Key Source Backends

The master encryption key is the root of VectorLedger's cryptographic hierarchy. All per-table keys are derived from it via HKDF-SHA256. Choose the backend appropriate for your deployment.

### Environment variable (CI / container deployments)

```bash
export VectorLedger_MASTER_KEY="$(openssl rand -hex 32)"
vledger init --key-source env
```

Best for containerised environments where secrets are injected as environment variables (Kubernetes Secrets, AWS ECS task definitions, etc.).

### HashiCorp Vault KV v2

```bash
# One-time setup: write the key to Vault
vault kv put secret/vledger/master_key value="$(openssl rand -hex 32)"

# Initialise with Vault backend
export VAULT_TOKEN="<your-vault-token>"
vledger init \
  --key-source vault \
  --vault-addr http://127.0.0.1:8200 \
  --vault-mount secret \
  --vault-path vledger/master_key
```

`VAULT_TOKEN` must be set in the environment before starting the server. VectorLedger checks the token's TTL at startup and logs a warning if it expires within 24 hours.

### AWS KMS

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
# AWS_SESSION_TOKEN is also supported for temporary credentials

vledger init \
  --key-source aws_kms \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/mrk-..." \
  --kms-region us-east-1
```

On first start, VectorLedger calls `GenerateDataKey` and caches the encrypted ciphertext blob locally (`kms_data_key.enc`). On subsequent restarts, it calls `Decrypt` against the cached blob. The cache file is protected with an HMAC-SHA256 integrity check — a tampered blob is detected before any network call.

### File (development only)

```bash
vledger init --key-source file
```

Generates a random key and writes it to `vledger-data/keys/master_key.hex` with mode `0o600`. **Not recommended for production.** Move to Vault or KMS before deployment.

---

### PyHSM (recommended — VectorGuard Labs)

PyHSM is a VectorGuard Labs product and the default key backend for VectorLedger. The master encryption key is sealed inside PyHSM's AES-256-GCM-SIV encrypted keystore and never touches disk in plaintext.

VectorLedger supports two PyHSM deployment models:

| Model | Transport | Use case |
|---|---|---|
| **Model 1 — Local** | Unix domain socket | Dev, CI, single-server production |
| **Model 2 — Remote** | TLS 1.3 + mTLS | Same-region separate-server production |

#### Two ways to install PyHSM

**Option A — TypeScript daemon (required for VectorLedger integration)**

This is what VectorLedger connects to. The daemon listens on a Unix domain socket and handles all key operations via IPC.

```bash
git clone https://github.com/pavondunbar/PyHSM.git ~/PyHSM
cd ~/PyHSM/pyhsm-ts
npm install
```

Start the daemon:

```bash
PYHSM_MASTER_PASSWORD="<your-password>" \
PYHSM_KEYSTORE_PATH="$HOME/PyHSM/pyhsm-keystore.enc" \
PYHSM_AUDIT_LOG_PATH="$HOME/PyHSM/pyhsm-audit.jsonl" \
npx tsx ~/PyHSM/pyhsm-ts/process.ts
```

**Option B — Python CLI (`pip install vectorguard-pyhsm`)**

The Python package installs the `vectorguard-pyhsm` command — a key management CLI for generating, rotating, and inspecting keys in a PyHSM keystore. It is a standalone tool, not a daemon. VectorLedger does **not** connect to it.

```bash
pip install vectorguard-pyhsm
```

You can use it to inspect or manage the same keystore that the TypeScript daemon uses:

```bash
# List keys in the keystore
vectorguard-pyhsm --store ~/PyHSM/pyhsm-keystore.enc list

# Rotate the VectorLedger wrapping key
vectorguard-pyhsm --store ~/PyHSM/pyhsm-keystore.enc rotate vledger.master-key

# Verify audit log integrity
vectorguard-pyhsm --store ~/PyHSM/pyhsm-keystore.enc audit --verify
```

To use the pip CLI, the TypeScript daemon does **not** need to be running — it opens the keystore file directly using `PYHSM_MASTER_PASSWORD`.

> **Summary:** install **both** if you want the full toolkit. The TypeScript daemon is what VectorLedger needs to run. The Python CLI is what you use to administer the keystore.

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PYHSM_MASTER_PASSWORD` | — | **Required.** Password that unlocks the PyHSM keystore. |
| `PYHSM_KEYSTORE_PATH` | `./pyhsm-keystore.enc` | Path where the encrypted keystore is stored. Set this to a persistent, backed-up location. |
| `PYHSM_AUDIT_LOG_PATH` | `<keystore>.audit.jsonl` | Path for PyHSM's own tamper-evident audit log. |
| `PYHSM_SOCKET_PATH` | `/tmp/pyhsm.sock` | Unix socket path the daemon listens on (Model 1). |
| `PYHSM_CALLER_SECRET` | — | Optional shared secret for IPC caller authentication. |
| `PYHSM_RATE_LIMIT` | `100` | Max operations per rate window. |
| `PYHSM_RATE_WINDOW_MS` | `60000` | Rate window in milliseconds. |

#### Model 2 — remote PyHSM environment variables

These variables can override the corresponding `key_source.json` fields at deploy time — useful for injecting cert paths via container environment without modifying the config file.

| Variable | Description |
|---|---|
| `PYHSM_ENDPOINT` | HTTPS endpoint of the remote PyHSM daemon |
| `PYHSM_CA_CERT` | Path to the CA certificate PEM |
| `PYHSM_CLIENT_CERT` | Path to the mTLS client certificate PEM |
| `PYHSM_CLIENT_KEY` | Path to the mTLS client private key PEM |
| `PYHSM_TIMEOUT_MS` | Per-request timeout in milliseconds |

#### How VectorLedger uses PyHSM across restarts

| Event | What happens |
|---|---|
| First `vledger init --key-source pyhsm` | VectorLedger generates a 32-byte master key in-process, asks PyHSM to encrypt it, stores only the encrypted blob at `vledger-data/keys/pyhsm_master_key.enc` with an HMAC-SHA256 integrity seal |
| Every `vledger start` | HMAC verified locally first, blob sent to PyHSM for decryption, plaintext key used briefly for key derivation then immediately zeroized from memory |
| PyHSM daemon not running at startup | `vledger start` fails immediately with a clear error — no data is touched |
| Cache file tampered | HMAC check fails, startup aborts before any IPC call |
| Remote PyHSM unreachable (Model 2) | Startup fails closed — VectorLedger never falls back to a weaker key source |

The same lifecycle applies to both Model 1 and Model 2. The only difference is the transport: Unix socket vs TLS 1.3 + mTLS.

#### Model 2 — step-by-step setup (remote PyHSM, same region)

This section walks through every step required to connect VectorLedger on
Server A to PyHSM running on Server B, on the same-region private subnet.

**Prerequisites:**
- Both servers are in the same AWS VPC (or equivalent private network).
- Server B has no public IP — only reachable via private subnet.
- `openssl` is available on whichever machine you use to generate certificates.

---

##### Step 1 — Generate TLS certificates

All three certificates (CA, PyHSM server, VectorLedger client) can be
generated on any machine and then distributed. Run these commands once —
treat the CA key (`ca.key`) with the same care as a root password.

```bash
# 1a. Create the Certificate Authority
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
    -subj "/CN=VectorLedger-PyHSM-CA" \
    -out ca.crt

# 1b. Create the PyHSM server certificate
#     Replace 10.0.1.50 with Server B's actual private IP.
openssl genrsa -out pyhsm-server.key 4096
openssl req -new -key pyhsm-server.key \
    -subj "/CN=pyhsm.internal" \
    -out pyhsm-server.csr
openssl x509 -req -in pyhsm-server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 3650 -sha256 \
    -extfile <(printf "subjectAltName=IP:10.0.1.50,DNS:pyhsm.internal") \
    -out pyhsm-server.crt

# 1c. Create the VectorLedger mTLS client certificate
openssl genrsa -out vledger-client.key 4096
openssl req -new -key vledger-client.key \
    -subj "/CN=vledger-client" \
    -out vledger-client.csr
openssl x509 -req -in vledger-client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 90 -sha256 \
    -out vledger-client.crt
```

> **90-day validity on the client cert is intentional.** Short-lived client
> certificates limit the blast radius if the private key is ever exposed.
> Set a calendar reminder to rotate before expiry (see
> [Rotating the client certificate](#rotating-the-client-certificate) below).

---

##### Step 2 — Distribute certificates

Copy the generated files to the correct server. Only the files each server
needs — never copy a private key to the wrong host.

**On Server B (PyHSM server):**

```bash
sudo mkdir -p /etc/pyhsm/tls
sudo cp ca.crt            /etc/pyhsm/tls/
sudo cp pyhsm-server.crt  /etc/pyhsm/tls/
sudo cp pyhsm-server.key  /etc/pyhsm/tls/
sudo chmod 600 /etc/pyhsm/tls/pyhsm-server.key
sudo chmod 644 /etc/pyhsm/tls/ca.crt /etc/pyhsm/tls/pyhsm-server.crt
```

**On Server A (VectorLedger server):**

```bash
sudo mkdir -p /etc/vledger/pyhsm
sudo cp ca.crt             /etc/vledger/pyhsm/
sudo cp vledger-client.crt /etc/vledger/pyhsm/
sudo cp vledger-client.key /etc/vledger/pyhsm/
sudo chmod 600 /etc/vledger/pyhsm/vledger-client.key
sudo chmod 644 /etc/vledger/pyhsm/ca.crt /etc/vledger/pyhsm/vledger-client.crt
```

---

##### Step 3 — Open the security group

In your AWS console (or equivalent), add an inbound rule to Server B's
security group:

| Field | Value |
|---|---|
| Type | Custom TCP |
| Port | 8443 |
| Source | Server A's security group ID (or its private IP /32) |

No other inbound rule is needed on Server B. There must be no public IP on
Server B and no 0.0.0.0/0 rule for port 8443.

---

##### Step 4 — Start PyHSM in remote (TLS) mode on Server B

PyHSM must be told to listen on a TCP port with TLS instead of the default
Unix socket. Supply the server certificate, key, and CA cert via environment
variables or the flags your PyHSM version supports:

```bash
PYHSM_MASTER_PASSWORD="<your-pyhsm-password>" \
PYHSM_KEYSTORE_PATH="/var/lib/pyhsm/pyhsm-keystore.enc" \
PYHSM_AUDIT_LOG_PATH="/var/log/pyhsm/pyhsm-audit.jsonl" \
PYHSM_TLS_CERT="/etc/pyhsm/tls/pyhsm-server.crt" \
PYHSM_TLS_KEY="/etc/pyhsm/tls/pyhsm-server.key" \
PYHSM_TLS_CA="/etc/pyhsm/tls/ca.crt" \
PYHSM_LISTEN="0.0.0.0:8443" \
npx tsx ~/PyHSM/pyhsm-ts/process.ts
```

Confirm it is listening (run on Server B):

```bash
ss -tlnp | grep 8443
# LISTEN  0  128  0.0.0.0:8443  ...
```

Confirm it is reachable from Server A (run on Server A):

```bash
# Replace 10.0.1.50 with Server B's private IP
nc -zv 10.0.1.50 8443
# Connection to 10.0.1.50 8443 port [tcp/*] succeeded!
```

---

##### Step 5 — Initialise VectorLedger with remote-pyhsm

Run this on **Server A**. Replace `10.0.1.50` with Server B's private IP:

```bash
vledger init \
  --data-dir ./vledger-data \
  --key-source remote-pyhsm \
  --pyhsm-endpoint    https://10.0.1.50:8443 \
  --pyhsm-ca-cert     /etc/vledger/pyhsm/ca.crt \
  --pyhsm-client-cert /etc/vledger/pyhsm/vledger-client.crt \
  --pyhsm-client-key  /etc/vledger/pyhsm/vledger-client.key
```

Verify the backend was recorded correctly:

```bash
cat vledger-data/keys/key_source.json
```

Expected output:

```json
{
  "backend": "remote_py_hsm",
  "endpoint": "https://10.0.1.50:8443",
  "ca_cert": "/etc/vledger/pyhsm/ca.crt",
  "client_cert": "/etc/vledger/pyhsm/vledger-client.crt",
  "client_key": "/etc/vledger/pyhsm/vledger-client.key",
  "timeout_ms": 5000,
  "max_retries": 3,
  "caller_id": "vledger",
  "key_id": "vledger.master-key"
}
```

If `"backend"` shows `"env"` or `"file"`, the connection to PyHSM failed
during init and VectorLedger fell back silently. Check that PyHSM is running
on Server B, the security group rule is in place, and the cert paths are
correct, then delete `vledger-data/` and re-run init.

---

##### Step 6 — Start VectorLedger

```bash
vledger start --data-dir ./vledger-data
```

On every start, VectorLedger connects to the remote PyHSM, decrypts the
master key blob, uses the key briefly for derivation, and immediately
zeroizes it from memory. If PyHSM is unreachable, startup fails closed — it
never falls back to a weaker key source.

---

##### Using environment variables instead of baking paths into key_source.json

If you prefer to inject cert paths at deploy time (e.g. via container
environment variables or a secrets manager), set these before running
`vledger init` or `vledger start`:

```bash
export PYHSM_ENDPOINT=https://10.0.1.50:8443
export PYHSM_CA_CERT=/etc/vledger/pyhsm/ca.crt
export PYHSM_CLIENT_CERT=/etc/vledger/pyhsm/vledger-client.crt
export PYHSM_CLIENT_KEY=/etc/vledger/pyhsm/vledger-client.key

vledger init --key-source remote-pyhsm --data-dir ./vledger-data
```

Environment variables override the corresponding fields in `key_source.json`
at runtime — useful for rotating cert paths without modifying the config file.

---

##### Rotating the client certificate

The mTLS client certificate should be rotated before it expires (90-day
validity recommended). No data migration is required — only the transport
credential changes.

```bash
# 1. Generate a new client cert signed by the same CA
openssl genrsa -out vledger-client-new.key 4096
openssl req -new -key vledger-client-new.key \
    -subj "/CN=vledger-client" -out vledger-client-new.csr
openssl x509 -req -in vledger-client-new.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 90 -sha256 -out vledger-client-new.crt

# 2. Copy the new cert and key to Server A
sudo cp vledger-client-new.crt /etc/vledger/pyhsm/vledger-client.crt
sudo cp vledger-client-new.key /etc/vledger/pyhsm/vledger-client.key
sudo chmod 600 /etc/vledger/pyhsm/vledger-client.key

# 3. Restart VectorLedger to pick up the new certificate
#    (no vledger init needed — key_source.json paths are unchanged)
```

---

##### Quick-reference: full init command

For scripting or re-running init with all options explicit:

```bash
vledger init \
  --data-dir ./vledger-data \
  --key-source remote-pyhsm \
  --pyhsm-endpoint    https://10.0.1.50:8443 \
  --pyhsm-ca-cert     /etc/vledger/pyhsm/ca.crt \
  --pyhsm-client-cert /etc/vledger/pyhsm/vledger-client.crt \
  --pyhsm-client-key  /etc/vledger/pyhsm/vledger-client.key \
  --pyhsm-timeout-ms  5000 \
  --pyhsm-max-retries 3
```

---

#### Rotating keys on a remote PyHSM

```bash
vledger rotate-keys \
  --data-dir ./vledger-data \
  --pyhsm-endpoint    https://10.0.1.50:8443 \
  --pyhsm-ca-cert     /etc/vledger/pyhsm/ca.crt \
  --pyhsm-client-cert /etc/vledger/pyhsm/vledger-client.crt \
  --pyhsm-client-key  /etc/vledger/pyhsm/vledger-client.key
```

#### Replay-attack prevention (Model 2)

Every request sent to a remote PyHSM over TLS includes two additional fields that PyHSM should validate:

| Field | Value | Purpose |
|---|---|---|
| `requestId` | UUID v4 | PyHSM rejects duplicate IDs within its replay window (recommended: 5 min) |
| `timestamp` | RFC 3339 UTC | PyHSM rejects requests more than 2 minutes stale or in the future |

These fields are injected automatically by VectorLedger — no configuration required. They are not present on Model 1 (local socket) requests, where replay is not a meaningful threat.

#### Windows

PyHSM uses TCP instead of a Unix socket on Windows. Start the daemon with `PYHSM_TCP_PORT` and pass the TCP address to VectorLedger:

```powershell
$env:PYHSM_MASTER_PASSWORD = "your-password"
$env:PYHSM_TCP_PORT = 7777
npx tsx ~/PyHSM/pyhsm-ts/process.ts

# Then init (Model 1, TCP loopback):
vledger init --key-source pyhsm --pyhsm-socket 127.0.0.1:7777
```

#### Key Source Backends summary

| Backend | `--key-source` | Key never on disk | External dependency |
|---|---|---|---|
| **PyHSM — local** (recommended, Model 1) | `pyhsm` | ✓ | PyHSM daemon on same host |
| **PyHSM — remote** (production, Model 2) | `remote-pyhsm` | ✓ | PyHSM daemon on private subnet + TLS certs |
| Environment variable | `env` | ✗ (in env) | None |
| Disk file | `file` | ✗ | None |
| HashiCorp Vault | `vault` | ✓ | Vault server + token |
| AWS KMS | `aws_kms` | ✓ | AWS credentials + KMS key |

---

## Licensing

VectorLedger uses a tiered license model. The binary enforces feature availability at startup by verifying a signed `license.json` file in your data directory. If no license file is present, the engine runs in **Free** tier mode.

Licenses are issued by VectorGuard Labs. After purchasing a subscription at [vectorguardlabs.com/pricing](https://vectorguardlabs.com/pricing), your `license.json` is generated automatically and delivered to the email address on your account.

### Pricing

| Tier | Price | Best for |
|---|---|---|
| **Free** | $0 / month | Development, evaluation, internal tools |
| **Starter** | $199 / month | Early-stage teams that need PostgreSQL client compatibility |
| **Growth** | $999 / month | Production fintechs and SaaS companies under SOC 2 or PCI-DSS |
| **Enterprise** | Contact Sales | Banks, payment processors, PCI-DSS Level 1, hardware HSM requirements |

Annual billing available on all paid tiers — pay for 10 months, get 12.
Contact [sales@vectorguardlabs.com](mailto:sales@vectorguardlabs.com) for multi-instance or custom pricing.

### What each tier includes

| Feature | Free | Starter | Growth | Enterprise |
|---|---|---|---|---|
| Core ledger + SQL REPL | ✓ | ✓ | ✓ | ✓ |
| AES-256-GCM encryption at rest | ✓ | ✓ | ✓ | ✓ |
| BLAKE3 hash chain + Merkle proofs | ✓ | ✓ | ✓ | ✓ |
| Four-eyes dual-control workflow | ✓ | ✓ | ✓ | ✓ |
| WORM audit log + chain verification | ✓ | ✓ | ✓ | ✓ |
| Backup & restore | ✓ | ✓ | ✓ | ✓ |
| Audit log export (date range) | 30 days | 90 days | Unlimited | Unlimited |
| PostgreSQL wire protocol (`--pgwire`) | ✗ | ✓ | ✓ | ✓ |
| WAL replication (hot standby) | ✗ | ✗ | ✓ | ✓ |
| Compliance reports (SOC 2 / PCI-DSS) | ✗ | ✗ | ✓ | ✓ |
| Hardware HSM PKCS#11 integration | ✗ | ✗ | ✗ | ✓ |
| Multi-node deployment | ✗ | ✗ | ✗ | ✓ |

### Installing a license

Place the `license.json` file provided by VectorGuard Labs into your data directory:

```bash
cp acme-license.json ./vledger-data/license.json
```

The server reads and verifies it on every start. No restart is required if you drop in a new license while the server is stopped — it is re-read at next startup.

Check the active license at any time:

```bash
vledger license --data-dir ./vledger-data
```

Example output (Growth tier):

```
── VectorLedger License ────────────────────────
  Tier       : Growth
  Licensee   : Acme Corp
  Email      : ops@acme.com
  Issued     : 2026-08-07
  Expires    : 2027-08-07
  Status     : Active (365 days remaining)
──────────────────────────────────────────────────
  Features:
    ✓ pgwire
    ✓ replication
    ✗ hsm
    ✓ compliance_report
    ✓ audit_export_unlimited
    ✗ multi_node
```

### Attempting to use a gated feature without entitlement

```
$ vledger start --data-dir ./vledger-data --pgwire
Error: Feature 'pgwire' is not available on your Free license.
Upgrade at https://vectorguardlabs.com/pricing

$ vledger start --data-dir ./vledger-data --pgwire   # on Starter
✓ pgwire enabled

$ vledger start --data-dir ./vledger-data            # replication on Starter
Error: Feature 'replication' is not available on your Starter license.
Upgrade at https://vectorguardlabs.com/pricing
```

### License expiry

The server startup banner shows days remaining when a signed license is active. A warning is printed when fewer than 30 days remain. Contact [sales@vectorguardlabs.com](mailto:sales@vectorguardlabs.com) to renew.

---

## Production Deployment Checklist

Before putting VectorLedger in front of production traffic:

- [ ] PyHSM daemon running with a persistent, backed-up keystore (`PYHSM_KEYSTORE_PATH` points to a durable location)
- [ ] `vledger init` completed with `--key-source pyhsm` (Model 1) or `--key-source remote-pyhsm` (Model 2)
- [ ] `key_source.json` shows `"backend": "py_hsm"` or `"backend": "remote_py_hsm"` — not `"env"` or `"file"`
- [ ] `keys/MASTER_KEY_PLACEHOLDER.txt` deleted (its presence fails the PCI-DSS compliance check)
- [ ] Admin credential file read, password changed, and `catalog/.admin_initial_credentials` deleted
- [ ] Data directory permissions locked (`chmod 700` on `vledger-data/` and all subdirectories)
- [ ] Volume encryption enabled on the disk hosting `vledger-data/`
- [ ] Replace the self-signed TLS certificate with a CA-signed one — place it at `keys/server.crt` and `keys/server.key`, then start with `--tls-cert-path` and `--tls-key-path`
- [ ] Configure replication with a secondary node (`replication.json`) or document a backup-based HA strategy
- [ ] Install a valid `license.json` for your paid tier — Free tier does not include replication or compliance reports (`vledger license --data-dir ./vledger-data` to confirm tier and expiry)
- [ ] Test a full backup and restore drill: `vledger backup` → `vledger restore` → `vledger verify`
- [ ] Schedule regular `vledger backup` runs (cron or your orchestrator)
- [ ] Schedule regular `vledger verify` runs (recommended: after each backup)
- [ ] Ship `audit/audit.log` to an append-only off-host destination in real time
- [ ] Run compliance reports and confirm zero FAIL items: `vledger compliance-report --standard pci-dss`

**Additional checklist items for Model 2 (remote PyHSM):**

- [ ] PyHSM server has no public IP — accessible only via private subnet
- [ ] Security group / firewall allows VectorLedger → PyHSM (port 8443) only — no other inbound
- [ ] CA certificate, client certificate, and client key stored at paths that survive reboots and are mode `0600`
- [ ] `PYHSM_CA_CERT`, `PYHSM_CLIENT_CERT`, `PYHSM_CLIENT_KEY` environment variables set (or paths baked into `key_source.json`)
- [ ] mTLS client certificate has a short validity period (90 days recommended) with a rotation schedule
- [ ] PyHSM configured to validate `requestId` (reject duplicates within 5-minute window) and reject stale `timestamp` values
- [ ] Verified that `vledger start` fails cleanly when PyHSM is unreachable — never falls back silently

---

## Testing & Verification

This section documents every testing mechanism available in VectorLedger. Run these commands on your own server to independently verify correctness, durability, and tamper-evidence before deploying to production.

### Prerequisites

Start the server before running any tests that require a live connection:

```bash
export VectorLedger_MASTER_KEY=$(openssl rand -hex 32)
./target/release/vledger init --key-source env
cat vledger-data/catalog/.admin_initial_credentials   # note the generated password
./target/release/vledger start --max-connections 200 --pgwire &
sleep 5
```

---

### 1. Benchmark Tests (TPS)

Measures transactions per second across INSERT, SELECT, and mixed workloads. Restart the server between each workload run to clear connection state.

```bash
# INSERT workload — write heavy
cargo run --release --package vledger-bench -- \
    --username admin --password <password> \
    --clients 50 --transactions 5000 --workload insert

# Restart between runs
pkill vledger && sleep 2 && ./target/release/vledger start --max-connections 200 --pgwire &
sleep 5

# SELECT workload — read heavy
cargo run --release --package vledger-bench -- \
    --username admin --password <password> \
    --clients 50 --transactions 5000 --workload select

pkill vledger && sleep 2 && ./target/release/vledger start --max-connections 200 --pgwire &
sleep 5

# MIXED workload — 70% INSERT, 30% SELECT
cargo run --release --package vledger-bench -- \
    --username admin --password <password> \
    --clients 50 --transactions 5000 --workload mixed
```

**Recommended instance:** AWS `c7g.xlarge` (Graviton3, 4 vCPU, 8 GB RAM). Avoid `t3`/`t4g` burstable instances — CPU credit throttling produces misleading results.

---

### 2. PostgreSQL Wire Protocol Compatibility

Verifies that VectorLedger accepts connections from standard PostgreSQL clients. Start the server with `--pgwire` and connect with `psql`:

```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

Run these queries to confirm compatibility:

```sql
SELECT 1;
SELECT version();
SELECT current_user();
SELECT current_database();
SHOW server_version;
SHOW server_encoding;
SHOW TimeZone;
SELECT COUNT(*) FROM ledger;
SELECT * FROM ledger LIMIT 5;
SELECT * FROM accounts LIMIT 5;
SELECT VERIFY_CHAIN();
BEGIN;
SELECT COUNT(*) FROM ledger;
COMMIT;
```

---

### 3. Concurrent Transaction Test

Runs the benchmark in one terminal while querying live from another to confirm no torn reads, duplicate sequences, or chain failures under concurrent load.

**Terminal 1:**
```bash
cargo run --release --package vledger-bench -- \
    --username admin --password <password> \
    --clients 10 --transactions 1000 --workload mixed &
```

**Terminal 2 (while benchmark runs):**
```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

```sql
SELECT COUNT(*) FROM ledger;
SELECT COUNT(DISTINCT sequence) FROM ledger;  -- must equal COUNT(*)
SELECT VERIFY_CHAIN();                         -- must return OK
```

---

### 4. WAL Corruption Test

Confirms that VectorLedger detects and rejects corrupted WAL data during recovery.

```bash
pkill vledger && sleep 2

# Corrupt a byte in the last WAL segment
python3 -c "
import os
wal_dir = 'vledger-data/wal'
segments = sorted(os.listdir(wal_dir))
target = os.path.join(wal_dir, segments[-1])
size = os.path.getsize(target)
mid = size // 2
with open(target, 'r+b') as f:
    f.seek(mid)
    b = f.read(1)
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))
print('WAL corruption written at offset', mid)
"

# Attempt restart — server will reject or truncate at the corrupt record
nohup ./target/release/vledger start --max-connections 200 --pgwire &
sleep 10
cat nohup.out | tail -10

# Restore the WAL (XOR with 0xFF again to flip back)
python3 -c "
import os
wal_dir = 'vledger-data/wal'
segments = sorted(os.listdir(wal_dir))
target = os.path.join(wal_dir, segments[-1])
size = os.path.getsize(target)
mid = size // 2
with open(target, 'r+b') as f:
    f.seek(mid)
    b = f.read(1)
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))
print('WAL restored at offset', mid)
"

# Restart and verify full recovery
pkill vledger && sleep 2
nohup ./target/release/vledger start --max-connections 200 --pgwire &
sleep 120  # wait for WAL replay
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

```sql
SELECT COUNT(*) FROM ledger;
SELECT VERIFY_CHAIN();
```

---

### 5. Logical Tampering Test

Confirms that the BLAKE3 hash chain detects in-memory data manipulation. `TAMPER_ENTRY` mutates an entry's description without updating its hash — simulating what a malicious actor would need to do to falsify a record.

```sql
-- Establish baseline
SELECT VERIFY_CHAIN();

-- Tamper with a specific entry
SELECT TAMPER_ENTRY(999999, 'THIS RECORD HAS BEEN FALSIFIED');

-- Hash chain must now detect the mutation
SELECT VERIFY_CHAIN();
-- Expected: ERROR: INTEGRITY FAILURE: Hash chain broken at sequence 999999

-- Confirm the specific entry is marked corrupted
SELECT VERIFY_ENTRY(999999);
-- Expected: status = CORRUPTED
```

---

### 6. Crash / Restart Recovery Test

Confirms that committed transactions survive a hard kill mid-write and that uncommitted transactions are rolled back cleanly.

```bash
# Start benchmark in background
cargo run --release --package vledger-bench -- \
    --username admin --password <password> \
    --clients 10 --transactions 10000 --workload insert &

BENCH_PID=$!

# Hard-kill the server while writes are in flight
sleep 10
kill -9 $(pgrep -f "vledger start")
echo "Server killed mid-write"
wait $BENCH_PID

# Restart — WAL replay recovers all committed transactions
nohup ./target/release/vledger start --max-connections 200 --pgwire &
sleep 120
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

```sql
SELECT COUNT(*) FROM ledger;
SELECT VERIFY_CHAIN();
-- Chain must be OK. Some in-flight transactions may be missing (expected).
-- All committed transactions must be present and valid.
```

---

### 7. Integrity Self-Test Suite

The built-in self-test runs five automated phases against a completely isolated temporary database. Your production data is never touched.

```bash
# Quick smoke test — 1K entries, instant
./target/release/vledger verify --self-test --entries 1000 2>/dev/null

# Dev run — 10K entries, ~5 seconds
./target/release/vledger verify --self-test --entries 10000 2>/dev/null

# Standard — 100K entries, ~30-60 seconds (default)
./target/release/vledger verify --self-test 2>/dev/null

# Enterprise stress test — 1M entries, ~10-15 minutes
./target/release/vledger verify --self-test --entries 1000000 2>/dev/null

# Keep the test database for manual inspection
./target/release/vledger verify --self-test --entries 10000 --keep-data 2>/dev/null
```

**What the self-test verifies:**

| Phase | What it tests |
|---|---|
| A — Baseline | Inserts N deterministic entries with varied amounts, verifies the hash chain immediately |
| B — WAL Integrity | Corrupts a WAL byte, confirms server detects and rejects it, restores the byte |
| C — Crash Recovery | Reopens the database, confirms 100% of entries recovered with chain intact |
| D — Logical Integrity | Mutates an entry in memory without updating its hash, confirms `VERIFY_CHAIN()` detects it |
| E — Entry Verification | Spot-checks five entries spread across the ledger with `VERIFY_ENTRY()` |

**Inspecting the self-test database manually:**

```bash
# Run with --keep-data to retain the database after the test
./target/release/vledger verify --self-test --entries 10000 --keep-data 2>/dev/null

# Note the directory printed at the end, then start a server against it
cat /path/to/vledger-self-test-<timestamp>/catalog/.admin_initial_credentials

./target/release/vledger start \
    --data-dir /path/to/vledger-self-test-<timestamp> \
    --max-connections 10 --pgwire &

sleep 5

psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

```sql
SELECT COUNT(*) FROM ledger;
SELECT VERIFY_CHAIN();
SELECT VERIFY_ENTRY(1);
SELECT VERIFY_ENTRY(5000);
SELECT VERIFY_ENTRY(10000);
\x
SELECT * FROM ledger ORDER BY sequence LIMIT 10;
SELECT * FROM ledger WHERE sequence = 5000;
SELECT * FROM ledger_lines WHERE sequence = 5000;
```

---

### 8. Chain Range Verification

Verify a specific range of entries rather than the full chain:

```sql
-- Verify entries 1 through 100,000
SELECT VERIFY_CHAIN(1, 100000);

-- Verify from 1,000,000 to end
SELECT VERIFY_CHAIN(1000000);

-- Verify the full chain
SELECT VERIFY_CHAIN();
```

---

### 9. Direct SQL Queries (without psql)

Query the production database directly from the terminal without starting psql:

```bash
./target/release/vledger sql --query "SELECT COUNT(*) FROM ledger"
./target/release/vledger sql --query "SELECT VERIFY_CHAIN()"
./target/release/vledger sql --query "SELECT * FROM ledger WHERE sequence = 500000"
./target/release/vledger sql --query "SELECT VERIFY_ENTRY(500000)"
./target/release/vledger sql --query "SELECT VERIFY_CHAIN(1000000, 1100000)"
./target/release/vledger sql --query "SELECT * FROM ledger LIMIT 10"
```

Each `vledger sql` invocation opens a fresh TLS connection, authenticates, runs the query, and closes. There is no persistent session between calls, so credentials are prompted every time by default.

**To avoid retyping credentials on every query, set environment variables:**

```bash
export VLEDGER_CLI_USERNAME=admin
export VLEDGER_CLI_PASSWORD=<your-password>

# All subsequent queries run without prompting
./target/release/vledger sql --query "SELECT COUNT(*) FROM ledger"
./target/release/vledger sql --query "SELECT VERIFY_CHAIN()"
./target/release/vledger sql --query "SELECT VERIFY_ENTRY(500000)"
```

**Alternatively, use psql for an interactive session** — authenticate once and run as many queries as you want:

```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
# Type \q to exit
```

---

## Running the Test Suite

```bash
# Unit and integration tests
cargo test --workspace

# Self-test (exercises the full engine end-to-end)
cargo run --release -- self-test
cargo run --release -- self-test-phase3

# Security audit (checks for known vulnerabilities in dependencies)
cargo install cargo-audit
cargo audit
```

---

## License

VectorLedger is licensed under the [Business Source License 1.1 (BUSL-1.1)](https://spdx.org/licenses/BUSL-1.1.html).

The source code is available for inspection, development, and non-production use. Production use requires a commercial license. Contact [engineering@vectorguardlabs.com](mailto:engineering@vectorguardlabs.com) for licensing inquiries.

---

## Built With

| Component | Library |
|---|---|
| Async runtime | [tokio](https://tokio.rs) |
| Symmetric encryption | [aes-gcm](https://docs.rs/aes-gcm) (AES-256-GCM) |
| Hashing | [blake3](https://github.com/BLAKE3-team/BLAKE3) |
| Signing | [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) |
| Key derivation | [hkdf](https://docs.rs/hkdf) |
| Password hashing | [argon2](https://docs.rs/argon2) |
| TLS | [rustls](https://github.com/rustls/rustls) |
| SQL parsing | [sqlparser](https://github.com/sqlparser-rs/sqlparser-rs) |
| Secret management | [reqwest](https://github.com/seanmonstar/reqwest) (Vault / AWS KMS) |

---

*VectorGuard Labs — financial infrastructure that proves its own integrity.*
