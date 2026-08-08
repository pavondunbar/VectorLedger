# VectorLedger

**A cryptographically verifiable financial database engine built for institutions that can't afford to trust their own database.**

VectorLedger is a purpose-built, append-only financial ledger written entirely in Rust. Every journal entry is linked by a tamper-evident BLAKE3 hash chain, every page of data is encrypted at rest with AES-256-GCM, and every query result can carry a cryptographic Merkle proof that the returned data has not been modified since it was written. Corrections to past records are impossible — even by a DBA with full disk access.

Built by [VectorGuard Labs](https://vectorguardlabs.com).

---

## Why VectorLedger?

Traditional relational databases treat audit trails as an afterthought: triggers that can be disabled, log tables that can be truncated, and backup files that can be silently replaced. For organizations operating under SOC 2, PCI-DSS, financial regulation, or internal zero-trust policies, this is not good enough.

VectorLedger makes tampering **cryptographically detectable**:

- A row written five years ago cannot be changed without invalidating every hash in the chain from that point to the present.
- Every SELECT response optionally carries a Merkle proof that any client can independently verify.
- The audit log is WORM-append-only — each event is hashed into the next, forming a second independent tamper-evident chain.
- The compliance engine generates SOC 2 Type II and PCI-DSS v4 evidence reports as executable code, not documentation.

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
- Every write is **fsync'd** before returning `Ok` — no silent data loss on crash
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

### Secrets Management
- Master key can be sourced from:
  - Environment variable (`VectorLedger_MASTER_KEY`)
  - File on disk (development only)
  - **HashiCorp Vault KV v2** (`VAULT_TOKEN` read at runtime; TTL checked and logged at startup)
  - **AWS KMS** `GenerateDataKey` (ciphertext blob cached with HMAC-SHA256 integrity check)
- Configuration file (`key_source.json`) contains only metadata — the key itself never appears in config

### Replication
- Synchronous hot-standby WAL replication
- Three security layers: TLS 1.3, optional mTLS, BLAKE3-keyed HMAC challenge-response inside TLS
- Replica verifies BLAKE3 hash of every received WAL record before applying it
- Exponential reconnect backoff with faster escalation on auth failures
- Replication secret stored at `0o600` on disk, generated from `OsRng`

### Compliance Reporting
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

These numbers represent a **conservative baseline on development
hardware**. Production deployments on Linux with NVMe SSD are expected
to deliver significantly higher throughput — fsync latency on NVMe
(50–200 µs) is 10–50× faster than a laptop SSD, which is the primary
bottleneck in the write path.

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
│          │  fsync every │ │  AES-256-GCM │                  │
│          │  commit      │ │  per-table   │                  │
│          │  CRC-32      │ │  encryption  │                  │
│          └─────────────┘ └──────────────┘                  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Audit Log   │  │  HSM Client  │  │  Replication     │  │
│  │  WORM BLAKE3 │  │  SoftHSM /   │  │  WAL streaming   │  │
│  │  chain       │  │  AWS / Azure │  │  TLS + HMAC      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

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

> **Never run `vledger init` without `--key-source pyhsm` in production.** The default without this flag uses an environment variable backend which stores key material in your shell environment.

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

-- Query all entries
SELECT * FROM ledger;
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

## CLI Reference

### `vledger init`

Initialise a new database.

```bash
vledger init [OPTIONS]
  --data-dir <PATH>       Data directory (default: ./vledger-data)
  --force                 Reinitialise an existing database
  --key-source <BACKEND>  env | file | vault | aws_kms | pyhsm  (default: pyhsm)
  --vault-addr <URL>      Vault server address
  --vault-mount <MOUNT>   Vault KV v2 mount path (default: secret)
  --vault-path <PATH>     Vault secret path (default: vledger/master_key)
  --kms-key-id <ARN>      AWS KMS key ARN or alias
  --kms-region <REGION>   AWS region (default: us-east-1)
  --pyhsm-socket <PATH>   PyHSM Unix socket path (default: /tmp/pyhsm.sock)
  --pyhsm-caller-id <ID>  Caller ID written to PyHSM audit log (default: vledger)
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
vledger rotate-keys --data-dir <PATH> [--hsm-socket <PATH>] [--caller-id <ID>]
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
| `PYHSM_SOCKET_PATH` | `/tmp/pyhsm.sock` | Unix socket path the daemon listens on. |
| `PYHSM_CALLER_SECRET` | — | Optional shared secret for IPC caller authentication. |
| `PYHSM_RATE_LIMIT` | `100` | Max operations per rate window. |
| `PYHSM_RATE_WINDOW_MS` | `60000` | Rate window in milliseconds. |

#### How VectorLedger uses PyHSM across restarts

| Event | What happens |
|---|---|
| First `vledger init --key-source pyhsm` | VectorLedger generates a 32-byte master key in-process, asks PyHSM to encrypt it, stores only the encrypted blob at `vledger-data/keys/pyhsm_master_key.enc` with an HMAC-SHA256 integrity seal |
| Every `vledger start` | HMAC verified locally first, blob sent to PyHSM for decryption, plaintext key used briefly for key derivation then immediately zeroized from memory |
| PyHSM daemon not running at startup | `vledger start` fails immediately with a clear error — no data is touched |
| Cache file tampered | HMAC check fails, startup aborts before any IPC call |

#### Windows

PyHSM uses TCP instead of a Unix socket on Windows. Start the daemon with `PYHSM_TCP_PORT` and pass the TCP address to VectorLedger:

```powershell
$env:PYHSM_MASTER_PASSWORD = "your-password"
$env:PYHSM_TCP_PORT = 7777
npx tsx ~/PyHSM/pyhsm-ts/process.ts

# Then init:
vledger init --key-source pyhsm --pyhsm-socket 127.0.0.1:7777
```

#### Key Source Backends summary

| Backend | `--key-source` | Key never on disk | External dependency |
|---|---|---|---|
| **PyHSM** (recommended) | `pyhsm` | ✓ | PyHSM daemon running |
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
| **Starter** | $99 / month | Early-stage teams that need PostgreSQL client compatibility |
| **Growth** | $399 / month | Production fintechs and SaaS companies under SOC 2 or PCI-DSS |
| **Enterprise** | $999 / month | Banks, payment processors, PCI-DSS Level 1, hardware HSM requirements |

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
- [ ] `vledger init` completed with `--key-source pyhsm` and `key_source.json` shows `"backend": "py_hsm"`
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
