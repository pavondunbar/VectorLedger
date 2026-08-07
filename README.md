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
| macOS or Linux | — | Windows is not supported |
| Git | Any recent | To clone the repository |

No other runtime dependencies are required. All cryptographic libraries are statically linked via Cargo.

---

## Installation

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
git clone https://github.com/vectorguardlabs/vectorledger.git
cd vectorledger
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

### 1. Set the master encryption key

VectorLedger requires a 256-bit master key for encrypting data at rest. For development, set it as an environment variable:

```bash
export VectorLedger_MASTER_KEY="$(openssl rand -hex 32)"
```

For production, see [Key Source Backends](#key-source-backends) below.

### 2. Initialise the database

```bash
vledger init --data-dir ./vledger-data
```

This creates the directory structure, generates an Ed25519 signing keypair, and writes `key_source.json`. On first run you will see:

```
✓ VectorLedger initialised at: ./vledger-data
  Signing key (first 16 hex): 3f8a1c...
  Key source stored in: keys/key_source.json
```

### 3. Start the server

```bash
vledger start --data-dir ./vledger-data --bind 127.0.0.1:5433
```

The first start generates an initial admin password and prints it once:

```
╔══════════════════════════════════════════════════════╗
║  VectorLedger — Initial Admin Credentials          ║
║  Username : admin                                    ║
║  Password : Xk9mP2qRvLnJwBcY7dZs4fHt              ║
║  CHANGE THIS IMMEDIATELY with `vledger user set-password` ║
╚══════════════════════════════════════════════════════╝
── VectorLedger ────────────────────────────────
  Listening  : 127.0.0.1:5433  (TLS 1.3)
  Data dir   : ./vledger-data
  Protocol   : newline-delimited JSON
──────────────────────────────────────────────────
```

### 4. Run your first queries

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

### 5. Also start the PostgreSQL wire-protocol listener

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

If you lose the admin password, or need to wipe the database and start fresh, delete the data directory and re-initialise:

```bash
# Stop the server first (Ctrl-C in the terminal where it is running)

rm -rf ./vledger-data

export VectorLedger_MASTER_KEY="$(openssl rand -hex 32)"
vledger init --data-dir ./vledger-data
vledger start --data-dir ./vledger-data --bind 127.0.0.1:5433
```

The first `start` after a fresh `init` prints a new admin password. Copy it before doing anything else.

A few things to keep in mind:

- Deleting `vledger-data` is **permanent and irreversible**. All ledger entries, accounts, audit logs, and user accounts are gone. Only do this on a database that either has no data worth keeping, or has already been backed up with `vledger backup`.
- The `VectorLedger_MASTER_KEY` you generate is a new key, unrelated to the old one. If you had encrypted data in the old directory, it cannot be decrypted with the new key.
- For production, store the master key in Vault or AWS KMS (see [Key Source Backends](#key-source-backends)) so it survives shell session restarts without being re-generated.

If you just want to reset the admin password without wiping data, use `vledger user set-password` while the server is not running (direct mode reads the catalog directly):

```bash
# Stop the server first, then:
vledger user set-password --username admin --data-dir ./vledger-data
# New password: <type new password>
# Confirm password: <type again>
```

---

## CLI Reference

### `vledger init`

Initialise a new database.

```bash
vledger init [OPTIONS]
  --data-dir <PATH>       Data directory (default: ./vledger-data)
  --force                 Reinitialise an existing database
  --key-source <BACKEND>  env | file | vault | aws_kms  (default: env)
  --vault-addr <URL>      Vault server address
  --vault-mount <MOUNT>   Vault KV v2 mount path (default: secret)
  --vault-path <PATH>     Vault secret path (default: vledger/master_key)
  --kms-key-id <ARN>      AWS KMS key ARN or alias
  --kms-region <REGION>   AWS region (default: us-east-1)
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

Place a signed `license.json` in your data directory to unlock paid features. If no file is present, the engine runs in Free tier. See the [Licensing](#licensing) section for the full tier comparison and feature list.

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

## Licensing

VectorLedger uses a tiered license model. The binary enforces feature availability at startup by verifying a signed `license.json` file in your data directory. If no license file is present, the engine runs in **Free** tier mode.

### Tiers

| Feature | Free | Growth | Enterprise |
|---|---|---|---|
| Core ledger + SQL REPL | ✓ | ✓ | ✓ |
| Self-tests | ✓ | ✓ | ✓ |
| Backup & restore | ✓ | ✓ | ✓ |
| Compliance reports | ✓ | ✓ | ✓ |
| PostgreSQL wire protocol (`--pgwire`) | ✗ | ✓ | ✓ |
| WAL replication | ✗ | ✓ | ✓ |
| HSM PKCS#11 integration | ✗ | ✗ | ✓ |
| Unlimited audit log export | ✗ | ✓ | ✓ |
| Multi-node deployment | ✗ | ✗ | ✓ |

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

Example output:

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

### Attempting to use a gated feature without a license

```
$ vledger start --data-dir ./vledger-data --pgwire
Error: Feature 'pgwire' is not available on your Free license.
Upgrade at https://vectorguardlabs.com/pricing
```

### License expiry

The server startup banner shows days remaining when a signed license is active. A warning is printed when fewer than 30 days remain. Contact [sales@vectorguardlabs.com](mailto:sales@vectorguardlabs.com) to renew.

---

## Production Deployment Checklist

Before putting VectorLedger in front of production traffic:

- [ ] Replace the self-signed TLS certificate with a CA-signed one and set `tls_cert_path` / `tls_key_path`
- [ ] Switch master key source from `env`/`file` to `vault` or `aws_kms`
- [ ] Delete `keys/MASTER_KEY_PLACEHOLDER.txt` (its presence will fail the PCI-DSS compliance check)
- [ ] Set up HSM key management and run `vledger init --hsm-backend soft|aws|azure`
- [ ] Configure replication with a secondary node (`replication.json`)
- [ ] Install a valid `license.json` in the data directory (`vledger license` to confirm tier and expiry)
- [ ] Schedule regular `vledger backup` runs
- [ ] Schedule regular `vledger verify` runs (recommended: after each backup)
- [ ] Set `VLEDGER_CLI_USER` and `VLEDGER_CLI_PASSWORD` in your CI environment rather than using the initial admin password
- [ ] Change the initial admin password: `vledger sql --query "ALTER USER admin SET PASSWORD 'newpassword'"`
- [ ] Review the compliance report: `vledger compliance-report --standard pci-dss`

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
