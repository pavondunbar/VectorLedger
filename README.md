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
- **Append-only storage** — entries are never modified or deleted; corrections are made through explicit reversal entries that are themselves chained entries
- **BLAKE3 hash chain** — every journal entry contains `H(sequence || prev_hash || content_hash)`, forming an unbroken chain from first entry to last
- **Idempotency keys** — duplicate submissions for the same financial event are detected and returned without double-posting
- **Exposure limits** and **non-negative balance enforcement** configurable per account
- **Multi-domain** support — each account and entry is tagged to a legal entity or business domain
- **Hash-protected metadata** — every entry can carry an arbitrary JSON metadata blob (e.g. sender name, channel, status) that is included in `canonical_bytes()` and cannot be altered after posting without breaking the hash chain; indexed via SQLite FTS5 for instant full-text search
- **Settlement lifecycle** — entries support `Pending → Settled | Failed` status transitions stored as append-only events; the original entry row is never modified
- **Legal holds** — accounts can be placed under a legal hold, blocking all new entries, reversals, and settlement transitions until the hold is lifted
- **Reconciliation** — on-demand balance reconciliation recomputes all account balances from journal entries and compares against the running cache

### Financial Invariants Enforced at the Engine Level

VectorLedger enforces 16 financial invariants in code — not by policy or documentation. Every invariant is verified by the automated test suite on every release.

**Core double-entry rules:**
- Debits must equal credits on every entry — `UnbalancedEntry` returned if they differ, checked before any WAL write
- Every entry must have at least 2 lines (one debit, one credit) — `TooFewLines` if fewer
- Every amount must be non-zero — `ZeroAmount` enforced at the `Amount` type level (no float path exists to compile)

**Account validity:**
- Every account referenced in an entry must exist — `AccountNotFound`
- Closed accounts reject new entries — `AccountClosed`
- Currency on each line must match the account's registered currency — `CurrencyMismatch`

**Balance protection:**
- Asset and Expense accounts enforce non-negative balance (configurable per account) — `InsufficientFunds`
- Exposure limits: aggregate debit against a single account in one entry cannot exceed the account's configured limit — `ExposureLimitExceeded`

**Legal and compliance controls:**
- Accounts under legal hold block all new entries, reversals, and settlement transitions — `AccountUnderLegalHold`
- Entries against accounts requiring four-eyes approval must carry a second approver — `FourEyesRequired`

**Reversal rules:**
- Only `Posted` entries can be reversed — `CannotReverse` for any other status
- An entry can only be reversed once — `AlreadyReversed` on second attempt

**Cryptographic and structural integrity:**
- Sequence numbers are strictly monotonic with no gaps
- BLAKE3 hash chain maintained on every entry — `VERIFY_CHAIN()` detects any tampering
- WAL commits are Ed25519-signed — signature verification on replay detects substitution

**Asset precision:**
- Amounts for known currencies cannot exceed the maximum minor unit value for that currency's precision — `PrecisionViolation` (USD precision=2, BTC precision=8, ETH precision=18)

**Idempotency:**
- Duplicate entries with the same idempotency key are detected and skipped — `IdempotencyConflict`

**Global ledger equation:**
- `Σ(Assets + Expenses) == Σ(Liabilities + Equity + Income)` — verified by `check_financial_invariants()`

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
- Four built-in roles: `admin`, `operator`, `auditor`, `readonly`

| Role | SELECT | INSERT ledger | INSERT accounts | VERIFY | Admin ops |
|---|---|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `operator` | ✓ | ✓ | ✓ | ✓ | ✗ |
| `auditor` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `readonly` | ✓ | ✗ | ✗ | ✗ | ✗ |

- Privilege enforcement is applied to the **resolved query plan**, not raw SQL text — immune to comment/whitespace bypass attacks
- **Per-user domain filter** — user accounts can be restricted to a specific domain; the restriction is enforced at query execution time
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
- Events recorded: `server_started`, `auth_event` (every login success/failure), `query_executed` (every SQL statement), `entry_posted` (every committed transaction), `four_eyes_submitted/approved/rejected`, `backup_created`, `key_rotated`
- Export to JSON or CSV with optional date-range filtering via `vledger audit-export`
- **Tiered export limits** enforced by license: Free (30 days), Starter (90 days), Growth/Enterprise (unlimited)

### Cryptographic Audit Package

VectorLedger can generate a portable, self-contained cryptographic audit evidence package that any third party can verify independently — no database access, no server, no credentials required.

Three-tier design:

**Tier 1 — Commitment package** (default, fast at any scale)
```bash
vledger audit-package \
  --data-dir ./vledger-data \
  --tenant "Acme Financial" \
  --description "Q3 2026 regulatory audit" \
  --period-start 2026-07-01 \
  --period-end 2026-09-30 \
  --output audit-q3-2026.json
```
Computes the Merkle root over all entries in a single O(n) pass, signs it with the database Ed25519 key, and writes a compact JSON commitment. Completes in seconds regardless of ledger size.

**Tier 2 — On-demand entry proof** (prove one specific entry)
```bash
vledger audit-proof --data-dir ./vledger-data \
  --commitment audit.json \
  --sequence 406340 \
  --output entry-proof.json
```
Generates a single Merkle inclusion proof proving that entry 406340 belongs to the committed root. The auditor receives a self-contained file they can verify without database access.

**Tier 3 — Full export** (small ledgers only)
```bash
vledger audit-package --data-dir ./vledger-data --include-entries
```
Embeds all entries and per-entry proofs. Only practical for ledgers with fewer than ~10,000 entries.

**Verification** (no database access required):
```bash
vledger verify-audit-package --file audit.json
vledger verify-audit-package --file entry-proof.json
```

Output:
```
  [1/3] Content hash     ✓
  [2/3] Chain hash       ✓
  [3/3] Merkle proof     ✓

✓ VERIFIED — 1 entries, all checks passed.
  Merkle root : 804efb54ea31539a...
```

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

> **License requirement:** WAL replication requires a **Growth or Enterprise** license.

Synchronous hot-standby WAL replication with three independent security layers:

1. **TLS 1.3** on the replication channel
2. **Optional mTLS** — the primary can require a client certificate from each replica
3. **BLAKE3-keyed HMAC challenge-response** inside TLS before any WAL data is exchanged

Additional integrity guarantees:
- Replica verifies BLAKE3 hash of every received WAL record before applying it
- Exponential reconnect backoff (500 ms → 30 s) with faster escalation on auth failures
- **Divergence detection** via periodic `DivergenceCheckpoint` messages carrying a rolling BLAKE3 WAL chain hash

### Compliance Reporting

> **Important scope note:** VectorLedger generates machine-generated technical evidence supporting SOC 2 and PCI-DSS control assessments. This evidence is a technical input to an audit — it does not by itself make an organization compliant.

- **SOC 2 Type II** controls: CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.2, CC8.1, A1.1
- **PCI-DSS v4** controls: Req 2.2, 3.4, 3.5, 4.2, 7.1, 10.2, 10.3, 10.5, 11.5
- Reports are generated by running checks against real filesystem state — not pre-written text
- Output as Markdown or JSON; piped to a file with `--output`

### Backup and Restore
- Point-in-time backup creates an **AES-256-GCM encrypted** `.tar` archive with a BLAKE3 manifest
- Each file in the archive is encrypted with a unique per-backup key derived from the master key via HKDF-SHA256
- Private key material is **excluded** from backups — only the public signing key is archived
- Restore decrypts every file using the `.key` sidecar, then verifies each file's BLAKE3 hash against the manifest before completing

### Client SDKs
Native client libraries are included for three languages, all in `clients/`:

- Python — `clients/python/`
- TypeScript / Node.js — `clients/typescript/`
- Go — `clients/go/`

---

## Performance

### Memory allocator

VectorLedger uses **jemalloc** as its global allocator on Linux and macOS (via `tikv-jemallocator`). jemalloc aggressively returns freed memory to the OS after large working-set operations — in particular WAL recovery, where processing 25 M+ records with the default ptmalloc allocator causes ~7 GB of RSS to accumulate and never be returned.

---

Benchmarked on Apple Silicon (MacBook, macOS) running in `group_commit` WAL mode with a mixed read/write workload (10 concurrent clients, 1,000 transactions each, 70% INSERT / 30% SELECT):

- Throughput: **430 TPS**
- Min latency: **311 µs**
- p50 latency: 23 ms
- p95 latency: 36 ms
- p99 latency: **42 ms**
- Errors: 0 / 10,000

> **Do not use the 430 TPS figure for production capacity planning.** It was measured on a single MacBook with 10 concurrent clients.

### WAL sync modes

| Mode | Durability | Typical use |
|---|---|---|
| `group_commit` | Up to one flush window of data loss on hard crash | **Default — recommended for most deployments** |
| `per_record` | Zero data loss — every write fsynced immediately | Strict regulatory environments |
| `no_sync` | None | Development and CI only |

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
│          └─────────────┘ └──────────────┘                  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Audit Log   │  │  HSM Client  │  │  Replication     │  │
│  │  WORM BLAKE3 │  │  Model 1 or  │  │  WAL streaming   │  │
│  │  chain       │  │  Model 2     │  │  TLS + HMAC      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Rust toolchain 1.80+ — install via [rustup.rs](https://rustup.rs)
- macOS or Linux (Windows supported on x86_64 and ARM64)
- Git (any recent version)

No other runtime dependencies are required. All cryptographic libraries are statically linked via Cargo.

---

## Installation

### Option 1 — Install via curl (recommended)

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
```

After installation:

```bash
vledger --version
vledger self-test
```

### Option 2 — Build from source

```bash
git clone https://github.com/pavondunbar/VectorLedger.git
cd VectorLedger
cargo build --release
cargo install --path crates/vledger
```

---

## Quick Start

### 1. Initialize the database

```bash
vledger init --data-dir ./vledger-data --key-source pyhsm
```

For testing without PyHSM:
```bash
vledger init --data-dir ./vledger-data --key-source file
```

### 2. Lock down the data directory

```bash
chmod 700 vledger-data/ vledger-data/keys/ vledger-data/catalog/ \
          vledger-data/audit/ vledger-data/wal/ vledger-data/pages/
```

### 3. Start the server

```bash
# Native server only (port 5433)
nohup vledger start --data-dir ./vledger-data --with-proofs > nohup.out 2>&1 &

# With PostgreSQL wire protocol (port 5432) — requires paid license
nohup vledger start --data-dir ./vledger-data --with-proofs --pgwire > nohup.out 2>&1 &
```

Wait for the server to be ready:
```bash
until grep -q "Listening" nohup.out 2>/dev/null; do sleep 2; done && echo "Server ready"
```

### 4. Read and change the admin password

```bash
cat vledger-data/catalog/.admin_initial_credentials
vledger user set-password --username admin --data-dir ./vledger-data
rm vledger-data/catalog/.admin_initial_credentials
```

### 5. Connect and run queries

Via the native REPL:
```bash
vledger sql --data-dir ./vledger-data --username admin
```

Via psql (requires `--pgwire` and paid license):
```bash
psql "host=127.0.0.1 port=5432 user=admin sslmode=require"
```

---

## Importing Existing Data

### CSV column mapping

Every CSV has different column names. Use `--map YOUR_COLUMN=VLEDGER_FIELD` to tell VectorLedger which column is which.

**Step 1 — Check your CSV headers:**
```bash
head -1 your-data.csv
```

**Step 2 — Dry run first (validates mapping, no data written):**
```bash
vledger import --file your-data.csv \
  --dry-run \
  --create-accounts \
  --id-column your_unique_id_column \
  --map sender_account=debit_account \
  --map receiver_account=credit_account \
  --map amount=amount \
  --map memo=description \
  --map txn_date=effective_date \
  --default-currency USD \
  --metadata-columns sender_name,receiver_name,channel,status
```

**Step 3 — Execute the import:**
```bash
vledger import --file your-data.csv \
  --create-accounts \
  --id-column your_unique_id_column \
  --map sender_account=debit_account \
  --map receiver_account=credit_account \
  --map amount=amount \
  --map memo=description \
  --map txn_date=effective_date \
  --default-currency USD \
  --metadata-columns sender_name,receiver_name,channel,status \
  --on-error skip \
  --progress 100000
```

**Column mapping reference:**

- `debit_account` — sending/source account. Required.
- `credit_account` — receiving/destination account. Required.
- `amount` — transaction amount in minor units (cents). Required.
- `description` — human-readable description. Required.
- `currency` — ISO 4217 currency code. Required if not using `--default-currency`.
- `domain` — logical partition for multi-tenant setups. Optional.
- `effective_date` — when the transaction occurred. Optional.
- `external_ref` — external system reference ID. Optional.
- `idempotency_key` — duplicate detection key. Optional.

**`--id-column` — always specify this.** Points to your CSV's unique transaction ID column. This is what VectorLedger uses to detect duplicates on re-imports. Without it, re-running the import will duplicate all rows.

**`--create-accounts` — always include this.** Automatically creates any account referenced in the file that doesn't exist yet. Auto-created accounts use Suspense type.

**If the import is interrupted:**
```bash
vledger import --file your-data.csv --resume [same flags as original run]
```

> **IMPORTANT:** The server must NOT be running during import. Run `pkill vledger` first.

### After a large import — populate the SQLite index

```bash
vledger migrate-to-sqlite --data-dir ./vledger-data
```

This is a one-time operation. It reads the WAL and populates SQLite in three passes:
- Pass 1: Index all entries and persist all account records to SQLite (~45,000 entries/sec)
- Pass 2: Build secondary indexes
- Pass 3: Build account cross-reference index (2 lines per entry — 25M entries = 50M lines)

It is crash-safe — if interrupted, re-run and it resumes from where it left off.

**Scale reference:**
- 25 million records → ~75 minutes total
- 1 billion records → ~7-9 hours (one-time, run overnight)

After migration completes, start the server. Account records are now persisted in SQLite so they load instantly on startup regardless of how many WAL segments are skipped.

---

## SQL Reference

VectorLedger supports a financial-ledger SQL dialect over both the native TLS connection (port 5433) and the PostgreSQL wire protocol (port 5432). It is **PostgreSQL-compatible** — not PostgreSQL — so standard PostgreSQL system catalog queries (`\l`, `\dt`, `pg_catalog.*`) are not supported.

### Database and schema

VectorLedger has one database (`vledger`) and three fixed tables:

- `ledger` — one row per journal entry
- `ledger_lines` — one row per debit/credit line (two rows per entry)
- `accounts` — chart of accounts

The schema is fixed. `CREATE TABLE`, `DROP TABLE`, `UPDATE`, and `DELETE` are not supported — the ledger is append-only by design.

### Scan safety — default row cap

Unbounded full-table scans are automatically capped at **10,000 entries**. Use `LIMIT` or point-lookup filters to retrieve more.

### Tables

#### `ledger`
```sql
-- Point lookups (no cap)
SELECT * FROM ledger WHERE sequence = 19678432;
SELECT * FROM ledger WHERE external_ref = 'TXN-001';

-- Multiple point lookups with IN (no cap)
SELECT sequence, content_hash, chain_hash FROM ledger WHERE sequence IN (1, 2, 3);
SELECT * FROM ledger WHERE sequence IN (19678432, 25000001, 25000002, 25000003);

-- Filtered queries
SELECT * FROM ledger WHERE domain = 'main' LIMIT 100;
SELECT * FROM ledger WHERE status = 'Posted' LIMIT 50;
```

Columns: `sequence`, `id`, `status`, `description`, `domain`, `effective_at`, `posted_at`, `external_ref`, `content_hash`, `chain_hash`, `lines`, `metadata`

Entry status values: `Posted`, `Reversed`, `Reversal`, `PendingApproval`, `Rejected`, `Pending`, `Settled`, `Failed`

#### `ledger_lines`
```sql
SELECT * FROM ledger_lines WHERE sequence = 19678432;

-- Multiple sequences with IN
SELECT * FROM ledger_lines WHERE sequence IN (19678432, 25000001, 25000002);

SELECT * FROM ledger_lines WHERE dr_cr = 'Debit' LIMIT 50;
SELECT * FROM ledger_lines WHERE dr_cr = 'Credit' LIMIT 50;
```

Columns: `date`, `sequence`, `entry_id`, `description`, `domain`, `account_id`, `dr_cr`, `amount`, `currency`, `status`, `metadata`

#### `accounts`
```sql
SELECT * FROM accounts;
SELECT * FROM accounts WHERE code = '0601095315';
SELECT * FROM accounts WHERE id = 'c0a89fbd-8eea-45a9-9e5c-0893c1cafe08';
SELECT * FROM accounts WHERE name = 'Christine Hyacinth';
SELECT * FROM accounts WHERE domain = 'main';

-- Multiple lookups with IN
SELECT * FROM accounts WHERE code IN ('0601095315', '0036011743', '1275341255');
SELECT * FROM accounts WHERE id IN ('c0a89fbd-...', 'cd1f97bd-...', 'ae262006-...');
```

Columns: `id`, `code`, `name`, `account_type`, `currency`, `status`, `domain`, `balance`

### Write commands

#### Post a journal entry
```sql
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain)
VALUES ('Wire transfer', 'CASH', 'REVENUE', 100000, 'USD', 'main');
```

- `amount` is in **minor units** (cents for USD — 100000 = $1,000.00)
- `debit_account` and `credit_account` accept either account `code` or UUID
- Optional fields: `external_ref`, `idempotency_key`, `metadata`

#### Create an account
```sql
INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('CASH', 'Cash - USD', 'Asset', 'USD', 'main');
```

Account types: `Asset`, `Liability`, `Equity`, `Income`, `Expense`, `Suspense`

### Reversal and correction workflow

Corrections are made by posting new entries — the original is never modified or deleted.

```sql
-- Step 1: Find the entry to reverse
SELECT * FROM ledger WHERE sequence = 19678432;
SELECT * FROM ledger_lines WHERE sequence = 19678432;

-- Step 2: Look up account codes from the UUIDs in ledger_lines
SELECT id, code, name, balance FROM accounts WHERE id = 'c0a89fbd-8eea-45a9-9e5c-0893c1cafe08';
SELECT id, code, name, balance FROM accounts WHERE id = 'cd1f97bd-f93e-4596-866a-0f2f4a0de6ad';

-- Step 3: Post the reversal (flip debit and credit)
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata)
VALUES (
  'Reversal of sequence 19678432 - Transfer to Tekiau Cecilia',
  '6f1c6012-b5df-461f-9259-bc790a063643',
  'f93081c2-d1f0-4dd4-9b48-4f68f6d0023e',
  44602, 'USD', 'main',
  'reversal-of-f0da247e-8b29-4556-aaa4-cf424626adcc',
  '{"reverses":"f0da247e-8b29-4556-aaa4-cf424626adcc","reason":"correction"}'
);

-- Step 4: Post the correction (with correct details)
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata)
VALUES (
  'Corrected Transfer to Tekiau Cecilia',
  'f93081c2-d1f0-4dd4-9b48-4f68f6d0023e',
  '6f1c6012-b5df-461f-9259-bc790a063643',
  44700, 'USD', 'main',
  'correction-of-f0da247e-8b29-4556-aaa4-cf424626adcc',
  '{"corrects":"f0da247e-8b29-4556-aaa4-cf424626adcc"}'
);

-- Step 5: Verify chain integrity
SELECT VERIFY_CHAIN();
```

The original entry is never modified or deleted. All three entries (original, reversal, correction) remain permanently in the ledger. A reversal without a correction is also valid — post only the reversal if the transaction should simply not exist.

### Financial functions

```sql
-- Account balance (returns minor units)
SELECT BALANCE('CASH');
SELECT BALANCE('account-uuid-here');

-- Verify the entire BLAKE3 hash chain
SELECT VERIFY_CHAIN();

-- Verify a range of entries
SELECT VERIFY_CHAIN(1, 100000);

-- Verify a single entry's hashes
SELECT VERIFY_ENTRY(19678432);
```

### Aggregates and joins

```sql
SELECT COUNT(sequence) FROM ledger;
SELECT SUM(amount) FROM ledger GROUP BY domain;
SELECT AVG(amount) FROM ledger;
SELECT MIN(sequence), MAX(sequence) FROM ledger;
SELECT SUM(amount) FROM ledger_lines WHERE dr_cr = 'Debit';
SELECT SUM(amount) FROM ledger_lines WHERE dr_cr = 'Credit';
SELECT * FROM ledger JOIN accounts ON ledger.domain = accounts.domain LIMIT 10;
```

### Metadata search

Every entry carries a `metadata` field — an arbitrary JSON blob (e.g. `{"sender_name":"Alice","receiver_name":"Bob","channel":"mobile"}`). From v1.0.30, metadata is indexed using a **SQLite FTS5 full-text index**, making search instant regardless of ledger size.

```sql
-- Find all entries involving a person by name (LIKE — uses FTS5 index)
SELECT * FROM ledger WHERE metadata LIKE '%Elizabeth Cadet%';
SELECT * FROM ledger_lines WHERE metadata LIKE '%Elizabeth Cadet%';

-- Case-insensitive search (ILIKE)
SELECT * FROM ledger WHERE metadata ILIKE '%elizabeth cadet%';

-- Search for a specific role
SELECT * FROM ledger WHERE metadata LIKE '%"receiver_name":"Elizabeth Cadet"%';
SELECT * FROM ledger WHERE metadata LIKE '%"sender_name":"Elizabeth Cadet"%';

-- Exact full metadata match
SELECT * FROM ledger WHERE metadata = '{"channel":"mobile","receiver_name":"Elizabeth Cadet","sender_name":"Basma Ammar","status":"completed","transaction_type":"fee"}';
```

**Supported on both `ledger` and `ledger_lines`.** Results are ordered by sequence.

**FTS index is automatic** — no configuration needed. On first startup after upgrading to v1.0.30 on an existing database, VectorLedger detects the empty FTS index and rebuilds it automatically. Progress is logged to `nohup.out`. Subsequent startups skip this step. All new entries are indexed at insert time.

**Works with any metadata field name.** Because the entire JSON blob is indexed as text, future CSV imports with different column names (e.g. `beneficiary`, `payee`, `customer_ref`) are automatically searchable without any schema changes.

---

### What is NOT supported

- `UPDATE` — append-only; entries are permanent
- `DELETE` — append-only; entries are permanent
- `DROP TABLE` / `DROP DATABASE` — schema is fixed
- `NOT IN` — use separate queries instead
- `pg_catalog.*` system tables — not PostgreSQL internally
- Multiple databases or schemas — single-database engine

---

## CLI Reference

### `vledger user`

Manage user accounts. The server does not need to be running — commands connect to it automatically if available, otherwise write directly to disk.

```bash
# Create a new user
vledger user create --username alice --role operator
# Roles: admin, operator, auditor, readonly (default: readonly)

# List all users
vledger user list

# Change a user's role (revokes all active sessions immediately)
vledger user set-role --username alice --role auditor

# Change a user's password (revokes all active sessions immediately)
vledger user set-password --username alice

# Enable or disable a user
vledger user set-enabled --username alice --enabled false
vledger user set-enabled --username alice --enabled true

# Delete a user
vledger user delete --username alice
```

**Note on `set-role`:** When a user's role is changed, all their active sessions are immediately revoked. They must log in again to receive the new permissions. No account deletion and recreation is needed.

### `vledger import`

```bash
vledger import [OPTIONS]
  -f, --file <PATH>                  Import file path (required)
  --dry-run                          Validate only — no data written
  --map <SRC=TARGET>                 Column mapping (repeatable)
  --id-column <COL>                  Source column used as idempotency key for
                                     duplicate detection on re-imports. Always
                                     specify this — without it, re-running the
                                     import will duplicate all rows.
  --create-accounts                  Auto-create referenced accounts not yet in
                                     ledger. Always include this flag.
  --default-currency <CODE>          Default currency (default: USD)
  --on-error <abort|skip|collect>    Behaviour on row error (default: abort)
  --progress <N>                     Print progress every N rows (default: 10,000)
  --metadata-columns <LIST>          Comma-separated source columns to pack into
                                     the metadata JSON field on every entry
  --resume                           Resume an interrupted import from last checkpoint
  --wal-sync-mode <MODE>             group_commit (default) | no_sync | per_record
```

### `vledger migrate-to-sqlite`

One-time migration that populates the SQLite entry index from the WAL. Run after a large `vledger import`. The server must NOT be running.

```bash
vledger migrate-to-sqlite --data-dir ./vledger-data
```

From v1.0.21 onward, this also persists all account records to SQLite so that server startup after migration loads accounts instantly without replaying the full WAL history.

### FTS index rebuild (automatic on startup)

From v1.0.30, VectorLedger maintains a **SQLite FTS5 full-text index** over all entry metadata. This index is built automatically:

- **New entries** — indexed at insert time with no manual action required.
- **Existing databases** (pre-v1.0.30) — on the first startup after upgrading, VectorLedger detects the empty FTS index and rebuilds it automatically in a background pass before accepting connections. Progress is logged to `nohup.out`:

```
INFO FTS index empty — rebuilding from existing entries total=17652378
INFO FTS rebuild progress processed=1000000
INFO FTS rebuild progress processed=2000000
...
INFO FTS index rebuilt entries_indexed=17652378
```

No manual steps are required. Subsequent startups skip the rebuild entirely.

### `vledger start`

```bash
vledger start [OPTIONS]
  --data-dir <PATH>              Data directory (default: ./vledger-data)
  --pgwire                       Also start the PostgreSQL wire-protocol listener on port 5432
  --with-proofs                  Attach Merkle proofs to every SELECT response
  --wal-sync-mode <MODE>         per_record | group_commit | no_sync (default: group_commit)
  --group-commit-delay-ms <MS>   Group-commit flush interval in ms (default: 2)
  --max-connections <N>          Max concurrent connections (default: 128)
```

Two background tasks run automatically after startup:
- **Hourly integrity check** — calls `VERIFY_CHAIN()` every 60 minutes
- **15-minute invariant monitor** — checks the global ledger equation every 15 minutes

### `vledger verify`

```bash
vledger verify --data-dir ./vledger-data
```

### `vledger hsm` — HSM Setup and Key Source Configuration

> **Enterprise license required** for PyHSM key sources.

VectorLedger does not link a PKCS#11 `.so` directly. Instead it communicates with a separate **PyHSM daemon** (a TypeScript/Node.js process) over either a Unix socket (Model 1, same server) or mTLS over TCP (Model 2, separate server). Raw key material never leaves PyHSM — the master key is AES-wrapped inside it and VectorLedger only ever holds the ciphertext blob on disk at `vledger-data/keys/pyhsm_master_key.enc`.

#### Model 1 — Local PyHSM (same server)

**Step 1 — Ensure your Enterprise license is in place:**
```bash
cp your-license.json ./vledger-data/license.json
vledger license --data-dir ./vledger-data
```

**Step 2 — Start the PyHSM daemon** so it is listening on `/tmp/pyhsm.sock` before initializing VectorLedger.

**Step 3 — Initialize with PyHSM as the key source:**
```bash
vledger init --data-dir ./vledger-data --key-source pyhsm
# Optional overrides:
vledger init --data-dir ./vledger-data --key-source pyhsm \
  --pyhsm-socket /tmp/pyhsm.sock \
  --pyhsm-caller-id vledger
```

This writes `vledger-data/keys/key_source.json`:
```json
{
  "backend": "py_hsm",
  "socket_path": "/tmp/pyhsm.sock",
  "caller_id": "vledger",
  "key_id": "vledger.master-key"
}
```

**Step 4 — Start the server normally:**
```bash
vledger start --data-dir ./vledger-data --with-proofs --pgwire
```
On every boot VectorLedger sends the cached blob to PyHSM to unwrap it. If PyHSM is not running, startup fails immediately.

#### Model 2 — Remote PyHSM over mTLS (separate server)

```bash
vledger init --data-dir ./vledger-data \
  --key-source remote-pyhsm \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm/ca.pem \
  --pyhsm-client-cert /etc/vledger/pyhsm/client.pem \
  --pyhsm-client-key /etc/vledger/pyhsm/client-key.pem \
  --pyhsm-timeout-ms 5000 \
  --pyhsm-max-retries 3
```

This writes `vledger-data/keys/key_source.json`:
```json
{
  "backend": "remote_py_hsm",
  "endpoint": "https://pyhsm.internal.example.com:8443",
  "ca_cert": "/etc/vledger/pyhsm/ca.pem",
  "client_cert": "/etc/vledger/pyhsm/client.pem",
  "client_key": "/etc/vledger/pyhsm/client-key.pem",
  "timeout_ms": 5000,
  "max_retries": 3,
  "caller_id": "vledger",
  "key_id": "vledger.master-key"
}
```

#### Hardware HSM backends (AWS CloudHSM / Azure Dedicated HSM)

For physical hardware, bridge sidecars (`vledger-hsm-aws-bridge`, `vledger-hsm-azure-bridge`) translate the JSON IPC to hardware PKCS#11 calls. Configure `vledger-data/keys/hsm_config.json`:

**AWS CloudHSM:**
```json
{
  "backend": "aws_cloud_hsm",
  "bridge_socket": "~/.vledger-hsm-aws/bridge.sock",
  "cluster_id": "cluster-xxxxxxxxx",
  "crypto_user": "vgdb-cu",
  "verify_bridge_tls": true
}
```

**Azure Dedicated HSM (Thales Luna Network HSM 7):**
```json
{
  "backend": "azure_dedicated_hsm",
  "bridge_socket": "~/.vledger-hsm-azure/bridge.sock",
  "resource_group": "my-resource-group",
  "device_host": "hsm.internal.example.com",
  "partition": "vledger"
}
```

#### Other key source backends

For non-HSM deployments, `key_source.json` supports:

```json
{ "backend": "env", "var": "VectorLedger_MASTER_KEY" }
```
```json
{ "backend": "file", "path": "/path/to/master_key.hex" }
```
```json
{
  "backend": "vault",
  "addr": "http://127.0.0.1:8200",
  "mount": "secret",
  "secret_path": "vledger/master_key",
  "field": "value"
}
```
```json
{
  "backend": "aws_kms",
  "key_id": "arn:aws:kms:us-east-1:123456789012:key/...",
  "region": "us-east-1"
}
```

#### Key rotation

```bash
# Model 1
vledger rotate-keys --data-dir ./vledger-data \
  --hsm-socket /tmp/pyhsm.sock

# Model 2
vledger rotate-keys --data-dir ./vledger-data \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm/ca.pem \
  --pyhsm-client-cert /etc/vledger/pyhsm/client.pem \
  --pyhsm-client-key /etc/vledger/pyhsm/client-key.pem
```
The old key version is archived for decryption of existing data; all new writes use the new version.

### `vledger self-test` / `vledger self-test-phase3`

Run the built-in self-test suites against an isolated temporary database. Your production data is never touched.

```bash
vledger self-test
vledger self-test-phase3
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

### `vledger reconcile`

```bash
vledger reconcile --data-dir ./vledger-data
vledger reconcile --data-dir ./vledger-data --format json --output reconcile.json
```

### `vledger backup` / `vledger restore`

```bash
vledger backup --data-dir ./vledger-data --output ~/vledger-backup-$(date +%Y%m%d).tar
vledger restore --from backup.tar --target ./vledger-data-restored --force
vledger backup-verify --from backup.tar
```

### `vledger audit-export`

```bash
vledger audit-export --data-dir ./vledger-data --format json --output audit.json
```

### `vledger compliance-report`

```bash
vledger compliance-report --data-dir ./vledger-data --standard pci-dss --format markdown --output pci-report.md
vledger compliance-report --data-dir ./vledger-data --standard soc2 --format markdown --output soc2-report.md
```

### `vledger settle`

```bash
vledger settle --data-dir ./vledger-data --entry-id <UUID> --status settled --notes "settled via ACH"
```

### `vledger hold`

```bash
vledger hold place --data-dir ./vledger-data --account <CODE_OR_UUID>
vledger hold lift  --data-dir ./vledger-data --account <CODE_OR_UUID>
vledger hold list  --data-dir ./vledger-data
```

### `vledger retention`

```bash
vledger retention show  --data-dir ./vledger-data
vledger retention set   --data-dir ./vledger-data --days 2555   # 7 years
vledger retention clear --data-dir ./vledger-data
```

### `vledger rules`

```bash
vledger rules show    --data-dir ./vledger-data
vledger rules set     --data-dir ./vledger-data --version "2026-Q3" \
                      --description "Updated FX rules per IFRS 9" \
                      --effective-date 2026-07-01
vledger rules history --data-dir ./vledger-data
```

### `vledger seed`

Populate the database with randomly generated journal entries for testing and benchmarking. Does not require a running server — opens the data directory directly.

```bash
# Generate 10 million entries with 50 accounts
vledger seed --data-dir ./vledger-data --entries 10000000 --accounts 50 --progress 500000

# Reproducible dataset — same data every time
vledger seed --data-dir ./vledger-data --entries 10000000 --seed 12345
```

### `vledger status`

Show database version, WAL segment count, and active segment.

```bash
vledger status --data-dir ./vledger-data
```

### `vledger license`

Show the active license tier, features, and expiry.

```bash
vledger license --data-dir ./vledger-data
```

### `vledger start-primary` / `vledger start-replica` — Multi-Node WAL Replication

> **Growth or Enterprise license required.**

WAL replication runs a hot-standby replica that streams every committed WAL record from the primary in real time. The channel is secured with TLS 1.3, optional mTLS, and a BLAKE3 HMAC challenge-response handshake. The replica verifies the BLAKE3 hash of every received WAL record before writing it locally.

#### Step 1 — Configure the primary

Create `<data_dir>/replication.json` on the primary node:

```json
{
  "role": "primary",
  "replication_addr": "0.0.0.0:5434",
  "ack_timeout_ms": 5000,
  "heartbeat_interval_ms": 1000,
  "send_buffer_bytes": 67108864,
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary",
    "server_cert": "/etc/vledger/replication/server.pem",
    "server_key": "/etc/vledger/replication/server-key.pem",
    "ca_cert": "/etc/vledger/replication/ca.pem"
  }
}
```

> If you omit `server_cert` and `server_key`, a self-signed certificate is auto-generated at startup — suitable for development.

#### Step 2 — Start the primary

```bash
vledger start-primary --data-dir /opt/vledger-primary
# Override the bind address at CLI:
vledger start-primary --data-dir /opt/vledger-primary --bind 0.0.0.0:5434
```

On first run, `replication_secret.hex` (a 32-byte BLAKE3 HMAC shared secret, mode 0600) is auto-generated in the data directory.

#### Step 3 — Copy the secret to the replica

```bash
scp /opt/vledger-primary/replication_secret.hex \
    replica-host:/opt/vledger-replica/replication_secret.hex
```

The replica does **not** auto-generate this file — startup fails with a clear error if it is missing.

#### Step 4 — Configure the replica

Create `<data_dir>/replication.json` on the replica node:

```json
{
  "role": "replica",
  "replication_addr": "primary-host:5434",
  "ack_timeout_ms": 5000,
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary",
    "ca_cert": "/etc/vledger/replication/ca.pem"
  }
}
```

For mTLS (primary requires client certificate from replica), add:
```json
"client_cert": "/etc/vledger/replication/replica-client.pem",
"client_key": "/etc/vledger/replication/replica-client-key.pem"
```

#### Step 5 — Start the replica

```bash
vledger start-replica --data-dir /opt/vledger-replica
# Override the primary address at CLI:
vledger start-replica --data-dir /opt/vledger-replica --primary primary-host:5434
```

The replica connects, performs the BLAKE3 HMAC challenge-response inside TLS, then streams WAL records. On disconnection it reconnects automatically with exponential back-off (500 ms → 30 s).

#### TLS mode reference

| `tls.enabled` | `tls.ca_cert` | `tls.client_cert` | Effective mode |
|---|---|---|---|
| `false` | — | — | Plain TCP (dev only) |
| `true` | `null` | `null` | TLS, self-signed, no mTLS |
| `true` | path | `null` | TLS, CA-verified, no mTLS |
| `true` | path | path + key | Mutual TLS (mTLS) |

#### License enforcement

If `replication.json` exists in the data directory when `vledger start` is run, the `Replication` feature license is checked immediately — the server will not start without a valid Growth+ license.

VectorLedger has **245 automated tests** across 6 test files and 4 crates, all passing on every release.

```bash
# Run the full test suite
cargo test --package vledger-ledger --package vledger-sql --package vledger-server --package vledger-audit

# Run only the regression tests (reversal/correction workflow guarantees)
cargo test --package vledger-ledger regression

# Run only the SQL layer tests
cargo test --package vledger-sql sql_tests

# Run only the auth/user management tests
cargo test --package vledger-server auth_tests

# Run the built-in self-tests (end-to-end engine verification)
vledger self-test
vledger self-test-phase3
```

### Test coverage by area

**`vledger-ledger` — 100 tests**
- Financial invariants (INV-1 through INV-14): double-entry balance, balance cache correctness, idempotency, monotonic sequences, hash chain validity, reversal nets to zero, overflow boundaries, currency mismatch rejection, exposure limits, four-eyes, legal holds, global ledger equation, WAL replay reconstruction
- Property-based tests (random inputs, hundreds of iterations each)
- Stress tests: up to 5,000 concurrent clients, concurrent reversal races, idempotency races
- Crash / fault injection: WAL replay after crash, torn write recovery
- EntryDb account persistence: upsert, load, roundtrip, accounts survive store reopen (v1.0.21 regression)
- Regression: `test_reversal_correction_preserves_chain_integrity`, `test_reversal_only_preserves_chain_integrity`, `test_double_reversal_rejected`

**`vledger-sql` — 95 tests**
- Adversarial: malformed SQL, oversized queries, injection-style input, Unicode, binary garbage
- SQL pipeline: CREATE ACCOUNT, INSERT INTO ledger, SELECT with all filter variants (=, IN), BALANCE, VERIFY_CHAIN, tamper detection, compatibility constants
- Rejection: UPDATE, DELETE, DROP TABLE, DROP DATABASE, NOT IN, read/write split enforcement
- Aggregates (COUNT, SUM), JOINs, idempotency via SQL

**`vledger-server` — 33 tests**
- UserStore bootstrap, create/list/delete users
- `set-role`: changes role, unknown user fails, persists after reopen
- `set-enabled`: disable/re-enable
- `set-password`: success, unknown user fails
- `authenticate`: correct password, wrong password, unknown user, disabled user, correct role
- `validate_token`: valid token, unknown token
- Role capability matrix for all four roles
- Role string parsing

**`vledger-audit` — 17 tests**
- Open, append, sequence incrementing, hash chain linkage
- First event `prev_hash` = ZERO_HASH, self-verify
- `verify_chain`: empty, single, 20 events, all event kinds
- Chain tip tracking, persistence across reopen
- Hash uniqueness across events

---

## Licensing

VectorLedger uses a tiered license model. The binary enforces feature availability at startup by verifying a signed `license.json` file in your data directory.

### Pricing

| Tier | Price | Best for |
|---|---|---|
| **Free** | $0 / month | Development, evaluation, internal tools |
| **Starter** | $499 / month | Early-stage teams that need PostgreSQL client compatibility |
| **Growth** | $2,499 / month | Production fintechs and SaaS companies under SOC 2 or PCI-DSS |
| **Enterprise** | Contact Sales | Banks, payment processors, PCI-DSS Level 1, hardware HSM requirements |

Annual billing available on all paid tiers — pay for 10 months, get 12.
Contact [pavon@vectorguardlabs.com](mailto:pavon@vectorguardlabs.com) for multi-instance or custom pricing.

### Feature tiers

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

```bash
cp your-license.json ./vledger-data/license.json
vledger license --data-dir ./vledger-data
```

---

## Production Deployment Checklist

- [ ] PyHSM daemon running with a persistent, backed-up keystore
- [ ] `vledger init` completed with `--key-source pyhsm` (Model 1) or `--key-source remote-pyhsm` (Model 2)
- [ ] `key_source.json` shows `"backend": "py_hsm"` or `"backend": "remote_py_hsm"` — not `"env"` or `"file"`
- [ ] Admin credential file read, password changed, and `catalog/.admin_initial_credentials` deleted
- [ ] Data directory permissions locked (`chmod 700` on all subdirectories)
- [ ] Volume encryption enabled on the disk hosting `vledger-data/`
- [ ] Replace self-signed TLS certificate with a CA-signed one
- [ ] Valid `license.json` installed for your paid tier
- [ ] Test a full backup and restore drill: `vledger backup` → `vledger restore` → `vledger verify`
- [ ] Schedule regular `vledger backup` runs
- [ ] Schedule regular `vledger verify` runs (recommended: after each backup)
- [ ] Run `cargo test --package vledger-ledger --package vledger-sql --package vledger-server --package vledger-audit` and confirm 245 tests pass
- [ ] Run compliance reports and confirm zero FAIL items: `vledger compliance-report --standard pci-dss`
- [ ] Ship `audit/audit.log` to an append-only off-host destination in real time

---

## Changelog

### v1.0.30 — FTS5 metadata index
- Added SQLite FTS5 full-text index over all entry metadata (`entries_fts` virtual table, `unicode61` tokenizer)
- `WHERE metadata LIKE '%value%'` and `WHERE metadata ILIKE '%value%'` now use the FTS index — queries that previously took minutes on 17M+ entry ledgers now return in milliseconds
- FTS index is populated at insert time for all new entries
- On first startup after upgrade, existing databases are automatically backfilled (progress logged to `nohup.out`); subsequent startups skip the step
- Index works with any metadata field name — future CSV imports with different column layouts are automatically searchable

### v1.0.29 — Metadata scan OOM fix
- Fixed server crash (OOM) introduced in v1.0.28: replaced `entries_scan(entry_count())` with `stream_entries()`, which iterates SQLite rows one at a time in constant RAM

### v1.0.28 — Metadata scan cap fix
- Fixed `WHERE metadata LIKE` returning 0 rows on ledgers larger than 10,000 entries: scan was incorrectly capped at `DEFAULT_SCAN_LIMIT` regardless of total ledger size

### v1.0.27 — Metadata WHERE filtering
- Added `WHERE metadata = 'value'` and `WHERE metadata LIKE '%value%'` / `ILIKE` support on both `ledger` and `ledger_lines`
- Previously metadata was readable in SELECT output but not filterable in WHERE clauses

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
| Query index | [rusqlite](https://docs.rs/rusqlite) (SQLite) |
| Secret management | [reqwest](https://github.com/seanmonstar/reqwest) (Vault / AWS KMS) |

---

## License

VectorLedger is licensed under the [Business Source License 1.1 (BUSL-1.1)](https://spdx.org/licenses/BUSL-1.1.html).

The source code is available for inspection, development, and non-production use. Production use requires a commercial license. Contact [engineering@vectorguardlabs.com](mailto:engineering@vectorguardlabs.com) for licensing inquiries.

---

*VectorGuard Labs — financial infrastructure that proves its own integrity.*
