# VectorLedger

**A cryptographically verifiable database engine built for institutions that can't afford to trust their own database.**

VectorLedger is a purpose-built, append-only financial ledger written entirely in Rust. Every journal entry is linked by a tamper-evident BLAKE3 hash chain, every page of data is encrypted at rest with AES-256-GCM, and every query result can carry a cryptographic Merkle proof proving the returned data has not been modified since it was written. Historical tampering is **cryptographically detectable** — any modification to a past record invalidates every hash in the chain from that point forward.

Built by [VectorGuard Labs](https://vectorguardlabs.com) · **Version 1.5.4** · License: BUSL-1.1

---

## Table of Contents

1. [Why VectorLedger?](#why-vectorledger)
2. [Key Features](#key-features)
3. [Architecture Overview](#architecture-overview)
4. [Quick Install](#quick-install)
5. [Quick Start](#quick-start)
6. [SQL Dialect](#sql-dialect)
7. [Double-Entry Accounting Model](#double-entry-accounting-model)
8. [Client Libraries](#client-libraries)
9. [MCP Server](#mcp-server)
10. [pgwire Support](#pgwire-support)
11. [Licensing Tiers](#licensing-tiers)
12. [Performance](#performance)
13. [Changelog](#changelog)
14. [Further Reading](#further-reading)

---

## Why VectorLedger?

Traditional relational databases treat audit trails as an afterthought: triggers that can be disabled, log tables that can be truncated, and backup files that can be silently replaced. For organizations operating under SOC 2, PCI-DSS, financial regulation, or internal zero-trust policies, this is not good enough.

VectorLedger makes tampering **cryptographically detectable**:

- A row written years ago cannot be changed without invalidating every hash in the chain from that point to the present.
- Every SELECT response optionally carries a Merkle proof that any client can independently verify.
- The audit log is WORM-append-only — each event is hashed into the next, forming a second independent tamper-evident chain.
- The compliance engine generates machine-generated **technical evidence supporting SOC 2 Type II and PCI-DSS v4 control assessments** — not pre-written documentation.

> **Important scope note:** VectorLedger generates technical evidence *supporting* an audit. It does not by itself make an organization compliant. Organizational compliance requires additional controls, policies, and independent auditor assessment beyond what any database engine can provide.

---

## Key Features

### Core Ledger Engine

- **Double-entry accounting** enforced at the type level — every journal entry must balance (debits == credits) before it is accepted
- **Append-only storage** — entries are never modified or deleted; corrections are posted as explicit reversal entries that extend the hash chain
- **BLAKE3 hash chain** — every journal entry contains `H(sequence || prev_hash || content_hash)`, forming an unbroken chain from first entry to last
- **16 financial invariants** enforced in code on every write — not by policy (see [Double-Entry Accounting Model](#double-entry-accounting-model))
- **Idempotency keys** — duplicate submissions for the same financial event are detected and skipped without double-posting
- **Multi-domain support** — each account and entry is tagged to a legal entity or business domain
- **Hash-protected metadata** — arbitrary JSON metadata included in `canonical_bytes()` and indexed via SQLite FTS5 for full-text search
- **Settlement lifecycle** — entries support `Pending → Settled | Failed` status transitions as append-only events
- **Legal holds** — accounts can be placed under a legal hold, blocking all new entries, reversals, and settlement transitions
- **Reconciliation** — on-demand balance reconciliation recomputes all account balances from journal lines

### Cryptographic Security

- **AES-256-GCM** encryption at rest with per-table keys derived via HKDF-SHA256 from a master key — compromising one table key does not expose others
- **Ed25519** commit signing on every WAL commit record — external auditors can verify the transaction log without trusting the server
- **Argon2id** password hashing (64 MiB / 3 iterations / 4 lanes — above OWASP minimum)
- **Merkle proofs** on every SELECT response — clients can verify the returned rows match the committed database state
- **ZeroizeOnDrop** on all sensitive key material — private keys are erased from memory when dropped
- `WalSyncMode::NoSync` is a **compile-time feature gate**, not a runtime option — it does not exist in the release binary type system

### HSM and Secrets Management

- **PyHSM integration** — Model 1 (local Unix socket) and Model 2 (remote mTLS) deployment
- **AWS CloudHSM** and **Azure Dedicated HSM** (Thales Luna Network HSM 7) via bridge sidecars
- **HashiCorp Vault KV v2** and **AWS KMS** as additional key backends
- Raw key material never accessible from the VectorLedger host in Model 2

### Compliance and Audit

- **SOC 2 Type II** (8 controls) and **PCI-DSS v4** (9 controls) compliance evidence reports
- **WORM audit log** with its own independent BLAKE3 hash chain
- **Cryptographic audit packages** — Ed25519-signed Merkle commitments over any entry range
- **Four-eyes (dual-control) approval** workflow for high-value transactions

### Developer Experience

- **PostgreSQL wire protocol** compatibility (port 5432) — connect with psql, DBeaver, any PG driver
- **MCP server** — AI assistants (Claude Desktop, Cursor, Kiro) can query and write to the ledger directly
- **Natural-language queries** via `vledger sql --ask` (requires `OPENAI_API_KEY`)
- **Client SDKs** for Go, Python, and TypeScript
- **15 MCP tools** including 5 financial reasoning tools

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│  vledger process                                         │
│                                                          │
│  Port 5433 — Native TLS (JSON protocol)                  │
│  Port 5432 — PostgreSQL wire protocol (--pgwire)         │
│  Port 9090 — Prometheus metrics (--metrics-addr)         │
│  Port 5434 — WAL replication (replication.json present)  │
│  Port 3000 — MCP server HTTP+SSE (vledger mcp)           │
└──────────────────┬───────────────────────────────────────┘
                   │
   ┌───────────────┴────────────────┐
   │  vledger-data/                 │
   │  ├── wal/          WAL segments│
   │  ├── pages/        Page store  │
   │  ├── indexes/      SQLite idx  │
   │  ├── catalog/      Users, meta │
   │  ├── audit/        WORM log    │
   │  ├── keys/         Key config  │
   │  ├── foureyes/     Approval Q  │
   │  └── snapshots/    Backups     │
   └────────────────────────────────┘
                   │
   ┌───────────────┴────────────────┐
   │  PyHSM daemon (port 8443 mTLS) │
   │  Master key sealed inside      │
   └────────────────────────────────┘
```

### Crates Overview

| Crate | Responsibility |
|---|---|
| `vledger` | Main binary, CLI subcommands |
| `vledger-ledger` | Core ledger engine, 16 financial invariants |
| `vledger-crypto` | All cryptographic primitives (BLAKE3, AES-256-GCM, Ed25519, Argon2id) |
| `vledger-wal` | Write-ahead log, durability, recovery |
| `vledger-pages` | Encrypted page store |
| `vledger-sql` | SQL parser, planner, executor |
| `vledger-server` | TLS 1.3 server, RBAC, sessions, rate limiting |
| `vledger-pgwire` | PostgreSQL wire protocol v3 compatibility |
| `vledger-mcp` | Model Context Protocol server, 15 tools |
| `vledger-hsm` | HSM integration (PyHSM, AWS CloudHSM, Azure HSM) |
| `vledger-secrets` | Secrets manager backends (Vault, KMS, env, file) |
| `vledger-audit` | WORM audit log with independent hash chain |
| `vledger-compliance` | SOC 2 and PCI-DSS compliance evidence reports |
| `vledger-foureyes` | Four-eyes dual-control approval workflow |
| `vledger-replication` | Synchronous hot-standby WAL replication |
| `vledger-license` | License tier enforcement, Ed25519 verification |
| `vledger-kani` | 21 formal verification (Kani) proof harnesses |

### Key Invariants

- Only one `vledger` process may open a data directory at a time (enforced by advisory lock).
- PyHSM must be reachable before `vledger start` — startup fails closed if PyHSM is down.
- The WORM audit log is append-only and fsync'd on every write.
- TLS 1.3 is mandatory on all connections — plain-text is rejected.

---

## Quick Install

### Option 1 — Install script (recommended)

**macOS / Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex
```

### Option 2 — Download a release binary

Pre-built binaries for v1.5.4 are available on the [GitHub Releases page](https://github.com/pavondunbar/VectorLedger/releases/tag/v1.5.4):

| Platform | Download |
|---|---|
| Linux x86_64 | `vledger-v1.5.4-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `vledger-v1.5.4-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `vledger-v1.5.4-x86_64-apple-darwin.tar.gz` |
| macOS ARM64 (Apple Silicon) | `vledger-v1.5.4-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `vledger-v1.5.4-x86_64-pc-windows-msvc.zip` |

Each release is accompanied by a `SHA256SUMS` file and a CycloneDX SBOM. Verify before installing:

```bash
# Verify SHA-256 checksum
sha256sum -c vledger-v1.5.4-checksums.txt

# Verify cosign signature (keyless OIDC)
cosign verify-blob \
  --certificate vledger-v1.5.4-checksums.txt.sig.pem \
  --signature   vledger-v1.5.4-checksums.txt.sig \
  --certificate-identity "https://github.com/pavondunbar/VectorLedger/.github/workflows/release.yml@refs/tags/v1.5.4" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vledger-v1.5.4-checksums.txt
```

### Option 3 — Build from source

Prerequisites: Rust toolchain 1.80+

```bash
git clone https://github.com/pavondunbar/VectorLedger.git
cd VectorLedger
cargo build --release
# Binary at: target/release/vledger
```

---

## Quick Start

### 1. Initialize a new database

```bash
# Development (file-based key — not for production)
vledger init --data-dir ./vledger-data --key-source file

# Production (local PyHSM)
vledger init --data-dir /var/lib/vledger/data --key-source pyhsm

# Production (remote PyHSM with mTLS)
vledger init \
  --data-dir /var/lib/vledger/data \
  --key-source remote-pyhsm \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --pyhsm-client-cert /etc/vledger/client.crt \
  --pyhsm-client-key /etc/vledger/client.key
```

### 2. Start the server

```bash
vledger start \
  --data-dir ./vledger-data \
  --bind 127.0.0.1:5433 \
  --pgwire \
  --wal-sync-mode group_commit
```

### 3. Run SQL queries

```bash
# Interactive REPL
vledger sql --username admin --server 127.0.0.1:5433

# Single query
vledger sql --username admin \
  --query "SELECT BALANCE('CASH')"

# Natural-language query (requires OPENAI_API_KEY, AgenticAI license)
export OPENAI_API_KEY=sk-...
vledger sql --ask "show me all payments over \$10,000 last week"
```

### 4. Post a journal entry

```sql
INSERT INTO accounts (code, name, account_type, currency, domain)
  VALUES ('CASH', 'Cash Account', 'Asset', 'USD', 'main');

INSERT INTO accounts (code, name, account_type, currency, domain)
  VALUES ('REV', 'Revenue', 'Income', 'USD', 'main');

INSERT INTO ledger (debit_account, credit_account, amount, description, currency, domain)
  VALUES ('CASH', 'REV', 100000, 'Cash sale', 'USD', 'main');
-- amount is in minor units: 100000 = $1,000.00
```

### 5. Verify chain integrity

```bash
vledger sql --username admin \
  --query "SELECT VERIFY_CHAIN()"
```

### 6. Start the MCP server (AgenticAI license required)

```bash
vledger mcp --bind 127.0.0.1:3000

# Add to your MCP client config:
# { "mcpServers": { "vledger": { "url": "http://127.0.0.1:3000/sse" } } }
```

---

## SQL Dialect

VectorLedger implements a **financial-ledger SQL dialect** parsed by the `sqlparser` crate. It is PostgreSQL wire-protocol compatible but is not a full PostgreSQL implementation.

### Supported Tables

| Table | Description | Key Columns |
|---|---|---|
| `ledger` | Journal entries | `sequence`, `id`, `status`, `description`, `domain`, `effective_at`, `posted_at`, `external_ref`, `content_hash`, `chain_hash`, `lines`, `metadata` |
| `ledger_lines` | Debit/credit lines | `date`, `sequence`, `entry_id`, `description`, `domain`, `account_id`, `dr_cr`, `amount`, `currency`, `status`, `metadata` |
| `accounts` | Chart of accounts | `id`, `code`, `name`, `account_type`, `currency`, `status`, `domain`, `balance` |

### Supported Operations

```sql
-- Query entries
SELECT * FROM ledger WHERE sequence = 786295;
SELECT sequence, status, description FROM ledger WHERE domain = 'main' LIMIT 100;
SELECT * FROM ledger WHERE sequence IN (1, 2, 3);

-- Query lines
SELECT * FROM ledger_lines WHERE entry_id = 'e99c3ea8-...';

-- Account balance
SELECT BALANCE('CASH');
SELECT BALANCE('e99c3ea8-7761-419b-9a5a-79b570220a13');

-- Hash chain integrity
SELECT VERIFY_CHAIN();
SELECT VERIFY_CHAIN(1, 100000);  -- range
SELECT VERIFY_ENTRY(786295);      -- single entry

-- Merkle root
SELECT MERKLE_ROOT(786295);             -- single entry
SELECT MERKLE_ROOT(786000, 786500);     -- range

-- Post an entry
INSERT INTO ledger (debit_account, credit_account, amount, description, currency, domain)
  VALUES ('CASH', 'REV', 100000, 'Cash sale', 'USD', 'main');

-- Create an account
INSERT INTO accounts (code, name, account_type, currency, domain)
  VALUES ('CASH', 'Cash Account', 'Asset', 'USD', 'main');
```

### Not Supported

`UPDATE`, `DELETE`, `CREATE TABLE`, `DROP TABLE`, `CREATE INDEX`, `ALTER TABLE`, `pg_catalog.*`, `information_schema.*`

### Important Notes

- **Amounts are always in minor units** — $10.00 USD = `1000` (integer cents). Never use decimals.
- **String literals use single quotes** — `'value'`. Double-quoted string literals are non-standard and may be removed in a future release.
- **Default scan cap**: 10,000 rows on unbounded full-table scans. Point lookups (`WHERE sequence = N`) bypass this cap.
- **RBAC on plans**: privilege is checked on the resolved query plan, not raw SQL text — immune to comment/whitespace bypass.
- **`MERKLE_ROOT()`** does not require `--with-proofs`. It is always available to `admin`, `operator`, and `auditor` roles.

### DBeaver Connection Note

DBeaver shows `SQL Error [02000]` on the **Test Connection** button because it runs catalog introspection queries that VectorLedger doesn't implement. This is cosmetic — the connection itself is open and authenticated. Dismiss the error and open a SQL editor; queries work normally. To suppress: set `assumeMinServerVersion=9.0` in DBeaver driver properties.

---

## Double-Entry Accounting Model

VectorLedger enforces **16 financial invariants at the engine layer** — not by policy or documentation. Every invariant is verified by the automated test suite on every release.

### The 16 Financial Invariants

**Core double-entry rules:**
1. **Debits == Credits** on every entry — `UnbalancedEntry` returned before any WAL write
2. **At least 2 lines** per entry — `TooFewLines` if fewer
3. **Non-zero amounts** — `ZeroAmount` enforced at the `Amount` type level (no float path exists to compile)

**Account validity:**
4. **Account existence** — every referenced account must exist — `AccountNotFound`
5. **Account status** — closed accounts reject new entries — `AccountClosed`
6. **Currency match** — each line must match the account's registered currency — `CurrencyMismatch`

**Balance protection:**
7. **Non-negative balance** — Asset and Expense accounts (configurable per account) — `InsufficientFunds`
8. **Exposure limits** — aggregate debit in one entry cannot exceed the account's configured limit — `ExposureLimitExceeded`

**Legal and compliance controls:**
9. **Legal holds** — held accounts block all new entries, reversals, and settlement transitions — `AccountUnderLegalHold`
10. **Four-eyes requirement** — entries to accounts with `require_four_eyes = true` must go through approval — `FourEyesRequired`

**Reversal rules:**
11. **Reversal of posted only** — only `Posted` entries can be reversed — `CannotReverse`
12. **One reversal per entry** — `AlreadyReversed` on second attempt

**Cryptographic and structural integrity:**
13. **Sequence monotonicity** — strictly monotonic with no gaps
14. **Hash chain** — BLAKE3 chain maintained on every entry; `VERIFY_CHAIN()` detects any tampering
15. **Currency precision** — amounts cannot exceed max minor unit value for currency precision — `PrecisionViolation` (USD: 2, BTC: 8, ETH: 18)

**Idempotency:**
16. **Duplicate detection** — entries with the same idempotency key are detected and skipped — `IdempotencyConflict`

### Account Types

`Asset`, `Liability`, `Equity`, `Income`, `Expense`, `Suspense`

Normal balance directions:
- **Asset / Expense** → increased by Debits (positive balance = Debit)
- **Liability / Equity / Income** → increased by Credits (positive balance may appear as Credit/negative)

### Entry Status Lifecycle

```
Posted → Pending → Settled
                 → Failed
Posted → Reversed
       → Reversal
       → PendingApproval → Posted (after four-eyes approval)
                         → Rejected
```

### Corrections

Corrections follow the append-only model: post a **reversal entry** (flip debit/credit at the original amount) then a **correction entry** at the correct amount. The original entry is never modified. The MCP tools `propose_correction` and `execute_correction` implement a structured two-step workflow with mandatory human confirmation.

### Global Ledger Equation

`Σ(Assets + Expenses) == Σ(Liabilities + Equity + Income)` — verified by `check_financial_invariants()`

---

## Client Libraries

All three SDKs speak the **native newline-delimited JSON wire protocol** over TLS 1.3 on port 5433.

**Wire protocol:**
```
Request:  {"sql": "SELECT ...", "with_proof": false}\n
Response: {"ok": true, "columns": [...], "rows": [[...]], "rows_affected": N,
           "proof": {"root_hex": "...", "leaf_count": N, "verified": true}}\n
```

All three clients validate account identifiers via the same character allowlist (`^[A-Za-z0-9_\-\.:]{1,128}$`) before SQL interpolation to prevent injection.

### Python

```python
from vledger_client import VledgerClient

with VledgerClient.connect("127.0.0.1", 5433) as client:
    result = client.query("SELECT * FROM ledger LIMIT 10")
    for row in result.rows:
        print(row.get("description"), row.get("amount"))

    balance = client.balance("CASH")  # returns int (minor units)
    ok = client.verify_chain()        # returns bool

# With Merkle proofs
with VledgerClient.connect("127.0.0.1", 5433, with_proofs=True) as client:
    result = client.query("SELECT * FROM ledger WHERE sequence = 1")
    if result.proof:
        print(f"Merkle root: {result.proof.root_hex}")
        print(f"Verified: {result.proof.verified}")
```

Install: `pip install vledger-client` (or from `clients/python/`)

### TypeScript

```typescript
import { VledgerClient } from './src/client';

const client = await VledgerClient.connect({
  host: '127.0.0.1',
  port: 5433,
  tls: true,
});

const result = await client.query('SELECT * FROM ledger LIMIT 10');
for (const row of result.rows) {
  console.log(row.get('description'), row.get('amount'));
}

const balance = await client.balance('CASH'); // returns number (minor units)
const ok = await client.verifyChain();

// With Merkle proofs
const proofResult = await client.query(
  'SELECT * FROM ledger WHERE sequence = 1',
  { withProof: true }
);
console.log(proofResult.proof?.rootHex);

client.close();
```

Install: `npm install` in `clients/typescript/`

### Go

```go
import "github.com/pavondunbar/VectorLedger/clients/go/vledger"

client, err := vledger.Connect(vledger.Options{
    Host:   "127.0.0.1",
    Port:   5433,
    UseTLS: true,
})
if err != nil { log.Fatal(err) }
defer client.Close()

result, err := client.Query("SELECT * FROM ledger LIMIT 10")
for _, row := range result.Rows {
    desc, _ := row.GetString("description")
    fmt.Println(desc)
}

balance, err := client.Balance("CASH") // returns int64 (minor units)
ok, err := client.VerifyChain()

// With Merkle proofs
result, err = client.Query(
    "SELECT * FROM ledger WHERE sequence = 1",
    vledger.WithProof(),
)
fmt.Println(result.Proof.RootHex)
```

---

## MCP Server

VectorLedger ships a [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants (Claude Desktop, Cursor, Kiro, and any other MCP-capable client) query and write to the ledger directly — no SQL required.

Requires **AgenticAI** license feature (Starter, Growth, or Enterprise tier).

### Starting the MCP Server

```bash
# Embedded — shares the data directory with a running vledger start
# (auto-detects port 5433 and switches to network mode)
vledger mcp --bind 127.0.0.1:3000

# Or run the standalone binary with an explicit server target
vledger-mcp \
  --data-dir ./vledger-data \
  --bind 127.0.0.1:3000 \
  --server 127.0.0.1:5433
```

### MCP Client Configuration

```json
{
  "mcpServers": {
    "vledger": {
      "url": "http://127.0.0.1:3000/sse"
    }
  }
}
```

### Health Endpoint

```bash
curl http://127.0.0.1:3000/health
# {"ok":true,"service":"vledger-mcp","version":"1.5.4","tools":15,
#  "agent_queries_used":3,"agent_queries_limit":100,"agent_queries_remaining":97}
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
| `explain_balance` | Reasoning | Why is an account at its current balance? Chains metadata → debits → credits → narrative |
| `reconcile_account` | Reasoning | Does stored balance match sum(posted lines)? Returns BALANCED or exact discrepancy |
| `find_policy_violations` | Reasoning | Large transactions, pending-too-long, missing external refs, failed entries |
| `summarize_period` | Reasoning | Natural-language summary: counts by status, volume, Merkle commitment, chain integrity |
| `audit_report` | Reasoning | Full cryptographic audit evidence report for a period |
| `resolve_account` | Identity | Resolve name/code/UUID → authoritative account ID (mandatory before writes) |
| `propose_correction` | Correction | Show reversal+correction plan (writes nothing) |
| `execute_correction` | Correction | Execute reversal + correction after user confirms |

### Agent Query Billing

One **Agent Query** is counted per `initialize` JSON-RPC request (one conversation), regardless of how many internal tool calls the agent makes within that session.

**Session idle timeout:** 30 minutes. After 30 minutes of inactivity, the next question starts a new Agent Query.

| Tier | Agent Queries / Month |
|---|---|
| Free | Disabled |
| Starter | 10 |
| Growth | 100 |
| Enterprise | Unlimited |

The counter file (`mcp_queries.json`) resets automatically on the first day of each UTC month. It is a commercial metering mechanism — not a security control.

### Natural-Language Queries (`--ask`)

```bash
export OPENAI_API_KEY=sk-...
vledger sql --ask "show me all payments over \$10,000 last week"
vledger sql --ask "what is the balance of the CASH account"
vledger sql --ask "compute the Merkle root over entries 100000 to 200000"
```

| Environment Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — | **Required.** Your API key. |
| `OPENAI_MODEL` | `gpt-4o` | Model to use for translation. |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Override for Ollama, Groq, etc. |

The generated SQL is printed to stderr as `→ SQL: ...` before execution. No ledger data, credentials, or key material is transmitted to the LLM provider.

### `AGENT_SYSTEM_PROMPT`

A public `AGENT_SYSTEM_PROMPT` constant is exported from `vledger-mcp` and returned in the MCP `initialize` response's `instructions` field. It contains financially-aware instructions covering minor-units semantics, double-entry rules, account type normal balances, entry status lifecycle, tool routing guidance, and behavioral rules.

```python
from vledger_mcp import AGENT_SYSTEM_PROMPT

agent = Agent(
    name="VectorLedger Agent",
    instructions=AGENT_SYSTEM_PROMPT,
    mcp_servers=[vledger],
)
```

---

## pgwire Support

VectorLedger implements the PostgreSQL wire protocol v3 on port 5432. Requires **Starter or higher** license.

Enable at startup:
```bash
vledger start --data-dir ./vledger-data --pgwire
```

Connect with psql:
```bash
psql "host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require"
```

TLS 1.3 is mandatory — plain-text connections are rejected. Authentication is cleartext password inside TLS, verified against Argon2id hashes.

**Merkle proofs via pgwire:** start with `--with-proofs --pgwire` and every SELECT result includes a `NoticeResponse` with the BLAKE3 Merkle root:

```
NOTICE:  Merkle root: 5a8b9ce38e7e95d66070c74d889fbe1811d9a19e459889839fc2384780a366f4 (1 leaf, verified: true)
```

> Note: `MERKLE_ROOT()` SQL function is available at all times without `--with-proofs`. The flag only adds automatic per-query proof notices.

**Known incompatibilities:** `pg_catalog.*`, `information_schema.*`, `\dt` psql meta-commands, `CREATE/DROP TABLE`, `UPDATE`, `DELETE`. See [SQL Dialect](#sql-dialect) for the full list.

---

## Licensing Tiers

License files (`license.json`) are Ed25519-signed by VectorGuard Labs and verified against the public key baked into the binary. The server checks the license at startup and at UTC midnight daily.

| Tier | Features | Price |
|---|---|---|
| **Free** | Core ledger, single node, 30-day audit export | Free |
| **Starter** | + PgWire, AgenticAI, 90-day audit export | $499/mo |
| **Growth** | + Replication, ComplianceReport, AuditExportUnlimited, AgenticAI | $2,499/mo |
| **Enterprise** | All features + HSM, MultiNode, AgenticAI | From $4,999/mo |

Contact `pavon@vectorguardlabs.com` to purchase or renew a license.

Check your current license:
```bash
vledger license --data-dir ./vledger-data
```

License file format:
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

---

## Performance

Benchmark results (Apple Silicon, group_commit, 10 clients × 1,000 transactions, 70% INSERT / 30% SELECT):

| Metric | Result |
|---|---|
| Throughput | 430 TPS |
| Min latency | 311 µs |
| p50 latency | 23 ms |
| p95 latency | 36 ms |
| p99 latency | 42 ms |

Run your own benchmarks with the included tool:
```bash
vledger-bench \
  --server 127.0.0.1:5433 \
  --clients 10 \
  --transactions 1000 \
  --workload mixed \
  --report bench-report.json
```

---

## Changelog

### v1.5.4
- **Bug fix (v1.5.2/v1.5.3 regression):** Previous fixes patched `tools.rs` (the embedded/direct-access code path) but the production MCP server runs in network mode, which routes all tool calls through `network.rs` — a completely separate implementation of `execute_correction` that had no idempotency logic at all. Fixed `network.rs` with the same pre-flight `external_ref` check and deterministic idempotency keys.

### v1.5.0
- **Bug fix:** `require_feature()` was only checking the explicit `features` list, not the tier's default features. Licenses on paid tiers were incorrectly blocked from tier-default features.
- MCP server and `vledger sql --ask` gated behind `Feature::AgenticAi` (Starter, Growth, Enterprise)
- Monthly Agent Query limits enforced: Starter 10, Growth 100, Enterprise unlimited

### v1.4.5
- `propose_correction` and `execute_correction` MCP tools — structured two-step correction workflow with mandatory human confirmation

### v1.4.4
- `resolve_account` MCP tool — mandatory identity gate before any write involving named parties

### v1.4.3
- JSON-RPC notifications (no `id` field) return HTTP 204 — fixes Kiro V3 stuck on loading

### v1.4.2
- SSE `endpoint` event sends full absolute URL — fixes Kiro CLI V3

### v1.4.1
- `vledger mcp` auto-detects running `vledger start` on port 5433 and switches to network mode

### v1.4.0
- Financial semantic layer: 5 new reasoning tools (`explain_balance`, `reconcile_account`, `find_policy_violations`, `summarize_period`, `audit_report`)
- `AGENT_SYSTEM_PROMPT` constant in `vledger-mcp`
- Richer `--ask` schema context with full financial domain knowledge

### v1.0.39
- **Bug fix:** Merkle root display was truncated to 32 hex characters at 3 display sites; now shows full 64-character hash

### v1.0.38
- **Bug fix:** Column projection (`SELECT specific, columns FROM ledger`) now works correctly for all 3 tables

### v1.0.37
- `MERKLE_ROOT()` now accepts a single argument (`to_seq` defaults to `from_seq`)

### v1.0.36
- `MERKLE_ROOT(from_seq, to_seq)` SQL function added

### v1.0.35
- **Bug fix:** pgwire `--with-proofs` flag was silently ignored; Merkle root now correctly delivered to pgwire clients

### v1.0.34
- Static analysis (`cargo clippy` with deny rules), mutation testing (`cargo-mutants`), 21 formal verification harnesses (Kani)
- `Amount` arithmetic operators now use checked arithmetic — silent overflow is a compile-time error

### v1.0.33
- 498 tests across 11 packages; 4 proptest properties; 12 fuzz targets total (6 added)

### v1.0.32
- **Security:** Fixed 3 fuzz-discovered bugs: WAL OOM on crafted `payload_len`, SQL planner panic on column/value mismatch, harness allocation cap
- `WalSyncMode::NoSync` compile-gated behind `--features dev-no-sync`

### v1.0.31
- Removed unsafe `SignedCommit::verify()` (self-consistency check); only `verify_against(trusted_key)` remains

---

## Further Reading

- **[OPERATIONS.md](./OPERATIONS.md)** — Installation, configuration reference, CLI command reference, backup/restore, key rotation, replication, monitoring, troubleshooting
- **[SECURITY.md](./SECURITY.md)** — Security model, cryptographic primitives, vulnerability disclosure, known limitations
- **VectorGuard Labs:** https://vectorguardlabs.com
- **Security reports:** security@vectorguardlabs.com
- **License / sales:** pavon@vectorguardlabs.com
