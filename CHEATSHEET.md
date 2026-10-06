# VECTORLEDGER CHEAT SHEET — v1.0.39

---

## 1. INSTALL AND VERIFY

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
vledger --version
```

To stop the server without erasing data:

```bash
pkill vledger
```

To start completely over (erases all data):

```bash
pkill vledger
sudo rm -rf vledger-data/ nohup.out
sudo rm -f /usr/local/bin/vledger
```

---

## 2. RUN SELF-TESTS

Confirms the binary works correctly on your machine before touching any data.

```bash
vledger self-test
vledger self-test-phase3
```

---

## 3. INITIALIZE THE DATABASE

```bash
vledger init --data-dir ./vledger-data --key-source file
```

> **NOTE:** `--key-source file` stores the master key on disk. Fine for getting started and testing.
> For production use `--key-source pyhsm` (requires the PyHSM daemon running first).

---

## 4. LOCK DOWN THE DATA DIRECTORY

```bash
chmod 700 vledger-data/ vledger-data/keys/ vledger-data/catalog/ \
          vledger-data/audit/ vledger-data/wal/ vledger-data/pages/
```

---

## 5. DATA — CHOOSE ONE

### 5A. IMPORT EXISTING DATA (migrating from another database)

**Step 1 — Export from your source database**

```bash
# PostgreSQL
psql your-db -c "\COPY journal_entries TO 'export.csv' CSV HEADER"
```

**Step 2 — Check your CSV headers**

```bash
head -1 [FILENAME].csv
```

**Step 3 — Map your columns and dry run first (no data written)**

> **NOTE:** Every CSV has different column names. Use `--map YOUR_COLUMN=VLEDGER_FIELD` to tell
> VectorLedger which column is which. The dry run validates your mapping without writing any data.

```bash
vledger import --file [FILENAME].csv \
  --dry-run \
  --create-accounts \
  --id-column [YOUR_UNIQUE_ID_COLUMN] \
  --map [YOUR_SENDER_COL]=debit_account \
  --map [YOUR_RECEIVER_COL]=credit_account \
  --map [YOUR_AMOUNT_COL]=amount \
  --map [YOUR_DESC_COL]=description \
  --map [YOUR_DATE_COL]=effective_date \
  --default-currency USD \
  --metadata-columns [EXTRA_COL1],[EXTRA_COL2],[EXTRA_COL3]
```

**Column mapping reference — `--map YOUR_COLUMN=TARGET_FIELD`:**

| Field | Required? | Notes |
|---|---|---|
| `debit_account` | Required | The sending/source account |
| `credit_account` | Required | The receiving/destination account |
| `amount` | Required | Transaction amount in minor units (cents) |
| `description` | Required | Human-readable description |
| `currency` | Required* | ISO 4217 code. *Not required if using `--default-currency` |
| `domain` | Optional | Logical partition for multi-tenant setups |
| `effective_date` | Optional | When the transaction occurred |
| `external_ref` | Optional | External system reference ID |
| `idempotency_key` | Optional | Duplicate detection key (auto-generated if omitted) |

**`--id-column` — always specify this:**
- Points to your CSV's unique transaction ID column (e.g. `transaction_id`, `payment_id`).
- Used to detect duplicates on re-imports.
- If omitted, a BLAKE3 hash of the full row is used — re-running with different flags will not detect existing entries as duplicates.

**`--metadata-columns` — preserve extra columns:**
- Packs extra columns into a hash-protected JSON field on every entry.
- These are stored, queryable, and tamper-protected but have no special meaning to the ledger engine.
- Example: `--metadata-columns sender_name,receiver_name,channel,status,transaction_type`

**`--create-accounts` — always include this:**
- Automatically creates any referenced account that doesn't exist yet.
- Auto-created accounts use Suspense type with USD currency.
- Without this flag, imports will fail on any account not already registered.

**Amount precision:** Amounts must be in minor units (cents). $915.87 → 91587.

**The dry run reports:** total rows, valid vs invalid rows, accounts detected/missing, currencies found, first 20 errors with row numbers.

**Step 4 — Execute the import**

Use the same flags as the dry run, minus `--dry-run`:

```bash
vledger import --file [FILENAME].csv \
  --create-accounts \
  --id-column [YOUR_UNIQUE_ID_COLUMN] \
  --map [YOUR_SENDER_COL]=debit_account \
  --map [YOUR_RECEIVER_COL]=credit_account \
  --map [YOUR_AMOUNT_COL]=amount \
  --map [YOUR_DESC_COL]=description \
  --map [YOUR_DATE_COL]=effective_date \
  --default-currency USD \
  --metadata-columns [EXTRA_COL1],[EXTRA_COL2],[EXTRA_COL3] \
  --on-error skip \
  --progress 100000 \
  --wal-sync-mode group_commit
```

> **NOTE:** `--on-error skip` logs bad rows and continues. Use `--on-error abort` to stop on the first error.
> `--progress 100000` prints a progress line every 100,000 rows.
> `--wal-sync-mode group_commit` is recommended for large imports.

If the import is interrupted:

```bash
vledger import --file [FILENAME].csv --resume [same flags as original run]
```

At completion you receive `import-manifest.json` containing: source file hash, row counts (processed / imported / already existed / skipped / failed), first and last sequence numbers, chain tip, timestamps.

> **NOTE:** The server must NOT be running during import. Run `pkill vledger` first.

**Step 5 — Populate the SQLite query index (required after large imports)**

```bash
vledger migrate-to-sqlite --data-dir ./vledger-data
```

- One-time operation. Crash-safe — re-run if interrupted.
- Pass 1: index all entries and persist account records to SQLite (~45,000 entries/sec)
- Pass 2: build secondary indexes
- Pass 3: build account cross-reference index (2 lines per entry)
- Scale reference: 25 million records → ~75 minutes; 1 billion → ~7–9 hours (run overnight)

---

### 5B. GENERATE TEST DATA (testing and demos only)

```bash
vledger seed --data-dir ./vledger-data --entries 10000000 --accounts 50 --progress 500000
```

For reproducible datasets (same data every run):

```bash
vledger seed --data-dir ./vledger-data --entries 10000000 --seed 12345
```

---

## 6. VERIFY THE DATA

Run after import or seed to confirm everything is intact.

```bash
vledger verify --data-dir ./vledger-data
```

Expected output:
```
── VectorLedger Integrity Verification ─────────
  WAL integrity            ... ✓ (25000000 committed txns)
  Ledger hash chain        ... ✓ (25000000 entries, tip=3a45ca02...)
✓ Verification complete
```

If anyone tampered with any historical entry, the hash chain check prints `✗ BROKEN` and identifies exactly where the chain broke.

### 6A. BACKUP DATA

Always take a backup before major operations (re-imports, migrations, upgrades).

```bash
vledger backup --data-dir ./vledger-data --output ~/vledger-backup-$(date +%Y%m%d).tar
```

---

## 7. START THE SERVER

```bash
nohup vledger start --data-dir ./vledger-data --with-proofs > nohup.out 2>&1 &
```

With PostgreSQL wire protocol (requires paid plan):

```bash
nohup vledger start --data-dir ./vledger-data --with-proofs --pgwire > nohup.out 2>&1 &
```

Wait for the server to be ready:

```bash
until grep -q "Listening" nohup.out 2>/dev/null; do sleep 2; done && echo "Server ready"
```

To stop the server:

```bash
pkill vledger
```

---

## 8. READ THE ADMIN CREDENTIALS

```bash
cat vledger-data/catalog/.admin_initial_credentials
```

---

## 9. CHANGE THE ADMIN PASSWORD IMMEDIATELY

```bash
vledger user set-password --username admin --data-dir ./vledger-data
```

---

## 10. DELETE THE CREDENTIALS FILE

```bash
rm vledger-data/catalog/.admin_initial_credentials
```

---

## 11. OPEN THE SQL REPL

```bash
vledger sql --data-dir ./vledger-data --username admin
```

PostgreSQL REPL (paid plan with `--pgwire`):

```bash
psql "host=127.0.0.1 port=5432 user=admin sslmode=require"
```

---

## 12. NATURAL-LANGUAGE QUERIES WITH --ask

Ask questions in plain English. An LLM translates the question to SQL, prints the generated
query, and executes it — no SQL knowledge required.

### Setup

Set at minimum `OPENAI_API_KEY`. The other two variables are optional overrides:

```bash
export OPENAI_API_KEY=sk-...           # required
export OPENAI_MODEL=gpt-4o             # optional — default: gpt-4o
export OPENAI_BASE_URL=https://api.openai.com/v1  # optional — default: OpenAI
```

### Usage

```bash
vledger sql --ask "show me all failed payments in the last 30 days"
vledger sql --ask "what is the current balance of the CASH account"
vledger sql --ask "list the 10 largest transactions this month"
vledger sql --ask "compute the Merkle root over the last 1000 entries"
vledger sql --ask "how many entries were posted today"
```

The generated SQL is always printed to stderr before execution:

```
→ SQL: SELECT * FROM ledger WHERE status = 'Failed' AND effective_at >= '2026-09-01T00:00:00Z' LIMIT 100
(results follow)
```

For a cloud/remote server, add `--server`:

```bash
vledger sql --server 127.0.0.1:5433 --ask "show me all failed payments last week"
```

### Supported LLM providers

Any OpenAI-compatible endpoint works. Set `OPENAI_BASE_URL` and `OPENAI_MODEL` to switch — no code changes.

| Provider | `OPENAI_BASE_URL` | `OPENAI_MODEL` examples | Notes |
|---|---|---|---|
| **OpenAI** (default) | `https://api.openai.com/v1` | `gpt-4o`, `gpt-4-turbo` | Default — no env var needed |
| **xAI Grok** | `https://api.x.ai/v1` | `grok-3`, `grok-3-mini`, `grok-2` | API key from console.x.ai |
| **Anthropic** | `https://api.anthropic.com/v1` | `claude-opus-4-5`, `claude-sonnet-4-5` | Anthropic API key |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | Fast inference, free tier |
| **Together AI** | `https://api.together.xyz/v1` | `meta-llama/Llama-3-70b-chat-hf` | Open models |
| **Mistral** | `https://api.mistral.ai/v1` | `mistral-large-latest` | European data residency |
| **Ollama** (local) | `http://127.0.0.1:11434/v1` | `llama3.2`, `mistral` | Fully local, no API key |
| **LM Studio** (local) | `http://127.0.0.1:1234/v1` | (model loaded in LM Studio) | GUI-based local runner |
| **vLLM** (self-hosted) | `http://your-host:8000/v1` | any HuggingFace model | Self-hosted GPU server |
| **llama.cpp** (local) | `http://127.0.0.1:8080/v1` | any GGUF model | Ultra-lightweight local |

**Example — xAI Grok:**

```bash
export OPENAI_API_KEY=xai-...
export OPENAI_BASE_URL=https://api.x.ai/v1
export OPENAI_MODEL=grok-3
vledger sql --ask "show me all payments over $10,000 last week"
```

**Example — Ollama (fully local, no internet, no API key):**

```bash
ollama pull llama3.2
export OPENAI_API_KEY=ollama   # any non-empty string
export OPENAI_BASE_URL=http://127.0.0.1:11434/v1
export OPENAI_MODEL=llama3.2
vledger sql --ask "show me the last 5 transactions"
```

**Using Kiro CLI with --ask:**

Kiro orchestrates the workflow; the configured LLM handles SQL translation. Set the env vars
in your terminal before calling `--ask` from within your Kiro session:

```bash
export OPENAI_API_KEY=xai-...
export OPENAI_BASE_URL=https://api.x.ai/v1
export OPENAI_MODEL=grok-3
vledger sql --ask "list all accounts with a balance over $50,000"
```

---

## 13. MCP SERVER (AI AGENT ACCESS)

The MCP server exposes VectorLedger as callable tools for any AI agent — no SQL required.

### Tools exposed

| Tool | Category | What it does |
|---|---|---|
| `query_ledger` | Query | Run any SELECT, BALANCE(), VERIFY_CHAIN(), MERKLE_ROOT() |
| `post_entry` | Write | Record a new double-entry journal entry |
| `get_balance` | Query | Return current balance for an account |
| `list_accounts` | Query | List all accounts with balances |
| `query_ledger_lines` | Query | Query individual debit/credit lines |
| `verify_chain` | Integrity | Verify BLAKE3 cryptographic chain integrity |
| `merkle_root` | Integrity | Compute BLAKE3 Merkle commitment over a range |
| `explain_balance` | Reasoning | Why is an account at its current balance? |
| `reconcile_account` | Reasoning | Does the balance match the sum of posted lines? |
| `find_policy_violations` | Reasoning | Large txns, pending-too-long, missing refs, failures |
| `summarize_period` | Reasoning | Natural-language period summary |
| `audit_report` | Reasoning | Full cryptographic audit evidence report |
| `resolve_account` | Identity | Resolve name/code/UUID → authoritative account ID |
| `propose_correction` | Correction | Show reversal+correction plan — Step 1 (no writes) |
| `execute_correction` | Correction | Post reversal+correction after confirmation — Step 2 |

### Start the MCP server

**Local:**

```bash
# Embedded (uses existing data dir)
vledger mcp --bind 127.0.0.1:3000 --username admin

# Standalone binary
vledger-mcp --data-dir ./vledger-data --bind 127.0.0.1:3000 --username admin
```

**Cloud (EC2 / GCP / Azure) — background process:**

```bash
nohup vledger-mcp \
  --data-dir /var/lib/vledger/data \
  --bind 127.0.0.1:3000 \
  >> /var/log/vledger/mcp.log 2>&1 &
```

**Verify it is running:**

```bash
curl -s http://127.0.0.1:3000/health
# {"ok":true,"service":"vledger-mcp"}
```

### SSH tunnel reference (cloud instances)

All MCP clients use `http://127.0.0.1:3000`. The SSH tunnel makes your cloud instance's
port 3000 appear as a local port on your machine.

**All three servers at once (native TLS + PostgreSQL + MCP):**

```bash
ssh -i './YourKey.pem' \
  -L 5433:127.0.0.1:5433 \
  -L 5432:127.0.0.1:5432 \
  -L 3000:127.0.0.1:3000 \
  -N ubuntu@YOUR-INSTANCE-IP
```

**MCP server only:**

```bash
ssh -i './YourKey.pem' -L 3000:127.0.0.1:3000 -N ubuntu@YOUR-INSTANCE-IP
```

**Auto-reconnecting tunnel (recommended for long sessions):**

```bash
ssh -i './YourKey.pem' \
  -L 3000:127.0.0.1:3000 \
  -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  ubuntu@YOUR-INSTANCE-IP &
```

**Common cloud usernames:**

| Cloud | Default username |
|---|---|
| AWS EC2 (Ubuntu) | `ubuntu` |
| AWS EC2 (Amazon Linux) | `ec2-user` |
| GCP Compute Engine | your Google account username |
| Azure VM (Ubuntu) | `azureuser` |
| DigitalOcean | `root` or `ubuntu` |
| Hetzner Cloud | `root` |

### Connect an AI client

The MCP config snippet is the same for every client:

```json
{
  "mcpServers": {
    "vledger": { "url": "http://127.0.0.1:3000/sse" }
  }
}
```

**Option A — Kiro CLI**

```bash
mkdir -p .kiro/settings
cat > .kiro/settings/mcp.json << 'EOF'
{
  "mcpServers": {
    "vledger": {
      "url": "http://127.0.0.1:3000/sse",
      "disabled": false
    }
  }
}
EOF
```

Restart Kiro. Then ask naturally: *"Query the vledger and show me the last 10 posted entries."*

**Option B — Claude Desktop**

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vledger": { "url": "http://127.0.0.1:3000/sse" }
  }
}
```

Restart Claude Desktop. A hammer icon appears when tools are loaded.

**Option C — Cursor**

Edit `.cursor/mcp.json` in your project root (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "vledger": { "url": "http://127.0.0.1:3000/sse" }
  }
}
```

**Option D — Continue.dev (VS Code / JetBrains)**

Edit `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "vledger",
      "transport": { "type": "sse", "url": "http://127.0.0.1:3000/sse" }
    }
  ]
}
```

**Option E — LangChain (Python)**

```bash
pip install langchain-mcp-adapters langchain-openai langgraph
```

```python
import asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

async def main():
    async with sse_client("http://127.0.0.1:3000/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await load_mcp_tools(session)
            agent = create_react_agent(ChatOpenAI(model="gpt-4o"), tools)
            result = await agent.ainvoke({"messages": [{"role": "user",
                "content": "Show me failed transactions from last week then verify chain integrity."}]})
            print(result["messages"][-1].content)

asyncio.run(main())
```

**Option F — OpenAI Agents SDK (Python)**

```bash
pip install openai-agents mcp
```

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerSse

async def main():
    async with MCPServerSse("http://127.0.0.1:3000/sse") as vledger:
        agent = Agent(
            name="VectorLedger Agent",
            instructions="You are a financial ledger assistant. Use tools to answer questions, "
                         "post entries, and verify integrity.",
            mcp_servers=[vledger],
        )
        result = await Runner.run(agent,
            "Post a $1,000 payment from CASH to REVENUE as 'Invoice #1042', then verify the chain.")
        print(result.final_output)

asyncio.run(main())
```

**Option G — LlamaIndex (Python)**

```bash
pip install llama-index-tools-mcp llama-index-llms-openai
```

```python
import asyncio
from llama_index.tools.mcp import McpToolSpec
from llama_index.llms.openai import OpenAI
from llama_index.core.agent import ReActAgent

async def main():
    tools = await McpToolSpec(url="http://127.0.0.1:3000/sse").to_tool_list_async()
    agent = ReActAgent.from_tools(tools, llm=OpenAI(model="gpt-4o"), verbose=True)
    print(agent.chat("What are the top 5 accounts by balance?"))

asyncio.run(main())
```

**Option H — xAI Grok as the reasoning engine (Python)**

Drop-in replacement for any of the Python options above. Swap the LLM init:

```python
# LangChain + Grok
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(
    model="grok-3",
    openai_api_key="xai-...",       # from console.x.ai
    openai_api_base="https://api.x.ai/v1",
)

# OpenAI Agents SDK + Grok
import os
from openai import AsyncOpenAI
from agents import set_default_openai_client
grok = AsyncOpenAI(api_key="xai-...", base_url="https://api.x.ai/v1")
set_default_openai_client(grok)
# then use model="grok-3" in Agent(...)
```

**Option I — Raw HTTP / curl (no AI framework needed)**

```bash
BASE="http://127.0.0.1:3000"

# List all tools
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Query the ledger
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_ledger","arguments":{"sql":"SELECT * FROM ledger LIMIT 10"}}}'

# Get balance
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_balance","arguments":{"account":"CASH"}}}'

# Post entry (amount in minor units — 50000 = $500.00)
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"post_entry","arguments":{"description":"Monthly fee","debit_account":"CASH","credit_account":"REVENUE","amount":50000,"currency":"USD","domain":"main"}}}'

# Verify chain
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"verify_chain","arguments":{}}}'

# Merkle root over a range
curl -s -X POST $BASE/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"merkle_root","arguments":{"from_seq":1,"to_seq":10000}}}'
```

---

### Option J — OpenAI GPT Actions (ChatGPT Plus/Team/Enterprise)

ChatGPT's consumer UI does not support MCP natively. GPT Actions let you define
a custom HTTP action inside ChatGPT that calls VectorLedger's `/message` endpoint.

**Requirements:** ChatGPT Plus/Team/Enterprise account + VectorLedger MCP server
exposed over **HTTPS** with a public domain (not localhost).

**Expose MCP over HTTPS on EC2 using Caddy:**

```bash
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile << 'CADDYEOF'
mcp.yourdomain.com {
    reverse_proxy 127.0.0.1:3000
}
CADDYEOF
sudo systemctl reload caddy
```

**Create a GPT Action in ChatGPT:**

1. Go to chatgpt.com → Explore GPTs → Create → Configure → Actions → Create new action
2. Use this OpenAPI schema:

```yaml
openapi: "3.1.0"
info:
  title: VectorLedger
  version: "1.4.6"
servers:
  - url: https://mcp.yourdomain.com
paths:
  /message:
    post:
      operationId: callTool
      summary: Call a VectorLedger MCP tool
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                jsonrpc: { type: string }
                id:      { type: integer }
                method:  { type: string }
                params:  { type: object }
      responses:
        "200":
          description: Tool result
```

> **Note:** GPT Actions is a REST-style HTTP integration, not a native MCP
> connection. It requires a public HTTPS endpoint — the SSH tunnel used by
> other clients does not work. For read-only access, create a dedicated
> `auditor` role user for ChatGPT.

---

### Option K — OpenAI Codex

Codex runs in a sandboxed cloud container that cannot reach `127.0.0.1:3000`
through an SSH tunnel. Two approaches:

**Approach 1 — CLI via `--ask` (works today, no server exposure needed):**

Give Codex a task that drives VectorLedger's CLI:

```bash
# Codex task: "Download vledger, query the ledger for last month's activity"
wget https://github.com/pavondunbar/VectorLedger/releases/download/v1.4.6/vledger-v1.4.6-linux-x86_64.tar.gz
tar -xzf vledger-v1.4.6-linux-x86_64.tar.gz && chmod +x vledger

export OPENAI_API_KEY=sk-...
./vledger sql --ask "summarize last month's activity"
```

**Approach 2 — Python HTTP calls to a public HTTPS endpoint (Option J setup required):**

```python
import httpx

def call_tool(name, arguments):
    return httpx.post("https://mcp.yourdomain.com/message", json={
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    }).json()

print(call_tool("get_balance", {"account": "CASH"}))
```

> **Best use case for Codex:** writing scripts and automation that interact with
> VectorLedger, rather than direct ledger queries. For direct queries, Kiro,
> Claude Desktop, or the Agents SDK are better suited.

---

### Client selection guide

| You want to… | Best option |
|---|---|
| Ask quick terminal questions | `vledger sql --ask` (section 12) |
| Use xAI Grok for SQL translation | `--ask` with Grok env vars (section 12) |
| Chat with your ledger in a GUI | Claude Desktop (Option B) |
| Work inside VS Code | Continue.dev (Option D) or Cursor (Option C) |
| Work inside Kiro CLI | Kiro (Option A) |
| Use Grok as agent reasoning engine | LangChain + Grok or Agents SDK + Grok (Option H) |
| Build a Python automation pipeline | LangChain (Option E) or OpenAI Agents SDK (Option F) |
| Cron jobs, scripts, monitoring | Raw HTTP / curl (Option I) |
| Build a RAG or document-query system | LlamaIndex (Option G) |
| Use ChatGPT (consumer UI) | GPT Actions (Option J) — requires HTTPS public endpoint |
| Use OpenAI Codex | Codex + `--ask` (Option K, Approach 1) — works today, no server exposure |
| Fully local — no API key, no internet | Ollama + `--ask` (section 12) |
| Maximum privacy | Ollama + `--ask`, or MCP server on localhost only |

---

## 14. FINANCIAL AI REASONING TOOLS (v1.4.0)

Five high-order tools chain multiple queries internally and return structured financial
narratives. Call them via any MCP client or raw curl. No SQL required.

### explain_balance — why is an account at its current balance?

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name":"explain_balance",
    "arguments":{"account":"SETTLEMENT","limit":20}
  }}'
```

Returns: account type, normal balance direction, recent debits table, recent credits
table, totals, and a narrative interpretation. Use when a user asks *"why is X account
$82,400 lower than expected?"*

### reconcile_account — does the balance match posted lines?

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"reconcile_account",
    "arguments":{"account":"CASH"}
  }}'
```

Returns: total debits, total credits, computed balance, stored balance, discrepancy,
and BALANCED / DISCREPANCY DETECTED verdict. If a discrepancy is found, includes
remediation steps.

### find_policy_violations — scan for rule-breaking transactions

```bash
# Default: large txns > $50k, pending too long, missing external refs, failed entries
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
    "name":"find_policy_violations",
    "arguments":{
      "large_amount_threshold_minor_units": 5000000,
      "pending_days_threshold": 3,
      "check_large_amounts": true,
      "check_pending_too_long": true,
      "check_missing_external_ref": true,
      "check_failed_entries": true
    }
  }}'
```

Returns: categorised violation report with counts and entry details per category.

### summarize_period — natural-language period summary

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
    "name":"summarize_period",
    "arguments":{"from":"2026-09-01","to":"2026-09-30","domain":"main"}
  }}'
```

Returns: entry counts by status (Posted / Pending / Failed), total debit volume,
success rate, sequence range, Merkle root for the period, chain integrity status,
and a narrative paragraph.

### audit_report — full cryptographic audit evidence report

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
    "name":"audit_report",
    "arguments":{
      "from":"2026-09-01",
      "to":"2026-09-30",
      "tenant":"Acme Financial",
      "domain":"main"
    }
  }}'
```

Returns: ledger summary, hash chain verification result, BLAKE3 Merkle commitment,
sample entries with content hashes, and bash commands for independent auditor
verification. Suitable for presenting to an auditor or regulator.

---

### AGENT_SYSTEM_PROMPT — financially-aware agent instructions

When building Python agents, use the built-in prompt from `vledger-mcp`. It is
also returned automatically in the MCP `initialize` response (`instructions` field)
so GUI clients (Kiro, Claude Desktop, etc.) pick it up without manual configuration.

```python
# OpenAI Agents SDK
from agents import Agent
from agents.mcp import MCPServerSse

async with MCPServerSse("http://127.0.0.1:3000/sse") as vledger:
    # initialize() returns AGENT_SYSTEM_PROMPT in the instructions field
    # — the SDK applies it automatically. Or set it explicitly:
    agent = Agent(
        name="VectorLedger Agent",
        instructions="""You are a financial operations assistant for VectorLedger.
Amounts are always in minor units (cents) — $100.00 = 10000.
Every entry has exactly one Debit and one Credit line.
The ledger is append-only — corrections require reversal entries.
Never fabricate data — always call a tool. Always verify chain after posting.""",
        mcp_servers=[vledger],
    )
```

### Example multi-step agent workflows (v1.4.0)

These questions now trigger autonomous multi-step reasoning chains:

```
"Why is our settlement account $82,400 lower than expected?"
→ explain_balance("SETTLEMENT") → reconcile_account("SETTLEMENT")

"Find transactions that violate our settlement policy"
→ find_policy_violations(pending_days_threshold=1, large_amount_threshold_minor_units=1000000)

"Summarize last month's activity"
→ summarize_period(from="2026-09-01", to="2026-09-30")

"Generate an audit report for Q3"
→ audit_report(from="2026-07-01", to="2026-09-30", tenant="Acme Financial")

"Show me all transactions over $50,000 that don't have an associated approval"
→ find_policy_violations(check_missing_external_ref=true, large_amount_threshold_minor_units=5000000)

"Reconcile yesterday's transactions"
→ list_accounts() → reconcile_account() for each account with activity
```

---

### resolve_account — identity enforcement before writes (v1.4.4)

**MANDATORY before any write involving a named person or entity.**
Never guess or assign a random account to a named individual.

```bash
# Resolve by name
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name":"resolve_account",
    "arguments":{"query":"Duane Livingston"}
  }}'
```

Three possible results:

| Result | What it means | Agent action |
|---|---|---|
| `✓ FOUND` | Single confirmed match — shows account ID, code, type, balance | Show to user, get confirmation, then post |
| `✗ NOT_FOUND` | No account matches the name/code/UUID | ⛔ STOP — ask user for correct account code/UUID |
| `⚠ MULTIPLE_FOUND` | More than one match | ⛔ STOP — ask user to pick the correct account |

> **Important:** A person's name appearing in transaction metadata (e.g. `sender_name`)
> does **not** identify their account. The tool explicitly explains this and halts.

---

### propose_correction + execute_correction — structured correction workflow (v1.4.5)

When a user wants to change an amount on a posted entry, the agent must show the full
plan and get confirmation before writing anything.

**Step 1 — propose_correction (writes nothing):**

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name":"propose_correction",
    "arguments":{
      "sequence": 12467895,
      "correct_amount_minor_units": 40192
    }
  }}'
```

Returns the full structured proposal:

```
Correction Proposal
────────────────────────────────────────────
Original entry: #12467895
Original amount: $301.92
Correct amount:  $401.92
Net adjustment: +$100.00

Proposed actions:
1. Reverse entry #12467895 (flip debit/credit) — $301.92
2. Post correction — $401.92

What will be preserved:
  Historical entry    ✓ PRESERVED — never modified
  Original hash       ✓ PRESERVED
  New entries         WILL BE APPENDED

⚠ Awaiting confirmation
```

**Step 2 — execute_correction (only after user confirms):**

```bash
curl -s -X POST http://127.0.0.1:3000/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"execute_correction",
    "arguments":{
      "sequence": 12467895,
      "correct_amount_minor_units": 40192,
      "original_amount_minor_units": 30192,
      "debit_account_id": "<uuid-from-propose>",
      "credit_account_id": "<uuid-from-propose>",
      "original_description": "Payment to Martha Mughrabi",
      "original_entry_id": "de696756-1b49-4623-9ec6-3e82c6f9121d",
      "currency": "USD",
      "domain": "main"
    }
  }}'
```

Returns confirmation:

```
✓ Reversal posted     (sequence 25000006)
✓ Correction posted   (sequence 25000007)
✓ Double-entry balanced
✓ Original entry #12467895 PRESERVED
✓ Hash chain extended and verified
Net adjustment: +$100.00
```

> *"Ask your ledger. Don't edit it."*

---

## 15. AUDIT REPORTS

Stop the server first — audit commands open the data directory directly.

```bash
pkill vledger
```

Generate commitment audit package:

```bash
vledger audit-package \
  --data-dir ./vledger-data \
  --tenant "Your Company" \
  --description "Q3 2026 audit" \
  --period-start 2026-07-01 \
  --period-end 2026-09-30 \
  --output [FILENAME].json
```

Generate proof for a specific entry:

```bash
vledger audit-proof \
  --data-dir ./vledger-data \
  --commitment [FILENAME].json \
  --sequence [ENTRY NUMBER] \
  --output entry-[ENTRY NUMBER]-proof.json
```

Verify any audit package or entry proof:

```bash
vledger verify-audit-package --file [FILENAME].json
vledger verify-audit-package --file entry-[ENTRY NUMBER]-proof.json
```

---

## 16. COMPLIANCE REPORTS

Stop the server first.

```bash
pkill vledger
```

PCI-DSS:

```bash
vledger compliance-report --data-dir ./vledger-data \
  --standard pci-dss --format markdown --output pci-dss-report.md
```

SOC 2:

```bash
vledger compliance-report --data-dir ./vledger-data \
  --standard soc2 --format markdown --output soc2-report.md
```

Controls checked against real filesystem state:
- **SOC 2:** CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.2, CC8.1, A1.1
- **PCI-DSS v4:** Req 2.2, 3.4, 3.5, 4.2, 7.1, 10.2, 10.3, 10.5, 11.5

> **NOTE:** These reports generate technical evidence supporting a compliance audit. They do not
> make your organization compliant by themselves. Real certification requires an independent
> auditor, organizational policies, and personnel controls.

---

## 17. RECONCILIATION

Stop the server first, then reconcile.

```bash
pkill vledger
vledger reconcile --data-dir ./vledger-data
```

- Recomputes all account balances from journal entries and compares against the running cache.
- Exits non-zero if any discrepancy is found.

Save results to a file:

```bash
vledger reconcile --data-dir ./vledger-data --format json --output reconcile.json
```

---

## 18. COMMON VLEDGER SQL COMMANDS

**REPL controls:**
- `\x` — toggle expanded (vertical) display
- `\q` — quit the REPL

### Create accounts

```sql
-- Asset account
INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('CASH', 'Cash - USD', 'asset', 'USD', 'main');

-- Income account
INSERT INTO accounts (code, name, account_type, currency, domain)
VALUES ('REVENUE', 'Revenue', 'income', 'USD', 'main');

-- View all accounts
SELECT * FROM accounts;

-- Look up by UUID
SELECT * FROM accounts WHERE id = 'c0a89fbd-8eea-45a9-9e5c-0893c1cafe08';

-- Look up by code
SELECT * FROM accounts WHERE code = '0601095315';

-- Look up by name
SELECT * FROM accounts WHERE name = 'Christine Hyacinth';
```

### Post and query journal entries

```sql
-- Post a journal entry (amounts in minor units — 100000 = $1,000.00)
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain)
VALUES ('Customer payment', 'CASH', 'REVENUE', 100000, 'USD', 'main');

-- View recent entries
SELECT * FROM ledger LIMIT 10;

-- View in accounting format (one row per debit/credit line)
SELECT * FROM ledger_lines LIMIT 20;

-- Look up a specific entry
SELECT * FROM ledger WHERE sequence = 1;

-- Filter by domain
SELECT * FROM ledger WHERE domain = 'main' LIMIT 10;

-- Filter by status
SELECT * FROM ledger WHERE status = 'Posted' LIMIT 10;

-- Filter debit lines only
SELECT * FROM ledger_lines WHERE dr_cr = 'Debit' LIMIT 10;

-- Filter credit lines only
SELECT * FROM ledger_lines WHERE dr_cr = 'Credit' LIMIT 10;

-- View metadata on an imported entry
SELECT sequence, description, metadata FROM ledger WHERE sequence = 408366;
```

### Reversal and correction workflow

```sql
-- Step 1: Find the entry to reverse
SELECT * FROM ledger WHERE sequence = [SEQUENCE];
SELECT * FROM ledger_lines WHERE sequence = [SEQUENCE];

-- Step 2: Look up account codes from the UUIDs in ledger_lines
SELECT id, code, name, balance FROM accounts WHERE id = '[DEBIT_ACCOUNT_ID]';
SELECT id, code, name, balance FROM accounts WHERE id = '[CREDIT_ACCOUNT_ID]';

-- Step 3: Post the reversal (flip debit and credit)
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata)
VALUES (
  'Reversal of sequence [SEQUENCE] - [ORIGINAL DESCRIPTION]',
  '[ORIGINAL_CREDIT_ACCOUNT_CODE]',
  '[ORIGINAL_DEBIT_ACCOUNT_CODE]',
  [AMOUNT], 'USD', 'main',
  'reversal-of-[ORIGINAL_ENTRY_ID]',
  '{"reverses":"[ORIGINAL_ENTRY_ID]","reason":"[REASON]"}'
);

-- Step 4: Post the correction (with correct details)
INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata)
VALUES (
  'Corrected [ORIGINAL DESCRIPTION]',
  '[ORIGINAL_DEBIT_ACCOUNT_CODE]',
  '[ORIGINAL_CREDIT_ACCOUNT_CODE]',
  [CORRECTED_AMOUNT], 'USD', 'main',
  'correction-of-[ORIGINAL_ENTRY_ID]',
  '{"corrects":"[ORIGINAL_ENTRY_ID]"}'
);

-- Step 5: Verify chain integrity after reversal/correction
SELECT VERIFY_CHAIN();
```

> **NOTE:** The original entry is never modified or deleted. All three entries (original,
> reversal, correction) remain permanently in the ledger. This is the correct accounting
> approach and is required for regulatory compliance.

### Balances and aggregates

```sql
SELECT BALANCE('CASH');
SELECT COUNT(sequence) FROM ledger;
SELECT SUM(amount) FROM ledger GROUP BY domain;
SELECT AVG(amount) FROM ledger;
SELECT MIN(sequence), MAX(sequence) FROM ledger;
SELECT SUM(amount) FROM ledger_lines WHERE dr_cr = 'Debit';
SELECT SUM(amount) FROM ledger_lines WHERE dr_cr = 'Credit';
SELECT COUNT(sequence) FROM ledger_lines WHERE dr_cr = 'Debit';
```

### Joins

```sql
SELECT * FROM ledger JOIN accounts ON ledger.domain = accounts.domain LIMIT 10;
```

### Cryptographic verification

```sql
-- Verify entire chain
SELECT VERIFY_CHAIN();

-- Verify a range
SELECT VERIFY_CHAIN(1, 100);

-- Verify a single entry's hashes
SELECT VERIFY_ENTRY(1);

-- Merkle root for a single entry (to_seq defaults to from_seq)
SELECT MERKLE_ROOT(14395673);

-- Merkle root over a range of entries
SELECT MERKLE_ROOT(14395673, 14395700);
```

> **Note on Merkle root display (fixed in v1.0.39):** The inline Merkle root shown after
> `SELECT * FROM ledger` and in `verify-audit-package` output now always shows the full
> 64-character BLAKE3 hash. Previously it was truncated to 32 characters. The output of
> `SELECT MERKLE_ROOT()` and the inline display now always match.

### Compatibility

```sql
SELECT version();
SELECT current_user();
SELECT current_database();
```

### Proof that UPDATE and DELETE do not work

```sql
UPDATE ledger SET amount = 999 WHERE sequence = 14825943;
-- ERROR: plan error: Unsupported statement: UPDATE ...

DELETE FROM ledger WHERE sequence = 14825943;
-- ERROR: plan error: Unsupported statement: DELETE ...
```

### Metadata commands

```sql
-- Substring search (uses FTS5 index — fast on any ledger size)
SELECT * FROM ledger WHERE metadata LIKE '%Elizabeth Cadet%';
SELECT * FROM ledger_lines WHERE metadata LIKE '%Elizabeth Cadet%';

-- Case-insensitive search
SELECT * FROM ledger WHERE metadata LIKE '%elizabeth cadet%';

-- Search by specific role
SELECT * FROM ledger WHERE metadata LIKE '%"receiver_name":"Elizabeth Cadet"%';
SELECT * FROM ledger WHERE metadata LIKE '%"sender_name":"Elizabeth Cadet"%';

-- Exact full metadata match
SELECT * FROM ledger WHERE metadata = '{"channel":"mobile","receiver_name":"Elizabeth Cadet","sender_name":"Basma Ammar","status":"completed","transaction_type":"fee"}';

-- View raw metadata for a specific entry
SELECT metadata FROM ledger WHERE sequence = '17652378';

-- View a sample of metadata values
SELECT metadata FROM ledger LIMIT 20;
```

### Understanding content_hash, chain_hash, and merkle_root

**`content_hash`** — *"What is in this entry?"*
- BLAKE3 hash over the canonical fields of this entry: description, amount, accounts, currency, domain, metadata, timestamps
- Fingerprint of this one transaction in isolation
- If anyone changes a name in the metadata or the amount, this hash changes
- Has no knowledge of any other entry in the ledger

**`chain_hash`** — *"Where does this entry sit in the ledger?"*
- BLAKE3 hash of `sequence || previous_chain_hash || content_hash`
- Links this entry to every entry that came before it
- If any earlier entry is tampered with (even sequence 1), this hash changes
- You cannot reorder, delete, or insert entries into the middle without this hash exposing it
- This is what `VERIFY_CHAIN()` checks

**`merkle_root`** — *"Does this entry belong to a committed set?"*
- BLAKE3 Merkle tree root built over `content_hash` as the leaf input, with domain separation (`0x00 || content_hash`)
- For a single entry the tree has one leaf: `BLAKE3(0x00 || content_hash)` — deliberately different from `content_hash` itself
- Over a range of entries, it's a tree that lets you prove any one entry is included without revealing all the others
- Always prints the full 64-character hex (32 bytes) — as of v1.0.39 the display matches `SELECT MERKLE_ROOT()` exactly

**How they work together:**
- `content_hash` answers *what is in this entry?* — detects field-level tampering
- `chain_hash` answers *is this entry in the right position?* — detects insertion, deletion, or reordering
- `merkle_root` answers *does this entry belong to a specific committed set?* — detects exclusion or substitution

Think of it this way:
- `content_hash` is the fingerprint of the document
- `chain_hash` is the page number sewn into the binding of the book
- `merkle_root` is the seal on the cover that proves which pages are inside

---

## 19. LICENSING

Install a license:

```bash
cp [license-name].json ./vledger-data/license.json
```

Verify the active license:

```bash
vledger license --data-dir ./vledger-data
```

License tiers:

| Tier | Includes | Agent Queries/month |
|---|---|---|
| `free` | Core ledger only — no Agentic AI | — |
| `starter` | Core + pgwire + Agentic AI | 10 |
| `growth` | Core + pgwire + replication + compliance reports + unlimited audit export + Agentic AI | 100 |
| `enterprise` | Everything + HSM + multi-node + Agentic AI | Unlimited |

One Agent Query = one natural-language request to the VectorLedger Agent,
regardless of how many internal tool calls it makes. The monthly counter
resets automatically on the first day of each UTC month.

Check remaining quota:

```bash
curl -s http://127.0.0.1:3000/health | jq '.agent_queries_used, .agent_queries_remaining'
```

---

## 20. LICENSING (FROM SOURCE — OPERATORS ONLY)

Build the license generator:

```bash
cargo build --release --package vledger-license-gen
```

Issue a license:

```bash
./target/release/vledger-license-gen issue \
  --private-key ~/.vgl-keys/license_signing_key.hex \
  --licensee "Acme Bank" \
  --email ops@acmebank.com \
  --tier growth \
  --expires 2027-08-24 \
  --output acme-bank-license.json
```

Verify before sending:

```bash
./target/release/vledger-license-gen verify \
  --public-key ~/.vgl-keys/license_signing_pubkey.hex \
  --license acme-bank-license.json
```

Then send `acme-bank-license.json` to the client.

---

## 21. ADMINISTRATION

VectorLedger has four built-in roles:

| Role | SELECT | INSERT ledger | INSERT accounts | VERIFY | Admin ops |
|---|---|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `operator` | ✓ | ✓ | ✓ | ✓ | ✗ |
| `auditor` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `readonly` | ✓ | ✗ | ✗ | ✗ | ✗ |

Create a new user (admin only):

```bash
vledger user create --username [username] --role [role]
```

> **NOTES:** Roles: `admin`, `operator`, `auditor`, `readonly`. Defaults to `readonly` if
> `--role` is omitted. Password is prompted interactively.

List all users:

```bash
vledger user list
```

Change a user's password:

```bash
vledger user set-password --username [username]
```

Enable or disable a user:

```bash
vledger user set-enabled --username [username] --enabled false
vledger user set-enabled --username [username] --enabled true
```

Delete a user:

```bash
vledger user delete --username [username]
```

Change a user's role:

```bash
vledger user set-role --username [username] --role [role]

# Available roles:
vledger user set-role --username [username] --role admin
vledger user set-role --username [username] --role operator
vledger user set-role --username [username] --role auditor
vledger user set-role --username [username] --role readonly
```

> **NOTE:** When the role changes, all active sessions for that user are immediately revoked.
> The user must log in again to receive the new permissions. No delete and recreate needed.

---

## 22. HOW TO QUERY IMPORTS DIRECTLY IN THE TERMINAL

Get the CSV headers first:

```bash
head -n 1 [FILENAME].csv | tr ',' '\n'
```

Query a specific row:

```bash
awk -F',' 'NR==1 {for (i=1;i<=NF;i++) header[i]=$i; next} \
NR==[ROW NUMBER] {print "────────────────────────────────────────"; \
for (i=1;i<=NF;i++) printf "%-20s %s\n", header[i] ":", $i; \
print "────────────────────────────────────────"; exit}' [FILENAME].csv
```

---

## 23. AGENTIC AI

Wire VectorLedger to an AI agent so you can query and write to the ledger in
plain English — no SQL required.

### On your EC2 instance (or local machine running VectorLedger)

**Step 1 — Start the VectorLedger server:**

```bash
nohup vledger start --data-dir ~/vledger-data --with-proofs > nohup.out 2>&1 &
until grep -q "Listening" nohup.out; do sleep 2; done && echo "Server ready."
```

**Step 2 — Start the MCP server (choose ONE option):**

---

**Option A — Quick start (testing/dev)**

```bash
export VLEDGER_CLI_PASSWORD=YOUR-PASSWORD
nohup vledger mcp --bind 127.0.0.1:3000 --username admin >> ~/mcp.log 2>&1 &
```

Use a separate log file (`mcp.log`) — do not redirect to `nohup.out` or it
will overwrite the server startup log.

---

**Option B — Systemd service (production — survives reboots, no plain-text
password on the command line, auto-restarts on crash)**

Run these once to set it up:

```bash
# Create a protected credentials file
sudo mkdir -p /etc/vledger
sudo tee /etc/vledger/mcp.env << 'EOF'
VLEDGER_CLI_PASSWORD=YOUR-PASSWORD
VLEDGER_CLI_USER=admin
EOF
sudo chmod 600 /etc/vledger/mcp.env
sudo chown root:root /etc/vledger/mcp.env

# Create the systemd service
sudo tee /etc/systemd/system/vledger-mcp.service << 'EOF'
[Unit]
Description=VectorLedger MCP Server
After=network.target

[Service]
User=ubuntu
EnvironmentFile=/etc/vledger/mcp.env
ExecStart=/usr/local/bin/vledger mcp --bind 127.0.0.1:3000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vledger-mcp
sudo systemctl start vledger-mcp
```

After this, the MCP server starts automatically on every reboot. You never
need to run `nohup` again for the MCP server.

> **Option A and Option B are mutually exclusive — pick one.**
> If you set up the systemd service (Option B), do not also run the `nohup`
> command — they will both try to bind port 3000 and one will fail.

---

**Step 3 — Verify the MCP server is running:**

```bash
curl -s http://127.0.0.1:3000/health | jq
```

Expected output:
```json
{
  "ok": true,
  "service": "vledger-mcp",
  "tools": 15,
  "version": "1.4.6"
}
```

---

### On your local machine

**Open the SSH tunnel** (leave this terminal open for the entire session):

```bash
ssh -i './YourKey.pem' \
  -L 3000:127.0.0.1:3000 \
  -N ubuntu@YOUR-EC2-IP
```

**Verify the tunnel works:**

```bash
curl -s http://127.0.0.1:3000/health | jq
```

If this returns `{"ok":true}` on your local machine, the tunnel is working.

**Wire your AI agent:**

Create or update `~/.kiro/settings/mcp.json` (user-level, works from any directory):

```json
{
  "mcpServers": {
    "vledger": {
      "url": "http://127.0.0.1:3000/sse",
      "disabled": false
    }
  }
}
```

For other clients see section 13 (MCP Server). The config snippet is the same
for Kiro, Claude Desktop, Cursor, and Continue.dev.

**Restart your AI agent**, then verify the tools are loaded:

- **Kiro:** run `/mcp` — should show `vledger ● running 15 tools`
- **Claude Desktop:** look for the hammer icon in the chat input

---

### Test prompts

Try these in order to confirm everything is working:

```
Give me the information on journal entry 462,895
```
→ Agent calls `query_ledger` and `query_ledger_lines`, returns full entry details
  with amounts, accounts, timestamps, metadata, and Merkle verification.

```
The amount for journal entry 8,965,371 is wrong. It should be $200.00. Change it.
```
→ Agent calls `propose_correction`, shows the full reversal+correction plan
  (original amount, correct amount, net adjustment, what hashes are preserved),
  asks "Shall I proceed?", then calls `execute_correction` after you confirm.
  Requires v1.4.5 or later.

```
Remove journal entry 16,794,375.
```
→ Agent refuses — the ledger is append-only by design. No entry can ever be
  deleted. The agent explains the constraint and may offer a reversal if the
  entry needs to be corrected.

---

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl` returns nothing on EC2 | MCP server crashed | `cat ~/mcp.log` to see the error |
| `curl` returns nothing locally | SSH tunnel not running | Re-run the tunnel command |
| Port 3000 already in use | Both Option A and B are running | `pkill -f "vledger mcp"` then restart one only |
| Wrong password error in `mcp.log` | Incorrect password | Check with `vledger sql --server 127.0.0.1:5433 --username admin --query "SELECT 1"` |
| `nohup: failed to run command 'VLEDGER_CLI_PASSWORD=...'` | Inline env var passed to nohup | Use `export` first or use `env` prefix: `nohup env VLEDGER_CLI_PASSWORD=... vledger mcp ...` |
| Agent shows `✗ failed — 0 tools` | mcp.json not found or wrong format | Check `~/.kiro/settings/mcp.json` exists with no extra `EOF` text |
| Agent shows `◌ loading` stuck | Kiro V3 handshake issue | Upgrade to v1.4.3 or later |
| MCP server drops after a few minutes | Idle timeout (fixed in v1.4.6) | Upgrade to v1.4.6 or later |
| `Error: The Agentic AI feature requires a Starter, Growth, or Enterprise license` | No license file or Free tier | Copy `license.json` to `~/vledger-data/` and restart |
| Enterprise license blocked by AgenticAi gate | License issued before v1.4.8 | Upgrade to v1.5.0 — the fix falls back to tier defaults automatically |
| `agent_queries_remaining: 0` | Monthly limit reached | Wait for month rollover, or upgrade tier |

---

## 24. UPGRADE BINARY

```bash
pkill vledger
wget https://github.com/pavondunbar/VectorLedger/releases/download/v1.0.39/vledger-v1.4.5-linux-aarch64.tar.gz
tar -xzf vledger-v1.4.5-linux-aarch64.tar.gz
chmod +x vledger && sudo mv vledger $(which vledger)
vledger --version
```

---

## 25. DEMO VECTORLEDGER TO CLIENTS USING YOUR IMPORTED DATA

Install Nginx:

```bash
sudo apt-get install -y nginx-extras && sudo nginx -t && sudo systemctl restart nginx
```

Start the server:

```bash
nohup vledger start --data-dir ~/vledger-data --bind 0.0.0.0:5433 --pgwire --with-proofs &
```

Change the password using Steps 8 and 9 above.

Give the password to the client. They can run Postgres from their computer:

```bash
psql "host=[PUBLIC IP] port=5432 user=admin sslmode=require"
```

---

## 26. RUN DBEAVER FOR VECTORLEDGER

Make sure VectorLedger server is running with the `--pgwire` flag:

```bash
nohup vledger start --data-dir ./vledger-data \
  --with-proofs --pgwire --bind 0.0.0.0:5433 > nohup.out 2>&1 &
```

Wait for the server to load:

```bash
sleep 600
```

Verify VectorLedger is running:

```bash
ps aux | grep vledger
# You should see a vledger process with --pgwire in the args.
```

Use the SSH Tunnel to open Port 5432 from your local machine:

```bash
ssh -i ./[YOUR-PEM-KEY].pem -L 5433:127.0.0.1:5432 ubuntu@[PUBLIC-IP-ADDRESS] -N -f
```

Check to see if the connection is successful from the tunnel:

```bash
nc -zv 127.0.0.1 5433
# Output should be: Connection to 127.0.0.1 port 5433 [tcp] succeeded!
```

Test on your local computer to see if SSH tunneling works:

```bash
psql "host=127.0.0.1 port=5433 user=[YOUR-USERNAME] dbname=vledger sslmode=require"
# You should see: psql (x.x, server 15.0 (VectorLedger vgdb)) and an SSL connection confirmation.
# Type \q to exit.
```

Download and install DBeaver Community (free) from https://dbeaver.io

Open DBeaver and create a new connection:
- Click **New Database Connection** (plug icon top left)
- Select **PostgreSQL** and click **Next**
- Enter connection details:
  - Host: `127.0.0.1`
  - Port: `5433`
  - Database: `vledger`
  - Username: your VectorLedger username
  - Password: your VectorLedger password
- Click the **SSL** tab → check **Use SSL** → set **SSL Mode** to `require`
- Click **Driver Properties** and set:
  - `preferQueryMode` → `simple`
  - `assumeMinServerVersion` → `9.0`
- Click **Test Connection** — if you see `SQL Error [02000]: No results were returned by the query`, this is normal and expected. Click OK and proceed.
- Click **Finish**

To run queries in DBeaver:
- Left panel → expand connection → Databases → vledger
- Right-click vledger → SQL Editor → New SQL Script
- Type your query and press **Cmd+Enter** to execute

**What works in DBeaver:** SELECT, INSERT, VERIFY_CHAIN(), BALANCE(), exporting results to CSV, browsing ledger/ledger_lines/accounts, database navigator panel.

**What won't work:** system catalog queries (`\dt`, `pg_catalog.*`, `information_schema`), CREATE TABLE / DROP TABLE / UPDATE / DELETE, DBeaver's built-in backup/restore, ER diagrams and schema browsing.

If the tunnel port is already in use when reopening a session:

```bash
lsof -ti :5433 | xargs kill -9
ssh -i ./[YOUR-PEM-KEY].pem -L 5433:127.0.0.1:5432 ubuntu@[PUBLIC-IP-ADDRESS] -N -f
```

To start over with a fresh DBeaver connection: right-click the VectorLedger connection → Delete → confirm → re-add following the steps above.

---

## 27. RUN TESTS ON VECTORLEDGER (OPERATORS ONLY)

### Regression tests (3 tests)

```bash
cargo test --package vledger-ledger regression
```

- `test_reversal_correction_preserves_chain_integrity` — Posts original, reversal, and correction; asserts all chain and accounting invariants hold across all three entries
- `test_reversal_only_preserves_chain_integrity` — Posts original and reversal only; asserts net balance = zero and VERIFY_CHAIN() passes
- `test_double_reversal_rejected` — Asserts the second reversal of the same entry returns an error and VERIFY_CHAIN() still passes

### All vledger-ledger tests (132 tests)

```bash
cargo test --package vledger-ledger
```

| File | Tests | What it covers |
|---|---|---|
| `invariant_tests.rs` | ~30 | INV-1 through INV-14: double-entry balance, idempotency, monotonic sequences, hash chain, reversal, overflow, currency mismatch, exposure limits, closed accounts, global ledger equation, WAL replay |
| `proptest_invariants.rs` | ~11 | Property-based (random inputs, hundreds of iterations): balance, monotonic, hash chain, idempotency, reversal nets to zero, settlement immutability, balance vs sum of lines |
| `stress_tests.rs` | ~8 | 100–5,000 concurrent clients; concurrent reversal race; 500 clients same idempotency key; 200 readers + 100 writers simultaneously |
| `crash_tests.rs` | ~10 | Uncommitted WAL discarded; committed entry survives crash/reopen; idempotency survives crash; reversal atomic; torn WAL stops recovery cleanly |
| `fault_injection_tests.rs` | ~11 | Stage 0–10: crash before write, uncommitted never visible, 20 crash/reopen cycles, reversal atomicity, idempotency persistence, sequence monotonicity across crashes, truncated WAL, corrupted page file |
| `deterministic_recovery_tests.rs` | ~8 | Power loss mid-commit, segment boundary crash, checkpoint deleted/corrupted/future sequence, concurrent open refused, multi-entry batch spanning segment roll |
| `settlement_tests.rs` | ~19 | Posted → Pending → Settled/Failed; hash immutability after settlement; chain integrity after mixed settlements; legal hold place/lift; hold survives WAL replay |
| `concurrent_tests.rs` | ~5 | Consistent snapshots, sequential write consistency, concurrent idempotency deduplication, mixed read/write, hash chain under concurrent writes |
| `regression_tests.rs` | 3 | Described above |
| `entry_db_tests.rs` | 11 | SQLite account persistence: upsert, load, roundtrip, accounts survive store reopen |
| `store::tests` | 11 | Core store unit tests |
| `entry::tests` | 7 | Entry hash chain and validation |
| `amount::tests` | 4 | Amount type unit tests |

### All 498 tests across all packages

```bash
cargo test \
  --package vledger-ledger \
  --package vledger-sql \
  --package vledger-server \
  --package vledger-audit \
  --package vledger-replication \
  --package vledger-compliance \
  --package vledger-foureyes \
  --package vledger-hsm \
  --package vledger-license \
  --package vledger-crypto \
  --package vledger-wal
```

| Package | Tests | Covers |
|---|---|---|
| `vledger-ledger` | 132 | Invariants, crash, fault injection, stress, proptest, regression, deterministic recovery, settlement, legal hold, concurrent, SQLite persistence |
| `vledger-sql` | 95 | Adversarial SQL, full SQL pipeline |
| `vledger-server` | 33 | User management, auth, roles, metrics |
| `vledger-audit` | 17 | Append, verify_chain, hash chaining, persistence |
| `vledger-replication` | 21 | HMAC challenge-response, secret management, divergence detection, protocol encoding |
| `vledger-compliance` | 45 | SOC 2 / PCI-DSS controls, all evidence evaluations, JSON/Markdown serialisation |
| `vledger-foureyes` | 30 | Submit, approve, reject, list_pending, persistence, idempotency, audit events |
| `vledger-hsm` | 19 | Transport, key IDs, KeyPolicy, RemotePyHsmConfig, HsmError display |
| `vledger-license` | 21 | Free tier, tampered signature fallback, feature gating, parse round-trips |
| `vledger-crypto` | 34 | MasterKey determinism, all contexts pairwise distinct, DerivedKey conversions |
| `vledger-wal` | 29 | WAL encryption migration — plaintext, encrypted, mixed segments; segment-index AAD |
| **Total** | **498** | |

### Static analysis

```bash
bash scripts/static-analysis.sh
```

Runs two-pass `cargo clippy` with custom deny rules. Pass 1 targets financial and crypto packages with strict rules (`unwrap_used`, `expect_used`, `panic`, `cast_possible_truncation`, `cast_sign_loss`, `indexing_slicing`). Pass 2 targets all code with `correctness` and `suspicious` groups.

Auto-fix safe lints:

```bash
bash scripts/static-analysis.sh --fix
```

### Mutation testing

```bash
bash scripts/mutation-test.sh --package vledger-crypto
```

Injects plausible bugs and verifies the test suite catches each one. A surviving mutant indicates a test gap. Initial score on `vledger-crypto`: 57 caught / 20 survived (74%).

Run all 7 configured packages:

```bash
bash scripts/mutation-test.sh
```

Results written to `mutants.out/missed.txt` (survivors) and `caught.txt`.

### Formal verification (Kani)

Exhaustively proves properties for all possible inputs within bounded types — not just a sample.

```bash
# One-time setup
cargo install kani-verifier
cargo kani setup

# Run all 21 proof harnesses
bash scripts/formal-verify.sh

# Run a single harness
cargo kani --package vledger-kani --harness wal_boundary_exact

# List all harnesses
cargo kani list --package vledger-kani
```

The 21 harnesses cover four areas:
- **WAL bounds (5)** — `MAX_RECORD_PAYLOAD` cap rejects u32::MAX, usize::MAX, and all values ≥ 64 MiB; accepts all values < 64 MiB
- **Amount invariants (7)** — `Amount::new(0)` always None; checked arithmetic never panics; `checked_add` result equals x+y when no overflow
- **Hash chain (5)** — `ZERO_HASH` is exactly `[0u8; 32]`; `Hash` type is 32 bytes; `merkle_root(&[])` equals `ZERO_HASH`
- **MAC correctness (4)** — `mac_eq` is reflexive, symmetric, returns false when inputs differ, implies byte-for-byte equality

### Fuzz targets (nightly toolchain required, 12 targets)

```bash
cargo install cargo-fuzz

# Run any target (indefinitely by default)
cargo +nightly fuzz run fuzz_wal_recovery

# Cap execution time to 60 seconds
cargo +nightly fuzz run fuzz_transaction -- -max_total_time=60
```

All 12 targets:

```bash
cargo +nightly fuzz run fuzz_wal_recovery
cargo +nightly fuzz run fuzz_sql_parser
cargo +nightly fuzz run fuzz_pgwire_codec
cargo +nightly fuzz run fuzz_backup_restore
cargo +nightly fuzz run fuzz_auth
cargo +nightly fuzz run fuzz_transaction
cargo +nightly fuzz run fuzz_replication
cargo +nightly fuzz run fuzz_backup_keysidecar
cargo +nightly fuzz run fuzz_audit_log
cargo +nightly fuzz run fuzz_compliance_report
cargo +nightly fuzz run fuzz_csv_import
cargo +nightly fuzz run fuzz_wal_recovery_multisegment
```

| Target | What it fuzzes |
|---|---|
| `fuzz_wal_recovery` | Arbitrary WAL segment bytes through full crash recovery; proves no malformed WAL can cause panic, OOM, or infinite loop at startup |
| `fuzz_sql_parser` | Arbitrary SQL strings through parser, planner, and executor against a live in-memory ledger; proves no SQL input can crash the query engine |
| `fuzz_pgwire_codec` | Arbitrary bytes through the PostgreSQL wire protocol decoder; proves a malicious client cannot crash the server before authentication |
| `fuzz_backup_restore` | Arbitrary tar archive bytes through manifest parser, AES-256-GCM decryption, and path-traversal guard |
| `fuzz_auth` | Arbitrary usernames, passwords, role strings, and session tokens; proves no input can panic auth, bypass lockout, or cause a token to validate as the wrong user |
| `fuzz_transaction` | Arbitrary bytes through all four bincode WAL payload deserializers and full recover()/recover_verified()/recover_streaming() pipelines |
| `fuzz_replication` | Protocol message parsing, HMAC computation, secret file parsing, divergence checkpoint verification |
| `fuzz_backup_keysidecar` | JSON parsing, AES-256-GCM wrapped key decryption; asserts single-byte ciphertext corruption always causes decryption failure |
| `fuzz_audit_log` | Arbitrary bytes as audit.log; exercises WORM log parser and chain verifier on corrupt, truncated, and binary content |
| `fuzz_compliance_report` | Adversarially crafted data directories fed to the compliance engine; proves no filesystem state can cause panic or hang |
| `fuzz_csv_import` | Arbitrary bytes through CSV parser iteration, column mapping resolution, and amount field parsing |
| `fuzz_wal_recovery_multisegment` | Fuzz data split across 2–3 WAL segment files in 5 structured scenarios; exercises segment-stitching logic |
