# VectorLedger — Production Operations Runbook

This document covers operational procedures for running VectorLedger in a
production environment. It is intended for the system administrator or on-call
engineer responsible for maintaining a deployed VectorLedger instance.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Starting and Stopping](#2-starting-and-stopping)
3. [Health Checks](#3-health-checks)
4. [Monitoring and Alerting](#4-monitoring-and-alerting)
5. [Backup and Recovery](#5-backup-and-recovery)
6. [Replication](#6-replication)
7. [Key Rotation](#7-key-rotation)
8. [License Management](#8-license-management)
9. [User Management](#9-user-management)
10. [Failure Modes and Recovery](#10-failure-modes-and-recovery)
11. [Performance Tuning](#11-performance-tuning)
12. [Security Hardening Checklist](#12-security-hardening-checklist)
13. [Log Reference](#13-log-reference)
14. [SQL Syntax Notes and Client Compatibility](#14-sql-syntax-notes-and-client-compatibility)
15. [Recovery Point and Time Objectives](#15-recovery-point-and-time-objectives)

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
└──────────────────┬───────────────────────────────────────┘
                   │
   ┌───────────────┴────────────────┐
   │  vledger-data/                 │
   │  ├── wal/          WAL segments│
   │  ├── pages/        Page store  │
   │  ├── catalog/      Users, meta │
   │  ├── audit/        WORM log    │
   │  ├── keys/         Key files   │
   │  └── snapshots/    Backups     │
   └────────────────────────────────┘
                   │
   ┌───────────────┴────────────────┐
   │  PyHSM daemon (port 8443 mTLS) │
   │  Master key sealed inside      │
   └────────────────────────────────┘
```

**Key invariants:**
- Only one `vledger` process may open a data directory at a time (enforced by advisory lock).
- PyHSM must be reachable before `vledger start` — startup fails closed if PyHSM is down.
- The WORM audit log is append-only and fsync'd on every write.

---

## 2. Starting and Stopping

### Start (recommended production command)

```bash
nohup ./target/release/vledger start \
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

> **Merkle roots without `--with-proofs`:** As of v1.0.36, the
> `MERKLE_ROOT(from_seq, to_seq)` SQL function is available at all times
> regardless of server startup flags. Any client with the `admin`,
> `operator`, or `auditor` role can call it directly:
> ```sql
> SELECT MERKLE_ROOT(786000, 786500);
> ```
> The `--with-proofs` flag is a separate, optional feature that causes every
> `SELECT` to automatically append a Merkle proof as a pgwire `NOTICE`. It
> is not required to use `MERKLE_ROOT()` and is not included in the
> recommended production command above. Add it only if you want automatic
> per-query proofs on every SELECT result.

> ⚠ **Network binding security notice:** The command above binds the database
> interface (`--bind 0.0.0.0:5433`) and metrics endpoint (`--metrics-addr 0.0.0.0:9090`)
> to all network interfaces. This is required in some deployment architectures (e.g.
> behind a load balancer or inside a VPC) but must be paired with firewall rules to
> prevent public Internet exposure.
>
> - **Never expose ports 5432, 5433, 5434, or 9090 directly to the public Internet.**
> - Bind database interfaces to a private/internal network interface where your
>   architecture permits it.
> - Bind the metrics endpoint only to the interface reachable by your monitoring
>   infrastructure.
> - See the [Security Hardening Checklist](#12-security-hardening-checklist) for
>   required firewall rules before going to production.

### Stop (graceful)

```bash
# Send SIGTERM — drains in-flight connections then exits
kill -TERM $(cat /var/run/vledger.pid)

# Wait for clean shutdown (up to 60 seconds)
timeout 60 tail --pid=$(cat /var/run/vledger.pid) -f /dev/null
echo "Server stopped"
```

### Stop (immediate — data loss risk)

```bash
# Only use if graceful stop is stuck
kill -KILL $(cat /var/run/vledger.pid)
```

> ⚠ **Never use SIGKILL in production unless the process is hung.** SIGKILL bypasses
> graceful shutdown, leaving WAL records that have not been fsynced. The WAL recovery
> process will replay on next start, but transactions in the group-commit buffer may be lost.

### Verify server is running

```bash
./target/release/vledger status --data-dir /var/lib/vledger/data
```

---

## 3. Health Checks

### TCP connectivity

```bash
# Native TLS port
nc -z 127.0.0.1 5433 && echo "port 5433 open" || echo "port 5433 CLOSED"

# PostgreSQL wire protocol port
nc -z 127.0.0.1 5432 && echo "port 5432 open" || echo "port 5432 CLOSED"
```

### SQL health check

```bash
./target/release/vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT 1"
```

Expected output: `1`

### Hash chain integrity

```bash
./target/release/vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT VERIFY_CHAIN()"
```

Expected output: `status = OK`. Run this after every restart and as a daily cron job.

### Merkle root spot-check

```bash
./target/release/vledger sql \
  --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT MERKLE_ROOT(1, 100000)"
```

Returns a single row with `from_seq`, `to_seq`, `entry_count`, and
`merkle_root` (64-character BLAKE3 hex). Record the root alongside the
sequence range and timestamp — re-run at any future point to confirm the
range has not been tampered with. If the root changes for the same range,
the ledger has been modified.

### Prometheus metrics

```bash
curl -s http://127.0.0.1:9090/metrics | grep vledger
```

### Load balancer / uptime monitor health check endpoint

Use `SELECT 1` via the PostgreSQL wire protocol as your health check query.
PostgreSQL-wire-protocol clients and monitoring systems that issue supported SQL
queries can be used for health monitoring (e.g. Datadog, CloudWatch, PgBouncer).
Validate integration-specific behavior before production deployment — wire-protocol
compatibility does not guarantee that every PostgreSQL ecosystem tool will work
correctly with VectorLedger's append-only ledger model.

---

## 4. Monitoring and Alerting

### Recommended alert thresholds

| Metric | Warning | Critical | Action |
|---|---|---|---|
| `VERIFY_CHAIN()` result | — | `status != OK` | Page on-call immediately — chain is broken |
| Server process not running | — | Process absent | Restart immediately |
| Disk usage on data dir | 70% | 85% | Expand volume or archive old WAL segments |
| WAL segment count | > 100 | > 500 | Run `vledger backup` and consider WAL archiving |
| Audit log chain broken | — | Any break | Page on-call — potential tampering |
| Replication lag (if primary) | > 10s | > 60s | Check replica connectivity and disk |
| License expiry | 30 days | 7 days | Contact pavon@vectorguardlabs.com |

### Cron jobs (recommended)

```cron
# Daily chain integrity check — 2 AM UTC
0 2 * * * /opt/vledger/bin/vledger sql --server 127.0.0.1:5433 \
  --username admin --query "SELECT VERIFY_CHAIN()" \
  >> /var/log/vledger/chain-check.log 2>&1

# Daily Merkle root snapshot — 2:05 AM UTC
# Records the Merkle root for the full ledger range as a tamper-detection checkpoint.
# Compare today's output against a prior run — any change for the same range is an incident.
0 2 * * * /opt/vledger/bin/vledger sql --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT MERKLE_ROOT(1, (SELECT MAX(sequence) FROM ledger))" \
  >> /var/log/vledger/merkle-root.log 2>&1

# Daily backup — 3 AM UTC
0 3 * * * /opt/vledger/scripts/daily-backup.sh >> /var/log/vledger/backup.log 2>&1

# Weekly audit package commitment — Sunday 4 AM UTC
0 4 * * 0 /opt/vledger/bin/vledger audit-package \
  --data-dir /var/lib/vledger/data \
  --tenant "Your Company" \
  --output /var/lib/vledger/audit/weekly-$(date +%Y%m%d).json \
  >> /var/log/vledger/audit-package.log 2>&1

# License expiry check — daily 8 AM UTC
0 8 * * * /opt/vledger/bin/vledger license \
  --data-dir /var/lib/vledger/data \
  >> /var/log/vledger/license-check.log 2>&1
```

### Daily backup script (`/opt/vledger/scripts/daily-backup.sh`)

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

## 5. Backup and Recovery

### Create a backup

```bash
./target/release/vledger backup \
  --data-dir /var/lib/vledger/data \
  --output /var/lib/vledger/backups/vledger-backup-$(date +%Y%m%d).tar
```

The backup is AES-256-GCM encrypted if the master key is available. The `.tar.key`
sidecar file is written alongside the archive — **keep both files together**.

### Verify a backup (without restoring)

```bash
./target/release/vledger backup-verify \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar
```

### Restore a backup

```bash
# Stop the server first
kill -TERM $(cat /var/run/vledger.pid)
sleep 10

# Restore to a new directory (review before making it live)
./target/release/vledger restore \
  --from /var/lib/vledger/backups/vledger-backup-20260901.tar \
  --target /var/lib/vledger/data-restored \
  --force

# Verify integrity after restore
./target/release/vledger verify --data-dir /var/lib/vledger/data-restored

# If verified, swap directories
mv /var/lib/vledger/data /var/lib/vledger/data-old
mv /var/lib/vledger/data-restored /var/lib/vledger/data

# Restart
nohup ./target/release/vledger start --data-dir /var/lib/vledger/data --pgwire &
```

> **Always verify the restored database with `vledger verify` before making it live.**

---

## 6. Replication

### Start a primary with integrated replication

Create `/var/lib/vledger/data/replication.json`:

```json
{
  "role": "primary",
  "replication_addr": "0.0.0.0:5434",
  "ack_timeout_ms": 5000,
  "heartbeat_interval_ms": 1000,
  "tls": {
    "enabled": true,
    "server_hostname": "vledger-primary"
  }
}
```

Then `vledger start` will automatically activate the WAL shipper on port 5434.

### Copy the replication secret to replicas

```bash
# Run on primary after first start
scp /var/lib/vledger/data/replication_secret.hex \
  ubuntu@replica-host:/var/lib/vledger/data/replication_secret.hex

# Set permissions on replica
ssh ubuntu@replica-host \
  "chmod 600 /var/lib/vledger/data/replication_secret.hex"
```

### Manual failover (primary has crashed)

1. Confirm primary is down and will not come back automatically
2. On the replica, stop `vledger start-replica` if running
3. Remove or rename the `replication.json` on the replica (or set `"role": "primary"`)
4. Start the replica as a new primary:
   ```bash
   ./target/release/vledger start \
     --data-dir /var/lib/vledger/data \
     --pgwire &
   ```
5. Update your load balancer / DNS to point to the new primary
6. Notify clients of the failover

> ⚠ **There is no automatic primary election.** Manual intervention is always required.
> Ensure only one node is ever acting as primary at any time to prevent split-brain.

### Check replication lag

On the primary, run:
```bash
./target/release/vledger sql --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT COUNT(*) FROM ledger"
```

And compare with the same query on the replica. A persistent gap indicates lag.

---

## 7. Key Rotation

### Rotate HSM keys (Enterprise tier)

```bash
# Model 1 — local PyHSM
./target/release/vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --caller-id ops-team

# Model 2 — remote PyHSM
./target/release/vledger rotate-keys \
  --data-dir /var/lib/vledger/data \
  --pyhsm-endpoint https://pyhsm.internal.example.com:8443 \
  --pyhsm-ca-cert /etc/vledger/pyhsm-ca.pem \
  --caller-id ops-team
```

Key rotation is non-destructive. Existing ciphertext remains decryptable with the
archived key version. New writes use the new key immediately.

Every rotation event is recorded in the WORM audit log (`key_rotated`).

---

## 8. License Management

### Check current license

```bash
./target/release/vledger license --data-dir /var/lib/vledger/data
```

### Install a new or renewed license

```bash
# Place the license.json provided by VectorGuard Labs into the data directory
cp /path/to/new-license.json /var/lib/vledger/data/license.json

# The daily license watcher will pick it up at the next UTC midnight.
# To apply immediately, restart the server.
kill -TERM $(cat /var/run/vledger.pid)
nohup ./target/release/vledger start --data-dir /var/lib/vledger/data --pgwire &
```

### License expiry behaviour

- The server checks the license at startup and at midnight UTC daily.
- If the license expires while the server is running, paid features are disabled
  at the next midnight tick without requiring a restart.
- Free tier continues to function indefinitely with no license file.

Contact `pavon@vectorguardlabs.com` at least 30 days before expiry.

---

## 9. User Management

### Create a user

```bash
./target/release/vledger user create \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --role operator
# Password will be prompted interactively
```

Roles: `admin`, `operator`, `auditor`, `readonly`

### Change a password

```bash
./target/release/vledger user set-password \
  --data-dir /var/lib/vledger/data \
  --username alice
# New password will be prompted interactively
```

Password changes immediately revoke all active sessions for that user.

### Disable a compromised account

```bash
./target/release/vledger user set-enabled \
  --data-dir /var/lib/vledger/data \
  --username alice \
  --enabled false
```

Disabling an account immediately revokes all active sessions.

### List all users

```bash
./target/release/vledger user list --data-dir /var/lib/vledger/data
```

---

## 10. Failure Modes and Recovery

### The server won't start

**Symptom:** `vledger start` exits immediately with an error.

| Error message | Cause | Fix |
|---|---|---|
| `Data directory not found` | Wrong `--data-dir` path | Check path; run `vledger init` if new install |
| `cannot lock data directory` | Another vledger process is running | `pkill vledger`; check for stale PID files |
| `HSM daemon not reachable` | PyHSM is down | Start PyHSM; check socket/endpoint |
| `Feature 'pgwire' is not available` | License tier too low | Remove `--pgwire` flag or upgrade license |
| `WAL sync mode is NO_SYNC...REFUSED` | Existing data with `no_sync` | Use `group_commit` or `per_record`; note that `no_sync` is not available in release binaries at all — it requires a dev build with `--features dev-no-sync` |
| `Audit log cannot be opened` | Permissions or disk full | Check disk space; `chmod 700 data/audit/` |

### The hash chain is broken (`VERIFY_CHAIN()` returns non-OK)

This is a critical incident. Do not accept new writes until the issue is resolved.

1. Stop the server immediately: `kill -TERM $(cat /var/run/vledger.pid)`
2. Run: `./target/release/vledger verify --data-dir /var/lib/vledger/data`
3. Note the sequence number where the chain breaks
4. Do not modify any files in the data directory
5. Contact `pavon@vectorguardlabs.com` immediately
6. Restore from the most recent verified backup

### WAL corruption detected on startup

**Symptom:** Log shows `torn_write_detected=true` during WAL recovery.

1. The server automatically truncates at the corruption point and continues
2. Any transactions after the last clean checkpoint are discarded
3. Run `VERIFY_CHAIN()` after startup to confirm integrity
4. The number of discarded transactions is logged as `discarded=N`
5. If `discarded > 0`, notify affected clients that their last N transactions were not committed

### Disk full

1. Stop the server gracefully
2. Expand the volume or free space
3. Verify enough space exists: `df -h /var/lib/vledger`
4. Restart the server

> **Minimum recommended free space:** 20% of data directory size at all times.
> WAL segments accumulate until a checkpoint is written.

### PyHSM unreachable at startup

The server will refuse to start if PyHSM is configured but unreachable. This is
intentional — VectorLedger fails closed rather than starting without key access.

1. Check PyHSM daemon status: `systemctl status pyhsm` or check the socket
2. Verify the socket path: `ls -la /tmp/pyhsm.sock`
3. Start PyHSM before restarting VectorLedger

### Replica is lagging or disconnected

1. Check replica logs for `Replication error:` entries
2. Verify network connectivity from replica to primary port 5434
3. Verify the `replication_secret.hex` matches on both nodes
4. If the replica has diverged significantly, re-seed it from a backup:
   ```bash
   # On primary
   ./target/release/vledger backup --data-dir /var/lib/vledger/data \
     --output /tmp/reseed.tar
   scp /tmp/reseed.tar ubuntu@replica:/tmp/
   scp /var/lib/vledger/data/replication_secret.hex \
     ubuntu@replica:/var/lib/vledger/data/

   # On replica
   pkill vledger
   ./target/release/vledger restore --from /tmp/reseed.tar \
     --target /var/lib/vledger/data --force
   # Then restart vledger start-replica
   ```

### Forgotten admin password

1. Stop the server
2. Check for the initial credential file (present only on first start):
   ```bash
   cat /var/lib/vledger/data/catalog/.admin_initial_credentials
   ```
3. If that file is gone, reset the password directly:
   ```bash
   ./target/release/vledger user set-password \
     --data-dir /var/lib/vledger/data \
     --username admin
   ```
   This works only when the server is stopped (direct mode).

---

## 11. Performance Tuning

### WAL sync mode

| Mode | Durability | TPS (relative) | Use case |
|---|---|---|---|
| `group_commit` (default) | Up to 1 flush interval | Highest | Most deployments |
| `per_record` | Zero data loss | ~30–50% lower | Strict regulatory |
| `no_sync` | None | Highest | Dev/CI builds only — requires `--features dev-no-sync` at compile time; not available in release binaries |

Tune the group commit interval:
```bash
# More durable (default 2ms)
--wal-sync-mode group_commit --group-commit-delay-ms 2

# Higher throughput (accept more exposure)
--wal-sync-mode group_commit --group-commit-delay-ms 10
```

### Connection limits

Default is 128 native + 64 pgwire. Increase for high-concurrency deployments:

```bash
--max-connections 500
```

### Query timeout

Default 30 seconds. Reduce for stricter SLAs:

```bash
--query-timeout-ms 10000
```

### Storage

- **Local NVMe** (e.g. AWS i4i): best fsync latency, highest TPS
- **EBS gp3**: adequate for most workloads, simpler operational model
- **Minimum recommended IOPS**: 3,000 for group_commit; 10,000+ for per_record

---

## 12. Security Hardening Checklist

Run through this before going to production:

- [ ] Data directory permissions: `chmod 700 /var/lib/vledger/data`
- [ ] `keys/` subdirectory: `chmod 700 /var/lib/vledger/data/keys/`
- [ ] `catalog/` subdirectory: `chmod 700 /var/lib/vledger/data/catalog/`
- [ ] Remove `keys/MASTER_KEY_PLACEHOLDER.txt` if present
- [ ] Replace self-signed TLS certificate with a CA-signed one:
  ```bash
  # Place CA-signed cert and key, then restart with:
  --tls-cert-path /etc/vledger/server.crt \
  --tls-key-path /etc/vledger/server.key
  ```
- [ ] Change the default admin password: `vledger user set-password --username admin`
- [ ] Delete initial credential file: `rm /var/lib/vledger/data/catalog/.admin_initial_credentials`
- [ ] Confirm PyHSM is using Model 2 (remote mTLS) for production
- [ ] Firewall: port 5433 and 5432 accessible only to application servers
- [ ] Firewall: port 5434 (replication) accessible only to replica hosts
- [ ] Firewall: port 9090 (metrics) accessible only to monitoring infrastructure
- [ ] Install a valid `license.json` for the appropriate tier
- [ ] Verify `vledger license --data-dir ...` shows no warnings
- [ ] Run `vledger verify --self-test` and confirm all phases pass
- [ ] Run `SELECT VERIFY_CHAIN()` and confirm `status = OK`
- [ ] Schedule daily `VERIFY_CHAIN()` cron job
- [ ] Schedule daily backup cron job
- [ ] Test restore procedure from backup before going live
- [ ] Perform a documented backup restoration drill at least quarterly and after any
  material change to the backup or restore subsystem. Record the following for
  each drill:
  - Date and time of drill
  - Backup file used (name, date, size)
  - Restore duration (wall clock time)
  - Transaction/sequence count after restore
  - `VERIFY_CHAIN()` result
  - `vledger verify` result
  - Operator who performed the drill
  - Any issues encountered and how they were resolved

  A backup that has never been tested in a restore is not a verified backup.
- [ ] Run the full test suite to confirm the binary was built from a clean codebase:
  ```bash
  cargo test --package vledger-ledger --package vledger-sql \
             --package vledger-server --package vledger-audit \
             --package vledger-replication --package vledger-compliance \
             --package vledger-foureyes --package vledger-hsm \
             --package vledger-license --package vledger-crypto \
             --package vledger-wal
  ```
  All 498 tests must pass before deploying a new build to production.

---

## 13. Log Reference

VectorLedger uses structured JSON-style tracing logs. Key log fields:

| Log message | Meaning |
|---|---|
| `VectorLedger listening` | Server started successfully |
| `WAL recovery complete committed=N discarded=0` | Normal startup replay |
| `WAL recovery complete ... discarded=N` | Transactions lost — check chain |
| `torn_write_detected=true` | WAL corruption at shutdown — data truncated |
| `Replica authenticated (TLS)` | A replica connected successfully |
| `Replica ACK timeout` | Replica is lagging or disconnected |
| `Auth failed: invalid credentials` | Failed login attempt |
| `Account locked due to too many failed attempts` | Brute-force lockout triggered |
| `Password hash upgraded to hardened Argon2id params` | Lazy rehash on login |
| `License tier changed during daily re-check` | License downgrade detected |
| `WAL shipper: TLS disabled` | Replication running without TLS — dev only |
| `No database signing key found` | Audit packages will not be signed |

### Audit log events

All security-relevant events are written to `data/audit/audit.log` in WORM format:

| Event type | Trigger |
|---|---|
| `server_started` | Every `vledger start` |
| `auth_event` | Every login attempt (success and failure) |
| `query_executed` | Every SQL statement |
| `entry_posted` | Every committed journal entry |
| `four_eyes_submitted` | Four-eyes entry submitted for approval |
| `four_eyes_approved` | Four-eyes entry approved |
| `four_eyes_rejected` | Four-eyes entry rejected |
| `backup_created` | Every `vledger backup` |
| `key_rotated` | Every `vledger rotate-keys` key rotation |

Verify the audit log chain at any time:
```bash
./target/release/vledger sql --server 127.0.0.1:5433 \
  --username admin \
  --query "SELECT VERIFY_CHAIN()"
```

Export for external review:
```bash
./target/release/vledger audit-export \
  --data-dir /var/lib/vledger/data \
  --format json \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --output /tmp/audit-september-2026.json
```

---

## 14. SQL Syntax Notes and Client Compatibility

### String literals, numeric literals, and quoting rules

VectorLedger's SQL parser is more lenient than standard PostgreSQL in some areas.
One known difference is that VectorLedger may accept double-quoted values as string
literals in certain contexts. This is non-standard behavior.

In standard PostgreSQL, double quotes denote **identifiers** (table names, column
names, etc.), not string values. Using double quotes around a value would throw:
`column "45289" does not exist`. VectorLedger silently accepting them is a parser
quirk, not a supported feature.

**Use the following rules for all queries, application code, and scripts:**

```sql
-- Numeric literal: no quotes
SELECT * FROM ledger WHERE sequence = 45289;

-- String literal: single quotes only
SELECT * FROM ledger WHERE description = 'Payment to Jeremy Tamura';

-- Non-standard and unreliable: double quotes around a value
-- Do NOT use this form even if VectorLedger currently accepts it
SELECT * FROM ledger WHERE description = "Payment to Jeremy Tamura";
```

Use single quotes for string values. Do not quote numeric literals unless the
query intentionally requires a type conversion. Do not rely on double-quote string
acceptance — this behavior may change in a future VectorLedger release without notice.

> ⚠ **Portability note:** SQL written with double-quoted string literals will fail
> immediately if run against a standard PostgreSQL instance. Write portable SQL
> from the start.

### Unsupported PostgreSQL features

VectorLedger is PostgreSQL wire-protocol compatible but is not a full PostgreSQL
implementation. The following are not supported and will return errors:

| Feature | Notes |
|---|---|
| `pg_catalog.*` | System catalog tables do not exist |
| `information_schema.*` | Not implemented |
| `\dt`, `\d`, `\l` and other psql meta-commands | These query `pg_catalog` internally |
| `CREATE TABLE`, `DROP TABLE` | The ledger schema is fixed and append-only |
| `UPDATE`, `DELETE` | The ledger is immutable by design |
| `CREATE INDEX`, `ALTER TABLE` | Not supported |

### Recommended SQL client tools

| Tool | Platform | Notes |
|---|---|---|
| `psql` | Mac, Linux, Windows | Proven working; use `sslmode=require` and `host=127.0.0.1` to force IPv4 |
| DBeaver Community | Mac, Windows, Linux | Recommended GUI; see DBeaver connection note below |
| TablePlus | Mac, Windows, Linux | Lightweight GUI alternative |
| DataGrip | Mac, Windows, Linux | Full IDE-grade SQL tool; paid |

### DBeaver connection behavior

When you click **Test Connection** in DBeaver's setup dialog, DBeaver issues an
internal validation query after the TCP and authentication handshake completes.
VectorLedger does not implement the PostgreSQL system catalog tables that DBeaver
queries during this validation step, so DBeaver returns:

```
SQL Error [02000]: No results were returned by the query.
```

What this error means in practice:

- **The TCP connection was established successfully.** The error occurs after
  the connection is open, not before.
- **Authentication succeeded.** DBeaver would show an authentication error, not
  a `02000`, if credentials were wrong.
- **The error is in DBeaver's post-connect validation query**, not in the
  connection itself. DBeaver issues a catalog introspection query that returns
  no rows against VectorLedger, and DBeaver's internal code treats an empty
  result as an error condition.
- **Subsequent SQL execution is not affected.** Once you dismiss the error and
  open a SQL Editor, queries against `ledger`, `ledger_lines`, `accounts`,
  `VERIFY_CHAIN()`, and `BALANCE()` execute normally.

**To suppress the error:** In DBeaver's connection settings, go to
**Driver Properties** and set `assumeMinServerVersion` to `9.0`. This reduces
the scope of DBeaver's startup introspection queries. The `02000` warning may
still appear on some DBeaver versions — dismiss it and proceed. It does not
indicate a broken connection.

### Connecting via psql

```bash
psql "host=127.0.0.1 port=5433 user=[USERNAME] dbname=vledger sslmode=require"
```

> **Note:** Use `host=127.0.0.1` explicitly rather than `host=localhost`. On many
> systems `localhost` resolves to `::1` (IPv6), which does not route through the
> SSH tunnel. `127.0.0.1` forces IPv4 and connects correctly.

### Merkle Proofs via pgwire

> **As of v1.0.36, you do not need `--with-proofs` to query Merkle roots.**
> Use `SELECT MERKLE_ROOT(from_seq, to_seq)` from any SQL client — no server
> flag required. The `--with-proofs` flag described below is a separate
> feature that auto-attaches a proof `NOTICE` to every SELECT result. Use it
> only if you want that automatic behaviour.

When the server is started with `--with-proofs --pgwire`, VectorLedger computes a
BLAKE3 Merkle root over every SELECT result set and delivers it to pgwire clients as
a PostgreSQL `NoticeResponse` (message type `N`) immediately after the data rows and
before `CommandComplete`.

**psql output (with `\x` expanded display):**

```
pavon=> select * from ledger where sequence = '786295';
-[ RECORD 1 ]+------------------------------------------------------------------
sequence     | 786295
id           | e99c3ea8-7761-419b-9a5a-79b570220a13
status       | Posted
description  | Cash withdrawal
...
NOTICE:  Merkle root: b34281d3a443635aa8e6915842ff199d37b53ec8458f9a056e6284838221a776 (1 leaf, verified: true)
```

The notice format is:

```
Merkle root: <64-hex-char BLAKE3 root> (<N> leaf[s], verified: <true|false>)
```

- **`root`** — BLAKE3 Merkle root computed over the `content_hash` of every returned
  row (not the full ledger).
- **`leaf count`** — number of rows in the result set.
- **`verified: true`** — the server re-walked all leaf proof paths up to the root and
  confirmed they all match. `false` means the signing key was unavailable (no integrity
  failure — just no signature).

**Important notes:**

- The Merkle root covers the **query result set**, not the full ledger. Running
  `SELECT * FROM ledger` and `SELECT * FROM ledger WHERE sequence = X` produce
  different Merkle roots.
- To get a Merkle root over the entire ledger, use `vledger audit-package`. That
  command streams all entries, builds the full-ledger Merkle tree, and signs the root
  with the database Ed25519 key.
- DBeaver suppresses `NOTICE` messages by default. To surface them, open
  **Preferences → Database → Notifications** and enable "Show server warnings". They
  also appear in DBeaver's **Error Log** view regardless of that setting.
- Notice messages are always emitted when `--with-proofs` is active — there is no
  per-query way to suppress them via pgwire. If you need proof-free responses on
  specific queries, restart without `--with-proofs` and use `SELECT MERKLE_ROOT(from, to)`
  on demand instead — it requires no server flag and gives you the same root value.

### pgAdmin compatibility

pgAdmin (all versions) is **not recommended** for use with VectorLedger. pgAdmin
relies heavily on `pg_catalog` and `information_schema` for core functionality
including listing databases, enabling the Query Tool, and browsing the object tree.
Because VectorLedger does not implement these system catalogs, pgAdmin throws
`list index out of range` errors and the Query Tool may be inaccessible.

Use DBeaver, TablePlus, or `psql` instead.

---

## 15. Recovery Point and Time Objectives

The values in this section are operational targets. **Do not publish these numbers
externally until they have been measured against your specific hardware, deployment
configuration, and data volume.** Benchmarked figures should replace the estimates
below before this runbook is used in a production SLA or compliance audit.

### Recovery Point Objective (RPO)

RPO defines the maximum amount of committed data that can be lost under each
failure scenario.

| Scenario | Expected RPO | Notes |
|---|---|---|
| Process crash (SIGKILL or OOM) | 0 committed transactions | WAL replays on next start; group-commit buffer may lose up to 1 flush interval of in-flight transactions |
| Host failure (hard power loss) | 0–1 flush interval | Depends on WAL sync mode; `per_record` mode gives zero committed-data loss; `group_commit` exposes up to `--group-commit-delay-ms` ms of in-flight writes |
| Primary failure with replica running | 0 acknowledged transactions | Replica receives WAL ACKs before primary confirms commit; unACK'd in-flight writes may be lost |
| Restore from backup | Data since last backup | RPO equals the backup interval — daily backups mean up to 24 hours of data loss in a full-restore scenario |

### Recovery Time Objective (RTO)

RTO defines how quickly the system can be restored and accepting new writes.

| Scenario | Expected RTO | Notes |
|---|---|---|
| Process crash — restart on same host | Minutes | WAL replay time depends on segment count since last checkpoint; measure against your typical WAL backlog |
| Host failure — failover to warm replica | Minutes | Manual failover required (see [Replication](#6-replication)); no automatic election |
| Host failure — no replica, restore from backup | To be measured | Depends on backup size, network transfer speed, restore verification time, and `VERIFY_CHAIN()` duration |
| Full restore from backup (planned) | To be measured | Benchmark this during your quarterly restore drill and record the result |

### Measuring your actual RTO

Run a timed restore drill using your most recent backup:

```bash
time vledger restore \
  --from /var/lib/vledger/backups/vledger-backup-latest.tar \
  --target /var/lib/vledger/data-drill \
  --force && \
vledger verify --data-dir /var/lib/vledger/data-drill
```

Record the wall-clock time from `vledger restore` start to `VERIFY_CHAIN()` returning
`status = OK`. That is your measured RTO for a backup restore scenario. Update this
table with the result after each quarterly drill.

> ⚠ **Do not manufacture RTO/RPO numbers for marketing or compliance documents.**
> Use only values measured against your actual deployment. Unverified estimates in
> an SLA or audit report are a liability, not an asset.

---

*VectorGuard Labs — VectorLedger Operations Runbook*
*For support: pavon@vectorguardlabs.com*
*Security incidents: pavon@vectorguardlabs.com*
