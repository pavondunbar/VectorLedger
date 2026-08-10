# VectorLedger Recovery Objectives

This document defines the Recovery Point Objective (RPO), Recovery Time
Objective (RTO), and operational runbooks for VectorLedger deployments.

---

## Definitions

| Term | Definition |
|------|------------|
| **RPO** | Maximum acceptable data loss — how far back in time the database may roll back after a failure |
| **RTO** | Maximum acceptable downtime — how long until the service is back in a read/write state |
| **Crash** | Process killed or machine power-cycled without a clean shutdown |
| **Media failure** | Disk corruption, RAID failure, or storage-layer data loss |
| **DR** | Disaster Recovery — complete loss of the primary site |

---

## Recovery Point Objectives (RPO)

| Deployment Mode | WAL Sync Mode | RPO | Notes |
|---|---|---|---|
| Single-node | `per_record` | **0 seconds** | Every committed transaction is fsynced before ACK |
| Single-node | `group_commit` (default) | **≤ flush interval** (default 2 ms) | A hard crash may lose at most one flush window of committed transactions |
| Single-node | `no_sync` | **unbounded** | Dev/test only. Never use in production |
| Primary + synchronous replica | `per_record` | **0 seconds** | Replica ACKs before primary returns to client |
| Primary + synchronous replica | `group_commit` | **≤ flush interval** | Both nodes flush within the same window |
| Backup-based DR (no replica) | any | **≤ backup interval** | Typically 24 h for daily backups; reduce with more frequent snapshots |

### Achieving RPO = 0

Configure:
```
vledger start --wal-sync-mode per_record
```
And for synchronous replication, add a replica node per
`docs/replication-setup.md`.

### Group-commit RPO

With the default `group_commit` mode and `--group-commit-delay-ms 2`,
the worst-case data loss after a hard power failure is **2 ms** of
committed-but-not-fsynced transactions.  The WAL remains consistent —
those transactions are simply absent after recovery (they were never
visible to clients because the ACK had not been sent).

---

## Recovery Time Objectives (RTO)

| Failure Scenario | RTO | Steps |
|---|---|---|
| Process crash (data intact) | **< 30 seconds** | `vledger start` — WAL replay is automatic |
| Single corrupted WAL segment | **< 5 minutes** | `vledger verify`, then `vledger restore` from backup |
| Full disk failure (with replica) | **< 2 minutes** | Promote replica: `vledger-replica promote` |
| Full disk failure (backup-based) | **< 1 hour** | `vledger restore --from <archive>`, then `vledger verify` |
| Complete site loss (DR) | **< 4 hours** | Restore from off-site backup, re-seed replica |

---

## Operational Runbooks

### 1. Crash Recovery (automated)

VectorLedger performs WAL recovery automatically on every startup.
No operator intervention is required for a normal process crash:

```bash
# After a crash, simply restart:
vledger start --data-dir /var/lib/vledger

# Verify integrity after restart:
vledger verify --data-dir /var/lib/vledger
```

Recovery output example:
```
WAL integrity  ... ✓ (47 committed txns)
Ledger chain   ... ✓ (47 entries, tip=a3f2...)
✓ Verification complete
```

If `verify` reports a broken chain, stop immediately and follow the
**Corrupted Data** runbook below.

### 2. Point-in-Time Backup Restore

```bash
# Create a backup (with AES-256-GCM encryption):
vledger backup --data-dir /var/lib/vledger \
               --output /mnt/backups/vledger-$(date +%Y%m%d).tar

# Verify the backup before storing it off-site:
vledger backup-verify --data-dir /var/lib/vledger \
                      --from /mnt/backups/vledger-$(date +%Y%m%d).tar

# Restore to a new directory:
vledger restore --from /mnt/backups/vledger-20260810.tar \
                --target /var/lib/vledger-restored \
                --force

# Verify restored data:
vledger verify --data-dir /var/lib/vledger-restored
```

### 3. Corrupted Data / Broken Hash Chain

```bash
# Step 1: Stop the server immediately.
systemctl stop vledger

# Step 2: Run verification to determine the scope.
vledger verify --data-dir /var/lib/vledger

# Step 3: Do NOT write anything to the data directory.

# Step 4: Restore from the most recent known-good backup.
vledger restore \
  --from /mnt/backups/vledger-$(date +%Y%m%d -d yesterday).tar \
  --target /var/lib/vledger-new \
  --force

# Step 5: Verify the restored data.
vledger verify --data-dir /var/lib/vledger-new

# Step 6: If clean, atomically swap directories and restart.
mv /var/lib/vledger /var/lib/vledger-corrupt-$(date +%s)
mv /var/lib/vledger-new /var/lib/vledger
systemctl start vledger

# Step 7: Alert the security team — data corruption is a security event.
```

### 4. Replica Promotion (primary failure)

```bash
# On the replica node:
# Step 1: Verify replica WAL integrity.
vledger verify --data-dir /var/lib/vledger-replica

# Step 2: Promote the replica to primary.
#         This stops the WAL receiver and starts the primary server.
vledger-replica promote --data-dir /var/lib/vledger-replica \
                        --bind 0.0.0.0:5433

# Step 3: Update DNS or load-balancer to point at the new primary.

# Step 4: After the old primary is recovered, re-seed it as a new replica
#         from the promoted primary's backup.
```

### 5. WAL Key Rotation

Perform after a master key compromise or as part of regular key hygiene:

```bash
# Step 1: Stop writes (maintenance mode or stop server).
systemctl stop vledger

# Step 2: Rotate WAL encryption keys.
vledger rotate-keys --data-dir /var/lib/vledger

# Step 3: Update key_source.json to point at the new HSM key slot.

# Step 4: Restart.
systemctl start vledger

# Step 5: Verify.
vledger verify --data-dir /var/lib/vledger
```

---

## Backup Schedule Recommendations

| Data criticality | Backup frequency | Retention |
|---|---|---|
| Production financial data | Every 4 hours | 90 days |
| Staging / pre-production | Daily | 30 days |
| Development | Weekly | 7 days |

Backups should be:
- Stored in a different availability zone or region from the primary
- Tested monthly with a full restore to a temporary environment
- Verified with `vledger backup-verify` immediately after creation

---

## Monitoring Targets

The following metrics (exposed via the `/metrics` Prometheus endpoint —
see `docs/observability.md`) should have alerts:

| Metric | Alert threshold | Severity |
|---|---|---|
| `vledger_wal_sync_lag_ms` | > 100 ms | Warning |
| `vledger_wal_sync_lag_ms` | > 500 ms | Critical |
| `vledger_replica_lag_lsn` | > 1000 records | Warning |
| `vledger_replica_lag_lsn` | > 10000 records | Critical |
| `vledger_backup_age_seconds` | > 14400 (4 h) | Warning |
| `vledger_chain_verification_failures_total` | > 0 | Critical (page on-call) |
| `vledger_auth_failures_total` rate | > 10/min | Warning (brute-force) |

---

## Contact

For production incidents, contact the on-call team via:
- PagerDuty rotation: `vledger-oncall`
- Security incidents: `security@vectorguardlabs.com`
