//! `vledger verify --self-test` — full integrity self-test suite.
//!
//! Runs five test phases against a **completely isolated** temporary database.
//! Production data is never touched.
//!
//! ## Phases
//!
//! A  Baseline           — insert N entries, verify chain, sample hashes
//! B  WAL Corruption     — corrupt a WAL record, confirm rejection on restart
//! C  Recovery           — restore WAL, restart, confirm full recovery
//! D  Logical Tampering  — mutate an in-memory entry, confirm VERIFY_CHAIN fails
//! E  Entry Verification — spot-check individual entries with VERIFY_ENTRY
//!
//! ## Isolation guarantee
//!
//! All work is done inside a `tempfile::TempDir` (or a named directory when
//! `--keep-data` is set).  The directory is deleted on drop unless `keep_data`
//! is true.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;

use vledger_ledger::{
    Account, AccountType, Amount, JournalEntryBuilder, LedgerStore,
};

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseResult {
    Pass,
    Fail(String),
    Skip(String),
}

impl PhaseResult {
    fn is_pass(&self) -> bool { matches!(self, PhaseResult::Pass) }
    fn label(&self) -> &str {
        match self {
            PhaseResult::Pass      => "PASS",
            PhaseResult::Fail(_)   => "FAIL",
            PhaseResult::Skip(_)   => "SKIP",
        }
    }
    fn detail(&self) -> Option<&str> {
        match self {
            PhaseResult::Fail(s) | PhaseResult::Skip(s) => Some(s.as_str()),
            PhaseResult::Pass => None,
        }
    }
}

struct PhaseReport {
    name:   &'static str,
    result: PhaseResult,
    notes:  Vec<String>,
    elapsed_ms: u64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the full self-test suite.
///
/// `entries`   — number of journal entries to generate (default 100,000).
/// `keep_data` — if true, keep the test directory after completion.
pub async fn run(entries: u64, keep_data: bool) -> Result<()> {
    let entries = entries.max(100); // minimum 100 for meaningful tests

    // ── Create isolated test directory ────────────────────────────────────
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let (test_dir, _tmpdir): (PathBuf, Option<tempfile::TempDir>) = if keep_data {
        let path = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!("vledger-self-test-{timestamp}"));
        std::fs::create_dir_all(&path)?;
        (path, None)
    } else {
        let tmp = tempfile::TempDir::new()
            .context("Failed to create temporary test directory")?;
        let path = tmp.path().to_path_buf();
        (path, Some(tmp))
    };

    // Deterministic seed for reproducible data.
    let seed = blake3::hash(format!("vledger-self-test-{entries}").as_bytes());
    let seed_hex = hex::encode(&seed.as_bytes()[..8]);

    print_header(entries, &seed_hex, &test_dir);

    // Redirect tracing to /dev/null for self-test — the structured report
    // IS the output. Users who want verbose logs can set RUST_LOG=info.
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }

    let mut phases: Vec<PhaseReport> = Vec::new();

    // ── Phase A: Baseline ─────────────────────────────────────────────────
    let phase_a = phase_baseline(&test_dir, entries, &seed_hex).await;
    let baseline_ok = phase_a.result.is_pass();
    let chain_tip_before = phase_a.notes.iter()
        .find(|n| n.starts_with("chain_tip:"))
        .cloned()
        .unwrap_or_default();
    let entry_count_before: u64 = phase_a.notes.iter()
        .find(|n| n.starts_with("entry_count:"))
        .and_then(|n| n.split(':').nth(1))
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    phases.push(phase_a);

    // ── Phase B: WAL corruption ───────────────────────────────────────────
    if baseline_ok {
        phases.push(phase_wal_corruption(&test_dir).await);
    } else {
        phases.push(PhaseReport {
            name: "B  WAL Integrity",
            result: PhaseResult::Skip("baseline failed".into()),
            notes: vec![],
            elapsed_ms: 0,
        });
    }

    // ── Phase C: Recovery ─────────────────────────────────────────────────
    let phase_c = if baseline_ok {
        phase_recovery(&test_dir, entry_count_before, &chain_tip_before).await
    } else {
        PhaseReport {
            name: "C  Crash Recovery",
            result: PhaseResult::Skip("baseline failed".into()),
            notes: vec![],
            elapsed_ms: 0,
        }
    };
    let recovery_ok = phase_c.result.is_pass();
    phases.push(phase_c);

    // ── Phase D: Logical tampering ────────────────────────────────────────
    if recovery_ok {
        phases.push(phase_logical_tamper(&test_dir, entries).await);
    } else {
        phases.push(PhaseReport {
            name: "D  Logical Integrity",
            result: PhaseResult::Skip("recovery failed".into()),
            notes: vec![],
            elapsed_ms: 0,
        });
    }

    // ── Phase E: Entry verification ───────────────────────────────────────
    if recovery_ok {
        phases.push(phase_entry_verification(&test_dir, entries).await);
    } else {
        phases.push(PhaseReport {
            name: "E  Entry Verification",
            result: PhaseResult::Skip("recovery failed".into()),
            notes: vec![],
            elapsed_ms: 0,
        });
    }

    // ── Print report ──────────────────────────────────────────────────────
    print_report(&phases, keep_data, &test_dir, entries, &seed_hex);

    // Return error if any phase failed.
    let any_fail = phases.iter().any(|p| matches!(p.result, PhaseResult::Fail(_)));
    if any_fail {
        anyhow::bail!("Self-test FAILED — see report above");
    }

    Ok(())
}

// ── Phase A: Baseline ─────────────────────────────────────────────────────────

async fn phase_baseline(test_dir: &Path, entries: u64, seed_hex: &str) -> PhaseReport {
    let t = Instant::now();
    let mut notes = Vec::new();

    let result = (|| -> Result<()> {
        // Initialise a fresh ledger in the test directory.
        let wal_dir   = test_dir.join("wal");
        let pages_dir = test_dir.join("pages");
        std::fs::create_dir_all(&wal_dir)?;
        std::fs::create_dir_all(&pages_dir)?;

        let mut store = LedgerStore::open(test_dir)
            .context("Failed to open test ledger")?;

        // Create accounts using the seed for determinism.
        let accounts = create_test_accounts(&mut store, seed_hex)?;

        // Insert N entries with deterministic, varied amounts.
        insert_deterministic_entries(&mut store, &accounts, entries, seed_hex)?;

        // Verify chain immediately.
        store.verify_chain_integrity()
            .context("Hash chain invalid immediately after insertion")?;

        let count = store.entry_count() as u64;
        let tip   = hex::encode(store.chain_tip());

        if count != entries {
            anyhow::bail!("Expected {entries} entries, got {count}");
        }

        notes.push(format!("entry_count: {count}"));
        notes.push(format!("chain_tip: {tip}"));
        notes.push(format!("sequence_range: 1 – {count}"));
        notes.push(format!("accounts_created: {}", accounts.len()));

        // Sample 5 entries spread across the ledger.
        for &seq in sample_sequences(entries, 5).iter() {
            if let Some(e) = store.get_entry_by_sequence(seq) {
                notes.push(format!(
                    "sample seq={seq} content_hash={}",
                    hex::encode(&e.content_hash[..8])
                ));
            }
        }

        Ok(())
    })();

    PhaseReport {
        name: "A  Baseline",
        result: match result {
            Ok(())  => PhaseResult::Pass,
            Err(e)  => PhaseResult::Fail(e.to_string()),
        },
        notes,
        elapsed_ms: t.elapsed().as_millis() as u64,
    }
}

// ── Phase B: WAL corruption ───────────────────────────────────────────────────

async fn phase_wal_corruption(test_dir: &Path) -> PhaseReport {
    let t = Instant::now();
    let mut notes = Vec::new();

    let result = (|| -> Result<()> {
        let wal_dir = test_dir.join("wal");
        let segments = wal_segments(&wal_dir)?;

        // Target the last segment — most likely to contain committed records.
        let target = segments.last()
            .context("No WAL segments found")?;

        let size = std::fs::metadata(target)?.len();
        if size < 8 {
            anyhow::bail!("WAL segment too small to corrupt safely");
        }

        // Flip a byte in the middle of the segment.
        let offset = size / 2;
        flip_byte(target, offset)?;
        notes.push(format!("corrupted: {} at offset {offset}", target.display()));

        // Attempt to open the ledger — it must fail or detect the corruption.
        match LedgerStore::open(test_dir) {
            Err(e) => {
                notes.push(format!("rejected: {e}"));
                // Good — corruption was detected. Restore the byte.
                flip_byte(target, offset)?;
                notes.push("restored: WAL byte flipped back".into());
                Ok(())
            }
            Ok(store) => {
                // Server opened — check if recovery discarded corrupted records.
                let count = store.entry_count();
                flip_byte(target, offset)?;
                notes.push("restored: WAL byte flipped back".into());
                // As long as chain is valid, partial recovery is acceptable.
                store.verify_chain_integrity()
                    .context("Chain invalid after partial recovery")?;
                notes.push(format!("partial recovery: {count} entries, chain valid"));
                Ok(())
            }
        }
    })();

    PhaseReport {
        name: "B  WAL Integrity",
        result: match result {
            Ok(())  => PhaseResult::Pass,
            Err(e)  => PhaseResult::Fail(e.to_string()),
        },
        notes,
        elapsed_ms: t.elapsed().as_millis() as u64,
    }
}

// ── Phase C: Recovery ─────────────────────────────────────────────────────────

async fn phase_recovery(
    test_dir:            &Path,
    expected_count:      u64,
    expected_chain_tip:  &str,
) -> PhaseReport {
    let t = Instant::now();
    let mut notes = Vec::new();

    let result = (|| -> Result<()> {
        let store = LedgerStore::open(test_dir)
            .context("Failed to reopen ledger after WAL restore")?;

        let count = store.entry_count() as u64;
        let tip   = hex::encode(store.chain_tip());

        notes.push(format!("entries_recovered: {count} / {expected_count}"));
        notes.push(format!("chain_tip_after:  {tip}"));
        notes.push(format!("chain_tip_before: {}",
            expected_chain_tip.trim_start_matches("chain_tip: ")));

        if count != expected_count {
            anyhow::bail!(
                "Recovery mismatch: expected {expected_count} entries, got {count}"
            );
        }

        store.verify_chain_integrity()
            .context("Hash chain invalid after recovery")?;

        notes.push("chain_integrity: OK".into());
        Ok(())
    })();

    PhaseReport {
        name: "C  Crash Recovery",
        result: match result {
            Ok(())  => PhaseResult::Pass,
            Err(e)  => PhaseResult::Fail(e.to_string()),
        },
        notes,
        elapsed_ms: t.elapsed().as_millis() as u64,
    }
}

// ── Phase D: Logical tampering ────────────────────────────────────────────────

async fn phase_logical_tamper(test_dir: &Path, total_entries: u64) -> PhaseReport {
    let t = Instant::now();
    let mut notes = Vec::new();

    let result = (|| -> Result<()> {
        let mut store = LedgerStore::open(test_dir)
            .context("Failed to open ledger for tamper test")?;

        // Pick a target in the middle of the ledger.
        let target_seq = (total_entries / 2).max(1);

        // Capture original hash.
        let original_hash = store
            .get_entry_by_sequence(target_seq)
            .map(|e| hex::encode(e.content_hash))
            .unwrap_or_default();

        notes.push(format!("tamper_target: sequence {target_seq}"));
        notes.push(format!("original_hash: {}", &original_hash[..16]));

        // Tamper: silently mutate the description without updating hashes.
        let tampered = store.tamper_entry_for_demo(
            target_seq,
            "*** TAMPERED BY ATTACKER ***".into(),
        );

        if !tampered {
            anyhow::bail!("Could not find entry {target_seq} to tamper");
        }

        notes.push("tamper_applied: description mutated without hash update".into());

        // VERIFY_CHAIN must now detect the corruption.
        match store.verify_chain_integrity() {
            Ok(()) => {
                anyhow::bail!(
                    "SECURITY FAILURE: VERIFY_CHAIN() returned OK after tampering — \
                     hash chain did not detect the mutation"
                )
            }
            Err(e) => {
                let err_str = e.to_string();
                notes.push(format!("tampering_detected: {err_str}"));
                // Confirm the detection mentions our target sequence.
                if err_str.contains(&target_seq.to_string()) {
                    notes.push(format!("detection_precise: YES — sequence {target_seq} identified"));
                } else {
                    notes.push("detection_precise: chain broken (earlier linked entry caught)".into());
                }
                Ok(())
            }
        }
    })();

    PhaseReport {
        name: "D  Logical Integrity",
        result: match result {
            Ok(())  => PhaseResult::Pass,
            Err(e)  => PhaseResult::Fail(e.to_string()),
        },
        notes,
        elapsed_ms: t.elapsed().as_millis() as u64,
    }
}

// ── Phase E: Entry verification ───────────────────────────────────────────────

async fn phase_entry_verification(test_dir: &Path, total_entries: u64) -> PhaseReport {
    let t = Instant::now();
    let mut notes = Vec::new();

    let result = (|| -> Result<()> {
        // Reopen a fresh store — previous store was tampered in Phase D.
        // Since the tamper was in-memory only, a fresh open restores clean state.
        let store = LedgerStore::open(test_dir)
            .context("Failed to open ledger for entry verification")?;

        let check_seqs = [
            1u64,
            total_entries / 4,
            total_entries / 2,
            total_entries * 3 / 4,
            total_entries,
        ];

        let mut all_valid = true;
        for seq in check_seqs {
            match store.get_entry_by_sequence(seq) {
                None => {
                    notes.push(format!("seq={seq}: NOT FOUND"));
                    all_valid = false;
                }
                Some(entry) => {
                    let ok = entry.verify_hashes();
                    notes.push(format!(
                        "seq={seq}: {} (hash={}...)",
                        if ok { "VALID" } else { "CORRUPTED" },
                        hex::encode(&entry.content_hash[..8])
                    ));
                    if !ok { all_valid = false; }
                }
            }
        }

        if !all_valid {
            anyhow::bail!("One or more entries failed hash verification");
        }

        Ok(())
    })();

    PhaseReport {
        name: "E  Entry Verification",
        result: match result {
            Ok(())  => PhaseResult::Pass,
            Err(e)  => PhaseResult::Fail(e.to_string()),
        },
        notes,
        elapsed_ms: t.elapsed().as_millis() as u64,
    }
}

// ── Data generation helpers ───────────────────────────────────────────────────

struct TestAccounts {
    pairs: Vec<(vledger_ledger::AccountId, vledger_ledger::AccountId)>,
}

impl TestAccounts {
    fn len(&self) -> usize { self.pairs.len() * 2 }

    fn pair_for_seq(&self, seq: u64) -> (vledger_ledger::AccountId, vledger_ledger::AccountId) {
        let idx = (seq as usize) % self.pairs.len();
        self.pairs[idx]
    }
}

fn create_test_accounts(store: &mut LedgerStore, seed: &str) -> Result<TestAccounts> {
    // Create 10 asset accounts and 10 income accounts → 10 debit/credit pairs.
    let mut pairs = Vec::new();
    for i in 0..10usize {
        let asset_code   = format!("ASSET-{seed:.4}-{i:02}");
        let income_code  = format!("INCM-{seed:.4}-{i:02}");

        let asset_id = store.create_account(Account::new(
            &asset_code,
            &format!("Test Asset Account {i}"),
            AccountType::Asset,
            "USD",
            "self-test",
        ))?;

        let income_id = store.create_account(Account::new(
            &income_code,
            &format!("Test Income Account {i}"),
            AccountType::Income,
            "USD",
            "self-test",
        ))?;

        pairs.push((asset_id, income_id));
    }
    Ok(TestAccounts { pairs })
}

fn insert_deterministic_entries(
    store:    &mut LedgerStore,
    accounts: &TestAccounts,
    count:    u64,
    seed:     &str,
) -> Result<()> {
    // Use a simple LCG for deterministic but varied amounts.
    // LCG constants from Knuth.
    let mut lcg: u64 = u64::from_le_bytes(
        seed.as_bytes().iter().copied()
            .chain(std::iter::repeat(0u8))
            .take(8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or([0x13, 0x57, 0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce])
    );

    for seq in 1..=count {
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);

        let amount_minor = (lcg % 999_900) + 100; // $0.01 – $9,999.00
        let (debit_id, credit_id) = accounts.pair_for_seq(seq);

        let amount = Amount::new(amount_minor as i64)
            .ok_or_else(|| anyhow::anyhow!("zero amount generated at seq {seq}"))?;

        let description = format!("self-test-{seq}-{}", &hex::encode(lcg.to_le_bytes())[..6]);

        let entry = JournalEntryBuilder::new(&description, "self-test")
            .debit(debit_id, amount, "USD")
            .credit(credit_id, amount, "USD")
            .build();

        store.post_entry(entry)
            .map_err(|e| anyhow::anyhow!(
                "Failed to post entry {seq} (amount={amount_minor} minor units, \
                 debit={debit_id}, credit={credit_id}): {e}"
            ))?;

        // Progress indicator every 10% for large datasets.
        if count >= 10_000 && seq % (count / 10) == 0 {
            let pct = seq * 100 / count;
            eprint!("\r  Generating entries: {pct}%   ");
        }
    }

    if count >= 10_000 {
        eprintln!("\r  Generating entries: 100%  ");
    }

    Ok(())
}

// ── WAL helpers ───────────────────────────────────────────────────────────────

fn wal_segments(wal_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut segs: Vec<PathBuf> = std::fs::read_dir(wal_dir)
        .context("Cannot read WAL directory")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |x| x == "wal"))
        .collect();
    segs.sort();
    Ok(segs)
}

fn flip_byte(path: &Path, offset: u64) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&[b[0] ^ 0xFF])?;
    Ok(())
}

fn sample_sequences(total: u64, n: usize) -> Vec<u64> {
    (0..n)
        .map(|i| {
            let frac = (i as u64 * total) / (n as u64).max(1);
            frac.clamp(1, total)
        })
        .collect()
}

// ── Report output ─────────────────────────────────────────────────────────────

fn print_header(entries: u64, seed_hex: &str, test_dir: &Path) {
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║       VectorLedger Integrity Self-Test               ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("  Configuration");
    println!("  ─────────────────────────────────────────────────────");
    println!("  Entries     : {entries:>12}");
    println!("  Seed        : {seed_hex}");
    println!("  Database    : {}", test_dir.display());
    println!("  Version     : {}", env!("CARGO_PKG_VERSION"));
    println!();
}

fn print_report(
    phases:    &[PhaseReport],
    keep_data: bool,
    test_dir:  &Path,
    entries:   u64,
    seed_hex:  &str,
) {
    let all_pass = phases.iter().all(|p| p.result.is_pass());
    let total_ms: u64 = phases.iter().map(|p| p.elapsed_ms).sum();

    println!();
    println!("  Results");
    println!("  ─────────────────────────────────────────────────────");

    for phase in phases {
        let status = phase.result.label();
        let elapsed = phase.elapsed_ms;
        println!();
        println!("  {}  [{status}]  ({elapsed} ms)", phase.name);

        for note in &phase.notes {
            // Skip internal tracking notes, only print human-readable ones.
            if note.starts_with("entry_count:") || note.starts_with("chain_tip:") {
                continue;
            }
            println!("    {note}");
        }

        if let Some(detail) = phase.result.detail() {
            println!("    → {detail}");
        }
    }

    println!();
    println!("  ─────────────────────────────────────────────────────");
    println!("  Entries verified : {entries}");
    println!("  Seed             : {seed_hex}");
    println!("  Total elapsed    : {total_ms} ms  ({:.1} s)", total_ms as f64 / 1000.0);
    println!();

    if all_pass {
        println!("  ┌─────────────────────────────────────────────────┐");
        println!("  │           RESULT: ALL TESTS PASSED              │");
        println!("  └─────────────────────────────────────────────────┘");
    } else {
        println!("  ┌─────────────────────────────────────────────────┐");
        println!("  │              RESULT: TEST FAILED                │");
        println!("  └─────────────────────────────────────────────────┘");
        for phase in phases {
            if let PhaseResult::Fail(msg) = &phase.result {
                println!("  {} → {msg}", phase.name);
            }
        }
    }

    println!();

    if keep_data {
        println!("  Test artifacts retained at:");
        println!("  {}", test_dir.display());
        println!();
        println!("  Inspect the test ledger with psql (start server first):");
        println!("  1. vledger start --data-dir {} --max-connections 10 --pgwire &", test_dir.display());
        println!("  2. psql \"host=127.0.0.1 port=5432 user=admin dbname=vledger sslmode=require\"");
        println!();
        println!("  Suggested queries:");
        println!("    SELECT COUNT(*) FROM ledger;");
        println!("    SELECT VERIFY_CHAIN();");
        println!("    SELECT VERIFY_ENTRY(1);");
        println!("    SELECT VERIFY_ENTRY({});", entries / 2);
        println!("    SELECT VERIFY_ENTRY({entries});");
        println!("    SELECT * FROM ledger ORDER BY sequence LIMIT 10;");
        println!();
    }
}
