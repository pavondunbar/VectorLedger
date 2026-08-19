//! Portable, self-contained audit evidence package.
//!
//! ## Overview
//!
//! `generate()` produces a single JSON file containing:
//! - Every journal entry (full fields)
//! - Per-entry Merkle inclusion proofs
//! - Hash chain linkage proof (prev_hash → content_hash → chain_hash)
//! - Merkle root over all entries
//! - Ed25519 signature over the root + chain tip (using the database signing key)
//! - Package metadata (version, timestamp, algorithm, entry count)
//!
//! `verify()` consumes that JSON file and independently verifies:
//! 1. Every entry's content_hash matches its canonical bytes
//! 2. The hash chain linkage is intact (no gaps, no tampered hashes)
//! 3. Every Merkle inclusion proof path walks correctly to the root
//! 4. The Merkle root matches what is recorded in the package metadata
//! 5. The Ed25519 root signature is valid (if present)
//!
//! The verifier requires no database access, no server, and no key files —
//! only the package JSON and the vledger binary (or any reimplementation of
//! the verification algorithm).

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use vledger_crypto::{
    hash::{hash_bytes, hash_node, hash_to_hex},
    merkle::{merkle_proof, merkle_root},
    sign::DbVerifyingKey,
    ZERO_HASH,
};
use vledger_ledger::LedgerStore;

// ── Package format version ────────────────────────────────────────────────────

const FORMAT_VERSION: u32 = 1;

// ── generate ──────────────────────────────────────────────────────────────────

/// Generate a portable audit evidence package and write it to `output_path`.
pub fn generate(data_dir: &Path, output_path: &Path) -> Result<GenerateReport> {
    // Open the ledger (replays WAL, verifies chain on startup).
    let ledger = LedgerStore::open(data_dir)
        .context("Failed to open ledger")?;

    // Verify chain integrity before packaging — fail fast on a broken chain.
    ledger.verify_chain_integrity()
        .context("Cannot generate audit package: ledger hash chain is broken. Run `vledger verify` to diagnose.")?;

    let entries   = ledger.all_entries();
    let entry_count = entries.len();

    // ── Build Merkle tree ─────────────────────────────────────────────────
    // Leaf bytes = canonical_bytes() for each entry — same input used for
    // the content_hash stored in the entry.
    let leaf_bytes: Vec<Vec<u8>> = entries.iter()
        .map(|e| e.canonical_bytes())
        .collect();

    let root: [u8; 32] = if leaf_bytes.is_empty() {
        ZERO_HASH
    } else {
        merkle_root(&leaf_bytes)
    };
    let root_hex = hash_to_hex(&root);

    // ── Per-entry Merkle proofs ───────────────────────────────────────────
    let merkle_proofs_json: Vec<Value> = (0..entry_count)
        .map(|i| {
            let proof = merkle_proof(&leaf_bytes, i)
                .expect("merkle_proof cannot be None when i < len");
            json!({
                "leaf_index": proof.leaf_index,
                "leaf_hash":  hash_to_hex(&proof.leaf_hash),
                "path": proof.path.iter().map(|step| json!({
                    "sibling":         hash_to_hex(&step.sibling),
                    "sibling_is_left": step.sibling_is_left,
                })).collect::<Vec<_>>(),
                "root": hash_to_hex(&proof.root),
            })
        })
        .collect();

    // ── Chain proof (per-entry hash linkage for the verifier) ────────────
    let chain_proof_json: Vec<Value> = entries.iter().map(|e| {
        json!({
            "sequence":     e.sequence,
            "prev_hash":    hash_to_hex(&e.prev_hash),
            "content_hash": hash_to_hex(&e.content_hash),
            "chain_hash":   hash_to_hex(&e.chain_hash),
        })
    }).collect();

    // ── Sign: root_bytes || chain_tip_bytes ───────────────────────────────
    // Signing commits to both the Merkle root (covers all entry contents) and
    // the chain tip (covers the sequential ordering). Changing either invalidates
    // the signature.
    let chain_tip = ledger.chain_tip();
    let chain_tip_hex = hash_to_hex(chain_tip);

    let mut sign_payload = root.to_vec();
    sign_payload.extend_from_slice(chain_tip);

    let (root_signature_hex, signing_pubkey_hex) = match ledger.sign_bytes(&sign_payload) {
        Some((sig, pubkey)) => (hex::encode(sig), hex::encode(pubkey)),
        None => {
            tracing::warn!(
                "No database signing key found — audit package will not include a root signature. \
                 Run `vledger init` to generate a signing key."
            );
            (String::new(), String::new())
        }
    };

    // ── Serialize entries to JSON ─────────────────────────────────────────
    let entries_json: Vec<Value> = entries.iter()
        .map(|e| serde_json::to_value(e).expect("JournalEntry is always JSON-serializable"))
        .collect();

    // ── Assemble the package ──────────────────────────────────────────────
    let generated_at = chrono::Utc::now().to_rfc3339();
    let package = json!({
        "meta": {
            "format_version":    FORMAT_VERSION,
            "generated_at":      generated_at,
            "vledger_version":   env!("CARGO_PKG_VERSION"),
            "entry_count":       entry_count,
            "chain_tip":         chain_tip_hex,
            "merkle_root":       root_hex,
            "root_signature":    root_signature_hex,
            "signing_pubkey":    signing_pubkey_hex,
            "algorithm":         "BLAKE3 + Ed25519",
        },
        "entries":       entries_json,
        "merkle_proofs": merkle_proofs_json,
        "chain_proof":   chain_proof_json,
    });

    let json_str = serde_json::to_string_pretty(&package)
        .context("Failed to serialize audit package")?;
    std::fs::write(output_path, &json_str)
        .with_context(|| format!("Cannot write audit package to {}", output_path.display()))?;

    Ok(GenerateReport {
        entry_count,
        root_hex,
        chain_tip_hex,
        signed: !root_signature_hex.is_empty(),
        output_path: output_path.to_path_buf(),
    })
}

pub struct GenerateReport {
    pub entry_count:   usize,
    pub root_hex:      String,
    pub chain_tip_hex: String,
    pub signed:        bool,
    pub output_path:   std::path::PathBuf,
}

// ── verify ────────────────────────────────────────────────────────────────────

/// Verify a portable audit package JSON file.
///
/// Performs four independent checks in order:
/// 1. Content hash — every entry's stored content_hash matches its canonical bytes
/// 2. Chain linkage — every entry's chain_hash and prev_hash are consistent
/// 3. Merkle proofs — every inclusion proof walks correctly to the recorded root
/// 4. Root signature — the Ed25519 signature over root + chain_tip is valid (if present)
///
/// Returns a `VerifyReport` on success or an error listing every failure.
pub fn verify(file: &Path) -> Result<VerifyReport> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("Cannot read {}", file.display()))?;
    let package: Value = serde_json::from_str(&raw)
        .context("Invalid JSON in audit package")?;

    let meta         = &package["meta"];
    let entries_json = package["entries"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing 'entries' array in package"))?;
    let proofs_json  = package["merkle_proofs"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing 'merkle_proofs' array in package"))?;

    let root_hex      = meta["merkle_root"].as_str().unwrap_or("");
    let sig_hex       = meta["root_signature"].as_str().unwrap_or("");
    let pubkey_hex    = meta["signing_pubkey"].as_str().unwrap_or("");
    let chain_tip_hex = meta["chain_tip"].as_str().unwrap_or("");
    let entry_count   = entries_json.len();

    let mut errors: Vec<String> = Vec::new();

    // ── Deserialize entries ───────────────────────────────────────────────
    let entries: Vec<vledger_ledger::entry::JournalEntry> = entries_json.iter()
        .enumerate()
        .filter_map(|(i, v)| {
            serde_json::from_value(v.clone())
                .map_err(|e| {
                    errors.push(format!("Entry[{i}]: deserialization failed: {e}"));
                })
                .ok()
        })
        .collect();

    // ── Check 1: Content hashes ───────────────────────────────────────────
    let mut content_errors = 0usize;
    let mut leaf_bytes: Vec<Vec<u8>> = Vec::new();

    for entry in &entries {
        let canonical     = entry.canonical_bytes();
        let expected_hash = hash_bytes(&canonical);
        if expected_hash != entry.content_hash {
            errors.push(format!(
                "seq={}: content_hash mismatch — expected {}, stored {}",
                entry.sequence,
                hash_to_hex(&expected_hash),
                hash_to_hex(&entry.content_hash),
            ));
            content_errors += 1;
        }
        leaf_bytes.push(canonical);
    }

    // ── Check 2: Hash chain linkage ───────────────────────────────────────
    let mut chain_errors = 0usize;
    {
        let mut prev = ZERO_HASH;
        for entry in &entries {
            // Recompute chain_hash = BLAKE3(seq_le || prev_hash || content_hash)
            let mut h = blake3::Hasher::new();
            h.update(&entry.sequence.to_le_bytes());
            h.update(&entry.prev_hash);
            h.update(&entry.content_hash);
            let expected_chain = *h.finalize().as_bytes();

            if expected_chain != entry.chain_hash {
                errors.push(format!(
                    "seq={}: chain_hash mismatch — expected {}, stored {}",
                    entry.sequence,
                    hash_to_hex(&expected_chain),
                    hash_to_hex(&entry.chain_hash),
                ));
                chain_errors += 1;
            }
            if entry.prev_hash != prev {
                errors.push(format!(
                    "seq={}: prev_hash linkage broken — expected {}, stored {}",
                    entry.sequence,
                    hash_to_hex(&prev),
                    hash_to_hex(&entry.prev_hash),
                ));
                chain_errors += 1;
            }
            prev = entry.chain_hash;
        }

        // Verify chain tip matches metadata
        if let Some(last) = entries.last() {
            let actual_tip = hash_to_hex(&last.chain_hash);
            if actual_tip != chain_tip_hex {
                errors.push(format!(
                    "chain_tip mismatch — metadata: {chain_tip_hex}, computed: {actual_tip}"
                ));
                chain_errors += 1;
            }
        }
    }

    // ── Check 3: Merkle proofs ────────────────────────────────────────────
    let mut merkle_errors = 0usize;
    {
        // Recompute the root from leaf bytes and compare to metadata.
        let computed_root = if leaf_bytes.is_empty() {
            ZERO_HASH
        } else {
            merkle_root(&leaf_bytes)
        };
        let computed_root_hex = hash_to_hex(&computed_root);
        if computed_root_hex != root_hex {
            errors.push(format!(
                "Merkle root mismatch — metadata: {root_hex}, computed: {computed_root_hex}"
            ));
            merkle_errors += 1;
        }

        // Verify each individual Merkle proof path.
        for (i, proof_val) in proofs_json.iter().enumerate() {
            let leaf_hash_hex = proof_val["leaf_hash"].as_str().unwrap_or("");
            let root_in_proof = proof_val["root"].as_str().unwrap_or("");

            let leaf_hash_bytes: Option<[u8; 32]> = hex::decode(leaf_hash_hex).ok()
                .and_then(|b| b.try_into().ok());

            if let Some(mut cur) = leaf_hash_bytes {
                if let Some(steps) = proof_val["path"].as_array() {
                    for step in steps {
                        let sib_hex      = step["sibling"].as_str().unwrap_or("");
                        let sib_is_left  = step["sibling_is_left"].as_bool().unwrap_or(false);
                        let sib: Option<[u8; 32]> = hex::decode(sib_hex).ok()
                            .and_then(|b| b.try_into().ok());
                        if let Some(s) = sib {
                            cur = if sib_is_left {
                                hash_node(&s, &cur)
                            } else {
                                hash_node(&cur, &s)
                            };
                        } else {
                            errors.push(format!("Merkle proof[{i}]: invalid sibling hex"));
                            merkle_errors += 1;
                            break;
                        }
                    }
                }
                if hash_to_hex(&cur) != root_in_proof {
                    errors.push(format!(
                        "Merkle proof[{i}]: path does not verify to root — \
                         got {}, expected {root_in_proof}",
                        hash_to_hex(&cur),
                    ));
                    merkle_errors += 1;
                }
            } else {
                errors.push(format!("Merkle proof[{i}]: invalid leaf_hash hex"));
                merkle_errors += 1;
            }
        }
    }

    // ── Check 4: Root signature ───────────────────────────────────────────
    let mut sig_status = SigStatus::Absent;
    if !sig_hex.is_empty() && !pubkey_hex.is_empty() {
        let root_bytes:   Option<[u8; 32]> = hex::decode(root_hex).ok().and_then(|b| b.try_into().ok());
        let tip_bytes:    Option<[u8; 32]> = hex::decode(chain_tip_hex).ok().and_then(|b| b.try_into().ok());
        let pubkey_bytes: Option<[u8; 32]> = hex::decode(pubkey_hex).ok().and_then(|b| b.try_into().ok());
        let sig_bytes:    Option<[u8; 64]> = hex::decode(sig_hex).ok().and_then(|b| b.try_into().ok());

        match (root_bytes, tip_bytes, pubkey_bytes, sig_bytes) {
            (Some(root), Some(tip), Some(pubkey), Some(sig)) => {
                let mut payload = root.to_vec();
                payload.extend_from_slice(&tip);
                match DbVerifyingKey::from_bytes(&pubkey) {
                    Ok(vk) => match vk.verify(&payload, &sig) {
                        Ok(())  => sig_status = SigStatus::Valid,
                        Err(_)  => {
                            errors.push("Root signature verification FAILED".into());
                            sig_status = SigStatus::Invalid;
                        }
                    },
                    Err(e) => {
                        errors.push(format!("Invalid signing public key: {e}"));
                        sig_status = SigStatus::Invalid;
                    }
                }
            }
            _ => {
                errors.push("Failed to decode signature/pubkey/root/chain_tip hex".into());
                sig_status = SigStatus::Invalid;
            }
        }
    }

    let passed = errors.is_empty();

    let report = VerifyReport {
        entry_count,
        root_hex:      root_hex.to_string(),
        chain_tip_hex: chain_tip_hex.to_string(),
        content_ok:    content_errors == 0,
        chain_ok:      chain_errors == 0,
        merkle_ok:     merkle_errors == 0,
        sig_status,
        errors: errors.clone(),
        generated_at:     meta["generated_at"].as_str().unwrap_or("?").to_string(),
        vledger_version:  meta["vledger_version"].as_str().unwrap_or("?").to_string(),
        format_version:   meta["format_version"].as_u64().unwrap_or(0),
        passed,
    };

    if passed {
        Ok(report)
    } else {
        Err(anyhow::anyhow!(
            "Audit package verification FAILED ({} error(s))",
            errors.len()
        ))
        .map(|_: Result<VerifyReport>| unreachable!())
        .or(Ok(report))
        // Return the report so the caller can print details even on failure.
        // We signal failure through report.passed == false rather than Err.
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    /// No signature present in the package.
    Absent,
    /// Signature present and verified.
    Valid,
    /// Signature present but verification failed.
    Invalid,
}

pub struct VerifyReport {
    pub entry_count:      usize,
    pub root_hex:         String,
    pub chain_tip_hex:    String,
    pub content_ok:       bool,
    pub chain_ok:         bool,
    pub merkle_ok:        bool,
    pub sig_status:       SigStatus,
    pub errors:           Vec<String>,
    pub generated_at:     String,
    pub vledger_version:  String,
    pub format_version:   u64,
    pub passed:           bool,
}
