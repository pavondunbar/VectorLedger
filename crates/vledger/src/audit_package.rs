//! Portable, self-contained audit evidence package.
//!
//! ## Three-tier design
//!
//! ### Tier 1 — Commitment package (default, fast at any scale)
//! `generate()` in default mode produces a compact JSON file containing:
//! - Merkle root over all entries (BLAKE3, computed in one pass)
//! - Chain tip hash
//! - Ed25519 signature over root + chain tip
//! - Summary metadata (entry count, timestamps, algorithm)
//!
//! This takes seconds regardless of ledger size. It is the cryptographic
//! commitment that anchors all future proofs. The auditor receives this file
//! and can verify the signature independently.
//!
//! ### Tier 2 — On-demand entry proof (`prove_entry()`)
//! Given a commitment package and a sequence number, produces a single
//! inclusion proof for that entry. The auditor can verify that one entry
//! belongs to the committed Merkle root without loading the entire ledger.
//!
//! ### Tier 3 — Full export (`--include-entries` flag)
//! For small ledgers or period exports, `generate()` with `include_entries=true`
//! also embeds all entries and per-entry proofs. Only use this when the ledger
//! is small enough that the output file is manageable.
//!
//! ## Verification
//! `verify()` handles all three tiers:
//! - Always verifies: Merkle root matches signature, signature is valid
//! - When entries present: verifies content hashes, chain linkage, Merkle proofs

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

const FORMAT_VERSION: u32 = 2;

// ── GenerateOptions ───────────────────────────────────────────────────────────

pub struct GenerateOptions {
    /// When true, embed all entries and per-entry Merkle proofs in the package.
    /// Only practical for ledgers with < ~10,000 entries.
    /// Default: false — commitment-only package.
    pub include_entries: bool,
    /// Name of the organisation this package covers (e.g. "Acme Financial").
    pub tenant: Option<String>,
    /// Human-readable description of this audit package (e.g. "Q3 2026 ledger audit").
    pub description: Option<String>,
    /// Start of the reporting period (RFC 3339 or YYYY-MM-DD).
    pub period_start: Option<String>,
    /// End of the reporting period (RFC 3339 or YYYY-MM-DD).
    pub period_end: Option<String>,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            include_entries: false,
            tenant: None,
            description: None,
            period_start: None,
            period_end: None,
        }
    }
}

// ── generate ──────────────────────────────────────────────────────────────────

/// Generate an audit evidence package and write it to `output_path`.
///
/// By default produces a compact commitment-only package (fast, any scale).
/// Pass `opts.include_entries = true` to embed all entries and proofs.
pub fn generate(
    data_dir: &Path,
    output_path: &Path,
    opts: GenerateOptions,
) -> Result<GenerateReport> {
    let ledger = LedgerStore::open(data_dir).context("Failed to open ledger")?;

    // Fail fast if the chain is broken — don't package corrupt state.
    ledger.verify_chain_integrity().context(
        "Cannot generate audit package: ledger hash chain is broken. \
                  Run `vledger verify` to diagnose.",
    )?;

    let entries = ledger.all_entries();
    let entry_count = entries.len();

    // ── Build Merkle root (single pass over canonical bytes) ─────────────
    // This is the only O(n) step and is fast — no proof generation here.
    eprint!("  Computing Merkle root over {entry_count} entries...");
    let leaf_bytes: Vec<Vec<u8>> = entries.iter().map(|e| e.canonical_bytes()).collect();

    let root: [u8; 32] = if leaf_bytes.is_empty() {
        ZERO_HASH
    } else {
        merkle_root(&leaf_bytes)
    };
    let root_hex = hash_to_hex(&root);
    let chain_tip = ledger.chain_tip();
    let chain_tip_hex = hash_to_hex(chain_tip);
    let first_sequence = entries.first().map(|e| e.sequence).unwrap_or(0);
    let last_sequence = entries.last().map(|e| e.sequence).unwrap_or(0);
    eprintln!(" done.");

    // ── Sign: canonical commitment bytes ──────────────────────────────────
    // The signed payload binds ALL metadata fields so that the tenant name,
    // description, period, entry count, and root cannot be altered after
    // signing without invalidating the signature.
    //
    // Canonical format (deterministic, no JSON whitespace variation):
    //   merkle_root || chain_tip || entry_count_le8
    //   || tenant_len_le4 || tenant_bytes
    //   || description_len_le4 || description_bytes
    //   || period_start_len_le4 || period_start_bytes
    //   || period_end_len_le4 || period_end_bytes
    //   || first_sequence_le8 || last_sequence_le8
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(&root);
    sign_payload.extend_from_slice(chain_tip);
    sign_payload.extend_from_slice(&(entry_count as u64).to_le_bytes());
    let tenant_bytes = opts.tenant.as_deref().unwrap_or("").as_bytes();
    sign_payload.extend_from_slice(&(tenant_bytes.len() as u32).to_le_bytes());
    sign_payload.extend_from_slice(tenant_bytes);
    let desc_bytes = opts.description.as_deref().unwrap_or("").as_bytes();
    sign_payload.extend_from_slice(&(desc_bytes.len() as u32).to_le_bytes());
    sign_payload.extend_from_slice(desc_bytes);
    let ps_bytes = opts.period_start.as_deref().unwrap_or("").as_bytes();
    sign_payload.extend_from_slice(&(ps_bytes.len() as u32).to_le_bytes());
    sign_payload.extend_from_slice(ps_bytes);
    let pe_bytes = opts.period_end.as_deref().unwrap_or("").as_bytes();
    sign_payload.extend_from_slice(&(pe_bytes.len() as u32).to_le_bytes());
    sign_payload.extend_from_slice(pe_bytes);
    sign_payload.extend_from_slice(&first_sequence.to_le_bytes());
    sign_payload.extend_from_slice(&last_sequence.to_le_bytes());

    let (root_signature_hex, signing_pubkey_hex) = match ledger.sign_bytes(&sign_payload) {
        Some((sig, pubkey)) => (hex::encode(sig), hex::encode(pubkey)),
        None => {
            tracing::warn!(
                "No database signing key found — package will not include a root signature."
            );
            (String::new(), String::new())
        }
    };

    let generated_at = chrono::Utc::now().to_rfc3339();

    // ── Assemble commitment metadata ──────────────────────────────────────
    let mut package = json!({
        "meta": {
            "format_version":    FORMAT_VERSION,
            "package_type":      if opts.include_entries { "full" } else { "commitment" },
            "generated_at":      generated_at,
            "vledger_version":   env!("CARGO_PKG_VERSION"),
            "entry_count":       entry_count,
            "first_sequence":    first_sequence,
            "last_sequence":     last_sequence,
            "chain_tip":         chain_tip_hex,
            "merkle_root":       root_hex,
            "root_signature":    root_signature_hex,
            "signing_pubkey":    signing_pubkey_hex,
            "algorithm":         "BLAKE3 + Ed25519",
            // Business metadata — all included in the signed payload above.
            "tenant":       opts.tenant.as_deref().unwrap_or(""),
            "description":  opts.description.as_deref().unwrap_or(""),
            "period_start": opts.period_start.as_deref().unwrap_or(""),
            "period_end":   opts.period_end.as_deref().unwrap_or(""),
        }
    });

    // ── Optional: embed entries + per-entry proofs ────────────────────────
    if opts.include_entries {
        eprint!("  Generating {} per-entry Merkle proofs...", entry_count);
        let merkle_proofs_json: Vec<Value> = (0..entry_count)
            .map(|i| {
                let proof =
                    merkle_proof(&leaf_bytes, i).expect("merkle_proof cannot be None when i < len");
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
        eprintln!(" done.");

        let chain_proof_json: Vec<Value> = entries
            .iter()
            .map(|e| {
                json!({
                    "sequence":     e.sequence,
                    "prev_hash":    hash_to_hex(&e.prev_hash),
                    "content_hash": hash_to_hex(&e.content_hash),
                    "chain_hash":   hash_to_hex(&e.chain_hash),
                })
            })
            .collect();

        let entries_json: Vec<Value> = entries
            .iter()
            .map(|e| serde_json::to_value(e).expect("JournalEntry is always JSON-serializable"))
            .collect();

        package["entries"] = json!(entries_json);
        package["merkle_proofs"] = json!(merkle_proofs_json);
        package["chain_proof"] = json!(chain_proof_json);
    }

    // ── Write output ──────────────────────────────────────────────────────
    eprint!("  Writing package to {}...", output_path.display());
    let json_str =
        serde_json::to_string_pretty(&package).context("Failed to serialize audit package")?;
    std::fs::write(output_path, &json_str)
        .with_context(|| format!("Cannot write to {}", output_path.display()))?;
    eprintln!(" done.");

    Ok(GenerateReport {
        entry_count,
        root_hex,
        chain_tip_hex,
        signed: !root_signature_hex.is_empty(),
        package_type: if opts.include_entries {
            "full"
        } else {
            "commitment"
        },
        output_path: output_path.to_path_buf(),
    })
}

pub struct GenerateReport {
    pub entry_count: usize,
    pub root_hex: String,
    pub chain_tip_hex: String,
    pub signed: bool,
    pub package_type: &'static str,
    pub output_path: std::path::PathBuf,
}

// ── prove_entry ───────────────────────────────────────────────────────────────

/// Generate a single-entry inclusion proof against the committed Merkle root.
///
/// The auditor provides the commitment package (which contains the signed root)
/// and a sequence number. This function opens the database, builds the Merkle
/// tree, and returns a proof that the entry at `sequence` belongs to the root
/// recorded in the commitment.
///
/// The output is a self-contained JSON file the auditor can verify without
/// further database access.
pub fn prove_entry(
    data_dir: &Path,
    commitment_file: &Path,
    sequence: u64,
    output_path: &Path,
) -> Result<ProveReport> {
    // Load and validate the commitment package.
    let raw = std::fs::read_to_string(commitment_file)
        .with_context(|| format!("Cannot read commitment file: {}", commitment_file.display()))?;
    let commitment: Value =
        serde_json::from_str(&raw).context("Invalid JSON in commitment file")?;
    let committed_root = commitment["meta"]["merkle_root"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Commitment file missing merkle_root"))?
        .to_string();

    // Open ledger.
    let ledger = LedgerStore::open(data_dir).context("Failed to open ledger")?;
    let entries = ledger.all_entries();

    // Find the entry by sequence number.
    let idx = entries
        .iter()
        .position(|e| e.sequence == sequence)
        .ok_or_else(|| anyhow::anyhow!("Entry with sequence={sequence} not found"))?;
    let entry = &entries[idx];

    // Build leaf bytes for the full tree (needed to compute proof paths).
    eprint!("  Building Merkle tree over {} entries...", entries.len());
    let leaf_bytes: Vec<Vec<u8>> = entries.iter().map(|e| e.canonical_bytes()).collect();
    let root: [u8; 32] = merkle_root(&leaf_bytes);
    let root_hex = hash_to_hex(&root);
    eprintln!(" done.");

    // Sanity check: the current root must match the committed root.
    if root_hex != committed_root {
        anyhow::bail!(
            "Ledger Merkle root ({}) does not match committed root ({}). \
             The ledger may have changed since the commitment was generated.",
            &root_hex[..16],
            &committed_root[..16]
        );
    }

    let proof = merkle_proof(&leaf_bytes, idx)
        .ok_or_else(|| anyhow::anyhow!("Failed to generate Merkle proof for index {idx}"))?;

    let proof_json = json!({
        "meta": {
            "format_version":     FORMAT_VERSION,
            "package_type":       "entry_proof",
            "generated_at":       chrono::Utc::now().to_rfc3339(),
            "vledger_version":    env!("CARGO_PKG_VERSION"),
            "committed_root":     committed_root,
            "commitment_file":    commitment_file.display().to_string(),
        },
        "entry": serde_json::to_value(entry).expect("JournalEntry is JSON-serializable"),
        "chain_proof": {
            "sequence":     entry.sequence,
            "prev_hash":    hash_to_hex(&entry.prev_hash),
            "content_hash": hash_to_hex(&entry.content_hash),
            "chain_hash":   hash_to_hex(&entry.chain_hash),
        },
        "merkle_proof": {
            "leaf_index": proof.leaf_index,
            "leaf_hash":  hash_to_hex(&proof.leaf_hash),
            "path": proof.path.iter().map(|step| json!({
                "sibling":         hash_to_hex(&step.sibling),
                "sibling_is_left": step.sibling_is_left,
            })).collect::<Vec<_>>(),
            "root": hash_to_hex(&proof.root),
        },
    });

    let json_str =
        serde_json::to_string_pretty(&proof_json).context("Failed to serialize entry proof")?;
    std::fs::write(output_path, &json_str)
        .with_context(|| format!("Cannot write to {}", output_path.display()))?;

    Ok(ProveReport {
        sequence,
        entry_id: entry.id.to_string(),
        root_hex: root_hex.clone(),
        output_path: output_path.to_path_buf(),
    })
}

pub struct ProveReport {
    pub sequence: u64,
    pub entry_id: String,
    pub root_hex: String,
    pub output_path: std::path::PathBuf,
}

// ── verify ────────────────────────────────────────────────────────────────────

/// Verify an audit package or entry proof JSON file.
///
/// Works on all three package types:
/// - "commitment": verifies root signature only
/// - "full": verifies root signature + all entry hashes + chain + Merkle proofs
/// - "entry_proof": verifies one entry's content hash, chain hash, and Merkle proof
pub fn verify(file: &Path) -> Result<VerifyReport> {
    let raw =
        std::fs::read_to_string(file).with_context(|| format!("Cannot read {}", file.display()))?;
    let package: Value = serde_json::from_str(&raw).context("Invalid JSON in audit package")?;

    let meta = &package["meta"];
    let package_type = meta["package_type"].as_str().unwrap_or("commitment");
    let root_hex = meta["merkle_root"]
        .as_str()
        .or_else(|| meta["committed_root"].as_str())
        .unwrap_or("");
    let sig_hex = meta["root_signature"].as_str().unwrap_or("");
    let pubkey_hex = meta["signing_pubkey"].as_str().unwrap_or("");
    let chain_tip_hex = meta["chain_tip"].as_str().unwrap_or("");

    let mut errors: Vec<String> = Vec::new();

    // ── Check 1: Root signature ───────────────────────────────────────────
    // Always performed regardless of package type.
    let mut sig_status = SigStatus::Absent;
    if !sig_hex.is_empty() && !pubkey_hex.is_empty() {
        let root_bytes: Option<[u8; 32]> =
            hex::decode(root_hex).ok().and_then(|b| b.try_into().ok());
        let tip_bytes: Option<[u8; 32]> = hex::decode(chain_tip_hex)
            .ok()
            .and_then(|b| b.try_into().ok());
        let pubkey_bytes: Option<[u8; 32]> =
            hex::decode(pubkey_hex).ok().and_then(|b| b.try_into().ok());
        let sig_bytes: Option<[u8; 64]> = hex::decode(sig_hex).ok().and_then(|b| b.try_into().ok());

        match (root_bytes, tip_bytes, pubkey_bytes, sig_bytes) {
            (Some(root), Some(tip), Some(pubkey), Some(sig)) => {
                // Reconstruct the canonical signed payload — must match generate().
                let entry_count_val = meta["entry_count"].as_u64().unwrap_or(0);
                let first_seq = meta["first_sequence"].as_u64().unwrap_or(0);
                let last_seq = meta["last_sequence"].as_u64().unwrap_or(0);
                let tenant = meta["tenant"].as_str().unwrap_or("").as_bytes();
                let description = meta["description"].as_str().unwrap_or("").as_bytes();
                let period_start = meta["period_start"].as_str().unwrap_or("").as_bytes();
                let period_end = meta["period_end"].as_str().unwrap_or("").as_bytes();

                let mut payload = Vec::new();
                payload.extend_from_slice(&root);
                payload.extend_from_slice(&tip);
                payload.extend_from_slice(&entry_count_val.to_le_bytes());
                payload.extend_from_slice(&(tenant.len() as u32).to_le_bytes());
                payload.extend_from_slice(tenant);
                payload.extend_from_slice(&(description.len() as u32).to_le_bytes());
                payload.extend_from_slice(description);
                payload.extend_from_slice(&(period_start.len() as u32).to_le_bytes());
                payload.extend_from_slice(period_start);
                payload.extend_from_slice(&(period_end.len() as u32).to_le_bytes());
                payload.extend_from_slice(period_end);
                payload.extend_from_slice(&first_seq.to_le_bytes());
                payload.extend_from_slice(&last_seq.to_le_bytes());

                match DbVerifyingKey::from_bytes(&pubkey) {
                    Ok(vk) => match vk.verify(&payload, &sig) {
                        Ok(()) => sig_status = SigStatus::Valid,
                        Err(_) => {
                            errors.push("Root signature verification FAILED — commitment may have been altered".into());
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

    // ── Check 2 (entry_proof): single entry verification ─────────────────
    let mut content_ok = true;
    let mut chain_ok = true;
    let mut merkle_ok = true;
    let mut entry_count = meta["entry_count"].as_u64().unwrap_or(0) as usize;

    if package_type == "entry_proof" {
        entry_count = 1;
        if let Ok(entry) =
            serde_json::from_value::<vledger_ledger::entry::JournalEntry>(package["entry"].clone())
        {
            // Content hash
            let canonical = entry.canonical_bytes();
            let expected_hash = hash_bytes(&canonical);
            if expected_hash != entry.content_hash {
                errors.push(format!("seq={}: content_hash mismatch", entry.sequence));
                content_ok = false;
            }

            // Chain hash
            let mut h = blake3::Hasher::new();
            h.update(&entry.sequence.to_le_bytes());
            h.update(&entry.prev_hash);
            h.update(&entry.content_hash);
            let expected_chain = *h.finalize().as_bytes();
            if expected_chain != entry.chain_hash {
                errors.push(format!("seq={}: chain_hash mismatch", entry.sequence));
                chain_ok = false;
            }

            // Merkle proof path
            let proof_val = &package["merkle_proof"];
            let leaf_hex = proof_val["leaf_hash"].as_str().unwrap_or("");
            let root_in_proof = proof_val["root"].as_str().unwrap_or("");
            let leaf_bytes_opt: Option<[u8; 32]> =
                hex::decode(leaf_hex).ok().and_then(|b| b.try_into().ok());

            if let Some(mut cur) = leaf_bytes_opt {
                if let Some(steps) = proof_val["path"].as_array() {
                    for step in steps {
                        let sib_hex = step["sibling"].as_str().unwrap_or("");
                        let sib_is_left = step["sibling_is_left"].as_bool().unwrap_or(false);
                        let sib: Option<[u8; 32]> =
                            hex::decode(sib_hex).ok().and_then(|b| b.try_into().ok());
                        if let Some(s) = sib {
                            cur = if sib_is_left {
                                hash_node(&s, &cur)
                            } else {
                                hash_node(&cur, &s)
                            };
                        }
                    }
                }
                if hash_to_hex(&cur) != root_in_proof {
                    errors.push("Merkle proof path does not verify to committed root".into());
                    merkle_ok = false;
                }
                // Also confirm proof root matches package root
                if root_in_proof != root_hex {
                    errors.push(format!(
                        "Proof root ({}) does not match committed root ({})",
                        &root_in_proof[..16.min(root_in_proof.len())],
                        &root_hex[..16.min(root_hex.len())]
                    ));
                    merkle_ok = false;
                }
            } else {
                errors.push("Invalid leaf_hash hex in Merkle proof".into());
                merkle_ok = false;
            }
        } else {
            errors.push("Failed to deserialize entry from proof package".into());
            content_ok = false;
            chain_ok = false;
            merkle_ok = false;
        }
    }

    // ── Check 2 (full): all entries ───────────────────────────────────────
    if package_type == "full" {
        let entries_json = package["entries"].as_array();
        let proofs_json = package["merkle_proofs"].as_array();

        if let Some(entries_arr) = entries_json {
            entry_count = entries_arr.len();
            let mut leaf_bytes: Vec<Vec<u8>> = Vec::new();
            let mut content_errors = 0usize;
            let mut chain_errors = 0usize;

            let entries: Vec<vledger_ledger::entry::JournalEntry> = entries_arr
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    serde_json::from_value(v.clone())
                        .map_err(|e| errors.push(format!("Entry[{i}] deserialization failed: {e}")))
                        .ok()
                })
                .collect();

            let mut prev = ZERO_HASH;
            for entry in &entries {
                let canonical = entry.canonical_bytes();
                let expected_hash = hash_bytes(&canonical);
                if expected_hash != entry.content_hash {
                    errors.push(format!("seq={}: content_hash mismatch", entry.sequence));
                    content_errors += 1;
                }
                leaf_bytes.push(canonical);

                let mut h = blake3::Hasher::new();
                h.update(&entry.sequence.to_le_bytes());
                h.update(&entry.prev_hash);
                h.update(&entry.content_hash);
                let expected_chain = *h.finalize().as_bytes();
                if expected_chain != entry.chain_hash {
                    errors.push(format!("seq={}: chain_hash mismatch", entry.sequence));
                    chain_errors += 1;
                }
                if entry.prev_hash != prev {
                    errors.push(format!("seq={}: prev_hash linkage broken", entry.sequence));
                    chain_errors += 1;
                }
                prev = entry.chain_hash;
            }
            content_ok = content_errors == 0;
            chain_ok = chain_errors == 0;

            // Recompute root and compare.
            let computed_root = if leaf_bytes.is_empty() {
                ZERO_HASH
            } else {
                merkle_root(&leaf_bytes)
            };
            if hash_to_hex(&computed_root) != root_hex {
                errors.push("Merkle root mismatch — entries do not match committed root".into());
                merkle_ok = false;
            }

            // Verify each Merkle proof path.
            if let Some(proofs) = proofs_json {
                let mut merkle_errors = 0usize;
                for (i, proof_val) in proofs.iter().enumerate() {
                    let leaf_hex = proof_val["leaf_hash"].as_str().unwrap_or("");
                    let root_in_proof = proof_val["root"].as_str().unwrap_or("");
                    let leaf_opt: Option<[u8; 32]> =
                        hex::decode(leaf_hex).ok().and_then(|b| b.try_into().ok());
                    if let Some(mut cur) = leaf_opt {
                        if let Some(steps) = proof_val["path"].as_array() {
                            for step in steps {
                                let sib_hex = step["sibling"].as_str().unwrap_or("");
                                let sib_is_left =
                                    step["sibling_is_left"].as_bool().unwrap_or(false);
                                let sib: Option<[u8; 32]> =
                                    hex::decode(sib_hex).ok().and_then(|b| b.try_into().ok());
                                if let Some(s) = sib {
                                    cur = if sib_is_left {
                                        hash_node(&s, &cur)
                                    } else {
                                        hash_node(&cur, &s)
                                    };
                                }
                            }
                        }
                        if hash_to_hex(&cur) != root_in_proof {
                            errors.push(format!("Merkle proof[{i}]: path does not verify to root"));
                            merkle_errors += 1;
                        }
                    }
                }
                if merkle_errors > 0 {
                    merkle_ok = false;
                }
            }
        }
    }

    let passed = errors.is_empty();
    Ok(VerifyReport {
        entry_count,
        root_hex: root_hex.to_string(),
        chain_tip_hex: chain_tip_hex.to_string(),
        package_type: package_type.to_string(),
        content_ok,
        chain_ok,
        merkle_ok,
        sig_status,
        errors,
        generated_at: meta["generated_at"].as_str().unwrap_or("?").to_string(),
        vledger_version: meta["vledger_version"].as_str().unwrap_or("?").to_string(),
        format_version: meta["format_version"].as_u64().unwrap_or(0),
        passed,
        tenant: meta["tenant"].as_str().unwrap_or("").to_string(),
        description: meta["description"].as_str().unwrap_or("").to_string(),
        period_start: meta["period_start"].as_str().unwrap_or("").to_string(),
        period_end: meta["period_end"].as_str().unwrap_or("").to_string(),
        first_sequence: meta["first_sequence"].as_u64().unwrap_or(0),
        last_sequence: meta["last_sequence"].as_u64().unwrap_or(0),
        signing_pubkey: meta["signing_pubkey"].as_str().unwrap_or("").to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    Absent,
    Valid,
    Invalid,
}

pub struct VerifyReport {
    pub entry_count: usize,
    pub root_hex: String,
    pub chain_tip_hex: String,
    pub package_type: String,
    pub content_ok: bool,
    pub chain_ok: bool,
    pub merkle_ok: bool,
    pub sig_status: SigStatus,
    pub errors: Vec<String>,
    pub generated_at: String,
    pub vledger_version: String,
    pub format_version: u64,
    pub passed: bool,
    // Business metadata — used to display in AUTHENTICITY VERIFIED block
    pub tenant: String,
    pub description: String,
    pub period_start: String,
    pub period_end: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub signing_pubkey: String,
}
