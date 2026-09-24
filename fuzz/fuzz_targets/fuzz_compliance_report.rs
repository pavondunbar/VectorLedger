//! Fuzz target: compliance engine report generation.
//!
//! Feeds the compliance engine an adversarially crafted data directory and
//! proves that no filesystem state can cause a panic, OOM, or hang.
//!
//! ## What is fuzzed
//! - Data directory with fuzz-content files at every evidence path
//! - audit.log: arbitrary bytes (corrupt chain, truncated, binary garbage)
//! - replication.json: arbitrary JSON
//! - keys/key_source.json: arbitrary JSON with arbitrary backend field
//! - keys/server.crt: arbitrary bytes
//! - catalog/VERSION: arbitrary content
//! - Both ComplianceStandard::Soc2 and ComplianceStandard::PciDss

#![no_main]

use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let dir = match TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let p = dir.path();

    // Create a directory structure with fuzz-derived content
    let _ = std::fs::create_dir_all(p.join("wal"));
    let _ = std::fs::create_dir_all(p.join("pages"));
    let _ = std::fs::create_dir_all(p.join("catalog"));
    let _ = std::fs::create_dir_all(p.join("audit"));
    let _ = std::fs::create_dir_all(p.join("keys"));

    // Split fuzz data into multiple files using simple offsets
    let chunk = data.len() / 6;
    let chunk = chunk.max(1).min(4096);

    // audit/audit.log — fuzz content (may be corrupt chain, binary garbage, etc.)
    let audit_start = 0;
    let audit_end = (audit_start + chunk).min(data.len());
    let _ = std::fs::write(p.join("audit").join("audit.log"), &data[audit_start..audit_end]);

    // catalog/VERSION
    let ver_start = audit_end;
    let ver_end = (ver_start + chunk.min(32)).min(data.len());
    if ver_start < data.len() {
        let _ = std::fs::write(p.join("catalog").join("VERSION"), &data[ver_start..ver_end]);
    } else {
        let _ = std::fs::write(p.join("catalog").join("VERSION"), b"1.0.33");
    }

    // replication.json — fuzz JSON
    let rep_start = ver_end;
    let rep_end = (rep_start + chunk).min(data.len());
    if rep_start < data.len() {
        let _ = std::fs::write(p.join("replication.json"), &data[rep_start..rep_end]);
    }

    // keys/key_source.json — fuzz backend
    let ks_start = rep_end;
    let ks_end = (ks_start + chunk).min(data.len());
    if ks_start < data.len() {
        let _ = std::fs::write(p.join("keys").join("key_source.json"), &data[ks_start..ks_end]);
    }

    // keys/server.crt — may or may not exist
    if !data.is_empty() && data[0] % 2 == 0 {
        let cert_start = ks_end;
        let cert_end = (cert_start + chunk.min(256)).min(data.len());
        if cert_start < data.len() {
            let _ = std::fs::write(p.join("keys").join("server.crt"), &data[cert_start..cert_end]);
        }
    }

    let engine = ComplianceEngine::new(p.to_path_buf());
    let range = ReportDateRange::last_90_days();

    // Both standards — must not panic on any fuzz-derived filesystem state
    let result_soc2 = engine.generate_report(ComplianceStandard::Soc2, range.clone());
    let result_pci = engine.generate_report(ComplianceStandard::PciDss, range);

    // Reports must either succeed or return a typed error — never panic
    if let Ok(report) = result_soc2 {
        // Serialisation must not panic
        let _ = report.to_json();
        let _ = report.to_markdown();
        let _ = report.summary();
        let _ = report.counts();
        let _ = report.is_compliant();
    }

    if let Ok(report) = result_pci {
        let _ = report.to_json();
        let _ = report.to_markdown();
    }
});
