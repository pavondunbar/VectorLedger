//! Unit tests for the compliance engine.
//!
//! These tests verify that `ComplianceEngine::generate_report()` correctly
//! evaluates controls against real filesystem state, that the report
//! structure is correct, and that serialisation (JSON/Markdown) works.

#[cfg(test)]
mod tests {
    use std::path::Path;
    use tempfile::TempDir;

    use crate::{
        ComplianceEngine,
        ComplianceStandard,
        EvidenceStatus,
        ReportDateRange,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Create a minimal data directory that looks like an initialised
    /// VectorLedger instance: wal/, pages/, catalog/VERSION, audit/audit.log.
    fn init_data_dir(dir: &TempDir) {
        let p = dir.path();
        std::fs::create_dir_all(p.join("wal")).unwrap();
        std::fs::create_dir_all(p.join("pages")).unwrap();
        std::fs::create_dir_all(p.join("catalog")).unwrap();
        std::fs::create_dir_all(p.join("audit")).unwrap();
        std::fs::create_dir_all(p.join("keys")).unwrap();
        std::fs::write(p.join("catalog").join("VERSION"), "1.0.32").unwrap();
        // Create a non-empty audit log so chain-integrity check has something to open
        let audit_path = p.join("audit").join("audit.log");
        // Write a valid first audit event so AuditLog::open and verify_chain work
        let log = vledger_audit::AuditLog::open(&audit_path).unwrap();
        log.append(vledger_audit::AuditEventKind::ServerStarted {
            bind_addr: "127.0.0.1:5433".into(),
            version: "1.0.32".into(),
        })
        .unwrap();
    }

    /// Fully-initialised data dir with a CA-signed cert placeholder.
    fn init_data_dir_with_ca_cert(dir: &TempDir) {
        init_data_dir(dir);
        std::fs::write(
            dir.path().join("keys").join("server.crt"),
            "-----BEGIN CERTIFICATE-----\nMIIBIjAN\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────
    // SOC 2 report generation
    // ─────────────────────────────────────────────────────────────────────

    /// generate_report(Soc2) on an initialised data dir succeeds and returns
    /// the expected number of evidence items.
    #[test]
    fn soc2_report_generates_on_initialised_dir() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();

        // SOC 2 defines 8 controls
        assert_eq!(
            report.evidence.len(),
            8,
            "SOC 2 report must have exactly 8 control evidence items"
        );
        assert_eq!(report.standard, ComplianceStandard::Soc2);
    }

    /// generate_report(PciDss) on an initialised data dir succeeds and returns
    /// 9 evidence items.
    #[test]
    fn pcidss_report_generates_on_initialised_dir() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();

        // PCI-DSS defines 9 controls
        assert_eq!(
            report.evidence.len(),
            9,
            "PCI-DSS report must have exactly 9 control evidence items"
        );
        assert_eq!(report.standard, ComplianceStandard::PciDss);
    }

    /// An uninitialised data directory (empty) produces a report but with
    /// fail/na evidence items — it must not panic.
    #[test]
    fn report_on_empty_dir_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let result = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days());
        assert!(
            result.is_ok(),
            "generate_report must not fail on an empty dir (evidence items may be fail/na)"
        );
    }

    /// ComplianceReport::is_compliant returns false when any control fails.
    #[test]
    fn is_compliant_false_when_controls_fail() {
        let dir = TempDir::new().unwrap();
        // Deliberately not initialised — several controls will fail
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        // An uninitialised dir will have at least some failures
        // (CC6.1 expects catalog/VERSION, CC6.2 expects audit.log, etc.)
        // We just assert is_compliant() returns the correct type
        let compliant = report.is_compliant();
        // count passes to verify is_compliant logic
        let (pass, warn, fail, na) = report.counts();
        let expected = fail == 0;
        assert_eq!(
            compliant, expected,
            "is_compliant must be true iff no Fail items (pass={pass} warn={warn} fail={fail} na={na})"
        );
    }

    /// On a properly initialised dir, CC6.1 (TLS) passes because catalog/VERSION exists.
    #[test]
    fn cc6_1_passes_when_catalog_version_exists() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let cc6_1 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "CC6.1")
            .expect("CC6.1 must be present in SOC 2 report");
        assert_eq!(
            cc6_1.status,
            EvidenceStatus::Pass,
            "CC6.1 must pass when catalog/VERSION exists"
        );
    }

    /// CC6.6 (encryption at rest) passes when pages/ exists.
    #[test]
    fn cc6_6_passes_when_pages_dir_exists() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let cc6_6 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "CC6.6")
            .expect("CC6.6 must be present in SOC 2 report");
        assert_eq!(cc6_6.status, EvidenceStatus::Pass, "CC6.6 must pass when pages/ exists");
    }

    /// CC6.7 (TLS config) warns when no CA-signed cert is present.
    #[test]
    fn cc6_7_warns_without_ca_cert() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        // No server.crt in keys/
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let cc6_7 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "CC6.7")
            .expect("CC6.7 must be present");
        assert_eq!(
            cc6_7.status,
            EvidenceStatus::Warn,
            "CC6.7 must warn without a CA-signed certificate"
        );
    }

    /// CC6.7 passes when keys/server.crt exists.
    #[test]
    fn cc6_7_passes_with_ca_cert() {
        let dir = TempDir::new().unwrap();
        init_data_dir_with_ca_cert(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let cc6_7 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "CC6.7")
            .expect("CC6.7 must be present");
        assert_eq!(
            cc6_7.status,
            EvidenceStatus::Pass,
            "CC6.7 must pass when keys/server.crt exists"
        );
    }

    /// CC7.2 (audit log chain integrity) passes on a valid log.
    #[test]
    fn cc7_2_passes_on_valid_audit_log() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let cc7_2 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "CC7.2")
            .expect("CC7.2 must be present");
        assert_eq!(
            cc7_2.status,
            EvidenceStatus::Pass,
            "CC7.2 must pass on a valid audit log"
        );
    }

    /// A1.1 (replication) warns when replication.json is absent.
    #[test]
    fn a1_1_warns_without_replication_config() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        // No replication.json
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let a1_1 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "A1.1")
            .expect("A1.1 must be present");
        assert_eq!(
            a1_1.status,
            EvidenceStatus::Warn,
            "A1.1 must warn when replication.json is absent"
        );
    }

    /// A1.1 passes when replication.json exists.
    #[test]
    fn a1_1_passes_with_replication_config() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        std::fs::write(
            dir.path().join("replication.json"),
            r#"{"role":"primary","replication_addr":"0.0.0.0:5434","ack_timeout_ms":5000,"heartbeat_interval_ms":1000,"send_buffer_bytes":67108864}"#,
        )
        .unwrap();
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let a1_1 = report
            .evidence
            .iter()
            .find(|e| e.control_id == "A1.1")
            .expect("A1.1 must be present");
        assert_eq!(a1_1.status, EvidenceStatus::Pass, "A1.1 must pass when replication.json exists");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Report structure and serialisation
    // ─────────────────────────────────────────────────────────────────────

    /// ComplianceReport::counts() returns (pass, warn, fail, na) that sums
    /// to the total evidence count.
    #[test]
    fn report_counts_sum_to_total() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let (pass, warn, fail, na) = report.counts();
        assert_eq!(
            pass + warn + fail + na,
            report.evidence.len(),
            "counts must sum to total evidence items"
        );
    }

    /// ComplianceReport::summary() returns a non-empty string.
    #[test]
    fn report_summary_is_non_empty() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let summary = report.summary();
        assert!(!summary.is_empty(), "summary must not be empty");
    }

    /// ComplianceReport::to_json() produces valid JSON.
    #[test]
    fn report_to_json_is_valid() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("standard").is_some(), "JSON must contain 'standard' field");
        assert!(parsed.get("evidence").is_some(), "JSON must contain 'evidence' field");
    }

    /// ComplianceReport::to_markdown() produces a string containing control IDs.
    #[test]
    fn report_to_markdown_contains_control_ids() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();
        let md = report.to_markdown();
        assert!(md.contains("CC6.1"), "markdown must contain CC6.1");
        assert!(md.contains("CC7.2"), "markdown must contain CC7.2");
    }

    /// ReportDateRange::last_90_days has a 90-day span.
    #[test]
    fn report_date_range_last_90_days_span() {
        use chrono::Utc;
        let range = ReportDateRange::last_90_days();
        let span = (range.to - range.from).num_days();
        assert!(
            span >= 89 && span <= 91,
            "last_90_days must span approximately 90 days, got {span}"
        );
        assert!(range.to <= Utc::now(), "range.to must be <= now");
    }

    /// ReportDateRange::last_year has approximately 365 days.
    #[test]
    fn report_date_range_last_year_span() {
        let range = ReportDateRange::last_year();
        let span = (range.to - range.from).num_days();
        assert!(
            span >= 364 && span <= 366,
            "last_year must span approximately 365 days, got {span}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // PCI-DSS specific controls
    // ─────────────────────────────────────────────────────────────────────

    /// PCI-2.2 passes when MASTER_KEY_PLACEHOLDER.txt is absent.
    #[test]
    fn pci_2_2_passes_when_placeholder_absent() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();
        let ctrl = report
            .evidence
            .iter()
            .find(|e| e.control_id == "PCI-2.2")
            .expect("PCI-2.2 must be present");
        assert_eq!(
            ctrl.status,
            EvidenceStatus::Pass,
            "PCI-2.2 must pass when placeholder file is absent"
        );
    }

    /// PCI-2.2 fails when MASTER_KEY_PLACEHOLDER.txt is present.
    #[test]
    fn pci_2_2_fails_when_placeholder_present() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        std::fs::write(
            dir.path().join("keys").join("MASTER_KEY_PLACEHOLDER.txt"),
            "placeholder",
        )
        .unwrap();
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();
        let ctrl = report
            .evidence
            .iter()
            .find(|e| e.control_id == "PCI-2.2")
            .expect("PCI-2.2 must be present");
        assert_eq!(
            ctrl.status,
            EvidenceStatus::Fail,
            "PCI-2.2 must fail when placeholder file is present"
        );
    }

    /// PCI-3.5 passes when key_source.json specifies pyhsm backend.
    #[test]
    fn pci_3_5_passes_with_pyhsm_backend() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        std::fs::write(
            dir.path().join("keys").join("key_source.json"),
            r#"{"backend":"pyhsm","socket":"/tmp/pyhsm.sock"}"#,
        )
        .unwrap();
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();
        let ctrl = report
            .evidence
            .iter()
            .find(|e| e.control_id == "PCI-3.5")
            .expect("PCI-3.5 must be present");
        assert_eq!(
            ctrl.status,
            EvidenceStatus::Pass,
            "PCI-3.5 must pass with pyhsm backend"
        );
    }

    /// PCI-3.5 fails when key_source.json specifies file backend.
    #[test]
    fn pci_3_5_fails_with_file_backend() {
        let dir = TempDir::new().unwrap();
        init_data_dir(&dir);
        std::fs::write(
            dir.path().join("keys").join("key_source.json"),
            r#"{"backend":"file","path":"./master.key"}"#,
        )
        .unwrap();
        let engine = ComplianceEngine::new(dir.path().to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_90_days())
            .unwrap();
        let ctrl = report
            .evidence
            .iter()
            .find(|e| e.control_id == "PCI-3.5")
            .expect("PCI-3.5 must be present");
        assert_eq!(
            ctrl.status,
            EvidenceStatus::Fail,
            "PCI-3.5 must fail with file backend"
        );
    }
}
