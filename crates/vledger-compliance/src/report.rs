//! ComplianceReport and date-range helpers.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::evidence::{Evidence, EvidenceStatus};
use crate::rules::ComplianceStandard;

/// UTC date range for a compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDateRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl ReportDateRange {
    pub fn new(from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        Self { from, to }
    }

    /// Last 90 days up to now — typical SOC 2 Type II window.
    pub fn last_90_days() -> Self {
        let to = Utc::now();
        let from = to - Duration::days(90);
        Self { from, to }
    }

    /// Last 365 days (annual PCI-DSS review).
    pub fn last_year() -> Self {
        let to = Utc::now();
        let from = to - Duration::days(365);
        Self { from, to }
    }
}

/// The complete output of a compliance evaluation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub standard: ComplianceStandard,
    pub generated_at: DateTime<Utc>,
    pub date_range: ReportDateRange,
    pub evidence: Vec<Evidence>,
}

impl ComplianceReport {
    /// Count of PASS / WARN / FAIL / N/A controls.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let pass = self
            .evidence
            .iter()
            .filter(|e| e.status == EvidenceStatus::Pass)
            .count();
        let warn = self
            .evidence
            .iter()
            .filter(|e| e.status == EvidenceStatus::Warn)
            .count();
        let fail = self
            .evidence
            .iter()
            .filter(|e| e.status == EvidenceStatus::Fail)
            .count();
        let na = self
            .evidence
            .iter()
            .filter(|e| e.status == EvidenceStatus::NotApplicable)
            .count();
        (pass, warn, fail, na)
    }

    /// Whether every evaluated control passes (warnings are allowed).
    pub fn is_compliant(&self) -> bool {
        self.evidence
            .iter()
            .all(|e| e.status != EvidenceStatus::Fail)
    }

    /// One-line summary string.
    pub fn summary(&self) -> String {
        let (pass, warn, fail, na) = self.counts();
        format!(
            "{:?} compliance report ({} — {}): {} PASS, {} WARN, {} FAIL, {} N/A — {}",
            self.standard,
            self.date_range.from.format("%Y-%m-%d"),
            self.date_range.to.format("%Y-%m-%d"),
            pass,
            warn,
            fail,
            na,
            if self.is_compliant() {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            },
        )
    }

    /// Serialise to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialise to a simple Markdown table (for sharing with auditors).
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# {:?} Compliance Report\n\n**Period:** {} — {}\n\n**Generated:** {}\n\n",
            self.standard,
            self.date_range.from.format("%Y-%m-%d"),
            self.date_range.to.format("%Y-%m-%d"),
            self.generated_at.format("%Y-%m-%d %H:%M UTC"),
        );
        out.push_str("| Control | Title | Status | Findings |\n");
        out.push_str("|---------|-------|--------|----------|\n");
        for ev in &self.evidence {
            let findings = if ev.findings.is_empty() {
                "-".to_string()
            } else {
                ev.findings.join("; ")
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                ev.control_id, ev.title, ev.status, findings
            ));
        }
        let (pass, warn, fail, na) = self.counts();
        let result_label = if self.is_compliant() {
            if warn > 0 {
                "COMPLIANT WITH WARNINGS"
            } else {
                "COMPLIANT"
            }
        } else {
            "NON-COMPLIANT"
        };
        out.push_str(&format!(
            "\n**Result:** {} PASS · {} WARN · {} FAIL · {} N/A — **{}**\n",
            pass, warn, fail, na, result_label,
        ));
        out
    }
}
