//! ComplianceEngine — top-level entry point.

use std::path::PathBuf;

use chrono::Utc;

use crate::error::ComplianceError;
use crate::report::{ComplianceReport, ReportDateRange};
use crate::rules::{evaluate, ComplianceStandard};

/// Evaluates compliance controls and generates a `ComplianceReport`.
pub struct ComplianceEngine {
    data_dir: PathBuf,
}

impl ComplianceEngine {
    /// Create an engine that reads evidence from `data_dir`.
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Evaluate all controls for `standard` over `range` and return a full
    /// `ComplianceReport`.
    pub fn generate_report(
        &self,
        standard: ComplianceStandard,
        range: ReportDateRange,
    ) -> Result<ComplianceReport, ComplianceError> {
        let evidence = evaluate(standard, &self.data_dir, &range)?;
        Ok(ComplianceReport {
            standard,
            generated_at: Utc::now(),
            date_range: range,
            evidence,
        })
    }
}
