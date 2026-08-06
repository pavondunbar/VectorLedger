//! Evidence item — the atomic unit of a compliance report.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Pass/fail status of a single compliance control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// The control is satisfied.
    Pass,
    /// The control is not satisfied — finding must be addressed.
    Fail,
    /// The control could not be evaluated (data unavailable).
    NotApplicable,
}

impl std::fmt::Display for EvidenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass           => write!(f, "PASS"),
            Self::Fail           => write!(f, "FAIL"),
            Self::NotApplicable  => write!(f, "N/A"),
        }
    }
}

/// A single piece of compliance evidence for one control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Control identifier, e.g. `"CC6.1"` (SOC 2) or `"PCI-DSS-3.4"`.
    pub control_id:  String,
    /// Human-readable control title.
    pub title:       String,
    /// Pass / Fail / N/A.
    pub status:      EvidenceStatus,
    /// Human-readable description of what was checked.
    pub description: String,
    /// Specific findings or details supporting the status.
    pub findings:    Vec<String>,
    /// When this evidence was collected.
    pub collected_at: DateTime<Utc>,
}

impl Evidence {
    pub fn pass(
        control_id:  impl Into<String>,
        title:       impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            control_id:   control_id.into(),
            title:        title.into(),
            status:       EvidenceStatus::Pass,
            description:  description.into(),
            findings:     vec![],
            collected_at: Utc::now(),
        }
    }

    pub fn fail(
        control_id:  impl Into<String>,
        title:       impl Into<String>,
        description: impl Into<String>,
        findings:    Vec<String>,
    ) -> Self {
        Self {
            control_id:   control_id.into(),
            title:        title.into(),
            status:       EvidenceStatus::Fail,
            description:  description.into(),
            findings,
            collected_at: Utc::now(),
        }
    }

    pub fn na(
        control_id:  impl Into<String>,
        title:       impl Into<String>,
        reason:      impl Into<String>,
    ) -> Self {
        Self {
            control_id:   control_id.into(),
            title:        title.into(),
            status:       EvidenceStatus::NotApplicable,
            description:  reason.into(),
            findings:     vec![],
            collected_at: Utc::now(),
        }
    }
}
