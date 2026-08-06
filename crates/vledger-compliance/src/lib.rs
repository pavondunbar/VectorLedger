//! # vledger-compliance
//!
//! Compliance reporting hooks for VectorLedger.
//!
//! Generates evidence artefacts for SOC 2 and PCI-DSS audits by inspecting
//! the live audit log, WAL, and ledger state.
//!
//! ## Usage
//! ```no_run
//! use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};
//! use chrono::Utc;
//!
//! let engine = ComplianceEngine::new("./vledger-data".into());
//! let range  = ReportDateRange::last_90_days();
//! let report = engine.generate_report(ComplianceStandard::Soc2, range).unwrap();
//! println!("{}", report.summary());
//! ```

pub mod engine;
pub mod error;
pub mod evidence;
pub mod report;
pub mod rules;

pub use engine::ComplianceEngine;
pub use error::ComplianceError;
pub use evidence::{Evidence, EvidenceStatus};
pub use report::{ComplianceReport, ReportDateRange};
pub use rules::ComplianceStandard;
