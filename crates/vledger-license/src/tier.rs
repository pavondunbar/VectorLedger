//! License tiers and feature definitions.

use serde::{Deserialize, Serialize};

/// A licensable feature that can be gated by tier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// PostgreSQL wire protocol listener (port 5432).
    PgWire,
    /// Synchronous WAL replication to a hot standby.
    Replication,
    /// HSM PKCS#11 key management integration.
    Hsm,
    /// Full compliance report generation (SOC 2 + PCI-DSS).
    ComplianceReport,
    /// Unlimited audit log export date range (free tier: 30 days).
    AuditExportUnlimited,
    /// Multiple node deployments.
    MultiNode,
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Feature::PgWire => "pgwire",
            Feature::Replication => "replication",
            Feature::Hsm => "hsm",
            Feature::ComplianceReport => "compliance_report",
            Feature::AuditExportUnlimited => "audit_export_unlimited",
            Feature::MultiNode => "multi_node",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for Feature {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pgwire" => Ok(Feature::PgWire),
            "replication" => Ok(Feature::Replication),
            "hsm" => Ok(Feature::Hsm),
            "compliance_report" => Ok(Feature::ComplianceReport),
            "audit_export_unlimited" => Ok(Feature::AuditExportUnlimited),
            "multi_node" => Ok(Feature::MultiNode),
            other => Err(format!("unknown feature '{other}'")),
        }
    }
}

/// License tier names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    /// Free tier — core ledger only, single node, 30-day audit export.
    Free,
    /// Starter tier — adds PostgreSQL wire protocol, 90-day audit export.
    /// Single node, no replication. $199/month.
    Starter,
    /// Growth tier — pgwire, replication, unlimited audit export, full
    /// compliance reports. $999/month.
    Growth,
    /// Enterprise tier — all features, hardware HSM, multi-node. Contact Sales.
    Enterprise,
}

impl LicenseTier {
    /// Human-readable name for error messages and display.
    pub fn display_name(&self) -> &'static str {
        match self {
            LicenseTier::Free => "Free",
            LicenseTier::Starter => "Starter",
            LicenseTier::Growth => "Growth",
            LicenseTier::Enterprise => "Enterprise",
        }
    }

    /// Features included in this tier by default (used for free tier which
    /// has no license file and therefore no explicit features list).
    pub fn default_features(&self) -> Vec<Feature> {
        match self {
            LicenseTier::Free => vec![
                // Core features always available — no gating.
            ],
            LicenseTier::Starter => vec![
                // PostgreSQL wire protocol — the key unlock for Starter.
                // No replication, no compliance report, 90-day audit export
                // (enforced at export time by checking the license tier).
                Feature::PgWire,
            ],
            LicenseTier::Growth => vec![
                Feature::PgWire,
                Feature::Replication,
                Feature::ComplianceReport,
                Feature::AuditExportUnlimited,
            ],
            LicenseTier::Enterprise => vec![
                Feature::PgWire,
                Feature::Replication,
                Feature::Hsm,
                Feature::ComplianceReport,
                Feature::AuditExportUnlimited,
                Feature::MultiNode,
            ],
        }
    }
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for LicenseTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(LicenseTier::Free),
            "starter" => Ok(LicenseTier::Starter),
            "growth" => Ok(LicenseTier::Growth),
            "enterprise" => Ok(LicenseTier::Enterprise),
            other => Err(format!(
                "unknown tier '{other}' — use: free, starter, growth, enterprise"
            )),
        }
    }
}
