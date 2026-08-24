//! Chart of accounts — account definitions and the account type hierarchy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque account identifier.
pub type AccountId = Uuid;

/// Standard double-entry account types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountType {
    /// Asset accounts (cash, receivables, investments).
    /// Normal balance: Debit.
    Asset,
    /// Liability accounts (payables, loans).
    /// Normal balance: Credit.
    Liability,
    /// Equity / capital accounts.
    /// Normal balance: Credit.
    Equity,
    /// Income / revenue accounts.
    /// Normal balance: Credit.
    Income,
    /// Expense accounts.
    /// Normal balance: Debit.
    Expense,
    /// Contra accounts (e.g. accumulated depreciation).
    Contra,
    /// Suspense / clearing accounts.
    Suspense,
}

impl AccountType {
    /// Returns the normal balance sign for this account type.
    /// Debit-normal types return +1 (balance increases on debit).
    /// Credit-normal types return -1.
    pub fn normal_balance_sign(self) -> i64 {
        match self {
            Self::Asset | Self::Expense => 1,
            Self::Liability | Self::Equity | Self::Income => -1,
            Self::Contra => -1,
            Self::Suspense => 1,
        }
    }
}

/// Account status lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    Active,
    Closed,
    Frozen,
}

/// A single account in the chart of accounts.
///
/// Accounts are immutable once created (name / type changes require a new
/// account and a transfer entry, per double-entry discipline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    /// Human-readable code, e.g. "1001", "CASH_USD".
    pub code: String,
    /// Human-readable name, e.g. "Cash — USD Operating Account".
    pub name: String,
    pub account_type: AccountType,
    /// ISO 4217 or crypto currency code.
    pub currency_code: String,
    pub status: AccountStatus,
    /// Whether this account requires non-negative balance.
    pub require_non_negative_balance: bool,
    /// Maximum absolute exposure (debit) allowed in a single entry.
    /// `None` = no limit.
    pub exposure_limit: Option<i64>,
    /// Whether entries to this account require four-eyes approval.
    pub require_four_eyes: bool,
    /// Optional parent account ID (for hierarchical chart of accounts).
    pub parent_id: Option<AccountId>,
    /// UTC timestamp when this account was created.
    pub created_at: DateTime<Utc>,
    /// Domain / legal entity this account belongs to.
    pub domain: String,
    /// Whether this account is under a legal hold.
    /// When true, no new entries, reversals, or settlements are permitted
    /// until the hold is explicitly lifted by an admin.
    pub legal_hold: bool,
}

impl Account {
    /// Create a new account with sensible defaults.
    pub fn new(
        code: impl Into<String>,
        name: impl Into<String>,
        account_type: AccountType,
        currency_code: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            code: code.into(),
            name: name.into(),
            account_type,
            currency_code: currency_code.into().to_uppercase(),
            status: AccountStatus::Active,
            require_non_negative_balance: true,
            exposure_limit: None,
            require_four_eyes: false,
            parent_id: None,
            created_at: Utc::now(),
            domain: domain.into(),
            legal_hold: false,
        }
    }

    /// Is this account open for new entries?
    pub fn is_active(&self) -> bool {
        self.status == AccountStatus::Active
    }
}
