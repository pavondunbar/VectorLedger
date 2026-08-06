//! `Amount` — the fundamental financial value type.
//!
//! ## Design
//! Financial amounts are NEVER stored as floats.  `f64` arithmetic is
//! non-deterministic across platforms and can accumulate errors in
//! multi-step calculations.
//!
//! All amounts are stored as `i64` integer **minor units** (e.g. cents for
//! USD, satoshis for BTC).  The currency's `precision` field tells callers
//! how many decimal places to shift for display purposes.
//!
//! Arithmetic is performed in `i128` to prevent overflow on intermediate
//! calculations.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Neg, Sub};

/// A non-zero, integer financial amount in minor units.
///
/// Positive = credit direction; Negative = debit direction.
/// The sign convention follows standard double-entry accounting:
/// - Assets / Expenses: debit increases, credit decreases.
/// - Liabilities / Income / Equity: credit increases, debit decreases.
///
/// However, at this layer `Amount` is sign-agnostic — the `JournalLine`
/// specifies debit/credit explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(i64);

impl Amount {
    /// Create an `Amount` from minor units.
    ///
    /// # Errors
    /// Returns `None` if the value is zero (zero amounts are not allowed in
    /// journal entries per the invariant list).
    pub fn new(minor_units: i64) -> Option<Self> {
        if minor_units == 0 {
            None
        } else {
            Some(Self(minor_units))
        }
    }

    /// Create an `Amount` without the zero check.  Use only for balance
    /// accumulators, not for journal line amounts.
    pub fn zero() -> Self {
        Self(0)
    }

    /// Raw integer value in minor units.
    pub fn as_i64(self) -> i64 {
        self.0
    }

    /// Promote to i128 for arithmetic that might overflow i64.
    pub fn as_i128(self) -> i128 {
        self.0 as i128
    }

    /// Absolute value.
    pub fn abs(self) -> Self {
        Self(self.0.abs())
    }

    /// Returns true if this amount is positive (credit).
    pub fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Returns true if this amount is negative (debit direction).
    pub fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// Checked addition — returns `None` on overflow.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }
}

impl Neg for Amount {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Add for Amount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Amount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Amount> for i64 {
    fn from(a: Amount) -> i64 {
        a.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_amount_returns_none() {
        assert!(Amount::new(0).is_none());
    }

    #[test]
    fn non_zero_amount_created() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.as_i64(), 100);
    }

    #[test]
    fn negation() {
        let a = Amount::new(500).unwrap();
        assert_eq!((-a).as_i64(), -500);
    }

    #[test]
    fn addition() {
        let a = Amount::new(100).unwrap();
        let b = Amount::new(200).unwrap();
        assert_eq!((a + b).as_i64(), 300);
    }
}
