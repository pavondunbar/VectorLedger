//! Currency registry — maps currency codes to their minor-unit precision.
//!
//! Precision is the number of decimal places in the minor unit:
//! - USD → 2  (1 USD = 100 cents)
//! - JPY → 0  (1 JPY = 1 yen, no sub-unit)
//! - BTC → 8  (1 BTC = 100_000_000 satoshis)
//! - ETH → 18 (1 ETH = 10^18 wei)

use serde::{Deserialize, Serialize};
use std::fmt;

/// ISO 4217 currency code or crypto ticker (max 12 chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Currency {
    /// Uppercase ticker, e.g. "USD", "BTC", "ETH", "USDC".
    pub code: String,
    /// Number of decimal places for the minor unit.
    pub precision: u8,
    /// Human-readable name.
    pub name: String,
    /// Whether this is a crypto / digital asset (vs fiat).
    pub is_crypto: bool,
}

impl Currency {
    pub fn new(code: impl Into<String>, precision: u8, name: impl Into<String>, is_crypto: bool) -> Self {
        Self {
            code: code.into().to_uppercase(),
            precision,
            name: name.into(),
            is_crypto,
        }
    }

    /// US Dollar
    pub fn usd() -> Self {
        Self::new("USD", 2, "US Dollar", false)
    }

    /// Euro
    pub fn eur() -> Self {
        Self::new("EUR", 2, "Euro", false)
    }

    /// British Pound
    pub fn gbp() -> Self {
        Self::new("GBP", 2, "British Pound", false)
    }

    /// Bitcoin
    pub fn btc() -> Self {
        Self::new("BTC", 8, "Bitcoin", true)
    }

    /// Ethereum
    pub fn eth() -> Self {
        Self::new("ETH", 18, "Ethereum", true)
    }

    /// USDC
    pub fn usdc() -> Self {
        Self::new("USDC", 6, "USD Coin", true)
    }

    /// Japanese Yen (no minor unit)
    pub fn jpy() -> Self {
        Self::new("JPY", 0, "Japanese Yen", false)
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)
    }
}

/// In-memory currency registry.  In production this would be backed by the
/// catalog table in the page store.
#[derive(Debug, Default)]
pub struct CurrencyRegistry {
    currencies: std::collections::HashMap<String, Currency>,
}

impl CurrencyRegistry {
    pub fn new() -> Self {
        let mut r = Self::default();
        // Pre-load common currencies
        for c in [
            Currency::usd(),
            Currency::eur(),
            Currency::gbp(),
            Currency::btc(),
            Currency::eth(),
            Currency::usdc(),
            Currency::jpy(),
        ] {
            r.register(c);
        }
        r
    }

    pub fn register(&mut self, currency: Currency) {
        self.currencies.insert(currency.code.clone(), currency);
    }

    pub fn get(&self, code: &str) -> Option<&Currency> {
        self.currencies.get(&code.to_uppercase())
    }

    pub fn precision(&self, code: &str) -> Option<u8> {
        self.get(code).map(|c| c.precision)
    }
}
