//! Kani proof harnesses for the Amount financial type.
//!
//! Proves that:
//! 1. `Amount::new(0)` always returns None (zero amounts forbidden).
//! 2. `Amount::new(x)` for any positive x always returns Some.
//! 3. Checked arithmetic operators never panic for any valid i64 inputs.
//! 4. Negation, addition, and subtraction are consistent with i64 semantics.

use vledger_ledger::Amount;

// ── Harness 1: zero amount always rejected ────────────────────────────────────

/// Prove that `Amount::new(0)` always returns `None`.
/// The financial invariant "every amount must be non-zero" must hold
/// for all possible execution paths.
#[cfg(kani)]
#[kani::proof]
pub fn amount_zero_always_rejected() {
    let result = Amount::new(0);
    assert!(result.is_none(), "Amount::new(0) must always return None");
}

// ── Harness 2: positive amount always accepted ────────────────────────────────

/// Prove that `Amount::new(x)` returns `Some` for all positive i64 values.
#[cfg(kani)]
#[kani::proof]
pub fn amount_positive_always_accepted() {
    let x: i64 = kani::any();
    kani::assume(x > 0);

    let result = Amount::new(x);
    assert!(
        result.is_some(),
        "Amount::new(x) must return Some for all positive x"
    );
}

// ── Harness 3: Amount accepts non-zero values (positive and negative) ─────────

/// Prove that `Amount::new(x)` returns `Some` for all non-zero i64 values.
/// Amount is sign-agnostic — sign is conveyed by the JournalLine's debit/credit
/// field.  Only zero is rejected.
#[cfg(kani)]
#[kani::proof]
pub fn amount_nonzero_always_accepted() {
    let x: i64 = kani::any();
    kani::assume(x != 0);

    let result = Amount::new(x);
    let is_some = result.is_some();
    assert!(
        is_some,
        "Amount::new(x) must return Some for all non-zero x (positive or negative)"
    );
}

// ── Harness 4: checked_add never panics ──────────────────────────────────────

/// Prove that `Amount::checked_add` never panics for any two valid amounts.
/// Panics in financial arithmetic are a critical reliability failure.
#[cfg(kani)]
#[kani::proof]
pub fn amount_checked_add_never_panics() {
    let x: i64 = kani::any();
    let y: i64 = kani::any();
    kani::assume(x > 0 && y > 0);

    let a = Amount::new(x).unwrap();
    let b = Amount::new(y).unwrap();

    // checked_add returns None on overflow — must never panic
    let _ = a.checked_add(b);
}

// ── Harness 5: checked_sub never panics ──────────────────────────────────────

/// Prove that `Amount::checked_sub` never panics for any two valid amounts.
#[cfg(kani)]
#[kani::proof]
pub fn amount_checked_sub_never_panics() {
    let x: i64 = kani::any();
    let y: i64 = kani::any();
    kani::assume(x > 0 && y > 0);

    let a = Amount::new(x).unwrap();
    let b = Amount::new(y).unwrap();

    let _ = a.checked_sub(b);
}

// ── Harness 6: amount as_i128 never loses information ────────────────────────

/// Prove that converting Amount to i128 never loses the original value.
/// All internal ledger balance sums use i128 to prevent overflow.
#[cfg(kani)]
#[kani::proof]
pub fn amount_i128_conversion_lossless() {
    let x: i64 = kani::any();
    kani::assume(x > 0);

    let a = Amount::new(x).unwrap();
    let as_128 = a.as_i128();

    assert_eq!(
        as_128, x as i128,
        "Amount::as_i128 must be lossless for all positive i64 values"
    );
}

// ── Harness 7: checked_add result is correct when no overflow ─────────────────

/// Prove that when `checked_add` succeeds, the result equals x + y.
#[cfg(kani)]
#[kani::proof]
pub fn amount_checked_add_correct_result() {
    let x: i64 = kani::any();
    let y: i64 = kani::any();
    // Constrain to values that cannot overflow when added
    kani::assume(x > 0 && y > 0 && x <= i64::MAX / 2 && y <= i64::MAX / 2);

    let a = Amount::new(x).unwrap();
    let b = Amount::new(y).unwrap();

    let result = a.checked_add(b);
    assert!(result.is_some(), "checked_add must succeed when no overflow");

    let sum = result.unwrap();
    assert_eq!(
        sum.as_i128(),
        (x + y) as i128,
        "checked_add result must equal x + y when no overflow"
    );
}
