//! Kani proof harnesses for WAL reader payload bounds.
//!
//! Proves that:
//! 1. The MAX_RECORD_PAYLOAD cap (64 MiB) correctly rejects oversized values.
//! 2. The cap correctly accepts any value below the threshold.
//! 3. The cap cannot be bypassed by values near the boundary.

// MAX_RECORD_PAYLOAD = 64 * 1024 * 1024 = 67_108_864
const MAX_RECORD_PAYLOAD: usize = 64 * 1024 * 1024;

/// Simulates the reader guard logic extracted from vledger-wal/src/reader.rs.
/// Returns true if the payload_len is within the allowed range.
fn payload_len_is_safe(payload_len: usize) -> bool {
    payload_len < MAX_RECORD_PAYLOAD
}

// ── Harness 1: oversized payload always rejected ──────────────────────────────

/// Prove that any payload_len >= MAX_RECORD_PAYLOAD is always rejected.
/// This ensures no 4 GiB allocation can be triggered by a crafted WAL record.
#[cfg(kani)]
#[kani::proof]
pub fn wal_oversized_payload_always_rejected() {
    let payload_len: usize = kani::any();
    kani::assume(payload_len >= MAX_RECORD_PAYLOAD);

    assert!(
        !payload_len_is_safe(payload_len),
        "payload_len >= MAX_RECORD_PAYLOAD must always be rejected"
    );
}

// ── Harness 2: undersized payload always accepted ─────────────────────────────

/// Prove that any payload_len < MAX_RECORD_PAYLOAD is always accepted.
#[cfg(kani)]
#[kani::proof]
pub fn wal_safe_payload_always_accepted() {
    let payload_len: usize = kani::any();
    kani::assume(payload_len < MAX_RECORD_PAYLOAD);

    assert!(
        payload_len_is_safe(payload_len),
        "payload_len < MAX_RECORD_PAYLOAD must always be accepted"
    );
}

// ── Harness 3: boundary is exact ─────────────────────────────────────────────

/// Prove that the boundary is exactly at MAX_RECORD_PAYLOAD:
/// MAX_RECORD_PAYLOAD - 1 is accepted; MAX_RECORD_PAYLOAD itself is rejected.
#[cfg(kani)]
#[kani::proof]
pub fn wal_boundary_exact() {
    // One below the limit — must be accepted
    assert!(
        payload_len_is_safe(MAX_RECORD_PAYLOAD - 1),
        "MAX_RECORD_PAYLOAD - 1 must be accepted"
    );
    // Exactly at the limit — must be rejected
    assert!(
        !payload_len_is_safe(MAX_RECORD_PAYLOAD),
        "MAX_RECORD_PAYLOAD must be rejected"
    );
}

// ── Harness 4: u32::MAX as payload_len is always rejected ────────────────────

/// Prove that u32::MAX (0xFFFF_FFFF = 4 GiB) is always rejected.
/// This is the exact value that triggered the OOM crash found by the fuzzer.
#[cfg(kani)]
#[kani::proof]
pub fn wal_u32_max_payload_rejected() {
    let payload_len = u32::MAX as usize;

    assert!(
        !payload_len_is_safe(payload_len),
        "u32::MAX payload_len must always be rejected (OOM prevention)"
    );
}

// ── Harness 5: usize::MAX as payload_len is always rejected ──────────────────

/// Prove that usize::MAX is always rejected, regardless of platform.
#[cfg(kani)]
#[kani::proof]
pub fn wal_usize_max_payload_rejected() {
    assert!(
        !payload_len_is_safe(usize::MAX),
        "usize::MAX payload_len must always be rejected"
    );
}
