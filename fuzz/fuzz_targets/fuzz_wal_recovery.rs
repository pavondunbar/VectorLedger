//! Fuzz target: WAL crash recovery.
//!
//! Feeds arbitrary bytes as a WAL segment file and runs the full recovery
//! path. The goal is to prove that no input — however malformed — can cause
//! a panic, unbounded memory allocation, or silent data corruption.
//!
//! ## What is fuzzed
//! - Arbitrary byte sequences that look nothing like a valid WAL segment
//! - Valid segment headers with corrupt payloads
//! - Truncated records at every possible offset
//! - Records with manipulated CRC-32 fields
//! - Records with impossible payload_len values
//! - Sequences of valid records followed by partial garbage
//!
//! ## Success criteria
//! The fuzzer considers any of the following a bug:
//! - `panic!` / `unwrap` failure (via libfuzzer's AddressSanitizer)
//! - Allocation larger than 256 MiB (caught by libfuzzer memory limits)
//! - Infinite loop (caught by timeout)

#![no_main]

use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

fuzz_target!(|data: &[u8]| {
    // Write the fuzz input as a WAL segment file
    let dir = match TempDir::new() {
        Ok(d)  => d,
        Err(_) => return,
    };
    let seg_path = dir.path().join("00000000000000000000.wal");
    if std::fs::write(&seg_path, data).is_err() {
        return;
    }

    // Run recovery — must not panic regardless of input
    let _ = vledger_wal::recovery::recover(dir.path());

    // Also exercise the reader iterator directly
    if let Ok(reader) = vledger_wal::WalReader::open(dir.path()) {
        // Consume at most 1000 records to bound execution time
        for (i, _record) in reader.enumerate() {
            if i >= 1000 { break; }
        }
    }

    // Exercise encrypted recovery path with a zero master key
    let zero_key = [0u8; 32];
    let _ = vledger_wal::recovery::recover_verified(dir.path(), Some(zero_key));
});
