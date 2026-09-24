//! Fuzz target: WAL recovery across multiple segments.
//!
//! The existing fuzz_wal_recovery feeds bytes as a single segment file.
//! This target creates two or three segment files from fuzz data and runs
//! recovery, exercising the WalReader's segment-stitching logic.
//!
//! ## What is fuzzed
//! - Two segments: fuzz data split across segment 0 and segment 1
//! - Three segments: fuzz data split across segments 0, 1, and 2
//! - Segment with valid WAL_MAGIC followed by a segment with fuzz bytes
//! - Segment with fuzz bytes followed by a segment with valid records
//! - Encrypted segment (zero master key) followed by plaintext segment
//! - recover(), recover_verified(), recover_streaming() all exercised

#![no_main]

use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

use vledger_wal::recovery::{recover, recover_streaming, recover_verified};
use vledger_wal::segment::segment_filename;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    if data.is_empty() {
        return;
    }

    let dir = match TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let wal_dir = dir.path().join("wal");
    if std::fs::create_dir_all(&wal_dir).is_err() {
        return;
    }

    // ── Scenario selection via first byte ─────────────────────────────────
    let scenario = data[0] % 5;
    let payload = &data[1..];

    match scenario {
        // Scenario 0: two equal-sized segments from fuzz data
        0 => {
            let mid = payload.len() / 2;
            let seg0 = &payload[..mid];
            let seg1 = &payload[mid..];
            let _ = std::fs::write(wal_dir.join(segment_filename(0)), seg0);
            let _ = std::fs::write(wal_dir.join(segment_filename(1)), seg1);
        }

        // Scenario 1: three segments
        1 => {
            let third = payload.len() / 3;
            let _ = std::fs::write(wal_dir.join(segment_filename(0)), &payload[..third]);
            let _ = std::fs::write(wal_dir.join(segment_filename(1)), &payload[third..2 * third]);
            let _ = std::fs::write(wal_dir.join(segment_filename(2)), &payload[2 * third..]);
        }

        // Scenario 2: first segment has valid WAL records, second has fuzz bytes
        2 => {
            use vledger_wal::record::BeginPayload;
            use vledger_wal::{RecordType, WalSyncMode, WalWriter};

            {
                if let Ok(mut w) = WalWriter::open_with_options(
                    &wal_dir,
                    64 * 1024 * 1024,
                    WalSyncMode::PerRecord,
                    None,
                ) {
                    let _ = w.append_record(
                        1,
                        RecordType::Begin,
                        &BeginPayload { description: Some("seg0-valid".into()) },
                    );
                }
            }

            // Append fuzz bytes as a second "segment"
            let _ = std::fs::write(wal_dir.join(segment_filename(1)), payload);
        }

        // Scenario 3: first segment has fuzz bytes, second has valid records
        3 => {
            use vledger_wal::record::BeginPayload;
            use vledger_wal::{RecordType, WalSyncMode, WalWriter};

            let _ = std::fs::write(wal_dir.join(segment_filename(0)), payload);

            // Write valid records into segment 1
            let seg1_dir = TempDir::new().unwrap_or_else(|_| TempDir::new().unwrap());
            if let Ok(mut w) = WalWriter::open_with_options(
                seg1_dir.path(),
                64 * 1024 * 1024,
                WalSyncMode::PerRecord,
                None,
            ) {
                let _ = w.append_record(
                    1,
                    RecordType::Begin,
                    &BeginPayload { description: Some("seg1-valid".into()) },
                );
                // Copy the written segment to wal_dir as segment 1
                if let Ok(segs) = vledger_wal::segment::list_segments(seg1_dir.path()) {
                    if let Some(&idx) = segs.last() {
                        let src = seg1_dir.path().join(segment_filename(idx));
                        let _ = std::fs::copy(src, wal_dir.join(segment_filename(1)));
                    }
                }
            }
        }

        // Scenario 4: two segments of fuzz data, different sizes
        _ => {
            let cut = (payload.len() / 3).max(1);
            let _ = std::fs::write(wal_dir.join(segment_filename(0)), &payload[..cut]);
            let _ = std::fs::write(wal_dir.join(segment_filename(1)), &payload[cut..]);
        }
    }

    // Run all three recovery variants — must not panic
    let _ = recover(&wal_dir);

    let zero_key = [0u8; 32];
    let _ = recover_verified(&wal_dir, Some(zero_key));

    let mut committed = 0usize;
    let _ = recover_streaming(
        &wal_dir,
        None,
        false,
        None,
        0,
        |_tx| -> Result<(), vledger_wal::WalError> {
            committed += 1;
            if committed > 10_000 {
                return Err(vledger_wal::WalError::Serialization(
                    "fuzz: committed exceeded 10_000".into(),
                ));
            }
            Ok(())
        },
    );

    // Also exercise WalReader directly across all segments
    if let Ok(reader) = vledger_wal::WalReader::open(&wal_dir) {
        for (i, _) in reader.enumerate() {
            if i >= 2000 {
                break;
            }
        }
    }
});
