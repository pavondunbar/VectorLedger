//! Audit log export — JSON and CSV.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json;

use crate::error::AuditError;
use crate::event::AuditEvent;

// ── TimeRange ─────────────────────────────────────────────────────────────────

/// UTC timestamp range used to filter audit events during export.
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl TimeRange {
    pub fn new(from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        Self { from, to }
    }

    /// Accept all events (no time-range filter).
    pub fn all() -> Self {
        use chrono::TimeZone;
        Self {
            from: Utc.timestamp_opt(0, 0).unwrap(),
            to: DateTime::<Utc>::MAX_UTC,
        }
    }

    pub fn contains(&self, ts: &DateTime<Utc>) -> bool {
        ts >= &self.from && ts <= &self.to
    }
}

// ── ExportFormat ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Export audit events within `range` from `log_path` as newline-delimited
/// JSON (one event per line) into `writer`.
pub fn export_json<W: Write>(
    log_path: &Path,
    range: &TimeRange,
    writer: &mut W,
) -> Result<u64, AuditError> {
    scan_events(log_path, range, |ev| {
        let line =
            serde_json::to_string(ev).map_err(|e| AuditError::Serialisation(e.to_string()))?;
        writeln!(writer, "{line}")?;
        Ok(())
    })
}

/// Export audit events within `range` from `log_path` as CSV into `writer`.
///
/// Columns: `sequence, ts, kind, content_hash, chain_hash, details`
/// where `details` is the JSON-encoded event payload.
pub fn export_csv<W: Write>(
    log_path: &Path,
    range: &TimeRange,
    writer: &mut W,
) -> Result<u64, AuditError> {
    // Write header
    writeln!(writer, "sequence,ts,kind,content_hash,chain_hash,details")?;

    scan_events(log_path, range, |ev| {
        let details = serde_json::to_string(&ev.event)
            .map_err(|e| AuditError::Serialisation(e.to_string()))?;
        // CSV-escape the details field (wrap in quotes, escape internal quotes)
        let details_escaped = format!("\"{}\"", details.replace('"', "\"\""));
        writeln!(
            writer,
            "{},{},{},{},{},{}",
            ev.sequence,
            ev.ts.to_rfc3339(),
            ev.event.name(),
            &ev.content_hash[..16], // first 16 hex chars for readability
            &ev.chain_hash[..16],
            details_escaped,
        )?;
        Ok(())
    })
}

// ── Internal scanner ──────────────────────────────────────────────────────────

fn scan_events<F>(log_path: &Path, range: &TimeRange, mut cb: F) -> Result<u64, AuditError>
where
    F: FnMut(&AuditEvent) -> Result<(), AuditError>,
{
    if !log_path.exists() {
        return Ok(0);
    }

    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut count = 0u64;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ev: AuditEvent =
            serde_json::from_str(&line).map_err(|e| AuditError::Serialisation(e.to_string()))?;
        if range.contains(&ev.ts) {
            cb(&ev)?;
            count += 1;
        }
    }
    Ok(count)
}
