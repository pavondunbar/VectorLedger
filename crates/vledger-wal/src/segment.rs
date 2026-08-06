//! WAL segment file management.
//!
//! The WAL is split into fixed-size segment files named with a zero-padded
//! 20-digit sequence number, e.g. `00000000000000000001.wal`.
//!
//! Segments are immutable once sealed.  The active segment is the highest-
//! numbered file that has not yet been sealed.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::{WalError, WAL_MAGIC, WAL_VERSION};

/// Returns the canonical filename for a segment with the given index.
pub fn segment_filename(index: u64) -> String {
    format!("{:020}.wal", index)
}

/// Parses the segment index from a filename produced by [`segment_filename`].
pub fn parse_segment_index(filename: &str) -> Option<u64> {
    filename
        .strip_suffix(".wal")
        .and_then(|s| s.parse::<u64>().ok())
}

/// Represents a single WAL segment file on disk.
pub struct Segment {
    /// Absolute path to the segment file.
    pub path: PathBuf,
    /// Monotonically increasing index (0, 1, 2, …).
    pub index: u64,
    /// Whether this segment accepts new writes.
    pub sealed: bool,
    /// Current byte offset of the write cursor (end of last written record).
    pub write_offset: u64,
    /// Maximum bytes before the segment rolls over.
    pub max_size: u64,
    /// Open file handle (present while the segment is active).
    pub file: Option<File>,
}

impl Segment {
    /// Create a new, empty segment file.
    pub fn create(dir: &Path, index: u64, max_size: u64) -> Result<Self, WalError> {
        let path = dir.join(segment_filename(index));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(&path)?;

        Ok(Self {
            path,
            index,
            sealed: false,
            write_offset: 0,
            max_size,
            file: Some(file),
        })
    }

    /// Open an existing segment file for reading (sealed) or appending
    /// (active).
    pub fn open(path: PathBuf, index: u64, max_size: u64, sealed: bool) -> Result<Self, WalError> {
        let file = OpenOptions::new()
            .read(true)
            .write(!sealed)
            .open(&path)?;

        let metadata = file.metadata()?;
        let write_offset = metadata.len();

        Ok(Self {
            path,
            index,
            sealed,
            write_offset,
            max_size,
            file: Some(file),
        })
    }

    /// Returns `true` if there is enough space for `needed` bytes.
    pub fn has_space(&self, needed: usize) -> bool {
        !self.sealed && (self.write_offset + needed as u64) <= self.max_size
    }

    /// Seal this segment — no further writes are allowed.
    pub fn seal(&mut self) -> Result<(), WalError> {
        if let Some(ref file) = self.file {
            file.sync_all()?;
        }
        self.sealed = true;
        Ok(())
    }

    /// Force all pending writes to stable storage (fsync).
    pub fn sync(&self) -> Result<(), WalError> {
        if let Some(ref file) = self.file {
            file.sync_all()?;
        }
        Ok(())
    }

    /// Returns the segment magic bytes to validate the file header.
    pub fn expected_magic() -> [u8; 8] {
        let mut magic = [0u8; 8];
        magic[..4].copy_from_slice(&WAL_MAGIC.to_le_bytes());
        magic[4] = WAL_VERSION;
        magic[5] = 0;
        magic[6] = 0;
        magic[7] = 0;
        magic
    }
}

/// Scans a directory and returns sorted segment indices found there.
pub fn list_segments(dir: &Path) -> Result<Vec<u64>, WalError> {
    let mut indices = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Some(idx) = parse_segment_index(&name_str) {
            indices.push(idx);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}
