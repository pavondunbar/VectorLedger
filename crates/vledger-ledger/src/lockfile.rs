//! Advisory process lock for the data directory.
//!
//! VectorLedger is a single-writer database. Running two processes against
//! the same data directory would corrupt WAL state. This module acquires an
//! exclusive OS-level advisory lock on `vledger-data/.lockfile` at startup and
//! releases it on drop.
//!
//! On Linux and macOS this uses `flock(2)` (LOCK_EX | LOCK_NB).
//! If the lock is already held by another process, `LockError::AlreadyLocked`
//! is returned immediately without blocking.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error(
        "Data directory is already locked by another process. \
             Only one vgdb process may open a data directory at a time."
    )]
    AlreadyLocked,

    #[error("Failed to create lock file at {path}: {reason}")]
    CreateFailed { path: String, reason: String },

    #[error("I/O error on lock file: {0}")]
    Io(#[from] std::io::Error),
}

/// An exclusive advisory lock on the data directory.
/// Releases automatically on drop via `flock(LOCK_UN)`.
pub struct DataDirLock {
    path: PathBuf,
    // Kept alive so the fd stays open (lock is released when the file is closed).
    _file: File,
}

impl DataDirLock {
    /// Attempt to acquire an exclusive lock.
    ///
    /// Returns `Err(LockError::AlreadyLocked)` immediately if another process
    /// holds the lock.
    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        let lock_path = data_dir.join(".lockfile");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .read(true)
            .open(&lock_path)
            .map_err(|e| LockError::CreateFailed {
                path: lock_path.display().to_string(),
                reason: e.to_string(),
            })?;

        // Write the current PID into the file so operators can identify the holder.
        use std::io::Write;
        let mut f = &file;
        let _ = writeln!(f, "{}", std::process::id());

        // Attempt non-blocking exclusive flock
        if !try_exclusive_lock(&file) {
            return Err(LockError::AlreadyLocked);
        }

        Ok(Self {
            path: lock_path,
            _file: file,
        })
    }

    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // The lock is released when `_file` is dropped (fd closed).
        // Optionally remove the PID from the file to indicate clean shutdown.
        let _ = std::fs::write(&self.path, "");
    }
}

// ── Platform-specific flock ───────────────────────────────────────────────────

#[cfg(unix)]
fn try_exclusive_lock(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // LOCK_EX | LOCK_NB
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    result == 0
}

#[cfg(windows)]
fn try_exclusive_lock(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let handle = file.as_raw_handle() as HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    result != 0
}

#[cfg(not(any(unix, windows)))]
fn try_exclusive_lock(_file: &File) -> bool {
    // On unsupported platforms, optimistically allow the lock.
    // This is safe for development but not production.
    true
}
