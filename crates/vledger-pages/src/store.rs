//! Page store — manages reading, writing, and encrypting sealed pages.
//!
//! Encrypted tables write to `.epages` files with record size = page_size + 32.
//! Plaintext tables write to `.pages` files with record size = page_size.
//!
//! ## Sync modes
//!
//! `PageStore::write_page` no longer calls `sync_all()` directly.  Instead it
//! marks a `PageFlushState` dirty flag and returns immediately.  The caller is
//! responsible for either:
//!
//! - Calling `PageStore::sync()` explicitly (for `PerRecord`-equivalent
//!   durability), or
//! - Handing the `PageFlushState` to `spawn_page_commit_flusher()` which
//!   replicates the WAL group-commit pattern for page files.
//!
//! This mirrors the WAL's `GroupCommit` design and removes the dominant
//! blocking `sync_all()` call from the write-lock critical section, which
//! was the primary TPS bottleneck.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};
use vledger_crypto::{encrypt::{decrypt, encrypt, EncryptionKey}, merkle::merkle_root, Hash};

use crate::error::PageError;
use crate::page::Page;
use crate::DEFAULT_PAGE_SIZE;

const PAGE_EXT:      &str = "pages";
const EPAGE_EXT:     &str = "epages";
const GCM_OVERHEAD:  usize = 32; // nonce(12) + tag(16) + footer(4)

// ── PageFlushState ────────────────────────────────────────────────────────────

/// Shared dirty flag between `PageStore` and the background page flusher.
///
/// Set to `true` after any un-fsynced `write_page` call.  The background
/// flusher reads and clears this flag on each tick.
pub struct PageFlushState {
    pub dirty: AtomicBool,
}

impl PageFlushState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            dirty: AtomicBool::new(false),
        })
    }
}

impl Default for PageFlushState {
    fn default() -> Self {
        Self { dirty: AtomicBool::new(false) }
    }
}

// ── PageStore ─────────────────────────────────────────────────────────────────

pub struct PageStore {
    dir: PathBuf,
    pub page_size: usize,
    handles: HashMap<u32, File>,
    table_keys: HashMap<u32, EncryptionKey>,
    /// Shared dirty flag — set after every `write_page`, cleared by flusher.
    pub flush_state: Arc<PageFlushState>,
}

impl PageStore {
    pub fn open(dir: &Path) -> Result<Self, PageError> {
        Self::open_with_page_size(dir, DEFAULT_PAGE_SIZE)
    }

    pub fn open_with_page_size(dir: &Path, page_size: usize) -> Result<Self, PageError> {
        std::fs::create_dir_all(dir)?;
        info!(dir = %dir.display(), page_size, "PageStore opened");
        Ok(Self {
            dir: dir.to_path_buf(),
            page_size,
            handles: HashMap::new(),
            table_keys: HashMap::new(),
            flush_state: PageFlushState::new(),
        })
    }

    pub fn register_table_key(&mut self, table_id: u32, key: EncryptionKey) {
        info!(table_id, "Registered encryption key for table");
        self.table_keys.insert(table_id, key);
    }

    pub fn is_encrypted(&self, table_id: u32) -> bool {
        self.table_keys.contains_key(&table_id)
    }

    /// Write a sealed page to disk.
    ///
    /// **Does NOT call `sync_all()`.**  The write is buffered in the OS page
    /// cache and durability is delegated to the background page flusher (group
    /// commit) or an explicit `PageStore::sync()` call.  This removes the
    /// dominant blocking I/O operation from the write-lock critical section.
    pub fn write_page(&mut self, page: &Page) -> Result<(), PageError> {
        assert!(page.sealed, "only sealed pages may be written to disk");
        let table_id = page.header.table_id;
        let page_id  = page.header.page_id;

        if let Some(key) = self.table_keys.get(&table_id) {
            let record_size = self.page_size + GCM_OVERHEAD;
            let offset      = page_id * record_size as u64;
            let aad         = Self::make_aad(table_id, page_id);
            let mut ciphertext = encrypt(key, page.as_bytes(), Some(&aad))
                .map_err(PageError::Crypto)?;
            // Append 4-byte plaintext-length footer
            ciphertext.extend_from_slice(&(self.page_size as u32).to_le_bytes());
            debug_assert_eq!(ciphertext.len(), record_size);
            let file = self.efile_for_table(table_id)?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&ciphertext)?;
            // No sync_all() — background flusher handles durability.
            debug!(page_id, table_id, "Encrypted page written (buffered)");
        } else {
            let offset = page_id * self.page_size as u64;
            let file   = self.file_for_table(table_id)?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(page.as_bytes())?;
            // No sync_all() — background flusher handles durability.
            debug!(page_id, table_id, "Plaintext page written (buffered)");
        }

        // Mark dirty so the background flusher knows there is work to do.
        self.flush_state.dirty.store(true, Ordering::Release);
        Ok(())
    }

    /// Force an immediate `sync_all()` on every open table file.
    ///
    /// Called by:
    /// - The background page flusher on each tick.
    /// - `LedgerStore::checkpoint()` for explicit durability checkpoints.
    pub fn sync(&mut self) -> Result<(), PageError> {
        if !self.flush_state.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        for file in self.handles.values() {
            file.sync_all()?;
        }
        self.flush_state.dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn read_page(&mut self, table_id: u32, page_id: u64) -> Result<Page, PageError> {
        if let Some(key) = self.table_keys.get(&table_id).cloned() {
            let record_size = self.page_size + GCM_OVERHEAD;
            let offset      = page_id * record_size as u64;
            let file        = self.efile_for_table(table_id)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut record = vec![0u8; record_size];
            file.read_exact(&mut record)?;
            // ciphertext = record[..record_size-4], footer = record[record_size-4..]
            let ct_len = record_size - 4; // nonce+encrypted_page+tag = page_size+28
            let aad       = Self::make_aad(table_id, page_id);
            let plaintext = decrypt(&key, &record[..ct_len], Some(&aad))
                .map_err(PageError::Crypto)?;
            debug!(page_id, table_id, "Encrypted page decrypted");
            Page::from_bytes(plaintext)
        } else {
            let ps     = self.page_size;
            let offset = page_id * ps as u64;
            let file   = self.file_for_table(table_id)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; ps];
            file.read_exact(&mut buf)?;
            debug!(page_id, table_id, "Plaintext page read");
            Page::from_bytes(buf)
        }
    }

    pub fn table_merkle_root(&mut self, table_id: u32) -> Result<Hash, PageError> {
        let encrypted   = self.table_keys.contains_key(&table_id);
        let record_size = if encrypted { self.page_size + GCM_OVERHEAD } else { self.page_size };

        let file_len = if encrypted {
            self.efile_for_table(table_id)?.metadata()?.len()
        } else {
            self.file_for_table(table_id)?.metadata()?.len()
        };
        let page_count = file_len / record_size as u64;
        if page_count == 0 { return Ok(vledger_crypto::ZERO_HASH); }

        let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(page_count as usize);
        for pid in 0..page_count {
            let offset = pid * record_size as u64;
            let file = if encrypted {
                self.efile_for_table(table_id)?
            } else {
                self.file_for_table(table_id)?
            };
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; record_size];
            file.read_exact(&mut buf)?;
            hashes.push(buf);
        }
        Ok(merkle_root(&hashes))
    }

    pub fn page_count(&mut self, table_id: u32) -> Result<u64, PageError> {
        let encrypted   = self.table_keys.contains_key(&table_id);
        let record_size = if encrypted { self.page_size + GCM_OVERHEAD } else { self.page_size } as u64;
        let file_len = if encrypted {
            self.efile_for_table(table_id)?.metadata()?.len()
        } else {
            self.file_for_table(table_id)?.metadata()?.len()
        };
        Ok(file_len / record_size)
    }

    fn make_aad(table_id: u32, page_id: u64) -> [u8; 12] {
        let mut a = [0u8; 12];
        a[..4].copy_from_slice(&table_id.to_le_bytes());
        a[4..].copy_from_slice(&page_id.to_le_bytes());
        a
    }

    fn file_for_table(&mut self, table_id: u32) -> Result<&mut File, PageError> {
        if !self.handles.contains_key(&table_id) {
            let path = self.dir.join(format!("{:08x}.{}", table_id, PAGE_EXT));
            let f = OpenOptions::new().create(true).read(true).write(true).open(&path)?;
            self.handles.insert(table_id, f);
        }
        Ok(self.handles.get_mut(&table_id).unwrap())
    }

    fn efile_for_table(&mut self, table_id: u32) -> Result<&mut File, PageError> {
        let key = table_id.wrapping_add(0x8000_0000);
        if !self.handles.contains_key(&key) {
            let path = self.dir.join(format!("{:08x}.{}", table_id, EPAGE_EXT));
            let f = OpenOptions::new().create(true).read(true).write(true).open(&path)?;
            self.handles.insert(key, f);
        }
        Ok(self.handles.get_mut(&key).unwrap())
    }
}

// ── Background page flusher ───────────────────────────────────────────────────

/// Spawn a background task that periodically fsyncs page files.
///
/// Mirrors `spawn_group_commit_flusher` from the WAL.  Wakes every
/// `delay_ms` milliseconds and calls `sync_all()` on every open page file
/// when the dirty flag is set.
///
/// The `pages_dir` is re-scanned on each tick so that newly opened table
/// files are picked up automatically.
pub fn spawn_page_commit_flusher(
    pages_dir:   PathBuf,
    flush_state: Arc<PageFlushState>,
    delay_ms:    u64,
    shutdown:    tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        let interval = Duration::from_millis(delay_ms);
        info!(
            pages_dir = %pages_dir.display(),
            delay_ms,
            "Page group-commit flusher started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if !flush_state.dirty.load(Ordering::Acquire) {
                        continue;
                    }

                    let flushed = tokio::task::spawn_blocking({
                        let pages_dir   = pages_dir.clone();
                        let flush_state = Arc::clone(&flush_state);
                        move || -> std::io::Result<()> {
                            // Sync all .pages and .epages files in the directory.
                            let rd = std::fs::read_dir(&pages_dir)?;
                            for entry in rd.flatten() {
                                let path = entry.path();
                                if let Some(ext) = path.extension() {
                                    if ext == PAGE_EXT || ext == EPAGE_EXT {
                                        if let Ok(f) = OpenOptions::new()
                                            .write(true).open(&path)
                                        {
                                            let _ = f.sync_all();
                                        }
                                    }
                                }
                            }
                            flush_state.dirty.store(false, Ordering::Release);
                            Ok(())
                        }
                    }).await;

                    match flushed {
                        Ok(Ok(())) => debug!(delay_ms, "Page group-commit flush OK"),
                        Ok(Err(e)) => warn!("Page group-commit flush error: {e}"),
                        Err(e)     => warn!("Page group-commit flush task panicked: {e}"),
                    }
                }
                _ = shutdown.cancelled() => {
                    // Final flush on shutdown.
                    if flush_state.dirty.load(Ordering::Acquire) {
                        let pages_dir2 = pages_dir.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            if let Ok(rd) = std::fs::read_dir(&pages_dir2) {
                                for entry in rd.flatten() {
                                    let path = entry.path();
                                    if let Some(ext) = path.extension() {
                                        if ext == PAGE_EXT || ext == EPAGE_EXT {
                                            if let Ok(f) = OpenOptions::new()
                                                .write(true).open(&path)
                                            {
                                                let _ = f.sync_all();
                                            }
                                        }
                                    }
                                }
                            }
                        }).await;
                        info!("Page group-commit flusher: final flush on shutdown complete");
                    }
                    break;
                }
            }
        }

        info!("Page group-commit flusher exited");
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store(dir: &Path) -> PageStore { PageStore::open(dir).unwrap() }

    #[test]
    fn plaintext_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        let mut page = Page::new(0, 1);
        page.write_slot(b"hello ledger").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        // Explicitly sync before reading back to ensure data is on disk.
        store.sync().unwrap();
        assert_eq!(store.read_page(1, 0).unwrap().read_slot(0).unwrap(), b"hello ledger");
    }

    #[test]
    fn encrypted_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        store.register_table_key(99, EncryptionKey::generate());
        let mut page = Page::new(0, 99);
        page.write_slot(b"sensitive financial data").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        store.sync().unwrap();
        let loaded = store.read_page(99, 0).unwrap();
        assert_eq!(loaded.read_slot(0).unwrap(), b"sensitive financial data");
    }

    #[test]
    fn encrypted_page_not_readable_without_key() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        store.register_table_key(77, EncryptionKey::generate());
        let mut page = Page::new(0, 77);
        page.write_slot(b"secret").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        store.sync().unwrap();
        let mut store2 = make_store(dir.path());
        assert!(store2.read_page(77, 0).is_err());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        store.register_table_key(55, EncryptionKey::generate());
        let mut page = Page::new(0, 55);
        page.write_slot(b"private").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        store.sync().unwrap();
        let mut store2 = make_store(dir.path());
        store2.register_table_key(55, EncryptionKey::generate());
        assert!(store2.read_page(55, 0).is_err());
    }

    #[test]
    fn merkle_root_over_encrypted_pages() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        store.register_table_key(11, EncryptionKey::generate());
        for i in 0u64..3 {
            let mut page = Page::new(i, 11);
            page.write_slot(format!("row {i}").as_bytes()).unwrap();
            page.seal();
            store.write_page(&page).unwrap();
        }
        store.sync().unwrap();
        assert_ne!(store.table_merkle_root(11).unwrap(), vledger_crypto::ZERO_HASH);
    }

    #[test]
    fn dirty_flag_set_after_write_cleared_after_sync() {
        let dir = TempDir::new().unwrap();
        let mut store = make_store(dir.path());
        assert!(!store.flush_state.dirty.load(Ordering::Acquire));
        let mut page = Page::new(0, 1);
        page.write_slot(b"test").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        assert!(store.flush_state.dirty.load(Ordering::Acquire));
        store.sync().unwrap();
        assert!(!store.flush_state.dirty.load(Ordering::Acquire));
    }
}
