// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Persistent storage abstraction for `Craton Shield`.
//!
//! Provides a [`StorageProvider`] trait for key-value storage that can be
//! backed by RAM (testing), flash, EEPROM, or filesystem depending on the
//! target platform.  All implementations are fixed-size, heap-free, and
//! suitable for `#![no_std]` embedded use.
//!
//! Enable the `std` feature for the `FileStorageProvider` backend
//! (Linux/desktop targets).
//!
//! # Security notes
//!
//! Values are stored **unencrypted**.  Callers handling sensitive key material
//! must encrypt values before writing (see `vs-crypto`'s `CryptoProvider` for
//! AES-GCM).  The storage layer provides secure erasure (via `zeroize`) and,
//! on Unix, restrictive file permissions, but does **not** encrypt at rest.

use vs_types::VsError;
use zeroize::Zeroize;

#[cfg(feature = "std")]
mod file_storage;

#[cfg(feature = "std")]
pub use file_storage::FileStorageProvider;

// ---------------------------------------------------------------------------
// StorageProvider trait
// ---------------------------------------------------------------------------

/// Abstract key-value storage backend.
///
/// Keys and values are raw byte slices.  Implementations must be deterministic
/// and must not allocate on the heap (except those gated behind `std`).
pub trait StorageProvider {
    /// Read the value associated with `key` into `buf`.
    ///
    /// Returns the number of bytes written to `buf`.
    ///
    /// # Errors
    ///
    /// * [`VsError::NotFound`]     – key does not exist.
    /// * [`VsError::InvalidInput`] – buffer is too small or key exceeds
    ///   [`MAX_KEY_LEN`].
    fn read(&self, key: &[u8], buf: &mut [u8]) -> Result<usize, VsError>;

    /// Write `data` associated with `key`, overwriting any existing value.
    ///
    /// # Security
    ///
    /// Values are stored **unencrypted** by default. Callers handling
    /// sensitive material (keys, tokens, credentials) **must** either:
    /// - wrap this provider with `EncryptedStorageProvider` (feature
    ///   `encrypted`), or
    /// - encrypt values before writing using `CryptoProvider::aes_gcm_encrypt`.
    ///
    /// # Errors
    ///
    /// * [`VsError::InvalidInput`]      – key or value exceeds size limits.
    /// * [`VsError::ResourceExhausted`] – store is full.
    fn write(&mut self, key: &[u8], data: &[u8]) -> Result<(), VsError>;

    /// Delete the value associated with `key`.
    ///
    /// Implementations **must** securely erase the stored value so that
    /// deleted secrets do not persist in memory or on disk.
    /// Returns `Ok(())` even if the key did not exist.
    ///
    /// # Secure erase limitations
    ///
    /// RAM-backed implementations zero the entry via `zeroize`. File-backed
    /// implementations overwrite with zeros and fsync before unlinking.
    /// However, **neither approach guarantees erasure** on:
    /// - Copy-on-write filesystems (btrfs, ZFS) where old blocks survive.
    /// - SSDs with FTL wear-levelling that retains original pages.
    /// - Systems where `mlock` was not applied (data may have been paged
    ///   to swap).
    ///
    /// For stronger guarantees, use full-disk encryption (dm-crypt/LUKS).
    fn delete(&mut self, key: &[u8]) -> Result<(), VsError>;

    /// Check whether a key exists without reading its value.
    fn contains(&self, key: &[u8]) -> bool;

    /// Iterate over all stored keys.
    ///
    /// Calls `f` for each active key.  Return `false` from `f` to stop
    /// iteration early.
    fn for_each_key(&self, f: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), VsError>;

    /// Securely erase **all** entries.
    fn clear_all(&mut self) -> Result<(), VsError>;
}

// ---------------------------------------------------------------------------
// RamStorageProvider
// ---------------------------------------------------------------------------

/// Maximum number of key-value entries in [`RamStorageProvider`].
#[cfg(feature = "capacity-xl")]
const RAM_MAX_ENTRIES: usize = 256;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const RAM_MAX_ENTRIES: usize = 128;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const RAM_MAX_ENTRIES: usize = 64;

/// Maximum key length in bytes.
pub const MAX_KEY_LEN: usize = 32;

/// Maximum value length in bytes.
pub const MAX_VALUE_LEN: usize = 128;

/// A single key-value entry.
#[derive(Clone, Copy)]
struct StorageEntry {
    key: [u8; MAX_KEY_LEN],
    key_len: u8,
    value: [u8; MAX_VALUE_LEN],
    value_len: u8,
    active: bool,
}

impl StorageEntry {
    const EMPTY: Self = Self {
        key: [0u8; MAX_KEY_LEN],
        key_len: 0,
        value: [0u8; MAX_VALUE_LEN],
        value_len: 0,
        active: false,
    };

    fn key_matches(&self, key: &[u8]) -> bool {
        self.active && self.key_len as usize == key.len() && self.key[..key.len()] == *key
    }

    /// Securely zero all fields using volatile writes so the compiler cannot
    /// optimise the clearing away.
    fn secure_clear(&mut self) {
        self.key.zeroize();
        self.key_len.zeroize();
        self.value.zeroize();
        self.value_len.zeroize();
        self.active = false;
    }
}

/// In-memory key-value storage for testing and volatile contexts.
///
/// Stores up to `RAM_MAX_ENTRIES` entries with keys up to
/// [`MAX_KEY_LEN`] bytes and values up to [`MAX_VALUE_LEN`] bytes.
/// All state is lost on power cycle.
pub struct RamStorageProvider {
    entries: [StorageEntry; RAM_MAX_ENTRIES],
    count: usize,
}

impl RamStorageProvider {
    /// Create a new empty RAM storage provider.
    pub fn new() -> Self {
        Self {
            entries: [StorageEntry::EMPTY; RAM_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of active entries.
    pub fn entry_count(&self) -> usize {
        self.count
    }

    /// Return `(current_entries, max_entries)` for capacity monitoring.
    pub fn capacity(&self) -> (usize, usize) {
        (self.count, RAM_MAX_ENTRIES)
    }

    fn find_index(&self, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.key_matches(key))
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.active)
    }

    /// Recompute `count` from the entries array (debug-only sanity check).
    #[cfg(debug_assertions)]
    fn assert_count_consistent(&self) {
        let actual = self.entries.iter().filter(|e| e.active).count();
        debug_assert_eq!(
            self.count, actual,
            "RamStorageProvider::count desync: field={}, actual={}",
            self.count, actual
        );
    }
}

impl Default for RamStorageProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageProvider for RamStorageProvider {
    fn read(&self, key: &[u8], buf: &mut [u8]) -> Result<usize, VsError> {
        if key.len() > MAX_KEY_LEN {
            return Err(VsError::InvalidInput);
        }
        let idx = self.find_index(key).ok_or(VsError::NotFound)?;
        let entry = &self.entries[idx];
        let vlen = entry.value_len as usize;
        if buf.len() < vlen {
            return Err(VsError::InvalidInput);
        }
        buf[..vlen].copy_from_slice(&entry.value[..vlen]);
        Ok(vlen)
    }

    fn write(&mut self, key: &[u8], data: &[u8]) -> Result<(), VsError> {
        if key.len() > MAX_KEY_LEN || data.len() > MAX_VALUE_LEN {
            return Err(VsError::InvalidInput);
        }

        // Update existing entry if key exists.
        if let Some(idx) = self.find_index(key) {
            let entry = &mut self.entries[idx];
            // Securely clear old value before overwriting.
            entry.value.zeroize();
            entry.value[..data.len()].copy_from_slice(data);
            entry.value_len = data.len() as u8;
            return Ok(());
        }

        // Insert new entry.
        let idx = self.find_free_slot().ok_or(VsError::ResourceExhausted)?;
        let entry = &mut self.entries[idx];
        entry.key[..key.len()].copy_from_slice(key);
        entry.key_len = key.len() as u8;
        entry.value[..data.len()].copy_from_slice(data);
        entry.value_len = data.len() as u8;
        entry.active = true;
        self.count += 1;
        #[cfg(debug_assertions)]
        self.assert_count_consistent();
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), VsError> {
        if let Some(idx) = self.find_index(key) {
            self.entries[idx].secure_clear();
            self.count -= 1;
            #[cfg(debug_assertions)]
            self.assert_count_consistent();
        }
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> bool {
        if key.len() > MAX_KEY_LEN {
            return false;
        }
        self.find_index(key).is_some()
    }

    fn for_each_key(&self, f: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), VsError> {
        for entry in &self.entries {
            if entry.active {
                let key = &entry.key[..entry.key_len as usize];
                if !f(key) {
                    break;
                }
            }
        }
        Ok(())
    }

    fn clear_all(&mut self) -> Result<(), VsError> {
        for entry in self.entries.iter_mut() {
            if entry.active {
                entry.secure_clear();
            }
        }
        self.count = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Monotonic counter (backed by StorageProvider)
// ---------------------------------------------------------------------------

/// Key prefix for monotonic counter storage.
const COUNTER_KEY_PREFIX: &[u8] = b"ctr:";

/// A monotonic counter that can only increase, backed by a
/// [`StorageProvider`] for persistence across power cycles.
///
/// Useful for rollback protection (OTA version counters, nonce counters).
pub struct MonotonicCounter<'a, S: StorageProvider> {
    storage: &'a mut S,
    name: [u8; MAX_KEY_LEN],
    name_len: usize,
    cached_value: u64,
}

impl<'a, S: StorageProvider> MonotonicCounter<'a, S> {
    /// Create or load a monotonic counter with the given name.
    ///
    /// If the counter already exists in storage, its current value is loaded.
    /// Otherwise it starts at 0.
    pub fn new(storage: &'a mut S, name: &[u8]) -> Result<Self, VsError> {
        let prefix_len = COUNTER_KEY_PREFIX.len();
        let total_len = prefix_len + name.len();
        if total_len > MAX_KEY_LEN {
            return Err(VsError::InvalidInput);
        }

        let mut key = [0u8; MAX_KEY_LEN];
        key[..prefix_len].copy_from_slice(COUNTER_KEY_PREFIX);
        key[prefix_len..total_len].copy_from_slice(name);

        let cached_value = {
            let mut buf = [0u8; 8];
            match storage.read(&key[..total_len], &mut buf) {
                Ok(8) => u64::from_le_bytes(buf),
                Ok(_) => return Err(VsError::IntegrityFailure),
                Err(VsError::NotFound) => 0,
                Err(e) => return Err(e),
            }
        };

        Ok(Self {
            storage,
            name: key,
            name_len: total_len,
            cached_value,
        })
    }

    /// Return the current counter value.
    pub fn value(&self) -> u64 {
        self.cached_value
    }

    /// Increment the counter by 1 and persist.
    ///
    /// # Errors
    ///
    /// * [`VsError::ResourceExhausted`] – counter is at `u64::MAX`.
    pub fn increment(&mut self) -> Result<u64, VsError> {
        let new_val = self
            .cached_value
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.advance_to(new_val)
    }

    /// Advance the counter to `new_value` if it is >= the current value.
    /// Returns the new value on success.
    ///
    /// # Errors
    ///
    /// * [`VsError::PolicyViolation`] – `new_value` would decrease the
    ///   counter (rollback attempt).
    pub fn advance_to(&mut self, new_value: u64) -> Result<u64, VsError> {
        if new_value < self.cached_value {
            return Err(VsError::PolicyViolation);
        }
        // Write to persistent storage FIRST. If the write fails, the
        // in-memory cache remains at the old value, preserving the
        // monotonicity invariant across power cycles.
        let bytes = new_value.to_le_bytes();
        self.storage.write(&self.name[..self.name_len], &bytes)?;
        self.cached_value = new_value;
        Ok(new_value)
    }
}

// ---------------------------------------------------------------------------
// EncryptedStorageProvider (V5 fix)
// ---------------------------------------------------------------------------

/// AES-GCM nonce size.
#[cfg(any(feature = "encrypted", test))]
const ENC_NONCE_LEN: usize = 12;
/// AES-GCM tag size.
#[cfg(any(feature = "encrypted", test))]
const ENC_TAG_LEN: usize = 16;

/// Storage provider wrapper that encrypts all values before writing and
/// decrypts them on read, using AES-GCM via a [`CryptoProvider`].
///
/// This prevents accidental storage of plaintext secrets. The encryption
/// key is identified by `key_id` and must be provisioned in the crypto
/// provider before use.
///
/// # Overhead
///
/// Each stored value is prefixed with a 12-byte nonce and suffixed with a
/// 16-byte authentication tag, consuming 28 bytes of the value capacity.
/// The maximum plaintext that can be stored is `MAX_VALUE_LEN - 28` bytes.
///
/// # AAD
///
/// The storage key is used as additional authenticated data (AAD), binding
/// each ciphertext to its storage key and preventing ciphertext relocation
/// attacks.
///
/// # Feature gate
///
/// Requires the `encrypted` feature (which pulls in `vs-crypto`).
#[cfg(any(feature = "encrypted", test))]
pub struct EncryptedStorageProvider<'a, S: StorageProvider, C: vs_crypto::CryptoProvider> {
    inner: S,
    crypto: &'a C,
    key_id: vs_crypto::KeyId,
    nonce_counter: u64,
}

#[cfg(any(feature = "encrypted", test))]
impl<'a, S: StorageProvider, C: vs_crypto::CryptoProvider> EncryptedStorageProvider<'a, S, C> {
    /// Create a new encrypted storage provider.
    ///
    /// # Nonce Safety
    ///
    /// `nonce_start` **MUST** be greater than any nonce counter value
    /// previously used with this key. After each write, persist
    /// [`nonce_counter()`](Self::nonce_counter) to non-volatile storage
    /// and pass the persisted value (or higher) on next construction.
    /// Nonce reuse with AES-GCM destroys both confidentiality and
    /// authenticity.
    ///
    /// # Safety note
    ///
    /// A `nonce_start` of 0 is valid but may indicate the caller forgot to
    /// restore a persisted counter. In production, always pass the
    /// last-known counter value (or higher) to prevent nonce reuse.
    pub fn new(inner: S, crypto: &'a C, key_id: vs_crypto::KeyId, nonce_start: u64) -> Self {
        Self {
            inner,
            crypto,
            key_id,
            nonce_counter: nonce_start,
        }
    }

    /// Return the current nonce counter for persistence.
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter
    }

    /// Return a reference to the inner (unencrypted) storage provider.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the inner storage provider.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn next_nonce(&mut self) -> Result<[u8; ENC_NONCE_LEN], VsError> {
        let c = self
            .nonce_counter
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.nonce_counter = c;
        let mut nonce = [0u8; ENC_NONCE_LEN];
        // V9 fix: use a non-zero domain-separation prefix in bytes 0..4
        // to avoid triggering degenerate-prefix nonce validation. The
        // 8-byte big-endian counter is placed in bytes 4..12.
        nonce[..4].copy_from_slice(b"stor");
        let c_bytes = c.to_be_bytes();
        nonce[4..].copy_from_slice(&c_bytes);
        Ok(nonce)
    }
}

#[cfg(any(feature = "encrypted", test))]
impl<'a, S: StorageProvider, C: vs_crypto::CryptoProvider> StorageProvider
    for EncryptedStorageProvider<'a, S, C>
{
    fn read(&self, key: &[u8], buf: &mut [u8]) -> Result<usize, VsError> {
        // Read the encrypted blob: nonce(12) || ciphertext(N) || tag(16)
        let mut encrypted = [0u8; MAX_VALUE_LEN];
        let enc_len = self.inner.read(key, &mut encrypted)?;
        if enc_len < ENC_NONCE_LEN + ENC_TAG_LEN {
            return Err(VsError::IntegrityFailure);
        }

        let nonce: &[u8; ENC_NONCE_LEN] = encrypted[..ENC_NONCE_LEN]
            .try_into()
            .map_err(|_| VsError::IntegrityFailure)?;
        let ct_len = enc_len - ENC_NONCE_LEN - ENC_TAG_LEN;
        let ciphertext = &encrypted[ENC_NONCE_LEN..ENC_NONCE_LEN + ct_len];
        let tag: &[u8; ENC_TAG_LEN] = encrypted[ENC_NONCE_LEN + ct_len..enc_len]
            .try_into()
            .map_err(|_| VsError::IntegrityFailure)?;

        if buf.len() < ct_len {
            return Err(VsError::InvalidInput);
        }

        self.crypto.aes_gcm_decrypt(
            self.key_id,
            nonce,
            ciphertext,
            key,
            tag,
            &mut buf[..ct_len],
        )?;
        Ok(ct_len)
    }

    /// Encrypt `data` under the configured key and persist `nonce || ct || tag`
    /// to the inner storage.
    ///
    /// # Nonce counter advances on failure (IMPORTANT)
    ///
    /// `next_nonce()` is called *before* the encryption and inner-storage
    /// write are attempted, and the in-memory nonce counter is updated
    /// before either of those operations can fail. **Therefore, if the
    /// underlying `aes_gcm_encrypt` call or the inner `write` returns an
    /// error, the nonce counter has still advanced.** The failed nonce is
    /// permanently burned — it will never be reused, even after process
    /// restart, *provided* the caller persists `nonce_counter()` after
    /// every write attempt (success or failure).
    ///
    /// This is deliberate: reusing an AES-GCM nonce under the same key
    /// destroys both confidentiality (XOR of two plaintexts is recoverable
    /// from the two ciphertexts) and authenticity (the GHASH key can be
    /// extracted, allowing arbitrary forgery). Burning nonces on failure
    /// is the IND-CCA1 safety choice; the cost is at most `2^64`
    /// usable writes per key, which is unreachable in practice.
    ///
    /// Callers that need to detect this case can compare
    /// `nonce_counter()` before and after the call.
    fn write(&mut self, key: &[u8], data: &[u8]) -> Result<(), VsError> {
        let overhead = ENC_NONCE_LEN + ENC_TAG_LEN;
        if data.len() + overhead > MAX_VALUE_LEN {
            return Err(VsError::InvalidInput);
        }

        let nonce = self.next_nonce()?;
        let mut ct = [0u8; MAX_VALUE_LEN];
        let mut tag = [0u8; ENC_TAG_LEN];
        self.crypto.aes_gcm_encrypt(
            self.key_id,
            &nonce,
            data,
            key,
            &mut ct[..data.len()],
            &mut tag,
        )?;

        // Pack: nonce || ciphertext || tag
        let total_len = overhead + data.len();
        let mut blob = [0u8; MAX_VALUE_LEN];
        blob[..ENC_NONCE_LEN].copy_from_slice(&nonce);
        blob[ENC_NONCE_LEN..ENC_NONCE_LEN + data.len()].copy_from_slice(&ct[..data.len()]);
        blob[ENC_NONCE_LEN + data.len()..total_len].copy_from_slice(&tag);

        self.inner.write(key, &blob[..total_len])
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), VsError> {
        self.inner.delete(key)
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.inner.contains(key)
    }

    fn for_each_key(&self, f: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), VsError> {
        self.inner.for_each_key(f)
    }

    fn clear_all(&mut self) -> Result<(), VsError> {
        self.inner.clear_all()
    }
}

#[cfg(any(feature = "encrypted", test))]
impl<'a, S: StorageProvider, C: vs_crypto::CryptoProvider> EncryptedStorageProvider<'a, S, C> {
    /// Write multiple key-value pairs in a batch.
    ///
    /// Each pair gets its own nonce and is encrypted independently, but the
    /// method avoids repeated function-call overhead and allows the caller to
    /// persist the nonce counter once after the entire batch rather than after
    /// each individual write.
    ///
    /// Returns the number of pairs successfully written. If any write fails,
    /// the already-written pairs remain and the error is returned along with
    /// the count of successful writes.
    ///
    /// # Atomicity (or lack thereof)
    ///
    /// **Best-effort batching — not transactional.** On a mid-batch failure
    /// callers receive `Err((n, e))` where `n` is the number of pairs that
    /// were successfully persisted before the error, but the partial state
    /// remains on disk and the nonce counter has advanced past every
    /// attempted index (including the failed one — see
    /// [`EncryptedStorageProvider::write`] for the rationale).
    ///
    /// To roll back to the pre-batch state, the caller must explicitly call
    /// [`delete`](StorageProvider::delete) for each of the `n` preceding
    /// successes. There is no automatic rollback because the underlying
    /// [`StorageProvider`] has no journal to consult.
    ///
    /// To detect mid-batch crashes (where the process exits between writes),
    /// the caller should persist `nonce_counter()` after every successful
    /// batch and treat any gap on restart as an aborted batch whose tail
    /// must be re-applied or rolled back at the application layer.
    pub fn write_batch(&mut self, pairs: &[(&[u8], &[u8])]) -> Result<usize, (usize, VsError)> {
        for (i, &(key, data)) in pairs.iter().enumerate() {
            if let Err(e) = StorageProvider::write(self, key, data) {
                return Err((i, e));
            }
        }
        Ok(pairs.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // -- RamStorageProvider tests --

    #[test]
    fn ram_write_and_read() {
        let mut store = RamStorageProvider::new();
        store.write(b"key1", b"hello").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"key1", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[test]
    fn ram_overwrite_existing_key() {
        let mut store = RamStorageProvider::new();
        store.write(b"k", b"first").unwrap();
        store.write(b"k", b"second").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"k", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"second");
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn ram_read_nonexistent_key_returns_not_found() {
        let store = RamStorageProvider::new();
        let mut buf = [0u8; 128];
        let result = store.read(b"nope", &mut buf);
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn ram_delete_key() {
        let mut store = RamStorageProvider::new();
        store.write(b"key", b"val").unwrap();
        assert!(store.contains(b"key"));
        store.delete(b"key").unwrap();
        assert!(!store.contains(b"key"));
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn ram_delete_nonexistent_key_is_ok() {
        let mut store = RamStorageProvider::new();
        let result = store.delete(b"nope");
        assert!(result.is_ok());
    }

    #[test]
    fn ram_contains() {
        let mut store = RamStorageProvider::new();
        assert!(!store.contains(b"x"));
        store.write(b"x", b"y").unwrap();
        assert!(store.contains(b"x"));
    }

    #[test]
    fn ram_capacity() {
        let store = RamStorageProvider::new();
        let (used, max) = store.capacity();
        assert_eq!(used, 0);
        assert_eq!(max, RAM_MAX_ENTRIES);
    }

    #[test]
    fn ram_key_too_long_returns_invalid_input() {
        let mut store = RamStorageProvider::new();
        let long_key = [0xAA; MAX_KEY_LEN + 1];
        let result = store.write(&long_key, b"val");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn ram_value_too_long_returns_invalid_input() {
        let mut store = RamStorageProvider::new();
        let long_val = [0xBB; MAX_VALUE_LEN + 1];
        let result = store.write(b"k", &long_val);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn ram_buffer_too_small_for_read_returns_invalid_input() {
        let mut store = RamStorageProvider::new();
        store.write(b"k", b"longvalue").unwrap();
        let mut tiny_buf = [0u8; 2];
        let result = store.read(b"k", &mut tiny_buf);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn ram_read_oversized_key_returns_invalid_input() {
        let store = RamStorageProvider::new();
        let big_key = [0xCC; MAX_KEY_LEN + 1];
        let mut buf = [0u8; 128];
        assert_eq!(store.read(&big_key, &mut buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn ram_contains_oversized_key_returns_false() {
        let store = RamStorageProvider::new();
        let big_key = [0xCC; MAX_KEY_LEN + 1];
        assert!(!store.contains(&big_key));
    }

    #[test]
    fn ram_multiple_keys() {
        let mut store = RamStorageProvider::new();
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        store.write(b"c", b"3").unwrap();
        assert_eq!(store.entry_count(), 3);

        let mut buf = [0u8; 128];
        let len = store.read(b"b", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"2");
    }

    #[test]
    fn ram_full_returns_resource_exhausted() {
        let mut store = RamStorageProvider::new();
        for i in 0..RAM_MAX_ENTRIES {
            let key = [i as u8];
            store.write(&key, b"v").unwrap();
        }
        assert_eq!(store.entry_count(), RAM_MAX_ENTRIES);
        let result = store.write(b"\xFF\xFF", b"overflow");
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn ram_delete_then_reuse_slot() {
        let mut store = RamStorageProvider::new();
        store.write(b"old", b"data").unwrap();
        store.delete(b"old").unwrap();
        store.write(b"new", b"fresh").unwrap();
        assert_eq!(store.entry_count(), 1);
        assert!(store.contains(b"new"));
        assert!(!store.contains(b"old"));
    }

    #[test]
    fn ram_empty_key_and_value() {
        let mut store = RamStorageProvider::new();
        store.write(b"", b"").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"", &mut buf).unwrap();
        assert_eq!(len, 0);
    }

    #[test]
    fn ram_default_trait() {
        let store = RamStorageProvider::default();
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn ram_for_each_key() {
        let mut store = RamStorageProvider::new();
        store.write(b"alpha", b"1").unwrap();
        store.write(b"beta", b"2").unwrap();
        store.write(b"gamma", b"3").unwrap();

        let mut keys: Vec<Vec<u8>> = Vec::new();
        store
            .for_each_key(&mut |k| {
                keys.push(k.to_vec());
                true
            })
            .unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&b"alpha".to_vec()));
        assert!(keys.contains(&b"beta".to_vec()));
        assert!(keys.contains(&b"gamma".to_vec()));
    }

    #[test]
    fn ram_for_each_key_early_stop() {
        let mut store = RamStorageProvider::new();
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        store.write(b"c", b"3").unwrap();

        let mut count = 0usize;
        store
            .for_each_key(&mut |_| {
                count += 1;
                false // stop after first
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn ram_clear_all() {
        let mut store = RamStorageProvider::new();
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        store.clear_all().unwrap();
        assert_eq!(store.entry_count(), 0);
        assert!(!store.contains(b"a"));
        assert!(!store.contains(b"b"));
    }

    #[test]
    fn ram_clear_all_empty_store() {
        let mut store = RamStorageProvider::new();
        store.clear_all().unwrap();
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn ram_overwrite_clears_old_value_bytes() {
        let mut store = RamStorageProvider::new();
        store.write(b"k", b"longvalue123").unwrap();
        store.write(b"k", b"short").unwrap();
        // Read back – should only get the new shorter value.
        let mut buf = [0u8; 128];
        let len = store.read(b"k", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"short");
    }

    // -- MonotonicCounter tests --

    #[test]
    fn counter_starts_at_zero() {
        let mut store = RamStorageProvider::new();
        let ctr = MonotonicCounter::new(&mut store, b"test").unwrap();
        assert_eq!(ctr.value(), 0);
    }

    #[test]
    fn counter_increment() {
        let mut store = RamStorageProvider::new();
        let mut ctr = MonotonicCounter::new(&mut store, b"test").unwrap();
        let v = ctr.increment().unwrap();
        assert_eq!(v, 1);
        assert_eq!(ctr.value(), 1);
        let v = ctr.increment().unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn counter_advance_to() {
        let mut store = RamStorageProvider::new();
        let mut ctr = MonotonicCounter::new(&mut store, b"ver").unwrap();
        ctr.advance_to(10).unwrap();
        assert_eq!(ctr.value(), 10);
        ctr.advance_to(20).unwrap();
        assert_eq!(ctr.value(), 20);
    }

    #[test]
    fn counter_advance_to_lower_value_fails() {
        let mut store = RamStorageProvider::new();
        let mut ctr = MonotonicCounter::new(&mut store, b"ver").unwrap();
        ctr.advance_to(10).unwrap();
        let result = ctr.advance_to(5);
        assert_eq!(result, Err(VsError::PolicyViolation));
        assert_eq!(ctr.value(), 10);
    }

    #[test]
    fn counter_advance_to_same_value_is_ok() {
        let mut store = RamStorageProvider::new();
        let mut ctr = MonotonicCounter::new(&mut store, b"ver").unwrap();
        ctr.advance_to(10).unwrap();
        let result = ctr.advance_to(10);
        assert!(result.is_ok());
    }

    #[test]
    fn counter_persists_in_storage() {
        let mut store = RamStorageProvider::new();
        {
            let mut ctr = MonotonicCounter::new(&mut store, b"fw").unwrap();
            ctr.advance_to(42).unwrap();
        }
        // Re-open the counter from the same storage.
        let ctr2 = MonotonicCounter::new(&mut store, b"fw").unwrap();
        assert_eq!(ctr2.value(), 42);
    }

    #[test]
    fn counter_name_too_long_returns_error() {
        let mut store = RamStorageProvider::new();
        let long_name = [0xAA; MAX_KEY_LEN]; // prefix + name > MAX_KEY_LEN
        let result = MonotonicCounter::new(&mut store, &long_name);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_counters_independent() {
        let mut store = RamStorageProvider::new();
        {
            let mut c1 = MonotonicCounter::new(&mut store, b"a").unwrap();
            c1.advance_to(10).unwrap();
        }
        {
            let mut c2 = MonotonicCounter::new(&mut store, b"b").unwrap();
            c2.advance_to(99).unwrap();
        }
        // Read them back sequentially to avoid double borrow.
        {
            let c1 = MonotonicCounter::new(&mut store, b"a").unwrap();
            assert_eq!(c1.value(), 10);
        }
        {
            let c2 = MonotonicCounter::new(&mut store, b"b").unwrap();
            assert_eq!(c2.value(), 99);
        }
    }

    #[test]
    fn counter_overflow_returns_resource_exhausted() {
        let mut store = RamStorageProvider::new();
        let mut ctr = MonotonicCounter::new(&mut store, b"max").unwrap();
        ctr.advance_to(u64::MAX).unwrap();
        let result = ctr.increment();
        assert_eq!(result, Err(VsError::ResourceExhausted));
        assert_eq!(ctr.value(), u64::MAX);
    }

    // -- EncryptedStorageProvider tests --

    mod encrypted {
        use super::*;
        use alloc::vec;
        use vs_crypto::{KeyId, SoftwareCryptoProvider};

        fn setup() -> (SoftwareCryptoProvider, RamStorageProvider) {
            let mut crypto = SoftwareCryptoProvider::default();
            crypto.set_key(KeyId(0), &[0x42u8; 16]).unwrap();
            (crypto, RamStorageProvider::new())
        }

        #[test]
        fn encrypted_write_read_roundtrip() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            enc.write(b"secret-key", b"my-secret-value").unwrap();

            let mut buf = [0u8; 128];
            let len = enc.read(b"secret-key", &mut buf).unwrap();
            assert_eq!(&buf[..len], b"my-secret-value");
        }

        #[test]
        fn encrypted_data_is_not_plaintext() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            enc.write(b"k", b"sensitive-data").unwrap();

            // Read the raw encrypted blob from the inner store
            let mut raw = [0u8; 128];
            let raw_len = enc.inner().read(b"k", &mut raw).unwrap();
            // The raw data should NOT contain the plaintext
            let plaintext = b"sensitive-data";
            for window in raw[..raw_len].windows(plaintext.len()) {
                assert_ne!(window, plaintext, "plaintext found in encrypted storage!");
            }
        }

        #[test]
        fn encrypted_different_keys_different_ciphertext() {
            let mut crypto = SoftwareCryptoProvider::default();
            crypto.set_key(KeyId(0), &[0x11u8; 16]).unwrap();
            crypto.set_key(KeyId(1), &[0x22u8; 16]).unwrap();

            let store0 = RamStorageProvider::new();
            let mut enc0 = EncryptedStorageProvider::new(store0, &crypto, KeyId(0), 0);
            enc0.write(b"k", b"same-data").unwrap();

            let store1 = RamStorageProvider::new();
            // V9: use a different nonce_start to avoid nonce reuse detection
            // in the shared crypto provider's integrated NonceTracker.
            let mut enc1 = EncryptedStorageProvider::new(store1, &crypto, KeyId(1), 1000);
            enc1.write(b"k", b"same-data").unwrap();

            let mut raw0 = [0u8; 128];
            let len0 = enc0.inner().read(b"k", &mut raw0).unwrap();
            let mut raw1 = [0u8; 128];
            let len1 = enc1.inner().read(b"k", &mut raw1).unwrap();
            assert_ne!(&raw0[..len0], &raw1[..len1]);
        }

        #[test]
        fn encrypted_tampered_data_rejected() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            enc.write(b"k", b"hello").unwrap();

            // Tamper with the inner storage
            let mut raw = [0u8; 128];
            let raw_len = enc.inner().read(b"k", &mut raw).unwrap();
            raw[15] ^= 0xFF; // flip a byte in the ciphertext area
            enc.inner_mut().write(b"k", &raw[..raw_len]).unwrap();

            let mut buf = [0u8; 128];
            let result = enc.read(b"k", &mut buf);
            assert!(result.is_err(), "tampered data should fail decryption");
        }

        #[test]
        fn encrypted_delete_and_contains() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            enc.write(b"k", b"val").unwrap();
            assert!(enc.contains(b"k"));
            enc.delete(b"k").unwrap();
            assert!(!enc.contains(b"k"));
        }

        #[test]
        fn encrypted_clear_all() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            enc.write(b"a", b"1").unwrap();
            enc.write(b"b", b"2").unwrap();
            enc.clear_all().unwrap();
            assert!(!enc.contains(b"a"));
            assert!(!enc.contains(b"b"));
        }

        #[test]
        fn encrypted_oversize_value_rejected() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            // MAX_VALUE_LEN - 28 bytes overhead = max plaintext
            let max_pt = MAX_VALUE_LEN - 28;
            let too_big = vec![0xAA; max_pt + 1];
            assert_eq!(enc.write(b"k", &too_big), Err(VsError::InvalidInput));
        }

        #[test]
        fn encrypted_nonce_counter_increments() {
            let (crypto, store) = setup();
            let mut enc = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
            assert_eq!(enc.nonce_counter(), 0);
            enc.write(b"a", b"1").unwrap();
            assert_eq!(enc.nonce_counter(), 1);
            enc.write(b"b", b"2").unwrap();
            assert_eq!(enc.nonce_counter(), 2);
        }
    }
}
