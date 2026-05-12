// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Key manager — bounded key store with audit log and integrity checking.
//!
//! # API stability
//!
//! Pre-1.0 (workspace version 0.7.0); see ROADMAP for the 1.0 stability
//! commitment. The `KeyManager` type, its
//! `provision_key` / `rotate_key` / `revoke_key` / `generate_key` /
//! `verify_audit_integrity` methods, and the `KeyMetadata` / `AuditEntry`
//! types are tracked by the workspace `DEPRECATION.md` (if present) for
//! deprecation policy once 1.0 ships.

#[cfg(test)]
extern crate alloc;

use vs_crypto::{CryptoProvider, KeyId};
use vs_types::VsError;
use zeroize::Zeroize;

/// Maximum number of keys the manager can hold.
pub const MAX_KEYS: usize = 64;

/// Capacity of the audit ring buffer.
const AUDIT_CAPACITY: usize = 256;

/// Maximum key material length in bytes (256-bit keys).
const MAX_KEY_MATERIAL_LEN: usize = 32;

/// Cryptographic algorithm for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum KeyAlgorithm {
    /// AES-128 in Galois/Counter Mode (AEAD, 128-bit key).
    Aes128Gcm,
    /// AES-256 in Galois/Counter Mode (AEAD, 256-bit key).
    Aes256Gcm,
    /// HMAC with SHA-256 (256-bit key).
    HmacSha256,
    /// ECDSA over NIST P-256 (256-bit key).
    EcdsaP256,
    /// ECDH key agreement over NIST P-256 (256-bit key).
    EcdhP256,
}

impl KeyAlgorithm {
    /// Expected key material length in bytes for this algorithm.
    pub const fn expected_key_len(self) -> usize {
        match self {
            KeyAlgorithm::Aes128Gcm => 16,
            KeyAlgorithm::Aes256Gcm
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::EcdsaP256
            | KeyAlgorithm::EcdhP256 => 32,
        }
    }
}

/// Purpose that a key is authorized for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum KeyPurpose {
    /// In-vehicle bus message authentication (e.g., CAN/Ethernet MAC).
    BusAuthentication,
    /// Firmware image / boot chain signature verification.
    FirmwareVerification,
    /// UDS / diagnostic session authentication.
    DiagnosticSession,
    /// Telemetry payload encryption to backend.
    TelemetryEncryption,
    /// Over-the-air update package verification and decryption.
    OtaUpdate,
}

/// Metadata associated with a managed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Slot-bound key identifier. Must equal the slot index it occupies.
    pub key_id: KeyId,
    /// Cryptographic algorithm this key is authorized for.
    pub algorithm: KeyAlgorithm,
    /// Authorized usage class for this key.
    pub purpose: KeyPurpose,
    /// Provisioning timestamp (microseconds, monotonic-domain).
    pub created_at: u64,
    /// Optional expiry timestamp (microseconds). When `Some(t)` and
    /// `current_time >= t`, the key is treated as expired and zeroized
    /// by the next [`KeyManager::tick`].
    pub expires_at: Option<u64>,
    /// Number of times this key has been rotated. Bounded by
    /// [`KeyManager::set_max_rotation_count`] if configured.
    pub rotation_count: u32,
    /// Cumulative nonce usage across all rotations of this key.
    ///
    /// Tracks total nonce consumption to prevent nonce-space exhaustion
    /// across key rotations.  For AES-256-GCM with 96-bit nonces and a
    /// 4-byte counter, the safe limit is 2^32 nonces per key.  This
    /// counter persists across rotations so that a rotation cannot reset
    /// the nonce counter and silently re-enter exhausted nonce space.
    pub cumulative_nonce_count: u64,
}

/// State of a key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    Empty,
    Active,
    Revoked,
    Expired,
}

/// Internal entry in the key table.
struct KeyEntry {
    metadata: KeyMetadata,
    state: KeyState,
    material: [u8; MAX_KEY_MATERIAL_LEN],
    material_len: usize,
}

impl core::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("metadata", &self.metadata)
            .field("state", &self.state)
            .field("material", &"[REDACTED]")
            .field("material_len", &self.material_len)
            .finish()
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        self.material.zeroize();
        self.material_len = 0;
    }
}

impl Default for KeyEntry {
    fn default() -> Self {
        Self {
            metadata: KeyMetadata {
                key_id: KeyId(0),
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::BusAuthentication,
                created_at: 0,
                expires_at: None,
                rotation_count: 0,
                cumulative_nonce_count: 0,
            },
            state: KeyState::Empty,
            material: [0u8; MAX_KEY_MATERIAL_LEN],
            material_len: 0,
        }
    }
}

/// Type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// A key was inserted into an empty slot via `provision_key`.
    KeyProvisioned,
    /// An existing key's material was replaced via `rotate_key`.
    KeyRotated,
    /// A key was revoked (tombstoned) via `revoke_key`.
    KeyRevoked,
    /// A key was transitioned to `Expired` by `tick` after passing
    /// its `expires_at` timestamp.
    KeyExpired,
    /// A key was generated from the crypto provider's RNG via `generate_key`.
    KeyGenerated,
}

/// An entry in the audit ring buffer.
///
/// Each entry carries a `chain_hash`: SHA-256 over the previous entry's
/// `chain_hash` concatenated with this entry's serialized fields. The first
/// entry's predecessor hash is all-zero. Storing the chain hash per entry
/// allows O(1) post-wrap append (the rolling checksum becomes
/// `SHA-256(prev.chain_hash || new_entry_bytes)`) instead of the previous
/// O(AUDIT_CAPACITY) rebuild on every eviction.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    /// What kind of lifecycle event this entry records.
    pub event_type: AuditEventType,
    /// The key whose lifecycle changed.
    pub key_id: KeyId,
    /// Timestamp (microseconds) supplied by the caller at the time of the event.
    pub timestamp: u64,
    /// Monotonically increasing sequence number across all audit entries
    /// in this manager's lifetime (not reset by ring-buffer wrap).
    pub sequence: u64,
    /// SHA-256 chain hash captured at insertion time.
    pub chain_hash: [u8; 32],
}

/// Serialize an audit entry's identity fields into a fixed-size byte buffer
/// for hashing. **Excludes** `chain_hash` itself (the chain is hashed
/// separately as part of the chain step). Encodes position-dependent data
/// to prevent reorder attacks.
fn audit_entry_to_bytes(e: &AuditEntry) -> [u8; 25] {
    let mut buf = [0u8; 25];
    buf[0] = e.event_type as u8;
    buf[1..5].copy_from_slice(&e.key_id.0.to_le_bytes());
    buf[5..13].copy_from_slice(&e.timestamp.to_le_bytes());
    buf[13..21].copy_from_slice(&e.sequence.to_le_bytes());
    // Domain separator: position in ring buffer derived from sequence
    let pos = (e.sequence as usize % AUDIT_CAPACITY) as u32;
    buf[21..25].copy_from_slice(&pos.to_le_bytes());
    buf
}

/// An audit entry whose chain hash has already been computed but which has
/// not yet been stored. Produced by `prepare_audit` (phase 1, fallible) and
/// consumed by `commit_audit` (phase 2, infallible). Splitting the append
/// this way lets a crypto failure abort a key operation *before* any slot
/// state is mutated, so a committed key operation can never be paired with
/// an unverifiable audit entry.
#[derive(Clone, Copy)]
struct PreparedAudit {
    entry: AuditEntry,
    chain_hash: [u8; 32],
    is_overflow: bool,
}

/// Iterator over audit entries in chronological order.
pub struct AuditIter<'a> {
    audit: &'a [Option<AuditEntry>; AUDIT_CAPACITY],
    total_count: u64,
    index: usize,
    yielded: usize,
}

impl<'a> Iterator for AuditIter<'a> {
    type Item = &'a AuditEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let populated = if self.total_count > AUDIT_CAPACITY as u64 {
            AUDIT_CAPACITY
        } else {
            self.total_count as usize
        };
        if self.yielded >= populated {
            return None;
        }
        // Start from the oldest entry in the ring
        let start = if self.total_count > AUDIT_CAPACITY as u64 {
            (self.total_count as usize) % AUDIT_CAPACITY
        } else {
            0
        };
        let pos = (start + self.index) % AUDIT_CAPACITY;
        self.index += 1;
        self.yielded += 1;
        self.audit[pos].as_ref()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let populated = if self.total_count > AUDIT_CAPACITY as u64 {
            AUDIT_CAPACITY
        } else {
            self.total_count as usize
        };
        let remaining = populated.saturating_sub(self.yielded);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for AuditIter<'a> {}

/// Callback type for audit overflow notifications.
///
/// Called when an audit entry is overwritten due to ring buffer wrap.
/// Implementations should log a security event or raise an alert.
/// The callback receives the number of entries overwritten so far.
pub type AuditOverflowCallback = fn(overflow_count: u64);

/// Key lifecycle manager with fixed-size storage and audit trail.
pub struct KeyManager<C: CryptoProvider> {
    keys: [KeyEntry; MAX_KEYS],
    audit: [Option<AuditEntry>; AUDIT_CAPACITY],
    audit_head: usize,
    audit_count: u64,
    audit_overflow_count: u64,
    /// Rolling SHA-256 checksum: equals the `chain_hash` of the
    /// chronologically newest live audit entry. Allows O(1) verification
    /// of the chain tail.
    audit_checksum: [u8; 32],
    /// Chain-hash seed for verification: the chain hash that the
    /// chronologically-oldest live entry references as its predecessor.
    ///
    /// Initially zero (matching the all-zero seed used when the very first
    /// entry was inserted). After an eviction, becomes the `chain_hash` of
    /// the entry just evicted — preserving the chain anchor across wraps so
    /// `verify_audit_integrity` can detect tampering of every live entry.
    audit_chain_seed: [u8; 32],
    crypto: C,
    /// Optional callback invoked when audit entries are overwritten.
    audit_overflow_callback: Option<AuditOverflowCallback>,
    /// Optional maximum key lifetime in microseconds.
    max_key_lifetime_us: Option<u64>,
    /// Optional maximum number of rotations per key before it must be
    /// re-provisioned.  Prevents nonce-space exhaustion when the same
    /// AES-GCM key is rotated across many reboots (birthday bound).
    max_rotation_count: Option<u32>,
    /// Whether the audit checksum is in a valid state.
    ///
    /// Under the fail-closed two-phase append (`prepare_audit` /
    /// `commit_audit`), a crypto failure aborts the key operation *before*
    /// any audit entry is committed, so an unverifiable (zero-chain) entry
    /// is never stored and this flag is never cleared in normal operation.
    /// It is retained as a defensive invariant: `verify_audit_integrity`
    /// returns `CryptoError` if it is ever observed false.
    checksum_valid: bool,
    /// When true, key operations are rejected if the audit ring buffer
    /// would overflow and no overflow callback is set. This prevents
    /// an attacker from evicting audit evidence by flooding key operations.
    audit_fail_closed: bool,
    /// Cached count of slots currently in `KeyState::Active`. Maintained
    /// incrementally by provision/generate/rotate/revoke/tick so that
    /// [`key_capacity`](Self::key_capacity) is O(1) instead of O(MAX_KEYS).
    active_count: u32,
}

impl<C: CryptoProvider> KeyManager<C> {
    /// Create a new key manager backed by the given crypto provider.
    ///
    /// # Example
    ///
    /// ```
    /// use vs_crypto::{KeyId, SoftwareCryptoProvider};
    /// use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
    ///
    /// let mut km = KeyManager::new(SoftwareCryptoProvider::default());
    ///
    /// let key_id = KeyId(0);
    /// // Non-uniform key material: validate_key_material rejects all-zero
    /// // and all-same-byte slices.
    /// let mut material = [0u8; 32];
    /// for (i, b) in material.iter_mut().enumerate() {
    ///     *b = i as u8;
    /// }
    ///
    /// let meta = KeyMetadata {
    ///     key_id,
    ///     algorithm: KeyAlgorithm::Aes256Gcm,
    ///     purpose: KeyPurpose::BusAuthentication,
    ///     created_at: 1_000,
    ///     expires_at: None,
    ///     rotation_count: 0,
    ///     cumulative_nonce_count: 0,
    /// };
    ///
    /// km.provision_key(key_id, meta, &material).unwrap();
    ///
    /// let mut new_material = [0u8; 32];
    /// for (i, b) in new_material.iter_mut().enumerate() {
    ///     *b = (i as u8).wrapping_add(0x10);
    /// }
    /// km.rotate_key(key_id, &new_material, 2_000, None).unwrap();
    ///
    /// km.revoke_key(key_id, 3_000).unwrap();
    /// ```
    pub fn new(crypto: C) -> Self {
        Self {
            keys: core::array::from_fn(|idx| {
                let mut e = KeyEntry::default();
                // Seed each slot's metadata.key_id with its slot index so the
                // slot-index == key_id invariant holds from the moment the
                // manager is constructed (not just after first provision).
                e.metadata.key_id = KeyId::new(idx as u32);
                e
            }),
            audit: [None; AUDIT_CAPACITY],
            audit_head: 0,
            audit_count: 0,
            audit_overflow_count: 0,
            audit_checksum: [0u8; 32],
            audit_chain_seed: [0u8; 32],
            crypto,
            audit_overflow_callback: None,
            max_key_lifetime_us: None,
            max_rotation_count: None,
            checksum_valid: true,
            audit_fail_closed: false,
            active_count: 0,
        }
    }

    /// Enable fail-closed audit mode.
    ///
    /// When enabled, key operations (provision, rotate, revoke, generate)
    /// will return [`VsError::ResourceExhausted`] if the audit ring buffer
    /// would overflow and no [`AuditOverflowCallback`] has been set.
    /// This prevents an attacker from silently evicting audit evidence
    /// by flooding key operations.
    pub fn set_audit_fail_closed(&mut self, enabled: bool) {
        self.audit_fail_closed = enabled;
    }

    /// Set a callback that is invoked whenever an audit entry is overwritten
    /// due to ring buffer capacity. Use this to raise a security alert when
    /// audit entries are being lost.
    pub fn set_audit_overflow_callback(&mut self, cb: AuditOverflowCallback) {
        self.audit_overflow_callback = Some(cb);
    }

    /// Set the maximum key lifetime in microseconds. Keys provisioned without
    /// an explicit expiry will automatically have one computed from `created_at + max_us`.
    pub fn set_max_key_lifetime(&mut self, max_us: u64) {
        self.max_key_lifetime_us = Some(max_us);
    }

    /// Set the maximum number of rotations allowed per key.
    ///
    /// Once a key's `rotation_count` reaches this limit, further calls to
    /// [`rotate_key`](Self::rotate_key) will return
    /// [`VsError::ResourceExhausted`].  This prevents nonce-space exhaustion
    /// when the same AES-GCM key survives many reboots.
    pub fn set_max_rotation_count(&mut self, max: u32) {
        self.max_rotation_count = Some(max);
    }

    /// Returns a reference to the underlying crypto provider.
    pub fn crypto(&self) -> &C {
        &self.crypto
    }

    /// Returns the number of audit entries overwritten due to ring buffer wrap.
    pub fn audit_overflow_count(&self) -> u64 {
        self.audit_overflow_count
    }

    /// Returns `(active_keys, max_keys)` for capacity monitoring.
    ///
    /// O(1): uses an incrementally maintained counter rather than
    /// scanning all slots.
    pub fn key_capacity(&self) -> (usize, usize) {
        (self.active_count as usize, MAX_KEYS)
    }

    /// Returns `true` iff the audit ring has free capacity for at least
    /// one more append without evicting a live entry. Use this to perform
    /// pre-flight checks in fail-closed callers before invoking a state
    /// mutation that records an audit event.
    pub fn audit_has_headroom(&self) -> bool {
        // Headroom exists iff the slot we would write next is empty, OR
        // an overflow callback is installed (in which case eviction is
        // expected and recorded).
        self.audit[self.audit_head].is_none() || self.audit_overflow_callback.is_some()
    }

    fn validate_key_material(key_material: &[u8]) -> Result<(), VsError> {
        if key_material.is_empty() {
            return Err(VsError::InvalidInput);
        }
        // All-zero check (constant-time: always scan full slice)
        let mut all_zero: u8 = 0;
        for &b in key_material {
            all_zero |= b;
        }
        if all_zero == 0 {
            return Err(VsError::InvalidInput);
        }
        // Uniform-byte check (constant-time: always scan full slice)
        if key_material.len() > 1 {
            let first = key_material[0];
            let mut all_same: u8 = 0;
            for &b in &key_material[1..] {
                all_same |= b ^ first;
            }
            if all_same == 0 {
                return Err(VsError::InvalidInput);
            }
        }
        Ok(())
    }

    fn validate_key_length(algorithm: KeyAlgorithm, material_len: usize) -> Result<(), VsError> {
        if material_len != algorithm.expected_key_len() {
            return Err(VsError::InvalidInput);
        }
        Ok(())
    }

    fn validate_timestamps(metadata: &KeyMetadata) -> Result<(), VsError> {
        if let Some(expires) = metadata.expires_at {
            if expires <= metadata.created_at {
                return Err(VsError::InvalidConfig);
            }
        }
        Ok(())
    }

    /// Provision a new key into the specified slot.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] — `key_id` out of range, or audit ring
    ///   would overflow in fail-closed mode.
    /// - [`VsError::InvalidInput`] — key material is empty, oversized, degenerate
    ///   (all-zero / uniform), or the wrong length for the algorithm.
    /// - [`VsError::InvalidConfig`] — `metadata.key_id` mismatch or invalid expiry.
    /// - [`VsError::KeyRevoked`] / [`VsError::PolicyViolation`] — slot already revoked / active.
    /// - [`VsError::CryptoError`] — the audit chain hash could not be computed.
    ///   The slot is **not** mutated; the operation fails closed and may be retried.
    pub fn provision_key(
        &mut self,
        key_id: KeyId,
        mut metadata: KeyMetadata,
        key_material: &[u8],
    ) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEYS {
            return Err(VsError::ResourceExhausted);
        }
        if key_material.len() > MAX_KEY_MATERIAL_LEN {
            return Err(VsError::InvalidInput);
        }
        if metadata.key_id != key_id {
            return Err(VsError::InvalidConfig);
        }
        // Auto-set expiry if none provided and max lifetime is configured
        if metadata.expires_at.is_none() {
            if let Some(max) = self.max_key_lifetime_us {
                metadata.expires_at = Some(metadata.created_at.saturating_add(max));
            }
        }

        Self::validate_timestamps(&metadata)?;
        Self::validate_key_material(key_material)?;
        Self::validate_key_length(metadata.algorithm, key_material.len())?;

        let entry = &self.keys[idx];
        if entry.state == KeyState::Revoked {
            return Err(VsError::KeyRevoked);
        }
        if entry.state == KeyState::Active {
            return Err(VsError::PolicyViolation);
        }

        // Pre-flight audit headroom check: in fail-closed mode, refuse
        // BEFORE mutating slot state so a post-commit audit failure cannot
        // leave the slot updated with no audit record.
        if self.audit_fail_closed && !self.audit_has_headroom() {
            return Err(VsError::ResourceExhausted);
        }

        // Phase 1: compute the audit entry + chain hash BEFORE mutating slot
        // state. A crypto failure here aborts the whole operation with the
        // slot unchanged, so a committed key operation can never be paired
        // with an unverifiable (zero-chain) audit entry.
        let prepared =
            self.prepare_audit(AuditEventType::KeyProvisioned, key_id, metadata.created_at)?;

        let mut material = [0u8; MAX_KEY_MATERIAL_LEN];
        material[..key_material.len()].copy_from_slice(key_material);

        self.keys[idx] = KeyEntry {
            metadata,
            state: KeyState::Active,
            material,
            material_len: key_material.len(),
        };
        self.active_count = self.active_count.saturating_add(1);

        // Phase 2: infallible commit of the already-validated audit entry.
        self.commit_audit(prepared);
        Ok(())
    }

    /// Provision a new key and zeroize the source material.
    ///
    /// This is the preferred method for provisioning keys. It zeroizes
    /// `key_material` after copying it into the key slot, ensuring the
    /// caller's buffer does not retain sensitive data.
    pub fn provision_key_zeroizing(
        &mut self,
        key_id: KeyId,
        metadata: KeyMetadata,
        key_material: &mut [u8],
    ) -> Result<(), VsError> {
        let result = self.provision_key(key_id, metadata, key_material);
        // Zeroize source regardless of success/failure to prevent
        // key material from lingering in the caller's memory.
        key_material.zeroize();
        result
    }

    /// Generate a new key using the crypto provider's RNG and provision it.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] — `key_id` out of range, or audit ring
    ///   would overflow in fail-closed mode.
    /// - [`VsError::InvalidConfig`] — `metadata.key_id` mismatch or invalid expiry.
    /// - [`VsError::InvalidInput`] — the RNG produced degenerate key material.
    /// - [`VsError::KeyRevoked`] / [`VsError::PolicyViolation`] — slot already revoked / active.
    /// - [`VsError::CryptoError`] — RNG failure, or the audit chain hash could not
    ///   be computed. The slot is **not** mutated; the operation fails closed.
    pub fn generate_key(&mut self, key_id: KeyId, metadata: KeyMetadata) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEYS {
            return Err(VsError::ResourceExhausted);
        }
        if metadata.key_id != key_id {
            return Err(VsError::InvalidConfig);
        }
        Self::validate_timestamps(&metadata)?;

        let entry = &self.keys[idx];
        if entry.state == KeyState::Revoked {
            return Err(VsError::KeyRevoked);
        }
        if entry.state == KeyState::Active {
            return Err(VsError::PolicyViolation);
        }

        // Pre-flight audit headroom check: in fail-closed mode, refuse
        // BEFORE generating and writing key material.
        if self.audit_fail_closed && !self.audit_has_headroom() {
            return Err(VsError::ResourceExhausted);
        }

        let key_len = metadata.algorithm.expected_key_len();
        let mut material = [0u8; MAX_KEY_MATERIAL_LEN];
        self.crypto.random_bytes(&mut material[..key_len])?;

        // Validate generated material (reject degenerate RNG output)
        Self::validate_key_material(&material[..key_len])?;

        // Phase 1: compute the audit entry + chain hash BEFORE mutating slot
        // state, so a crypto failure aborts the operation with the slot
        // unchanged rather than committing an unverifiable audit entry.
        let prepared =
            self.prepare_audit(AuditEventType::KeyGenerated, key_id, metadata.created_at)?;

        self.keys[idx] = KeyEntry {
            metadata,
            state: KeyState::Active,
            material,
            material_len: key_len,
        };
        self.active_count = self.active_count.saturating_add(1);

        // Phase 2: infallible commit of the already-validated audit entry.
        self.commit_audit(prepared);
        Ok(())
    }

    /// Rotate an existing key with new material.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] — `key_id` out of range, rotation limit
    ///   reached, nonce space exhausted, or audit ring overflow in fail-closed mode.
    /// - [`VsError::InvalidInput`] — new material is empty, oversized, degenerate,
    ///   or the wrong length for the slot's algorithm.
    /// - [`VsError::InvalidConfig`] — the new expiry is not after `current_time`.
    /// - [`VsError::KeyRevoked`] / [`VsError::KeyExpired`] / [`VsError::NotInitialized`]
    ///   — slot not in the `Active` state.
    /// - [`VsError::CryptoError`] — the audit chain hash could not be computed.
    ///   The existing key material is **not** zeroized; the operation fails closed.
    pub fn rotate_key(
        &mut self,
        key_id: KeyId,
        new_material: &[u8],
        current_time: u64,
        new_expires_at: Option<u64>,
    ) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEYS {
            return Err(VsError::ResourceExhausted);
        }
        if new_material.is_empty() || new_material.len() > MAX_KEY_MATERIAL_LEN {
            return Err(VsError::InvalidInput);
        }
        Self::validate_key_material(new_material)?;

        let entry = &self.keys[idx];
        match entry.state {
            KeyState::Revoked => return Err(VsError::KeyRevoked),
            KeyState::Expired => return Err(VsError::KeyExpired),
            KeyState::Empty => return Err(VsError::NotInitialized),
            KeyState::Active => {}
        }
        // Validate length matches the algorithm for this slot
        Self::validate_key_length(entry.metadata.algorithm, new_material.len())?;

        // Validate the new expiry BEFORE mutating the key slot -- otherwise a
        // validation failure would leave the slot in an inconsistent state with
        // the old key material already zeroized.
        if let Some(new_exp) = new_expires_at {
            if new_exp <= current_time {
                return Err(VsError::InvalidConfig);
            }
        }

        let current_rotation = self.keys[idx].metadata.rotation_count;
        if let Some(max) = self.max_rotation_count {
            if current_rotation >= max {
                return Err(VsError::ResourceExhausted);
            }
        }
        let new_rotation_count = current_rotation
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;

        // Prevent nonce-space exhaustion across rotations.
        // AES-256-GCM with 96-bit nonces and a 4-byte counter has a safe
        // limit of 2^32 nonces per unique key.  If the cumulative count
        // exceeds this, require a full re-keying (new key provisioning).
        const AES_GCM_NONCE_LIMIT: u64 = u32::MAX as u64;
        if self.keys[idx].metadata.cumulative_nonce_count > AES_GCM_NONCE_LIMIT {
            return Err(VsError::ResourceExhausted);
        }

        // Pre-flight audit headroom check: in fail-closed mode, refuse
        // BEFORE zeroizing old material so a post-commit audit failure
        // cannot lose the live key without producing an audit record.
        if self.audit_fail_closed && !self.audit_has_headroom() {
            return Err(VsError::ResourceExhausted);
        }

        // Phase 1: compute the audit entry + chain hash BEFORE zeroizing the
        // old key material. A crypto failure here aborts the rotation with
        // the existing key intact rather than destroying it and recording an
        // unverifiable audit entry.
        let prepared = self.prepare_audit(AuditEventType::KeyRotated, key_id, current_time)?;

        let entry = &mut self.keys[idx];
        entry.material.zeroize();
        entry.material[..new_material.len()].copy_from_slice(new_material);
        entry.material_len = new_material.len();

        entry.state = KeyState::Active;
        entry.metadata.rotation_count = new_rotation_count;
        entry.metadata.created_at = current_time;
        entry.metadata.expires_at = new_expires_at;

        // Phase 2: infallible commit of the already-validated audit entry.
        self.commit_audit(prepared);
        Ok(())
    }

    /// Record nonce usage for a key, incrementing the cumulative nonce counter.
    ///
    /// Callers should invoke this after each encryption operation to track
    /// nonce consumption.  The cumulative counter persists across key
    /// rotations, preventing nonce-space exhaustion when keys are rotated.
    ///
    /// Returns [`VsError::ResourceExhausted`] if adding `count` would
    /// overflow the counter.
    pub fn record_nonce_usage(&mut self, key_id: KeyId, count: u64) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEYS {
            return Err(VsError::ResourceExhausted);
        }
        let entry = &mut self.keys[idx];
        match entry.state {
            KeyState::Revoked => return Err(VsError::KeyRevoked),
            KeyState::Expired => return Err(VsError::KeyExpired),
            KeyState::Empty => return Err(VsError::NotInitialized),
            KeyState::Active => {}
        }
        entry.metadata.cumulative_nonce_count = entry
            .metadata
            .cumulative_nonce_count
            .checked_add(count)
            .ok_or(VsError::ResourceExhausted)?;
        Ok(())
    }

    /// Revoke a key. Revoked keys become tombstones and cannot be re-provisioned.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] — `key_id` out of range, or audit ring
    ///   would overflow in fail-closed mode.
    /// - [`VsError::KeyRevoked`] / [`VsError::KeyExpired`] / [`VsError::NotInitialized`]
    ///   — slot not in the `Active` state.
    /// - [`VsError::CryptoError`] — the audit chain hash could not be computed.
    ///   The slot is **not** mutated; the operation fails closed and may be retried.
    pub fn revoke_key(&mut self, key_id: KeyId, current_time: u64) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEYS {
            return Err(VsError::ResourceExhausted);
        }

        match self.keys[idx].state {
            KeyState::Revoked => return Err(VsError::KeyRevoked),
            KeyState::Expired => return Err(VsError::KeyExpired),
            KeyState::Empty => return Err(VsError::NotInitialized),
            KeyState::Active => {}
        }

        // Pre-flight audit headroom check: in fail-closed mode, refuse
        // BEFORE zeroizing material so a post-commit audit failure cannot
        // leave the slot revoked silently.
        if self.audit_fail_closed && !self.audit_has_headroom() {
            return Err(VsError::ResourceExhausted);
        }

        // Phase 1: compute the audit entry + chain hash BEFORE mutating slot
        // state, so a crypto failure aborts the revocation with the slot
        // unchanged rather than committing an unverifiable audit entry.
        let prepared = self.prepare_audit(AuditEventType::KeyRevoked, key_id, current_time)?;

        let entry = &mut self.keys[idx];
        entry.state = KeyState::Revoked;
        entry.material.zeroize();
        entry.material_len = 0;
        self.active_count = self.active_count.saturating_sub(1);

        // Phase 2: infallible commit of the already-validated audit entry.
        self.commit_audit(prepared);
        Ok(())
    }

    /// Check if a key is valid (active and not expired).
    ///
    /// This is a **read-only** check — it does not transition the key's
    /// internal state to expired.  Call [`tick`](Self::tick) periodically
    /// to ensure expired keys are transitioned, zeroized, and audited.
    /// Material access via `get_key_material` is
    /// correctly denied for expired keys regardless of whether `tick` has run.
    #[must_use]
    pub fn is_key_valid(&self, key_id: KeyId, current_time: u64) -> bool {
        let idx = key_id.0 as usize;
        let Some(entry) = self.keys.get(idx) else {
            return false;
        };
        if entry.state != KeyState::Active {
            return false;
        }
        if let Some(expires) = entry.metadata.expires_at {
            if current_time >= expires {
                return false;
            }
        }
        true
    }

    /// Get the stored key material for an active key.
    ///
    /// Prefer [`with_key_material`](Self::with_key_material) to avoid copying
    /// key bytes into caller-controlled memory.
    ///
    /// Returns [`VsError::NotInitialized`] if the key has expired according
    /// to `current_time`, even if [`tick`](Self::tick) has not yet
    /// transitioned the key's state.  This ensures key material is never
    /// returned for expired keys.
    pub(crate) fn get_key_material(
        &self,
        key_id: KeyId,
        current_time: u64,
    ) -> Result<&[u8], VsError> {
        let idx = key_id.0 as usize;
        let entry = self.keys.get(idx).ok_or(VsError::NotFound)?;
        match entry.state {
            KeyState::Revoked => return Err(VsError::KeyRevoked),
            KeyState::Expired => return Err(VsError::KeyExpired),
            KeyState::Empty => return Err(VsError::NotInitialized),
            KeyState::Active => {}
        }
        if let Some(expires) = entry.metadata.expires_at {
            if current_time >= expires {
                return Err(VsError::KeyExpired);
            }
        }
        Ok(&entry.material[..entry.material_len])
    }

    /// Access key material through a callback. The material never leaves the
    /// manager and the caller cannot retain a reference beyond the closure.
    pub fn with_key_material<F, R>(
        &self,
        key_id: KeyId,
        current_time: u64,
        f: F,
    ) -> Result<R, VsError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let material = self.get_key_material(key_id, current_time)?;
        Ok(f(material))
    }

    /// Access key material with purpose and algorithm validation through a callback.
    pub fn with_key_material_for<F, R>(
        &self,
        key_id: KeyId,
        expected_purpose: KeyPurpose,
        expected_algorithm: KeyAlgorithm,
        current_time: u64,
        f: F,
    ) -> Result<R, VsError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let material =
            self.get_key_material_for(key_id, expected_purpose, expected_algorithm, current_time)?;
        Ok(f(material))
    }

    /// Get key material with purpose and algorithm validation.
    pub(crate) fn get_key_material_for(
        &self,
        key_id: KeyId,
        expected_purpose: KeyPurpose,
        expected_algorithm: KeyAlgorithm,
        current_time: u64,
    ) -> Result<&[u8], VsError> {
        let idx = key_id.0 as usize;
        let entry = self.keys.get(idx).ok_or(VsError::NotFound)?;
        match entry.state {
            KeyState::Revoked => return Err(VsError::KeyRevoked),
            KeyState::Expired => return Err(VsError::KeyExpired),
            KeyState::Empty => return Err(VsError::NotInitialized),
            KeyState::Active => {}
        }
        if let Some(expires) = entry.metadata.expires_at {
            if current_time >= expires {
                return Err(VsError::KeyExpired);
            }
        }
        if entry.metadata.purpose != expected_purpose
            || entry.metadata.algorithm != expected_algorithm
        {
            return Err(VsError::PolicyViolation);
        }
        Ok(&entry.material[..entry.material_len])
    }

    /// Get metadata for a key if it exists.
    pub fn get_metadata(&self, key_id: KeyId) -> Option<&KeyMetadata> {
        let idx = key_id.0 as usize;
        let entry = self.keys.get(idx)?;
        if entry.state == KeyState::Empty {
            return None;
        }
        Some(&entry.metadata)
    }

    /// Return the number of audit entries recorded.
    pub fn audit_count(&self) -> u64 {
        self.audit_count
    }

    /// Get an audit entry by its position in the ring buffer.
    pub fn get_audit_entry(&self, index: usize) -> Option<&AuditEntry> {
        if index >= AUDIT_CAPACITY {
            return None;
        }
        self.audit[index].as_ref()
    }

    /// Iterate over audit entries in chronological order (oldest first).
    pub fn audit_iter(&self) -> AuditIter<'_> {
        AuditIter {
            audit: &self.audit,
            total_count: self.audit_count,
            index: 0,
            yielded: 0,
        }
    }

    /// Verify integrity of the audit log by walking the per-entry chain
    /// hashes in chronological order and confirming each link.
    ///
    /// Verification is O(live_entries): for each entry, recompute
    /// `SHA-256(prev_chain || entry_bytes)` and constant-time-compare against
    /// the stored `chain_hash`. The seed is `audit_chain_seed`, which is
    /// `[0; 32]` when the log has never overflowed and the chain hash of the
    /// most-recently evicted entry otherwise. The final chain value must
    /// equal `self.audit_checksum`.
    pub fn verify_audit_integrity(&self) -> Result<bool, VsError> {
        if !self.checksum_valid {
            return Err(VsError::CryptoError);
        }
        let mut prev_chain = self.audit_chain_seed;
        let mut ok = true;
        for entry in self.audit_iter() {
            let entry_bytes = audit_entry_to_bytes(entry);
            let mut to_hash = [0u8; 32 + 25];
            to_hash[..32].copy_from_slice(&prev_chain);
            to_hash[32..].copy_from_slice(&entry_bytes);
            let mut computed = [0u8; 32];
            self.crypto.sha256(&to_hash, &mut computed)?;
            // Constant-time compare so a tampered entry's position is not
            // leaked by short-circuit evaluation. Accumulate the result.
            if !vs_types::constant_time_eq_32(&computed, &entry.chain_hash) {
                ok = false;
            }
            prev_chain = computed;
        }
        let tail_ok = vs_types::constant_time_eq_32(&prev_chain, &self.audit_checksum);
        Ok(ok && tail_ok)
    }

    /// Append an audit entry for a state-mutating key operation.
    ///
    /// This is a fail-closed two-phase operation. [`prepare_audit`] computes
    /// the new entry and its chain hash *before* the caller mutates slot
    /// state; if the crypto provider fails to compute the chain hash it
    /// returns [`VsError::CryptoError`] and the caller must abort the whole
    /// operation with no slot mutation. [`commit_audit`] then stores the
    /// already-validated entry and can never fail.
    ///
    /// `append_audit` is retained for the best-effort [`tick`](Self::tick)
    /// expiry path, where the key transition cannot be undone: it prepares
    /// and commits in one call and propagates a `prepare_audit` error so the
    /// caller can observe (and discard) it.
    fn append_audit(
        &mut self,
        event_type: AuditEventType,
        key_id: KeyId,
        timestamp: u64,
    ) -> Result<(), VsError> {
        let prepared = self.prepare_audit(event_type, key_id, timestamp)?;
        self.commit_audit(prepared);
        Ok(())
    }

    /// Phase 1 of an audit append: compute the new entry and its chain hash
    /// without mutating any audit or key state.
    ///
    /// Returns [`VsError::CryptoError`] if the chain hash cannot be computed
    /// (the crypto provider failed every retry) and [`VsError::ResourceExhausted`]
    /// if a fail-closed ring overflow would occur. Callers MUST invoke this
    /// (and propagate any error) *before* mutating slot state, so that an
    /// unverifiable audit entry can never accompany a committed key operation.
    fn prepare_audit(
        &mut self,
        event_type: AuditEventType,
        key_id: KeyId,
        timestamp: u64,
    ) -> Result<PreparedAudit, VsError> {
        let is_overflow = self.audit[self.audit_head].is_some();
        if is_overflow {
            // Fail-closed: reject the operation if audit would overflow
            // and no callback is configured to handle it.
            if self.audit_fail_closed && self.audit_overflow_callback.is_none() {
                return Err(VsError::ResourceExhausted);
            }
        }

        // Compute the new chain hash from the previous tail in O(1).
        //
        // The per-entry chain_hash + tail-only audit_checksum design reduces
        // both pre- and post-wrap appends to a single SHA-256 call.
        let prev_chain = self.audit_checksum;
        let mut new_entry = AuditEntry {
            event_type,
            key_id,
            timestamp,
            sequence: self.audit_count,
            chain_hash: [0u8; 32],
        };
        let mut chain_hash = [0u8; 32];
        // Fail-closed: a crypto failure here aborts the whole key operation
        // (callers propagate this error before mutating slot state) instead
        // of committing an entry with an unverifiable zero chain hash.
        if !self.compute_chain_step(&prev_chain, &new_entry, &mut chain_hash) {
            return Err(VsError::CryptoError);
        }
        new_entry.chain_hash = chain_hash;

        Ok(PreparedAudit {
            entry: new_entry,
            chain_hash,
            is_overflow,
        })
    }

    /// Phase 2 of an audit append: store the entry prepared by
    /// [`prepare_audit`]. Infallible — all crypto work happened in phase 1.
    fn commit_audit(&mut self, prepared: PreparedAudit) {
        if prepared.is_overflow {
            self.audit_overflow_count = self.audit_overflow_count.saturating_add(1);
            if let Some(cb) = self.audit_overflow_callback {
                cb(self.audit_overflow_count);
            }
            // Capture the evicted entry's chain hash as the new anchor for
            // verification. After this insert, the chronologically-oldest
            // live entry will be the one currently at position
            // (audit_head + 1) mod CAPACITY — and IT was inserted referencing
            // the entry we're about to overwrite as its predecessor.
            if let Some(ref evicted) = self.audit[self.audit_head] {
                self.audit_chain_seed = evicted.chain_hash;
            }
        }

        self.audit_checksum = prepared.chain_hash;
        self.audit[self.audit_head] = Some(prepared.entry);
        self.audit_head = (self.audit_head + 1) % AUDIT_CAPACITY;
        self.audit_count = self.audit_count.saturating_add(1);
    }

    /// Maximum number of SHA-256 retry attempts before giving up.
    const CHECKSUM_RETRY_LIMIT: usize = 3;

    /// Compute one chain step: SHA-256(prev_chain || entry_bytes).
    ///
    /// Returns `true` on success, `false` if the crypto provider failed
    /// every retry. A `false` result causes `prepare_audit` to abort the
    /// key operation cleanly (no slot mutation, no audit entry committed),
    /// so a *transient* crypto failure no longer permanently degrades the
    /// audit trail — the existing log stays fully verifiable and the next
    /// operation succeeds once the provider recovers.
    fn compute_chain_step(
        &self,
        prev_chain: &[u8; 32],
        entry: &AuditEntry,
        out: &mut [u8; 32],
    ) -> bool {
        let entry_bytes = audit_entry_to_bytes(entry);
        let mut to_hash = [0u8; 32 + 25];
        to_hash[..32].copy_from_slice(prev_chain);
        to_hash[32..].copy_from_slice(&entry_bytes);
        for _ in 0..Self::CHECKSUM_RETRY_LIMIT {
            if self.crypto.sha256(&to_hash, out).is_ok() {
                return true;
            }
        }
        false
    }

    /// Periodic tick to check for key expiry.
    ///
    /// Transitions any `Active` key whose `expires_at <= current_time` to
    /// `Expired`, zeroizing its material in place. One audit event of type
    /// [`AuditEventType::KeyExpired`] is appended per transition.
    ///
    /// # Audit-emit failures are silently dropped
    ///
    /// Audit append errors during expiry (including `ResourceExhausted`
    /// when fail-closed is set and the ring is full) are intentionally
    /// **discarded**: the key transition cannot be undone once material
    /// has been zeroized, so propagating the error would lie to the
    /// caller. The keys remain safely expired either way.
    ///
    /// Callers that need strict per-expiry audit guarantees must observe
    /// the `audit_count` delta across each `tick` call and reconcile it
    /// with the number of keys they expected to expire (e.g., by snapshotting
    /// `active_count` / `key_capacity` before and after the tick). Missing
    /// audit records under fail-closed mode signal that the audit ring
    /// needs to be drained.
    pub fn tick(&mut self, current_time: u64) {
        let mut expired_keys = [KeyId(0); MAX_KEYS];
        let mut count = 0;

        for idx in 0..MAX_KEYS {
            let entry = &mut self.keys[idx];
            if entry.state == KeyState::Active {
                if let Some(expires) = entry.metadata.expires_at {
                    if current_time >= expires {
                        entry.material.zeroize();
                        entry.material_len = 0;
                        entry.state = KeyState::Expired;
                        expired_keys[count] = entry.metadata.key_id;
                        count += 1;
                    }
                }
            }
        }

        // Decrement active_count once for each transitioned slot.
        self.active_count = self.active_count.saturating_sub(count as u32);

        for key_id in expired_keys.iter().take(count) {
            // Expiry audit events are best-effort: the key is already
            // expired and zeroized above, so we cannot undo the transition.
            // In fail-closed mode, this will stop recording further expirations
            // until the audit is drained, but the keys remain safely expired.
            let _ = self.append_audit(AuditEventType::KeyExpired, *key_id, current_time);
        }
    }

    // --- AUTOSAR KeyM interface mapping ---

    /// AUTOSAR `KeyM_KeyElementGet` equivalent.
    pub fn keym_key_element_get(&self, key_id: KeyId) -> Result<&KeyMetadata, VsError> {
        self.get_metadata(key_id).ok_or(VsError::NotFound)
    }

    /// AUTOSAR `KeyM_KeyElementSet` equivalent.
    pub fn keym_key_element_set(
        &mut self,
        key_id: KeyId,
        metadata: KeyMetadata,
        key_material: &[u8],
    ) -> Result<(), VsError> {
        self.provision_key(key_id, metadata, key_material)
    }

    /// AUTOSAR `KeyM_Update` equivalent (key rotation).
    pub fn keym_update(
        &mut self,
        key_id: KeyId,
        new_material: &[u8],
        current_time: u64,
    ) -> Result<(), VsError> {
        self.rotate_key(key_id, new_material, current_time, None)
    }

    /// AUTOSAR KeyM_KeyGenerate equivalent.
    ///
    /// Generates a new key using the crypto provider's RNG.
    pub fn keym_key_generate(
        &mut self,
        key_id: KeyId,
        metadata: KeyMetadata,
    ) -> Result<(), VsError> {
        self.generate_key(key_id, metadata)
    }

    /// AUTOSAR `KeyM_Start` equivalent — validates that the key manager
    /// is ready for cryptographic operations.
    #[must_use]
    pub fn keym_start(&self) -> bool {
        // Self-test 1: verify audit chain integrity.
        // Explicit match so crypto-provider errors are not silently swallowed.
        match self.verify_audit_integrity() {
            Ok(true) => {}
            Ok(false) | Err(_) => return false,
        }
        // Self-test 2: verify crypto provider responds
        let test_data = [0x43, 0x72, 0x61, 0x74, 0x6F, 0x6E, 0x53, 0x68]; // "CratonSh"
        let mut hash = [0u8; 32];
        if self.crypto.sha256(&test_data, &mut hash).is_err() {
            return false;
        }
        // Verify hash is non-zero (crypto provider is functional)
        let mut acc: u8 = 0;
        for &b in &hash {
            acc |= b;
        }
        acc != 0
    }

    /// AUTOSAR `KeyM_Finalize` equivalent — zeroizes all keys.
    ///
    /// Wipes secret material and resets lifecycle metadata for every slot.
    ///
    /// # Invariant preserved
    ///
    /// `metadata.key_id` is **intentionally NOT reset** to `KeyId(0)`.
    /// Slot index `i` continues to hold `key_id == KeyId(i as u32)` after
    /// finalize, matching the invariant required by all other APIs
    /// (`provision_key`, `get_metadata`, `keym_key_element_get`, etc.)
    /// that index by `key_id.0`. Zeroing the field would collapse every
    /// slot's id to 0 and break that invariant: after finalize, all but
    /// slot 0 would report a `key_id` inconsistent with their slot index.
    ///
    /// The secret-bearing fields (`material`, `material_len`,
    /// `expires_at`, `rotation_count`, `created_at`) are cleared, which
    /// is the security-relevant subset.
    pub fn keym_finalize(&mut self) {
        for (idx, entry) in self.keys.iter_mut().enumerate() {
            entry.material.zeroize();
            entry.material_len = 0;
            entry.state = KeyState::Empty;
            // Restore the slot-index invariant: after finalize, slot `i`
            // continues to advertise `key_id == KeyId(i as u32)`.
            entry.metadata.key_id = KeyId::new(idx as u32);
            entry.metadata.created_at = 0;
            entry.metadata.expires_at = None;
            entry.metadata.rotation_count = 0;
            entry.metadata.cumulative_nonce_count = 0;
        }
        self.active_count = 0;
    }
}

impl<C: CryptoProvider> Drop for KeyManager<C> {
    fn drop(&mut self) {
        for entry in &mut self.keys {
            entry.material.zeroize();
            entry.material_len = 0;
        }
        self.audit_checksum = [0u8; 32];
        self.audit_chain_seed = [0u8; 32];
        self.audit_count = 0;
        self.audit_overflow_count = 0;
        self.active_count = 0;
        for entry in &mut self.audit {
            *entry = None;
        }
    }
}

impl<C: CryptoProvider + Default> Default for KeyManager<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use core::cell::Cell;
    use vs_crypto::{KeyType, SoftwareCryptoProvider};

    type TestManager = KeyManager<SoftwareCryptoProvider>;

    fn new_mgr() -> TestManager {
        KeyManager::new(SoftwareCryptoProvider::default())
    }

    /// A crypto provider that delegates to `SoftwareCryptoProvider` but can be
    /// switched to fail every `sha256` call, used to exercise the fail-closed
    /// audit crypto-failure path.
    struct FailingCrypto {
        inner: SoftwareCryptoProvider,
        fail_sha256: Cell<bool>,
    }

    impl FailingCrypto {
        fn new() -> Self {
            Self {
                inner: SoftwareCryptoProvider::default(),
                fail_sha256: Cell::new(false),
            }
        }
        fn set_fail(&self, fail: bool) {
            self.fail_sha256.set(fail);
        }
    }

    impl CryptoProvider for FailingCrypto {
        fn aes_gcm_encrypt(
            &self,
            key_id: KeyId,
            nonce: &[u8; 12],
            plaintext: &[u8],
            aad: &[u8],
            ciphertext_out: &mut [u8],
            tag_out: &mut [u8; 16],
        ) -> Result<(), VsError> {
            self.inner
                .aes_gcm_encrypt(key_id, nonce, plaintext, aad, ciphertext_out, tag_out)
        }
        fn aes_gcm_decrypt(
            &self,
            key_id: KeyId,
            nonce: &[u8; 12],
            ciphertext: &[u8],
            aad: &[u8],
            tag: &[u8; 16],
            plaintext_out: &mut [u8],
        ) -> Result<(), VsError> {
            self.inner
                .aes_gcm_decrypt(key_id, nonce, ciphertext, aad, tag, plaintext_out)
        }
        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            if self.fail_sha256.get() {
                return Err(VsError::CryptoError);
            }
            self.inner.sha256(data, hash_out)
        }
        fn hmac_sha256(
            &self,
            key_id: KeyId,
            data: &[u8],
            mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            self.inner.hmac_sha256(key_id, data, mac_out)
        }
        fn ecdh_derive_shared(
            &self,
            private_key_id: KeyId,
            peer_public: &[u8; 65],
            shared_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            self.inner
                .ecdh_derive_shared(private_key_id, peer_public, shared_out)
        }
        fn sign_p256(
            &self,
            key_id: KeyId,
            digest: &[u8; 32],
            sig_out: &mut [u8; 64],
        ) -> Result<(), VsError> {
            self.inner.sign_p256(key_id, digest, sig_out)
        }
        fn verify_p256(
            &self,
            pub_key: &[u8; 65],
            digest: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<bool, VsError> {
            self.inner.verify_p256(pub_key, digest, sig)
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            self.inner.random_bytes(buf)
        }
        fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
            self.inner.delete_key(key_id)
        }
        fn generate_key(&mut self, key_id: KeyId, key_type: KeyType) -> Result<(), VsError> {
            self.inner.generate_key(key_id, key_type)
        }
    }

    /// Generate a 32-byte test key with sufficient entropy.
    fn test_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        k
    }

    /// Generate a 16-byte test key for AES-128.
    fn test_key_16(seed: u8) -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        k
    }

    fn make_metadata(key_id: KeyId) -> KeyMetadata {
        KeyMetadata {
            key_id,
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Core lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn provision_and_get() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        let got = mgr.get_metadata(KeyId(0)).expect("get");
        assert_eq!(got.key_id, KeyId(0));
        assert_eq!(got.algorithm, KeyAlgorithm::Aes256Gcm);
    }

    #[test]
    fn provision_rotate_revoke_lifecycle() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(1));
        mgr.provision_key(KeyId(1), meta, &test_key(0xBB))
            .expect("provision");
        assert!(mgr.is_key_valid(KeyId(1), 500));
        mgr.rotate_key(KeyId(1), &test_key(0xCC), 2000, None)
            .expect("rotate");
        let m = mgr.get_metadata(KeyId(1)).expect("get");
        assert_eq!(m.rotation_count, 1);
        mgr.revoke_key(KeyId(1), 3000).expect("revoke");
        assert!(!mgr.is_key_valid(KeyId(1), 500));
    }

    #[test]
    fn revoked_key_cannot_be_reprovisioned() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(2));
        mgr.provision_key(KeyId(2), meta, &test_key(0xAA))
            .expect("provision");
        mgr.revoke_key(KeyId(2), 2000).expect("revoke");
        let meta2 = make_metadata(KeyId(2));
        let result = mgr.provision_key(KeyId(2), meta2, &test_key(0xBB));
        assert_eq!(result, Err(VsError::KeyRevoked));
    }

    #[test]
    fn expired_key_is_invalid() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(3),
            algorithm: KeyAlgorithm::HmacSha256,
            purpose: KeyPurpose::DiagnosticSession,
            created_at: 1000,
            expires_at: Some(5000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(3), meta, &test_key(0xDD))
            .expect("provision");
        assert!(mgr.is_key_valid(KeyId(3), 4999));
        mgr.tick(5000);
        assert!(!mgr.is_key_valid(KeyId(3), 5000));
        assert!(!mgr.is_key_valid(KeyId(3), 6000));
        assert_eq!(mgr.audit_count(), 2);
        let latest = mgr.get_audit_entry(1).unwrap();
        assert_eq!(latest.event_type, AuditEventType::KeyExpired);
        assert_eq!(latest.key_id, KeyId(3));
    }

    // -----------------------------------------------------------------------
    // Audit trail tests
    // -----------------------------------------------------------------------

    #[test]
    fn audit_trail_records_events() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None)
            .expect("rotate");
        mgr.revoke_key(KeyId(0), 3000).expect("revoke");
        assert_eq!(mgr.audit_count(), 3);
        let e0 = mgr.get_audit_entry(0).expect("audit 0");
        assert_eq!(e0.event_type, AuditEventType::KeyProvisioned);
        assert_eq!(e0.sequence, 0);
        let e1 = mgr.get_audit_entry(1).expect("audit 1");
        assert_eq!(e1.event_type, AuditEventType::KeyRotated);
        assert_eq!(e1.sequence, 1);
        let e2 = mgr.get_audit_entry(2).expect("audit 2");
        assert_eq!(e2.event_type, AuditEventType::KeyRevoked);
        assert_eq!(e2.sequence, 2);
    }

    #[test]
    fn audit_ring_buffer_wraps() {
        let mut mgr = new_mgr();
        for i in 0..(AUDIT_CAPACITY as u32 + 10) {
            let meta = KeyMetadata {
                key_id: KeyId(i),
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::BusAuthentication,
                created_at: u64::from(i),
                expires_at: None,
                rotation_count: 0,
                cumulative_nonce_count: 0,
            };
            let slot = i % MAX_KEYS as u32;
            if (i as usize) < MAX_KEYS {
                let _ = mgr.provision_key(KeyId(slot), meta, &test_key(i as u8));
            } else {
                let _ = mgr.append_audit(AuditEventType::KeyProvisioned, KeyId(slot), u64::from(i));
            }
        }
        assert!(mgr.audit_count() > AUDIT_CAPACITY as u64);
        assert!(mgr.audit_overflow_count() > 0);
        let latest = mgr
            .get_audit_entry(((mgr.audit_count() - 1) as usize) % AUDIT_CAPACITY)
            .expect("latest");
        assert_eq!(latest.sequence, mgr.audit_count() - 1);
    }

    #[test]
    fn audit_integrity_check() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None)
            .expect("rotate");
        assert!(mgr.verify_audit_integrity().expect("verify"));
    }

    #[test]
    fn audit_integrity_detects_tampering() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        // Tamper with an audit entry
        if let Some(ref mut entry) = mgr.audit[0] {
            entry.key_id = KeyId(99);
        }
        assert!(!mgr.verify_audit_integrity().expect("verify"));
    }

    #[test]
    fn audit_integrity_after_wrap() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        for i in 0..300u64 {
            mgr.rotate_key(KeyId(0), &test_key((i & 0xFF) as u8), 2000 + i, None)
                .unwrap();
        }
        assert!(mgr.verify_audit_integrity().expect("verify after wrap"));
    }

    #[test]
    fn audit_integrity_after_wrap_detects_tampering() {
        // Per-entry chain hashes plus the `audit_chain_seed` anchor must
        // detect tampering of every live entry, even the chronologically
        // oldest, after a wrap.
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        for i in 0..(AUDIT_CAPACITY as u64 + 5) {
            mgr.rotate_key(KeyId(0), &test_key((i & 0xFF) as u8), 2000 + i, None)
                .unwrap();
        }
        // After a full wrap every slot is populated; tamper with slot 0.
        let entry = mgr.audit[0].as_mut().expect("populated after wrap");
        entry.key_id = KeyId(0xDEAD_BEEF);
        assert!(
            !mgr.verify_audit_integrity().expect("verify"),
            "tampering with a post-wrap entry must be detected"
        );
    }

    // -----------------------------------------------------------------------
    // Audit iterator tests
    // -----------------------------------------------------------------------

    #[test]
    fn audit_iter_empty() {
        let mgr = new_mgr();
        assert_eq!(mgr.audit_iter().count(), 0);
    }

    #[test]
    fn audit_iter_chronological_order() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None)
            .unwrap();
        mgr.revoke_key(KeyId(0), 3000).unwrap();

        let entries: alloc::vec::Vec<_> = mgr.audit_iter().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event_type, AuditEventType::KeyProvisioned);
        assert_eq!(entries[1].event_type, AuditEventType::KeyRotated);
        assert_eq!(entries[2].event_type, AuditEventType::KeyRevoked);
        // Monotonically increasing sequences
        for i in 1..entries.len() {
            assert!(entries[i].sequence > entries[i - 1].sequence);
        }
    }

    #[test]
    fn audit_iter_after_wrap() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        // Generate enough rotations to wrap
        for i in 0..300u64 {
            mgr.rotate_key(KeyId(0), &test_key((i & 0xFF) as u8), 2000 + i, None)
                .unwrap();
        }
        let entries: alloc::vec::Vec<_> = mgr.audit_iter().collect();
        assert_eq!(entries.len(), AUDIT_CAPACITY);
        // Should be in chronological order
        for i in 1..entries.len() {
            assert!(entries[i].sequence > entries[i - 1].sequence);
        }
    }

    #[test]
    fn audit_iter_exact_size() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None)
            .unwrap();
        let iter = mgr.audit_iter();
        assert_eq!(iter.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Error case tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_out_of_range() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(100));
        let result = mgr.provision_key(KeyId(100), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn get_nonexistent_key_returns_none() {
        let mgr = new_mgr();
        assert!(mgr.get_metadata(KeyId(0)).is_none());
    }

    #[test]
    fn provision_with_empty_key_material_rejected() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        let result = mgr.provision_key(KeyId(0), meta, &[]);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn provision_with_uniform_key_material_rejected() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        let result = mgr.provision_key(KeyId(0), meta, &[0xAA; 32]);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn provision_with_all_zero_key_material_rejected() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        let result = mgr.provision_key(KeyId(0), meta, &[0x00; 32]);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn provision_with_mismatched_key_id_rejected() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(5),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn provision_with_wrong_key_length_rejected() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes128Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        // Provide 32 bytes for AES-128 which expects 16
        let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // Timestamp validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn provision_with_expires_before_created_rejected() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 5000,
            expires_at: Some(1000), // before created_at
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn provision_with_expires_equal_created_rejected() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: Some(1000), // equal to created_at
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    // -----------------------------------------------------------------------
    // Rotation validation tests (the fixed bug)
    // -----------------------------------------------------------------------

    #[test]
    fn rotate_with_wrong_key_length_rejected() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0)); // AES-256 = 32 bytes
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        // Try to rotate with 16-byte material
        let result = mgr.rotate_key(KeyId(0), &test_key_16(0xBB), 2000, None);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn rotate_aes128_with_correct_length_succeeds() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes128Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key_16(0xAA))
            .unwrap();
        mgr.rotate_key(KeyId(0), &test_key_16(0xBB), 2000, None)
            .expect("rotate with correct length");
    }

    #[test]
    fn rotate_nonexistent_key_fails() {
        let mut mgr = new_mgr();
        assert_eq!(
            mgr.rotate_key(KeyId(5), &test_key(0xFF), 1000, None),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn rotate_revoked_key_fails() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.revoke_key(KeyId(0), 2000).unwrap();
        assert_eq!(
            mgr.rotate_key(KeyId(0), &test_key(0xBB), 3000, None),
            Err(VsError::KeyRevoked)
        );
    }

    #[test]
    fn rotate_expired_key_fails() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.tick(1000);
        assert_eq!(
            mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None),
            Err(VsError::KeyExpired)
        );
    }

    #[test]
    fn rotate_key_three_times() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None)
            .expect("rotate 1");
        mgr.rotate_key(KeyId(0), &test_key(0xCC), 3000, None)
            .expect("rotate 2");
        mgr.rotate_key(KeyId(0), &test_key(0xDD), 4000, None)
            .expect("rotate 3");
        let m = mgr.get_metadata(KeyId(0)).expect("get");
        assert_eq!(m.rotation_count, 3);
    }

    // -----------------------------------------------------------------------
    // generate_key tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_key_provisions_with_random_material() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.generate_key(KeyId(0), meta).expect("generate");
        assert!(mgr.is_key_valid(KeyId(0), 1500));
        let material = mgr.get_key_material(KeyId(0), 1500).expect("get");
        assert_eq!(material.len(), 32); // AES-256
                                        // Verify it's not all zeros (RNG produced real bytes)
        assert!(material.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_key_records_audit_event() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.generate_key(KeyId(0), meta).expect("generate");
        assert_eq!(mgr.audit_count(), 1);
        let e = mgr.get_audit_entry(0).unwrap();
        assert_eq!(e.event_type, AuditEventType::KeyGenerated);
    }

    #[test]
    fn generate_key_aes128() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes128Gcm,
            purpose: KeyPurpose::TelemetryEncryption,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.generate_key(KeyId(0), meta).expect("generate aes128");
        let material = mgr.get_key_material(KeyId(0), 1500).expect("get");
        assert_eq!(material.len(), 16);
    }

    #[test]
    fn generate_key_out_of_range_fails() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(100));
        assert_eq!(
            mgr.generate_key(KeyId(100), meta),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn generate_key_into_revoked_slot_fails() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.revoke_key(KeyId(0), 2000).unwrap();
        let meta2 = make_metadata(KeyId(0));
        assert_eq!(mgr.generate_key(KeyId(0), meta2), Err(VsError::KeyRevoked));
    }

    #[test]
    fn generate_key_into_active_slot_fails() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        let meta2 = make_metadata(KeyId(0));
        assert_eq!(
            mgr.generate_key(KeyId(0), meta2),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn generate_key_with_invalid_timestamps_fails() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 5000,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        assert_eq!(
            mgr.generate_key(KeyId(0), meta),
            Err(VsError::InvalidConfig)
        );
    }

    // -----------------------------------------------------------------------
    // with_key_material callback tests
    // -----------------------------------------------------------------------

    #[test]
    fn with_key_material_callback() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        let len = mgr
            .with_key_material(KeyId(0), 1500, |mat: &[u8]| mat.len())
            .expect("callback");
        assert_eq!(len, 32);
    }

    #[test]
    fn with_key_material_expired_fails() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        let result = mgr.with_key_material(KeyId(0), 1000, |_| ());
        assert_eq!(result, Err(VsError::KeyExpired));
    }

    #[test]
    fn with_key_material_for_validates_purpose() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        // Correct purpose
        let result = mgr.with_key_material_for(
            KeyId(0),
            KeyPurpose::BusAuthentication,
            KeyAlgorithm::Aes256Gcm,
            1500,
            |mat: &[u8]| mat.len(),
        );
        assert_eq!(result, Ok(32));
        // Wrong purpose
        let result = mgr.with_key_material_for(
            KeyId(0),
            KeyPurpose::OtaUpdate,
            KeyAlgorithm::Aes256Gcm,
            1500,
            |_: &[u8]| (),
        );
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    // -----------------------------------------------------------------------
    // Capacity, expiry, and boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn provision_all_64_slots_then_65th_fails() {
        let mut mgr = new_mgr();
        for i in 0..MAX_KEYS {
            let meta = make_metadata(KeyId(i as u32));
            mgr.provision_key(KeyId(i as u32), meta, &test_key(i as u8))
                .unwrap_or_else(|e| panic!("provision slot {i} failed: {e:?}"));
        }
        let meta = make_metadata(KeyId(64));
        let result = mgr.provision_key(KeyId(64), meta, &test_key(0xAA));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn get_metadata_empty_slot_returns_none() {
        let mgr = new_mgr();
        for i in 0..MAX_KEYS {
            assert!(mgr.get_metadata(KeyId(i as u32)).is_none());
        }
    }

    #[test]
    fn revoke_then_is_key_valid_returns_false() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        assert!(mgr.is_key_valid(KeyId(0), 500));
        mgr.revoke_key(KeyId(0), 2000).expect("revoke");
        assert!(!mgr.is_key_valid(KeyId(0), 500));
        assert!(!mgr.is_key_valid(KeyId(0), 0));
        assert!(!mgr.is_key_valid(KeyId(0), u64::MAX));
    }

    #[test]
    fn key_with_no_expiry_always_valid() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 0,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        assert!(mgr.is_key_valid(KeyId(0), 0));
        assert!(mgr.is_key_valid(KeyId(0), 1_000_000));
        assert!(mgr.is_key_valid(KeyId(0), u64::MAX));
    }

    #[test]
    fn key_expiry_boundary_exactly_at_expiry() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::HmacSha256,
            purpose: KeyPurpose::TelemetryEncryption,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        assert!(mgr.is_key_valid(KeyId(0), 999));
        assert!(!mgr.is_key_valid(KeyId(0), 1000));
        assert!(!mgr.is_key_valid(KeyId(0), 1001));
    }

    #[test]
    fn key_out_of_bounds_id() {
        let mgr = new_mgr();
        assert!(!mgr.is_key_valid(KeyId(64), 0));
        assert!(mgr.get_metadata(KeyId(64)).is_none());
    }

    #[test]
    fn tick_with_no_expiring_keys() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::EcdsaP256,
            purpose: KeyPurpose::FirmwareVerification,
            created_at: 100,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.tick(1_000_000);
        assert!(mgr.is_key_valid(KeyId(0), 1_000_000));
    }

    #[test]
    fn audit_entry_out_of_bounds() {
        let mgr = new_mgr();
        assert!(mgr.get_audit_entry(0).is_none());
        assert!(mgr.get_audit_entry(999).is_none());
    }

    #[test]
    fn get_key_material_checks_expiry() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        assert!(mgr.get_key_material(KeyId(0), 999).is_ok());
        assert_eq!(
            mgr.get_key_material(KeyId(0), 1000),
            Err(VsError::KeyExpired)
        );
    }

    #[test]
    fn get_key_material_for_validates_purpose_and_expiry() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        assert!(mgr
            .get_key_material_for(
                KeyId(0),
                KeyPurpose::BusAuthentication,
                KeyAlgorithm::Aes256Gcm,
                500
            )
            .is_ok());
        assert_eq!(
            mgr.get_key_material_for(
                KeyId(0),
                KeyPurpose::OtaUpdate,
                KeyAlgorithm::Aes256Gcm,
                500
            ),
            Err(VsError::PolicyViolation)
        );
        assert_eq!(
            mgr.get_key_material_for(
                KeyId(0),
                KeyPurpose::BusAuthentication,
                KeyAlgorithm::Aes256Gcm,
                1000
            ),
            Err(VsError::KeyExpired)
        );
    }

    #[test]
    fn expected_key_len_matches_algorithms() {
        assert_eq!(KeyAlgorithm::Aes128Gcm.expected_key_len(), 16);
        assert_eq!(KeyAlgorithm::Aes256Gcm.expected_key_len(), 32);
        assert_eq!(KeyAlgorithm::HmacSha256.expected_key_len(), 32);
        assert_eq!(KeyAlgorithm::EcdsaP256.expected_key_len(), 32);
        assert_eq!(KeyAlgorithm::EcdhP256.expected_key_len(), 32);
    }

    // -----------------------------------------------------------------------
    // Multi-slot tests
    // -----------------------------------------------------------------------

    #[test]
    fn provision_rotate_different_slots_concurrently() {
        let mut mgr = new_mgr();
        for i in 0..5u32 {
            let meta = KeyMetadata {
                key_id: KeyId(i),
                algorithm: KeyAlgorithm::Aes256Gcm,
                purpose: KeyPurpose::BusAuthentication,
                created_at: 1000 + u64::from(i),
                expires_at: None,
                rotation_count: 0,
                cumulative_nonce_count: 0,
            };
            mgr.provision_key(KeyId(i), meta, &test_key(i as u8))
                .expect("provision");
        }
        mgr.rotate_key(KeyId(0), &test_key(0xB0), 2000, None)
            .expect("rotate 0");
        mgr.rotate_key(KeyId(2), &test_key(0xC0), 2001, None)
            .expect("rotate 2");
        mgr.rotate_key(KeyId(4), &test_key(0xD0), 2002, None)
            .expect("rotate 4");
        mgr.rotate_key(KeyId(0), &test_key(0xE0), 2003, None)
            .expect("rotate 0 again");
        mgr.rotate_key(KeyId(2), &test_key(0xF0), 2004, None)
            .expect("rotate 2 again");
        assert_eq!(mgr.get_metadata(KeyId(0)).unwrap().rotation_count, 2);
        assert_eq!(mgr.get_metadata(KeyId(1)).unwrap().rotation_count, 0);
        assert_eq!(mgr.get_metadata(KeyId(2)).unwrap().rotation_count, 2);
        assert_eq!(mgr.get_metadata(KeyId(3)).unwrap().rotation_count, 0);
        assert_eq!(mgr.get_metadata(KeyId(4)).unwrap().rotation_count, 1);
    }

    // -----------------------------------------------------------------------
    // AUTOSAR interface tests
    // -----------------------------------------------------------------------

    #[test]
    fn autosar_keym_interface() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(5));
        mgr.keym_key_element_set(KeyId(5), meta, &test_key(0xEE))
            .expect("set");
        let got = mgr.keym_key_element_get(KeyId(5)).expect("get");
        assert_eq!(got.key_id, KeyId(5));
        mgr.keym_update(KeyId(5), &test_key(0xFF), 2000)
            .expect("update");
        let got = mgr
            .keym_key_element_get(KeyId(5))
            .expect("get after update");
        assert_eq!(got.rotation_count, 1);
    }

    #[test]
    fn autosar_keym_update_nonexistent_key_fails() {
        let mut mgr = new_mgr();
        let result = mgr.keym_update(KeyId(10), &test_key(0xFF), 1000);
        assert_eq!(result, Err(VsError::NotInitialized));
    }

    #[test]
    fn autosar_keym_start() {
        let mgr = new_mgr();
        assert!(mgr.keym_start());
    }

    #[test]
    fn autosar_keym_finalize_zeroizes_all() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        let meta1 = make_metadata(KeyId(1));
        mgr.provision_key(KeyId(1), meta1, &test_key(0xBB)).unwrap();
        mgr.keym_finalize();
        assert!(mgr.get_metadata(KeyId(0)).is_none());
        assert!(mgr.get_metadata(KeyId(1)).is_none());
        assert!(!mgr.is_key_valid(KeyId(0), 500));
        assert!(!mgr.is_key_valid(KeyId(1), 500));
    }

    // -----------------------------------------------------------------------
    // Revocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn get_metadata_on_revoked_key() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::HmacSha256,
            purpose: KeyPurpose::TelemetryEncryption,
            created_at: 100,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.revoke_key(KeyId(0), 2000).unwrap();
        assert!(mgr.get_metadata(KeyId(0)).is_some());
    }

    #[test]
    fn provision_revoked_slot_fails() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.revoke_key(KeyId(0), 2000).unwrap();
        let meta2 = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 200,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        assert_eq!(
            mgr.provision_key(KeyId(0), meta2, &test_key(0xBB)),
            Err(VsError::KeyRevoked)
        );
    }

    // -----------------------------------------------------------------------
    // Key validity at exact expiry
    // -----------------------------------------------------------------------

    #[test]
    fn key_validity_at_exact_expiry() {
        let mut mgr = new_mgr();
        let meta = KeyMetadata {
            key_id: KeyId(0),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 100,
            expires_at: Some(1000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        assert!(mgr.is_key_valid(KeyId(0), 999));
        assert!(!mgr.is_key_valid(KeyId(0), 1000));
        assert!(!mgr.is_key_valid(KeyId(0), 1001));
    }

    // -----------------------------------------------------------------------
    // Audit log capacity wrap + verification
    // -----------------------------------------------------------------------

    #[test]
    fn audit_log_capacity_wrap_verification() {
        let mut mgr = new_mgr();
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision");
        for i in 0..300u64 {
            mgr.rotate_key(KeyId(0), &test_key((i & 0xFF) as u8), 2000 + i, None)
                .expect("rotate");
        }
        assert_eq!(mgr.audit_count(), 301);
        let head_idx = 301 % AUDIT_CAPACITY;
        let latest_idx = if head_idx == 0 {
            AUDIT_CAPACITY - 1
        } else {
            head_idx - 1
        };
        let latest = mgr.get_audit_entry(latest_idx).expect("latest entry");
        assert_eq!(latest.sequence, 300);
        assert_eq!(latest.event_type, AuditEventType::KeyRotated);
    }

    // -----------------------------------------------------------------------
    // Algorithm and purpose enum coverage
    // -----------------------------------------------------------------------

    #[test]
    fn key_algorithm_and_purpose_enum_coverage() {
        let algos = [
            KeyAlgorithm::Aes128Gcm,
            KeyAlgorithm::Aes256Gcm,
            KeyAlgorithm::HmacSha256,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdhP256,
        ];
        for (i, a) in algos.iter().enumerate() {
            assert_eq!(*a, algos[i]);
            for (j, b) in algos.iter().enumerate() {
                if i != j {
                    assert_ne!(*a, *b);
                }
            }
        }
        let purposes = [
            KeyPurpose::BusAuthentication,
            KeyPurpose::FirmwareVerification,
            KeyPurpose::DiagnosticSession,
            KeyPurpose::TelemetryEncryption,
            KeyPurpose::OtaUpdate,
        ];
        for (i, p) in purposes.iter().enumerate() {
            assert_eq!(*p, purposes[i]);
            for (j, q) in purposes.iter().enumerate() {
                if i != j {
                    assert_ne!(*p, *q);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Debug redaction test
    // -----------------------------------------------------------------------

    #[test]
    fn debug_output_redacts_key_material() {
        let mut entry = KeyEntry::default();
        entry.material = test_key(0xAA);
        entry.material_len = 32;
        entry.state = KeyState::Active;
        let debug = format!("{:?}", entry);
        assert!(debug.contains("[REDACTED]"));
        // Must not contain any hex representation of the key
        assert!(!debug.contains("0xAA"));
        assert!(!debug.contains("170")); // decimal of 0xAA
    }

    // -----------------------------------------------------------------------
    // KeyMetadata PartialEq test
    // -----------------------------------------------------------------------

    #[test]
    fn key_metadata_partial_eq() {
        let a = make_metadata(KeyId(0));
        let b = make_metadata(KeyId(0));
        assert_eq!(a, b);
        let c = make_metadata(KeyId(1));
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // Crypto provider accessor test
    // -----------------------------------------------------------------------

    #[test]
    fn crypto_provider_accessible() {
        let mgr = new_mgr();
        // Verify we can access the crypto provider
        let mut buf = [0u8; 16];
        mgr.crypto().random_bytes(&mut buf).expect("random");
        // Provider should produce non-zero output
        assert!(buf.iter().any(|&b| b != 0));
    }

    // -----------------------------------------------------------------------
    // get_key_material returns NotFound for out-of-range
    // -----------------------------------------------------------------------

    #[test]
    fn get_key_material_out_of_range_returns_not_found() {
        let mgr = new_mgr();
        assert_eq!(mgr.get_key_material(KeyId(100), 0), Err(VsError::NotFound));
    }

    #[test]
    fn get_key_material_for_out_of_range_returns_not_found() {
        let mgr = new_mgr();
        assert_eq!(
            mgr.get_key_material_for(
                KeyId(100),
                KeyPurpose::BusAuthentication,
                KeyAlgorithm::Aes256Gcm,
                0
            ),
            Err(VsError::NotFound)
        );
    }

    // -----------------------------------------------------------------------
    // Security fix tests
    // -----------------------------------------------------------------------

    #[test]
    fn rotate_key_updates_timestamps() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        let meta = KeyMetadata {
            key_id: kid,
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: Some(5000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        mgr.provision_key(kid, meta, &test_key(1)).unwrap();
        mgr.rotate_key(kid, &test_key(2), 4000, Some(9000)).unwrap();
        let m = mgr.get_metadata(kid).unwrap();
        assert_eq!(m.created_at, 4000);
        assert_eq!(m.expires_at, Some(9000));
        assert_eq!(m.rotation_count, 1);
    }

    #[test]
    fn keym_start_healthy_returns_true() {
        let mgr = new_mgr();
        assert!(mgr.keym_start());
    }

    #[test]
    fn keym_finalize_zeroizes_metadata() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        mgr.keym_finalize();
        assert!(mgr.get_metadata(kid).is_none());
    }

    #[test]
    fn keym_key_generate_works() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(5);
        let meta = make_metadata(kid);
        assert!(mgr.keym_key_generate(kid, meta).is_ok());
        assert!(mgr.is_key_valid(kid, 500));
    }

    // -----------------------------------------------------------------------
    // V4: keym_start explicit audit integrity error handling
    // -----------------------------------------------------------------------

    #[test]
    fn keym_start_fresh_manager_passes() {
        let mgr = new_mgr();
        // Fresh manager has a valid (empty) audit chain.
        assert!(mgr.keym_start());
    }

    #[test]
    fn keym_start_after_provision_passes() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        assert!(mgr.keym_start());
    }

    // -----------------------------------------------------------------------
    // V5: max rotation count enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn max_rotation_count_enforced() {
        let mut mgr = new_mgr();
        mgr.set_max_rotation_count(2);
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        // Rotation 1 — ok
        mgr.rotate_key(kid, &test_key(2), 2000, None).unwrap();
        // Rotation 2 — ok (count is now 2)
        mgr.rotate_key(kid, &test_key(3), 3000, None).unwrap();
        // Rotation 3 — should fail: count (2) >= max (2)
        assert_eq!(
            mgr.rotate_key(kid, &test_key(4), 4000, None),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn max_rotation_count_none_allows_many() {
        let mut mgr = new_mgr();
        // No limit set — should allow many rotations.
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        for i in 2..20u8 {
            mgr.rotate_key(kid, &test_key(i), 1000 + u64::from(i), None)
                .unwrap();
        }
        assert_eq!(mgr.get_metadata(kid).unwrap().rotation_count, 18);
    }

    #[test]
    fn max_rotation_count_zero_blocks_all_rotations() {
        let mut mgr = new_mgr();
        mgr.set_max_rotation_count(0);
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        assert_eq!(
            mgr.rotate_key(kid, &test_key(2), 2000, None),
            Err(VsError::ResourceExhausted)
        );
    }

    // -----------------------------------------------------------------------
    // Nonce-space exhaustion tests
    // -----------------------------------------------------------------------

    #[test]
    fn record_nonce_usage_increments_counter() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();

        mgr.record_nonce_usage(kid, 100).unwrap();
        assert_eq!(mgr.get_metadata(kid).unwrap().cumulative_nonce_count, 100);

        mgr.record_nonce_usage(kid, 50).unwrap();
        assert_eq!(mgr.get_metadata(kid).unwrap().cumulative_nonce_count, 150);
    }

    #[test]
    fn record_nonce_usage_overflow_returns_error() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();

        mgr.record_nonce_usage(kid, u64::MAX).unwrap();
        assert_eq!(
            mgr.record_nonce_usage(kid, 1),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn record_nonce_usage_rejects_empty_slot() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        assert_eq!(mgr.record_nonce_usage(kid, 1), Err(VsError::NotInitialized));
    }

    #[test]
    fn record_nonce_usage_rejects_revoked_key() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();
        mgr.revoke_key(kid, 2000).unwrap();
        assert_eq!(mgr.record_nonce_usage(kid, 1), Err(VsError::KeyRevoked));
    }

    #[test]
    fn rotate_blocked_when_nonce_space_exhausted() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();

        // Push the cumulative nonce count past the AES-GCM limit (2^32).
        mgr.record_nonce_usage(kid, u32::MAX as u64 + 1).unwrap();

        assert_eq!(
            mgr.rotate_key(kid, &test_key(2), 2000, None),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn rotate_allowed_when_nonce_count_at_limit() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();

        // Exactly at the limit (2^32 - 1) should still be allowed.
        mgr.record_nonce_usage(kid, u32::MAX as u64).unwrap();

        assert!(mgr.rotate_key(kid, &test_key(2), 2000, None).is_ok());
    }

    #[test]
    fn nonce_count_persists_across_rotation() {
        let mut mgr = new_mgr();
        let kid = KeyId::new(0);
        mgr.provision_key(kid, make_metadata(kid), &test_key(1))
            .unwrap();

        mgr.record_nonce_usage(kid, 500).unwrap();
        mgr.rotate_key(kid, &test_key(2), 2000, None).unwrap();

        // The cumulative count must survive the rotation.
        assert_eq!(mgr.get_metadata(kid).unwrap().cumulative_nonce_count, 500);
    }

    #[test]
    fn provision_key_zeroizing_clears_source() {
        let mut mgr = new_mgr();
        let mut material = test_key(0xAB);
        let metadata = make_metadata(KeyId(0));
        mgr.provision_key_zeroizing(KeyId(0), metadata, &mut material)
            .unwrap();
        assert!(
            material.iter().all(|&b| b == 0),
            "source material must be zeroized"
        );
    }

    #[test]
    fn provision_key_zeroizing_clears_source_on_failure() {
        let mut mgr = new_mgr();
        // Use an invalid key length to trigger a failure
        let mut material = [0xAB; 7];
        let metadata = make_metadata(KeyId(0));
        let _ = mgr.provision_key_zeroizing(KeyId(0), metadata, &mut material);
        assert!(
            material.iter().all(|&b| b == 0),
            "source material must be zeroized even on failure"
        );
    }

    // -----------------------------------------------------------------------
    // Audit crypto-failure fail-closed tests (H1/H2)
    // -----------------------------------------------------------------------

    #[test]
    fn provision_key_crypto_failure_aborts_without_mutation() {
        let mut mgr = KeyManager::new(FailingCrypto::new());
        mgr.crypto().set_fail(true);
        let meta = make_metadata(KeyId(0));
        // A crypto failure during the audit chain step must abort the whole
        // operation with CryptoError.
        assert_eq!(
            mgr.provision_key(KeyId(0), meta, &test_key(0xAA)),
            Err(VsError::CryptoError)
        );
        // The slot must NOT have been mutated.
        assert!(mgr.get_metadata(KeyId(0)).is_none());
        assert!(!mgr.is_key_valid(KeyId(0), 1500));
        assert_eq!(mgr.audit_count(), 0);
        // After recovery the operation succeeds and the audit chain verifies.
        mgr.crypto().set_fail(false);
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA))
            .expect("provision after recovery");
        assert_eq!(mgr.audit_count(), 1);
        assert!(mgr.verify_audit_integrity().expect("verify"));
    }

    #[test]
    fn rotate_key_crypto_failure_preserves_existing_key() {
        let mut mgr = KeyManager::new(FailingCrypto::new());
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.crypto().set_fail(true);
        // Rotation must fail closed: existing key material stays intact.
        assert_eq!(
            mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None),
            Err(VsError::CryptoError)
        );
        assert_eq!(mgr.get_metadata(KeyId(0)).unwrap().rotation_count, 0);
        // The original key material must still be present and usable.
        mgr.crypto().set_fail(false);
        let mat = mgr.get_key_material(KeyId(0), 1500).expect("original key");
        assert_eq!(mat, &test_key(0xAA));
    }

    #[test]
    fn revoke_key_crypto_failure_aborts_without_mutation() {
        let mut mgr = KeyManager::new(FailingCrypto::new());
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        mgr.crypto().set_fail(true);
        assert_eq!(
            mgr.revoke_key(KeyId(0), 2000),
            Err(VsError::CryptoError)
        );
        // Slot must remain active, not revoked.
        assert!(mgr.is_key_valid(KeyId(0), 1500));
        mgr.crypto().set_fail(false);
        assert!(mgr.get_key_material(KeyId(0), 1500).is_ok());
    }

    #[test]
    fn generate_key_crypto_failure_aborts_without_mutation() {
        let mut mgr = KeyManager::new(FailingCrypto::new());
        mgr.crypto().set_fail(true);
        let meta = make_metadata(KeyId(0));
        assert_eq!(
            mgr.generate_key(KeyId(0), meta),
            Err(VsError::CryptoError)
        );
        assert!(mgr.get_metadata(KeyId(0)).is_none());
        assert_eq!(mgr.audit_count(), 0);
    }

    #[test]
    fn audit_count_never_advances_on_crypto_failure() {
        // A crypto failure must never commit an audit entry: audit_count
        // stays put and no zero-chain entry is left behind.
        let mut mgr = KeyManager::new(FailingCrypto::new());
        let meta = make_metadata(KeyId(0));
        mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
        assert_eq!(mgr.audit_count(), 1);
        mgr.crypto().set_fail(true);
        let _ = mgr.rotate_key(KeyId(0), &test_key(0xBB), 2000, None);
        assert_eq!(mgr.audit_count(), 1, "no audit entry committed on failure");
        // Existing committed entries still verify.
        mgr.crypto().set_fail(false);
        assert!(mgr.verify_audit_integrity().expect("verify"));
    }
}
