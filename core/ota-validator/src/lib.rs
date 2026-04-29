// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! OTA update security validation following TUF/Uptane principles.
//!
//! Provides threshold-of-N signature verification for root metadata,
//! rollback protection via monotonic version counters, and firmware
//! target hash verification.
//!
//! # Public API (v1.0 stable)
//!
//! The `OtaValidator` / `PersistentOtaValidator` / `HsmOtaValidator` types
//! and their `verify_*` methods, the standalone `verify_role_metadata` /
//! `verify_timestamp` / `verify_snapshot` / `verify_targets` /
//! `verify_vehicle_manifest` functions, and the `TufRoot` / `TufTimestamp`
//! / `TufSnapshot` / `TufTargets` / `SignedMetadata` / `VehicleManifest`
//! types form the v1.0 stable surface; breaking changes to them follow
//! the workspace semantic-versioning policy.

use vs_crypto::CryptoProvider;
use vs_storage::StorageProvider;
use vs_types::VsError;

#[cfg(feature = "json")]
pub mod json;

pub mod rollback;
pub use rollback::{HsmRollbackCounter, RollbackCounter, SoftwareRollbackCounter};

// ---------------------------------------------------------------------------
// Constant-time comparison helper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Cryptographic algorithm used by a TUF key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum KeyType {
    /// NIST P-256 (secp256r1) ECDSA.
    EcdsaP256,
}

/// A public key used inside TUF metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TufKey {
    /// SHA-256 fingerprint of the public key material.
    pub key_id: [u8; 32],
    /// Algorithm family.
    pub key_type: KeyType,
    /// Uncompressed SEC1 P-256 public point (0x04 || X || Y).
    pub public_key: [u8; 65],
}

/// TUF metadata role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum TufRole {
    /// The root of trust; signs the keys/thresholds for all other roles.
    Root,
    /// Targets metadata; lists firmware images available for installation.
    Targets,
    /// Snapshot metadata; pins the current version of the targets file.
    Snapshot,
    /// Timestamp metadata; short-lived freshness indicator pointing at
    /// the current snapshot.
    Timestamp,
}

/// Trusted root metadata – the anchor of the TUF chain of trust.
///
/// Defines the signing keys and thresholds for every TUF role.
/// Per-role keys default to empty; when empty, the root keys are
/// used as a fallback for that role.
#[derive(Debug, Clone)]
pub struct TufRoot {
    /// Monotonically increasing version number.
    pub version: u32,
    /// Expiration timestamp in microseconds since epoch.
    pub expires_us: u64,
    /// Up to 4 root signing keys.
    pub root_keys: [Option<TufKey>; 4],
    /// Minimum number of valid root signatures required.
    pub threshold: u8,

    // -- Per-role delegation keys -----------------------------------------
    /// Keys authorized to sign targets metadata.
    pub targets_keys: [Option<TufKey>; 4],
    /// Minimum number of valid signatures required for targets metadata.
    pub targets_threshold: u8,
    /// Keys authorized to sign snapshot metadata.
    pub snapshot_keys: [Option<TufKey>; 4],
    /// Minimum number of valid signatures required for snapshot metadata.
    pub snapshot_threshold: u8,
    /// Keys authorized to sign timestamp metadata.
    pub timestamp_keys: [Option<TufKey>; 4],
    /// Minimum number of valid signatures required for timestamp metadata.
    pub timestamp_threshold: u8,
}

impl TufRoot {
    /// Return the signing keys and threshold for the given role.
    ///
    /// Falls back to root keys if the role-specific keys are all `None`.
    pub fn keys_for_role(&self, role: TufRole) -> (&[Option<TufKey>; 4], u8) {
        let (keys, threshold) = match role {
            TufRole::Root => (&self.root_keys, self.threshold),
            TufRole::Targets => (&self.targets_keys, self.targets_threshold),
            TufRole::Snapshot => (&self.snapshot_keys, self.snapshot_threshold),
            TufRole::Timestamp => (&self.timestamp_keys, self.timestamp_threshold),
        };
        if keys.iter().any(Option::is_some) {
            (keys, threshold)
        } else {
            (&self.root_keys, self.threshold)
        }
    }
}

/// A single cryptographic signature attached to metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TufSignature {
    /// Key ID that produced the signature.
    pub key_id: [u8; 32],
    /// Raw P-256 signature (r || s), 32 bytes each.
    pub sig: [u8; 64],
}

/// Signed metadata wrapper carrying up to 4 signatures.
#[derive(Debug, Clone)]
pub struct SignedMetadata {
    /// Metadata version number.
    pub version: u32,
    /// Expiration timestamp in microseconds since epoch.
    pub expires_us: u64,
    /// Up to 4 detached signatures over `content_hash`.
    pub signatures: [Option<TufSignature>; 4],
    /// SHA-256 digest of the canonical metadata content.
    pub content_hash: [u8; 32],
}

/// Uptane vehicle manifest reported by the primary ECU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VehicleManifest {
    /// 17-byte ASCII VIN.
    pub vin: [u8; 17],
    /// Unique serial of the primary ECU.
    pub primary_ecu_serial: [u8; 32],
    /// Currently installed firmware version.
    pub installed_version: u32,
    /// Timestamp of this report in microseconds since epoch.
    pub report_time_us: u64,
}

impl VehicleManifest {
    /// Compute SHA-256 hash of the manifest fields (canonical byte representation).
    ///
    /// Serializes fields in fixed order: `vin || ecu_serial || version_le || time_le`.
    pub fn hash(&self, crypto: &impl CryptoProvider) -> Result<[u8; 32], VsError> {
        let mut buf = [0u8; 17 + 32 + 4 + 8]; // 61 bytes
        buf[..17].copy_from_slice(&self.vin);
        buf[17..49].copy_from_slice(&self.primary_ecu_serial);
        buf[49..53].copy_from_slice(&self.installed_version.to_le_bytes());
        buf[53..61].copy_from_slice(&self.report_time_us.to_le_bytes());
        let mut hash = [0u8; 32];
        crypto.sha256(&buf, &mut hash)?;
        Ok(hash)
    }

    /// Verify a P-256 signature over this manifest.
    pub fn verify(
        &self,
        sig: &[u8; 64],
        key: &TufKey,
        crypto: &impl CryptoProvider,
    ) -> Result<(), VsError> {
        let hash = self.hash(crypto)?;
        verify_vehicle_manifest(&hash, sig, key, crypto)
    }
}

// ---------------------------------------------------------------------------
// TUF delegation metadata types
// ---------------------------------------------------------------------------

/// TUF Timestamp metadata — short-lived freshness indicator.
///
/// Points to the current snapshot version and hash. This is the first
/// metadata file fetched during an update check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TufTimestamp {
    /// Monotonically increasing version number for this timestamp.
    pub version: u32,
    /// Expiration timestamp in microseconds since epoch.
    pub expires_us: u64,
    /// Version of the snapshot metadata this timestamp pins.
    pub snapshot_version: u32,
    /// SHA-256 digest of the snapshot metadata this timestamp pins.
    pub snapshot_hash: [u8; 32],
}

/// TUF Snapshot metadata — lists current version of targets metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TufSnapshot {
    /// Monotonically increasing version number for this snapshot.
    pub version: u32,
    /// Expiration timestamp in microseconds since epoch.
    pub expires_us: u64,
    /// Version of the targets metadata this snapshot pins.
    pub targets_version: u32,
    /// SHA-256 digest of the targets metadata this snapshot pins.
    pub targets_hash: [u8; 32],
}

/// A single firmware target entry in the targets metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TufTargetEntry {
    /// SHA-256 hash of the firmware image.
    pub hash: [u8; 32],
    /// Expected byte length of the firmware image.
    pub length: u64,
    /// Target identifier (e.g. ECU hardware ID), up to 32 bytes.
    pub target_id: [u8; 32],
    /// Number of valid bytes in `target_id`.
    pub target_id_len: u8,
}

/// TUF Targets metadata — lists firmware images available for installation.
#[derive(Debug, Clone)]
pub struct TufTargets {
    /// Monotonically increasing version number for this targets file.
    pub version: u32,
    /// Expiration timestamp in microseconds since epoch.
    pub expires_us: u64,
    /// Up to 8 target entries.
    pub targets: [Option<TufTargetEntry>; 8],
}

// ---------------------------------------------------------------------------
// Standalone TUF verification helpers
// ---------------------------------------------------------------------------

/// Count how many signatures in `metadata` can be verified against `keys`.
///
/// Tracks both used key **indices** and used **key_id** values to prevent
/// double-counting when two array entries share the same `key_id` (a
/// misconfiguration that would otherwise let one physical key satisfy
/// multiple threshold slots).
fn count_valid_sigs(
    metadata: &SignedMetadata,
    keys: &[Option<TufKey>; 4],
    crypto: &impl CryptoProvider,
) -> Result<u8, VsError> {
    let mut valid: u8 = 0;
    let mut used_keys = [false; 4]; // Track which key indices already contributed
    let mut used_key_ids: [Option<[u8; 32]>; 4] = [None; 4]; // Track key_id values
    let mut used_key_id_count: usize = 0;
    for sig_slot in &metadata.signatures {
        let Some(sig) = sig_slot else { continue };
        for (key_idx, key_slot) in keys.iter().enumerate() {
            let Some(key) = key_slot else { continue };
            if used_keys[key_idx] {
                continue; // This key index already contributed a valid signature
            }
            if key.key_id == sig.key_id {
                // Check if this key_id was already used by a different array
                // entry (misconfiguration: duplicate key_id in the key array).
                let mut key_id_already_used = false;
                for uid in used_key_ids.iter().take(used_key_id_count).flatten() {
                    if vs_types::constant_time_eq_32(uid, &key.key_id) {
                        key_id_already_used = true;
                        break;
                    }
                }
                if key_id_already_used {
                    break;
                }

                let verified =
                    crypto.verify_p256(&key.public_key, &metadata.content_hash, &sig.sig)?;
                if verified {
                    valid = valid.saturating_add(1);
                    used_keys[key_idx] = true;
                    if used_key_id_count < 4 {
                        used_key_ids[used_key_id_count] = Some(key.key_id);
                        used_key_id_count += 1;
                    }
                }
                break;
            }
        }
    }
    Ok(valid)
}

/// Verify a firmware target blob against its expected hash and length.
fn verify_target_impl(
    expected_hash: &[u8; 32],
    expected_length: u64,
    firmware_bytes: &[u8],
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    // Use constant-time comparison for firmware length to maintain
    // consistent timing discipline, even though length is not secret
    // in most threat models.
    let len_matches: bool = {
        let actual = (firmware_bytes.len() as u64).to_le_bytes();
        let expected = expected_length.to_le_bytes();
        use subtle::ConstantTimeEq;
        bool::from(actual.ct_eq(&expected))
    };
    if !len_matches {
        return Err(VsError::IntegrityFailure);
    }
    let mut computed_hash = [0u8; 32];
    crypto.sha256(firmware_bytes, &mut computed_hash)?;
    if !vs_types::constant_time_eq_32(&computed_hash, expected_hash) {
        return Err(VsError::IntegrityFailure);
    }
    Ok(())
}

/// Verify signatures and expiration for any TUF role metadata.
#[must_use = "TUF role metadata verification result must not be silently ignored"]
pub fn verify_role_metadata(
    metadata: &SignedMetadata,
    keys: &[Option<TufKey>; 4],
    threshold: u8,
    current_time_us: u64,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    if threshold == 0 {
        return Err(VsError::InvalidConfig);
    }
    if current_time_us >= metadata.expires_us {
        return Err(VsError::AuthenticationFailure);
    }
    let valid = count_valid_sigs(metadata, keys, crypto)?;
    if valid < threshold {
        return Err(VsError::AuthenticationFailure);
    }
    Ok(())
}

/// Verify TUF timestamp metadata.
#[must_use = "TUF timestamp verification result must not be silently ignored"]
pub fn verify_timestamp(
    metadata: &SignedMetadata,
    timestamp: &TufTimestamp,
    root: &TufRoot,
    current_time_us: u64,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    if metadata.version != timestamp.version {
        return Err(VsError::IntegrityFailure);
    }
    if metadata.expires_us != timestamp.expires_us {
        return Err(VsError::IntegrityFailure);
    }
    let (keys, threshold) = root.keys_for_role(TufRole::Timestamp);
    verify_role_metadata(metadata, keys, threshold, current_time_us, crypto)
}

/// Verify TUF snapshot metadata, cross-referencing the timestamp.
#[must_use = "TUF snapshot verification result must not be silently ignored"]
pub fn verify_snapshot(
    metadata: &SignedMetadata,
    snapshot: &TufSnapshot,
    timestamp: &TufTimestamp,
    root: &TufRoot,
    current_time_us: u64,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    if snapshot.version != timestamp.snapshot_version {
        return Err(VsError::IntegrityFailure);
    }
    // Bind the freshness window on the struct to the one that was signed,
    // for parity with `verify_timestamp` (TUF metadata-consistency rule).
    if metadata.expires_us != snapshot.expires_us {
        return Err(VsError::IntegrityFailure);
    }
    if !vs_types::constant_time_eq_32(&metadata.content_hash, &timestamp.snapshot_hash) {
        return Err(VsError::IntegrityFailure);
    }
    let (keys, threshold) = root.keys_for_role(TufRole::Snapshot);
    verify_role_metadata(metadata, keys, threshold, current_time_us, crypto)
}

/// Verify TUF targets metadata, cross-referencing the snapshot.
#[must_use = "TUF targets verification result must not be silently ignored"]
pub fn verify_targets(
    metadata: &SignedMetadata,
    targets: &TufTargets,
    snapshot: &TufSnapshot,
    root: &TufRoot,
    current_time_us: u64,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    if targets.version != snapshot.targets_version {
        return Err(VsError::IntegrityFailure);
    }
    // Bind the freshness window on the struct to the one that was signed,
    // for parity with `verify_timestamp` (TUF metadata-consistency rule).
    if metadata.expires_us != targets.expires_us {
        return Err(VsError::IntegrityFailure);
    }
    if !vs_types::constant_time_eq_32(&metadata.content_hash, &snapshot.targets_hash) {
        return Err(VsError::IntegrityFailure);
    }
    let (keys, threshold) = root.keys_for_role(TufRole::Targets);
    verify_role_metadata(metadata, keys, threshold, current_time_us, crypto)
}

/// Find a target entry by its identifier.
pub fn find_target_entry<'a>(
    targets: &'a TufTargets,
    target_id: &[u8],
) -> Result<&'a TufTargetEntry, VsError> {
    for entry in targets.targets.iter().flatten() {
        let id_len = entry.target_id_len as usize;
        if id_len <= 32 && entry.target_id[..id_len] == *target_id {
            return Ok(entry);
        }
    }
    Err(VsError::NotFound)
}

// ---------------------------------------------------------------------------
// Common root update verification logic
// ---------------------------------------------------------------------------

/// Verify a root metadata update against the current trusted root.
///
/// Checks:
/// 1. `new_root` fields are consistent with `new_metadata`.
/// 2. New root has a valid threshold (> 0).
/// 3. Version strictly greater than the current root (rollback protection).
/// 4. Metadata has not expired (`current_time_us < expires_us`).
/// 5. Threshold-of-N signatures from the **current** trusted root keys.
/// 6. Threshold-of-N signatures from the **new** root keys (cross-verification).
fn verify_root_update_common(
    new_metadata: &SignedMetadata,
    new_root: &TufRoot,
    current_time_us: u64,
    trusted_root: &TufRoot,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    // --- Consistency: new_root must match new_metadata ---
    if new_root.version != new_metadata.version {
        return Err(VsError::IntegrityFailure);
    }
    if new_root.expires_us != new_metadata.expires_us {
        return Err(VsError::IntegrityFailure);
    }

    // --- New root must have valid threshold ---
    if new_root.threshold == 0 {
        return Err(VsError::InvalidConfig);
    }

    // --- Rollback check (version) ---
    if new_metadata.version <= trusted_root.version {
        return Err(VsError::PolicyViolation);
    }

    // --- Expiration check ---
    if current_time_us >= new_metadata.expires_us {
        return Err(VsError::AuthenticationFailure);
    }

    // --- Threshold signature verification against CURRENT root keys ---
    let valid_sigs = count_valid_sigs(new_metadata, &trusted_root.root_keys, crypto)?;
    if valid_sigs < trusted_root.threshold {
        return Err(VsError::AuthenticationFailure);
    }

    // --- Cross-verify against NEW root keys (TUF spec requirement) ---
    let new_valid = count_valid_sigs(new_metadata, &new_root.root_keys, crypto)?;
    if new_valid < new_root.threshold {
        return Err(VsError::AuthenticationFailure);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role rollback tracking (TUF §5.4–5.6)
// ---------------------------------------------------------------------------

/// Per-role monotonic version floors enforced by the stateful validators.
///
/// Tracks the highest previously-verified version of the timestamp,
/// snapshot, and targets metadata. A new metadata blob is accepted only
/// when its `version` strictly exceeds the recorded floor for its role,
/// preventing a freeze attacker from replaying still-valid older metadata
/// to stall updates indefinitely.
#[derive(Debug, Default)]
struct RoleVersionState {
    // Encoding: 0 = None, v+1 = Some(v). u32::MAX is unrepresentable but TUF
    // version space is well below that cap. Atomic types are both Send + Sync
    // (Cell<Option<u32>> would block Sync impls in static contexts).
    //
    // Uses AtomicU32 (not AtomicU64) so the struct compiles on targets that
    // lack 64-bit atomics (e.g. thumbv7em-none-eabihf). TUF version numbers
    // are u32 so the +1 encoding fits comfortably.
    timestamp: core::sync::atomic::AtomicU32,
    snapshot: core::sync::atomic::AtomicU32,
    targets: core::sync::atomic::AtomicU32,
}

impl RoleVersionState {
    const fn new() -> Self {
        use core::sync::atomic::AtomicU32;
        Self {
            timestamp: AtomicU32::new(0),
            snapshot: AtomicU32::new(0),
            targets: AtomicU32::new(0),
        }
    }

    fn slot(&self, role: TufRole) -> Option<&core::sync::atomic::AtomicU32> {
        match role {
            TufRole::Timestamp => Some(&self.timestamp),
            TufRole::Snapshot => Some(&self.snapshot),
            TufRole::Targets => Some(&self.targets),
            TufRole::Root => None, // root rollback is enforced separately
        }
    }

    /// Check that `new_version` is strictly greater than the stored floor
    /// for `role` (returns `PolicyViolation` on rollback). Returns Ok on
    /// success without mutating state — call [`Self::record`] only after
    /// the underlying signature and freshness checks have all passed.
    fn check(&self, role: TufRole, new_version: u32) -> Result<(), VsError> {
        let Some(slot) = self.slot(role) else {
            return Ok(());
        };
        let raw = slot.load(core::sync::atomic::Ordering::Acquire);
        if raw > 0 {
            let prev = raw - 1;
            if new_version <= prev {
                return Err(VsError::PolicyViolation);
            }
        }
        Ok(())
    }

    /// Update the recorded floor for `role` to `new_version`. Caller is
    /// responsible for invoking this only after every other verification
    /// step has succeeded.
    fn record(&self, role: TufRole, new_version: u32) {
        let Some(slot) = self.slot(role) else {
            return;
        };
        slot.store(new_version + 1, core::sync::atomic::Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// OtaValidator
// ---------------------------------------------------------------------------

/// Stateful OTA validator implementing TUF root rotation and target
/// verification.
pub struct OtaValidator<C: CryptoProvider> {
    crypto: C,
    trusted_root: TufRoot,
    /// Monotonic rollback counter – only increases.
    rollback_version: u32,
    /// Per-role highest-seen versions for timestamp/snapshot/targets
    /// rollback protection (TUF §5.4–5.6).
    role_versions: RoleVersionState,
}

impl<C: CryptoProvider> OtaValidator<C> {
    /// Create a validator with an initial trusted root.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidConfig`] if the root threshold is zero.
    pub fn new(crypto: C, trusted_root: TufRoot) -> Result<Self, VsError> {
        if trusted_root.threshold == 0 {
            return Err(VsError::InvalidConfig);
        }
        let rollback_version = trusted_root.version;
        Ok(Self {
            crypto,
            trusted_root,
            rollback_version,
            role_versions: RoleVersionState::new(),
        })
    }

    /// Verify and apply a root metadata update.
    ///
    /// Checks:
    /// 1. `new_root` fields consistent with `new_metadata`.
    /// 2. New root has valid threshold (> 0).
    /// 3. Version strictly greater than the current root (rollback protection).
    /// 4. Metadata has not expired (`current_time_us < expires_us`).
    /// 5. Threshold-of-N signatures from the **current** trusted root keys.
    /// 6. Threshold-of-N signatures from the **new** root keys (cross-verification).
    ///
    /// On success the internal trusted root is replaced and the rollback
    /// counter is advanced.
    #[must_use = "TUF root update verification result must not be silently ignored"]
    pub fn verify_root_update(
        &mut self,
        new_metadata: &SignedMetadata,
        new_root: &TufRoot,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        verify_root_update_common(
            new_metadata,
            new_root,
            current_time_us,
            &self.trusted_root,
            &self.crypto,
        )?;

        // --- All checks passed – update state ---
        self.trusted_root = new_root.clone();
        self.rollback_version = self.rollback_version.max(new_metadata.version);

        Ok(())
    }

    /// Verify a firmware target blob against its expected hash and length.
    #[must_use = "firmware target verification result must not be silently ignored"]
    pub fn verify_target(
        &self,
        expected_hash: &[u8; 32],
        expected_length: u64,
        firmware_bytes: &[u8],
    ) -> Result<(), VsError> {
        verify_target_impl(expected_hash, expected_length, firmware_bytes, &self.crypto)
    }

    /// Return the current rollback version counter.
    pub fn rollback_version(&self) -> u32 {
        self.rollback_version
    }

    /// Verify TUF timestamp metadata against the trusted root.
    ///
    /// In addition to signature and expiry checks, this method enforces
    /// monotonic per-role rollback: every successfully verified timestamp
    /// must carry a `version` strictly greater than the previous one.
    /// Replaying an older (but still-valid) timestamp is rejected with
    /// [`VsError::PolicyViolation`].
    pub fn verify_timestamp(
        &self,
        metadata: &SignedMetadata,
        timestamp: &TufTimestamp,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        crate::verify_timestamp(
            metadata,
            timestamp,
            &self.trusted_root,
            current_time_us,
            &self.crypto,
        )?;
        self.role_versions
            .check(TufRole::Timestamp, metadata.version)?;
        self.role_versions
            .record(TufRole::Timestamp, metadata.version);
        Ok(())
    }

    /// Verify TUF snapshot metadata, cross-referencing the timestamp.
    ///
    /// Enforces monotonic per-role rollback in addition to the standard
    /// signature/expiry/cross-reference checks. See [`Self::verify_timestamp`].
    pub fn verify_snapshot(
        &self,
        metadata: &SignedMetadata,
        snapshot: &TufSnapshot,
        timestamp: &TufTimestamp,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        crate::verify_snapshot(
            metadata,
            snapshot,
            timestamp,
            &self.trusted_root,
            current_time_us,
            &self.crypto,
        )?;
        self.role_versions
            .check(TufRole::Snapshot, metadata.version)?;
        self.role_versions
            .record(TufRole::Snapshot, metadata.version);
        Ok(())
    }

    /// Verify TUF targets metadata, cross-referencing the snapshot.
    ///
    /// Enforces monotonic per-role rollback in addition to the standard
    /// signature/expiry/cross-reference checks. See [`Self::verify_timestamp`].
    pub fn verify_targets(
        &self,
        metadata: &SignedMetadata,
        targets: &TufTargets,
        snapshot: &TufSnapshot,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        crate::verify_targets(
            metadata,
            targets,
            snapshot,
            &self.trusted_root,
            current_time_us,
            &self.crypto,
        )?;
        self.role_versions
            .check(TufRole::Targets, metadata.version)?;
        self.role_versions
            .record(TufRole::Targets, metadata.version);
        Ok(())
    }

    /// Find a target by ID and verify the firmware image against it.
    pub fn verify_target_from_targets(
        &self,
        targets: &TufTargets,
        target_id: &[u8],
        firmware_bytes: &[u8],
    ) -> Result<(), VsError> {
        let entry = find_target_entry(targets, target_id)?;
        self.verify_target(&entry.hash, entry.length, firmware_bytes)
    }

    /// Verify a complete TUF metadata chain: timestamp -> snapshot -> targets -> firmware.
    #[must_use = "TUF full-update verification result must not be silently ignored"]
    pub fn verify_full_update(
        &self,
        ts_metadata: &SignedMetadata,
        timestamp: &TufTimestamp,
        snap_metadata: &SignedMetadata,
        snapshot: &TufSnapshot,
        tgt_metadata: &SignedMetadata,
        targets: &TufTargets,
        target_id: &[u8],
        firmware_bytes: &[u8],
        current_time_us: u64,
    ) -> Result<(), VsError> {
        self.verify_timestamp(ts_metadata, timestamp, current_time_us)?;
        self.verify_snapshot(snap_metadata, snapshot, timestamp, current_time_us)?;
        self.verify_targets(tgt_metadata, targets, snapshot, current_time_us)?;
        self.verify_target_from_targets(targets, target_id, firmware_bytes)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PersistentOtaValidator (StorageProvider-backed)
// ---------------------------------------------------------------------------

/// Storage key for the rollback version counter.
const ROLLBACK_STORAGE_KEY: &[u8] = b"ota_rollback_ver";

/// OTA validator with persistent rollback protection via [`StorageProvider`].
///
/// The rollback counter survives power cycles when backed by flash, EEPROM,
/// or HSM OTP fuses through the `StorageProvider` abstraction.
pub struct PersistentOtaValidator<C: CryptoProvider, S: StorageProvider> {
    crypto: C,
    storage: S,
    trusted_root: TufRoot,
    rollback_version: u32,
}

impl<C: CryptoProvider, S: StorageProvider> PersistentOtaValidator<C, S> {
    /// Create a validator with persistent storage for the rollback counter.
    ///
    /// If the storage already contains a rollback version, the higher of the
    /// stored value and the initial root version is used.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidConfig`] if the root threshold is zero.
    /// Returns [`VsError::StorageError`] if the initial persistence write fails.
    pub fn new(crypto: C, mut storage: S, trusted_root: TufRoot) -> Result<Self, VsError> {
        if trusted_root.threshold == 0 {
            return Err(VsError::InvalidConfig);
        }
        let stored_version = {
            let mut buf = [0u8; 4];
            match storage.read(ROLLBACK_STORAGE_KEY, &mut buf) {
                Ok(4) => u32::from_le_bytes(buf),
                Err(VsError::NotFound) => 0, // First boot, no stored version yet
                Err(e) => return Err(e),     // Propagate real storage errors
                Ok(_) => return Err(VsError::StorageError), // Unexpected read length
            }
        };
        let rollback_version = stored_version.max(trusted_root.version);

        // Persist the initial value.
        storage
            .write(ROLLBACK_STORAGE_KEY, &rollback_version.to_le_bytes())
            .map_err(|_| VsError::StorageError)?;

        Ok(Self {
            crypto,
            storage,
            trusted_root,
            rollback_version,
        })
    }

    /// Verify and apply a root metadata update with persistent rollback
    /// protection.
    pub fn verify_root_update(
        &mut self,
        new_metadata: &SignedMetadata,
        new_root: &TufRoot,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        verify_root_update_common(
            new_metadata,
            new_root,
            current_time_us,
            &self.trusted_root,
            &self.crypto,
        )?;

        let new_rollback = self.rollback_version.max(new_metadata.version);

        // Persist the new rollback version BEFORE updating in-memory state
        // to avoid TOCTOU: if the write fails, in-memory state stays consistent.
        self.storage
            .write(ROLLBACK_STORAGE_KEY, &new_rollback.to_le_bytes())
            .map_err(|_| VsError::StorageError)?;

        self.trusted_root = new_root.clone();
        self.rollback_version = new_rollback;

        Ok(())
    }

    /// Verify a firmware target blob against its expected hash and length.
    pub fn verify_target(
        &self,
        expected_hash: &[u8; 32],
        expected_length: u64,
        firmware_bytes: &[u8],
    ) -> Result<(), VsError> {
        verify_target_impl(expected_hash, expected_length, firmware_bytes, &self.crypto)
    }

    /// Return the current rollback version counter.
    pub fn rollback_version(&self) -> u32 {
        self.rollback_version
    }

    /// Consume the validator and return the underlying storage provider.
    pub fn take_storage(self) -> S {
        self.storage
    }
}

// ---------------------------------------------------------------------------
// HsmOtaValidator — HSM-backed rollback counter
// ---------------------------------------------------------------------------

/// OTA validator with hardware-backed rollback protection.
///
/// Uses a [`RollbackCounter`] (typically [`HsmRollbackCounter`]) instead of
/// a bare `u32` for rollback version tracking. On real hardware, counter
/// increments burn OTP fuses and are permanently irreversible.
pub struct HsmOtaValidator<C: CryptoProvider, R: RollbackCounter> {
    crypto: C,
    trusted_root: TufRoot,
    rollback: R,
}

impl<C: CryptoProvider, R: RollbackCounter> HsmOtaValidator<C, R> {
    /// Create a validator with an initial trusted root and rollback counter.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidConfig`] if the root threshold is zero.
    pub fn new(crypto: C, trusted_root: TufRoot, rollback: R) -> Result<Self, VsError> {
        if trusted_root.threshold == 0 {
            return Err(VsError::InvalidConfig);
        }
        Ok(Self {
            crypto,
            trusted_root,
            rollback,
        })
    }

    /// Verify and apply a root metadata update with hardware-backed rollback
    /// protection.
    pub fn verify_root_update(
        &mut self,
        new_metadata: &SignedMetadata,
        new_root: &TufRoot,
        current_time_us: u64,
    ) -> Result<(), VsError> {
        // --- Consistency: new_root must match new_metadata ---
        if new_root.version != new_metadata.version {
            return Err(VsError::IntegrityFailure);
        }
        if new_root.expires_us != new_metadata.expires_us {
            return Err(VsError::IntegrityFailure);
        }

        // --- New root must have valid threshold ---
        if new_root.threshold == 0 {
            return Err(VsError::InvalidConfig);
        }

        // --- Rollback check against hardware counter AND trusted root ---
        let current_counter = self.rollback.read()?;
        // Guard against the hardware monotonic counter exceeding u32::MAX.
        // If this happens, no u32 firmware version can satisfy the rollback
        // check, effectively bricking OTA updates. Fail early with a clear
        // error so the integrator can detect the misconfiguration.
        if current_counter > u64::from(u32::MAX) {
            return Err(VsError::ResourceExhausted);
        }
        let current_version = u64::from(self.trusted_root.version);
        let effective_floor = current_counter.max(current_version);
        if u64::from(new_metadata.version) <= effective_floor {
            return Err(VsError::PolicyViolation);
        }

        // --- Expiration check ---
        if current_time_us >= new_metadata.expires_us {
            return Err(VsError::AuthenticationFailure);
        }

        // --- Threshold signature verification against CURRENT root keys ---
        let valid_sigs =
            count_valid_sigs(new_metadata, &self.trusted_root.root_keys, &self.crypto)?;
        if valid_sigs < self.trusted_root.threshold {
            return Err(VsError::AuthenticationFailure);
        }

        // --- Cross-verify against NEW root keys ---
        let new_valid = count_valid_sigs(new_metadata, &new_root.root_keys, &self.crypto)?;
        if new_valid < new_root.threshold {
            return Err(VsError::AuthenticationFailure);
        }

        // --- All checks passed – commit state ---
        //
        // Advance the hardware counter FIRST. On real hardware this burns
        // OTP fuses and is irreversible, but it can also fail (e.g. fuse
        // hardware fault, capability check). If we replaced
        // `self.trusted_root` before that call and the advance failed, the
        // in-memory anchor would diverge from the persistent counter,
        // leaving the validator in a state that silently accepts metadata
        // whose version is below the hardware floor on next call. By
        // advancing first we guarantee that the in-memory anchor is only
        // ever updated when the irreversible counter has already moved.
        self.rollback.advance_to(u64::from(new_metadata.version))?;
        self.trusted_root = new_root.clone();

        Ok(())
    }

    /// Verify a firmware target blob against its expected hash and length.
    pub fn verify_target(
        &self,
        expected_hash: &[u8; 32],
        expected_length: u64,
        firmware_bytes: &[u8],
    ) -> Result<(), VsError> {
        verify_target_impl(expected_hash, expected_length, firmware_bytes, &self.crypto)
    }

    /// Return the current hardware rollback counter value.
    pub fn rollback_counter(&self) -> Result<u64, VsError> {
        self.rollback.read()
    }
}

// ---------------------------------------------------------------------------
// Standalone manifest verification
// ---------------------------------------------------------------------------

/// Verify a P-256 signature over a vehicle manifest hash.
///
/// This is used by the director repository (or primary ECU) to validate
/// that a manifest was genuinely produced by the primary ECU.
pub fn verify_vehicle_manifest(
    manifest_hash: &[u8; 32],
    sig: &[u8; 64],
    primary_key: &TufKey,
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    let verified = crypto.verify_p256(&primary_key.public_key, manifest_hash, sig)?;
    if verified {
        Ok(())
    } else {
        Err(VsError::AuthenticationFailure)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vs_crypto::KeyId;

    // -- TestCrypto mock ----------------------------------------------------

    /// Minimal mock crypto provider for deterministic unit tests.
    struct TestCrypto;

    impl CryptoProvider for TestCrypto {
        fn aes_gcm_encrypt(
            &self,
            _key_id: KeyId,
            _nonce: &[u8; 12],
            _plaintext: &[u8],
            _aad: &[u8],
            _ciphertext_out: &mut [u8],
            _tag_out: &mut [u8; 16],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn aes_gcm_decrypt(
            &self,
            _key_id: KeyId,
            _nonce: &[u8; 12],
            _ciphertext: &[u8],
            _aad: &[u8],
            _tag: &[u8; 16],
            _plaintext_out: &mut [u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            // Simple deterministic XOR-based mixing for testing.
            *hash_out = [0u8; 32];
            for (i, &byte) in data.iter().enumerate() {
                hash_out[i % 32] ^= byte;
                // Rotate-mix to avoid trivial collisions.
                hash_out[(i.wrapping_add(7)) % 32] =
                    hash_out[(i.wrapping_add(7)) % 32].wrapping_add(byte);
            }
            Ok(())
        }

        fn hmac_sha256(
            &self,
            _key_id: KeyId,
            _data: &[u8],
            _mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn ecdh_derive_shared(
            &self,
            _private_key_id: KeyId,
            _peer_public: &[u8; 65],
            _shared_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn sign_p256(
            &self,
            _key_id: KeyId,
            _digest: &[u8; 32],
            _sig_out: &mut [u8; 64],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn verify_p256(
            &self,
            _pub_key: &[u8; 65],
            digest: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<bool, VsError> {
            // Simple mock: signature is valid if the first byte of the digest
            // matches the first byte of the signature.
            Ok(digest[0] == sig[0])
        }

        fn random_bytes(&self, _buf: &mut [u8]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
    }

    // -- Test helpers -------------------------------------------------------

    /// Create a [`TufKey`] with the given `id_byte` used to fill `key_id[0]`.
    fn make_key(id_byte: u8) -> TufKey {
        let mut key_id = [0u8; 32];
        key_id[0] = id_byte;
        TufKey {
            key_id,
            key_type: KeyType::EcdsaP256,
            public_key: [0x04; 65], // placeholder uncompressed point
        }
    }

    /// Create a signature whose `key_id[0]` = `key_byte` and `sig[0]` = `sig_byte`.
    fn make_sig(key_byte: u8, sig_byte: u8) -> TufSignature {
        let mut key_id = [0u8; 32];
        key_id[0] = key_byte;
        let mut sig = [0u8; 64];
        sig[0] = sig_byte;
        TufSignature { key_id, sig }
    }

    const NO_KEYS: [Option<TufKey>; 4] = [None, None, None, None];

    /// Build a simple root with `n_keys` keys and the specified `threshold`.
    fn make_root(version: u32, expires_us: u64, n_keys: usize, threshold: u8) -> TufRoot {
        let mut root_keys: [Option<TufKey>; 4] = [None, None, None, None];
        for (i, slot) in root_keys.iter_mut().enumerate().take(n_keys.min(4)) {
            *slot = Some(make_key(i as u8 + 1));
        }
        TufRoot {
            version,
            expires_us,
            root_keys,
            threshold,
            targets_keys: NO_KEYS,
            targets_threshold: 0,
            snapshot_keys: NO_KEYS,
            snapshot_threshold: 0,
            timestamp_keys: NO_KEYS,
            timestamp_threshold: 0,
        }
    }

    /// Build a root with separate per-role keys.
    fn make_root_with_role_keys(
        version: u32,
        expires_us: u64,
        root_key_byte: u8,
        targets_key_byte: u8,
        snapshot_key_byte: u8,
        timestamp_key_byte: u8,
    ) -> TufRoot {
        TufRoot {
            version,
            expires_us,
            root_keys: [Some(make_key(root_key_byte)), None, None, None],
            threshold: 1,
            targets_keys: [Some(make_key(targets_key_byte)), None, None, None],
            targets_threshold: 1,
            snapshot_keys: [Some(make_key(snapshot_key_byte)), None, None, None],
            snapshot_threshold: 1,
            timestamp_keys: [Some(make_key(timestamp_key_byte)), None, None, None],
            timestamp_threshold: 1,
        }
    }

    /// Build signed metadata with given signatures whose `content_hash[0]`
    /// controls whether our mock crypto considers them valid.
    fn make_hash(byte0: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte0;
        h
    }

    fn make_signed_metadata(
        version: u32,
        expires_us: u64,
        sigs: &[TufSignature],
        content_hash_byte0: u8,
    ) -> SignedMetadata {
        let mut signatures: [Option<TufSignature>; 4] = [None, None, None, None];
        for (i, s) in sigs.iter().enumerate().take(4) {
            signatures[i] = Some(*s);
        }
        let mut content_hash = [0u8; 32];
        content_hash[0] = content_hash_byte0;
        SignedMetadata {
            version,
            expires_us,
            signatures,
            content_hash,
        }
    }

    // -- Tests --------------------------------------------------------------

    #[test]
    fn valid_root_update_with_threshold_signatures() {
        let root = make_root(1, 1_000_000, 2, 2);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Two valid signatures: key_id[0]=1 sig[0]=0xAA, key_id[0]=2 sig[0]=0xAA
        // content_hash[0]=0xAA so mock verify returns true for both.
        let sigs = [make_sig(1, 0xAA), make_sig(2, 0xAA)];
        let metadata = make_signed_metadata(2, 2_000_000, &sigs, 0xAA);
        let new_root = make_root(2, 2_000_000, 2, 2);

        let result = validator.verify_root_update(&metadata, &new_root, 500_000);
        assert!(result.is_ok());
        assert_eq!(validator.rollback_version(), 2);
    }

    #[test]
    fn expired_root_metadata_returns_authentication_failure() {
        let root = make_root(1, 1_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(2, 500_000, &sigs, 0xBB);
        let new_root = make_root(2, 500_000, 2, 1);

        // current_time_us = 600_000 >= expires_us = 500_000
        let result = validator.verify_root_update(&metadata, &new_root, 600_000);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn root_version_rollback_returns_policy_violation() {
        let root = make_root(5, 10_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xCC)];
        // version 3 <= current version 5
        let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xCC);
        let new_root = make_root(3, 10_000_000, 2, 1);

        let result = validator.verify_root_update(&metadata, &new_root, 1_000);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn same_version_is_also_rollback() {
        let root = make_root(5, 10_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xCC)];
        // version 5 == current version 5 => still a rollback
        let metadata = make_signed_metadata(5, 10_000_000, &sigs, 0xCC);
        let new_root = make_root(5, 10_000_000, 2, 1);

        let result = validator.verify_root_update(&metadata, &new_root, 1_000);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn target_hash_mismatch_returns_integrity_failure() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware = b"hello firmware";
        let wrong_hash = [0xFF; 32]; // definitely wrong
        let result = validator.verify_target(&wrong_hash, firmware.len() as u64, firmware);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn target_length_mismatch_returns_integrity_failure() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware = b"hello firmware";
        let mut expected_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut expected_hash).unwrap();

        // Claim a different length
        let result = validator.verify_target(&expected_hash, 999, firmware);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn threshold_not_met_returns_authentication_failure() {
        // Root requires threshold=2 but we only provide 1 valid signature.
        let root = make_root(1, 1_000_000, 2, 2);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Only one valid signature (key 1, sig matches hash).
        // Key 2's signature does NOT match hash (sig[0]=0xFF != content_hash[0]=0xAA).
        let sigs = [make_sig(1, 0xAA), make_sig(2, 0xFF)];
        let metadata = make_signed_metadata(2, 2_000_000, &sigs, 0xAA);
        let new_root = make_root(2, 2_000_000, 2, 2);

        let result = validator.verify_root_update(&metadata, &new_root, 500_000);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn rollback_counter_prevents_downgrade() {
        let root = make_root(1, 5_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Upgrade to version 3.
        let sigs = [make_sig(1, 0xDD)];
        let metadata = make_signed_metadata(3, 5_000_000, &sigs, 0xDD);
        let new_root = make_root(3, 5_000_000, 2, 1);
        validator
            .verify_root_update(&metadata, &new_root, 100)
            .unwrap();
        assert_eq!(validator.rollback_version(), 3);

        // Now attempt version 2 – should fail.
        let metadata_old = make_signed_metadata(2, 5_000_000, &sigs, 0xDD);
        let old_root = make_root(2, 5_000_000, 2, 1);
        let result = validator.verify_root_update(&metadata_old, &old_root, 200);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn valid_target_passes_verification() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware = b"valid firmware image payload";
        let mut expected_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut expected_hash).unwrap();

        let result = validator.verify_target(&expected_hash, firmware.len() as u64, firmware);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_vehicle_manifest_valid() {
        let key = make_key(1);
        let mut manifest_hash = [0u8; 32];
        manifest_hash[0] = 0x42;
        let mut sig = [0u8; 64];
        sig[0] = 0x42; // matches hash[0] => mock says valid

        let result = verify_vehicle_manifest(&manifest_hash, &sig, &key, &TestCrypto);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_vehicle_manifest_invalid_sig() {
        let key = make_key(1);
        let mut manifest_hash = [0u8; 32];
        manifest_hash[0] = 0x42;
        let mut sig = [0u8; 64];
        sig[0] = 0x99; // does NOT match hash[0] => mock says invalid

        let result = verify_vehicle_manifest(&manifest_hash, &sig, &key, &TestCrypto);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn vehicle_manifest_struct_fields() {
        let manifest = VehicleManifest {
            vin: *b"1HGBH41JXMN109186",
            primary_ecu_serial: [0xAB; 32],
            installed_version: 42,
            report_time_us: 1_000_000,
        };
        assert_eq!(manifest.installed_version, 42);
        assert_eq!(manifest.vin[0], b'1');
        assert_eq!(manifest.report_time_us, 1_000_000);
    }

    #[test]
    fn vehicle_manifest_hash_and_verify() {
        let manifest = VehicleManifest {
            vin: *b"1HGBH41JXMN109186",
            primary_ecu_serial: [0xAB; 32],
            installed_version: 42,
            report_time_us: 1_000_000,
        };
        let hash = manifest.hash(&TestCrypto).unwrap();
        // Hash should be non-zero.
        assert_ne!(hash, [0u8; 32]);

        // Create a signature whose sig[0] matches hash[0] for our mock.
        let key = make_key(1);
        let mut sig = [0u8; 64];
        sig[0] = hash[0]; // mock says valid
        assert!(manifest.verify(&sig, &key, &TestCrypto).is_ok());

        // Wrong sig should fail.
        sig[0] = hash[0].wrapping_add(1);
        assert_eq!(
            manifest.verify(&sig, &key, &TestCrypto),
            Err(VsError::AuthenticationFailure)
        );
    }

    #[test]
    fn root_with_zero_valid_signatures_fails() {
        let root = make_root(1, 1_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // No signatures at all.
        let metadata = make_signed_metadata(2, 2_000_000, &[], 0xAA);
        let new_root = make_root(2, 2_000_000, 2, 1);

        let result = validator.verify_root_update(&metadata, &new_root, 500_000);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn root_with_all_4_keys_valid_threshold_3_passes() {
        let root = make_root(1, 5_000_000, 4, 3);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // All 4 signatures valid (sig[0] == content_hash[0] == 0xBB).
        let sigs = [
            make_sig(1, 0xBB),
            make_sig(2, 0xBB),
            make_sig(3, 0xBB),
            make_sig(4, 0xBB),
        ];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xBB);
        let new_root = make_root(2, 5_000_000, 4, 3);

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn root_with_exactly_threshold_signatures_passes() {
        let root = make_root(1, 5_000_000, 3, 2);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Exactly 2 valid sigs (threshold=2), third is invalid.
        let sigs = [
            make_sig(1, 0xCC),
            make_sig(2, 0xCC),
            make_sig(3, 0xFF), // invalid (0xFF != 0xCC)
        ];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xCC);
        let new_root = make_root(2, 5_000_000, 3, 2);

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn target_with_empty_firmware_and_matching_hash_passes() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware: &[u8] = &[];
        let mut expected_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut expected_hash).unwrap();

        let result = validator.verify_target(&expected_hash, 0, firmware);
        assert!(result.is_ok());
    }

    #[test]
    fn target_with_very_large_expected_length_mismatch() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware = b"small";
        let mut expected_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut expected_hash).unwrap();

        // Claim a very large length.
        let result = validator.verify_target(&expected_hash, u64::MAX, firmware);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn rollback_counter_starts_at_initial_root_version() {
        let root = make_root(1, 1_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();
        assert_eq!(validator.rollback_version(), 1);
    }

    #[test]
    fn multiple_sequential_updates_increment_version() {
        let root = make_root(1, 10_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Update to version 2.
        let sigs = [make_sig(1, 0xDD)];
        let metadata = make_signed_metadata(2, 10_000_000, &sigs, 0xDD);
        let new_root = make_root(2, 10_000_000, 2, 1);
        validator
            .verify_root_update(&metadata, &new_root, 100)
            .unwrap();
        assert_eq!(validator.rollback_version(), 2);

        // Update to version 3.
        let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xDD);
        let new_root = make_root(3, 10_000_000, 2, 1);
        validator
            .verify_root_update(&metadata, &new_root, 200)
            .unwrap();
        assert_eq!(validator.rollback_version(), 3);

        // Update to version 10.
        let metadata = make_signed_metadata(10, 10_000_000, &sigs, 0xDD);
        let new_root = make_root(10, 10_000_000, 2, 1);
        validator
            .verify_root_update(&metadata, &new_root, 300)
            .unwrap();
        assert_eq!(validator.rollback_version(), 10);
    }

    #[test]
    fn root_metadata_with_version_u32_max() {
        let root = make_root(u32::MAX - 1, 10_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xEE)];
        let metadata = make_signed_metadata(u32::MAX, 10_000_000, &sigs, 0xEE);
        let new_root = make_root(u32::MAX, 10_000_000, 2, 1);

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert!(result.is_ok());
        assert_eq!(validator.rollback_version(), u32::MAX);
    }

    #[test]
    fn tuf_key_struct_field_access() {
        let key = make_key(0x42);
        assert_eq!(key.key_id[0], 0x42);
        assert_eq!(key.key_type, KeyType::EcdsaP256);
        assert_eq!(key.public_key[0], 0x04);
        assert_eq!(key.public_key.len(), 65);
    }

    #[test]
    fn vehicle_manifest_with_wrong_signature_fails() {
        let key = make_key(1);
        let mut manifest_hash = [0u8; 32];
        manifest_hash[0] = 0x42;
        let mut sig = [0u8; 64];
        sig[0] = 0x00; // does NOT match hash[0]=0x42 => mock says invalid

        let result = verify_vehicle_manifest(&manifest_hash, &sig, &key, &TestCrypto);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn root_with_threshold_zero_returns_invalid_config() {
        // threshold=0 is no longer accepted — it must be rejected.
        let root = make_root(1, 5_000_000, 2, 0);
        let result = OtaValidator::new(TestCrypto, root);
        assert!(matches!(result, Err(VsError::InvalidConfig)));
    }

    #[test]
    fn new_root_with_threshold_zero_rejected_in_update() {
        let root = make_root(1, 5_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);
        let new_root = make_root(2, 5_000_000, 2, 0); // threshold=0

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn key_type_enum_values() {
        let kt = KeyType::EcdsaP256;
        assert_eq!(kt, KeyType::EcdsaP256);
        // Verify Debug trait is implemented.
        let _ = format_args!("{kt:?}");
    }

    // -- Cross-verification tests (V1) --

    #[test]
    fn cross_verify_fails_if_new_keys_reject() {
        // Old root has key 1, new root has key 2.
        // Metadata is signed by key 1 only — passes old check, fails new check.
        let root = make_root(1, 5_000_000, 1, 1); // key 1
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xAA)]; // only key 1 signature
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);

        // New root only has key 2 — no matching signature.
        let mut new_root = make_root(2, 5_000_000, 1, 1);
        new_root.root_keys = [Some(make_key(2)), None, None, None];

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn cross_verify_passes_with_both_key_sets() {
        // Old root has key 1, new root has key 2.
        // Metadata is signed by both keys.
        let root = make_root(1, 5_000_000, 1, 1); // key 1
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xAA), make_sig(2, 0xAA)]; // both keys
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);

        let mut new_root = make_root(2, 5_000_000, 1, 1);
        new_root.root_keys = [Some(make_key(2)), None, None, None]; // only key 2

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert!(result.is_ok());
    }

    // -- Metadata-root consistency tests (V3) --

    #[test]
    fn metadata_root_version_mismatch_rejected() {
        let root = make_root(1, 5_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);
        let new_root = make_root(3, 5_000_000, 2, 1); // version 3 != metadata version 2

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn metadata_root_expires_mismatch_rejected() {
        let root = make_root(1, 5_000_000, 2, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);
        let mut new_root = make_root(2, 5_000_000, 2, 1);
        new_root.expires_us = 6_000_000; // mismatch

        let result = validator.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    // -- PersistentOtaValidator tests --

    #[test]
    fn persistent_validator_starts_at_root_version() {
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(5, 10_000_000, 2, 1);
        let validator = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();
        assert_eq!(validator.rollback_version(), 5);
    }

    #[test]
    fn persistent_validator_uses_stored_version_if_higher() {
        let mut store = vs_storage::RamStorageProvider::new();
        // Pre-write a higher version to storage.
        store
            .write(ROLLBACK_STORAGE_KEY, &10u32.to_le_bytes())
            .unwrap();

        let root = make_root(5, 10_000_000, 2, 1);
        let validator = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();
        // Should use the stored version (10) since it's higher than root (5).
        assert_eq!(validator.rollback_version(), 10);
    }

    #[test]
    fn persistent_validator_update_advances_version() {
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(1, 10_000_000, 2, 1);
        let mut validator = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(5, 10_000_000, &sigs, 0xAA);
        let new_root = make_root(5, 10_000_000, 2, 1);
        validator
            .verify_root_update(&metadata, &new_root, 100)
            .unwrap();
        assert_eq!(validator.rollback_version(), 5);
    }

    #[test]
    fn persistent_validator_rollback_fails() {
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(5, 10_000_000, 2, 1);
        let mut validator = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();

        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xBB);
        let old_root = make_root(3, 10_000_000, 2, 1);

        let result = validator.verify_root_update(&metadata, &old_root, 100);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn persistent_validator_verify_target() {
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();

        let firmware = b"firmware image data";
        let mut hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut hash).unwrap();

        let result = validator.verify_target(&hash, firmware.len() as u64, firmware);
        assert!(result.is_ok());
    }

    #[test]
    fn persistent_validator_persists_to_storage() {
        use vs_storage::StorageProvider;

        // Create validator, update to version 7, then take_storage to verify.
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(1, 10_000_000, 2, 1);
        let mut v = PersistentOtaValidator::new(TestCrypto, store, root).unwrap();

        let sigs = [make_sig(1, 0xCC)];
        let metadata = make_signed_metadata(7, 10_000_000, &sigs, 0xCC);
        let new_root = make_root(7, 10_000_000, 2, 1);
        v.verify_root_update(&metadata, &new_root, 100).unwrap();
        assert_eq!(v.rollback_version(), 7);

        // Get storage back to verify persistence.
        let store = v.take_storage();
        let mut buf = [0u8; 4];
        let len = store.read(ROLLBACK_STORAGE_KEY, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(u32::from_le_bytes(buf), 7);

        // "Second boot": re-create validator from same storage.
        let root2 = make_root(1, 10_000_000, 2, 1);
        let v2 = PersistentOtaValidator::new(TestCrypto, store, root2).unwrap();
        assert_eq!(v2.rollback_version(), 7);
    }

    #[test]
    fn persistent_validator_threshold_zero_rejected() {
        let store = vs_storage::RamStorageProvider::new();
        let root = make_root(1, 10_000_000, 2, 0);
        let result = PersistentOtaValidator::new(TestCrypto, store, root);
        assert!(matches!(result, Err(VsError::InvalidConfig)));
    }

    // -- HsmOtaValidator tests ------------------------------------------------

    #[test]
    fn hsm_ota_validator_valid_update() {
        let root = make_root(1, 10_000_000, 2, 1);
        let counter = SoftwareRollbackCounter::new();
        let mut v = HsmOtaValidator::new(TestCrypto, root, counter).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 10_000_000, &sigs, 0xAA);
        let new_root = make_root(2, 10_000_000, 2, 1);
        v.verify_root_update(&metadata, &new_root, 100).unwrap();
        // Counter should now match the version (2).
        assert_eq!(v.rollback_counter(), Ok(2));
    }

    #[test]
    fn hsm_ota_validator_rollback_rejected() {
        let root = make_root(5, 10_000_000, 2, 1);
        let counter = SoftwareRollbackCounter::with_initial(5);
        let mut v = HsmOtaValidator::new(TestCrypto, root, counter).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xAA);
        let new_root = make_root(3, 10_000_000, 2, 1);
        let result = v.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn hsm_ota_validator_counter_advances_to_version() {
        let root = make_root(1, 10_000_000, 2, 1);
        let counter = SoftwareRollbackCounter::new();
        let mut v = HsmOtaValidator::new(TestCrypto, root, counter).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let m1 = make_signed_metadata(2, 10_000_000, &sigs, 0xAA);
        let r1 = make_root(2, 10_000_000, 2, 1);
        v.verify_root_update(&m1, &r1, 100).unwrap();
        assert_eq!(v.rollback_counter(), Ok(2));

        let m2 = make_signed_metadata(5, 10_000_000, &sigs, 0xAA);
        let r2 = make_root(5, 10_000_000, 2, 1);
        v.verify_root_update(&m2, &r2, 200).unwrap();
        // Counter should now match version 5.
        assert_eq!(v.rollback_counter(), Ok(5));
    }

    #[test]
    fn hsm_ota_validator_verify_target() {
        let root = make_root(1, 10_000_000, 2, 1);
        let counter = SoftwareRollbackCounter::new();
        let v = HsmOtaValidator::new(TestCrypto, root, counter).unwrap();

        let firmware = b"firmware binary data";
        let mut expected_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut expected_hash).unwrap();

        v.verify_target(&expected_hash, firmware.len() as u64, firmware)
            .unwrap();
    }

    #[test]
    fn hsm_ota_validator_expired_metadata_rejected() {
        let root = make_root(1, 1_000, 2, 1);
        let counter = SoftwareRollbackCounter::new();
        let mut v = HsmOtaValidator::new(TestCrypto, root, counter).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 1_000, &sigs, 0xAA);
        let new_root = make_root(2, 1_000, 2, 1);
        let result = v.verify_root_update(&metadata, &new_root, 2_000);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn hsm_ota_validator_threshold_zero_rejected() {
        let root = make_root(1, 10_000_000, 2, 0);
        let counter = SoftwareRollbackCounter::new();
        let result = HsmOtaValidator::new(TestCrypto, root, counter);
        assert!(matches!(result, Err(VsError::InvalidConfig)));
    }

    // -- TUF delegation tests -----------------------------------------------

    fn make_target_entry(id: &[u8], hash: [u8; 32], length: u64) -> TufTargetEntry {
        let mut target_id = [0u8; 32];
        let len = id.len().min(32);
        target_id[..len].copy_from_slice(&id[..len]);
        TufTargetEntry {
            hash,
            length,
            target_id,
            target_id_len: len as u8,
        }
    }

    #[test]
    fn verify_timestamp_valid() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0xAA; 32],
        };
        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(1, 5_000_000, &sigs, 0xBB);

        let result = validator.verify_timestamp(&metadata, &timestamp, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_timestamp_expired() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 1_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(1, 1_000, &sigs, 0xBB);

        let result = validator.verify_timestamp(&metadata, &timestamp, 2_000);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn verify_timestamp_version_mismatch() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 2,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(1, 5_000_000, &sigs, 0xBB); // version 1 != 2

        let result = validator.verify_timestamp(&metadata, &timestamp, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn verify_snapshot_valid() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 3,
            snapshot_hash: make_hash(0xCC),
        };
        let snapshot = TufSnapshot {
            version: 3,
            expires_us: 5_000_000,
            targets_version: 2,
            targets_hash: make_hash(0xDD),
        };
        let sigs = [make_sig(1, 0xCC)];
        // content_hash must match timestamp.snapshot_hash
        let metadata = make_signed_metadata(3, 5_000_000, &sigs, 0xCC);

        let result = validator.verify_snapshot(&metadata, &snapshot, &timestamp, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_snapshot_version_mismatch() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 3,
            snapshot_hash: [0xCC; 32],
        };
        let snapshot = TufSnapshot {
            version: 2, // mismatch — timestamp says 3
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: [0; 32],
        };
        let sigs = [make_sig(1, 0xCC)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xCC);

        let result = validator.verify_snapshot(&metadata, &snapshot, &timestamp, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn verify_snapshot_hash_mismatch() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0xAA; 32],
        };
        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: [0; 32],
        };
        let sigs = [make_sig(1, 0xBB)];
        // content_hash[0]=0xBB != timestamp.snapshot_hash[0]=0xAA
        let metadata = make_signed_metadata(1, 5_000_000, &sigs, 0xBB);

        let result = validator.verify_snapshot(&metadata, &snapshot, &timestamp, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn verify_snapshot_expires_mismatch_rejected() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 3,
            snapshot_hash: make_hash(0xCC),
        };
        let snapshot = TufSnapshot {
            version: 3,
            expires_us: 9_000_000, // differs from metadata.expires_us below
            targets_version: 2,
            targets_hash: make_hash(0xDD),
        };
        let sigs = [make_sig(1, 0xCC)];
        let metadata = make_signed_metadata(3, 5_000_000, &sigs, 0xCC);

        let result = validator.verify_snapshot(&metadata, &snapshot, &timestamp, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn verify_targets_valid() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 2,
            targets_hash: make_hash(0xDD),
        };
        let targets = TufTargets {
            version: 2,
            expires_us: 5_000_000,
            targets: [None, None, None, None, None, None, None, None],
        };
        let sigs = [make_sig(1, 0xDD)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xDD);

        let result = validator.verify_targets(&metadata, &targets, &snapshot, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_targets_version_mismatch() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 3,
            targets_hash: [0xDD; 32],
        };
        let targets = TufTargets {
            version: 2, // mismatch
            expires_us: 5_000_000,
            targets: [None, None, None, None, None, None, None, None],
        };
        let sigs = [make_sig(1, 0xDD)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xDD);

        let result = validator.verify_targets(&metadata, &targets, &snapshot, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn verify_targets_expires_mismatch_rejected() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 2,
            targets_hash: make_hash(0xDD),
        };
        let targets = TufTargets {
            version: 2,
            expires_us: 9_000_000, // differs from metadata.expires_us below
            targets: [None, None, None, None, None, None, None, None],
        };
        let sigs = [make_sig(1, 0xDD)];
        let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xDD);

        let result = validator.verify_targets(&metadata, &targets, &snapshot, 100);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn find_target_entry_found() {
        let entry = make_target_entry(b"ecu-main", [0xAB; 32], 1024);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };
        let found = find_target_entry(&targets, b"ecu-main").unwrap();
        assert_eq!(found.hash, [0xAB; 32]);
        assert_eq!(found.length, 1024);
    }

    #[test]
    fn find_target_entry_not_found() {
        let entry = make_target_entry(b"ecu-main", [0xAB; 32], 1024);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };
        let result = find_target_entry(&targets, b"ecu-other");
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn verify_target_from_targets_valid() {
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let firmware = b"firmware image data";
        let mut hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut hash).unwrap();

        let entry = make_target_entry(b"ecu-main", hash, firmware.len() as u64);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };

        let result = validator.verify_target_from_targets(&targets, b"ecu-main", firmware);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_target_from_targets_bad_hash() {
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let entry = make_target_entry(b"ecu-main", [0xFF; 32], 10);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };

        let firmware = b"0123456789"; // 10 bytes, but hash won't match
        let result = validator.verify_target_from_targets(&targets, b"ecu-main", firmware);
        assert_eq!(result, Err(VsError::IntegrityFailure));
    }

    #[test]
    fn per_role_keys_used_for_timestamp() {
        // Root keys use id_byte=0x10, timestamp keys use id_byte=0x20
        let root = make_root_with_role_keys(1, 10_000_000, 0x10, 0x30, 0x40, 0x20);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        // Sign with timestamp key (key_id[0]=0x20), content_hash[0]=0x20 for match
        let sigs = [make_sig(0x20, 0x20)];
        let metadata = make_signed_metadata(1, 5_000_000, &sigs, 0x20);

        let result = validator.verify_timestamp(&metadata, &timestamp, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn per_role_keys_root_key_rejected_for_timestamp() {
        let root = make_root_with_role_keys(1, 10_000_000, 0x10, 0x30, 0x40, 0x20);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        // Sign with root key (key_id[0]=0x10) — should fail for timestamp role
        let sigs = [make_sig(0x10, 0x10)];
        let metadata = make_signed_metadata(1, 5_000_000, &sigs, 0x10);

        let result = validator.verify_timestamp(&metadata, &timestamp, 100);
        assert_eq!(result, Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn keys_for_role_falls_back_to_root() {
        let root = make_root(1, 10_000_000, 2, 1);
        // No per-role keys set — should fall back to root keys
        let (keys, threshold) = root.keys_for_role(TufRole::Targets);
        assert_eq!(threshold, 1);
        assert!(keys[0].is_some());
    }

    #[test]
    fn tuf_role_enum_variants() {
        assert_ne!(TufRole::Root, TufRole::Targets);
        assert_ne!(TufRole::Snapshot, TufRole::Timestamp);
    }

    #[test]
    fn full_tuf_delegation_chain() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Step 1: Verify timestamp
        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: make_hash(0xAA),
        };
        let sigs = [make_sig(1, 0xBB)];
        let ts_metadata = make_signed_metadata(1, 5_000_000, &sigs, 0xBB);
        validator
            .verify_timestamp(&ts_metadata, &timestamp, 100)
            .unwrap();

        // Step 2: Verify snapshot (version and hash must match timestamp)
        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: make_hash(0xCC),
        };
        let snap_sigs = [make_sig(1, 0xAA)];
        // content_hash must match timestamp.snapshot_hash (0xAA)
        let snap_metadata = make_signed_metadata(1, 5_000_000, &snap_sigs, 0xAA);
        validator
            .verify_snapshot(&snap_metadata, &snapshot, &timestamp, 100)
            .unwrap();

        // Step 3: Verify targets (version and hash must match snapshot)
        let firmware = b"firmware v1.0";
        let mut fw_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut fw_hash).unwrap();
        let entry = make_target_entry(b"ecu-main", fw_hash, firmware.len() as u64);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };
        let tgt_sigs = [make_sig(1, 0xCC)];
        // content_hash must match snapshot.targets_hash (0xCC)
        let tgt_metadata = make_signed_metadata(1, 5_000_000, &tgt_sigs, 0xCC);
        validator
            .verify_targets(&tgt_metadata, &targets, &snapshot, 100)
            .unwrap();

        // Step 4: Verify firmware against target entry
        validator
            .verify_target_from_targets(&targets, b"ecu-main", firmware)
            .unwrap();
    }

    #[test]
    fn verify_full_update_chains_all_checks() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: make_hash(0xAA),
        };
        let ts_metadata = make_signed_metadata(1, 5_000_000, &[make_sig(1, 0xBB)], 0xBB);

        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: make_hash(0xCC),
        };
        let snap_metadata = make_signed_metadata(1, 5_000_000, &[make_sig(1, 0xAA)], 0xAA);

        let firmware = b"firmware v1.0";
        let mut fw_hash = [0u8; 32];
        TestCrypto.sha256(firmware, &mut fw_hash).unwrap();
        let entry = make_target_entry(b"ecu-main", fw_hash, firmware.len() as u64);
        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [Some(entry), None, None, None, None, None, None, None],
        };
        let tgt_metadata = make_signed_metadata(1, 5_000_000, &[make_sig(1, 0xCC)], 0xCC);

        let result = validator.verify_full_update(
            &ts_metadata,
            &timestamp,
            &snap_metadata,
            &snapshot,
            &tgt_metadata,
            &targets,
            b"ecu-main",
            firmware,
            100,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_full_update_fails_on_bad_timestamp() {
        let root = make_root(1, 10_000_000, 2, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let timestamp = TufTimestamp {
            version: 1,
            expires_us: 1_000,
            snapshot_version: 1,
            snapshot_hash: make_hash(0xAA),
        };
        let ts_metadata = make_signed_metadata(1, 1_000, &[make_sig(1, 0xBB)], 0xBB);

        let snapshot = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: make_hash(0xCC),
        };
        let snap_metadata = make_signed_metadata(1, 5_000_000, &[make_sig(1, 0xAA)], 0xAA);

        let targets = TufTargets {
            version: 1,
            expires_us: 5_000_000,
            targets: [None, None, None, None, None, None, None, None],
        };
        let tgt_metadata = make_signed_metadata(1, 5_000_000, &[make_sig(1, 0xCC)], 0xCC);

        // Expired timestamp (current_time > expires_us)
        let result = validator.verify_full_update(
            &ts_metadata,
            &timestamp,
            &snap_metadata,
            &snapshot,
            &tgt_metadata,
            &targets,
            b"ecu-main",
            b"firmware",
            2_000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_signatures_not_double_counted() {
        let crypto = TestCrypto;
        let key = make_key(1);
        let keys = [Some(key), None, None, None];
        let sig = make_sig(1, 0xAA);
        // Same signature duplicated in two slots
        let metadata = SignedMetadata {
            version: 1,
            expires_us: u64::MAX,
            signatures: [Some(sig), Some(sig), None, None],
            content_hash: make_hash(0xAA),
        };
        let count = count_valid_sigs(&metadata, &keys, &crypto).unwrap();
        // Should count as 1, not 2 (same key)
        assert_eq!(count, 1);
    }

    #[test]
    fn metadata_version_at_u32_max_accepted() {
        // A firmware metadata version of u32::MAX must be handled without
        // overflow. The validator should not reject it for rollback reasons
        // when the current root version is 1 (u32::MAX > 1).
        //
        // We use verify_root_update, which is where the rollback check lives.
        // The call may fail for signature reasons (TestCrypto uses a
        // content-hash-based mock), but it must NOT return PolicyViolation
        // (rollback rejection).
        let root = make_root(1, u64::MAX, 1, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        // Build metadata and a new root at version u32::MAX.
        // Use content_hash_byte0 = 0xAA and sig[0] = 0xAA so mock verify passes.
        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(u32::MAX, u64::MAX, &sigs, 0xAA);
        let new_root = make_root(u32::MAX, u64::MAX, 1, 1);

        let result = validator.verify_root_update(&metadata, &new_root, 1_000);
        // Must not be a PolicyViolation (rollback). Any other outcome is acceptable.
        assert_ne!(
            result,
            Err(VsError::PolicyViolation),
            "u32::MAX version should not trigger rollback rejection"
        );
    }

    #[test]
    fn expired_metadata_rejected() {
        // Metadata that has already expired must be rejected.
        // expires_us = 500_000, current_time_us = 600_000 → expired.
        let root = make_root(1, 1_000_000, 1, 1);
        let mut validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xBB)];
        let metadata = make_signed_metadata(2, 500_000, &sigs, 0xBB);
        let new_root = make_root(2, 500_000, 1, 1);

        // current_time_us (600_000) >= expires_us (500_000) → expired
        let result = validator.verify_root_update(&metadata, &new_root, 600_000);
        assert_eq!(
            result,
            Err(VsError::AuthenticationFailure),
            "expired metadata must be rejected with AuthenticationFailure"
        );
    }

    // -- Per-role rollback regression tests (TUF §5.4–5.6) --------------------

    #[test]
    fn timestamp_replay_with_lower_version_rejected() {
        // Accept version 5 first, then attempt to replay version 5 and
        // version 3. Both must be rejected with PolicyViolation even
        // though the signature and expiry are still valid (freeze attack).
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let sigs = [make_sig(1, 0xBB)];
        let ts5 = TufTimestamp {
            version: 5,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let m5 = make_signed_metadata(5, 5_000_000, &sigs, 0xBB);
        validator.verify_timestamp(&m5, &ts5, 100).unwrap();

        // Same version: must be rejected (not strictly greater).
        let result = validator.verify_timestamp(&m5, &ts5, 200);
        assert_eq!(result, Err(VsError::PolicyViolation));

        // Lower version: must be rejected.
        let ts3 = TufTimestamp {
            version: 3,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let m3 = make_signed_metadata(3, 5_000_000, &sigs, 0xBB);
        let result = validator.verify_timestamp(&m3, &ts3, 300);
        assert_eq!(result, Err(VsError::PolicyViolation));

        // Strictly higher version succeeds.
        let ts6 = TufTimestamp {
            version: 6,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let m6 = make_signed_metadata(6, 5_000_000, &sigs, 0xBB);
        validator.verify_timestamp(&m6, &ts6, 400).unwrap();
    }

    #[test]
    fn snapshot_replay_with_lower_version_rejected() {
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let ts = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 5,
            snapshot_hash: make_hash(0xAA),
        };
        let snap5 = TufSnapshot {
            version: 5,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: [0; 32],
        };
        let m5 = make_signed_metadata(5, 5_000_000, &[make_sig(1, 0xAA)], 0xAA);
        validator.verify_snapshot(&m5, &snap5, &ts, 100).unwrap();

        // Replay same version 5: rejected.
        let result = validator.verify_snapshot(&m5, &snap5, &ts, 200);
        assert_eq!(result, Err(VsError::PolicyViolation));

        // Lower version 3 (with matching timestamp.snapshot_version=3): also rejected.
        let ts3 = TufTimestamp {
            version: 1,
            expires_us: 5_000_000,
            snapshot_version: 3,
            snapshot_hash: make_hash(0xAA),
        };
        let snap3 = TufSnapshot {
            version: 3,
            expires_us: 5_000_000,
            targets_version: 1,
            targets_hash: [0; 32],
        };
        let m3 = make_signed_metadata(3, 5_000_000, &[make_sig(1, 0xAA)], 0xAA);
        let result = validator.verify_snapshot(&m3, &snap3, &ts3, 300);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn targets_replay_with_lower_version_rejected() {
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let snap = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 5,
            targets_hash: make_hash(0xDD),
        };
        let tgt5 = TufTargets {
            version: 5,
            expires_us: 5_000_000,
            targets: [None, None, None, None, None, None, None, None],
        };
        let m5 = make_signed_metadata(5, 5_000_000, &[make_sig(1, 0xDD)], 0xDD);
        validator.verify_targets(&m5, &tgt5, &snap, 100).unwrap();

        // Replay same version 5: rejected.
        let result = validator.verify_targets(&m5, &tgt5, &snap, 200);
        assert_eq!(result, Err(VsError::PolicyViolation));

        // Lower version 3 (with matching snapshot.targets_version=3): rejected.
        let snap3 = TufSnapshot {
            version: 1,
            expires_us: 5_000_000,
            targets_version: 3,
            targets_hash: make_hash(0xDD),
        };
        let tgt3 = TufTargets {
            version: 3,
            expires_us: 5_000_000,
            targets: [None, None, None, None, None, None, None, None],
        };
        let m3 = make_signed_metadata(3, 5_000_000, &[make_sig(1, 0xDD)], 0xDD);
        let result = validator.verify_targets(&m3, &tgt3, &snap3, 300);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn role_version_state_not_updated_when_signature_fails() {
        // If the underlying verify_* check fails (e.g. bad signature),
        // the per-role version floor must NOT be advanced — otherwise a
        // bad metadata blob could be used to lock out future legitimate
        // updates.
        let root = make_root(1, 10_000_000, 1, 1);
        let validator = OtaValidator::new(TestCrypto, root).unwrap();

        let ts = TufTimestamp {
            version: 7,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        // sig[0] = 0x00 != content_hash[0] = 0xBB → mock rejects.
        let bad = make_signed_metadata(7, 5_000_000, &[make_sig(1, 0x00)], 0xBB);
        let result = validator.verify_timestamp(&bad, &ts, 100);
        assert_eq!(result, Err(VsError::AuthenticationFailure));

        // Now a legitimate version 5 must still be accepted — the floor
        // never advanced past 0.
        let ts5 = TufTimestamp {
            version: 5,
            expires_us: 5_000_000,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        let good = make_signed_metadata(5, 5_000_000, &[make_sig(1, 0xCC)], 0xCC);
        validator.verify_timestamp(&good, &ts5, 200).unwrap();
    }

    // -- HSM root-update state-desync regression -----------------------------

    /// A rollback counter whose `advance_to` always fails. Used to prove
    /// that `HsmOtaValidator::verify_root_update` does not mutate the
    /// in-memory `trusted_root` when the hardware counter advance fails.
    struct FailingAdvanceCounter {
        value: u64,
    }

    impl RollbackCounter for FailingAdvanceCounter {
        fn read(&self) -> Result<u64, VsError> {
            Ok(self.value)
        }
        fn increment(&mut self) -> Result<u64, VsError> {
            Err(VsError::BusError)
        }
        fn advance_to(&mut self, _target: u64) -> Result<u64, VsError> {
            Err(VsError::BusError)
        }
    }

    #[test]
    fn hsm_validator_anchor_unchanged_when_advance_fails() {
        let original_root = make_root(1, 10_000_000, 2, 1);
        let counter = FailingAdvanceCounter { value: 1 };
        let mut v = HsmOtaValidator::new(TestCrypto, original_root.clone(), counter).unwrap();

        let sigs = [make_sig(1, 0xAA)];
        let metadata = make_signed_metadata(2, 10_000_000, &sigs, 0xAA);
        let new_root = make_root(2, 10_000_000, 2, 1);

        // advance_to returns HardwareFault → verify_root_update must
        // propagate the error AND leave the in-memory anchor untouched.
        let result = v.verify_root_update(&metadata, &new_root, 100);
        assert_eq!(result, Err(VsError::BusError));

        // Inspect the anchor: version must still be the original 1.
        assert_eq!(v.trusted_root.version, original_root.version);
    }
}
