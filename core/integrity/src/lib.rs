// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

use vs_crypto::{CryptoProvider, KeyId};
use vs_types::{AlertSeverity, VsError};

/// Maximum number of monitored memory regions.
pub const MAX_REGIONS: usize = 64;

/// Size of the authentication message for baseline updates (bytes).
const AUTH_MESSAGE_SIZE: usize = 44;

/// Size of the snapshot HMAC input: `region_count(8) + measurement_counter(8)`
/// `+ epoch(8) + check_interval_ticks(8)` + per-region data.
/// We build it dynamically in a fixed buffer.
const SNAPSHOT_HMAC_PREFIX_SIZE: usize = 32;

/// Callback invoked when tamper is detected.
///
/// Parameters: `(region_id, base_addr, severity)`.
pub type TamperCallback = fn(u32, usize, AlertSeverity);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Public view of region metadata.  Does **not** expose the expected hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionInfo {
    /// Unique identifier for this region.
    pub id: u32,
    /// Base address of the region.
    pub base_addr: usize,
    /// Length of the region in bytes.
    pub length: usize,
    /// Whether this region is actively monitored.
    pub active: bool,
    /// Epoch at which this region was last successfully verified.
    pub last_verified_epoch: u64,
}

/// Result of an integrity check on a single region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// Region hash matches expected value.
    Ok,
    /// Region hash does not match (tamper detected).
    Tampered,
    /// Region data could not be read (data provider returned `None`).
    Unavailable,
}

/// Per-region check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityResult {
    pub region_id: u32,
    pub status: IntegrityStatus,
}

/// Opaque snapshot of monitor state for persistence across reboots.
///
/// Does **not** include the crypto provider — the caller must supply one when
/// restoring via [`IntegrityMonitor::from_snapshot`].
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MonitorSnapshot {
    regions: [IntegrityRegion; MAX_REGIONS],
    region_count: usize,
    measurement_counter: u64,
    epoch: u64,
    auth_key_id_present: bool,
    auth_key_id: KeyId,
    check_interval_ticks: u64,
    /// Whether the HMAC field was computed with a valid auth key.
    ///
    /// This distinguishes "no authentication configured" (`false`) from
    /// "authentication configured but HMAC happens to be all-zero" (`true`),
    /// preventing an attacker from forging an unauthenticated snapshot by
    /// setting the HMAC to zero.
    authenticated: bool,
    /// HMAC-SHA256 over snapshot contents for tamper detection.
    /// Only valid when `authenticated` is `true`.
    hmac: [u8; 32],
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Internal representation of a monitored memory region.
#[derive(Clone, Copy)]
#[repr(C)]
struct IntegrityRegion {
    id: u32,
    base_addr: usize,
    length: usize,
    expected_hash: [u8; 32],
    active: bool,
    last_verified_epoch: u64,
}

impl Default for IntegrityRegion {
    fn default() -> Self {
        Self {
            id: 0,
            base_addr: 0,
            length: 0,
            expected_hash: [0u8; 32],
            active: false,
            last_verified_epoch: 0,
        }
    }
}

impl IntegrityRegion {
    fn to_info(&self) -> RegionInfo {
        RegionInfo {
            id: self.id,
            base_addr: self.base_addr,
            length: self.length,
            active: self.active,
            last_verified_epoch: self.last_verified_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// IntegrityMonitor
// ---------------------------------------------------------------------------

/// Integrity monitor that tracks memory regions and verifies their SHA-256
/// hashes using constant-time comparison.
pub struct IntegrityMonitor<C: CryptoProvider> {
    regions: [IntegrityRegion; MAX_REGIONS],
    region_count: usize,
    measurement_counter: u64,
    epoch: u64,
    crypto: C,
    auth_key_id: Option<KeyId>,
    tamper_callback: Option<TamperCallback>,
    check_interval_ticks: u64,
    ticks_since_last_check: u64,
}

impl<C: CryptoProvider> IntegrityMonitor<C> {
    /// Create a new integrity monitor with the given crypto provider.
    pub fn new(crypto: C) -> Self {
        Self {
            regions: [IntegrityRegion::default(); MAX_REGIONS],
            region_count: 0,
            measurement_counter: 0,
            epoch: 0,
            crypto,
            auth_key_id: None,
            tamper_callback: None,
            check_interval_ticks: 0,
            ticks_since_last_check: 0,
        }
    }

    // -- Configuration ------------------------------------------------------

    /// Set the HMAC key used to authenticate baseline updates.
    ///
    /// When set, [`update_baseline`](Self::update_baseline) requires a valid
    /// HMAC-SHA256 tag (see [`build_update_auth_message`]).
    pub fn set_auth_key(&mut self, key_id: KeyId) {
        self.auth_key_id = Some(key_id);
    }

    /// Clear the authentication key, allowing unauthenticated baseline
    /// updates.
    pub fn clear_auth_key(&mut self) {
        self.auth_key_id = None;
    }

    /// Set a callback invoked whenever tamper is detected.
    pub fn set_tamper_callback(&mut self, cb: TamperCallback) {
        self.tamper_callback = Some(cb);
    }

    /// Clear the tamper callback.
    pub fn clear_tamper_callback(&mut self) {
        self.tamper_callback = None;
    }

    /// Set the tick-based check interval.
    ///
    /// When non-zero, [`tick`](Self::tick) returns `true` every `interval`
    /// calls, signaling that the caller should run verification.  Set to `0`
    /// to disable.
    pub fn set_check_interval(&mut self, interval: u64) {
        self.check_interval_ticks = interval;
        self.ticks_since_last_check = 0;
    }

    /// Advance the internal tick counter.
    ///
    /// Returns `true` when the check interval has elapsed and the caller
    /// should perform verification.  Always returns `false` when the interval
    /// is `0`.
    pub fn tick(&mut self) -> bool {
        if self.check_interval_ticks == 0 {
            return false;
        }
        self.ticks_since_last_check = self.ticks_since_last_check.saturating_add(1);
        if self.ticks_since_last_check >= self.check_interval_ticks {
            self.ticks_since_last_check = 0;
            true
        } else {
            false
        }
    }

    // -- Registration -------------------------------------------------------

    /// Register a memory region for monitoring.
    ///
    /// Computes the initial SHA-256 hash of `data` as the baseline.  Inactive
    /// slots are reused before allocating new ones, preventing slot exhaustion
    /// after repeated register / unregister cycles.
    pub fn register_region(
        &mut self,
        id: u32,
        base_addr: usize,
        data: &[u8],
    ) -> Result<(), VsError> {
        // Reject duplicate active IDs.
        for i in 0..self.region_count {
            if self.regions[i].active && self.regions[i].id == id {
                return Err(VsError::PolicyViolation);
            }
        }

        // Prefer reusing an inactive slot; otherwise append.
        let slot = self
            .find_inactive_slot()
            .or_else(|| {
                if self.region_count < MAX_REGIONS {
                    let idx = self.region_count;
                    self.region_count += 1;
                    Some(idx)
                } else {
                    None
                }
            })
            .ok_or(VsError::ResourceExhausted)?;

        let mut hash = [0u8; 32];
        self.crypto.sha256(data, &mut hash)?;

        self.regions[slot] = IntegrityRegion {
            id,
            base_addr,
            length: data.len(),
            expected_hash: hash,
            active: true,
            last_verified_epoch: 0,
        };

        Ok(())
    }

    /// Unregister a region by ID.
    ///
    /// The slot is marked inactive and its expected hash is zeroed so that the
    /// baseline cannot be recovered from a memory dump.
    pub fn unregister_region(&mut self, id: u32) -> Result<(), VsError> {
        let idx = self.find_region_index(id).ok_or(VsError::NotFound)?;
        self.regions[idx].expected_hash = [0u8; 32];
        self.regions[idx].active = false;
        Ok(())
    }

    /// Remove all registered regions and reset all counters.
    pub fn clear_all(&mut self) {
        for i in 0..self.region_count {
            self.regions[i] = IntegrityRegion::default();
        }
        self.region_count = 0;
        self.measurement_counter = 0;
        self.epoch = 0;
        self.ticks_since_last_check = 0;
    }

    // -- Verification -------------------------------------------------------

    /// Verify a single region against its expected hash.
    ///
    /// The caller **must** provide the `base_addr` that was used at
    /// registration — a mismatch returns [`VsError::InvalidInput`], binding
    /// the verification to the correct memory location.
    ///
    /// # Errors
    ///
    /// - [`VsError::NotFound`] — no active region with `id`.
    /// - [`VsError::InvalidInput`] — `base_addr` does not match the
    ///   registered address.
    /// - [`VsError::CryptoError`] — hash computation failed.
    /// - [`VsError::ResourceExhausted`] — measurement counter saturated.
    pub fn verify_region(
        &mut self,
        id: u32,
        base_addr: usize,
        current_data: &[u8],
    ) -> Result<IntegrityResult, VsError> {
        let idx = self.find_region_index(id).ok_or(VsError::NotFound)?;
        let region = &self.regions[idx];

        if base_addr != region.base_addr {
            return Err(VsError::InvalidInput);
        }

        if current_data.len() != region.length {
            self.fire_tamper(id, base_addr);
            return Ok(IntegrityResult {
                region_id: id,
                status: IntegrityStatus::Tampered,
            });
        }

        let expected = region.expected_hash;

        let mut hash = [0u8; 32];
        self.crypto.sha256(current_data, &mut hash)?;

        self.increment_counter()?;

        let status = if vs_types::constant_time_eq_32(&hash, &expected) {
            self.regions[idx].last_verified_epoch = self.epoch;
            IntegrityStatus::Ok
        } else {
            self.fire_tamper(id, base_addr);
            IntegrityStatus::Tampered
        };

        Ok(IntegrityResult {
            region_id: id,
            status,
        })
    }

    /// Verify all active regions in a single pass.
    ///
    /// `data_provider` is called with `(region_id, base_addr, length)` and
    /// must return the current memory contents, or `None` if the region
    /// cannot be read.
    ///
    /// The epoch counter is incremented once per call.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidInput`] — `results` buffer is smaller than
    ///   [`active_region_count`](Self::active_region_count).
    /// - [`VsError::CryptoError`] — a hash computation failed.  The entire
    ///   batch is aborted because a crypto failure may indicate a compromised
    ///   subsystem.
    /// - [`VsError::ResourceExhausted`] — measurement counter saturated.
    pub fn verify_all<'a, F>(
        &mut self,
        mut data_provider: F,
        results: &mut [IntegrityResult],
    ) -> Result<usize, VsError>
    where
        F: FnMut(u32, usize, usize) -> Option<&'a [u8]>,
    {
        let active = self.active_region_count();
        if results.len() < active {
            return Err(VsError::InvalidInput);
        }

        self.epoch = self.epoch.saturating_add(1);
        let mut count = 0;

        for i in 0..self.region_count {
            if !self.regions[i].active {
                continue;
            }

            let region = self.regions[i];
            let result = match data_provider(region.id, region.base_addr, region.length) {
                Some(data) if data.len() != region.length => {
                    self.fire_tamper(region.id, region.base_addr);
                    IntegrityResult {
                        region_id: region.id,
                        status: IntegrityStatus::Tampered,
                    }
                }
                Some(data) => {
                    let mut hash = [0u8; 32];
                    self.crypto.sha256(data, &mut hash)?;
                    self.increment_counter()?;

                    if vs_types::constant_time_eq_32(&hash, &region.expected_hash) {
                        self.regions[i].last_verified_epoch = self.epoch;
                        IntegrityResult {
                            region_id: region.id,
                            status: IntegrityStatus::Ok,
                        }
                    } else {
                        self.fire_tamper(region.id, region.base_addr);
                        IntegrityResult {
                            region_id: region.id,
                            status: IntegrityStatus::Tampered,
                        }
                    }
                }
                None => IntegrityResult {
                    region_id: region.id,
                    status: IntegrityStatus::Unavailable,
                },
            };

            results[count] = result;
            count += 1;
        }

        Ok(count)
    }

    /// Fast-path integrity check: returns on the **first** integrity failure
    /// detected.
    ///
    /// Unlike [`verify_all`](Self::verify_all) (which always checks every
    /// region for audit purposes), this method is optimised for fast anomaly
    /// detection.  It skips inactive regions without touching the data
    /// provider and exits immediately when a tampered or unavailable region
    /// is found.
    ///
    /// On success (`Ok(true)`), every active region matched its baseline.
    /// On detection (`Ok(false)`), the first failing [`IntegrityResult`] is
    /// written to `first_failure`.  The epoch counter is **not** incremented
    /// (the caller should follow up with a full `verify_all` for audit).
    ///
    /// # Errors
    ///
    /// - [`VsError::CryptoError`] — a hash computation failed.
    /// - [`VsError::ResourceExhausted`] — measurement counter saturated.
    pub fn verify_all_fast<'a, F>(
        &mut self,
        mut data_provider: F,
        first_failure: &mut IntegrityResult,
    ) -> Result<bool, VsError>
    where
        F: FnMut(u32, usize, usize) -> Option<&'a [u8]>,
    {
        // Pre-scan: count active regions so we can skip the entire sweep
        // when there is nothing to verify.
        let active = self.active_region_count();
        if active == 0 {
            return Ok(true);
        }

        for i in 0..self.region_count {
            if !self.regions[i].active {
                continue;
            }

            let region = self.regions[i];

            match data_provider(region.id, region.base_addr, region.length) {
                Some(data) if data.len() != region.length => {
                    self.fire_tamper(region.id, region.base_addr);
                    *first_failure = IntegrityResult {
                        region_id: region.id,
                        status: IntegrityStatus::Tampered,
                    };
                    return Ok(false);
                }
                Some(data) => {
                    let mut hash = [0u8; 32];
                    self.crypto.sha256(data, &mut hash)?;
                    self.increment_counter()?;

                    if !vs_types::constant_time_eq_32(&hash, &region.expected_hash) {
                        self.fire_tamper(region.id, region.base_addr);
                        *first_failure = IntegrityResult {
                            region_id: region.id,
                            status: IntegrityStatus::Tampered,
                        };
                        return Ok(false);
                    }
                }
                None => {
                    *first_failure = IntegrityResult {
                        region_id: region.id,
                        status: IntegrityStatus::Unavailable,
                    };
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    // -- Baseline management ------------------------------------------------

    /// Update the expected hash of a region after a legitimate change.
    ///
    /// When an authentication key is configured (via
    /// [`set_auth_key`](Self::set_auth_key)), the caller must provide a valid
    /// HMAC-SHA256 tag computed over the authentication message returned by
    /// [`build_update_auth_message`].
    ///
    /// Pass `None` for `auth_tag` when no authentication key is configured.
    pub fn update_baseline(
        &mut self,
        id: u32,
        new_data: &[u8],
        auth_tag: Option<&[u8; 32]>,
    ) -> Result<(), VsError> {
        let idx = self.find_region_index(id).ok_or(VsError::NotFound)?;

        if let Some(key_id) = self.auth_key_id {
            let tag = auth_tag.ok_or(VsError::AuthenticationFailure)?;
            let msg = build_auth_message(&self.crypto, id, new_data)?;
            let mut expected_mac = [0u8; 32];
            self.crypto.hmac_sha256(key_id, &msg, &mut expected_mac)?;
            if !vs_types::constant_time_eq_32(tag, &expected_mac) {
                return Err(VsError::AuthenticationFailure);
            }
        }

        let mut hash = [0u8; 32];
        self.crypto.sha256(new_data, &mut hash)?;

        self.regions[idx].expected_hash = hash;
        self.regions[idx].length = new_data.len();

        Ok(())
    }

    // -- Queries ------------------------------------------------------------

    /// Get the monotonic measurement counter.
    pub fn measurement_count(&self) -> u64 {
        self.measurement_counter
    }

    /// Returns `true` if the measurement counter has reached `u64::MAX`.
    ///
    /// A saturated counter is no longer monotonic.  The caller should take
    /// corrective action (e.g., re-provision the monitor).
    pub fn is_counter_saturated(&self) -> bool {
        self.measurement_counter == u64::MAX
    }

    /// Get the current epoch (incremented on each
    /// [`verify_all`](Self::verify_all) call).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns `(allocated_slots, max_slots)`.
    pub fn region_capacity(&self) -> (usize, usize) {
        (self.region_count, MAX_REGIONS)
    }

    /// Get the number of active (non-unregistered) regions.
    pub fn active_region_count(&self) -> usize {
        (0..self.region_count)
            .filter(|&i| self.regions[i].active)
            .count()
    }

    /// Get public metadata for a region by ID.
    ///
    /// Returns `None` if the region does not exist or is inactive.  The
    /// expected hash is **not** included in the returned [`RegionInfo`].
    pub fn get_region(&self, id: u32) -> Option<RegionInfo> {
        self.find_region(id).map(|r| r.to_info())
    }

    // -- Snapshot / restore -------------------------------------------------

    /// Capture the current monitor state for persistence.
    ///
    /// The returned [`MonitorSnapshot`] is `#[repr(C)]` and `Copy`, so it
    /// can be stored to non-volatile memory directly.
    pub fn snapshot(&self) -> Result<MonitorSnapshot, VsError> {
        let has_auth = self.auth_key_id.is_some();
        let mut snap = MonitorSnapshot {
            regions: self.regions,
            region_count: self.region_count,
            measurement_counter: self.measurement_counter,
            epoch: self.epoch,
            auth_key_id_present: has_auth,
            auth_key_id: self.auth_key_id.unwrap_or(KeyId(0)),
            check_interval_ticks: self.check_interval_ticks,
            authenticated: has_auth,
            hmac: [0u8; 32],
        };
        // Compute HMAC over snapshot contents for tamper detection.
        if let Some(key_id) = self.auth_key_id {
            let d = snapshot_content_hash(&self.crypto, &snap)?;
            self.crypto.hmac_sha256(key_id, &d, &mut snap.hmac)?;
        }
        Ok(snap)
    }

    /// Restore a monitor from a previously captured snapshot.
    ///
    /// When the snapshot contains a non-zero HMAC (i.e., an auth key was
    /// configured when the snapshot was taken), the HMAC is verified before
    /// restoring.  Returns [`VsError::AuthenticationFailure`] if the HMAC
    /// does not match, indicating the snapshot may have been tampered with.
    ///
    /// The tamper callback is **not** persisted — the caller must re-register
    /// it after restoring.
    pub fn from_snapshot(snapshot: MonitorSnapshot, crypto: C) -> Result<Self, VsError> {
        // Verify snapshot HMAC if an auth key was present when it was taken.
        // Reject snapshots where `auth_key_id_present` is set but
        // `authenticated` is not — this catches forgery attempts where an
        // attacker sets the HMAC to zero and clears `authenticated`.
        if snapshot.auth_key_id_present {
            if !snapshot.authenticated {
                return Err(VsError::AuthenticationFailure);
            }
            let digest = snapshot_content_hash(&crypto, &snapshot)?;
            let mut expected_hmac = [0u8; 32];
            crypto.hmac_sha256(snapshot.auth_key_id, &digest, &mut expected_hmac)?;
            if !vs_types::constant_time_eq_32(&snapshot.hmac, &expected_hmac) {
                return Err(VsError::AuthenticationFailure);
            }
        }

        Ok(Self {
            regions: snapshot.regions,
            region_count: snapshot.region_count,
            measurement_counter: snapshot.measurement_counter,
            epoch: snapshot.epoch,
            crypto,
            auth_key_id: if snapshot.auth_key_id_present {
                Some(snapshot.auth_key_id)
            } else {
                None
            },
            tamper_callback: None,
            check_interval_ticks: snapshot.check_interval_ticks,
            ticks_since_last_check: 0,
        })
    }

    // -- Private helpers ----------------------------------------------------

    fn find_region(&self, id: u32) -> Option<&IntegrityRegion> {
        (0..self.region_count)
            .find(|&i| self.regions[i].active && self.regions[i].id == id)
            .map(|i| &self.regions[i])
    }

    fn find_region_index(&self, id: u32) -> Option<usize> {
        (0..self.region_count).find(|&i| self.regions[i].active && self.regions[i].id == id)
    }

    fn find_inactive_slot(&self) -> Option<usize> {
        (0..self.region_count).find(|&i| !self.regions[i].active)
    }

    fn increment_counter(&mut self) -> Result<(), VsError> {
        self.measurement_counter = self
            .measurement_counter
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        Ok(())
    }

    fn fire_tamper(&self, region_id: u32, base_addr: usize) {
        if let Some(cb) = self.tamper_callback {
            cb(region_id, base_addr, AlertSeverity::Critical);
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Build the authentication message for a baseline update.
///
/// The message is `region_id (4 LE) || data_len (8 LE) || sha256(data) (32)`.
///
/// Compute `HMAC-SHA256(auth_key, message)` over this result and pass the tag
/// to [`IntegrityMonitor::update_baseline`].
pub fn build_update_auth_message(
    crypto: &impl CryptoProvider,
    id: u32,
    new_data: &[u8],
) -> Result<[u8; AUTH_MESSAGE_SIZE], VsError> {
    build_auth_message(crypto, id, new_data)
}

fn build_auth_message(
    crypto: &impl CryptoProvider,
    id: u32,
    data: &[u8],
) -> Result<[u8; AUTH_MESSAGE_SIZE], VsError> {
    let mut msg = [0u8; AUTH_MESSAGE_SIZE];
    msg[0..4].copy_from_slice(&id.to_le_bytes());
    msg[4..12].copy_from_slice(&(data.len() as u64).to_le_bytes());
    let mut hash = [0u8; 32];
    crypto.sha256(data, &mut hash)?;
    msg[12..44].copy_from_slice(&hash);
    Ok(msg)
}

/// Compute a SHA-256 digest over the meaningful fields of a
/// [`MonitorSnapshot`], excluding the `hmac` field itself.
///
/// The digest is used as the HMAC message when authenticating snapshots.
fn snapshot_content_hash(
    crypto: &impl CryptoProvider,
    snap: &MonitorSnapshot,
) -> Result<[u8; 32], VsError> {
    // Build a deterministic byte representation of the snapshot fields.
    // We hash the scalar fields first, then each region's data.
    let mut buf = [0u8; SNAPSHOT_HMAC_PREFIX_SIZE];
    buf[0..8].copy_from_slice(&(snap.region_count as u64).to_le_bytes());
    buf[8..16].copy_from_slice(&snap.measurement_counter.to_le_bytes());
    buf[16..24].copy_from_slice(&snap.epoch.to_le_bytes());
    buf[24..32].copy_from_slice(&snap.check_interval_ticks.to_le_bytes());

    // Hash the prefix, then fold in each region's data.
    let mut hash = [0u8; 32];
    crypto.sha256(&buf, &mut hash)?;

    for i in 0..snap.region_count {
        let r = &snap.regions[i];
        let mut region_buf = [0u8; 4 + 8 + 8 + 32 + 1 + 8];
        region_buf[0..4].copy_from_slice(&r.id.to_le_bytes());
        region_buf[4..12].copy_from_slice(&(r.base_addr as u64).to_le_bytes());
        region_buf[12..20].copy_from_slice(&(r.length as u64).to_le_bytes());
        region_buf[20..52].copy_from_slice(&r.expected_hash);
        region_buf[52] = u8::from(r.active);
        region_buf[53..61].copy_from_slice(&r.last_verified_epoch.to_le_bytes());

        // Chain: hash = SHA256(prev_hash || region_buf)
        let mut chain = [0u8; 32 + 61];
        chain[..32].copy_from_slice(&hash);
        chain[32..].copy_from_slice(&region_buf);
        crypto.sha256(&chain, &mut hash)?;
    }

    Ok(hash)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use vs_crypto::KeyId;

    // -----------------------------------------------------------------------
    // Full test crypto provider (deterministic, not cryptographically secure)
    // -----------------------------------------------------------------------

    struct TestCrypto {
        rng_state: Cell<u64>,
    }

    impl TestCrypto {
        fn new() -> Self {
            Self {
                rng_state: Cell::new(0x1234_5678_9ABC_DEF0),
            }
        }

        /// Deterministic 256-bit hash (not secure — for testing only).
        fn simple_hash(data: &[u8]) -> [u8; 32] {
            let mut hash = [0u8; 32];
            for (i, &byte) in data.iter().enumerate() {
                let idx = i % 32;
                hash[idx] = hash[idx].wrapping_add(byte);
                let next = (idx + 1) % 32;
                hash[next] = hash[next].wrapping_add(hash[idx].wrapping_mul(31));
            }
            for i in 0..32 {
                let next = (i + 1) % 32;
                hash[next] ^= hash[i].wrapping_mul(17);
            }
            hash
        }

        fn next_u64(&self) -> u64 {
            let s = self.rng_state.get();
            let new = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.rng_state.set(new);
            new
        }

        fn derive_keystream(key_id: KeyId, nonce: &[u8; 12]) -> [u8; 32] {
            let mut seed = [0u8; 16];
            seed[0..4].copy_from_slice(&key_id.0.to_le_bytes());
            seed[4..16].copy_from_slice(nonce);
            Self::simple_hash(&seed)
        }
    }

    impl CryptoProvider for TestCrypto {
        fn aes_gcm_encrypt(
            &self,
            key_id: KeyId,
            nonce: &[u8; 12],
            plaintext: &[u8],
            aad: &[u8],
            ciphertext_out: &mut [u8],
            tag_out: &mut [u8; 16],
        ) -> Result<(), VsError> {
            if ciphertext_out.len() < plaintext.len() {
                return Err(VsError::InvalidInput);
            }
            let ks = Self::derive_keystream(key_id, nonce);
            for (i, &b) in plaintext.iter().enumerate() {
                ciphertext_out[i] = b ^ ks[i % 32];
            }
            let mut tag_seed = [0u8; 32];
            for (i, &b) in aad.iter().enumerate() {
                tag_seed[i % 32] ^= b;
            }
            for (i, &b) in ciphertext_out[..plaintext.len()].iter().enumerate() {
                tag_seed[i % 32] = tag_seed[i % 32].wrapping_add(b);
            }
            let tag_hash = Self::simple_hash(&tag_seed);
            tag_out.copy_from_slice(&tag_hash[..16]);
            Ok(())
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
            if plaintext_out.len() < ciphertext.len() {
                return Err(VsError::InvalidInput);
            }
            // Verify tag.
            let mut tag_seed = [0u8; 32];
            for (i, &b) in aad.iter().enumerate() {
                tag_seed[i % 32] ^= b;
            }
            for (i, &b) in ciphertext.iter().enumerate() {
                tag_seed[i % 32] = tag_seed[i % 32].wrapping_add(b);
            }
            let tag_hash = Self::simple_hash(&tag_seed);
            if *tag != tag_hash[..16] {
                return Err(VsError::AuthenticationFailure);
            }
            // Decrypt.
            let ks = Self::derive_keystream(key_id, nonce);
            for (i, &b) in ciphertext.iter().enumerate() {
                plaintext_out[i] = b ^ ks[i % 32];
            }
            Ok(())
        }

        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            *hash_out = Self::simple_hash(data);
            Ok(())
        }

        fn hmac_sha256(
            &self,
            key_id: KeyId,
            data: &[u8],
            mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            // Deterministic keyed hash: hash(key_id || hash(data)).
            let data_hash = Self::simple_hash(data);
            let mut keyed = [0u8; 36];
            keyed[0..4].copy_from_slice(&key_id.0.to_le_bytes());
            keyed[4..36].copy_from_slice(&data_hash);
            *mac_out = Self::simple_hash(&keyed);
            Ok(())
        }

        fn ecdh_derive_shared(
            &self,
            private_key_id: KeyId,
            peer_public: &[u8; 65],
            shared_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            let mut buf = [0u8; 69];
            buf[0..4].copy_from_slice(&private_key_id.0.to_le_bytes());
            buf[4..69].copy_from_slice(peer_public);
            *shared_out = Self::simple_hash(&buf);
            Ok(())
        }

        fn sign_p256(
            &self,
            key_id: KeyId,
            digest: &[u8; 32],
            sig_out: &mut [u8; 64],
        ) -> Result<(), VsError> {
            let mut input = [0u8; 36];
            input[0..4].copy_from_slice(&key_id.0.to_le_bytes());
            input[4..36].copy_from_slice(digest);
            let r = Self::simple_hash(&input);
            input[0] ^= 0xFF;
            let s = Self::simple_hash(&input);
            sig_out[..32].copy_from_slice(&r);
            sig_out[32..].copy_from_slice(&s);
            Ok(())
        }

        fn verify_p256(
            &self,
            _pub_key: &[u8; 65],
            digest: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<bool, VsError> {
            // Re-derive the expected signature from test key id 1.
            let mut input = [0u8; 36];
            input[0..4].copy_from_slice(&1u32.to_le_bytes());
            input[4..36].copy_from_slice(digest);
            let r = Self::simple_hash(&input);
            input[0] ^= 0xFF;
            let s = Self::simple_hash(&input);
            Ok(sig[..32] == r && sig[32..] == s)
        }

        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            for chunk in buf.chunks_mut(8) {
                let val = self.next_u64();
                let bytes = val.to_le_bytes();
                for (dst, &src) in chunk.iter_mut().zip(bytes.iter()) {
                    *dst = src;
                }
            }
            Ok(())
        }

        fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
    }

    // Helper: pre-filled results buffer.
    fn empty_results() -> [IntegrityResult; 8] {
        [IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        }; 8]
    }

    // -----------------------------------------------------------------------
    // Original tests (updated for new API)
    // -----------------------------------------------------------------------

    #[test]
    fn register_and_verify_intact() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Hello, CratonShield!";

        monitor.register_region(1, 0x1000, data).expect("register");
        let result = monitor.verify_region(1, 0x1000, data).expect("verify");
        assert_eq!(result.status, IntegrityStatus::Ok);
    }

    #[test]
    fn detect_single_byte_tamper() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Original firmware data here.";

        monitor.register_region(1, 0x2000, data).expect("register");

        let mut tampered = *data;
        tampered[0] = b'X';

        let result = monitor.verify_region(1, 0x2000, &tampered).expect("verify");
        assert_eq!(result.status, IntegrityStatus::Tampered);
    }

    #[test]
    fn detect_length_change() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Fixed length data";

        monitor.register_region(1, 0x3000, data).expect("register");

        let result = monitor.verify_region(1, 0x3000, b"Short").expect("verify");
        assert_eq!(result.status, IntegrityStatus::Tampered);
    }

    #[test]
    fn verify_all_regions() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"Region one data";
        let data2 = b"Region two data";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        let mut results = empty_results();
        let count = monitor
            .verify_all(
                |id, _addr, _len| match id {
                    1 => Some(data1.as_slice()),
                    2 => Some(data2.as_slice()),
                    _ => None,
                },
                &mut results,
            )
            .expect("verify_all");

        assert_eq!(count, 2);
        assert_eq!(results[0].status, IntegrityStatus::Ok);
        assert_eq!(results[1].status, IntegrityStatus::Ok);
    }

    #[test]
    fn verify_all_detects_partial_tamper() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"Good region";
        let data2 = b"Bad region!";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        let mut results = empty_results();
        let count = monitor
            .verify_all(
                |id, _addr, _len| match id {
                    1 => Some(data1.as_slice()),
                    2 => Some(b"TAMPERED!!!".as_slice()),
                    _ => None,
                },
                &mut results,
            )
            .expect("verify_all");

        assert_eq!(count, 2);
        assert_eq!(results[0].status, IntegrityStatus::Ok);
        assert_eq!(results[1].status, IntegrityStatus::Tampered);
    }

    #[test]
    fn unregister_region() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Some data";

        monitor.register_region(1, 0x1000, data).expect("register");
        assert_eq!(monitor.active_region_count(), 1);

        monitor.unregister_region(1).expect("unregister");
        assert_eq!(monitor.active_region_count(), 0);
        assert!(monitor.get_region(1).is_none());
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Data";

        monitor.register_region(1, 0x1000, data).expect("first");
        let result = monitor.register_region(1, 0x2000, data);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn capacity_limit() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"X";

        for i in 0..MAX_REGIONS {
            monitor
                .register_region(i as u32, i * 0x100, data)
                .expect("register");
        }

        let result = monitor.register_region(MAX_REGIONS as u32, 0xFFFF, data);
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn measurement_counter_increments() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Counter test";

        monitor.register_region(1, 0x1000, data).expect("register");
        assert_eq!(monitor.measurement_count(), 0);

        monitor.verify_region(1, 0x1000, data).expect("verify1");
        assert_eq!(monitor.measurement_count(), 1);

        monitor.verify_region(1, 0x1000, data).expect("verify2");
        assert_eq!(monitor.measurement_count(), 2);
    }

    #[test]
    fn update_baseline() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Old data";
        let new_data = b"New data here!";

        monitor.register_region(1, 0x1000, data).expect("register");

        let r = monitor.verify_region(1, 0x1000, data).expect("verify old");
        assert_eq!(r.status, IntegrityStatus::Ok);

        monitor.update_baseline(1, new_data, None).expect("update");

        let r = monitor
            .verify_region(1, 0x1000, data)
            .expect("verify old after update");
        assert_eq!(r.status, IntegrityStatus::Tampered);

        let r = monitor
            .verify_region(1, 0x1000, new_data)
            .expect("verify new");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    #[test]
    fn nonexistent_region_returns_error() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let result = monitor.verify_region(99, 0x0, b"data");
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn verify_region_with_all_zero_data() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = [0u8; 64];
        monitor.register_region(1, 0x1000, &data).expect("register");
        let result = monitor.verify_region(1, 0x1000, &data).expect("verify");
        assert_eq!(result.status, IntegrityStatus::Ok);
    }

    #[test]
    fn verify_region_with_max_size_data() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = [0xAB_u8; 1024];
        monitor.register_region(1, 0x1000, &data).expect("register");
        let result = monitor.verify_region(1, 0x1000, &data).expect("verify");
        assert_eq!(result.status, IntegrityStatus::Ok);
    }

    #[test]
    fn register_unregister_reregister_same_id() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"First registration";
        monitor.register_region(1, 0x1000, data).expect("register");
        assert_eq!(monitor.active_region_count(), 1);

        monitor.unregister_region(1).expect("unregister");
        assert_eq!(monitor.active_region_count(), 0);

        let data2 = b"Second registration";
        monitor
            .register_region(1, 0x2000, data2)
            .expect("re-register");
        assert_eq!(monitor.active_region_count(), 1);

        let result = monitor.verify_region(1, 0x2000, data2).expect("verify");
        assert_eq!(result.status, IntegrityStatus::Ok);
    }

    #[test]
    fn unregister_nonexistent_region_returns_error() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let result = monitor.unregister_region(42);
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn update_baseline_nonexistent_region_returns_error() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let result = monitor.update_baseline(42, b"new data", None);
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn verify_all_with_empty_data_provider() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"Region one";
        let data2 = b"Region two";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        let mut results = empty_results();
        let count = monitor
            .verify_all(|_id, _addr, _len| None, &mut results)
            .expect("verify_all");

        assert_eq!(count, 2);
        assert_eq!(results[0].status, IntegrityStatus::Unavailable);
        assert_eq!(results[1].status, IntegrityStatus::Unavailable);
    }

    #[test]
    fn verify_all_rejects_small_buffer() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Some data";

        monitor.register_region(1, 0x1000, data).expect("reg1");
        monitor.register_region(2, 0x2000, data).expect("reg2");
        monitor.register_region(3, 0x3000, data).expect("reg3");

        // Only room for 2 results, but 3 active regions → error.
        let mut results = [IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        }; 2];

        let err = monitor
            .verify_all(|_id, _addr, _len| Some(data.as_slice()), &mut results)
            .unwrap_err();
        assert_eq!(err, VsError::InvalidInput);
    }

    #[test]
    fn active_region_count_after_multiple_register_unregister_cycles() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"data";

        monitor.register_region(1, 0x1000, data).expect("reg1");
        monitor.register_region(2, 0x2000, data).expect("reg2");
        monitor.register_region(3, 0x3000, data).expect("reg3");
        assert_eq!(monitor.active_region_count(), 3);

        monitor.unregister_region(2).expect("unreg2");
        assert_eq!(monitor.active_region_count(), 2);

        monitor.unregister_region(1).expect("unreg1");
        assert_eq!(monitor.active_region_count(), 1);

        monitor.unregister_region(3).expect("unreg3");
        assert_eq!(monitor.active_region_count(), 0);
    }

    #[test]
    fn measurement_counter_no_increment_on_length_mismatch() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Fixed length data";

        monitor.register_region(1, 0x1000, data).expect("register");
        assert_eq!(monitor.measurement_count(), 0);

        let result = monitor.verify_region(1, 0x1000, b"Short").expect("verify");
        assert_eq!(result.status, IntegrityStatus::Tampered);
        assert_eq!(monitor.measurement_count(), 0);
    }

    #[test]
    fn measurement_counter_no_increment_on_crypto_error() {
        struct FailCrypto {
            fail_on_verify: bool,
        }
        impl CryptoProvider for FailCrypto {
            fn aes_gcm_encrypt(
                &self,
                _: KeyId,
                _: &[u8; 12],
                _: &[u8],
                _: &[u8],
                _: &mut [u8],
                _: &mut [u8; 16],
            ) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn aes_gcm_decrypt(
                &self,
                _: KeyId,
                _: &[u8; 12],
                _: &[u8],
                _: &[u8],
                _: &[u8; 16],
                _: &mut [u8],
            ) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
                if self.fail_on_verify {
                    return Err(VsError::CryptoError);
                }
                *hash_out = TestCrypto::simple_hash(data);
                Ok(())
            }
            fn hmac_sha256(&self, _: KeyId, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn ecdh_derive_shared(
                &self,
                _: KeyId,
                _: &[u8; 65],
                _: &mut [u8; 32],
            ) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn verify_p256(
                &self,
                _: &[u8; 65],
                _: &[u8; 32],
                _: &[u8; 64],
            ) -> Result<bool, VsError> {
                Err(VsError::CryptoError)
            }
            fn random_bytes(&self, _: &mut [u8]) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
            fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
                Err(VsError::CryptoError)
            }
        }

        let mut monitor = IntegrityMonitor::new(FailCrypto {
            fail_on_verify: false,
        });
        let data = b"Some data here";
        monitor.register_region(1, 0x1000, data).expect("register");

        // Now make crypto fail — verify_region returns Err.
        monitor.crypto = FailCrypto {
            fail_on_verify: true,
        };
        let err = monitor.verify_region(1, 0x1000, data).unwrap_err();
        assert_eq!(err, VsError::CryptoError);
        assert_eq!(monitor.measurement_count(), 0);
    }

    #[test]
    fn get_region_returns_correct_metadata() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Region metadata test";
        monitor.register_region(42, 0xBEEF, data).expect("register");

        let info = monitor.get_region(42).expect("get_region");
        assert_eq!(info.id, 42);
        assert_eq!(info.base_addr, 0xBEEF);
        assert_eq!(info.length, data.len());
        assert!(info.active);
    }

    #[test]
    fn two_regions_different_data_verify_independently() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"First region data AAAA";
        let data2 = b"Second region data BBB";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        // Each region's data should not verify against the other.
        let r = monitor
            .verify_region(1, 0x1000, data2)
            .expect("cross-verify");
        assert_eq!(r.status, IntegrityStatus::Tampered);

        let r = monitor
            .verify_region(2, 0x2000, data1)
            .expect("cross-verify");
        assert_eq!(r.status, IntegrityStatus::Tampered);
    }

    #[test]
    fn constant_time_eq_identical_arrays_return_true() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_differing_in_last_byte_return_false() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[31] = 0x43;
        assert!(!vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_ones() {
        let a = [0xFFu8; 32];
        let b = [0xFFu8; 32];
        assert!(vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_first_byte_differs() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[0] = 0x00;
        assert!(!vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_middle_byte_differs() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[15] = 0x00;
        assert!(!vs_types::constant_time_eq_32(&a, &b));
    }

    #[test]
    fn constant_time_eq_completely_different() {
        let a = [0x00u8; 32];
        let b = [0xFFu8; 32];
        assert!(!vs_types::constant_time_eq_32(&a, &b));
    }

    // -----------------------------------------------------------------------
    // New tests: slot reuse (#1)
    // -----------------------------------------------------------------------

    #[test]
    fn slot_reuse_after_unregister_at_capacity() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"X";

        // Fill all 64 slots.
        for i in 0..MAX_REGIONS as u32 {
            monitor
                .register_region(i, i as usize * 0x100, data)
                .expect("register");
        }

        // Free one slot.
        monitor.unregister_region(10).expect("unregister");
        assert_eq!(monitor.active_region_count(), MAX_REGIONS - 1);

        // Registering a new region should reuse the freed slot — not fail.
        monitor
            .register_region(999, 0xF000, data)
            .expect("reuse slot");
        assert_eq!(monitor.active_region_count(), MAX_REGIONS);

        // Verify the new region works.
        let r = monitor
            .verify_region(999, 0xF000, data)
            .expect("verify reused");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    #[test]
    fn slot_reuse_does_not_leak_old_capacity() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"D";

        // Register and unregister the same ID many times.
        for _ in 0..MAX_REGIONS * 3 {
            monitor.register_region(1, 0x1000, data).expect("reg");
            monitor.unregister_region(1).expect("unreg");
        }

        // Should still be able to register — slots are reused.
        monitor.register_region(1, 0x1000, data).expect("final reg");
        assert_eq!(monitor.active_region_count(), 1);
        // region_count should be 1, not 192.
        let (allocated, _) = monitor.region_capacity();
        assert_eq!(allocated, 1);
    }

    // -----------------------------------------------------------------------
    // New tests: base_addr validation (#5)
    // -----------------------------------------------------------------------

    #[test]
    fn base_addr_mismatch_returns_error() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"addr test";
        monitor.register_region(1, 0x1000, data).expect("register");

        let err = monitor.verify_region(1, 0x2000, data).unwrap_err();
        assert_eq!(err, VsError::InvalidInput);
    }

    // -----------------------------------------------------------------------
    // New tests: counter saturation (#6)
    // -----------------------------------------------------------------------

    #[test]
    fn counter_saturation_returns_error() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"sat test";
        monitor.register_region(1, 0x1000, data).expect("register");

        // Force counter to MAX.
        monitor.measurement_counter = u64::MAX;
        assert!(monitor.is_counter_saturated());

        let err = monitor.verify_region(1, 0x1000, data).unwrap_err();
        assert_eq!(err, VsError::ResourceExhausted);
    }

    // -----------------------------------------------------------------------
    // New tests: verify_all buffer too small (#8)
    // -----------------------------------------------------------------------

    #[test]
    fn verify_all_empty_buffer_with_active_regions() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor
            .register_region(1, 0x1000, b"data")
            .expect("register");

        let mut results = [];
        let err = monitor
            .verify_all(|_, _, _| Some(b"data".as_slice()), &mut results)
            .unwrap_err();
        assert_eq!(err, VsError::InvalidInput);
    }

    // -----------------------------------------------------------------------
    // New tests: HMAC-authenticated baseline updates (#3)
    // -----------------------------------------------------------------------

    #[test]
    fn update_baseline_with_valid_auth() {
        let crypto = TestCrypto::new();
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"original";
        let new_data = b"updated!";
        let auth_key: KeyId = KeyId(42);

        monitor.register_region(1, 0x1000, data).expect("register");
        monitor.set_auth_key(auth_key);

        // Compute valid auth tag.
        let msg = build_update_auth_message(&crypto, 1, new_data).expect("build msg");
        let mut tag = [0u8; 32];
        crypto.hmac_sha256(auth_key, &msg, &mut tag).expect("hmac");

        monitor
            .update_baseline(1, new_data, Some(&tag))
            .expect("authed update");

        let r = monitor.verify_region(1, 0x1000, new_data).expect("verify");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    #[test]
    fn update_baseline_with_invalid_auth() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"original";
        let new_data = b"updated!";

        monitor.register_region(1, 0x1000, data).expect("register");
        monitor.set_auth_key(KeyId(42));

        let bad_tag = [0xFFu8; 32];
        let err = monitor
            .update_baseline(1, new_data, Some(&bad_tag))
            .unwrap_err();
        assert_eq!(err, VsError::AuthenticationFailure);

        // Baseline should be unchanged.
        let r = monitor
            .verify_region(1, 0x1000, data)
            .expect("verify unchanged");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    #[test]
    fn update_baseline_missing_tag_when_auth_required() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"original";

        monitor.register_region(1, 0x1000, data).expect("register");
        monitor.set_auth_key(KeyId(42));

        let err = monitor.update_baseline(1, b"new data", None).unwrap_err();
        assert_eq!(err, VsError::AuthenticationFailure);
    }

    #[test]
    fn update_baseline_without_auth_key_ignores_tag() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"original";
        let new_data = b"updated!";

        monitor.register_region(1, 0x1000, data).expect("register");

        // No auth key set — tag is ignored.
        monitor.update_baseline(1, new_data, None).expect("update");

        let r = monitor.verify_region(1, 0x1000, new_data).expect("verify");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    // -----------------------------------------------------------------------
    // New tests: tick-based scheduling (#12)
    // -----------------------------------------------------------------------

    #[test]
    fn tick_fires_at_interval() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.set_check_interval(3);

        assert!(!monitor.tick()); // 1
        assert!(!monitor.tick()); // 2
        assert!(monitor.tick()); // 3 → fires

        assert!(!monitor.tick()); // 1
        assert!(!monitor.tick()); // 2
        assert!(monitor.tick()); // 3 → fires again
    }

    #[test]
    fn tick_disabled_when_interval_zero() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.set_check_interval(0);

        for _ in 0..100 {
            assert!(!monitor.tick());
        }
    }

    // -----------------------------------------------------------------------
    // New tests: tamper callback (#13)
    // -----------------------------------------------------------------------

    use core::sync::atomic::{AtomicU32, Ordering};

    static TAMPER_REGION_ID: AtomicU32 = AtomicU32::new(0);

    fn test_tamper_callback(region_id: u32, _base_addr: usize, _sev: AlertSeverity) {
        TAMPER_REGION_ID.store(region_id, Ordering::SeqCst);
    }

    #[test]
    fn tamper_callback_fires_on_tamper() {
        TAMPER_REGION_ID.store(0, Ordering::SeqCst);

        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.set_tamper_callback(test_tamper_callback);

        let data = b"good data";
        monitor.register_region(7, 0x1000, data).expect("register");

        let _ = monitor.verify_region(7, 0x1000, b"BAD__DATA");
        assert_eq!(TAMPER_REGION_ID.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn tamper_callback_not_called_on_ok() {
        TAMPER_REGION_ID.store(0, Ordering::SeqCst);

        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.set_tamper_callback(test_tamper_callback);

        let data = b"good data";
        monitor.register_region(5, 0x1000, data).expect("register");

        let _ = monitor.verify_region(5, 0x1000, data);
        // Callback should NOT have fired.
        assert_eq!(TAMPER_REGION_ID.load(Ordering::SeqCst), 0);
    }

    // -----------------------------------------------------------------------
    // New tests: snapshot / restore (#14)
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_and_restore_roundtrip() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"persist me";
        monitor.register_region(1, 0x1000, data).expect("register");
        monitor.set_auth_key(KeyId(99));
        monitor.set_check_interval(5);
        monitor.verify_region(1, 0x1000, data).expect("verify");

        let snap = monitor.snapshot().expect("snapshot");

        // Restore into a new monitor.
        let mut restored =
            IntegrityMonitor::from_snapshot(snap, TestCrypto::new()).expect("from_snapshot");

        // State should be preserved.
        assert_eq!(restored.measurement_count(), 1);
        assert_eq!(restored.active_region_count(), 1);

        let r = restored
            .verify_region(1, 0x1000, data)
            .expect("verify restored");
        assert_eq!(r.status, IntegrityStatus::Ok);
    }

    // -----------------------------------------------------------------------
    // New tests: clear_all (#11)
    // -----------------------------------------------------------------------

    #[test]
    fn clear_all_resets_everything() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"data";

        monitor.register_region(1, 0x1000, data).expect("reg1");
        monitor.register_region(2, 0x2000, data).expect("reg2");
        monitor.verify_region(1, 0x1000, data).expect("verify");

        assert_eq!(monitor.active_region_count(), 2);
        assert_eq!(monitor.measurement_count(), 1);

        monitor.clear_all();

        assert_eq!(monitor.active_region_count(), 0);
        assert_eq!(monitor.measurement_count(), 0);
        assert_eq!(monitor.epoch(), 0);
        let (allocated, _) = monitor.region_capacity();
        assert_eq!(allocated, 0);
    }

    // -----------------------------------------------------------------------
    // New tests: epoch tracking (#4 freshness)
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_increments_on_verify_all() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"epoch test";
        monitor.register_region(1, 0x1000, data).expect("register");

        assert_eq!(monitor.epoch(), 0);

        let mut results = empty_results();
        monitor
            .verify_all(|_, _, _| Some(data.as_slice()), &mut results)
            .expect("v1");
        assert_eq!(monitor.epoch(), 1);

        monitor
            .verify_all(|_, _, _| Some(data.as_slice()), &mut results)
            .expect("v2");
        assert_eq!(monitor.epoch(), 2);
    }

    #[test]
    fn last_verified_epoch_tracks_per_region() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"region one";
        let data2 = b"region two";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        // Verify all once.
        let mut results = empty_results();
        monitor
            .verify_all(
                |id, _, _| match id {
                    1 => Some(data1.as_slice()),
                    2 => Some(data2.as_slice()),
                    _ => None,
                },
                &mut results,
            )
            .expect("verify_all");

        let info1 = monitor.get_region(1).unwrap();
        let info2 = monitor.get_region(2).unwrap();
        assert_eq!(info1.last_verified_epoch, 1);
        assert_eq!(info2.last_verified_epoch, 1);

        // Verify again but region 2 is unavailable.
        monitor
            .verify_all(
                |id, _, _| match id {
                    1 => Some(data1.as_slice()),
                    _ => None,
                },
                &mut results,
            )
            .expect("verify_all 2");

        let info1 = monitor.get_region(1).unwrap();
        let info2 = monitor.get_region(2).unwrap();
        assert_eq!(info1.last_verified_epoch, 2);
        // Region 2 was unavailable — epoch should NOT have advanced.
        assert_eq!(info2.last_verified_epoch, 1);
    }

    // -----------------------------------------------------------------------
    // New tests: TestCrypto full coverage (#15)
    // -----------------------------------------------------------------------

    #[test]
    fn test_crypto_aes_gcm_roundtrip() {
        let crypto = TestCrypto::new();
        let key_id: KeyId = KeyId(1);
        let nonce = [0u8; 12];
        let plaintext = b"secret payload!";
        let aad = b"header";

        let mut ct = [0u8; 15];
        let mut tag = [0u8; 16];
        crypto
            .aes_gcm_encrypt(key_id, &nonce, plaintext, aad, &mut ct, &mut tag)
            .expect("encrypt");

        let mut recovered = [0u8; 15];
        crypto
            .aes_gcm_decrypt(key_id, &nonce, &ct, aad, &tag, &mut recovered)
            .expect("decrypt");

        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn test_crypto_aes_gcm_bad_tag_rejected() {
        let crypto = TestCrypto::new();
        let key_id: KeyId = KeyId(1);
        let nonce = [0u8; 12];
        let plaintext = b"secret";

        let mut ct = [0u8; 6];
        let mut tag = [0u8; 16];
        crypto
            .aes_gcm_encrypt(key_id, &nonce, plaintext, b"", &mut ct, &mut tag)
            .expect("encrypt");

        // Flip a tag byte.
        tag[0] ^= 0xFF;
        let mut pt = [0u8; 6];
        let err = crypto
            .aes_gcm_decrypt(key_id, &nonce, &ct, b"", &tag, &mut pt)
            .unwrap_err();
        assert_eq!(err, VsError::AuthenticationFailure);
    }

    #[test]
    fn test_crypto_hmac_key_dependent() {
        let crypto = TestCrypto::new();
        let data = b"same data";

        let mut mac1 = [0u8; 32];
        let mut mac2 = [0u8; 32];
        crypto
            .hmac_sha256(KeyId(1), data, &mut mac1)
            .expect("hmac1");
        crypto
            .hmac_sha256(KeyId(2), data, &mut mac2)
            .expect("hmac2");

        assert_ne!(mac1, mac2, "different keys must produce different MACs");
    }

    #[test]
    fn test_crypto_hmac_data_dependent() {
        let crypto = TestCrypto::new();

        let mut mac1 = [0u8; 32];
        let mut mac2 = [0u8; 32];
        crypto
            .hmac_sha256(KeyId(1), b"aaa", &mut mac1)
            .expect("hmac1");
        crypto
            .hmac_sha256(KeyId(1), b"bbb", &mut mac2)
            .expect("hmac2");

        assert_ne!(mac1, mac2, "different data must produce different MACs");
    }

    #[test]
    fn test_crypto_ecdh() {
        let crypto = TestCrypto::new();
        let mut shared = [0u8; 32];
        let peer_pub = [0x04u8; 65];
        crypto
            .ecdh_derive_shared(KeyId(1), &peer_pub, &mut shared)
            .expect("ecdh");
        assert_ne!(shared, [0u8; 32], "shared secret should not be all zeros");
    }

    #[test]
    fn test_crypto_sign_verify_roundtrip() {
        let crypto = TestCrypto::new();
        let digest = TestCrypto::simple_hash(b"message");
        let mut sig = [0u8; 64];
        crypto.sign_p256(KeyId(1), &digest, &mut sig).expect("sign");

        let pub_key = [0x04u8; 65];
        let valid = crypto.verify_p256(&pub_key, &digest, &sig).expect("verify");
        assert!(valid);
    }

    #[test]
    fn test_crypto_random_bytes_fills_buffer() {
        let crypto = TestCrypto::new();
        let mut buf = [0u8; 32];
        crypto.random_bytes(&mut buf).expect("random");
        assert_ne!(buf, [0u8; 32], "random output should not be all zeros");
    }

    #[test]
    fn test_crypto_random_bytes_deterministic() {
        let c1 = TestCrypto::new();
        let c2 = TestCrypto::new();
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        c1.random_bytes(&mut buf1).expect("r1");
        c2.random_bytes(&mut buf2).expect("r2");
        assert_eq!(buf1, buf2, "same seed must produce same output");
    }

    // -----------------------------------------------------------------------
    // New test: unregister zeros the hash
    // -----------------------------------------------------------------------

    #[test]
    fn unregister_prevents_old_data_verification() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"sensitive firmware";
        monitor.register_region(1, 0x1000, data).expect("register");
        monitor.unregister_region(1).expect("unregister");

        // Cannot verify a deactivated region.
        let err = monitor.verify_region(1, 0x1000, data).unwrap_err();
        assert_eq!(err, VsError::NotFound);
    }

    // -----------------------------------------------------------------------
    // New tests: verify_all_fast (early-exit)
    // -----------------------------------------------------------------------

    #[test]
    fn verify_all_fast_all_ok() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"Region one data";
        let data2 = b"Region two data";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");

        let mut failure = IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        };
        let ok = monitor
            .verify_all_fast(
                |id, _addr, _len| match id {
                    1 => Some(data1.as_slice()),
                    2 => Some(data2.as_slice()),
                    _ => None,
                },
                &mut failure,
            )
            .expect("verify_all_fast");

        assert!(ok, "all regions intact should return true");
    }

    #[test]
    fn verify_all_fast_stops_on_first_tamper() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data1 = b"Good region";
        let data2 = b"Bad region!";
        let data3 = b"Third regi.";

        monitor.register_region(1, 0x1000, data1).expect("reg1");
        monitor.register_region(2, 0x2000, data2).expect("reg2");
        monitor.register_region(3, 0x3000, data3).expect("reg3");

        let counter_before = monitor.measurement_count();

        let mut failure = IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        };
        let ok = monitor
            .verify_all_fast(
                |id, _addr, _len| match id {
                    1 => Some(data1.as_slice()),
                    2 => Some(b"TAMPERED!!!".as_slice()),
                    3 => Some(data3.as_slice()),
                    _ => None,
                },
                &mut failure,
            )
            .expect("verify_all_fast");

        assert!(!ok, "should detect tamper");
        assert_eq!(failure.region_id, 2);
        assert_eq!(failure.status, IntegrityStatus::Tampered);

        // Counter should have incremented for region 1 (OK) and region 2
        // (hash computed before comparison), but NOT region 3 (skipped).
        assert_eq!(monitor.measurement_count(), counter_before + 2);
    }

    #[test]
    fn verify_all_fast_stops_on_unavailable() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Region data";

        monitor.register_region(1, 0x1000, data).expect("reg1");
        monitor.register_region(2, 0x2000, data).expect("reg2");

        let mut failure = IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Ok,
        };
        let ok = monitor
            .verify_all_fast(|_id, _addr, _len| None, &mut failure)
            .expect("verify_all_fast");

        assert!(!ok, "should detect unavailable");
        assert_eq!(failure.region_id, 1);
        assert_eq!(failure.status, IntegrityStatus::Unavailable);
    }

    #[test]
    fn verify_all_fast_no_regions_returns_true() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());

        let mut failure = IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        };
        let ok = monitor
            .verify_all_fast(|_, _, _| None, &mut failure)
            .expect("verify_all_fast empty");

        assert!(ok, "no regions means nothing to fail");
    }

    #[test]
    fn verify_all_fast_detects_length_mismatch() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        let data = b"Fixed length data";

        monitor.register_region(1, 0x1000, data).expect("register");

        let mut failure = IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Ok,
        };
        let ok = monitor
            .verify_all_fast(|_id, _addr, _len| Some(b"Short".as_slice()), &mut failure)
            .expect("verify_all_fast");

        assert!(!ok);
        assert_eq!(failure.region_id, 1);
        assert_eq!(failure.status, IntegrityStatus::Tampered);
    }

    // -----------------------------------------------------------------------
    // Snapshot authentication field tests
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_unauthenticated_has_authenticated_false() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.register_region(1, 0x1000, b"data").unwrap();
        let snap = monitor.snapshot().unwrap();
        assert!(
            !snap.authenticated,
            "no auth key => authenticated must be false"
        );
        assert_eq!(snap.hmac, [0u8; 32], "no auth key => hmac must be zero");
    }

    #[test]
    fn snapshot_authenticated_has_authenticated_true() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.register_region(1, 0x1000, b"data").unwrap();
        monitor.set_auth_key(KeyId(42));
        let snap = monitor.snapshot().unwrap();
        assert!(
            snap.authenticated,
            "auth key set => authenticated must be true"
        );
        assert_ne!(
            snap.hmac, [0u8; 32],
            "auth key set => hmac must be non-zero"
        );
    }

    #[test]
    fn snapshot_forgery_with_zero_hmac_rejected() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.register_region(1, 0x1000, b"data").unwrap();
        monitor.set_auth_key(KeyId(42));
        let mut snap = monitor.snapshot().unwrap();

        // Attacker zeroes the HMAC and clears authenticated.
        snap.hmac = [0u8; 32];
        snap.authenticated = false;

        // Should still fail because auth_key_id_present is true but
        // authenticated is false.
        let result = IntegrityMonitor::from_snapshot(snap, TestCrypto::new());
        assert!(
            matches!(result, Err(VsError::AuthenticationFailure)),
            "forgery with zero HMAC must be rejected"
        );
    }

    #[test]
    fn snapshot_tampered_hmac_rejected() {
        let mut monitor = IntegrityMonitor::new(TestCrypto::new());
        monitor.register_region(1, 0x1000, b"data").unwrap();
        monitor.set_auth_key(KeyId(42));
        let mut snap = monitor.snapshot().unwrap();

        // Flip a bit in the HMAC.
        snap.hmac[0] ^= 0x01;

        let result = IntegrityMonitor::from_snapshot(snap, TestCrypto::new());
        assert!(
            matches!(result, Err(VsError::AuthenticationFailure)),
            "tampered HMAC must be rejected"
        );
    }
}
