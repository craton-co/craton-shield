// SPDX-License-Identifier: Apache-2.0
//! Rollback counter abstraction for OTA update security.
//!
//! Provides a [`RollbackCounter`] trait that abstracts monotonic counter
//! access, enabling OTA validators to use either software (RAM/storage)
//! or hardware (HSM OTP fuse) backed counters.

use vs_types::VsError;

/// Maximum number of increments the default [`RollbackCounter::advance_to`]
/// implementation will perform in a single call.  Prevents unbounded
/// fuse burn on hardware-backed counters.
const DEFAULT_MAX_ADVANCE_STEPS: u64 = 64;

/// Monotonic rollback counter that cannot be decremented.
///
/// Implementations may be backed by:
/// - Software RAM (testing only — [`SoftwareRollbackCounter`])
/// - HSM OTP fuses ([`HsmRollbackCounter`]) for hardware-backed irreversibility
/// - [`StorageProvider`](vs_storage::StorageProvider) persistence
pub trait RollbackCounter {
    /// Read the current counter value.
    fn read(&self) -> Result<u64, VsError>;

    /// Increment the counter by 1. Returns the new value.
    ///
    /// On hardware-backed counters (OTP fuses), this is **irreversible**.
    fn increment(&mut self) -> Result<u64, VsError>;

    /// Advance the counter to at least `target`.
    ///
    /// Increments the counter repeatedly until it reaches or exceeds `target`.
    /// Returns the final counter value.
    ///
    /// The default implementation caps the number of increments at a configured
    /// maximum to prevent unbounded fuse burn on hardware-backed counters.
    /// Returns [`VsError::PolicyViolation`] if the gap exceeds this limit.
    ///
    /// [`HsmRollbackCounter`] applies its own stricter cap
    /// (`MAX_FUSE_BURN_PER_CALL = 10`).
    fn advance_to(&mut self, target: u64) -> Result<u64, VsError> {
        let current = self.read()?;
        if current >= target {
            return Ok(current);
        }
        let gap = target.saturating_sub(current);
        if gap > DEFAULT_MAX_ADVANCE_STEPS {
            return Err(VsError::PolicyViolation);
        }
        let mut remaining = gap;
        while remaining > 0 {
            self.increment()?;
            remaining -= 1;
        }
        self.read()
    }
}

// ---------------------------------------------------------------------------
// Software (RAM) counter — testing only
// ---------------------------------------------------------------------------

/// RAM-only rollback counter for unit testing.
pub struct SoftwareRollbackCounter {
    value: u64,
}

impl SoftwareRollbackCounter {
    /// Create a new counter starting at 0.
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Create a counter with an initial value.
    pub fn with_initial(value: u64) -> Self {
        Self { value }
    }
}

impl Default for SoftwareRollbackCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl RollbackCounter for SoftwareRollbackCounter {
    fn read(&self) -> Result<u64, VsError> {
        Ok(self.value)
    }

    fn increment(&mut self) -> Result<u64, VsError> {
        self.value = self
            .value
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        Ok(self.value)
    }
}

// ---------------------------------------------------------------------------
// HSM-backed counter — delegates to HsmHardware trait
// ---------------------------------------------------------------------------

use vs_hal::HsmHardware;

/// Maximum number of OTP fuses that [`HsmRollbackCounter::advance_to`]
/// will burn in a single call.  Attempting to advance further returns
/// [`VsError::PolicyViolation`].
const MAX_FUSE_BURN_PER_CALL: u64 = 10;

/// HSM OTP fuse-backed rollback counter.
///
/// Delegates to [`HsmHardware::hsm_read_monotonic_counter`] and
/// [`HsmHardware::hsm_increment_monotonic_counter`]. On real hardware
/// (NXP HSE), increments burn OTP fuses and are permanently irreversible.
pub struct HsmRollbackCounter<H: HsmHardware> {
    hsm: H,
}

impl<H: HsmHardware> HsmRollbackCounter<H> {
    /// Wrap an HSM hardware instance as a rollback counter.
    pub fn new(hsm: H) -> Self {
        Self { hsm }
    }

    /// Access the underlying HSM.
    pub fn hsm(&self) -> &H {
        &self.hsm
    }
}

impl<H: HsmHardware> RollbackCounter for HsmRollbackCounter<H> {
    fn read(&self) -> Result<u64, VsError> {
        self.hsm.hsm_read_monotonic_counter()
    }

    fn increment(&mut self) -> Result<u64, VsError> {
        self.hsm.hsm_increment_monotonic_counter()
    }

    /// Advance the counter to `target` with a safety cap.
    ///
    /// Returns [`VsError::PolicyViolation`] if the gap between the current
    /// value and `target` exceeds `MAX_FUSE_BURN_PER_CALL` (10) to prevent
    /// accidentally burning a large number of OTP fuses.
    fn advance_to(&mut self, target: u64) -> Result<u64, VsError> {
        let current = self.read()?;
        if current >= target {
            return Ok(current);
        }
        let gap = target - current;
        if gap > MAX_FUSE_BURN_PER_CALL {
            return Err(VsError::PolicyViolation);
        }
        let mut val = current;
        while val < target {
            val = self.increment()?;
        }
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use vs_hal::{HsmCapabilities, HsmSlotId};

    // -- Software counter tests -------------------------------------------

    #[test]
    fn software_counter_starts_at_zero() {
        let counter = SoftwareRollbackCounter::new();
        assert_eq!(counter.read(), Ok(0));
    }

    #[test]
    fn software_counter_increment() {
        let mut counter = SoftwareRollbackCounter::new();
        assert_eq!(counter.increment(), Ok(1));
        assert_eq!(counter.read(), Ok(1));
    }

    #[test]
    fn software_counter_multiple_increments() {
        let mut counter = SoftwareRollbackCounter::new();
        for i in 1..=10 {
            assert_eq!(counter.increment(), Ok(i));
        }
        assert_eq!(counter.read(), Ok(10));
    }

    #[test]
    fn software_counter_with_initial_value() {
        let counter = SoftwareRollbackCounter::with_initial(42);
        assert_eq!(counter.read(), Ok(42));
    }

    #[test]
    fn software_counter_default() {
        let counter = SoftwareRollbackCounter::default();
        assert_eq!(counter.read(), Ok(0));
    }

    #[test]
    fn software_counter_advance_to() {
        let mut counter = SoftwareRollbackCounter::new();
        assert_eq!(counter.advance_to(5), Ok(5));
        assert_eq!(counter.read(), Ok(5));
    }

    #[test]
    fn software_counter_advance_to_already_past() {
        let mut counter = SoftwareRollbackCounter::with_initial(10);
        assert_eq!(counter.advance_to(5), Ok(10)); // already past
        assert_eq!(counter.read(), Ok(10));
    }

    #[test]
    fn software_counter_advance_to_exact() {
        let mut counter = SoftwareRollbackCounter::with_initial(5);
        assert_eq!(counter.advance_to(5), Ok(5)); // already at target
    }

    // -- Mock HSM Hardware for testing ------------------------------------

    /// Mock HSM hardware that uses a Cell<u64> for the monotonic counter.
    struct MockHsmHardware {
        counter: Cell<u64>,
    }

    impl MockHsmHardware {
        fn new() -> Self {
            Self {
                counter: Cell::new(0),
            }
        }

        fn with_initial(value: u64) -> Self {
            Self {
                counter: Cell::new(value),
            }
        }
    }

    impl HsmHardware for MockHsmHardware {
        fn capabilities(&self) -> HsmCapabilities {
            // This mock only exercises the monotonic-counter path; every
            // other primitive returns `NotInitialized`. Reflect that
            // honestly in the capability descriptor so any future caller
            // doesn't mistake the mock for an HMAC/ECDH/AES-capable HSM.
            HsmCapabilities::NONE
        }

        fn hsm_aes_gcm_encrypt(
            &self,
            _slot: HsmSlotId,
            _nonce: &[u8; 12],
            _plaintext: &[u8],
            _aad: &[u8],
            _ciphertext_out: &mut [u8],
            _tag_out: &mut [u8; 16],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_aes_gcm_decrypt(
            &self,
            _slot: HsmSlotId,
            _nonce: &[u8; 12],
            _ciphertext: &[u8],
            _aad: &[u8],
            _tag: &[u8; 16],
            _plaintext_out: &mut [u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_sign_p256(
            &self,
            _slot: HsmSlotId,
            _digest: &[u8; 32],
            _sig_out: &mut [u8; 64],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_verify_p256(
            &self,
            _slot: HsmSlotId,
            _pub_key: &[u8; 65],
            _digest: &[u8; 32],
            _sig: &[u8; 64],
        ) -> Result<bool, VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_sha256(&self, _data: &[u8], _hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_hmac_sha256(
            &self,
            _slot: HsmSlotId,
            _data: &[u8],
            _mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            // Explicit (no trait-level default as of v0.7.1). The mock does
            // not back HMAC; callers must consult `capabilities()`.
            Err(VsError::NotInitialized)
        }

        fn hsm_ecdh_derive(
            &self,
            _private_slot: HsmSlotId,
            _peer_public: &[u8; 65],
            _shared_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            // Explicit (no trait-level default as of v0.7.1). The mock does
            // not back ECDH; callers must consult `capabilities()`.
            Err(VsError::NotInitialized)
        }

        fn hsm_random_bytes(&self, _buf: &mut [u8]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_import_key(
            &mut self,
            _slot: HsmSlotId,
            _key_material: &[u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn hsm_read_monotonic_counter(&self) -> Result<u64, VsError> {
            Ok(self.counter.get())
        }

        fn hsm_increment_monotonic_counter(&mut self) -> Result<u64, VsError> {
            let val = self
                .counter
                .get()
                .checked_add(1)
                .ok_or(VsError::ResourceExhausted)?;
            self.counter.set(val);
            Ok(val)
        }
    }

    // -- HSM counter tests ------------------------------------------------

    #[test]
    fn hsm_counter_read_and_increment() {
        let hsm = MockHsmHardware::new();
        let mut counter = HsmRollbackCounter::new(hsm);
        assert_eq!(counter.read(), Ok(0));
        assert_eq!(counter.increment(), Ok(1));
        assert_eq!(counter.read(), Ok(1));
        assert_eq!(counter.increment(), Ok(2));
        assert_eq!(counter.read(), Ok(2));
    }

    #[test]
    fn hsm_counter_with_initial_value() {
        let hsm = MockHsmHardware::with_initial(10);
        let counter = HsmRollbackCounter::new(hsm);
        assert_eq!(counter.read(), Ok(10));
    }

    #[test]
    fn hsm_counter_advance_to() {
        let hsm = MockHsmHardware::new();
        let mut counter = HsmRollbackCounter::new(hsm);
        assert_eq!(counter.advance_to(5), Ok(5));
        assert_eq!(counter.read(), Ok(5));
    }

    #[test]
    fn hsm_counter_advance_to_already_past() {
        let hsm = MockHsmHardware::with_initial(10);
        let mut counter = HsmRollbackCounter::new(hsm);
        assert_eq!(counter.advance_to(5), Ok(10));
        assert_eq!(counter.read(), Ok(10));
    }

    #[test]
    fn hsm_counter_hsm_accessor() {
        let hsm = MockHsmHardware::with_initial(42);
        let counter = HsmRollbackCounter::new(hsm);
        assert_eq!(counter.hsm().counter.get(), 42);
    }

    // -- Default advance_to safety cap tests ---------------------------------

    #[test]
    fn software_counter_advance_to_within_limit() {
        let mut counter = SoftwareRollbackCounter::new();
        // DEFAULT_MAX_ADVANCE_STEPS = 64, so advancing by 64 should succeed.
        assert_eq!(
            counter.advance_to(super::DEFAULT_MAX_ADVANCE_STEPS),
            Ok(super::DEFAULT_MAX_ADVANCE_STEPS)
        );
    }

    #[test]
    fn software_counter_advance_to_exceeds_limit() {
        let mut counter = SoftwareRollbackCounter::new();
        // Advancing by more than DEFAULT_MAX_ADVANCE_STEPS must fail.
        assert_eq!(
            counter.advance_to(super::DEFAULT_MAX_ADVANCE_STEPS + 1),
            Err(VsError::PolicyViolation)
        );
        // Counter must not have been modified.
        assert_eq!(counter.read(), Ok(0));
    }

    #[test]
    fn hsm_counter_advance_to_exceeds_fuse_burn_cap() {
        let hsm = MockHsmHardware::new();
        let mut counter = HsmRollbackCounter::new(hsm);
        // HSM cap is MAX_FUSE_BURN_PER_CALL = 10.
        assert_eq!(
            counter.advance_to(super::MAX_FUSE_BURN_PER_CALL + 1),
            Err(VsError::PolicyViolation)
        );
        assert_eq!(counter.read(), Ok(0));
    }
}
