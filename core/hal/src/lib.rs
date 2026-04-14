// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

//! Hardware Abstraction Layer (HAL) for `Craton Shield`.
//!
//! Defines traits for hardware interfaces that differ across automotive
//! platforms (NXP S32G, Infineon AURIX, QEMU, etc.). By programming
//! against these traits the core `Craton Shield` logic remains
//! platform-independent.

use vs_types::VsError;

// Safety: prevent the insecure stub HSM from compiling in release builds.
#[cfg(all(feature = "stub-hsm", not(test), not(debug_assertions)))]
compile_error!(
    "The `stub-hsm` feature must not be used in release builds. \
     It provides cryptographically insecure stub implementations \
     intended only for testing."
);

// ---------------------------------------------------------------------------
// CanBus — CAN hardware interface
// ---------------------------------------------------------------------------

/// Raw CAN frame from hardware.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct RawCanFrame {
    /// CAN arbitration ID (11-bit or 29-bit).
    pub id: u32,
    /// Data length code.
    pub dlc: u8,
    /// Payload bytes (up to 8 for CAN, 64 for CAN-FD).
    pub data: [u8; 64],
    /// Hardware timestamp in microseconds.
    pub timestamp_us: u64,
    /// Whether this is a CAN-FD frame.
    pub is_fd: bool,
    /// Whether the extended (29-bit) ID format is used.
    pub is_extended: bool,
}

/// Maximum standard (11-bit) CAN ID.
pub const CAN_ID_STANDARD_MAX: u32 = 0x7FF;

/// Maximum extended (29-bit) CAN ID.
pub const CAN_ID_EXTENDED_MAX: u32 = 0x1FFF_FFFF;

/// CAN-FD DLC-to-byte-length mapping per ISO 11898-1.
///
/// DLC values 0-8 map directly to 0-8 bytes. Values 9-15 map to
/// 12, 16, 20, 24, 32, 48, 64 bytes respectively.
const CAN_FD_DLC_TO_LEN: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

impl RawCanFrame {
    /// Create a zeroed frame.
    pub const fn zeroed() -> Self {
        Self {
            id: 0,
            dlc: 0,
            data: [0u8; 64],
            timestamp_us: 0,
            is_fd: false,
            is_extended: false,
        }
    }

    /// Check whether the CAN arbitration ID is valid for the frame's format.
    ///
    /// Standard frames use 11-bit IDs (max `0x7FF`), extended frames use
    /// 29-bit IDs (max `0x1FFF_FFFF`).
    pub fn is_valid_id(&self) -> bool {
        if self.is_extended {
            self.id <= CAN_ID_EXTENDED_MAX
        } else {
            self.id <= CAN_ID_STANDARD_MAX
        }
    }

    /// Effective payload length in bytes based on DLC.
    ///
    /// For classic CAN the length is `min(dlc, 8)`. For CAN-FD the
    /// non-linear ISO 11898-1 mapping is applied (DLC 9→12, 10→16, …, 15→64).
    pub fn payload_len(&self) -> usize {
        if self.is_fd {
            let idx = (self.dlc as usize).min(15);
            CAN_FD_DLC_TO_LEN[idx]
        } else {
            (self.dlc as usize).min(8)
        }
    }

    /// Return the payload slice `&data[..payload_len()]`.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.payload_len()]
    }
}

/// CAN bus error information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum CanError {
    /// No error.
    None,
    /// Bit stuffing error.
    BitStuffing,
    /// Form error (fixed-form bit field violation).
    FormError,
    /// Acknowledgement error.
    AckError,
    /// Bit recessive/dominant error.
    BitError,
    /// CRC error.
    CrcError,
    /// Bus-off state entered.
    BusOff,
    /// Error-passive state entered.
    ErrorPassive,
    /// Receive buffer overrun.
    Overrun,
}

/// CAN bus error counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CanErrorCounters {
    /// Transmit error counter (0-255, bus-off at 256).
    pub tx_error_count: u16,
    /// Receive error counter (0-255).
    pub rx_error_count: u16,
}

/// Hardware CAN bus interface trait.
///
/// Implementations provide access to physical CAN controllers
/// (`SocketCAN` on Linux, MCAL on AUTOSAR, direct register access on bare
/// metal, etc.).
pub trait CanBus {
    /// Receive the next pending CAN frame, if available.
    ///
    /// Returns `Ok(Some(frame))` if a frame is available, `Ok(None)` if the
    /// receive buffer is empty, or `Err` on hardware error.
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError>;

    /// Transmit a CAN frame.
    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError>;

    /// Return the bus bitrate in bits per second (e.g. `500_000` for 500 kbit/s).
    fn bitrate(&self) -> u32;

    /// Check whether the bus is in error-passive or bus-off state.
    fn is_bus_off(&self) -> bool;

    /// Return the current error state of the CAN controller.
    ///
    /// Default: no error.
    fn last_error(&self) -> CanError {
        CanError::None
    }

    /// Return CAN error counters (TEC/REC).
    ///
    /// Default: zero counters.
    fn error_counters(&self) -> CanErrorCounters {
        CanErrorCounters {
            tx_error_count: 0,
            rx_error_count: 0,
        }
    }

    /// Attempt to recover from bus-off state.
    ///
    /// Default: returns Ok (no-op for controllers with automatic recovery).
    fn recover_bus_off(&mut self) -> Result<(), VsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timer — monotonic clock
// ---------------------------------------------------------------------------

/// Monotonic microsecond timer trait.
///
/// Provides the time source for all `Craton Shield` timestamping,
/// watchdog checks, and connection timeouts.
pub trait Timer {
    /// Return the current monotonic time in microseconds.
    fn now_us(&self) -> u64;

    /// Return the number of CPU cycles since boot (for WCET measurement).
    ///
    /// Returns `None` if cycle counting is not available on this platform.
    fn cycle_count(&self) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// HsmHardware — HSM hardware interface
// ---------------------------------------------------------------------------

/// Key slot identifier for HSM hardware.
pub type HsmSlotId = u32;

/// HSM hardware interface trait.
///
/// Abstracts access to hardware security modules (NXP HSE, Infineon HSM,
/// SHE+, TPM, etc.). The `CryptoProvider`
/// can delegate operations to an `HsmHardware` implementation.
///
/// # Status
///
/// Only `MockHsmHardware` (feature `mock-hsm`)
/// is currently provided. Real HSM integrations (NXP HSE, Infineon SHE+,
/// PKCS#11) are planned — see the roadmap.
pub trait HsmHardware {
    /// Request AES-256-GCM encryption from the HSM.
    ///
    /// # Contract
    ///
    /// `ciphertext_out.len()` **must** equal `plaintext.len()`.
    /// Implementations **must** return [`VsError::InvalidInput`] when
    /// the lengths do not match.
    fn hsm_aes_gcm_encrypt(
        &self,
        slot: HsmSlotId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError>;

    /// Request AES-256-GCM decryption from the HSM.
    ///
    /// # Contract
    ///
    /// `plaintext_out.len()` **must** equal `ciphertext.len()`.
    /// Implementations **must** return [`VsError::InvalidInput`] when
    /// the lengths do not match.
    fn hsm_aes_gcm_decrypt(
        &self,
        slot: HsmSlotId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError>;

    /// Request ECDSA P-256 signing from the HSM.
    fn hsm_sign_p256(
        &self,
        slot: HsmSlotId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError>;

    /// Request ECDSA P-256 verification from the HSM.
    fn hsm_verify_p256(
        &self,
        slot: HsmSlotId,
        pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError>;

    /// Request SHA-256 hashing from the HSM accelerator.
    fn hsm_sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError>;

    /// Request HMAC-SHA-256 from the HSM.
    ///
    /// Real HSM firmware (NXP HSE, Infineon SHE+) exposes HMAC natively.
    /// The default returns [`VsError::NotInitialized`] because a correct
    /// software fallback (RFC 2104) would require extracting the raw key
    /// from the slot, which is intentionally impossible through the
    /// `HsmHardware` trait (keys must not leave the HSM boundary).
    /// Implementations that support HMAC **must** override this method.
    fn hsm_hmac_sha256(
        &self,
        _slot: HsmSlotId,
        _data: &[u8],
        _mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    /// Request ECDH P-256 shared secret derivation from the HSM.
    ///
    /// Real HSM firmware exposes ECDH natively with key-never-leaves-HSM
    /// guarantees. The default returns [`VsError::NotInitialized`] because
    /// a software fallback would require extracting the private key from
    /// the HSM slot, violating the security boundary. Implementations that
    /// support ECDH **must** override this method.
    fn hsm_ecdh_derive(
        &self,
        _private_slot: HsmSlotId,
        _peer_public: &[u8; 65],
        _shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    /// Generate random bytes from the HSM's hardware RNG.
    fn hsm_random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError>;

    /// Import a key into the specified HSM slot.
    fn hsm_import_key(&mut self, slot: HsmSlotId, key_material: &[u8]) -> Result<(), VsError>;

    /// Read the monotonic counter (OTP fuse-backed, cannot be reset).
    fn hsm_read_monotonic_counter(&self) -> Result<u64, VsError>;

    /// Increment the monotonic counter by 1 (irreversible).
    fn hsm_increment_monotonic_counter(&mut self) -> Result<u64, VsError>;
}

// ---------------------------------------------------------------------------
// EthernetPhy — Ethernet hardware interface
// ---------------------------------------------------------------------------

/// Maximum Ethernet frame size (1522 bytes: 1500 payload + 14 header + 4 VLAN + 4 FCS).
pub const MAX_ETH_FRAME_LEN: usize = 1522;

/// Raw Ethernet frame from hardware.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawEthFrame {
    /// Full Ethernet frame bytes (header + payload).
    pub data: [u8; MAX_ETH_FRAME_LEN],
    /// Actual frame length. Must not exceed [`MAX_ETH_FRAME_LEN`].
    pub len: u16,
    /// Hardware receive timestamp in microseconds.
    pub timestamp_us: u64,
}

impl PartialEq for RawEthFrame {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len || self.timestamp_us != other.timestamp_us {
            return false;
        }
        // Only compare valid payload bytes, not the entire buffer.
        let safe_len = (self.len as usize).min(MAX_ETH_FRAME_LEN);
        self.data[..safe_len] == other.data[..safe_len]
    }
}

impl Eq for RawEthFrame {}

impl RawEthFrame {
    /// Create a zeroed frame.
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; MAX_ETH_FRAME_LEN],
            len: 0,
            timestamp_us: 0,
        }
    }

    /// Return the valid frame bytes, clamped to the buffer size.
    ///
    /// If `len` exceeds [`MAX_ETH_FRAME_LEN`] the slice is clamped to
    /// the full buffer to prevent out-of-bounds access.
    pub fn payload(&self) -> &[u8] {
        let safe_len = (self.len as usize).min(MAX_ETH_FRAME_LEN);
        &self.data[..safe_len]
    }

    /// Check whether `len` is within the valid buffer range.
    pub fn is_valid_len(&self) -> bool {
        (self.len as usize) <= MAX_ETH_FRAME_LEN
    }
}

/// Ethernet PHY / MAC hardware interface.
pub trait EthernetPhy {
    /// Receive the next pending Ethernet frame, if available.
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError>;

    /// Transmit an Ethernet frame.
    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError>;

    /// Return the link speed in Mbit/s (100, 1000, etc.).
    fn link_speed_mbps(&self) -> u32;

    /// Check whether the link is up.
    fn link_is_up(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Watchdog — hardware watchdog timer
// ---------------------------------------------------------------------------

/// Watchdog hardware interface.
///
/// Abstracts access to hardware watchdog timers. `Craton Shield` uses this to
/// ensure the tick loop doesn't stall. If `kick()` is not called within the
/// configured timeout, the hardware watchdog resets the ECU.
pub trait Watchdog {
    /// Start the watchdog with the given timeout in microseconds.
    fn start(&mut self, timeout_us: u64) -> Result<(), VsError>;

    /// Kick (refresh) the watchdog to prevent reset.
    fn kick(&mut self) -> Result<(), VsError>;

    /// Stop the watchdog (if supported by hardware).
    fn stop(&mut self) -> Result<(), VsError>;

    /// Return true if the watchdog is running.
    fn is_running(&self) -> bool;

    /// Return the configured timeout in microseconds.
    fn timeout_us(&self) -> u64;
}

// ---------------------------------------------------------------------------
// SecureStorage — persistent key/config storage
// ---------------------------------------------------------------------------

/// Maximum key length for storage operations.
pub const MAX_STORAGE_KEY_LEN: usize = 32;

/// Maximum value length for storage operations.
pub const MAX_STORAGE_VALUE_LEN: usize = 256;

/// Persistent secure storage interface.
///
/// Provides key-value storage for configuration, key material, and monotonic
/// counters. Implementations may target NVM, flash, or file-backed stores.
pub trait SecureStorage {
    /// Read a value by key. Returns the number of bytes read, or
    /// `VsError::NotFound` if the key does not exist.
    fn read(&self, key: &[u8], value_out: &mut [u8]) -> Result<usize, VsError>;

    /// Write a value by key. Creates or overwrites the entry.
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), VsError>;

    /// Delete a key-value pair. Returns `VsError::NotFound` if missing.
    fn delete(&mut self, key: &[u8]) -> Result<(), VsError>;

    /// Check if a key exists.
    fn contains(&self, key: &[u8]) -> bool;

    /// Read a monotonic counter. Returns `VsError::NotFound` if not initialized.
    fn read_counter(&self, counter_id: u8) -> Result<u64, VsError>;

    /// Increment a monotonic counter by 1 (irreversible). Returns the new value.
    fn increment_counter(&mut self, counter_id: u8) -> Result<u64, VsError>;
}

// ---------------------------------------------------------------------------
// Stub implementations for testing
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "stub-hsm"))]
/// Stub CAN bus that always returns no frames and discards transmissions.
pub struct StubCanBus {
    bitrate: u32,
}

#[cfg(any(test, feature = "stub-hsm"))]
impl StubCanBus {
    pub const fn new(bitrate: u32) -> Self {
        Self { bitrate }
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl CanBus for StubCanBus {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        Ok(None)
    }
    fn transmit(&mut self, _frame: &RawCanFrame) -> Result<(), VsError> {
        Ok(())
    }
    fn bitrate(&self) -> u32 {
        self.bitrate
    }
    fn is_bus_off(&self) -> bool {
        false
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
/// Stub Ethernet PHY that always returns no frames and discards transmissions.
pub struct StubEthernetPhy {
    link_speed: u32,
    link_up: bool,
}

#[cfg(any(test, feature = "stub-hsm"))]
impl StubEthernetPhy {
    pub const fn new(link_speed: u32) -> Self {
        Self {
            link_speed,
            link_up: true,
        }
    }

    /// Set whether the link is up (for testing link-down scenarios).
    pub fn set_link_up(&mut self, up: bool) {
        self.link_up = up;
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl Default for StubEthernetPhy {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl EthernetPhy for StubEthernetPhy {
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        Ok(None)
    }
    fn transmit(&mut self, _data: &[u8]) -> Result<(), VsError> {
        Ok(())
    }
    fn link_speed_mbps(&self) -> u32 {
        self.link_speed
    }
    fn link_is_up(&self) -> bool {
        self.link_up
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
/// Stub HSM hardware for testing.
///
/// Provides deterministic (insecure) implementations of all HSM operations
/// using simple software crypto. **Not for production use.**
pub struct StubHsmHardware {
    /// Key storage indexed by slot ID (up to 16 slots).
    keys: [[u8; 32]; 16],
    monotonic_counter: u64,
}

#[cfg(any(test, feature = "stub-hsm"))]
impl StubHsmHardware {
    pub fn new() -> Self {
        Self {
            keys: [[0u8; 32]; 16],
            monotonic_counter: 0,
        }
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl Default for StubHsmHardware {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl HsmHardware for StubHsmHardware {
    fn hsm_aes_gcm_encrypt(
        &self,
        slot: HsmSlotId,
        _nonce: &[u8; 12],
        plaintext: &[u8],
        _aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        if ciphertext_out.len() != plaintext.len() {
            return Err(VsError::InvalidInput);
        }
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        // Stub: XOR plaintext with key byte for a deterministic (insecure) transform.
        let key_byte = self.keys[idx][0];
        for (i, &b) in plaintext.iter().enumerate() {
            ciphertext_out[i] = b ^ key_byte;
        }
        // Stub tag: fill with the key's first byte.
        tag_out.fill(key_byte);
        Ok(())
    }

    fn hsm_aes_gcm_decrypt(
        &self,
        slot: HsmSlotId,
        _nonce: &[u8; 12],
        ciphertext: &[u8],
        _aad: &[u8],
        tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        if plaintext_out.len() != ciphertext.len() {
            return Err(VsError::InvalidInput);
        }
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        let key_byte = self.keys[idx][0];
        // Verify the tag matches what hsm_aes_gcm_encrypt would produce
        // for this slot. Even in a stub, validating the tag catches
        // integration bugs where the tag is not properly forwarded.
        let mut expected_tag = [0u8; 16];
        expected_tag.fill(key_byte);
        if tag != &expected_tag {
            return Err(VsError::AuthenticationFailure);
        }
        for (i, &b) in ciphertext.iter().enumerate() {
            plaintext_out[i] = b ^ key_byte;
        }
        Ok(())
    }

    fn hsm_sign_p256(
        &self,
        slot: HsmSlotId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        // Stub: signature = digest XOR key, repeated.
        for i in 0..32 {
            sig_out[i] = digest[i] ^ self.keys[idx][i];
            sig_out[32 + i] = digest[i] ^ self.keys[idx][i].wrapping_add(1);
        }
        Ok(())
    }

    fn hsm_verify_p256(
        &self,
        slot: HsmSlotId,
        _pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        // Stub: verify by recomputing the deterministic signature from
        // hsm_sign_p256 and comparing. This ensures tests that sign-then-
        // verify actually exercise the verification path rather than
        // blindly succeeding.
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        let mut expected = [0u8; 64];
        for i in 0..32 {
            expected[i] = digest[i] ^ self.keys[idx][i];
            expected[32 + i] = digest[i] ^ self.keys[idx][i].wrapping_add(1);
        }
        // Constant-time comparison
        let mut diff: u8 = 0;
        for i in 0..64 {
            diff |= sig[i] ^ expected[i];
        }
        Ok(diff == 0)
    }

    fn hsm_sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Stub: simple non-cryptographic hash for testing.
        let mut h = [0u8; 32];
        for (i, &b) in data.iter().enumerate() {
            h[i % 32] ^= b;
            h[(i + 7) % 32] = h[(i + 7) % 32].wrapping_add(b);
        }
        hash_out.copy_from_slice(&h);
        Ok(())
    }

    fn hsm_hmac_sha256(
        &self,
        slot: HsmSlotId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        self.hsm_sha256(data, mac_out)?;
        for i in 0..32 {
            mac_out[i] ^= self.keys[idx][i];
        }
        Ok(())
    }

    fn hsm_ecdh_derive(
        &self,
        private_slot: HsmSlotId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let idx = private_slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        // Stub: XOR first 32 bytes of peer public key with our key.
        for i in 0..32 {
            shared_out[i] = peer_public[i + 1] ^ self.keys[idx][i];
        }
        Ok(())
    }

    fn hsm_random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        // Stub: deterministic "random" — fill with incrementing bytes.
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9D).wrapping_add(0x37);
        }
        Ok(())
    }

    fn hsm_import_key(&mut self, slot: HsmSlotId, key_material: &[u8]) -> Result<(), VsError> {
        let idx = slot as usize;
        if idx >= 16 {
            return Err(VsError::InvalidInput);
        }
        if key_material.len() > 32 {
            return Err(VsError::InvalidInput);
        }
        self.keys[idx] = [0u8; 32];
        self.keys[idx][..key_material.len()].copy_from_slice(key_material);
        Ok(())
    }

    fn hsm_read_monotonic_counter(&self) -> Result<u64, VsError> {
        Ok(self.monotonic_counter)
    }

    fn hsm_increment_monotonic_counter(&mut self) -> Result<u64, VsError> {
        self.monotonic_counter = self
            .monotonic_counter
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        Ok(self.monotonic_counter)
    }
}

/// Stub timer that returns a fixed or manually-advanced time.
///
/// The timer enforces monotonicity: [`set`](Self::set) will only move time
/// forward. Use `set_unchecked` in tests that
/// intentionally need to violate monotonicity.
#[cfg(any(test, feature = "stub-hsm"))]
pub struct StubTimer {
    current_us: u64,
}

#[cfg(any(test, feature = "stub-hsm"))]
impl StubTimer {
    pub const fn new(start_us: u64) -> Self {
        Self {
            current_us: start_us,
        }
    }

    /// Advance the timer by `delta_us` microseconds (saturating).
    pub fn advance(&mut self, delta_us: u64) {
        self.current_us = self.current_us.saturating_add(delta_us);
    }

    /// Set the timer to `us`, enforcing monotonicity.
    ///
    /// If `us` is less than the current time, the value is clamped to the
    /// current time (no-op). This preserves the monotonic contract that
    /// consumers of the [`Timer`] trait rely on.
    pub fn set(&mut self, us: u64) {
        if us > self.current_us {
            self.current_us = us;
        }
    }

    /// Set the timer to an arbitrary value **without** monotonicity checks.
    ///
    /// Only use this in tests that intentionally need to simulate
    /// backward-moving time (e.g. verifying that callers handle it safely).
    pub fn set_unchecked(&mut self, us: u64) {
        self.current_us = us;
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl Timer for StubTimer {
    fn now_us(&self) -> u64 {
        self.current_us
    }
    fn cycle_count(&self) -> Option<u64> {
        None
    }
}

/// Stub watchdog that tracks state but never resets.
#[cfg(any(test, feature = "stub-hsm"))]
pub struct StubWatchdog {
    running: bool,
    timeout_us: u64,
    kick_count: u64,
}

#[cfg(any(test, feature = "stub-hsm"))]
impl StubWatchdog {
    pub const fn new() -> Self {
        Self {
            running: false,
            timeout_us: 0,
            kick_count: 0,
        }
    }

    pub fn kick_count(&self) -> u64 {
        self.kick_count
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl Default for StubWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "stub-hsm"))]
impl Watchdog for StubWatchdog {
    fn start(&mut self, timeout_us: u64) -> Result<(), VsError> {
        if timeout_us == 0 {
            return Err(VsError::InvalidInput);
        }
        self.timeout_us = timeout_us;
        self.running = true;
        Ok(())
    }

    fn kick(&mut self) -> Result<(), VsError> {
        if !self.running {
            return Err(VsError::NotInitialized);
        }
        self.kick_count = self.kick_count.saturating_add(1);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), VsError> {
        self.running = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn timeout_us(&self) -> u64 {
        self.timeout_us
    }
}

/// A single key-value entry in [`StubSecureStorage`].
#[derive(Clone, Copy)]
struct StorageEntry {
    key: [u8; MAX_STORAGE_KEY_LEN],
    key_len: usize,
    value: [u8; MAX_STORAGE_VALUE_LEN],
    value_len: usize,
}

/// In-memory secure storage for testing.
pub struct StubSecureStorage {
    entries: [Option<StorageEntry>; 32],
    entry_count: usize,
    counters: [Option<u64>; 8],
}

impl StubSecureStorage {
    pub fn new() -> Self {
        Self {
            entries: [None; 32],
            entry_count: 0,
            counters: [None; 8],
        }
    }

    /// Find the index of a key, if it exists.
    fn find_key(&self, key: &[u8]) -> Option<usize> {
        for i in 0..self.entry_count {
            if let Some(ref entry) = self.entries[i] {
                if entry.key_len == key.len() && &entry.key[..entry.key_len] == key {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for StubSecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for StubSecureStorage {
    fn read(&self, key: &[u8], value_out: &mut [u8]) -> Result<usize, VsError> {
        if key.is_empty() {
            return Err(VsError::InvalidInput);
        }
        if let Some(idx) = self.find_key(key) {
            if let Some(ref entry) = self.entries[idx] {
                if value_out.len() < entry.value_len {
                    return Err(VsError::ResourceExhausted);
                }
                value_out[..entry.value_len].copy_from_slice(&entry.value[..entry.value_len]);
                return Ok(entry.value_len);
            }
        }
        Err(VsError::NotFound)
    }

    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), VsError> {
        if key.is_empty() || key.len() > MAX_STORAGE_KEY_LEN || value.len() > MAX_STORAGE_VALUE_LEN
        {
            return Err(VsError::InvalidInput);
        }
        // Overwrite if key exists.
        if let Some(idx) = self.find_key(key) {
            let mut val_buf = [0u8; MAX_STORAGE_VALUE_LEN];
            val_buf[..value.len()].copy_from_slice(value);
            if let Some(ref mut entry) = self.entries[idx] {
                entry.value = val_buf;
                entry.value_len = value.len();
            }
            return Ok(());
        }
        // Insert new entry.
        if self.entry_count >= 32 {
            return Err(VsError::ResourceExhausted);
        }
        let mut key_buf = [0u8; MAX_STORAGE_KEY_LEN];
        key_buf[..key.len()].copy_from_slice(key);
        let mut val_buf = [0u8; MAX_STORAGE_VALUE_LEN];
        val_buf[..value.len()].copy_from_slice(value);
        self.entries[self.entry_count] = Some(StorageEntry {
            key: key_buf,
            key_len: key.len(),
            value: val_buf,
            value_len: value.len(),
        });
        self.entry_count += 1;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), VsError> {
        if key.is_empty() {
            return Err(VsError::InvalidInput);
        }
        if let Some(idx) = self.find_key(key) {
            // Swap-remove with last entry.
            self.entry_count -= 1;
            if idx != self.entry_count {
                self.entries[idx] = self.entries[self.entry_count];
            }
            self.entries[self.entry_count] = None;
            return Ok(());
        }
        Err(VsError::NotFound)
    }

    fn contains(&self, key: &[u8]) -> bool {
        if key.is_empty() {
            return false;
        }
        self.find_key(key).is_some()
    }

    fn read_counter(&self, counter_id: u8) -> Result<u64, VsError> {
        if (counter_id as usize) >= self.counters.len() {
            return Err(VsError::StorageError);
        }
        self.counters[counter_id as usize].ok_or(VsError::NotFound)
    }

    fn increment_counter(&mut self, counter_id: u8) -> Result<u64, VsError> {
        if (counter_id as usize) >= self.counters.len() {
            return Err(VsError::StorageError);
        }
        let current = self.counters[counter_id as usize].unwrap_or(0);
        let val = current.checked_add(1).ok_or(VsError::ResourceExhausted)?;
        self.counters[counter_id as usize] = Some(val);
        Ok(val)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- StubCanBus tests -----------------------------------------------------

    #[test]
    fn stub_can_bus_receive_returns_none() {
        let mut bus = StubCanBus::new(500_000);
        assert_eq!(bus.receive().unwrap(), None);
        assert_eq!(bus.bitrate(), 500_000);
        assert!(!bus.is_bus_off());
    }

    #[test]
    fn stub_can_bus_transmit_succeeds() {
        let mut bus = StubCanBus::new(500_000);
        let frame = RawCanFrame::zeroed();
        assert!(bus.transmit(&frame).is_ok());
    }

    #[test]
    fn stub_can_bus_zero_bitrate() {
        let bus = StubCanBus::new(0);
        assert_eq!(bus.bitrate(), 0);
    }

    #[test]
    fn stub_can_bus_max_bitrate() {
        let bus = StubCanBus::new(u32::MAX);
        assert_eq!(bus.bitrate(), u32::MAX);
    }

    #[test]
    fn stub_can_bus_multiple_transmit() {
        let mut bus = StubCanBus::new(500_000);
        let frame = RawCanFrame::zeroed();
        for _ in 0..10 {
            assert!(bus.transmit(&frame).is_ok());
        }
    }

    // -- StubTimer tests ------------------------------------------------------

    #[test]
    fn stub_timer_returns_start_time() {
        let timer = StubTimer::new(1_000_000);
        assert_eq!(timer.now_us(), 1_000_000);
        assert_eq!(timer.cycle_count(), None);
    }

    #[test]
    fn stub_timer_advance() {
        let mut timer = StubTimer::new(0);
        timer.advance(500);
        assert_eq!(timer.now_us(), 500);
        timer.advance(1_500);
        assert_eq!(timer.now_us(), 2_000);
    }

    #[test]
    fn stub_timer_set_forward() {
        let mut timer = StubTimer::new(0);
        timer.set(999_999);
        assert_eq!(timer.now_us(), 999_999);
    }

    #[test]
    fn stub_timer_set_monotonic_clamps_backward() {
        // set() enforces monotonicity: going backward is a no-op.
        let mut timer = StubTimer::new(1000);
        timer.set(500);
        assert_eq!(timer.now_us(), 1000);
    }

    #[test]
    fn stub_timer_set_unchecked_allows_backward() {
        let mut timer = StubTimer::new(1000);
        timer.set_unchecked(500);
        assert_eq!(timer.now_us(), 500);
    }

    #[test]
    fn stub_timer_saturating_advance() {
        let mut timer = StubTimer::new(u64::MAX - 10);
        timer.advance(20);
        assert_eq!(timer.now_us(), u64::MAX);
    }

    #[test]
    fn stub_timer_zero_advance() {
        let mut timer = StubTimer::new(100);
        timer.advance(0);
        assert_eq!(timer.now_us(), 100);
    }

    #[test]
    fn stub_timer_advance_then_set_forward() {
        let mut timer = StubTimer::new(0);
        timer.advance(100);
        timer.set(200);
        assert_eq!(timer.now_us(), 200);
        timer.advance(25);
        assert_eq!(timer.now_us(), 225);
    }

    // -- RawCanFrame tests ----------------------------------------------------

    #[test]
    fn raw_can_frame_zeroed() {
        let frame = RawCanFrame::zeroed();
        assert_eq!(frame.id, 0);
        assert_eq!(frame.dlc, 0);
        assert!(!frame.is_fd);
        assert!(!frame.is_extended);
        assert!(frame.is_valid_id());
    }

    #[test]
    fn raw_can_frame_with_data() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x123;
        frame.dlc = 8;
        frame.data[0] = 0xDE;
        frame.data[7] = 0xAD;
        frame.is_extended = true;
        assert_eq!(frame.id, 0x123);
        assert_eq!(frame.dlc, 8);
        assert_eq!(frame.data[0], 0xDE);
        assert!(frame.is_extended);
        assert!(frame.is_valid_id());
    }

    #[test]
    fn raw_can_frame_fd_max_dlc() {
        let mut frame = RawCanFrame::zeroed();
        frame.is_fd = true;
        frame.dlc = 15;
        frame.data[63] = 0xFF;
        assert_eq!(frame.payload_len(), 64);
        assert_eq!(frame.data[63], 0xFF);
    }

    #[test]
    fn can_frame_id_validation_standard() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = CAN_ID_STANDARD_MAX;
        assert!(frame.is_valid_id());

        frame.id = CAN_ID_STANDARD_MAX + 1;
        assert!(!frame.is_valid_id());
    }

    #[test]
    fn can_frame_id_validation_extended() {
        let mut frame = RawCanFrame::zeroed();
        frame.is_extended = true;

        frame.id = CAN_ID_EXTENDED_MAX;
        assert!(frame.is_valid_id());

        frame.id = CAN_ID_EXTENDED_MAX + 1;
        assert!(!frame.is_valid_id());

        frame.id = u32::MAX;
        assert!(!frame.is_valid_id());
    }

    #[test]
    fn can_frame_payload_slice() {
        let mut frame = RawCanFrame::zeroed();
        frame.dlc = 3;
        frame.data[0] = 0xAA;
        frame.data[1] = 0xBB;
        frame.data[2] = 0xCC;
        assert_eq!(frame.payload(), &[0xAA, 0xBB, 0xCC]);
    }

    // -- CAN-FD DLC mapping (ISO 11898-1) ------------------------------------

    #[test]
    fn payload_len_classic_can() {
        let mut frame = RawCanFrame::zeroed();
        frame.dlc = 8;
        assert_eq!(frame.payload_len(), 8);

        frame.dlc = 5;
        assert_eq!(frame.payload_len(), 5);

        // DLC > 8 clamped to 8 for classic CAN.
        frame.dlc = 15;
        assert_eq!(frame.payload_len(), 8);
    }

    #[test]
    fn payload_len_can_fd_iso_mapping() {
        let mut frame = RawCanFrame::zeroed();
        frame.is_fd = true;

        // Direct mapping 0-8.
        for dlc in 0..=8u8 {
            frame.dlc = dlc;
            assert_eq!(frame.payload_len(), dlc as usize);
        }

        // Non-linear mapping 9-15.
        let expected = [
            (9, 12),
            (10, 16),
            (11, 20),
            (12, 24),
            (13, 32),
            (14, 48),
            (15, 64),
        ];
        for &(dlc, len) in &expected {
            frame.dlc = dlc;
            assert_eq!(frame.payload_len(), len, "DLC {dlc} should map to {len}");
        }
    }

    #[test]
    fn payload_len_can_fd_over_15_clamps() {
        let mut frame = RawCanFrame::zeroed();
        frame.is_fd = true;
        frame.dlc = 100;
        assert_eq!(frame.payload_len(), 64);

        frame.dlc = u8::MAX;
        assert_eq!(frame.payload_len(), 64);
    }

    #[test]
    fn payload_len_zero_dlc() {
        let frame = RawCanFrame::zeroed();
        assert_eq!(frame.payload_len(), 0);
    }

    // -- RawEthFrame tests ----------------------------------------------------

    #[test]
    fn raw_eth_frame_zeroed() {
        let frame = RawEthFrame::zeroed();
        assert_eq!(frame.len, 0);
        assert_eq!(frame.timestamp_us, 0);
        assert!(frame.is_valid_len());
        assert_eq!(frame.payload().len(), 0);
    }

    #[test]
    fn raw_eth_frame_with_data() {
        let mut frame = RawEthFrame::zeroed();
        frame.data[0] = 0xFF;
        frame.len = 64;
        frame.timestamp_us = 42_000;
        assert_eq!(frame.payload().len(), 64);
        assert_eq!(frame.payload()[0], 0xFF);
    }

    #[test]
    fn raw_eth_frame_max_len() {
        let mut frame = RawEthFrame::zeroed();
        frame.len = MAX_ETH_FRAME_LEN as u16;
        frame.data[MAX_ETH_FRAME_LEN - 1] = 0xAB;
        assert!(frame.is_valid_len());
        assert_eq!(frame.payload().len(), MAX_ETH_FRAME_LEN);
        assert_eq!(frame.payload()[MAX_ETH_FRAME_LEN - 1], 0xAB);
    }

    #[test]
    fn raw_eth_frame_invalid_len_clamped() {
        let mut frame = RawEthFrame::zeroed();
        frame.len = u16::MAX;
        assert!(!frame.is_valid_len());
        // payload() safely clamps to buffer size.
        assert_eq!(frame.payload().len(), MAX_ETH_FRAME_LEN);
    }

    #[test]
    fn raw_eth_frame_equality() {
        let a = RawEthFrame::zeroed();
        let b = RawEthFrame::zeroed();
        assert_eq!(a, b);
    }

    // -- Watchdog tests -------------------------------------------------------

    #[test]
    fn watchdog_start_kick_stop_lifecycle() {
        let mut wd = StubWatchdog::new();
        assert!(!wd.is_running());
        assert_eq!(wd.timeout_us(), 0);
        assert_eq!(wd.kick_count(), 0);

        wd.start(10_000).unwrap();
        assert!(wd.is_running());
        assert_eq!(wd.timeout_us(), 10_000);

        wd.kick().unwrap();
        wd.kick().unwrap();
        assert_eq!(wd.kick_count(), 2);

        wd.stop().unwrap();
        assert!(!wd.is_running());
    }

    #[test]
    fn watchdog_kick_while_stopped_returns_error() {
        let mut wd = StubWatchdog::new();
        assert!(wd.kick().is_err());
    }

    #[test]
    fn watchdog_is_running_after_restart() {
        let mut wd = StubWatchdog::new();
        wd.start(5_000).unwrap();
        wd.stop().unwrap();
        wd.start(20_000).unwrap();
        assert!(wd.is_running());
        assert_eq!(wd.timeout_us(), 20_000);
    }

    #[test]
    fn watchdog_zero_timeout_rejected() {
        let mut wd = StubWatchdog::new();
        assert_eq!(wd.start(0), Err(VsError::InvalidInput));
        assert!(!wd.is_running());
    }

    // -- SecureStorage tests --------------------------------------------------

    #[test]
    fn secure_storage_write_read_roundtrip() {
        let mut store = StubSecureStorage::new();
        store.write(b"key1", b"hello").unwrap();
        let mut buf = [0u8; 64];
        let len = store.read(b"key1", &mut buf).unwrap();
        assert_eq!(len, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn secure_storage_overwrite() {
        let mut store = StubSecureStorage::new();
        store.write(b"k", b"old").unwrap();
        store.write(b"k", b"new_value").unwrap();
        let mut buf = [0u8; 64];
        let len = store.read(b"k", &mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(&buf[..9], b"new_value");
    }

    #[test]
    fn secure_storage_delete() {
        let mut store = StubSecureStorage::new();
        store.write(b"key", b"val").unwrap();
        assert!(store.contains(b"key"));
        store.delete(b"key").unwrap();
        assert!(!store.contains(b"key"));
    }

    #[test]
    fn secure_storage_delete_not_found() {
        let mut store = StubSecureStorage::new();
        assert_eq!(store.delete(b"missing"), Err(VsError::NotFound));
    }

    #[test]
    fn secure_storage_read_not_found() {
        let store = StubSecureStorage::new();
        let mut buf = [0u8; 16];
        assert_eq!(store.read(b"nope", &mut buf), Err(VsError::NotFound));
    }

    #[test]
    fn secure_storage_contains() {
        let mut store = StubSecureStorage::new();
        assert!(!store.contains(b"x"));
        store.write(b"x", b"y").unwrap();
        assert!(store.contains(b"x"));
    }

    #[test]
    fn secure_storage_read_buffer_too_small() {
        let mut store = StubSecureStorage::new();
        store.write(b"big", b"hello world").unwrap();
        let mut tiny_buf = [0u8; 4];
        assert_eq!(
            store.read(b"big", &mut tiny_buf),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn secure_storage_empty_key_rejected() {
        let mut store = StubSecureStorage::new();
        assert_eq!(store.write(b"", b"val"), Err(VsError::InvalidInput));
        assert_eq!(store.delete(b""), Err(VsError::InvalidInput));
        assert!(!store.contains(b""));

        let mut buf = [0u8; 16];
        assert_eq!(store.read(b"", &mut buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn secure_storage_counter_increment() {
        let mut store = StubSecureStorage::new();
        assert_eq!(store.read_counter(0), Err(VsError::NotFound));
        assert_eq!(store.increment_counter(0).unwrap(), 1);
        assert_eq!(store.increment_counter(0).unwrap(), 2);
        assert_eq!(store.read_counter(0).unwrap(), 2);
    }

    #[test]
    fn secure_storage_counter_out_of_range() {
        let mut store = StubSecureStorage::new();
        assert_eq!(store.read_counter(100), Err(VsError::StorageError));
        assert_eq!(store.increment_counter(100), Err(VsError::StorageError));
    }

    #[test]
    fn secure_storage_counter_overflow_returns_error() {
        let mut store = StubSecureStorage::new();
        // Seed counter to u64::MAX.
        store.counters[0] = Some(u64::MAX);
        assert_eq!(store.increment_counter(0), Err(VsError::ResourceExhausted));
        // Value must remain unchanged.
        assert_eq!(store.read_counter(0).unwrap(), u64::MAX);
    }

    // -- CanError / CanBus default methods tests ------------------------------

    #[test]
    fn can_error_enum_values() {
        assert_eq!(CanError::None, CanError::None);
        assert_ne!(CanError::BitStuffing, CanError::FormError);
        assert_ne!(CanError::AckError, CanError::BitError);
        assert_ne!(CanError::CrcError, CanError::BusOff);
        assert_ne!(CanError::ErrorPassive, CanError::Overrun);
    }

    #[test]
    fn can_bus_default_methods_on_stub() {
        let bus = StubCanBus::new(500_000);
        assert_eq!(bus.last_error(), CanError::None);
        assert_eq!(
            bus.error_counters(),
            CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0
            }
        );
    }

    #[test]
    fn can_bus_recover_bus_off_default() {
        let mut bus = StubCanBus::new(500_000);
        assert!(bus.recover_bus_off().is_ok());
    }

    // -- StubEthernetPhy tests ------------------------------------------------

    #[test]
    fn stub_ethernet_phy_receive_returns_none() {
        let mut phy = StubEthernetPhy::new(1000);
        assert_eq!(phy.receive().unwrap(), None);
    }

    #[test]
    fn stub_ethernet_phy_transmit_succeeds() {
        let mut phy = StubEthernetPhy::new(1000);
        assert!(phy.transmit(&[0xAA; 64]).is_ok());
    }

    #[test]
    fn stub_ethernet_phy_link_speed() {
        let phy = StubEthernetPhy::new(100);
        assert_eq!(phy.link_speed_mbps(), 100);
    }

    #[test]
    fn stub_ethernet_phy_link_default_up() {
        let phy = StubEthernetPhy::new(1000);
        assert!(phy.link_is_up());
    }

    #[test]
    fn stub_ethernet_phy_link_down() {
        let mut phy = StubEthernetPhy::new(1000);
        phy.set_link_up(false);
        assert!(!phy.link_is_up());
    }

    #[test]
    fn stub_ethernet_phy_default() {
        let phy = StubEthernetPhy::default();
        assert_eq!(phy.link_speed_mbps(), 1000);
        assert!(phy.link_is_up());
    }

    // -- StubHsmHardware tests ------------------------------------------------

    #[test]
    fn stub_hsm_import_and_encrypt_decrypt() {
        let mut hsm = StubHsmHardware::new();
        hsm.hsm_import_key(0, &[0x42; 16]).unwrap();

        let plaintext = b"hello world";
        let nonce = [1u8; 12];
        let mut ciphertext = [0u8; 11];
        let mut tag = [0u8; 16];

        hsm.hsm_aes_gcm_encrypt(0, &nonce, plaintext, b"", &mut ciphertext, &mut tag)
            .unwrap();

        // Ciphertext should differ from plaintext (XOR with key byte).
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mut recovered = [0u8; 11];
        hsm.hsm_aes_gcm_decrypt(0, &nonce, &ciphertext, b"", &tag, &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[test]
    fn stub_hsm_length_mismatch_rejected() {
        let hsm = StubHsmHardware::new();
        let nonce = [0u8; 12];
        let mut ct = [0u8; 5]; // wrong size
        let mut tag = [0u8; 16];
        let result = hsm.hsm_aes_gcm_encrypt(0, &nonce, &[0u8; 10], b"", &mut ct, &mut tag);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn stub_hsm_slot_out_of_range() {
        let hsm = StubHsmHardware::new();
        let nonce = [0u8; 12];
        let mut ct = [0u8; 4];
        let mut tag = [0u8; 16];
        let result = hsm.hsm_aes_gcm_encrypt(99, &nonce, &[0u8; 4], b"", &mut ct, &mut tag);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn stub_hsm_sign_and_verify() {
        let mut hsm = StubHsmHardware::new();
        hsm.hsm_import_key(1, &[0xAB; 32]).unwrap();
        let digest = [0x55u8; 32];
        let mut sig = [0u8; 64];
        hsm.hsm_sign_p256(1, &digest, &mut sig).unwrap();
        // Signature should be non-zero.
        assert!(sig.iter().any(|&b| b != 0));
        // Stub verify always returns true.
        assert!(hsm.hsm_verify_p256(1, &[0u8; 65], &digest, &sig).unwrap());
    }

    #[test]
    fn stub_hsm_sha256() {
        let hsm = StubHsmHardware::new();
        let mut hash1 = [0u8; 32];
        let mut hash2 = [0u8; 32];
        hsm.hsm_sha256(b"hello", &mut hash1).unwrap();
        hsm.hsm_sha256(b"world", &mut hash2).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn stub_hsm_hmac_sha256() {
        let mut hsm = StubHsmHardware::new();
        hsm.hsm_import_key(2, &[0xCD; 32]).unwrap();
        let mut mac = [0u8; 32];
        hsm.hsm_hmac_sha256(2, b"test data", &mut mac).unwrap();
        assert!(mac.iter().any(|&b| b != 0));
    }

    #[test]
    fn stub_hsm_ecdh_derive() {
        let mut hsm = StubHsmHardware::new();
        hsm.hsm_import_key(3, &[0xEF; 32]).unwrap();
        let peer_pub = [0x04; 65]; // Uncompressed point prefix
        let mut shared = [0u8; 32];
        hsm.hsm_ecdh_derive(3, &peer_pub, &mut shared).unwrap();
        assert!(shared.iter().any(|&b| b != 0));
    }

    #[test]
    fn stub_hsm_random_bytes() {
        let hsm = StubHsmHardware::new();
        let mut buf = [0u8; 32];
        hsm.hsm_random_bytes(&mut buf).unwrap();
        // Should not be all zeros.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn stub_hsm_monotonic_counter() {
        let mut hsm = StubHsmHardware::new();
        assert_eq!(hsm.hsm_read_monotonic_counter().unwrap(), 0);
        assert_eq!(hsm.hsm_increment_monotonic_counter().unwrap(), 1);
        assert_eq!(hsm.hsm_increment_monotonic_counter().unwrap(), 2);
        assert_eq!(hsm.hsm_read_monotonic_counter().unwrap(), 2);
    }

    #[test]
    fn stub_hsm_import_key_too_large() {
        let mut hsm = StubHsmHardware::new();
        assert_eq!(
            hsm.hsm_import_key(0, &[0u8; 33]),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn stub_hsm_default() {
        let hsm = StubHsmHardware::default();
        assert_eq!(hsm.hsm_read_monotonic_counter().unwrap(), 0);
    }

    // -- RawEthFrame PartialEq improvement test -------------------------------

    #[test]
    fn raw_eth_frame_partial_eq_only_compares_valid_bytes() {
        let mut a = RawEthFrame::zeroed();
        let mut b = RawEthFrame::zeroed();
        a.len = 4;
        b.len = 4;
        a.data[0] = 0xFF;
        b.data[0] = 0xFF;
        // Trailing bytes differ but should not affect equality.
        a.data[100] = 0xAA;
        b.data[100] = 0xBB;
        assert_eq!(a, b);
    }
}
