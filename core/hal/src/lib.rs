// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Hardware Abstraction Layer (HAL) for `Craton Shield`.
//!
//! Defines traits for hardware interfaces that differ across automotive
//! platforms (NXP S32G, Infineon AURIX, QEMU, etc.). By programming
//! against these traits the core `Craton Shield` logic remains
//! platform-independent.
//!
//! # Example
//!
//! ```
//! use vs_hal::{CanBus, Timer};
//!
//! /// Drain one CAN frame (if any) and return its hardware ID paired with
//! /// the timestamp the application observed it.
//! fn process<B: CanBus, T: Timer>(bus: &mut B, timer: &T) -> Option<(u32, u64)> {
//!     let frame = bus.receive().ok()??;
//!     let now = timer.now_us();
//!     Some((frame.id, now))
//! }
//! ```

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
    /// Returns `Some(counters)` when the driver can report TEC/REC values, or
    /// `None` when the underlying controller / driver does not expose them.
    /// Callers **must not** treat the default as "controller has zero
    /// errors" — distinguish the `Some(0)` and `None` cases explicitly.
    ///
    /// Default: `None`.
    fn error_counters(&self) -> Option<CanErrorCounters> {
        None
    }

    /// Attempt to recover from bus-off state.
    ///
    /// Default: returns Ok (no-op for controllers with automatic recovery).
    fn recover_bus_off(&mut self) -> Result<(), VsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BatchReceive — batched frame drain (perf optimization)
// ---------------------------------------------------------------------------

/// Optional batched-receive interface for drivers that can return multiple
/// frames per syscall (e.g. `recvmmsg(2)` on Linux).
///
/// Implementing this trait is opt-in: drivers should provide it when the
/// underlying transport supports vectored I/O. Callers can fall back to the
/// regular [`CanBus::receive`] / [`EthernetPhy::receive`] loop when the
/// driver does not implement `BatchReceive`.
///
/// # Performance
///
/// On Linux, replacing N individual `read(2)` calls with one `recvmmsg(2)`
/// trims per-frame syscall overhead from ~250 ns to ~25 ns for an 8-deep
/// batch, eliminating a significant fraction of the per-frame cost on
/// high-rate CAN-FD buses (1 Mfps).
///
/// # Contract
///
/// - Returns `Ok(n)` where `n <= count` is the number of frames written
///   into the front of the `frames` slice.
/// - Returns `Ok(0)` if no frames are pending (non-blocking).
/// - Returns `Err` on a hard transport error.
/// - Frames written beyond index `n` are unspecified (caller must not read them).
pub trait BatchReceive {
    /// The frame type returned by this batch interface.
    type Frame;

    /// Drain up to `count` frames into `frames`, returning the actual count.
    ///
    /// `count` is implicitly clamped to `frames.len()`.
    fn recv_batch(&mut self, frames: &mut [Self::Frame], count: usize) -> Result<usize, VsError>;

    /// Return the raw file descriptor (or platform-equivalent) so that
    /// callers can integrate this driver into an `epoll`/`kqueue` reactor.
    ///
    /// Returns `None` on platforms where no FD-style handle is available
    /// (bare-metal, simulated).
    fn as_raw_fd(&self) -> Option<i32> {
        None
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

/// Static capability descriptor declared by every [`HsmHardware`] implementor.
///
/// Callers consult this struct to detect at composition time — before any
/// runtime call — whether the underlying HSM supports a given primitive.
/// This avoids the previous Pre-1.0 trait-surface evolution idiom of issuing a probe call and treating
/// [`VsError::NotInitialized`] as "operation unsupported", which conflated
/// "HSM unsupported" with "HSM not yet initialized" and required a runtime
/// round-trip per probed primitive.
///
/// # Stability
///
/// Adding a field is a breaking change to the trait surface (callers may
/// construct [`HsmCapabilities`] literally in tests). Bump the crate's
/// `version` accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct HsmCapabilities {
    /// Implementation provides hardware-backed HMAC-SHA-256
    /// ([`HsmHardware::hsm_hmac_sha256`]).
    pub supports_hmac_sha256: bool,
    /// Implementation provides hardware-backed ECDH P-256 derivation
    /// ([`HsmHardware::hsm_ecdh_derive`]).
    pub supports_ecdh_p256: bool,
    /// Implementation provides hardware-backed ECDSA P-256 sign/verify
    /// ([`HsmHardware::hsm_sign_p256`], [`HsmHardware::hsm_verify_p256`]).
    pub supports_ecdsa_p256: bool,
    /// Implementation provides hardware-backed AES-256-GCM
    /// ([`HsmHardware::hsm_aes_gcm_encrypt`],
    /// [`HsmHardware::hsm_aes_gcm_decrypt`]).
    pub supports_aes_gcm_256: bool,
    /// Implementation zeroizes all in-RAM key material on `Drop`. See the
    /// Zeroize contract on [`HsmHardware`] for the exact obligation.
    pub supports_zeroize_on_drop: bool,
    /// Implementation backs [`HsmHardware::hsm_random_bytes`] with a real
    /// hardware RNG (TRNG / DRBG seeded from a TRNG). Stub or software-only
    /// implementations **must** set this to `false`; callers that need
    /// cryptographic-grade randomness **must** consult this flag and refuse
    /// to proceed when it is `false`.
    pub supports_hw_rng: bool,
    /// Maximum number of addressable key slots. `slot >= max_key_slots`
    /// **must** be rejected with [`VsError::InvalidInput`].
    pub max_key_slots: u16,
}

impl HsmCapabilities {
    /// All-disabled capability descriptor with zero slots.
    ///
    /// Useful as a starting point in tests or for stub implementations
    /// that intentionally claim no hardware backing.
    pub const NONE: Self = Self {
        supports_hmac_sha256: false,
        supports_ecdh_p256: false,
        supports_ecdsa_p256: false,
        supports_aes_gcm_256: false,
        supports_zeroize_on_drop: false,
        supports_hw_rng: false,
        max_key_slots: 0,
    };
}

/// HSM hardware interface trait.
///
/// Abstracts access to hardware security modules (NXP HSE, Infineon HSM,
/// SHE+, TPM, etc.). The `CryptoProvider`
/// can delegate operations to an `HsmHardware` implementation.
///
/// # Status
///
/// Only `StubHsmHardware` (feature `stub-hsm`, test/dev only) is
/// currently provided in-tree. Real HSM integrations (NXP HSE, Infineon
/// SHE+, PKCS#11) are planned — see the roadmap.
///
/// # Trait surface (Pre-1.0 trait-surface evolution)
///
/// As of Pre-1.0 trait-surface evolution every primitive is a **required** method — there are no
/// default implementations that silently degrade to
/// [`VsError::NotInitialized`]. Implementors that genuinely cannot support
/// a primitive must:
///
/// 1. Declare `supports_X = false` in [`Self::capabilities`], so callers
///    can early-detect the gap without a probe call, **and**
/// 2. Return [`VsError::NotInitialized`] from the unsupported method
///    explicitly (not via a trait-level default).
///
/// This eliminates the Pre-1.0 trait-surface evolution trap where adding a new primitive to the trait
/// silently compiled against existing implementors with a wrong default.
///
/// # Zeroize contract
///
/// Implementations **must** zeroize every byte of in-RAM key material on
/// `Drop`. This obligation is non-negotiable on real hardware:
///
/// - Key bytes imported through [`Self::hsm_import_key`] **must not**
///   outlive the `HsmHardware` instance in any cache, scratch buffer, or
///   serialization path.
/// - Intermediate values derived from key material (HMAC inner/outer keys,
///   ECDH scratch, AES round keys held in software) **must** be zeroized
///   either on each operation's return path or, at minimum, on `Drop`.
/// - Implementors that store keys exclusively inside the HSM's protected
///   boundary (and never copy them into host RAM) may declare
///   `supports_zeroize_on_drop = true` trivially — but the contract still
///   applies to any cached metadata that could narrow an attacker's
///   search space.
///
/// Implementors should use `zeroize::ZeroizeOnDrop` (or an equivalent
/// `Drop` impl that writes zeros via `core::ptr::write_volatile`) to
/// honour this requirement. Failing to do so is a **security defect**, not
/// a quality-of-implementation matter.
pub trait HsmHardware {
    /// Return the static capability descriptor for this implementation.
    ///
    /// Callers **must** consult this before invoking an optional primitive
    /// (HMAC, ECDH) to avoid relying on [`VsError::NotInitialized`] as a
    /// support indicator.
    ///
    /// # Stability
    ///
    /// The returned value **must** be stable for the lifetime of the
    /// instance — capabilities do not change at runtime.
    fn capabilities(&self) -> HsmCapabilities;

    /// Request AES-256-GCM encryption from the HSM.
    ///
    /// # Preconditions
    ///
    /// - `slot` < [`HsmCapabilities::max_key_slots`].
    /// - The slot **must** contain an imported AES-256 key (see
    ///   [`Self::hsm_import_key`]); otherwise return
    ///   [`VsError::NotInitialized`].
    /// - `ciphertext_out.len()` **must** equal `plaintext.len()`.
    /// - `nonce` **must** be unique per (key, message) pair — GCM
    ///   collapses catastrophically on nonce reuse.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range, or length mismatch.
    /// - [`VsError::NotInitialized`] — slot empty.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// Any scratch buffer holding plaintext or intermediate AES state
    /// **must** be zeroized before this method returns.
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
    /// # Preconditions
    ///
    /// - `slot` < [`HsmCapabilities::max_key_slots`] and contains a key.
    /// - `plaintext_out.len()` **must** equal `ciphertext.len()`.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range, or length mismatch.
    /// - [`VsError::NotInitialized`] — slot empty.
    /// - [`VsError::AuthenticationFailure`] — tag check failed; the
    ///   `plaintext_out` buffer **must not** be observable in this case.
    ///
    /// # Zeroize
    ///
    /// On authentication failure, implementations **must** zeroize any
    /// partial plaintext written to `plaintext_out` before returning.
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
    ///
    /// # Preconditions
    ///
    /// - `slot` < [`HsmCapabilities::max_key_slots`] and contains a
    ///   P-256 private key.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range.
    /// - [`VsError::NotInitialized`] — slot empty.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// The private key **must not** leave the HSM boundary. Any
    /// per-signature scalar `k` held in software scratch **must** be
    /// zeroized before this method returns.
    fn hsm_sign_p256(
        &self,
        slot: HsmSlotId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError>;

    /// Request ECDSA P-256 verification from the HSM.
    ///
    /// # Preconditions
    ///
    /// - `pub_key` is the SEC1 uncompressed encoding (`0x04 || X || Y`).
    /// - `slot` may be ignored by implementations that accept the public
    ///   key inline; if used, must be < [`HsmCapabilities::max_key_slots`].
    ///
    /// # Error semantics
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
    /// well-formed but does not verify, and `Err` only on
    /// hardware/encoding errors — **never** to indicate verification
    /// failure.
    ///
    /// # Stub semantics — drift warning
    ///
    /// Stub implementations may verify against an internal slot rather than
    /// the supplied `pub_key`; production HSMs validate against `pub_key`.
    /// Callers needing strong external-key guarantees should NOT use stub
    /// backends — confirm via [`Self::capabilities`] /
    /// [`HsmCapabilities::supports_zeroize_on_drop`] (and, where exposed,
    /// any insecurity marker on the concrete type) before trusting a
    /// verification result against an externally supplied key.
    fn hsm_verify_p256(
        &self,
        slot: HsmSlotId,
        pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError>;

    /// Request SHA-256 hashing from the HSM accelerator.
    ///
    /// # Preconditions
    ///
    /// None — SHA-256 is keyless.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// Not applicable — there is no secret input.
    fn hsm_sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError>;

    /// Request HMAC-SHA-256 from the HSM.
    ///
    /// Real HSM firmware (NXP HSE, Infineon SHE+) exposes HMAC natively.
    /// Implementations that lack hardware HMAC support **must** declare
    /// `supports_hmac_sha256 = false` in [`Self::capabilities`] and
    /// return [`VsError::NotInitialized`] from this method — there is no
    /// trait-level default as of Pre-1.0 trait-surface evolution.
    ///
    /// # Preconditions
    ///
    /// - `slot` < [`HsmCapabilities::max_key_slots`] and contains an HMAC
    ///   key.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range.
    /// - [`VsError::NotInitialized`] — slot empty, or HMAC unsupported by
    ///   this HSM.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// The HMAC key **must** stay inside the HSM. Any RFC 2104
    /// inner/outer-key scratch held in software **must** be zeroized
    /// before this method returns.
    fn hsm_hmac_sha256(
        &self,
        slot: HsmSlotId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError>;

    /// Request ECDH P-256 shared secret derivation from the HSM.
    ///
    /// Real HSM firmware exposes ECDH natively with key-never-leaves-HSM
    /// guarantees. Implementations that lack hardware ECDH support
    /// **must** declare `supports_ecdh_p256 = false` in
    /// [`Self::capabilities`] and return [`VsError::NotInitialized`] from
    /// this method — there is no trait-level default as of Pre-1.0 trait-surface evolution.
    ///
    /// # Preconditions
    ///
    /// - `private_slot` < [`HsmCapabilities::max_key_slots`] and contains
    ///   a P-256 private key.
    /// - `peer_public` is the SEC1 uncompressed encoding
    ///   (`0x04 || X || Y`); implementations **must** validate the point
    ///   is on the curve and not the identity.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range, or invalid peer
    ///   point.
    /// - [`VsError::NotInitialized`] — slot empty, or ECDH unsupported.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// The private scalar **must not** leave the HSM. The derived shared
    /// secret is sensitive: callers are expected to zeroize
    /// `shared_out` after use, and implementations **must** zeroize any
    /// intermediate scalar/point state before returning.
    fn hsm_ecdh_derive(
        &self,
        private_slot: HsmSlotId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError>;

    /// Generate random bytes from the HSM's hardware RNG.
    ///
    /// # WARNING
    ///
    /// Stub / test implementations of this method are **deterministic** —
    /// they exist purely to keep test fixtures reproducible and provide
    /// *zero* cryptographic strength. **Never enable `stub-hsm` in
    /// security-relevant builds.** Callers needing cryptographic randomness
    /// **must** consult [`HsmCapabilities::supports_hw_rng`] and refuse to
    /// proceed when it is `false`.
    ///
    /// # Preconditions
    ///
    /// `buf.len()` may be zero (which is a no-op). Implementations
    /// **must** never block indefinitely on RNG initialization in this
    /// method — return [`VsError::NotInitialized`] instead.
    ///
    /// # Error semantics
    ///
    /// - [`VsError::NotInitialized`] — RNG not seeded / health-test failed.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    fn hsm_random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError>;

    /// Import a key into the specified HSM slot.
    ///
    /// # Preconditions
    ///
    /// - `slot` < [`HsmCapabilities::max_key_slots`].
    /// - `key_material.len()` must match a length the implementation
    ///   recognizes (typically 16/24/32 for AES, 32 for HMAC/P-256).
    ///
    /// # Error semantics
    ///
    /// - [`VsError::InvalidInput`] — slot out of range, or unsupported
    ///   key length.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    ///
    /// # Zeroize
    ///
    /// The caller-provided `key_material` slice **must** be zeroized by
    /// the caller after this method returns. Implementations **must**
    /// zeroize any internal copy on `Drop` (see the Zeroize contract on
    /// the trait).
    fn hsm_import_key(&mut self, slot: HsmSlotId, key_material: &[u8]) -> Result<(), VsError>;

    /// Read the monotonic counter (OTP fuse-backed, cannot be reset).
    ///
    /// # Error semantics
    ///
    /// - [`VsError::NotInitialized`] — counter fuses not provisioned.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    fn hsm_read_monotonic_counter(&self) -> Result<u64, VsError>;

    /// Increment the monotonic counter by 1 (irreversible).
    ///
    /// # Error semantics
    ///
    /// - [`VsError::ResourceExhausted`] — counter has reached its maximum
    ///   value (no further increments are possible).
    /// - [`VsError::NotInitialized`] — counter fuses not provisioned.
    /// - [`VsError::CryptoError`] — HSM hardware error.
    fn hsm_increment_monotonic_counter(&mut self) -> Result<u64, VsError>;
}

// ---------------------------------------------------------------------------
// EthernetPhy — Ethernet hardware interface
// ---------------------------------------------------------------------------

/// Maximum Ethernet frame size (1522 bytes: 1500 payload + 14 header + 4 VLAN + 4 FCS).
pub const MAX_ETH_FRAME_LEN: usize = 1522;

/// Raw Ethernet frame from hardware.
///
/// # Performance note
///
/// Returning a `RawEthFrame` by value (e.g. from [`EthernetPhy::receive`])
/// copies the full 1522-byte buffer up the call stack on every frame. At
/// 1 Gbps line rate this is the known hot-path cost of the current
/// trait-surface shape; profiling at v0.7 puts the copy near the top of
/// the per-frame ingress budget. A future revision (planned for v0.8)
/// will replace the by-value return with an out-parameter
/// (`fn receive(&mut self, out: &mut RawEthFrame) -> Result<bool, _>`) so
/// callers can reuse a single buffer. Until then, prefer
/// [`BatchReceive`] where the driver supports it.
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
    ///
    /// # Performance
    ///
    /// Returning by value copies the full 1522-byte `RawEthFrame` buffer up
    /// the call stack on every received frame. This is the known hot-path
    /// cost at 1 Gbps; a future v0.8 revision will switch to an
    /// out-parameter shape to allow buffer reuse. See [`RawEthFrame`].
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
///
/// # Zeroize contract
///
/// Implementations **MUST** zeroize key material in old value bytes when
/// overwriting or deleting. This obligation applies to every byte of any
/// in-RAM, flash, or NVM buffer that previously held the value — leaving
/// residual key material readable after `write` (overwrite) or `delete` is
/// a security defect, not a quality-of-implementation matter. This trait
/// cannot enforce the requirement structurally; it is a contract that
/// implementors must honour.
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
// Tpm2Transport — forward-looking stub for a real TPM 2.0 transport
// ---------------------------------------------------------------------------

/// Maximum size of a single TPM 2.0 command or response buffer at the
/// TIS/CRB transport layer (TPM 2.0 Library Specification, Part 1).
///
/// Used by the experimental [`Tpm2Transport`] trait. The exact bound is
/// **not** finalized and may change before v1.0.
#[cfg(feature = "tpm2-experimental")]
pub const TPM2_MAX_BUFFER: usize = 4096;

/// Forward-looking trait for a **real** TPM 2.0 transport (TIS or CRB).
///
/// # Status: EXPERIMENTAL — DO NOT IMPLEMENT IN PRODUCTION
///
/// This trait is a **placeholder**. It exists purely to document the
/// intended API surface for a future hardware-rooted attestation path
/// and to give downstream consumers a stable symbol to anchor their own
/// prototype work against. The method signatures, command parameter
/// shapes, error semantics, and even the trait's existence may change
/// arbitrarily before the v1.0 release of `Craton Shield`.
///
/// The current `secure-boot` attestation primitive
/// (`vs_secure_boot::CryptoProviderBackedTpm`, renamed from `HardwareTpm`
/// in the Pre-1.0 trait-surface evolution) is **software-backed** — it delegates to a `CryptoProvider`
/// and produces a custom dual-HMAC quote, not a real `TPMS_ATTEST`
/// structure signed via `TPM_ALG_RSASSA` / `TPM_ALG_ECDSA`. To obtain a
/// true hardware root of trust, downstream platforms must speak the TPM
/// 2.0 wire protocol to a discrete TPM (Infineon SLB 9670/9672, ST
/// ST33TPHF, Nuvoton NPCT75x, etc.) over TIS (Trusted Interface
/// Specification) or CRB (Command Response Buffer) using SPI, LPC, or
/// I2C. This trait reserves the surface for that path.
///
/// Method signatures intentionally mirror the TPM 2.0 command set at
/// the transport level: callers serialize a TPM2 command into a byte
/// buffer, the transport ships it to the device, and the response is
/// deserialized by the caller. Higher-level helpers (e.g. `TPM2_Quote`,
/// `TPM2_PCR_Extend`, `TPM2_StartAuthSession`) are out of scope and
/// will be layered on top in a future crate.
///
/// # Stability
///
/// Gated behind the `tpm2-experimental` cargo feature and marked
/// [`#[deprecated]`](deprecated) so that accidental production use
/// triggers a compiler warning at every call site. **Do not depend on
/// this trait outside of prototypes.**
#[cfg(feature = "tpm2-experimental")]
#[deprecated(note = "API not finalized; do not implement in production yet. \
            This trait is a forward-looking placeholder for the v1.0 \
            real-TPM2 hardware path and may change without notice.")]
pub trait Tpm2Transport {
    /// Initialize the TPM 2.0 transport (clear the command/response
    /// buffer, take ownership of the locality, send `TPM2_Startup`).
    ///
    /// Placeholder; signature subject to change.
    fn tpm2_init(&mut self) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    /// Send a fully-serialized TPM 2.0 command over the underlying
    /// transport (TIS or CRB) and read back the response.
    ///
    /// `command` contains the marshalled command header (tag, command
    /// size, command code) followed by the command's parameter area.
    /// On success `response_out` is filled with the device's response
    /// and the number of bytes written is returned.
    ///
    /// Placeholder; signature subject to change.
    fn tpm2_transmit(&mut self, command: &[u8], response_out: &mut [u8]) -> Result<usize, VsError> {
        let _ = (command, response_out);
        Err(VsError::NotInitialized)
    }

    /// Issue a low-level `TPM2_GetCapability` query (e.g. to read
    /// firmware version, supported algorithms, PCR bank selection).
    ///
    /// Placeholder; signature subject to change.
    fn tpm2_get_capability(
        &mut self,
        capability: u32,
        property: u32,
        response_out: &mut [u8],
    ) -> Result<usize, VsError> {
        let _ = (capability, property, response_out);
        Err(VsError::NotInitialized)
    }

    /// Release the locality and shut the transport down cleanly.
    ///
    /// Placeholder; signature subject to change.
    fn tpm2_shutdown(&mut self) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// Stub implementations for testing
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-stubs"))]
/// Stub CAN bus that always returns no frames and discards transmissions.
pub struct StubCanBus {
    bitrate: u32,
}

#[cfg(any(test, feature = "test-stubs"))]
impl StubCanBus {
    /// Construct a [`StubCanBus`] reporting the given fixed bitrate.
    pub const fn new(bitrate: u32) -> Self {
        Self { bitrate }
    }
}

#[cfg(any(test, feature = "test-stubs"))]
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

#[cfg(any(test, feature = "test-stubs"))]
/// Stub Ethernet PHY that always returns no frames and discards transmissions.
pub struct StubEthernetPhy {
    link_speed: u32,
    link_up: bool,
}

#[cfg(any(test, feature = "test-stubs"))]
impl StubEthernetPhy {
    /// Construct a [`StubEthernetPhy`] reporting the given link speed
    /// (Mbit/s) and an initially up link.
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

#[cfg(any(test, feature = "test-stubs"))]
impl Default for StubEthernetPhy {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(any(test, feature = "test-stubs"))]
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
    /// Construct a fresh stub HSM with all 16 slots zeroed and the
    /// monotonic counter at zero. **Insecure — test/dev use only.**
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
    fn capabilities(&self) -> HsmCapabilities {
        // The stub provides software (insecure) emulation of every primitive,
        // but it is **not** a hardware-backed HSM and does **not** zeroize on
        // drop. Real HSM implementations should declare these capabilities
        // honestly; the stub deliberately reports `supports_zeroize_on_drop =
        // false` so that any consumer that accidentally pulls the stub into
        // a non-test build can detect the gap via `capabilities()`.
        HsmCapabilities {
            supports_hmac_sha256: true,
            supports_ecdh_p256: true,
            supports_ecdsa_p256: true,
            supports_aes_gcm_256: true,
            supports_zeroize_on_drop: false,
            // The stub RNG is deterministic — never advertise hardware RNG
            // backing. Callers must check this flag before relying on
            // [`HsmHardware::hsm_random_bytes`] for cryptographic
            // randomness.
            supports_hw_rng: false,
            max_key_slots: 16,
        }
    }

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

    /// WARNING: stub RNG is **deterministic** — fills `buf` with a fixed
    /// permutation derived solely from the index. It provides **zero**
    /// cryptographic strength and exists only to keep test fixtures
    /// reproducible. Never enable `stub-hsm` in security-relevant builds.
    /// Callers must check [`HsmCapabilities::supports_hw_rng`] before
    /// trusting this output for any cryptographic purpose.
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
#[cfg(any(test, feature = "test-stubs"))]
pub struct StubTimer {
    current_us: u64,
}

#[cfg(any(test, feature = "test-stubs"))]
impl StubTimer {
    /// Construct a [`StubTimer`] initialized to `start_us` microseconds.
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

#[cfg(any(test, feature = "test-stubs"))]
impl Timer for StubTimer {
    fn now_us(&self) -> u64 {
        self.current_us
    }
    fn cycle_count(&self) -> Option<u64> {
        None
    }
}

/// Stub watchdog that tracks state but never resets.
#[cfg(any(test, feature = "test-stubs"))]
pub struct StubWatchdog {
    running: bool,
    timeout_us: u64,
    kick_count: u64,
}

#[cfg(any(test, feature = "test-stubs"))]
impl StubWatchdog {
    /// Construct a stopped [`StubWatchdog`] with a zero timeout and zero
    /// kick count.
    pub const fn new() -> Self {
        Self {
            running: false,
            timeout_us: 0,
            kick_count: 0,
        }
    }

    /// Return the cumulative number of successful [`Watchdog::kick`] calls
    /// observed since construction. Useful in tests for asserting that the
    /// tick loop is actually exercising the watchdog.
    pub fn kick_count(&self) -> u64 {
        self.kick_count
    }
}

#[cfg(any(test, feature = "test-stubs"))]
impl Default for StubWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-stubs"))]
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
#[cfg(any(test, feature = "test-stubs"))]
#[derive(Clone, Copy)]
struct StorageEntry {
    key: [u8; MAX_STORAGE_KEY_LEN],
    key_len: usize,
    value: [u8; MAX_STORAGE_VALUE_LEN],
    value_len: usize,
}

/// In-memory secure storage for testing.
///
/// **Not for production use.** Gated behind `cfg(any(test, feature =
/// "test-stubs"))` so the in-memory stub cannot ship into release builds.
#[cfg(any(test, feature = "test-stubs"))]
pub struct StubSecureStorage {
    entries: [Option<StorageEntry>; 32],
    entry_count: usize,
    counters: [Option<u64>; 8],
}

#[cfg(any(test, feature = "test-stubs"))]
impl StubSecureStorage {
    /// Create an empty stub storage with no entries and no counters.
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

#[cfg(any(test, feature = "test-stubs"))]
impl Default for StubSecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-stubs"))]
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
            if let Some(ref mut entry) = self.entries[idx] {
                // Zeroize the previous value bytes before writing the new
                // value. Honours the `SecureStorage` zeroize contract: no
                // residual key material may remain readable across an
                // overwrite.
                entry.value = [0u8; MAX_STORAGE_VALUE_LEN];
                entry.value[..value.len()].copy_from_slice(value);
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
            // Zeroize the slot's value bytes before any move / clear so the
            // prior key material is not left readable in the now-inactive
            // slot. Honours the `SecureStorage` zeroize contract.
            if let Some(ref mut entry) = self.entries[idx] {
                entry.value = [0u8; MAX_STORAGE_VALUE_LEN];
                entry.value_len = 0;
            }
            // Swap-remove with last entry.
            self.entry_count -= 1;
            if idx != self.entry_count {
                self.entries[idx] = self.entries[self.entry_count];
            }
            // Clear the (now duplicate) tail slot. Setting to `None` drops
            // the `StorageEntry`; we additionally overwrite via assignment
            // so any residual bytes in the `Option<StorageEntry>` slot are
            // not observable.
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
        // The stub does not expose TEC/REC, so the default `None` propagates.
        // This guards against future regressions where a stub silently
        // returns `Some(zeroed)` and masks "unsupported by driver".
        assert_eq!(bus.error_counters(), None);
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

    // -- HsmCapabilities regression tests -------------------------------------

    #[test]
    fn hsm_capabilities_none_is_all_disabled() {
        let caps = HsmCapabilities::NONE;
        assert!(!caps.supports_hmac_sha256);
        assert!(!caps.supports_ecdh_p256);
        assert!(!caps.supports_ecdsa_p256);
        assert!(!caps.supports_aes_gcm_256);
        assert!(!caps.supports_zeroize_on_drop);
        assert!(!caps.supports_hw_rng);
        assert_eq!(caps.max_key_slots, 0);
    }

    #[test]
    fn hsm_capabilities_is_copy_and_eq() {
        let a = HsmCapabilities::NONE;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn stub_hsm_capabilities_match_implementation() {
        // The stub claims to implement every primitive (it does, insecurely)
        // but explicitly reports `supports_zeroize_on_drop = false` and
        // `supports_hw_rng = false`. Lock that in so a regression in the
        // stub doesn't silently flip a security-relevant flag.
        let hsm = StubHsmHardware::new();
        let caps = hsm.capabilities();
        assert!(caps.supports_hmac_sha256);
        assert!(caps.supports_ecdh_p256);
        assert!(caps.supports_ecdsa_p256);
        assert!(caps.supports_aes_gcm_256);
        assert!(!caps.supports_zeroize_on_drop);
        assert!(!caps.supports_hw_rng);
        assert_eq!(caps.max_key_slots, 16);
    }

    #[test]
    fn stub_hsm_implements_every_required_method() {
        // Compile-time check disguised as a runtime test: this only builds
        // if `StubHsmHardware` provides every required method on the Pre-1.0 trait-surface evolution
        // trait surface (no defaults).
        let mut hsm = StubHsmHardware::new();
        hsm.hsm_import_key(0, &[0u8; 32]).unwrap();
        let _caps: HsmCapabilities = hsm.capabilities();

        let nonce = [0u8; 12];
        let mut ct = [0u8; 4];
        let mut tag = [0u8; 16];
        hsm.hsm_aes_gcm_encrypt(0, &nonce, &[0u8; 4], b"", &mut ct, &mut tag)
            .unwrap();
        let mut pt = [0u8; 4];
        hsm.hsm_aes_gcm_decrypt(0, &nonce, &ct, b"", &tag, &mut pt)
            .unwrap();

        let mut sig = [0u8; 64];
        hsm.hsm_sign_p256(0, &[0u8; 32], &mut sig).unwrap();
        let _ = hsm
            .hsm_verify_p256(0, &[0u8; 65], &[0u8; 32], &sig)
            .unwrap();

        let mut h = [0u8; 32];
        hsm.hsm_sha256(b"x", &mut h).unwrap();

        let mut mac = [0u8; 32];
        hsm.hsm_hmac_sha256(0, b"x", &mut mac).unwrap();

        let mut shared = [0u8; 32];
        hsm.hsm_ecdh_derive(0, &[0x04u8; 65], &mut shared).unwrap();

        let mut rnd = [0u8; 8];
        hsm.hsm_random_bytes(&mut rnd).unwrap();

        let _ = hsm.hsm_read_monotonic_counter().unwrap();
        let _ = hsm.hsm_increment_monotonic_counter().unwrap();
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
