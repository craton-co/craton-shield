// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! C FFI bindings for Craton Shield Auto on Linux/QNX gateway ECUs.
//!
//! Provides a platform singleton with `Mutex`-based thread safety, token bucket rate
//! limiting, CAN/Ethernet frame submission, health snapshots, and lifecycle management.
//! Requires `std` — not intended for bare-metal Cortex-M targets.
//! All other crates in the workspace remain `#![no_std]`.

// Prevent the stub crypto provider from being compiled into release binaries.
#[cfg(all(not(feature = "production"), not(debug_assertions), not(test)))]
compile_error!(
    "The `production` feature must be enabled for release builds. \
     Without it, the FFI layer uses a stub CryptoProvider that provides \
     zero security. Enable the `production` feature and supply a real \
     CryptoProvider for production."
);

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_runtime::CanFrame;
use vs_runtime_auto::{AutomotiveConfig, AutomotiveShield, SubsystemStatus};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Stub CryptoProvider (non-production only)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "production"))]
#[derive(Clone)]
struct StubCryptoProvider;

#[cfg(not(feature = "production"))]
impl Default for StubCryptoProvider {
    fn default() -> Self {
        Self
    }
}

#[cfg(not(feature = "production"))]
impl CryptoProvider for StubCryptoProvider {
    fn aes_gcm_encrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
        _: &mut [u8; 16],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
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
        Err(VsError::NotInitialized)
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Non-cryptographic stub: allows init/health paths to succeed.
        // Must produce non-zero, deterministic, and collision-resistant-enough
        // output to pass the CryptoProvider::self_test() canary checks.
        for (i, b) in hash_out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0xA5);
        }
        for (i, &b) in data.iter().enumerate() {
            hash_out[i % 32] ^= b;
            hash_out[(i + 1) % 32] = hash_out[(i + 1) % 32].wrapping_add(b);
        }
        Ok(())
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], _mac_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Fail-closed: refuse HMAC in stub mode to prevent SecurityAccess bypass.
        // An all-zeros HMAC would allow any tester to authenticate by sending
        // 32 zero bytes. Event logging uses sha256 (which succeeds) so this
        // does not break init/health paths.
        Err(VsError::NotInitialized)
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], _: &mut [u8; 32]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        // Fail-closed: reject all signatures in stub mode.
        Err(VsError::NotInitialized)
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        // Stub: fill with position-dependent values to allow platform
        // initialization to succeed while producing non-uniform output.
        // This is NOT cryptographically random — the compile_error! guard
        // prevents this stub from reaching release builds. Security flows
        // (e.g. SecurityAccess seeds) that depend on unpredictable random
        // bytes will produce predictable values, which is acceptable only
        // for testing. Using position-dependent fill avoids the all-zeros
        // pattern that could allow trivial authentication bypass in tests.
        // STUB: deterministic, non-cryptographic fill.
        // The compile_error! guard prevents this from reaching release builds.
        // Using position + length mixing to avoid trivially predictable patterns
        // while remaining deterministic for test reproducibility.
        let len_mix = buf.len() as u8;
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42).wrapping_add(len_mix);
        }
        Ok(())
    }
    fn delete_key(&mut self, _key_id: KeyId) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn generate_key(&mut self, _key_id: KeyId, _key_type: KeyType) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// Production CryptoProvider (C callback bridge)
// ---------------------------------------------------------------------------

/// C-compatible cryptographic callback table for production builds.
///
/// The C caller must supply valid function pointers for all operations used by
/// the automotive platform. Pass this struct to `vs_auto_platform_init_with_crypto`
/// to initialize the platform with a real cryptographic backend (e.g. HSM driver).
///
/// The `context` pointer is forwarded to every callback so the C implementation
/// can carry driver state without global variables. The FFI layer does not
/// dereference or free `context`.
#[cfg(feature = "production")]
#[repr(C)]
pub struct VsCryptoCallbacks {
    /// Magic number that must be set to `VS_CRYPTO_CALLBACKS_MAGIC` (0xC5A7_0001).
    /// Checked before every callback invocation to detect use-after-free.
    pub magic: u32,
    /// Opaque context pointer forwarded to every callback.
    pub context: *mut core::ffi::c_void,
    pub sha256: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        data: *const u8,
        data_len: usize,
        hash_out: *mut u8,
    ) -> i32,
    pub hmac_sha256: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        key_id: u32,
        data: *const u8,
        data_len: usize,
        mac_out: *mut u8,
    ) -> i32,
    pub aes_gcm_encrypt: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        key_id: u32,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        plaintext: *const u8,
        pt_len: usize,
        ciphertext: *mut u8,
        tag: *mut u8,
    ) -> i32,
    pub aes_gcm_decrypt: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        key_id: u32,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        ciphertext: *const u8,
        ct_len: usize,
        tag: *const u8,
        plaintext: *mut u8,
    ) -> i32,
    pub ecdh_derive_shared: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        key_id: u32,
        peer_pub: *const u8,
        shared_out: *mut u8,
    ) -> i32,
    pub sign_p256: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        key_id: u32,
        digest: *const u8,
        sig_out: *mut u8,
    ) -> i32,
    pub verify_p256: unsafe extern "C" fn(
        ctx: *mut core::ffi::c_void,
        pub_key: *const u8,
        digest: *const u8,
        sig: *const u8,
    ) -> i32,
    pub random_bytes:
        unsafe extern "C" fn(ctx: *mut core::ffi::c_void, buf: *mut u8, len: usize) -> i32,
    pub delete_key: unsafe extern "C" fn(ctx: *mut core::ffi::c_void, key_id: u32) -> i32,
    pub generate_key:
        unsafe extern "C" fn(ctx: *mut core::ffi::c_void, key_id: u32, key_type: u32) -> i32,
}

// SAFETY: VsCryptoCallbacks contains a raw pointer (`context`) and function
// pointers. The C caller guarantees that the context pointer remains valid for
// the lifetime of the platform and that the callbacks are thread-safe.
#[cfg(feature = "production")]
unsafe impl Send for VsCryptoCallbacks {}

// SAFETY: All callbacks are required to be thread-safe by contract.
#[cfg(feature = "production")]
unsafe impl Sync for VsCryptoCallbacks {}

/// Production `CryptoProvider` that delegates to C function pointers.
///
/// Stores a raw pointer to the C-owned `VsCryptoCallbacks` struct rather than
/// a `&'static` reference. This avoids unsoundly fabricating a `'static`
/// lifetime for memory whose true lifetime is controlled by the C caller.
///
/// # Safety contract
///
/// The C caller guarantees the pointer remains valid from
/// `vs_auto_platform_init_with_crypto` until `vs_auto_platform_shutdown`.
/// Every method validates the pointer is non-null and the magic canary is
/// intact before dereferencing.
#[cfg(feature = "production")]
struct ExternalCryptoProvider {
    callbacks: *const VsCryptoCallbacks,
}

// SAFETY: `callbacks` is a raw pointer to a C-owned struct that the C caller
// guarantees is thread-safe and valid for the platform lifetime. Raw pointers
// are `Copy` (and therefore trivially `Clone`), so this is safe.
#[cfg(feature = "production")]
impl Clone for ExternalCryptoProvider {
    fn clone(&self) -> Self {
        Self {
            callbacks: self.callbacks,
        }
    }
}

// SAFETY: The C caller guarantees that the callback table and its context
// pointer are safe to use from any thread.
#[cfg(feature = "production")]
unsafe impl Send for ExternalCryptoProvider {}

// SAFETY: All callback invocations go through raw pointer dereference with
// null and magic checks; the C caller guarantees thread-safety of callbacks.
#[cfg(feature = "production")]
unsafe impl Sync for ExternalCryptoProvider {}

#[cfg(feature = "production")]
impl ExternalCryptoProvider {
    fn result_from_code(code: i32) -> Result<(), VsError> {
        if code == 0 {
            Ok(())
        } else {
            Err(VsError::CryptoError)
        }
    }

    /// Validate that the callbacks pointer is non-null and the magic canary
    /// matches. Returns a reference to the callbacks struct on success.
    ///
    /// # Safety
    ///
    /// The returned reference borrows from a raw pointer. The C caller
    /// guarantees the pointer remains valid for the platform lifetime.
    /// This method must only be called while the platform is initialized.
    fn check_and_deref(&self) -> Result<&VsCryptoCallbacks, VsError> {
        if self.callbacks.is_null() {
            return Err(VsError::NotInitialized);
        }
        // Defense-in-depth: reject misaligned pointers before dereference.
        if (self.callbacks as usize) % core::mem::align_of::<VsCryptoCallbacks>() != 0 {
            return Err(VsError::NotInitialized);
        }
        // SAFETY: We checked non-null and aligned above. The C caller
        // guarantees the pointer remains valid from init until shutdown.
        let cb = unsafe { &*self.callbacks };
        if cb.magic != VS_CRYPTO_CALLBACKS_MAGIC {
            Err(VsError::NotInitialized)
        } else {
            Ok(cb)
        }
    }
}

#[cfg(feature = "production")]
impl CryptoProvider for ExternalCryptoProvider {
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        // SAFETY: caller-provided callbacks; pointers and lengths are valid.
        let code = unsafe {
            (cb.aes_gcm_encrypt)(
                cb.context,
                key_id,
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        Self::result_from_code(code)
    }
    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe {
            (cb.aes_gcm_decrypt)(
                cb.context,
                key_id,
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        };
        Self::result_from_code(code)
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code =
            unsafe { (cb.sha256)(cb.context, data.as_ptr(), data.len(), hash_out.as_mut_ptr()) };
        Self::result_from_code(code)
    }
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe {
            (cb.hmac_sha256)(
                cb.context,
                key_id,
                data.as_ptr(),
                data.len(),
                mac_out.as_mut_ptr(),
            )
        };
        Self::result_from_code(code)
    }
    fn ecdh_derive_shared(
        &self,
        key_id: KeyId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe {
            (cb.ecdh_derive_shared)(
                cb.context,
                key_id,
                peer_public.as_ptr(),
                shared_out.as_mut_ptr(),
            )
        };
        Self::result_from_code(code)
    }
    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code =
            unsafe { (cb.sign_p256)(cb.context, key_id, digest.as_ptr(), sig_out.as_mut_ptr()) };
        Self::result_from_code(code)
    }
    fn verify_p256(
        &self,
        public_key: &[u8; 65],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<bool, VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe {
            (cb.verify_p256)(
                cb.context,
                public_key.as_ptr(),
                digest.as_ptr(),
                signature.as_ptr(),
            )
        };
        match code {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(VsError::CryptoError),
        }
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe { (cb.random_bytes)(cb.context, buf.as_mut_ptr(), buf.len()) };
        Self::result_from_code(code)
    }
    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe { (cb.delete_key)(cb.context, key_id.0) };
        Self::result_from_code(code)
    }
    fn generate_key(&mut self, key_id: KeyId, key_type: KeyType) -> Result<(), VsError> {
        let cb = self.check_and_deref()?;
        let code = unsafe { (cb.generate_key)(cb.context, key_id.0, key_type as u32) };
        Self::result_from_code(code)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VS_OK: i32 = 0;
const VS_ERR_INVALID_ARG: i32 = -1;
const VS_ERR_NOT_INITIALIZED: i32 = -2;
const VS_ERR_INTERNAL: i32 = -3;
const VS_ERR_RATE_LIMITED: i32 = -4;
const VS_ERR_ALREADY_INITIALIZED: i32 = -5;
const VS_ERR_INTEGRITY_FAILURE: i32 = -6;
const VS_ERR_MISALIGNED: i32 = -7;

const CAN_RATE_CAPACITY: u64 = 100_000;
const CAN_RATE_TOKENS_PER_SEC: u64 = 50_000;

/// Ethernet rate limiter capacity.
/// Higher than CAN because Ethernet links carry more traffic volume.
const ETH_RATE_CAPACITY: u64 = 200_000;
/// Ethernet rate limiter refill rate (tokens per second).
const ETH_RATE_TOKENS_PER_SEC: u64 = 100_000;

const LIN_RATE_CAPACITY: u64 = 500;
const LIN_RATE_TOKENS_PER_SEC: u64 = 500;
const FLEXRAY_RATE_CAPACITY: u64 = 2000;
const FLEXRAY_RATE_TOKENS_PER_SEC: u64 = 2000;

/// Magic number for `VsCryptoCallbacks` validity checking.
#[cfg(feature = "production")]
pub const VS_CRYPTO_CALLBACKS_MAGIC: u32 = 0xC5A7_0001;

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct VsResult {
    pub code: i32,
}

impl VsResult {
    const fn ok() -> Self {
        Self { code: VS_OK }
    }
    const fn invalid_arg() -> Self {
        Self {
            code: VS_ERR_INVALID_ARG,
        }
    }
    const fn not_initialized() -> Self {
        Self {
            code: VS_ERR_NOT_INITIALIZED,
        }
    }
    const fn internal() -> Self {
        Self {
            code: VS_ERR_INTERNAL,
        }
    }
    const fn rate_limited() -> Self {
        Self {
            code: VS_ERR_RATE_LIMITED,
        }
    }
    const fn already_initialized() -> Self {
        Self {
            code: VS_ERR_ALREADY_INITIALIZED,
        }
    }
    const fn misaligned() -> Self {
        Self {
            code: VS_ERR_MISALIGNED,
        }
    }
}

/// CAN / CAN-FD frame as seen by the C caller.
#[repr(C)]
pub struct VsCanFrame {
    pub id: u32,
    pub dlc: u8,
    pub data: [u8; 64],
    pub is_extended: u8,
    pub is_fd: u8,
    pub timestamp_us: u64,
}

/// Ethernet packet as seen by the C caller.
#[repr(C)]
pub struct VsEthPacket {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: u16, // 0 = no VLAN
    pub has_vlan: u8,
    /// Reserved padding byte for ABI alignment. Must be initialized to zero
    /// by C callers. This field is never read by the Rust implementation.
    pub padding: u8,
    pub dst_port: u16, // 0 = no port
    pub has_dst_port: u8,
    pub payload_len: u32,
    pub payload: [u8; 1500],
    pub timestamp_us: u64,
}

/// Automotive health snapshot exposed to C callers.
#[repr(C)]
pub struct VsHealthAuto {
    pub crypto: i32,
    pub key_manager: i32,
    pub secure_boot: i32,
    pub event_logger: i32,
    pub can_monitor: i32,
    pub eth_monitor: i32,
    pub ids_engine: i32,
    pub firewall: i32,
    pub ota_validator: i32,
    pub anomaly: i32,
    pub integrity: i32,
    pub policy_engine: i32,
    pub storage: i32,
    pub hal: i32,
    pub signal_ids: i32,
    pub v2x: i32,
    pub diag_gateway: i32,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn status_to_i32(s: SubsystemStatus) -> i32 {
    match s {
        SubsystemStatus::Ready => 0,
        SubsystemStatus::Degraded => 1,
        SubsystemStatus::Failed => 2,
        SubsystemStatus::NotInitialized => 3,
    }
}

struct TokenBucket {
    tokens: u64,
    capacity: u64,
    rate: u64,
    last_refill_us: u64,
    /// Accumulated fractional microseconds from rounding. Prevents precision
    /// loss when `rate` does not evenly divide 1\_000\_000 (e.g. `rate=1` would
    /// previously lose almost a full token per second from integer truncation).
    remainder_accum_us: u64,
}

impl TokenBucket {
    const fn new(capacity: u64, rate: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            rate,
            last_refill_us: 0,
            remainder_accum_us: 0,
        }
    }

    /// Attempt to consume one token, refilling based on elapsed time.
    ///
    /// # Accumulated-microseconds optimization
    ///
    /// Rather than computing `elapsed_us * rate / 1_000_000` directly (which
    /// loses fractional tokens to integer truncation on every call), we
    /// accumulate `elapsed_us * rate` into `remainder_accum_us` across calls.
    /// The division by 1\_000\_000 is performed on the accumulated total,
    /// and only the remainder is carried forward. This ensures that even
    /// very low rates (e.g. `rate=1` token/sec with sub-second call
    /// intervals) eventually grant tokens without precision loss.
    fn try_consume(&mut self, now_us: u64) -> bool {
        // Guard against non-monotonic timestamps: if `now_us` is before the
        // last refill (e.g. due to a time discontinuity), skip refill entirely
        // to avoid granting a burst of tokens from a large forward jump after
        // a backward one.
        if now_us >= self.last_refill_us {
            let elapsed = now_us - self.last_refill_us;
            // Cap elapsed time to prevent a single large forward time jump
            // from instantly refilling the bucket to capacity. At most refill
            // 2 seconds' worth of tokens per call.
            let capped_elapsed = if elapsed > 2_000_000 {
                2_000_000
            } else {
                elapsed
            };
            // Compute refill using accumulated microseconds to prevent
            // precision loss from integer truncation. For example, rate=1
            // previously computed 0 tokens for remainder_us=999_999.
            let total_us = self
                .remainder_accum_us
                .saturating_add(capped_elapsed.saturating_mul(self.rate));
            let refill = total_us / 1_000_000;
            self.remainder_accum_us = total_us % 1_000_000;
            if refill > 0 {
                self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
                self.last_refill_us = now_us;
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_refill_us = 0;
        self.remainder_accum_us = 0;
    }
}

fn monotonic_now_us() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u64
}

/// Catch Rust panics at the FFI boundary and convert them to error codes.
///
/// All FFI entry points wrap their logic in `ffi_guard` to prevent Rust
/// panics from unwinding across the C ABI boundary (which is undefined
/// behavior). If a panic occurs:
///
/// 1. The panic count is incremented atomically.
/// 2. The `PLATFORM` `RwLock` becomes permanently poisoned.
/// 3. All subsequent FFI calls return `VS_ERR_INTERNAL`.
/// 4. Recovery requires process restart (fail-stop semantics).
///
/// `AssertUnwindSafe` is used intentionally: the fail-stop poisoning
/// guarantees that no inconsistent state is ever observed after a panic.
/// The mutex will refuse to grant access once poisoned, so the
/// `AssertUnwindSafe` assertion is sound under our fail-stop contract.
///
/// # Known gap: partial mutations within a single FFI call
///
/// If a panic occurs *mid-mutation* (e.g. halfway through updating platform
/// state), the data protected by the lock may be left in a partially-modified
/// state. However, because the `RwLock` becomes permanently poisoned on
/// panic, no subsequent call can ever observe that inconsistent state. The
/// fail-stop poisoning converts a potential data-integrity issue into a
/// permanent, detectable failure. This is the accepted trade-off: partial
/// mutations are the known gap, and fail-stop poisoning prevents any
/// subsequent access.
#[allow(clippy::single_match_else)]
fn ffi_guard<F: FnOnce() -> VsResult + std::panic::UnwindSafe>(f: F) -> VsResult {
    match catch_unwind(f) {
        Ok(r) => r,
        Err(_) => {
            PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
            VsResult::internal()
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global automotive platform singleton.
///
/// Uses `RwLock` to allow concurrent read access for health checks while
/// serializing write access for frame submissions and lifecycle operations.
///
/// **Fail-stop on poisoning**: If a panic occurs while this lock is held
/// (caught by `ffi_guard`), the lock becomes permanently poisoned and all
/// subsequent FFI calls return `VS_ERR_INTERNAL`. This is intentional
/// fail-stop behavior for safety-critical systems — a panicked platform
/// must not silently resume operation. Recovery requires process restart.
// NOTE: RwLock is used despite write-heavy access because `vs_auto_get_health`
// is the only read path, and on most platforms RwLock::read() is cheaper than
// Mutex::lock() when there are no writers. The write-heavy access pattern means
// this behaves similarly to a Mutex in practice, but health checks (the most
// latency-sensitive call on the monitoring path) benefit from non-exclusive access.
#[cfg(not(feature = "production"))]
static PLATFORM: RwLock<Option<AutomotiveShield<StubCryptoProvider>>> = RwLock::new(None);

/// Global automotive platform singleton (production variant).
///
/// See non-production `PLATFORM` for fail-stop poisoning semantics.
#[cfg(feature = "production")]
static PLATFORM: RwLock<Option<AutomotiveShield<ExternalCryptoProvider>>> = RwLock::new(None);

/// Wrapper around a raw pointer to make it `Send + Sync` for storage in
/// a `Mutex`. The C caller guarantees thread-safety of the callback table.
#[cfg(feature = "production")]
struct CallbackPtr(*const VsCryptoCallbacks);

// SAFETY: The C caller guarantees the callback table is thread-safe.
#[cfg(feature = "production")]
unsafe impl Send for CallbackPtr {}
#[cfg(feature = "production")]
unsafe impl Sync for CallbackPtr {}

/// Holds the raw pointer to the production crypto callbacks for the lifetime
/// of the platform.
///
/// Stored as a raw pointer instead of `&'static VsCryptoCallbacks` to avoid
/// unsoundly fabricating a `'static` lifetime for C-owned memory. The pointer
/// is nulled out on shutdown to prevent use-after-free if the C caller
/// deallocates the callback struct afterward.
///
/// # Safety
///
/// The C caller guarantees the pointed-to struct remains valid and immutable
/// from `vs_auto_platform_init_with_crypto` until `vs_auto_platform_shutdown`.
#[cfg(feature = "production")]
static CRYPTO_CALLBACKS: Mutex<Option<CallbackPtr>> = Mutex::new(None);

/// Per-frame rate limiter for CAN ingestion.
///
/// Separated from `PLATFORM` to avoid contention: the rate limiter is
/// acquired and released before the platform lock, so concurrent callers
/// only contend on the lightweight counter check, not the full platform.
///
/// Poisoning follows the same fail-stop semantics as `PLATFORM`.
static CAN_RATE_LIMITER: Mutex<TokenBucket> =
    Mutex::new(TokenBucket::new(CAN_RATE_CAPACITY, CAN_RATE_TOKENS_PER_SEC));

/// Per-frame rate limiter for Ethernet ingestion.
///
/// Uses higher capacity/rate than CAN to accommodate the higher throughput
/// of automotive Ethernet links (100BASE-T1 / 1000BASE-T1).
/// Separated from the CAN limiter so that CAN and Ethernet paths do not
/// contend on the same lock.
static ETH_RATE_LIMITER: Mutex<TokenBucket> =
    Mutex::new(TokenBucket::new(ETH_RATE_CAPACITY, ETH_RATE_TOKENS_PER_SEC));

/// LIN bus rate limiter (separate from CAN/Ethernet).
///
/// Initialized directly (like CAN/ETH) rather than lazily via `Option` so
/// that all rate limiters share a uniform type and access pattern. The
/// limiter is reset to full capacity during `platform_init` /
/// `platform_shutdown` just like the CAN and Ethernet limiters.
static LIN_RATE_LIMITER: Mutex<TokenBucket> =
    Mutex::new(TokenBucket::new(LIN_RATE_CAPACITY, LIN_RATE_TOKENS_PER_SEC));
/// `FlexRay` rate limiter.
static FLEXRAY_RATE_LIMITER: Mutex<TokenBucket> = Mutex::new(TokenBucket::new(
    FLEXRAY_RATE_CAPACITY,
    FLEXRAY_RATE_TOKENS_PER_SEC,
));

/// Monotonic timestamp for rate limiter refills.
/// Uses `AtomicU64` to avoid locking for timestamp reads.
static LAST_MONOTONIC_US: AtomicU64 = AtomicU64::new(0);

static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

/// Runtime marker set to `true` when `vs_auto_platform_init()` (the stub
/// variant) is called. Allows C callers to detect at runtime whether the
/// platform was initialized with the stub crypto provider, even if the
/// `compile_error!` guard was somehow bypassed (e.g. conditional compilation
/// misconfiguration). Check via `vs_auto_is_stub_initialized()`.
static IS_STUB_INIT: AtomicBool = AtomicBool::new(false);

/// Returns `true` if the platform was compiled with the stub crypto provider.
/// C callers can use this to detect non-production builds at runtime.
#[no_mangle]
pub extern "C" fn vs_auto_is_stub_crypto() -> bool {
    cfg!(not(feature = "production"))
}

/// Returns `true` if the platform was initialized via the stub (non-production)
/// init path. This is a runtime check that complements the compile-time
/// `compile_error!` guard — if a stub build somehow slips through to
/// production, C callers can detect it by checking this flag after init.
#[no_mangle]
pub extern "C" fn vs_auto_is_stub_initialized() -> bool {
    IS_STUB_INIT.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Initialize the automotive platform (non-production / testing only).
///
/// Uses a stub `CryptoProvider` that provides no real security.
/// For production builds, use `vs_auto_platform_init_with_crypto` instead.
#[cfg(not(feature = "production"))]
#[no_mangle]
pub extern "C" fn vs_auto_platform_init() -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        if guard.is_some() {
            return VsResult::already_initialized();
        }

        if let Ok(mut limiter) = CAN_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = ETH_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = LIN_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = FLEXRAY_RATE_LIMITER.lock() {
            limiter.reset();
        }

        let config = AutomotiveConfig::default();
        *guard = Some(AutomotiveShield::new(&config));

        // Mark that the stub init path was used. C callers can check
        // `vs_auto_is_stub_initialized()` to detect this at runtime.
        // Uses Release ordering so that a concurrent Acquire load on
        // another thread observes `true` only after the platform is
        // fully initialized (the RwLock provides its own barrier, but
        // the flag can be read without holding the lock).
        IS_STUB_INIT.store(true, Ordering::Release);

        // Runtime warning: the stub crypto provider is active.
        // This is visible in logs and provides a second safety net
        // beyond the compile_error! guard for release builds.
        // Emitted unconditionally (not just debug_assertions) so that any
        // build variant using the stub produces a visible warning.
        eprintln!(
            "[craton-shield] WARNING: Platform initialized with STUB CryptoProvider. \
             ALL cryptographic operations are non-functional. \
             Random number generation is DETERMINISTIC and PREDICTABLE. \
             SecurityAccess seeds, nonces, and IVs are NOT random. \
             This build must NOT be deployed to production."
        );

        VsResult::ok()
    }))
}

/// Initialize the automotive platform with a caller-supplied cryptographic backend.
///
/// # Safety
///
/// The caller **must** guarantee all of the following:
///
/// 1. `callbacks` points to a valid, fully-initialized `VsCryptoCallbacks` struct
///    with `magic` set to `VS_CRYPTO_CALLBACKS_MAGIC` (`0xC5A70001`).
/// 2. The `VsCryptoCallbacks` struct and its `context` pointer remain valid and
///    allocated for the **entire duration** between this call and the
///    corresponding [`vs_auto_platform_shutdown`] call. The struct must not be
///    freed, moved, or modified while the platform is running.
/// 3. All function pointers in the callbacks struct are thread-safe — they may
///    be called concurrently from multiple threads.
/// 4. No other thread calls any `vs_auto_*` function between this call
///    returning `VS_OK` and the platform being fully initialized.
///
/// Violating any of these guarantees is **undefined behavior** (use-after-free,
/// data races, or null pointer dereference).
#[cfg(feature = "production")]
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_platform_init_with_crypto(
    callbacks: *const VsCryptoCallbacks,
) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if callbacks.is_null() {
            return VsResult::invalid_arg();
        }
        if (callbacks as usize) % core::mem::align_of::<VsCryptoCallbacks>() != 0 {
            return VsResult::misaligned();
        }

        // Verify magic number to detect corrupted or uninitialized callback structs.
        let magic = unsafe { (*callbacks).magic };
        if magic != VS_CRYPTO_CALLBACKS_MAGIC {
            return VsResult::invalid_arg();
        }

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        if guard.is_some() {
            return VsResult::already_initialized();
        }

        if let Ok(mut limiter) = CAN_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = ETH_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = LIN_RATE_LIMITER.lock() {
            limiter.reset();
        }
        if let Ok(mut limiter) = FLEXRAY_RATE_LIMITER.lock() {
            limiter.reset();
        }

        // SAFETY: the caller guarantees that `callbacks` points to a valid
        // `VsCryptoCallbacks` struct that remains allocated and valid until
        // `vs_auto_platform_shutdown` is called. We store the raw pointer
        // directly instead of fabricating a `&'static` reference, which
        // would be unsound because the true lifetime is controlled by the
        // C caller. The pointer is nulled on shutdown to prevent
        // use-after-free.
        if let Ok(mut cb_guard) = CRYPTO_CALLBACKS.lock() {
            *cb_guard = Some(CallbackPtr(callbacks));
        }

        let crypto = ExternalCryptoProvider { callbacks };

        // S9: Crypto self-test — hash a known test vector to verify the
        // callback table is functional before committing to initialization.
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        {
            let mut hash_out = [0u8; 32];
            if crypto.sha256(&[], &mut hash_out).is_err() {
                // Callback failed entirely; clear stored pointer and bail.
                if let Ok(mut cb_guard) = CRYPTO_CALLBACKS.lock() {
                    *cb_guard = None;
                }
                return VsResult::internal();
            }
            const EXPECTED_SHA256_EMPTY: [u8; 32] = [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ];
            if hash_out != EXPECTED_SHA256_EMPTY {
                // The callback returned success but produced wrong output.
                // This catches corrupted or invalid callback tables that
                // pass the magic check but don't actually implement SHA-256.
                if let Ok(mut cb_guard) = CRYPTO_CALLBACKS.lock() {
                    *cb_guard = None;
                }
                return VsResult::internal();
            }
        }

        let config = AutomotiveConfig::default();
        match AutomotiveShield::init(config, crypto) {
            Ok(shield) => {
                *guard = Some(shield);
                VsResult::ok()
            }
            Err(_) => {
                // Clean up the stored pointer on init failure.
                if let Ok(mut cb_guard) = CRYPTO_CALLBACKS.lock() {
                    *cb_guard = None;
                }
                VsResult::internal()
            }
        }
    }))
}

/// Submit a CAN frame with full automotive validation.
///
/// # Safety
///
/// `frame` must point to a valid `VsCanFrame`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_submit_can_frame(frame: *const VsCanFrame) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if frame.is_null() {
            return VsResult::invalid_arg();
        }
        if (frame as usize) % core::mem::align_of::<VsCanFrame>() != 0 {
            return VsResult::misaligned();
        }

        let ffi_frame = unsafe { &*frame };

        // Automotive CAN ID validation: standard 11-bit, extended 29-bit.
        let max_id: u32 = if ffi_frame.is_extended != 0 {
            0x1FFF_FFFF
        } else {
            0x7FF
        };
        if ffi_frame.id > max_id {
            return VsResult::invalid_arg();
        }

        // DLC validation: classic CAN max 8, CAN-FD max 64.
        let max_dlc: u8 = if ffi_frame.is_fd != 0 { 64 } else { 8 };
        if ffi_frame.dlc > max_dlc {
            return VsResult::invalid_arg();
        }

        let now_us = monotonic_now_us();
        LAST_MONOTONIC_US.store(now_us, Ordering::Relaxed);

        // Rate-limit check: acquire and release the limiter lock before
        // touching the platform, so concurrent callers only contend on
        // the lightweight counter, not the full platform state.
        {
            let Ok(mut limiter) = CAN_RATE_LIMITER.lock() else {
                return VsResult::internal();
            };
            if !limiter.try_consume(now_us) {
                return VsResult::rate_limited();
            }
        }

        // Build the CAN frame outside the platform lock to minimize
        // critical section duration.
        let dlc = (ffi_frame.dlc as usize).min(64);
        let mut data = [0u8; 64];
        data[..dlc].copy_from_slice(&ffi_frame.data[..dlc]);

        let can_frame = CanFrame {
            id: ffi_frame.id,
            is_extended: ffi_frame.is_extended != 0,
            is_fd: ffi_frame.is_fd != 0,
            dlc: ffi_frame.dlc,
            data,
        };

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => match platform.submit_can_frame(&can_frame, ffi_frame.timestamp_us) {
                Ok(()) => VsResult::ok(),
                Err(_) => VsResult::internal(),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// Submit an Ethernet packet for IDS + firewall inspection.
///
/// # Safety
///
/// `packet` must point to a valid `VsEthPacket`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_submit_eth_packet(packet: *const VsEthPacket) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if packet.is_null() {
            return VsResult::invalid_arg();
        }
        if (packet as usize) % core::mem::align_of::<VsEthPacket>() != 0 {
            return VsResult::misaligned();
        }

        let pkt = unsafe { &*packet };

        // Validate payload length.
        if pkt.payload_len as usize > 1500 {
            return VsResult::invalid_arg();
        }

        let now_us = monotonic_now_us();
        LAST_MONOTONIC_US.store(now_us, Ordering::Relaxed);

        // Rate-limit check using the Ethernet rate limiter.
        {
            let Ok(mut limiter) = ETH_RATE_LIMITER.lock() else {
                return VsResult::internal();
            };
            if !limiter.try_consume(now_us) {
                return VsResult::rate_limited();
            }
        }

        let vlan = if pkt.has_vlan != 0 {
            Some(pkt.vlan_id)
        } else {
            None
        };
        let dst_port = if pkt.has_dst_port != 0 {
            Some(pkt.dst_port)
        } else {
            None
        };
        let payload_len = pkt.payload_len as usize;

        let eth_pkt = vs_runtime::EthPacket {
            src_mac: pkt.src_mac,
            dst_mac: pkt.dst_mac,
            vlan_id: vlan,
            ethertype: pkt.ethertype,
            dst_port,
            payload: &pkt.payload[..payload_len],
        };

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => match platform.submit_eth_packet(&eth_pkt, pkt.timestamp_us) {
                Ok(()) => VsResult::ok(),
                Err(_) => VsResult::internal(),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// Get the automotive health snapshot.
///
/// # Safety
///
/// `out` must point to a valid, writable `VsHealthAuto`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_get_health(out: *mut VsHealthAuto) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if out.is_null() {
            return VsResult::invalid_arg();
        }
        if (out as usize) % core::mem::align_of::<VsHealthAuto>() != 0 {
            return VsResult::misaligned();
        }

        let Ok(guard) = PLATFORM.read() else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(platform) => {
                let h = platform.health_status();
                let health = VsHealthAuto {
                    crypto: status_to_i32(h.core.crypto),
                    key_manager: status_to_i32(h.core.key_manager),
                    secure_boot: status_to_i32(h.core.secure_boot),
                    event_logger: status_to_i32(h.core.event_logger),
                    can_monitor: status_to_i32(h.core.can_monitor),
                    eth_monitor: status_to_i32(h.core.eth_monitor),
                    ids_engine: status_to_i32(h.core.ids_engine),
                    firewall: status_to_i32(h.core.firewall),
                    ota_validator: status_to_i32(h.core.ota_validator),
                    anomaly: status_to_i32(h.core.anomaly),
                    integrity: status_to_i32(h.core.integrity),
                    policy_engine: status_to_i32(h.core.policy_engine),
                    storage: status_to_i32(h.core.storage),
                    hal: status_to_i32(h.core.hal),
                    signal_ids: status_to_i32(h.signal_ids),
                    v2x: status_to_i32(h.v2x),
                    diag_gateway: status_to_i32(h.diag_gateway),
                };
                unsafe { out.write(health) };
                VsResult::ok()
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Shutdown the automotive platform.
///
/// On shutdown:
/// - The platform singleton is set to `None`.
/// - The crypto callbacks pointer is nulled out (production builds).
/// - Rate limiters are reset to full capacity.
#[no_mangle]
pub extern "C" fn vs_auto_platform_shutdown() -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => {
                platform.shutdown();
                *guard = None;

                // Null out the crypto callbacks pointer to prevent
                // use-after-free after the C caller deallocates the
                // callback struct.
                #[cfg(feature = "production")]
                if let Ok(mut cb_guard) = CRYPTO_CALLBACKS.lock() {
                    *cb_guard = None;
                }

                IS_STUB_INIT.store(false, Ordering::Release);

                // Reset rate limiters to full capacity so a subsequent
                // re-initialization starts with a clean slate.
                if let Ok(mut limiter) = CAN_RATE_LIMITER.lock() {
                    limiter.reset();
                }
                if let Ok(mut limiter) = ETH_RATE_LIMITER.lock() {
                    limiter.reset();
                }
                if let Ok(mut limiter) = LIN_RATE_LIMITER.lock() {
                    limiter.reset();
                }
                if let Ok(mut limiter) = FLEXRAY_RATE_LIMITER.lock() {
                    limiter.reset();
                }

                VsResult::ok()
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Return the total number of panics caught by FFI boundary guards.
#[no_mangle]
pub extern "C" fn vs_auto_get_panic_count() -> u64 {
    PANIC_COUNT.load(Ordering::Relaxed)
}

/// Return `true` if the platform Mutex is poisoned (a previous panic
/// occurred while the lock was held). Once poisoned, all FFI calls return
/// `VS_ERR_INTERNAL` and the process must be restarted to recover.
///
/// C callers should check this after receiving `VS_ERR_INTERNAL` to
/// distinguish a transient error from a permanent fail-stop condition.
#[no_mangle]
pub extern "C" fn vs_auto_is_poisoned() -> bool {
    PLATFORM.read().is_err()
}

// ---------------------------------------------------------------------------
// Additional FFI functions (LIN, FlexRay, UDS, OTA)
// ---------------------------------------------------------------------------

/// LIN frame for FFI submission.
#[repr(C)]
pub struct VsLinFrame {
    pub frame_id: u8,
    pub payload_len: u8,
    pub payload: [u8; 8],
    pub timestamp_us: u64,
}

/// `FlexRay` frame for FFI submission.
#[repr(C)]
pub struct VsFlexRayFrame {
    pub slot_id: u16,
    pub cycle: u8,
    pub payload_len: u16,
    pub payload: [u8; 254],
    pub timestamp_us: u64,
}

/// UDS request for FFI submission.
#[repr(C)]
pub struct VsUdsRequest {
    pub tester_addr: u16,
    pub sid: u8,
    pub payload_len: u16,
    pub payload: [u8; 256],
    pub timestamp_us: u64,
}

/// UDS decision result for FFI.
#[repr(C)]
pub struct VsUdsDecision {
    /// 0 = Forward, 1 = Block, 2 = Challenge
    pub decision: i32,
    /// Block reason (only valid when decision == 1):
    /// 0 = Unauthorized, 1 = `LockedOut`, 2 = `SessionExpired`,
    /// 3 = `PolicyDenied`, 4 = `SessionsFull`
    pub block_reason: i32,
    /// Challenge seed (only valid when decision == 2).
    pub seed: [u8; 16],
}

/// OTA manifest validation request for FFI.
#[repr(C)]
pub struct VsOtaManifest {
    pub data_len: u32,
    pub data: [u8; 4096],
    pub expected_hash: [u8; 32],
    pub timestamp_us: u64,
}

/// Submit a LIN frame for anomaly detection.
///
/// # Safety
///
/// `frame` must point to a valid `VsLinFrame`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_submit_lin_frame(frame: *const VsLinFrame) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if frame.is_null() {
            return VsResult::invalid_arg();
        }
        if (frame as usize) % core::mem::align_of::<VsLinFrame>() != 0 {
            return VsResult::misaligned();
        }

        let f = unsafe { &*frame };

        let payload_len = f.payload_len as usize;
        if payload_len > 8 {
            return VsResult::invalid_arg();
        }

        {
            let Ok(mut limiter) = LIN_RATE_LIMITER.lock() else {
                return VsResult::internal();
            };
            if !limiter.try_consume(monotonic_now_us()) {
                return VsResult::rate_limited();
            }
        }

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => {
                match platform.submit_lin_frame(
                    f.frame_id,
                    &f.payload[..payload_len],
                    f.timestamp_us,
                ) {
                    Ok(()) => VsResult::ok(),
                    Err(_) => VsResult::invalid_arg(),
                }
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Submit a `FlexRay` frame for anomaly detection.
///
/// # Safety
///
/// `frame` must point to a valid `VsFlexRayFrame`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_submit_flexray_frame(frame: *const VsFlexRayFrame) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if frame.is_null() {
            return VsResult::invalid_arg();
        }
        if (frame as usize) % core::mem::align_of::<VsFlexRayFrame>() != 0 {
            return VsResult::misaligned();
        }

        let f = unsafe { &*frame };

        let payload_len = f.payload_len as usize;
        if payload_len > 254 {
            return VsResult::invalid_arg();
        }

        {
            let Ok(mut limiter) = FLEXRAY_RATE_LIMITER.lock() else {
                return VsResult::internal();
            };
            if !limiter.try_consume(monotonic_now_us()) {
                return VsResult::rate_limited();
            }
        }

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => {
                match platform.submit_flexray_frame(
                    f.slot_id,
                    f.cycle,
                    &f.payload[..payload_len],
                    f.timestamp_us,
                ) {
                    Ok(()) => VsResult::ok(),
                    Err(_) => VsResult::invalid_arg(),
                }
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Process a UDS diagnostic request and return the gateway decision.
///
/// # Safety
///
/// `request` must point to a valid `VsUdsRequest`.
/// `decision_out` must point to a valid, writable `VsUdsDecision`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_uds_request(
    request: *const VsUdsRequest,
    decision_out: *mut VsUdsDecision,
) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if request.is_null() || decision_out.is_null() {
            return VsResult::invalid_arg();
        }
        if (request as usize) % core::mem::align_of::<VsUdsRequest>() != 0 {
            return VsResult::misaligned();
        }
        if (decision_out as usize) % core::mem::align_of::<VsUdsDecision>() != 0 {
            return VsResult::misaligned();
        }

        let req = unsafe { &*request };
        let payload_len = (req.payload_len as usize).min(256);

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => {
                let decision = platform.diag_gateway_mut().receive_uds_request(
                    req.tester_addr,
                    req.sid,
                    &req.payload[..payload_len],
                    req.timestamp_us,
                );

                let out = match decision {
                    vs_diag_gateway::DiagDecision::Forward => VsUdsDecision {
                        decision: 0,
                        block_reason: 0,
                        seed: [0u8; 16],
                    },
                    vs_diag_gateway::DiagDecision::Block(reason) => {
                        let reason_code = match reason {
                            vs_diag_gateway::BlockReason::Unauthorized => 0,
                            vs_diag_gateway::BlockReason::LockedOut => 1,
                            vs_diag_gateway::BlockReason::SessionExpired => 2,
                            vs_diag_gateway::BlockReason::PolicyDenied => 3,
                            vs_diag_gateway::BlockReason::SessionsFull => 4,
                        };
                        VsUdsDecision {
                            decision: 1,
                            block_reason: reason_code,
                            seed: [0u8; 16],
                        }
                    }
                    vs_diag_gateway::DiagDecision::Challenge(challenge) => VsUdsDecision {
                        decision: 2,
                        block_reason: 0,
                        seed: challenge.seed,
                    },
                };

                unsafe { decision_out.write(out) };
                VsResult::ok()
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Validate an OTA update manifest hash.
///
/// # Safety
///
/// `manifest` must point to a valid `VsOtaManifest`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_auto_validate_ota_manifest(manifest: *const VsOtaManifest) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if manifest.is_null() {
            return VsResult::invalid_arg();
        }
        if (manifest as usize) % core::mem::align_of::<VsOtaManifest>() != 0 {
            return VsResult::misaligned();
        }

        let m = unsafe { &*manifest };
        let data_len = (m.data_len as usize).min(4096);

        let Ok(mut guard) = PLATFORM.write() else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => {
                match platform.validate_ota_manifest(
                    &m.data[..data_len],
                    &m.expected_hash,
                    m.timestamp_us,
                ) {
                    Ok(()) => VsResult::ok(),
                    Err(_) => VsResult {
                        code: VS_ERR_INTEGRITY_FAILURE,
                    },
                }
            }
            None => VsResult::not_initialized(),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes FFI lifecycle tests to prevent concurrent access to the
    /// global `PLATFORM` singleton. All tests that access PLATFORM must
    /// acquire this lock to prevent state pollution.
    static FFI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// FFI tests use a global `PLATFORM` singleton and must not run in
    /// parallel. This single test function exercises the full lifecycle
    /// sequentially: init, health check, double-init rejection, shutdown,
    /// and shutdown-when-not-initialized.
    ///
    /// Runs on an 8 MiB stack thread because `AutomotiveShield` is too
    /// large for the default test thread stack.
    #[test]
    fn auto_ffi_lifecycle() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                auto_ffi_lifecycle_inner();
            })
            .expect("spawn thread");
        handle.join().expect("thread panicked");
    }

    fn auto_ffi_lifecycle_inner() {
        // Ensure clean state — shutdown is a no-op if not initialized.
        let _ = vs_auto_platform_shutdown();

        // 1. Init succeeds.
        let r = vs_auto_platform_init();
        assert_eq!(r.code, VS_OK);

        // 2. Double init is rejected.
        let r = vs_auto_platform_init();
        assert_eq!(r.code, VS_ERR_ALREADY_INITIALIZED);

        // 3. Health check after init — all subsystems ready (0).
        let mut health = core::mem::MaybeUninit::<VsHealthAuto>::uninit();
        let r = unsafe { vs_auto_get_health(health.as_mut_ptr()) };
        assert_eq!(r.code, VS_OK, "vs_auto_get_health must succeed after init");

        // SAFETY: `vs_auto_get_health` returned VS_OK, which is the contract
        // guaranteeing that the output pointer was fully written.  We verified
        // this above; `assume_init()` is safe here.
        let health = if r.code == VS_OK {
            unsafe { health.assume_init() }
        } else {
            panic!(
                "vs_auto_get_health failed (code {}); health struct is not initialized",
                r.code
            );
        };
        assert_eq!(health.crypto, 0);
        assert_eq!(health.signal_ids, 0);
        assert_eq!(health.v2x, 0);
        assert_eq!(health.diag_gateway, 0);

        // 3b. Input validation while initialized.
        // LIN frame with payload > 8 bytes.
        {
            let frame = VsLinFrame {
                frame_id: 0x10,
                payload_len: 9,
                payload: [0u8; 8],
                timestamp_us: 1_000,
            };
            let r = unsafe { vs_auto_submit_lin_frame(&raw const frame) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
        }
        // FlexRay frame with payload > 254 bytes.
        {
            let frame = VsFlexRayFrame {
                slot_id: 1,
                cycle: 0,
                payload_len: 255,
                payload: [0u8; 254],
                timestamp_us: 1_000,
            };
            let r = unsafe { vs_auto_submit_flexray_frame(&raw const frame) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
        }
        // CAN frame with invalid standard ID (> 0x7FF).
        {
            let frame = VsCanFrame {
                id: 0x800,
                dlc: 1,
                data: [0u8; 64],
                is_extended: 0,
                is_fd: 0,
                timestamp_us: 1_000,
            };
            let r = unsafe { vs_auto_submit_can_frame(&raw const frame) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
        }
        // CAN frame with invalid DLC (> 8 for classic CAN).
        {
            let frame = VsCanFrame {
                id: 0x100,
                dlc: 9,
                data: [0u8; 64],
                is_extended: 0,
                is_fd: 0,
                timestamp_us: 1_000,
            };
            let r = unsafe { vs_auto_submit_can_frame(&raw const frame) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
        }
        // Ethernet packet with payload > 1500 bytes.
        {
            let packet = VsEthPacket {
                src_mac: [0u8; 6],
                dst_mac: [0u8; 6],
                ethertype: 0x0800,
                vlan_id: 0,
                has_vlan: 0,
                padding: 0,
                dst_port: 0,
                has_dst_port: 0,
                payload_len: 1501,
                payload: [0u8; 1500],
                timestamp_us: 1_000,
            };
            let r = unsafe { vs_auto_submit_eth_packet(&raw const packet) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
        }

        // 4. Shutdown succeeds.
        let r = vs_auto_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        // 5. Shutdown when not initialized returns error.
        let r = vs_auto_platform_shutdown();
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        // 6. Health check when not initialized returns error.
        let mut health2 = core::mem::MaybeUninit::<VsHealthAuto>::uninit();
        let r = unsafe { vs_auto_get_health(health2.as_mut_ptr()) };
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        // 7. Null pointer checks.
        let r = unsafe { vs_auto_get_health(core::ptr::null_mut()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        let r = unsafe { vs_auto_submit_can_frame(core::ptr::null()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);
    }

    // ---- TokenBucket unit tests ----

    #[test]
    fn token_bucket_initial_capacity() {
        let mut bucket = TokenBucket::new(10, 5);
        // Should be able to consume initial capacity tokens at time 0.
        for _ in 0..10 {
            assert!(bucket.try_consume(0));
        }
        // 11th should fail.
        assert!(!bucket.try_consume(0));
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(10, 5); // 5 tokens/sec
                                                  // Drain all tokens.
        for _ in 0..10 {
            assert!(bucket.try_consume(0));
        }
        assert!(!bucket.try_consume(0));

        // After 1 second, 5 tokens should be available.
        assert!(bucket.try_consume(1_000_000));
    }

    #[test]
    fn token_bucket_backward_time_does_not_refill() {
        let mut bucket = TokenBucket::new(10, 5);
        // Consume some at time 1_000_000.
        for _ in 0..10 {
            assert!(bucket.try_consume(1_000_000));
        }
        // Backward time jump should not refill.
        assert!(!bucket.try_consume(500_000));
    }

    #[test]
    fn token_bucket_large_forward_jump_capped() {
        let mut bucket = TokenBucket::new(100, 50); // capacity 100, rate 50/sec
                                                    // Drain all tokens at time 0.
        for _ in 0..100 {
            assert!(bucket.try_consume(0));
        }
        assert!(!bucket.try_consume(0));

        // Large forward jump (10 seconds). With the 2-second cap, only
        // 2 * 50 = 100 tokens should be refilled (capped to capacity).
        // Without the cap, 500 tokens would be computed (but still capped
        // to capacity). The cap prevents burst after long idle periods.
        assert!(bucket.try_consume(10_000_000));
    }

    #[test]
    fn token_bucket_reset() {
        let mut bucket = TokenBucket::new(10, 5);
        for _ in 0..10 {
            assert!(bucket.try_consume(0));
        }
        assert!(!bucket.try_consume(0));

        bucket.reset();
        // After reset, full capacity available again.
        for _ in 0..10 {
            assert!(bucket.try_consume(0));
        }
    }

    #[test]
    fn token_bucket_fractional_second_refill() {
        let mut bucket = TokenBucket::new(100, 50_000); // 50K tokens/sec
                                                        // Drain all.
        for _ in 0..100 {
            assert!(bucket.try_consume(0));
        }
        assert!(!bucket.try_consume(0));

        // After 1ms (1000us), should get 50 tokens (50000 * 0.001).
        // Actually: remainder_us=1000, refill = 1000 * 50000 / 1000000 = 50
        assert!(bucket.try_consume(1_000));
    }

    // ---- New FFI function null-pointer tests ----

    #[test]
    fn lin_frame_null_pointer() {
        let r = unsafe { vs_auto_submit_lin_frame(core::ptr::null()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);
    }

    #[test]
    fn flexray_frame_null_pointer() {
        let r = unsafe { vs_auto_submit_flexray_frame(core::ptr::null()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);
    }

    #[test]
    fn uds_request_null_pointer() {
        let r = unsafe { vs_auto_uds_request(core::ptr::null(), core::ptr::null_mut()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);
    }

    #[test]
    fn ota_manifest_null_pointer() {
        let r = unsafe { vs_auto_validate_ota_manifest(core::ptr::null()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);
    }

    #[test]
    fn lin_frame_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                // Ensure platform is shut down.
                let _ = vs_auto_platform_shutdown();

                let frame = VsLinFrame {
                    frame_id: 0x10,
                    payload_len: 4,
                    payload: [1, 2, 3, 4, 0, 0, 0, 0],
                    timestamp_us: 1_000,
                };
                let r = unsafe { vs_auto_submit_lin_frame(&raw const frame) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    #[test]
    fn flexray_frame_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                let frame = VsFlexRayFrame {
                    slot_id: 1,
                    cycle: 0,
                    payload_len: 4,
                    payload: [0u8; 254],
                    timestamp_us: 1_000,
                };
                let r = unsafe { vs_auto_submit_flexray_frame(&raw const frame) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    #[test]
    fn ota_manifest_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                let manifest = VsOtaManifest {
                    data_len: 4,
                    data: [0u8; 4096],
                    expected_hash: [0u8; 32],
                    timestamp_us: 1_000,
                };
                let r = unsafe { vs_auto_validate_ota_manifest(&raw const manifest) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    // ---- Pointer alignment validation tests ----

    /// Helper: create a misaligned pointer from an aligned buffer.
    /// Returns a pointer offset by 1 byte from the start of a sufficiently
    /// large allocation, which is guaranteed to be misaligned for any type
    /// with alignment > 1.
    fn misaligned_ptr<T>(buf: &[u8]) -> *const T {
        let base = buf.as_ptr();
        let aligned_addr = base as usize;
        // Offset by 1 byte to break alignment for any repr(C) struct.
        let misaligned = aligned_addr + 1;
        misaligned as *const T
    }

    fn misaligned_ptr_mut<T>(buf: &mut [u8]) -> *mut T {
        let base = buf.as_mut_ptr();
        let aligned_addr = base as usize;
        let misaligned = aligned_addr + 1;
        misaligned as *mut T
    }

    #[test]
    fn can_frame_misaligned_pointer() {
        let buf = [0u8; 256];
        let ptr: *const VsCanFrame = misaligned_ptr(&buf);
        let r = unsafe { vs_auto_submit_can_frame(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn eth_packet_misaligned_pointer() {
        // VsEthPacket is large, allocate on the heap.
        let buf = vec![0u8; core::mem::size_of::<VsEthPacket>() + 16];
        let ptr: *const VsEthPacket = misaligned_ptr(&buf);
        let r = unsafe { vs_auto_submit_eth_packet(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn health_misaligned_pointer() {
        let mut buf = [0u8; 256];
        let ptr: *mut VsHealthAuto = misaligned_ptr_mut(&mut buf);
        let r = unsafe { vs_auto_get_health(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn lin_frame_misaligned_pointer() {
        let buf = [0u8; 64];
        let ptr: *const VsLinFrame = misaligned_ptr(&buf);
        let r = unsafe { vs_auto_submit_lin_frame(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn flexray_frame_misaligned_pointer() {
        let buf = [0u8; 512];
        let ptr: *const VsFlexRayFrame = misaligned_ptr(&buf);
        let r = unsafe { vs_auto_submit_flexray_frame(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn uds_request_misaligned_pointer() {
        let buf = [0u8; 512];
        let ptr: *const VsUdsRequest = misaligned_ptr(&buf);
        let mut decision = core::mem::MaybeUninit::<VsUdsDecision>::uninit();
        let r = unsafe { vs_auto_uds_request(ptr, decision.as_mut_ptr()) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn uds_decision_misaligned_pointer() {
        let req = VsUdsRequest {
            tester_addr: 0x100,
            sid: 0x27,
            payload_len: 0,
            payload: [0u8; 256],
            timestamp_us: 1_000,
        };
        let mut buf = [0u8; 128];
        let out_ptr: *mut VsUdsDecision = misaligned_ptr_mut(&mut buf);
        let r = unsafe { vs_auto_uds_request(&raw const req, out_ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    #[test]
    fn ota_manifest_misaligned_pointer() {
        // VsOtaManifest is large, allocate on the heap.
        let buf = vec![0u8; core::mem::size_of::<VsOtaManifest>() + 16];
        let ptr: *const VsOtaManifest = misaligned_ptr(&buf);
        let r = unsafe { vs_auto_validate_ota_manifest(ptr) };
        assert_eq!(r.code, VS_ERR_MISALIGNED);
    }

    // ---- TokenBucket refill precision test ----

    #[test]
    fn token_bucket_refill_precision() {
        let mut bucket = TokenBucket::new(10, 2); // capacity=10, 2 tokens/sec
                                                  // Consume all tokens.
        for _ in 0..10 {
            assert!(bucket.try_consume(1_000_000));
        }
        assert!(!bucket.try_consume(1_000_000));
        // After 500ms (at t=1.5s), should have 1 token (2 * 0.5 = 1).
        assert!(bucket.try_consume(1_500_000));
        // No more tokens available after consuming that one.
        assert!(!bucket.try_consume(1_500_000));
    }

    #[test]
    fn token_bucket_very_low_rate_accumulates() {
        // Rate of 1 token/sec: sub-second calls should accumulate remainder
        // and eventually grant a token.
        let mut bucket = TokenBucket::new(5, 1);
        // Drain all tokens at time 0.
        for _ in 0..5 {
            assert!(bucket.try_consume(0));
        }
        assert!(!bucket.try_consume(0));

        // At 999ms: accumulated 999_000 * 1 = 999_000 us, not enough for 1 token.
        assert!(!bucket.try_consume(999_000));
        // At 1000ms: accumulated remainder + 1000us * 1 = 999_000 + 1_000 = 1_000_000,
        // which yields exactly 1 token.
        assert!(bucket.try_consume(1_000_000));
        assert!(!bucket.try_consume(1_000_000));
    }

    #[test]
    fn token_bucket_does_not_exceed_capacity_on_refill() {
        let mut bucket = TokenBucket::new(5, 100); // capacity=5, 100 tokens/sec
                                                   // Drain all.
        for _ in 0..5 {
            assert!(bucket.try_consume(0));
        }
        // After 1 second: 100 tokens computed, but capped to capacity=5.
        for _ in 0..5 {
            assert!(bucket.try_consume(1_000_000));
        }
        // 6th should fail — capacity is 5.
        assert!(!bucket.try_consume(1_000_000));
    }

    // ---- FFI not-initialized tests for CAN, ETH, UDS ----

    #[test]
    fn can_frame_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                let frame = VsCanFrame {
                    id: 0x100,
                    dlc: 8,
                    data: [0u8; 64],
                    is_extended: 0,
                    is_fd: 0,
                    timestamp_us: 1_000,
                };
                let r = unsafe { vs_auto_submit_can_frame(&raw const frame) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    #[test]
    fn eth_packet_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                let packet = VsEthPacket {
                    src_mac: [0u8; 6],
                    dst_mac: [0u8; 6],
                    ethertype: 0x0800,
                    vlan_id: 0,
                    has_vlan: 0,
                    padding: 0,
                    dst_port: 0,
                    has_dst_port: 0,
                    payload_len: 4,
                    payload: [0u8; 1500],
                    timestamp_us: 1_000,
                };
                let r = unsafe { vs_auto_submit_eth_packet(&raw const packet) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    #[test]
    fn uds_request_not_initialized() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                let req = VsUdsRequest {
                    tester_addr: 0x100,
                    sid: 0x27,
                    payload_len: 0,
                    payload: [0u8; 256],
                    timestamp_us: 1_000,
                };
                let mut decision = core::mem::MaybeUninit::<VsUdsDecision>::uninit();
                let r = unsafe { vs_auto_uds_request(&raw const req, decision.as_mut_ptr()) };
                assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }

    // Input validation tests are in auto_ffi_lifecycle_inner (step 3b)
    // to avoid global singleton race conditions with parallel tests.

    // ---- ffi_guard panic recovery test ----

    #[test]
    fn ffi_guard_catches_panic_and_returns_internal() {
        let before = PANIC_COUNT.load(Ordering::Relaxed);

        let result = ffi_guard(|| {
            panic!("intentional test panic");
        });

        assert_eq!(result.code, VS_ERR_INTERNAL);
        let after = PANIC_COUNT.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn ffi_guard_passes_through_ok_result() {
        let result = ffi_guard(VsResult::ok);
        assert_eq!(result.code, VS_OK);
    }

    #[test]
    fn ffi_guard_passes_through_error_result() {
        let result = ffi_guard(VsResult::invalid_arg);
        assert_eq!(result.code, VS_ERR_INVALID_ARG);
    }

    // ---- status_to_i32 helper test ----

    #[test]
    fn status_to_i32_mapping() {
        assert_eq!(status_to_i32(SubsystemStatus::Ready), 0);
        assert_eq!(status_to_i32(SubsystemStatus::Degraded), 1);
        assert_eq!(status_to_i32(SubsystemStatus::Failed), 2);
        assert_eq!(status_to_i32(SubsystemStatus::NotInitialized), 3);
    }

    // ---- Stub detection tests ----

    #[test]
    fn stub_crypto_detection() {
        // In test builds (non-production), this should return true.
        assert!(vs_auto_is_stub_crypto());
    }

    #[test]
    fn stub_init_flag_lifecycle() {
        let _guard = FFI_TEST_LOCK.lock().expect("lock poisoned");
        let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
        let handle = builder
            .spawn(|| {
                let _ = vs_auto_platform_shutdown();

                // Before init, flag should be false.
                assert!(!vs_auto_is_stub_initialized());

                let r = vs_auto_platform_init();
                assert_eq!(r.code, VS_OK);

                // After init, flag should be true.
                assert!(vs_auto_is_stub_initialized());

                let _ = vs_auto_platform_shutdown();

                // After shutdown, flag should be false again.
                assert!(!vs_auto_is_stub_initialized());
            })
            .expect("spawn");
        handle.join().expect("thread panicked");
    }
}
