// SPDX-License-Identifier: Apache-2.0
//! C FFI layer for the `Craton Shield` platform.
//!
//! This crate exposes a C-compatible API for initializing, ticking,
//! submitting traffic, querying health, and shutting down the
//! `Craton Shield` runtime.
//!
//! # Panic strategy
//!
//! All `extern "C"` functions are wrapped in [`catch_unwind`] to prevent
//! unwinding across the FFI boundary, which is undefined behaviour.
//! **This only works when the panic strategy is `unwind` (the default).**
//! If the crate is compiled with `panic = "abort"`, the `catch_unwind`
//! guards are no-ops and a panic will abort the process immediately.
//!
//! **Important:** The workspace root `Cargo.toml` sets `panic = "abort"` in
//! the `[profile.release]` section for binary size optimization. When
//! building `vs-ffi` as a shared library for C integration, override this
//! in your downstream `Cargo.toml`:
//!
//! ```toml
//! [profile.release.package.vs-ffi]
//! panic = "unwind"
//! ```
//!
//! Alternatively, use the `release-safe` profile which inherits from release
//! but can be configured with `panic = "unwind"`.
//!
//! # Lock ordering
//!
//! The crate uses several `Mutex`-protected statics. To avoid deadlocks,
//! all code must acquire locks in the following order and **never nest**
//! them:
//!
//! 1. `GLOBAL_RATE_LIMITER`, `CAN_RATE_LIMITER`, or `ETH_RATE_LIMITER`
//!    (mutually independent — never held simultaneously)
//! 2. `PLATFORM`
//!
//! No function holds more than one lock at a time.

// Most FFI functions and helpers are gated behind the `mock-hsm` or
// `production` feature.  Without either feature selected the helpers
// compile but are not reachable, so we suppress dead-code warnings here.
#![cfg_attr(
    not(any(feature = "mock-hsm", feature = "production")),
    allow(dead_code, unused_imports)
)]
// Every Rust-side public item (the `extern "C"` C ABI entry points, the
// `#[repr(C)]` types, the `VS_ERR_*` and `VS_ABI_VERSION` constants)
// must carry a `///` doc comment. C consumers can only reason about
// behaviour at the FFI boundary from these docs (and the cratonshield.h
// header generated from them via cbindgen), so an undocumented public
// item here is effectively an unspecified ABI contract.
#![deny(missing_docs)]

// F-04: in non-test builds where debug_assertions is disabled, the crate
// must be built with `--features production`.  Without it the platform
// uses a cryptographically insecure SoftwareCryptoProvider.
//
// NOTE: `debug_assertions` is controlled independently of the release
// profile.  The additional runtime check inside `vs_platform_init` covers
// the bypass vector where `debug_assertions = false` is set in a dev profile.
#[cfg(all(not(feature = "production"), not(test), not(debug_assertions)))]
compile_error!(
    "The `vs-ffi` crate must be compiled with `--features production` in release builds. \
     Without it, the platform initializes with a SoftwareCryptoProvider (mock-hsm) \
     that provides deterministic, cryptographically insecure operations. \
     (F-04: also guarded at runtime inside vs_platform_init.)"
);

// Safety: the FFI crate relies on catch_unwind to prevent panics from
// unwinding across the C ABI boundary.  With panic = "abort", catch_unwind
// becomes a no-op and panics will abort the process immediately.
//
// Note: the `panic = "abort"` cfg predicate requires nightly Rust.
// For stable toolchains, use the `release-safe` profile which sets
// `panic = "unwind"`. A runtime check below provides a fallback guard.
#[cfg(all(not(test), panic = "abort"))]
compile_error!(
    "The `vs-ffi` crate must be compiled with `panic = \"unwind\"` to ensure \
     `catch_unwind` guards work correctly at the FFI boundary. Add \
     `[profile.release.package.vs-ffi] panic = \"unwind\"` to your Cargo.toml."
);

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(feature = "mock-hsm")]
use vs_crypto::SoftwareCryptoProvider;
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, PlatformHealth, SubsystemStatus,
};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// CryptoProvider selection
// ---------------------------------------------------------------------------
//
// Non-production builds use the mock-hsm `SoftwareCryptoProvider` from
// `vs-crypto`. This provides real (but deterministic / insecure) crypto
// operations suitable for integration testing.
//
// Production builds must supply a concrete `CryptoProvider` implementation
// via the `vs_platform_init_with_crypto` FFI entry point. The
// `#[cfg(feature = "production")]` code path does not provide a default
// provider — the integrator must wire one in.

// ---------------------------------------------------------------------------
// FFI result codes
// ---------------------------------------------------------------------------

/// Result type returned by every FFI function.
///
/// `code == 0` (`VS_OK`) indicates success; any negative value is one of
/// the `VS_ERR_*` constants below. Returned by value because `#[repr(C)]`
/// guarantees a 4-byte layout identical to a bare `int32_t` on every
/// supported target, so the FFI ABI is equivalent to `int32_t (*)()`.
#[repr(C)]
#[must_use]
pub struct VsResult {
    /// Result code: `VS_OK` (0) on success, one of the `VS_ERR_*`
    /// constants on failure.
    pub code: i32,
}

/// Operation completed successfully.
pub const VS_OK: i32 = 0;
/// A pointer argument was null or otherwise invalid.
pub const VS_ERR_INVALID_ARG: i32 = -1;
/// The platform has not been initialized yet.
pub const VS_ERR_NOT_INITIALIZED: i32 = -2;
/// An internal error occurred (e.g. mutex poisoned, unexpected failure).
pub const VS_ERR_INTERNAL: i32 = -3;
/// The rate limiter blocked the request (too many events).
pub const VS_ERR_RATE_LIMITED: i32 = -4;
/// The platform has already been initialized.
pub const VS_ERR_ALREADY_INITIALIZED: i32 = -5;
/// A cryptographic operation failed.
pub const VS_ERR_CRYPTO: i32 = -6;
/// A resource limit was reached (e.g., rule table full).
pub const VS_ERR_RESOURCE_EXHAUSTED: i32 = -7;
/// A security policy violation was detected.
pub const VS_ERR_POLICY_VIOLATION: i32 = -8;
/// Authentication failed.
pub const VS_ERR_AUTH_FAILURE: i32 = -9;
/// Operation timed out.
pub const VS_ERR_TIMEOUT: i32 = -10;
/// The requested item was not found.
pub const VS_ERR_NOT_FOUND: i32 = -11;
/// A key has expired.
pub const VS_ERR_KEY_EXPIRED: i32 = -12;
/// A key has been revoked.
pub const VS_ERR_KEY_REVOKED: i32 = -13;
/// Internal state is corrupted after a panic; shutdown and re-init required.
pub const VS_ERR_STATE_CORRUPTED: i32 = -14;

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
    const fn state_corrupted() -> Self {
        Self {
            code: VS_ERR_STATE_CORRUPTED,
        }
    }
    #[allow(unreachable_patterns)]
    const fn from_vs_error(e: VsError) -> Self {
        match e {
            VsError::NotInitialized => Self::not_initialized(),
            VsError::CryptoError => Self {
                code: VS_ERR_CRYPTO,
            },
            VsError::ResourceExhausted => Self {
                code: VS_ERR_RESOURCE_EXHAUSTED,
            },
            VsError::PolicyViolation => Self {
                code: VS_ERR_POLICY_VIOLATION,
            },
            VsError::AuthenticationFailure => Self {
                code: VS_ERR_AUTH_FAILURE,
            },
            VsError::Timeout => Self {
                code: VS_ERR_TIMEOUT,
            },
            VsError::InvalidInput | VsError::InvalidConfig => Self::invalid_arg(),
            VsError::NotFound => Self {
                code: VS_ERR_NOT_FOUND,
            },
            VsError::KeyExpired => Self {
                code: VS_ERR_KEY_EXPIRED,
            },
            VsError::KeyRevoked => Self {
                code: VS_ERR_KEY_REVOKED,
            },
            VsError::BusError
            | VsError::IntegrityFailure
            | VsError::StorageError
            | VsError::OverlappingRegion => Self::internal(),
            // `VsError` is `#[non_exhaustive]`. Unknown future variants fold
            // to a generic internal error so the FFI surface stays stable.
            _ => Self::internal(),
        }
    }
}

// ---------------------------------------------------------------------------
// FFI-safe CAN frame
// ---------------------------------------------------------------------------

/// CAN / CAN-FD frame as seen by the C caller.
///
/// `is_extended` and `is_fd` use `u8` instead of `bool` for FFI safety:
/// C callers may pass any non-zero value for "true", but Rust's `bool`
/// in `#[repr(C)]` requires exactly 0 or 1, making other values UB.
#[repr(C)]
pub struct VsCanFrame {
    /// CAN arbitration ID. 11-bit (≤ `0x7FF`) for standard frames or
    /// 29-bit (≤ `0x1FFF_FFFF`) when `is_extended != 0`.
    pub id: u32,
    /// Data length code. Classic CAN: 0–8 bytes. CAN-FD: encodes 0–64
    /// bytes via the ISO 11898-1 DLC table.
    pub dlc: u8,
    /// Frame payload. The first `dlc_to_len(dlc)` bytes are valid; the
    /// remainder is zero-padded by the FFI shim before forwarding.
    pub data: [u8; 64],
    /// Non-zero if this is a 29-bit extended-format frame.
    pub is_extended: u8,
    /// Non-zero if this is a CAN-FD frame (extended payload up to 64
    /// bytes, BRS optional).
    pub is_fd: u8,
    /// Caller-supplied monotonic timestamp in microseconds. Used as the
    /// arrival time for IDS and anomaly correlation.
    pub timestamp_us: u64,
}

// ---------------------------------------------------------------------------
// FFI-safe health struct
// ---------------------------------------------------------------------------

/// Subsystem health snapshot exposed to C callers.
///
/// Each field encodes a [`SubsystemStatus`] as an `i32`:
///   0 = Ready, 1 = Degraded, 2 = Failed, 3 = `NotInitialized`.
#[repr(C)]
pub struct VsHealth {
    /// Status of the `CryptoProvider` subsystem.
    pub crypto: i32,
    /// Status of the key-manager subsystem.
    pub key_manager: i32,
    /// Status of the secure-boot verifier.
    pub secure_boot: i32,
    /// Status of the event-logger pipeline.
    pub event_logger: i32,
    /// Status of the CAN-bus monitor.
    pub can_monitor: i32,
    /// Status of the Ethernet monitor.
    pub eth_monitor: i32,
    /// Status of the IDS / intrusion-detection engine.
    pub ids_engine: i32,
    /// Status of the network firewall.
    pub firewall: i32,
    /// Status of the OTA validator.
    pub ota_validator: i32,
    /// Status of the anomaly detector.
    pub anomaly: i32,
    /// Status of the integrity monitor.
    pub integrity: i32,
    /// Status of the policy engine.
    pub policy_engine: i32,
    /// Status of the storage subsystem.
    pub storage: i32,
    /// Status of the hardware abstraction layer.
    pub hal: i32,
}

// ---------------------------------------------------------------------------
// ABI stability guards — must match cratonshield.h _Static_assert values
// ---------------------------------------------------------------------------

const _: () = assert!(
    core::mem::size_of::<VsResult>() == 4,
    "VsResult size mismatch with C header"
);
const _: () = assert!(
    core::mem::size_of::<VsCanFrame>() == 80,
    "VsCanFrame size mismatch with C header"
);
const _: () = assert!(
    core::mem::size_of::<VsHealth>() == 56,
    "VsHealth size mismatch with C header"
);

// ---------------------------------------------------------------------------
// ABI version
// ---------------------------------------------------------------------------

/// Packed ABI version: `(major << 16) | (minor << 8) | patch`.
///
/// This is the single source of truth for the Craton Shield core C ABI
/// version.  The C header (`core/include/cratonshield.h`) defines
/// `#define VS_ABI_VERSION 0x00010000` and the build will fail to compile
/// if these values diverge (see the `const _: ()` assertion below and the
/// `_Static_assert` in the header).
///
/// ## Versioning policy (see `ABI.md` at workspace root)
///
/// * **Major bump** — Breaking ABI change. Pre-existing C consumers that
///   linked against the previous major version MUST refuse to dispatch.
///   Examples: struct layout change, function signature change, removal
///   of an exported symbol.
/// * **Minor bump** — Backward-compatible additions (new functions, new
///   trailing struct fields when explicitly reserved).
/// * **Patch bump** — Bug fixes and clarifications that do not change
///   layout or semantics.
///
/// A downstream C consumer MUST call [`vs_abi_version`] at init and
/// refuse to dispatch when the returned value's major component does not
/// match the `VS_ABI_VERSION` constant from the header it was compiled
/// against.
pub const VS_ABI_VERSION: u32 = 0x0001_0000;

// Single-source-of-truth assertion: the constant baked into the Rust
// crate MUST match the value documented in cratonshield.h.  If you bump
// one you MUST bump the other in the same commit.
const _: () = assert!(
    VS_ABI_VERSION == 0x0001_0000,
    "VS_ABI_VERSION must match cratonshield.h #define VS_ABI_VERSION"
);

/// Return the packed ABI version of the linked `vs-ffi` library.
///
/// Downstream C consumers SHOULD call this immediately after loading the
/// shared library and SHOULD refuse to dispatch any further `vs_*` call
/// if `(vs_abi_version() >> 16) != (VS_ABI_VERSION >> 16)` — i.e. the
/// major component disagrees with the header the consumer was compiled
/// against.
///
/// Encoding: `(major << 16) | (minor << 8) | patch`.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_abi_version() -> u32 {
    VS_ABI_VERSION
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [`SubsystemStatus`] to its C-side integer encoding.
fn status_to_i32(s: SubsystemStatus) -> i32 {
    match s {
        SubsystemStatus::Ready => 0,
        SubsystemStatus::Degraded => 1,
        SubsystemStatus::Failed => 2,
        SubsystemStatus::NotInitialized => 3,
    }
}

/// Convert a [`PlatformHealth`] to its FFI-safe representation.
fn health_to_ffi(h: &PlatformHealth) -> VsHealth {
    VsHealth {
        crypto: status_to_i32(h.crypto),
        key_manager: status_to_i32(h.key_manager),
        secure_boot: status_to_i32(h.secure_boot),
        event_logger: status_to_i32(h.event_logger),
        can_monitor: status_to_i32(h.can_monitor),
        eth_monitor: status_to_i32(h.eth_monitor),
        ids_engine: status_to_i32(h.ids_engine),
        firewall: status_to_i32(h.firewall),
        ota_validator: status_to_i32(h.ota_validator),
        anomaly: status_to_i32(h.anomaly),
        integrity: status_to_i32(h.integrity),
        policy_engine: status_to_i32(h.policy_engine),
        storage: status_to_i32(h.storage),
        hal: status_to_i32(h.hal),
    }
}

/// Return a monotonic timestamp in microseconds.
///
/// Uses `std::time::Instant` anchored to the first call, so the clock
/// cannot be rewound by an attacker adjusting `SystemTime`.
///
/// # Cost
///
/// Each call is roughly ~30 ns on vDSO-equipped Linux (`CLOCK_MONOTONIC`
/// resolved without a syscall) and a few hundred nanoseconds on platforms
/// without vDSO support. The `OnceLock` epoch is hot after the first call.
/// For sustained CAN traffic above ~50 kHz, consider batching frames and
/// resolving a single timestamp for the batch rather than calling this
/// once per frame.
fn monotonic_now_us() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    // Saturate to u64::MAX instead of silently truncating u128.
    let micros = epoch.elapsed().as_micros();
    if micros > u64::MAX as u128 {
        u64::MAX
    } else {
        micros as u64
    }
}

// ---------------------------------------------------------------------------
// Global platform state & Rate Limiting
// ---------------------------------------------------------------------------

/// Non-production builds use the deterministic `SoftwareCryptoProvider`.
/// When `pqc` is also enabled the platform carries a `RustCryptoPqProvider`;
/// otherwise the zero-cost `StubPostQuantumProvider` is used.
#[cfg(all(feature = "mock-hsm", not(feature = "pqc")))]
static PLATFORM: Mutex<Option<CratonShield<SoftwareCryptoProvider>>> = Mutex::new(None);

#[cfg(all(feature = "mock-hsm", feature = "pqc"))]
static PLATFORM: Mutex<
    Option<CratonShield<SoftwareCryptoProvider, vs_crypto::RustCryptoPqProvider>>,
> = Mutex::new(None);

/// Counter of poisoned mutex recoveries for monitoring.
static POISONED_MUTEX_COUNT: AtomicU64 = AtomicU64::new(0);

/// Degraded flag — set after any poisoned mutex recovery.
///
/// Once set, all FFI calls except `vs_platform_shutdown` return
/// `VS_ERR_STATE_CORRUPTED`. A successful shutdown + re-init cycle
/// clears the flag.
static DEGRADED: AtomicBool = AtomicBool::new(false);

/// Return the number of poisoned mutex recoveries since init.
///
/// A non-zero value indicates that a panic corrupted internal state.
/// The platform should be shut down and re-initialized.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_get_poisoned_mutex_count() -> u64 {
    POISONED_MUTEX_COUNT.load(Ordering::Acquire)
}

/// Helper to recover from a poisoned mutex by replacing its contents.
///
/// When a panic is caught by `catch_unwind`, the mutex becomes poisoned.
/// Rather than permanently locking out all subsequent calls, we recover
/// by accepting the (potentially inconsistent) inner value. The platform
/// should be re-initialized after a panic regardless.
///
/// Each recovery increments `POISONED_MUTEX_COUNT` so integrators can
/// detect and respond to internal state corruption.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, ()> {
    match mutex.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            // V7 fix: Track poisoned mutex recoveries so integrators can
            // detect state corruption. This counter is exposed via
            // `vs_get_poisoned_mutex_count()`.
            POISONED_MUTEX_COUNT.fetch_add(1, Ordering::Release);
            // V9 fix: set DEGRADED *before* recovering the guard to close
            // the window where another thread could observe inconsistent
            // state between into_inner() and the DEGRADED flag being set.
            DEGRADED.store(true, Ordering::Release);
            // The platform state may be inconsistent after a panic.
            // Accept the inner value so that shutdown/re-init can proceed,
            // but the DEGRADED flag (set above) ensures no operations run
            // on it.
            Ok(poisoned.into_inner())
        }
    }
}

/// Specialized recovery for the PLATFORM mutex that clears corrupted state.
///
/// After a panic poisons the PLATFORM mutex, the inner `CratonShield` state
/// is potentially corrupt.  This helper recovers the mutex and replaces the
/// inner value with `None`, ensuring no operations run on corrupt state.
/// Only `vs_platform_shutdown` and `vs_platform_init` use this path.
#[cfg(feature = "mock-hsm")]
fn lock_platform_or_clear(
) -> Result<std::sync::MutexGuard<'static, Option<CratonShield<SoftwareCryptoProvider>>>, ()> {
    match PLATFORM.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            POISONED_MUTEX_COUNT.fetch_add(1, Ordering::Release);
            DEGRADED.store(true, Ordering::Release);
            let mut guard = poisoned.into_inner();
            // Clear the potentially corrupted platform state.
            *guard = None;
            Ok(guard)
        }
    }
}

// Production builds: the integrator must supply a real CryptoProvider via
// `vs_platform_init_with_crypto`. This static is intentionally not
// provided — production code must be wired through an enterprise
// CryptoProvider. The `production` feature's compile_error guard at the
// top of `vs-crypto` prevents the mock-hsm from leaking into release.

/// Maximum elapsed time (30 seconds) used for token refill calculation.
///
/// If a VM is suspended and resumed, the elapsed time could be enormous,
/// leading to a full bucket refill and enabling a post-resume burst.
/// Clamping prevents this.
const MAX_STALL_US: u64 = 30_000_000;

struct TokenBucket {
    tokens: u64,
    last_update_us: u64,
    capacity: u64,
    fill_rate_per_sec: u64,
}

impl TokenBucket {
    const fn new(capacity: u64, fill_rate_per_sec: u64) -> Self {
        Self {
            tokens: capacity,
            last_update_us: 0,
            capacity,
            fill_rate_per_sec,
        }
    }

    fn try_consume(&mut self, now_us: u64) -> bool {
        if self.last_update_us == 0 {
            self.last_update_us = now_us;
        } else if now_us > self.last_update_us {
            // V8 fix: clamp elapsed to prevent burst-refill after VM suspend.
            let elapsed = core::cmp::min(now_us - self.last_update_us, MAX_STALL_US);
            let added_tokens = (elapsed as u128 * self.fill_rate_per_sec as u128) / 1_000_000;

            if added_tokens > 0 {
                // Clamp to u64::MAX before casting to prevent silent truncation.
                let clamped = if added_tokens > u64::MAX as u128 {
                    self.capacity
                } else {
                    added_tokens as u64
                };
                self.tokens = core::cmp::min(self.capacity, self.tokens.saturating_add(clamped));

                // V3 fix: snap last_update_us to now_us rather than computing
                // a back-derived consumed_us. The previous approach accumulated
                // rounding error from integer division over long uptimes. Since
                // we already computed how many tokens to add from the elapsed
                // time, snapping to now_us is exact and drift-free. Any
                // fractional tokens are simply deferred to the next call.
                self.last_update_us = now_us;
            }
        }
        // If now_us < last_update_us (clock went backwards), do NOT refill
        // to prevent burst attacks via clock manipulation.

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_update_us = 0;
    }
}

/// Aggregate rate limiter across all protocols.
///
/// Prevents cross-protocol DoS where an attacker floods both CAN and
/// Ethernet simultaneously to exceed the platform's processing budget.
/// The global capacity is intentionally lower than the sum of per-protocol
/// capacities so that combined traffic is bounded.
static GLOBAL_RATE_LIMITER: Mutex<TokenBucket> = Mutex::new(TokenBucket::new(150_000, 75_000));

/// Separate rate limiters per protocol to prevent cross-protocol `DoS`.
static CAN_RATE_LIMITER: Mutex<TokenBucket> = Mutex::new(TokenBucket::new(100_000, 50_000));
static ETH_RATE_LIMITER: Mutex<TokenBucket> = Mutex::new(TokenBucket::new(100_000, 50_000));

/// Maximum Ethernet frame size (jumbo frame limit).
const MAX_ETH_FRAME_LEN: usize = 9216;

/// Counter of panics caught by FFI boundary guards.
///
/// Exposed via [`vs_get_panic_count`] so that integrators can detect
/// unrecoverable internal errors without parsing stderr.
static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

/// Execute `f` inside [`catch_unwind`], incrementing `PANIC_COUNT` on panic.
///
/// Returns `VsResult::internal()` if the closure panics.
fn ffi_guard<F: FnOnce() -> VsResult + std::panic::UnwindSafe>(f: F) -> VsResult {
    catch_unwind(f).unwrap_or_else(|_| {
        PANIC_COUNT.fetch_add(1, Ordering::Release);
        VsResult::internal()
    })
}

/// Return the number of panics caught by FFI boundary guards since init.
///
/// A non-zero value indicates internal errors that should be investigated.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_get_panic_count() -> u64 {
    PANIC_COUNT.load(Ordering::Acquire)
}

/// Return `1` if the platform is in degraded state (after a mutex poison
/// recovery), `0` otherwise.
///
/// When degraded, all FFI calls except `vs_platform_shutdown` return
/// `VS_ERR_STATE_CORRUPTED`. Shut down and re-initialize to clear.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_is_degraded() -> u64 {
    u64::from(DEGRADED.load(Ordering::Acquire))
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Initialize the platform with default configuration.
///
/// Resets per-protocol rate limiters so that a shutdown / re-init cycle
/// starts with a full token budget.
///
/// # Panic strategy requirement
///
/// This function requires `panic = "unwind"` to be set for the `vs-ffi`
/// crate. The FFI boundary relies on [`catch_unwind`] to prevent panics
/// from unwinding across the C ABI (which is undefined behaviour). If
/// the crate is compiled with `panic = "abort"`, `catch_unwind` becomes
/// a no-op and panics will abort the process. A compile-time check
/// catches this on nightly, and a runtime check here verifies that
/// `catch_unwind` is functional on stable toolchains.
///
/// Returns `VS_OK` on success, `VS_ERR_ALREADY_INITIALIZED` if the
/// platform is already running, `VS_ERR_INTERNAL` if `catch_unwind` is
/// non-functional or the mutex is poisoned.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_platform_init() -> VsResult {
    ffi_guard(|| {
        // Runtime guard: verify catch_unwind is functional (complements
        // the compile-time check which requires nightly cfg predicates).
        // If catch_unwind is a no-op (panic = "abort"), we cannot safely
        // guard the FFI boundary, so refuse to initialize.
        let unwind_works = std::panic::catch_unwind(|| {}).is_ok();
        if !unwind_works {
            return VsResult::internal();
        }

        // F-04 runtime guard: refuse to initialize in a non-test context if
        // insecure build features (mock-hsm, pq-software) are compiled in but
        // debug_assertions is OFF.  This covers the edge case where
        // `debug_assertions = false` is set in a dev profile, bypassing the
        // compile_error! guard in vs-crypto.
        #[cfg(not(test))]
        if !cfg!(debug_assertions) && vs_crypto::is_insecure_build() {
            return VsResult::internal();
        }

        if DEGRADED.load(Ordering::Acquire) {
            return VsResult::state_corrupted();
        }
        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        if guard.is_some() {
            return VsResult::already_initialized();
        }

        // Reset rate limiters so a re-init cycle starts with full budgets.
        if let Ok(mut l) = lock_or_recover(&GLOBAL_RATE_LIMITER) {
            l.reset();
        }
        if let Ok(mut l) = lock_or_recover(&CAN_RATE_LIMITER) {
            l.reset();
        }
        if let Ok(mut l) = lock_or_recover(&ETH_RATE_LIMITER) {
            l.reset();
        }

        let config = PlatformConfig::default();
        match CratonShield::new(&config) {
            Ok(shield) => {
                *guard = Some(shield);
                VsResult::ok()
            }
            Err(_) => VsResult::internal(),
        }
    })
}

// NOTE: vs_platform_init_permissive (fail-open mode) has been removed.
// The platform always operates in fail-closed mode for security.

/// Tick the platform.
///
/// Must be called periodically. `timestamp_us` is the current monotonic
/// time in microseconds.
///
/// Returns `VS_OK` on success, `VS_ERR_NOT_INITIALIZED` if the platform
/// has not been initialized, or `VS_ERR_INTERNAL` on internal error.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_platform_tick(timestamp_us: u64) -> VsResult {
    ffi_guard(|| {
        if DEGRADED.load(Ordering::Acquire) {
            return VsResult::state_corrupted();
        }
        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => match platform.tick(timestamp_us) {
                Ok(()) => VsResult::ok(),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    })
}

/// Submit a CAN frame for analysis.
///
/// # Safety
///
/// `frame` must point to a valid, properly aligned `VsCanFrame` that
/// remains valid for the duration of this call.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_submit_can_frame(frame: *const VsCanFrame) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if DEGRADED.load(Ordering::Acquire) {
            return VsResult::state_corrupted();
        }
        if frame.is_null() {
            return VsResult::invalid_arg();
        }

        // Alignment check: reject misaligned pointers before dereferencing.
        if (frame as usize) % core::mem::align_of::<VsCanFrame>() != 0 {
            return VsResult::invalid_arg();
        }

        // SAFETY: We have verified the following preconditions:
        //   1. `frame` is non-null (checked above).
        //   2. `frame` is properly aligned for `VsCanFrame` (checked above).
        //   3. `VsCanFrame` uses a fixed-size [u8; 64] data array, so no
        //      separate slice length validation is needed.
        // The caller is responsible for ensuring `frame` points to a valid,
        // initialized `VsCanFrame` that remains valid (no concurrent
        // mutation or deallocation) for the duration of this call.
        let ffi_frame = unsafe { &*frame };

        // CAN ID range validation: standard IDs are 11-bit, extended 29-bit.
        // The `id & !max_id != 0` form generates a single AND + branch on
        // most ISAs (vs a CMP for `id > max_id`) and is identical in the
        // set of rejected inputs.  Kept in sync with the production variant.
        let max_id: u32 = if ffi_frame.is_extended != 0 {
            0x1FFF_FFFF
        } else {
            0x7FF
        };
        if ffi_frame.id & !max_id != 0 {
            return VsResult::invalid_arg();
        }

        // DLC validation: classic CAN max 8, CAN-FD max 64.
        let max_dlc: u8 = if ffi_frame.is_fd != 0 { 64 } else { 8 };
        if ffi_frame.dlc > max_dlc {
            return VsResult::invalid_arg();
        }

        let now_us = monotonic_now_us();

        // Global aggregate rate limiter (cross-protocol DoS protection).
        // TODO(perf): replace the two rate-limiter mutex acquisitions
        // (GLOBAL + per-protocol) with a CAS loop on an AtomicU64 that
        // packs `tokens` and `last_update_us`. The current triple-lock
        // (GLOBAL + CAN + PLATFORM) is the dominant cost per submission
        // on contended workloads above ~10 kHz.
        let Ok(mut global) = lock_or_recover(&GLOBAL_RATE_LIMITER) else {
            return VsResult::internal();
        };
        if !global.try_consume(now_us) {
            return VsResult::rate_limited();
        }
        drop(global);

        // Fail-closed: if the rate-limiter mutex is poisoned, reject the
        // request rather than silently skipping rate limiting.
        let Ok(mut limiter) = lock_or_recover(&CAN_RATE_LIMITER) else {
            return VsResult::internal();
        };
        if !limiter.try_consume(now_us) {
            return VsResult::rate_limited();
        }
        drop(limiter); // release before acquiring PLATFORM lock

        // CAN-FD DLC-to-byte-length mapping (ISO 11898-1).
        // Classic CAN uses DLC directly (capped at 8).
        const CAN_FD_DLC_TO_LEN: [usize; 16] =
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

        // Zero bytes beyond the actual data length to prevent leaking
        // uninitialized caller memory if the frame is later logged or
        // retransmitted.
        let data_len = if ffi_frame.is_fd != 0 {
            CAN_FD_DLC_TO_LEN[ffi_frame.dlc.min(15) as usize]
        } else {
            ffi_frame.dlc.min(8) as usize
        };
        // Validate data_len against the ffi_frame.data array (always 64 bytes).
        // This is defensive — the DLC-to-length table guarantees <= 64, but
        // belt-and-suspenders given this is an FFI boundary.
        let data_len = data_len.min(ffi_frame.data.len());
        // TODO(perf): `CanFrame::data` is a fixed `[u8; 64]`, so we always
        // zero the full 64 bytes even when `data_len <= 8`. Pre-1.0 we
        // could narrow this to a `(len, data)` pair or a `heapless::Vec`
        // to avoid the dead-store; deferred because the API change
        // propagates into vs-runtime / vs-can-monitor.
        let mut data = [0u8; 64];
        data[..data_len].copy_from_slice(&ffi_frame.data[..data_len]);

        let can_frame = CanFrame {
            id: ffi_frame.id,
            is_extended: ffi_frame.is_extended != 0,
            is_fd: ffi_frame.is_fd != 0,
            dlc: ffi_frame.dlc,
            data,
        };

        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => match platform.submit_can_frame(&can_frame, ffi_frame.timestamp_us) {
                Ok(()) => VsResult::ok(),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// Submit an Ethernet packet for analysis.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes that remain valid
/// for the duration of this call. `data` may be null only if `len` is 0.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_submit_eth_packet(data: *const u8, len: usize) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if DEGRADED.load(Ordering::Acquire) {
            return VsResult::state_corrupted();
        }
        // Reject null pointers and zero-length frames (no valid Ethernet
        // frame has zero bytes).
        if data.is_null() || len == 0 {
            return VsResult::invalid_arg();
        }

        // Size validation: reject oversized frames. MAX_ETH_FRAME_LEN
        // (9216 bytes) covers jumbo frames; anything larger is invalid.
        if len > MAX_ETH_FRAME_LEN {
            return VsResult::invalid_arg();
        }

        // Minimum Ethernet frame sanity check: dst(6) + src(6) + type(2) = 14.
        if len < 14 {
            return VsResult::invalid_arg();
        }

        // No alignment check needed: `data` is *const u8 (align = 1).

        // SAFETY: We have verified the following preconditions:
        //   1. `data` is non-null (checked above).
        //   2. `len` is within [14, MAX_ETH_FRAME_LEN] (9216), preventing
        //      oversized reads.
        //   3. u8 has alignment 1, so no alignment issue is possible.
        // The caller is responsible for ensuring `data` points to at least
        // `len` valid, readable bytes that remain valid for the duration of
        // this call (i.e., no concurrent mutation or deallocation).
        let payload = unsafe { core::slice::from_raw_parts(data, len) };

        let now_us = monotonic_now_us();

        // Global aggregate rate limiter (cross-protocol DoS protection).
        let Ok(mut global) = lock_or_recover(&GLOBAL_RATE_LIMITER) else {
            return VsResult::internal();
        };
        if !global.try_consume(now_us) {
            return VsResult::rate_limited();
        }
        drop(global);

        // Fail-closed: if the rate-limiter mutex is poisoned, reject the
        // request rather than silently skipping rate limiting.
        let Ok(mut limiter) = lock_or_recover(&ETH_RATE_LIMITER) else {
            return VsResult::internal();
        };
        if !limiter.try_consume(now_us) {
            return VsResult::rate_limited();
        }
        drop(limiter); // release before acquiring PLATFORM lock

        // Parse Ethernet headers if we have enough data, otherwise
        // build a minimal packet.
        let packet = parse_raw_eth_packet(payload);

        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(platform) => match platform.submit_eth_packet(&packet, now_us) {
                Ok(()) => VsResult::ok(),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

// =============================================================================
// Post-Quantum Cryptography C ABI (feature = "pqc")
//
// These functions are only compiled when the `pqc` feature is enabled, which
// pulls in `vs-runtime/pq` → `vs-crypto/pq` → the RustCrypto ml-kem / ml-dsa
// crates.  The `PLATFORM` static is then typed as
// `CratonShield<SoftwareCryptoProvider, RustCryptoPqProvider>`.
//
// When `pqc` is not enabled the stub provider is used and all PQC calls from
// C are simply not linked into the binary — callers get a link error which is
// intentional (they must enable the feature explicitly).
// =============================================================================

/// Provision an ML-KEM-768 key slot from a 64-byte TRNG seed
/// (d ∥ z byte string, FIPS 203).
///
/// `slot`     — key slot index (0 .. KEY_SLOTS).
/// `seed`     — pointer to exactly 64 bytes of cryptographically random seed.
/// `seed_len` — must be exactly 64. Returns `VS_ERR_INVALID_ARG` otherwise.
///              This parameter exists so callers cannot accidentally pass a
///              shorter buffer that would cause an out-of-bounds read.
///
/// Returns `VS_OK` on success, or an error code on failure.
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_provision_mlkem_key(
    slot: u32,
    seed: *const u8,
    seed_len: usize,
) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if seed.is_null() || seed_len != 64 {
            return VsResult::invalid_arg();
        }
        // SAFETY: `seed` is non-null and `seed_len == 64` was verified above.
        // Caller must ensure the pointer is valid for reads of 64 bytes and properly aligned.
        // The length parameter was validated above against the exact expected size.
        let seed_slice: &[u8] = unsafe { core::slice::from_raw_parts(seed, seed_len) };
        let seed_buf: &[u8; 64] = seed_slice
            .try_into()
            .expect("length == 64 verified above; try_into cannot fail");
        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(p) => match p.pq_provision_mlkem_key(vs_crypto::KeyId(slot), seed_buf) {
                Ok(()) => VsResult::ok(),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// Provision an ML-DSA-65 signing key slot from a 32-byte TRNG seed
/// (ξ, FIPS 204).
///
/// `slot`     — key slot index (0 .. KEY_SLOTS).
/// `seed`     — pointer to exactly 32 bytes of cryptographically random seed.
/// `seed_len` — must be exactly 32. Returns `VS_ERR_INVALID_ARG` otherwise.
///              This parameter exists so callers cannot accidentally pass a
///              shorter buffer that would cause an out-of-bounds read.
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_provision_mldsa_key(
    slot: u32,
    seed: *const u8,
    seed_len: usize,
) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if seed.is_null() || seed_len != 32 {
            return VsResult::invalid_arg();
        }
        // SAFETY: `seed` is non-null and `seed_len == 32` was verified above.
        // Caller must ensure the pointer is valid for reads of 32 bytes and properly aligned.
        // The length parameter was validated above against the exact expected size.
        let seed_slice: &[u8] = unsafe { core::slice::from_raw_parts(seed, seed_len) };
        let seed_buf: &[u8; 32] = seed_slice
            .try_into()
            .expect("length == 32 verified above; try_into cannot fail");
        let Ok(mut guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_mut() {
            Some(p) => match p.pq_provision_mldsa_key(vs_crypto::KeyId(slot), seed_buf) {
                Ok(()) => VsResult::ok(),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// ML-KEM-768 encapsulation (FIPS 203).
///
/// Writes 1088 ciphertext bytes to `ct_out` and 32 shared-secret bytes to
/// `ss_out`.  Both output buffers must be non-null and caller-allocated with
/// at least the required capacity (`MLKEM768_CIPHERTEXT_LEN` = 1088 and
/// `MLKEM_SHARED_SECRET_LEN` = 32, respectively).  The randomness is supplied
/// internally by the PQ provider's RNG.
///
/// `slot`       — ML-KEM key slot (must have been provisioned with
///                `vs_pq_provision_mlkem_key`).
/// `ct_out`     — output: at least 1088 bytes for the ML-KEM-768 ciphertext.
/// `ct_out_len` — capacity of `ct_out` in bytes; must be ≥ 1088. Returns
///                `VS_ERR_INVALID_ARG` if smaller. Only the first 1088 bytes
///                are written.
/// `ss_out`     — output: at least 32 bytes for the shared secret.
/// `ss_out_len` — capacity of `ss_out` in bytes; must be ≥ 32. Returns
///                `VS_ERR_INVALID_ARG` if smaller. Only the first 32 bytes
///                are written.
///
/// **BREAKING ABI CHANGE**: this signature gained the `ct_out_len` and
/// `ss_out_len` parameters to prevent caller-side buffer overflows. C
/// callers must update their call sites.
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_mlkem_encapsulate(
    slot: u32,
    ct_out: *mut u8,
    ct_out_len: usize,
    ss_out: *mut u8,
    ss_out_len: usize,
) -> VsResult {
    use vs_crypto::{MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN};
    ffi_guard(AssertUnwindSafe(|| {
        if ct_out.is_null() || ss_out.is_null() {
            return VsResult::invalid_arg();
        }
        // Validate output-buffer capacities BEFORE any writes. If either is
        // too small, return without touching the buffers.
        if ct_out_len < MLKEM768_CIPHERTEXT_LEN || ss_out_len < MLKEM_SHARED_SECRET_LEN {
            return VsResult::invalid_arg();
        }
        let mut ct_buf = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss_buf = [0u8; MLKEM_SHARED_SECRET_LEN];
        let Ok(guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(p) => {
                match p.pq_mlkem_encapsulate(vs_crypto::KeyId(slot), &mut ct_buf, &mut ss_buf) {
                    Ok(()) => {
                        // SAFETY: `ct_out` is non-null (checked above) and
                        // `ct_out_len >= MLKEM768_CIPHERTEXT_LEN` was validated
                        // above; we write exactly `MLKEM768_CIPHERTEXT_LEN`
                        // bytes from the local `ct_buf`. `ct_buf` and the
                        // caller's region cannot alias because `ct_buf` lives
                        // on this function's stack.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                ct_buf.as_ptr(),
                                ct_out,
                                MLKEM768_CIPHERTEXT_LEN,
                            );
                        }
                        // SAFETY: `ss_out` is non-null (checked above) and
                        // `ss_out_len >= MLKEM_SHARED_SECRET_LEN` was validated
                        // above; we write exactly `MLKEM_SHARED_SECRET_LEN`
                        // bytes from the local `ss_buf`. `ss_buf` lives on this
                        // function's stack and cannot alias the caller region.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                ss_buf.as_ptr(),
                                ss_out,
                                MLKEM_SHARED_SECRET_LEN,
                            );
                        }
                        VsResult::ok()
                    }
                    Err(e) => VsResult::from_vs_error(e),
                }
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// ML-KEM-768 decapsulation (FIPS 203).
///
/// Reads 1088 ciphertext bytes from `ct_in` and writes the 32-byte shared
/// secret to `ss_out`.
///
/// `slot`       — ML-KEM key slot (must have been provisioned).
/// `ct_in`      — pointer to the 1088-byte ciphertext produced by encapsulation.
/// `ct_len`     — must be exactly 1088 (`MLKEM768_CIPHERTEXT_LEN`).
///                Returns `VS_ERR_INVALID_ARG` otherwise.
/// `ss_out`     — output: at least 32 bytes for the recovered shared secret.
/// `ss_out_len` — capacity of `ss_out` in bytes; must be ≥ 32
///                (`MLKEM_SHARED_SECRET_LEN`). Returns `VS_ERR_INVALID_ARG`
///                if smaller. Only the first 32 bytes are written.
///
/// **BREAKING ABI CHANGE**: this signature gained the `ss_out_len` parameter
/// to prevent caller-side buffer overflows. C callers must update their call
/// sites.
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_mlkem_decapsulate(
    slot: u32,
    ct_in: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_out_len: usize,
) -> VsResult {
    use vs_crypto::{MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN};
    ffi_guard(AssertUnwindSafe(|| {
        if ct_in.is_null() || ss_out.is_null() || ct_len != MLKEM768_CIPHERTEXT_LEN {
            return VsResult::invalid_arg();
        }
        // Validate output-buffer capacity BEFORE any writes.
        if ss_out_len < MLKEM_SHARED_SECRET_LEN {
            return VsResult::invalid_arg();
        }
        // SAFETY: `ct_in` is non-null and `ct_len == MLKEM768_CIPHERTEXT_LEN` was verified above.
        // Caller must ensure the pointer is valid for reads of MLKEM768_CIPHERTEXT_LEN bytes
        // and properly aligned. The length parameter was validated above against the exact
        // expected size.
        let ct_slice: &[u8] = unsafe { core::slice::from_raw_parts(ct_in, ct_len) };
        let ct: &[u8; MLKEM768_CIPHERTEXT_LEN] = ct_slice
            .try_into()
            .expect("length == MLKEM768_CIPHERTEXT_LEN verified above; try_into cannot fail");
        let mut ss_buf = [0u8; MLKEM_SHARED_SECRET_LEN];
        let Ok(guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(p) => match p.pq_mlkem_decapsulate(vs_crypto::KeyId(slot), ct, &mut ss_buf) {
                Ok(()) => {
                    // SAFETY: `ss_out` is non-null (checked above) and
                    // `ss_out_len >= MLKEM_SHARED_SECRET_LEN` was validated
                    // above; we write exactly `MLKEM_SHARED_SECRET_LEN` bytes
                    // from the local stack-allocated `ss_buf`, which cannot
                    // alias the caller's region.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            ss_buf.as_ptr(),
                            ss_out,
                            MLKEM_SHARED_SECRET_LEN,
                        );
                    }
                    VsResult::ok()
                }
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// ML-DSA-65 signing (FIPS 204).
///
/// Signs `msg_len` bytes from `msg_in` and writes the 3309-byte signature to
/// `sig_out`.
///
/// `slot`        — ML-DSA key slot (must have been provisioned).
/// `msg_in`      — pointer to message bytes.
/// `msg_len`     — message length in bytes. Must be in `[1, 65535]`. The
///                 64 KiB upper bound prevents stack overflow from large
///                 messages in the ML-DSA internal hashing and matches the
///                 maximum message size supported by the underlying
///                 `ml-dsa` crate.
/// `sig_out`     — output: at least 3309 bytes for the ML-DSA-65 signature.
/// `sig_out_len` — capacity of `sig_out` in bytes; must be ≥ 3309
///                 (`MLDSA65_SIGNATURE_LEN`). Returns `VS_ERR_INVALID_ARG`
///                 if smaller. Only the first 3309 bytes are written.
///
/// **BREAKING ABI CHANGE**: this signature gained the `sig_out_len` parameter
/// to prevent caller-side buffer overflows. C callers must update their call
/// sites.
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_mldsa_sign(
    slot: u32,
    msg_in: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
) -> VsResult {
    use vs_crypto::MLDSA65_SIGNATURE_LEN;
    ffi_guard(AssertUnwindSafe(|| {
        if msg_in.is_null() || sig_out.is_null() || msg_len == 0 || msg_len > 65535 {
            return VsResult::invalid_arg();
        }
        // Validate output-buffer capacity BEFORE any writes.
        if sig_out_len < MLDSA65_SIGNATURE_LEN {
            return VsResult::invalid_arg();
        }
        // SAFETY: caller guarantees `msg_in` points to `msg_len` readable bytes.
        let msg: &[u8] = unsafe { core::slice::from_raw_parts(msg_in, msg_len) };
        let mut sig_buf = [0u8; MLDSA65_SIGNATURE_LEN];
        let Ok(guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(p) => match p.pq_mldsa_sign(vs_crypto::KeyId(slot), msg, &mut sig_buf) {
                Ok(()) => {
                    // SAFETY: `sig_out` is non-null (checked above) and
                    // `sig_out_len >= MLDSA65_SIGNATURE_LEN` was validated
                    // above; we write exactly `MLDSA65_SIGNATURE_LEN` bytes
                    // from the local stack-allocated `sig_buf`, which cannot
                    // alias the caller's region.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            sig_buf.as_ptr(),
                            sig_out,
                            MLDSA65_SIGNATURE_LEN,
                        );
                    }
                    VsResult::ok()
                }
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// ML-DSA-65 signature verification (FIPS 204).
///
/// Returns `VS_OK` if `sig_in` is a valid ML-DSA-65 signature over
/// `msg_in[0..msg_len]` for the 1952-byte public key in `pub_key_in`.
/// Returns `VS_ERR_CRYPTO` if the signature is structurally valid but
/// does not verify.
///
/// `pub_key_in`  — pointer to the 1952-byte ML-DSA-65 public key.
/// `pub_key_len` — must be exactly 1952 (`MLDSA65_PUBLIC_KEY_LEN`).
/// `msg_in`      — pointer to message bytes.
/// `msg_len`     — message length in bytes. Must be in `[1, 65535]`. The
///                 64 KiB upper bound prevents stack overflow from large
///                 messages in the ML-DSA internal hashing.
/// `sig_in`      — pointer to the 3309-byte signature.
/// `sig_len`     — must be exactly 3309 (`MLDSA65_SIGNATURE_LEN`).
#[cfg(feature = "pqc")]
#[no_mangle]
pub unsafe extern "C" fn vs_pq_mldsa_verify(
    pub_key_in: *const u8,
    pub_key_len: usize,
    msg_in: *const u8,
    msg_len: usize,
    sig_in: *const u8,
    sig_len: usize,
) -> VsResult {
    use vs_crypto::{MLDSA65_PUBLIC_KEY_LEN, MLDSA65_SIGNATURE_LEN};
    ffi_guard(AssertUnwindSafe(|| {
        if pub_key_in.is_null()
            || msg_in.is_null()
            || sig_in.is_null()
            || msg_len == 0
            || msg_len > 65535
            || pub_key_len != MLDSA65_PUBLIC_KEY_LEN
            || sig_len != MLDSA65_SIGNATURE_LEN
        {
            return VsResult::invalid_arg();
        }
        // SAFETY: `pub_key_in` is non-null and `pub_key_len == MLDSA65_PUBLIC_KEY_LEN`
        // was verified above. Caller must ensure the pointer is valid for reads of
        // MLDSA65_PUBLIC_KEY_LEN bytes and properly aligned. The length parameter was
        // validated above against the exact expected size.
        let pub_key_slice: &[u8] = unsafe { core::slice::from_raw_parts(pub_key_in, pub_key_len) };
        let pub_key: &[u8; MLDSA65_PUBLIC_KEY_LEN] = pub_key_slice
            .try_into()
            .expect("length == MLDSA65_PUBLIC_KEY_LEN verified above; try_into cannot fail");
        // SAFETY: `msg_in` is non-null and `msg_len` was validated above (1..=65535).
        // Caller must ensure the pointer is valid for reads of `msg_len` bytes.
        let msg: &[u8] = unsafe { core::slice::from_raw_parts(msg_in, msg_len) };
        // SAFETY: `sig_in` is non-null and `sig_len == MLDSA65_SIGNATURE_LEN` was
        // verified above. Caller must ensure the pointer is valid for reads of
        // MLDSA65_SIGNATURE_LEN bytes and properly aligned. The length parameter was
        // validated above against the exact expected size.
        let sig_slice: &[u8] = unsafe { core::slice::from_raw_parts(sig_in, sig_len) };
        let sig: &[u8; MLDSA65_SIGNATURE_LEN] = sig_slice
            .try_into()
            .expect("length == MLDSA65_SIGNATURE_LEN verified above; try_into cannot fail");
        let Ok(guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(p) => match p.pq_mldsa_verify(pub_key, msg, sig) {
                Ok(true) => VsResult::ok(),
                Ok(false) => VsResult::from_vs_error(vs_types::VsError::CryptoError),
                Err(e) => VsResult::from_vs_error(e),
            },
            None => VsResult::not_initialized(),
        }
    }))
}

/// Parse raw bytes into an `EthPacket`, extracting MAC addresses,
/// optional VLAN tag, ethertype, and destination port (for TCP/UDP
/// over IPv4) when the frame is large enough.
fn parse_raw_eth_packet(raw: &[u8]) -> EthPacket<'_> {
    // Minimum Ethernet header: 6 dst + 6 src + 2 ethertype = 14 bytes.
    if raw.len() < 14 {
        return EthPacket {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            vlan_id: None,
            ethertype: 0,
            dst_port: None,
            payload: raw,
        };
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&raw[0..6]);
    src_mac.copy_from_slice(&raw[6..12]);

    let ethertype_or_tpid = u16::from_be_bytes([raw[12], raw[13]]);

    // 802.1Q VLAN tagged frame: TPID == 0x8100.
    let (vlan_id, ethertype, ip_start) = if ethertype_or_tpid == 0x8100 && raw.len() >= 18 {
        let vlan = u16::from_be_bytes([raw[14], raw[15]]) & 0x0FFF;
        let etype = u16::from_be_bytes([raw[16], raw[17]]);
        (Some(vlan), etype, 18)
    } else {
        (None, ethertype_or_tpid, 14)
    };

    let payload = &raw[ip_start..];
    let dst_port = extract_dst_port(ethertype, payload);

    EthPacket {
        src_mac,
        dst_mac,
        vlan_id,
        ethertype,
        dst_port,
        payload,
    }
}

/// Extract the destination port from an IPv4 or IPv6 TCP or UDP packet.
///
/// Returns `None` for non-IP ethertypes, non-TCP/UDP protocols,
/// or packets too short to contain a valid transport header.
fn extract_dst_port(ethertype: u16, ip_payload: &[u8]) -> Option<u16> {
    match ethertype {
        0x0800 => extract_dst_port_ipv4(ip_payload),
        0x86DD => extract_dst_port_ipv6(ip_payload),
        _ => None,
    }
}

/// Extract destination port from an IPv4 packet.
fn extract_dst_port_ipv4(ip_payload: &[u8]) -> Option<u16> {
    // Minimum IPv4 header is 20 bytes.
    if ip_payload.len() < 20 {
        return None;
    }

    // IHL (Internet Header Length) is the lower 4 bits of the first byte,
    // measured in 32-bit words.
    let ihl = (ip_payload[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip_payload.len() < ihl {
        return None;
    }

    let protocol = ip_payload[9];
    extract_transport_port(protocol, &ip_payload[ihl..])
}

/// Extract destination port from an IPv6 packet.
///
/// Handles the fixed 40-byte IPv6 header and chases extension headers
/// (Hop-by-Hop, Routing, Fragment, Destination Options, AH, ESP/skip,
/// Mobility, HIP, Shim6) to find the upper-layer protocol.
///
/// Limits extension header chasing to 8 hops to prevent infinite loops
/// from malformed packets.
fn extract_dst_port_ipv6(ip_payload: &[u8]) -> Option<u16> {
    // Minimum IPv6 header is 40 bytes.
    if ip_payload.len() < 40 {
        return None;
    }

    let mut next_header = ip_payload[6];
    let mut offset: usize = 40;

    // Chase extension headers, max 8 hops to prevent DoS from
    // crafted packets with circular extension header chains.
    for _ in 0..8 {
        match next_header {
            // TCP or UDP — we found the transport layer.
            6 | 17 => return extract_transport_port(next_header, &ip_payload[offset..]),
            // Extension headers with standard (next_header, length) format:
            // 0 = Hop-by-Hop, 43 = Routing, 60 = Destination Options,
            // 135 = Mobility, 139 = HIP, 140 = Shim6
            0 | 43 | 60 | 135 | 139 | 140 => {
                if ip_payload.len() < offset + 2 {
                    return None;
                }
                next_header = ip_payload[offset];
                // Length is in 8-octet units, not counting the first 8 octets.
                let ext_len = (ip_payload[offset + 1] as usize + 1) * 8;
                offset += ext_len;
                if offset > ip_payload.len() {
                    return None;
                }
            }
            // Fragment header (44) — fixed 8 bytes.
            44 => {
                if ip_payload.len() < offset + 8 {
                    return None;
                }
                next_header = ip_payload[offset];
                offset += 8;
            }
            // AH (51) — Authentication Header.
            51 => {
                if ip_payload.len() < offset + 2 {
                    return None;
                }
                next_header = ip_payload[offset];
                let ah_len = (ip_payload[offset + 1] as usize + 2) * 4;
                offset += ah_len;
                if offset > ip_payload.len() {
                    return None;
                }
            }
            // No Next Header (59) or unknown — stop.
            _ => return None,
        }
    }
    None
}

/// Extract destination port from a transport-layer payload.
fn extract_transport_port(protocol: u8, transport: &[u8]) -> Option<u16> {
    // TCP (6) and UDP (17) both have dst_port at bytes 2..4.
    if protocol != 6 && protocol != 17 {
        return None;
    }
    if transport.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([transport[2], transport[3]]))
}

/// Retrieve the current health status of the platform.
///
/// # Safety
///
/// `out` must point to a valid, properly aligned, writable `VsHealth`
/// that remains valid for the duration of this call.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn vs_get_health(out: *mut VsHealth) -> VsResult {
    ffi_guard(AssertUnwindSafe(|| {
        if DEGRADED.load(Ordering::Acquire) {
            return VsResult::state_corrupted();
        }
        if out.is_null() {
            return VsResult::invalid_arg();
        }

        // Alignment check.
        if (out as usize) % core::mem::align_of::<VsHealth>() != 0 {
            return VsResult::invalid_arg();
        }

        let Ok(guard) = lock_or_recover(&PLATFORM) else {
            return VsResult::internal();
        };
        match guard.as_ref() {
            Some(platform) => {
                let health = health_to_ffi(platform.health());
                // SAFETY: We checked that `out` is non-null and aligned.
                // The caller is responsible for ensuring it points to a
                // valid, writable `VsHealth` for the duration of this call.
                unsafe {
                    core::ptr::write(out, health);
                }
                VsResult::ok()
            }
            None => VsResult::not_initialized(),
        }
    }))
}

/// Shut down the platform and release all resources.
///
/// After this call, all other functions (except `vs_platform_init`)
/// will return `VS_ERR_NOT_INITIALIZED`.
#[cfg(feature = "mock-hsm")]
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn vs_platform_shutdown() -> VsResult {
    ffi_guard(|| {
        // Use lock_platform_or_clear so that if the mutex was poisoned,
        // the potentially corrupt CratonShield is replaced with None
        // before we attempt any operations on it.
        let Ok(mut guard) = lock_platform_or_clear() else {
            return VsResult::internal();
        };
        if let Some(platform) = guard.as_mut() {
            platform.shutdown();
            *guard = None;
            // Clear degraded flag so re-init can proceed.
            DEGRADED.store(false, Ordering::Release);
            VsResult::ok()
        } else {
            // Even if not initialized, clear degraded so re-init works.
            DEGRADED.store(false, Ordering::Release);
            VsResult::not_initialized()
        }
    })
}

// =============================================================================
// Production FFI
//
// Enabled with `--features production` (and `mock-hsm` must NOT be set).
// Uses a `Box<dyn CryptoProvider>` trait object so the crate compiles and
// links without requiring the integrator to name their concrete type at
// compile time.  The real provider is injected at runtime via
// `vs_platform_init_with_provider`.
//
// For hardware-backed providers (PKCS#11 HSM, TPM 2.0, OP-TEE) see
// `INSTALL.md §Production Deployment`.
// =============================================================================

#[cfg(all(feature = "production", not(feature = "mock-hsm")))]
mod production {
    use super::*;
    use vs_crypto::CryptoProvider;

    // -----------------------------------------------------------------------
    // Runtime guard: fail-closed if mock-hsm compiled without debug_assertions.
    //
    // The compile_error! guard at the top of this file catches most cases at
    // build time. This runtime check adds defence-in-depth for unusual
    // toolchain configurations where `debug_assertions` may be disabled
    // in a non-release profile.
    // -----------------------------------------------------------------------
    fn assert_not_mock_build() -> bool {
        // In a legitimate production build mock-hsm is not compiled in.
        // If somehow both features are active (which the cfg above prevents),
        // this would be unreachable. The check is here for belt-and-suspenders.
        cfg!(not(feature = "mock-hsm"))
    }

    // -----------------------------------------------------------------------
    // Global platform state (trait-object variant)
    // -----------------------------------------------------------------------

    static PROD_PLATFORM: Mutex<Option<CratonShield<Box<dyn CryptoProvider + Send>>>> =
        Mutex::new(None);

    fn lock_prod_platform_or_clear() -> Result<
        std::sync::MutexGuard<'static, Option<CratonShield<Box<dyn CryptoProvider + Send>>>>,
        (),
    > {
        match PROD_PLATFORM.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                POISONED_MUTEX_COUNT.fetch_add(1, Ordering::Release);
                DEGRADED.store(true, Ordering::Release);
                let mut guard = poisoned.into_inner();
                *guard = None;
                Ok(guard)
            }
        }
    }

    // -----------------------------------------------------------------------
    // vs_platform_init  — production variant
    //
    // Requires that a CryptoProvider has already been registered via
    // `vs_platform_register_provider` (see below).  If none has been
    // registered this returns VS_ERR_NOT_INITIALIZED so that callers
    // see a clear error rather than a hard crash.
    // -----------------------------------------------------------------------

    /// Global slot for the integrator-supplied `CryptoProvider`.
    ///
    /// Set once via `vs_platform_register_provider` before calling
    /// `vs_platform_init`.  Cleared on `vs_platform_shutdown`.
    static PENDING_PROVIDER: Mutex<Option<Box<dyn CryptoProvider + Send>>> = Mutex::new(None);

    /// Register a heap-boxed `CryptoProvider` to be consumed by the next
    /// `vs_platform_init` call.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if the `PENDING_PROVIDER`
    /// mutex is poisoned (a previous registration attempt panicked). The
    /// caller is expected to surface the error rather than silently dropping
    /// the provider, since a dropped provider would otherwise cause the
    /// subsequent `vs_platform_init` to return `VS_ERR_NOT_INITIALIZED`
    /// with no indication of the underlying mutex-poison root cause. The
    /// returned `Err` is itself the signal to shut down + re-init.
    ///
    /// # Safety
    ///
    /// Intended for use from Rust integration code.  C callers should use
    /// the callback-based `vs_auto` API in the `vs-ffi-auto` crate instead.
    pub fn register_provider(provider: Box<dyn CryptoProvider + Send>) -> Result<(), VsError> {
        match PENDING_PROVIDER.lock() {
            Ok(mut slot) => {
                *slot = Some(provider);
                Ok(())
            }
            Err(_) => {
                // Mark the platform degraded so the operator sees a
                // consistent state corruption signal across the FFI.
                POISONED_MUTEX_COUNT.fetch_add(1, Ordering::Release);
                DEGRADED.store(true, Ordering::Release);
                Err(VsError::PolicyViolation)
            }
        }
    }

    /// Initialize the platform using the `CryptoProvider` previously
    /// registered via [`register_provider`].
    ///
    /// Returns `VS_OK` on success, `VS_ERR_NOT_INITIALIZED` if no provider
    /// has been registered, `VS_ERR_ALREADY_INITIALIZED` if the platform
    /// is already running, `VS_ERR_INTERNAL` if `catch_unwind` is
    /// non-functional / a mutex is poisoned, or `VS_ERR_STATE_CORRUPTED`
    /// if the platform is in degraded state. Thread-safe: concurrent calls
    /// from multiple threads are serialised on the `PROD_PLATFORM` mutex.
    #[no_mangle]
    #[allow(unsafe_code)]
    pub extern "C" fn vs_platform_init() -> VsResult {
        ffi_guard(|| {
            // Runtime guard: verify catch_unwind is functional.
            let unwind_works = std::panic::catch_unwind(|| {}).is_ok();
            if !unwind_works {
                return VsResult::internal();
            }

            // Belt-and-suspenders: refuse to init if mock build somehow slipped through.
            if !assert_not_mock_build() {
                return VsResult::internal();
            }

            if DEGRADED.load(Ordering::Acquire) {
                return VsResult::state_corrupted();
            }

            let Ok(mut guard) = lock_prod_platform_or_clear() else {
                return VsResult::internal();
            };
            if guard.is_some() {
                return VsResult::already_initialized();
            }

            // Take the pending provider; fail if none registered.
            let Ok(mut provider_slot) = PENDING_PROVIDER.lock() else {
                return VsResult::internal();
            };
            let Some(provider) = provider_slot.take() else {
                // No provider registered — caller must call register_provider first.
                return VsResult::not_initialized();
            };
            drop(provider_slot);

            // Reset rate limiters so a shutdown/re-init cycle starts fresh.
            if let Ok(mut l) = lock_or_recover(&GLOBAL_RATE_LIMITER) {
                l.reset();
            }
            if let Ok(mut l) = lock_or_recover(&CAN_RATE_LIMITER) {
                l.reset();
            }
            if let Ok(mut l) = lock_or_recover(&ETH_RATE_LIMITER) {
                l.reset();
            }

            let config = PlatformConfig::default();
            match CratonShield::new_with_crypto(&config, provider) {
                Ok(shield) => {
                    *guard = Some(shield);
                    VsResult::ok()
                }
                Err(_) => VsResult::internal(),
            }
        })
    }

    /// Advance the platform clock and process pending events.
    ///
    /// Production-build counterpart of the mock-hsm `vs_platform_tick`.
    /// `timestamp_us` is the current monotonic time in microseconds. Returns
    /// `VS_OK` on success, `VS_ERR_NOT_INITIALIZED` if no platform exists,
    /// or `VS_ERR_INTERNAL` / `VS_ERR_STATE_CORRUPTED` on lock errors.
    #[no_mangle]
    #[allow(unsafe_code)]
    pub extern "C" fn vs_platform_tick(timestamp_us: u64) -> VsResult {
        ffi_guard(|| {
            if DEGRADED.load(Ordering::Acquire) {
                return VsResult::state_corrupted();
            }
            let Ok(mut guard) = lock_or_recover(&PROD_PLATFORM) else {
                return VsResult::internal();
            };
            match guard.as_mut() {
                Some(platform) => match platform.tick(timestamp_us) {
                    Ok(()) => VsResult::ok(),
                    Err(e) => VsResult::from_vs_error(e),
                },
                None => VsResult::not_initialized(),
            }
        })
    }

    /// Submit a CAN frame for analysis (production variant).
    ///
    /// Same contract as the mock-hsm `vs_submit_can_frame`: validates the
    /// frame, applies global + per-protocol rate limiting, then forwards
    /// to the IDS / anomaly stack. Returns `VS_OK`, `VS_ERR_INVALID_ARG`,
    /// `VS_ERR_NOT_INITIALIZED`, `VS_ERR_RATE_LIMITED`, or
    /// `VS_ERR_STATE_CORRUPTED`.
    ///
    /// # Safety
    ///
    /// `frame` must point to a valid, properly aligned `VsCanFrame` that
    /// remains valid for the duration of this call.
    #[no_mangle]
    #[allow(unsafe_code)]
    pub unsafe extern "C" fn vs_submit_can_frame(frame: *const VsCanFrame) -> VsResult {
        ffi_guard(AssertUnwindSafe(|| {
            if DEGRADED.load(Ordering::Acquire) {
                return VsResult::state_corrupted();
            }
            if frame.is_null() {
                return VsResult::invalid_arg();
            }
            if (frame as usize) % core::mem::align_of::<VsCanFrame>() != 0 {
                return VsResult::invalid_arg();
            }
            // SAFETY: non-null, aligned, caller guarantees validity for call duration.
            let ffi_frame = unsafe { &*frame };

            let max_id: u32 = if ffi_frame.is_extended != 0 {
                0x1FFF_FFFF
            } else {
                0x7FF
            };
            if ffi_frame.id & !max_id != 0 {
                return VsResult::invalid_arg();
            }
            let max_dlc: u8 = if ffi_frame.is_fd != 0 { 64 } else { 8 };
            if ffi_frame.dlc > max_dlc {
                return VsResult::invalid_arg();
            }

            let now_us = monotonic_now_us();
            // TODO(perf): collapse the two rate-limiter mutexes (GLOBAL +
            // CAN) into a single atomic token bucket (CAS loop on an
            // AtomicU64 packing tokens + last_update_us). Triple-lock per
            // frame dominates the hot path above ~10 kHz of contended CAN
            // submissions. Kept in sync with the mock-hsm variant.
            let Ok(mut global) = lock_or_recover(&GLOBAL_RATE_LIMITER) else {
                return VsResult::internal();
            };
            if !global.try_consume(now_us) {
                return VsResult::rate_limited();
            }
            drop(global);
            let Ok(mut limiter) = lock_or_recover(&CAN_RATE_LIMITER) else {
                return VsResult::internal();
            };
            if !limiter.try_consume(now_us) {
                return VsResult::rate_limited();
            }
            drop(limiter);

            const CAN_FD_DLC_TO_LEN: [usize; 16] =
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];
            let data_len = if ffi_frame.is_fd != 0 {
                CAN_FD_DLC_TO_LEN[ffi_frame.dlc.min(15) as usize]
            } else {
                ffi_frame.dlc.min(8) as usize
            }
            .min(ffi_frame.data.len());
            // TODO(perf): `CanFrame::data` requires a full `[u8; 64]`, so
            // short classic CAN frames still pay for zeroing 56 unused
            // bytes. Pre-1.0 we could swap to a `(len, data)` pair; the
            // change propagates into vs-runtime and vs-can-monitor.
            let mut data = [0u8; 64];
            data[..data_len].copy_from_slice(&ffi_frame.data[..data_len]);

            let can_frame = CanFrame {
                id: ffi_frame.id,
                is_extended: ffi_frame.is_extended != 0,
                is_fd: ffi_frame.is_fd != 0,
                dlc: ffi_frame.dlc,
                data,
            };
            let Ok(mut guard) = lock_or_recover(&PROD_PLATFORM) else {
                return VsResult::internal();
            };
            match guard.as_mut() {
                Some(platform) => {
                    match platform.submit_can_frame(&can_frame, ffi_frame.timestamp_us) {
                        Ok(()) => VsResult::ok(),
                        Err(e) => VsResult::from_vs_error(e),
                    }
                }
                None => VsResult::not_initialized(),
            }
        }))
    }

    /// Submit an Ethernet packet for analysis (production variant).
    ///
    /// Same contract as the mock-hsm `vs_submit_eth_packet`. Returns
    /// `VS_OK`, `VS_ERR_INVALID_ARG`, `VS_ERR_NOT_INITIALIZED`,
    /// `VS_ERR_RATE_LIMITED`, or `VS_ERR_STATE_CORRUPTED`.
    ///
    /// # Safety
    ///
    /// `data` must point to at least `len` readable bytes valid for the
    /// duration of this call. May be NULL only if `len == 0` (which
    /// itself returns `VS_ERR_INVALID_ARG`).
    #[no_mangle]
    #[allow(unsafe_code)]
    pub unsafe extern "C" fn vs_submit_eth_packet(data: *const u8, len: usize) -> VsResult {
        ffi_guard(AssertUnwindSafe(|| {
            if DEGRADED.load(Ordering::Acquire) {
                return VsResult::state_corrupted();
            }
            if data.is_null() || len == 0 || len > MAX_ETH_FRAME_LEN || len < 14 {
                return VsResult::invalid_arg();
            }
            // SAFETY: non-null, len validated above.
            let payload = unsafe { core::slice::from_raw_parts(data, len) };

            let now_us = monotonic_now_us();
            let Ok(mut global) = lock_or_recover(&GLOBAL_RATE_LIMITER) else {
                return VsResult::internal();
            };
            if !global.try_consume(now_us) {
                return VsResult::rate_limited();
            }
            drop(global);
            let Ok(mut limiter) = lock_or_recover(&ETH_RATE_LIMITER) else {
                return VsResult::internal();
            };
            if !limiter.try_consume(now_us) {
                return VsResult::rate_limited();
            }
            drop(limiter);

            let packet = parse_raw_eth_packet(payload);
            let Ok(mut guard) = lock_or_recover(&PROD_PLATFORM) else {
                return VsResult::internal();
            };
            match guard.as_mut() {
                Some(platform) => match platform.submit_eth_packet(&packet, now_us) {
                    Ok(()) => VsResult::ok(),
                    Err(e) => VsResult::from_vs_error(e),
                },
                None => VsResult::not_initialized(),
            }
        }))
    }

    /// Fill `*out` with the current subsystem health snapshot
    /// (production variant). Returns `VS_OK`, `VS_ERR_INVALID_ARG` for a
    /// null / misaligned `out`, `VS_ERR_NOT_INITIALIZED`, or
    /// `VS_ERR_STATE_CORRUPTED`.
    ///
    /// # Safety
    ///
    /// `out` must point to a writable, properly aligned `VsHealth` that
    /// remains valid for the duration of this call.
    #[no_mangle]
    #[allow(unsafe_code)]
    pub unsafe extern "C" fn vs_get_health(out: *mut VsHealth) -> VsResult {
        ffi_guard(AssertUnwindSafe(|| {
            if DEGRADED.load(Ordering::Acquire) {
                return VsResult::state_corrupted();
            }
            if out.is_null() || (out as usize) % core::mem::align_of::<VsHealth>() != 0 {
                return VsResult::invalid_arg();
            }
            let Ok(guard) = lock_or_recover(&PROD_PLATFORM) else {
                return VsResult::internal();
            };
            match guard.as_ref() {
                Some(platform) => {
                    let health = health_to_ffi(platform.health());
                    // SAFETY: non-null and aligned, checked above.
                    unsafe { core::ptr::write(out, health) };
                    VsResult::ok()
                }
                None => VsResult::not_initialized(),
            }
        }))
    }

    /// Shut down the platform and release all resources (production
    /// variant). Returns `VS_OK` if a live platform was torn down, or
    /// `VS_ERR_NOT_INITIALIZED` if shutdown is a no-op. Clears the
    /// `DEGRADED` flag so a subsequent `vs_platform_init` can succeed.
    #[no_mangle]
    #[allow(unsafe_code)]
    pub extern "C" fn vs_platform_shutdown() -> VsResult {
        ffi_guard(|| {
            let Ok(mut guard) = lock_prod_platform_or_clear() else {
                return VsResult::internal();
            };
            if let Some(platform) = guard.as_mut() {
                platform.shutdown();
                *guard = None;
                DEGRADED.store(false, Ordering::Release);
                VsResult::ok()
            } else {
                DEGRADED.store(false, Ordering::Release);
                VsResult::not_initialized()
            }
        })
    }

    // -----------------------------------------------------------------------
    // Tests for the production path
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex as StdMutex;
        use vs_crypto::SoftwareCryptoProvider;

        static TEST_LOCK: StdMutex<()> = StdMutex::new(());

        fn reset() {
            if let Ok(mut g) = PROD_PLATFORM.lock() {
                if let Some(p) = g.as_mut() {
                    p.shutdown();
                }
                *g = None;
            }
            if let Ok(mut s) = PENDING_PROVIDER.lock() {
                *s = None;
            }
            DEGRADED.store(false, Ordering::Release);
        }

        fn test_rng(buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x42);
            }
        }

        #[test]
        fn prod_init_without_provider_returns_not_initialized() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();
            let r = vs_platform_init();
            assert_eq!(
                r.code, VS_ERR_NOT_INITIALIZED,
                "init without a registered provider must return NOT_INITIALIZED"
            );
            reset();
        }

        #[test]
        fn prod_lifecycle_with_software_provider() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();

            // Register the software (test) provider.
            let provider: Box<dyn CryptoProvider + Send> =
                Box::new(SoftwareCryptoProvider::new(test_rng));
            register_provider(provider)
                .expect("PENDING_PROVIDER mutex must not be poisoned in tests");

            let r = vs_platform_init();
            assert_eq!(r.code, VS_OK, "init with registered provider must succeed");

            let r = vs_platform_tick(1_000_000);
            assert_eq!(r.code, VS_OK);

            let mut health = VsHealth {
                crypto: -1,
                key_manager: -1,
                secure_boot: -1,
                event_logger: -1,
                can_monitor: -1,
                eth_monitor: -1,
                ids_engine: -1,
                firewall: -1,
                ota_validator: -1,
                anomaly: -1,
                integrity: -1,
                policy_engine: -1,
                storage: -1,
                hal: -1,
            };
            let r = unsafe { vs_get_health(core::ptr::from_mut(&mut health)) };
            assert_eq!(r.code, VS_OK);
            assert_eq!(health.crypto, 0, "crypto subsystem must be Ready");

            let r = vs_platform_shutdown();
            assert_eq!(r.code, VS_OK);

            let r = vs_platform_tick(2_000_000);
            assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

            reset();
        }

        #[test]
        fn prod_double_init_returns_already_initialized() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();

            register_provider(Box::new(SoftwareCryptoProvider::new(test_rng)))
                .expect("PENDING_PROVIDER mutex must not be poisoned in tests");
            let r = vs_platform_init();
            assert_eq!(r.code, VS_OK);

            // Second init without a pending provider returns NOT_INITIALIZED
            // (provider was consumed), which is the correct behaviour.
            let r2 = vs_platform_init();
            assert!(
                r2.code == VS_ERR_ALREADY_INITIALIZED || r2.code == VS_ERR_NOT_INITIALIZED,
                "second init must be rejected (code={})",
                r2.code
            );

            let _ = vs_platform_shutdown();
            reset();
        }

        #[test]
        fn prod_null_health_pointer_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();
            register_provider(Box::new(SoftwareCryptoProvider::new(test_rng)))
                .expect("PENDING_PROVIDER mutex must not be poisoned in tests");
            let _ = vs_platform_init();
            let r = unsafe { vs_get_health(core::ptr::null_mut()) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            let _ = vs_platform_shutdown();
            reset();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "mock-hsm"))]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Serialize all FFI tests since they share a global PLATFORM static.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// Since all tests share the global PLATFORM static, we run them
    /// sequentially in a single test function to avoid data races.
    #[test]
    fn ffi_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        // --- Operations before init return VS_ERR_NOT_INITIALIZED ---
        // Ensure we start clean (another test may have left state).
        reset_platform();

        let r = vs_platform_tick(0);
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        let mut health = VsHealth {
            crypto: -1,
            key_manager: -1,
            secure_boot: -1,
            event_logger: -1,
            can_monitor: -1,
            eth_monitor: -1,
            ids_engine: -1,
            firewall: -1,
            ota_validator: -1,
            anomaly: -1,
            integrity: -1,
            policy_engine: -1,
            storage: -1,
            hal: -1,
        };
        let r = unsafe { vs_get_health(core::ptr::from_mut(&mut health)) };
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        // --- Null pointer checks ---
        let r = unsafe { vs_get_health(core::ptr::null_mut()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        let r = unsafe { vs_submit_can_frame(core::ptr::null()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        let r = unsafe { vs_submit_eth_packet(core::ptr::null(), 10) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        // --- Init (fail-closed: no policy rules loaded) ---
        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // --- Tick after init ---
        let r = vs_platform_tick(1_000_000);
        assert_eq!(r.code, VS_OK);

        // --- Submit CAN frame (denied: no policy rules loaded) ---
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 8,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 2_000_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        // --- Submit Ethernet packet (denied: no policy rules loaded) ---
        let packet_data: [u8; 16] = [0u8; 16];
        let r = unsafe { vs_submit_eth_packet(packet_data.as_ptr(), packet_data.len()) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        // --- Get health ---
        let r = unsafe { vs_get_health(core::ptr::from_mut(&mut health)) };
        assert_eq!(r.code, VS_OK);
        // After init, all subsystems should be Ready (0).
        assert_eq!(health.crypto, 0);
        assert_eq!(health.can_monitor, 0);
        assert_eq!(health.ids_engine, 0);

        // --- Shutdown ---
        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        // --- After shutdown, operations return not-initialized ---
        let r = vs_platform_tick(3_000_000);
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
    }

    /// Helper to ensure the global PLATFORM is clean before and after each
    /// sequential test function.
    fn reset_platform() {
        if let Ok(mut guard) = lock_or_recover(&PLATFORM) {
            if let Some(platform) = guard.as_mut() {
                platform.shutdown();
            }
            *guard = None;
        }
        DEGRADED.store(false, Ordering::Release);
    }

    #[test]
    fn ffi_platform_init_then_shutdown_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(1_000);
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        reset_platform();
    }

    #[test]
    fn ffi_double_shutdown_returns_not_initialized() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);

        reset_platform();
    }

    #[test]
    fn ffi_double_init_returns_already_initialized() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_init();
        assert_eq!(r.code, VS_ERR_ALREADY_INITIALIZED);

        reset_platform();
    }

    #[test]
    fn ffi_tick_after_init_works() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(100);
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(200);
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(300);
        assert_eq!(r.code, VS_OK);

        reset_platform();
    }

    #[test]
    fn ffi_get_health_after_init_returns_valid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let mut health = VsHealth {
            crypto: -1,
            key_manager: -1,
            secure_boot: -1,
            event_logger: -1,
            can_monitor: -1,
            eth_monitor: -1,
            ids_engine: -1,
            firewall: -1,
            ota_validator: -1,
            anomaly: -1,
            integrity: -1,
            policy_engine: -1,
            storage: -1,
            hal: -1,
        };

        let r = unsafe { vs_get_health(core::ptr::from_mut(&mut health)) };
        assert_eq!(r.code, VS_OK);

        assert_eq!(health.crypto, 0); // Ready
        assert_eq!(health.key_manager, 0); // Ready
        assert_eq!(health.secure_boot, 3); // NotInitialized (requires explicit boot verification)
        assert_eq!(health.event_logger, 0); // Ready
        assert_eq!(health.can_monitor, 0); // Ready
        assert_eq!(health.eth_monitor, 0); // Ready
        assert_eq!(health.ids_engine, 0); // Ready
        assert_eq!(health.firewall, 0); // Ready
        assert_eq!(health.ota_validator, 3); // NotInitialized (requires explicit OTA setup)
        assert_eq!(health.anomaly, 0); // Ready
        assert_eq!(health.integrity, 0); // Ready
        assert_eq!(health.policy_engine, 0); // Ready

        reset_platform();
    }

    #[test]
    fn ffi_init_tick_multiple_times_shutdown() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        for ts in (1_000..10_000).step_by(1_000) {
            let r = vs_platform_tick(ts);
            assert_eq!(r.code, VS_OK);
        }

        let frame = VsCanFrame {
            id: 0x200,
            dlc: 4,
            data: [0xAB; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 10_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        reset_platform();
    }

    #[test]
    fn ffi_can_frame_dlc_validation() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Classic CAN with dlc > 8 should be rejected.
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 9,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        // CAN-FD with dlc > 64 should be rejected.
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 65,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 1,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        // CAN-FD with dlc = 64 passes validation but is denied by
        // fail-closed policy (no rules loaded).
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 64,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 1,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        reset_platform();
    }

    #[test]
    fn ffi_can_frame_id_validation() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Standard CAN with id > 0x7FF should be rejected.
        let frame = VsCanFrame {
            id: 0x800,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        // Extended CAN with id > 0x1FFFFFFF should be rejected.
        let frame = VsCanFrame {
            id: 0x2000_0000,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 1,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        // Extended CAN with id = 0x1FFFFFFF passes validation but is
        // denied by fail-closed policy (no rules loaded).
        let frame = VsCanFrame {
            id: 0x1FFF_FFFF,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 1,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        // Standard CAN with id = 0x7FF passes validation but is denied
        // by fail-closed policy (no rules loaded).
        let frame = VsCanFrame {
            id: 0x7FF,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        reset_platform();
    }

    #[test]
    fn ffi_eth_packet_oversized_rejected() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let big = vec![0u8; MAX_ETH_FRAME_LEN + 1];
        let r = unsafe { vs_submit_eth_packet(big.as_ptr(), big.len()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        reset_platform();
    }

    #[test]
    fn token_bucket_filling_and_consuming() {
        let mut bucket = TokenBucket::new(10, 1000);

        let start_us = 1_000_000;

        for _ in 0..10 {
            assert!(bucket.try_consume(start_us));
        }

        assert!(!bucket.try_consume(start_us));

        let mut t_us = start_us + 5_000;
        for _ in 0..5 {
            assert!(bucket.try_consume(t_us));
        }

        assert!(!bucket.try_consume(t_us));

        t_us += 20_000;
        for _ in 0..10 {
            assert!(bucket.try_consume(t_us));
        }
        assert!(!bucket.try_consume(t_us));
    }

    #[test]
    fn token_bucket_no_time_advance() {
        let mut bucket = TokenBucket::new(5, 1000);
        let t = 1_000_000;
        for _ in 0..5 {
            assert!(bucket.try_consume(t));
        }
        assert!(!bucket.try_consume(t));
    }

    #[test]
    fn token_bucket_clock_backwards_no_burst() {
        let mut bucket = TokenBucket::new(5, 1000);
        let t = 1_000_000;

        for _ in 0..5 {
            assert!(bucket.try_consume(t));
        }

        // Clock goes backward -- should NOT refill tokens.
        assert!(!bucket.try_consume(t - 500_000));
        assert!(!bucket.try_consume(t - 1_000_000));
    }

    #[test]
    fn token_bucket_reset() {
        let mut bucket = TokenBucket::new(5, 1000);
        let t = 1_000_000;
        for _ in 0..5 {
            assert!(bucket.try_consume(t));
        }
        assert!(!bucket.try_consume(t));

        bucket.reset();
        // After reset, full capacity should be available again.
        for _ in 0..5 {
            assert!(bucket.try_consume(t));
        }
        assert!(!bucket.try_consume(t));
    }

    #[test]
    fn ffi_vs_result_codes_distinct() {
        let codes = [
            VS_OK,
            VS_ERR_INVALID_ARG,
            VS_ERR_NOT_INITIALIZED,
            VS_ERR_INTERNAL,
            VS_ERR_RATE_LIMITED,
            VS_ERR_ALREADY_INITIALIZED,
            VS_ERR_CRYPTO,
            VS_ERR_RESOURCE_EXHAUSTED,
            VS_ERR_POLICY_VIOLATION,
            VS_ERR_AUTH_FAILURE,
            VS_ERR_TIMEOUT,
            VS_ERR_NOT_FOUND,
            VS_ERR_KEY_EXPIRED,
            VS_ERR_KEY_REVOKED,
            VS_ERR_STATE_CORRUPTED,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes[{i}] == codes[{j}]");
            }
        }
    }

    #[test]
    fn ffi_from_vs_error_maps_all_variants() {
        assert_eq!(
            VsResult::from_vs_error(VsError::NotInitialized).code,
            VS_ERR_NOT_INITIALIZED
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::CryptoError).code,
            VS_ERR_CRYPTO
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::ResourceExhausted).code,
            VS_ERR_RESOURCE_EXHAUSTED
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::PolicyViolation).code,
            VS_ERR_POLICY_VIOLATION
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::AuthenticationFailure).code,
            VS_ERR_AUTH_FAILURE
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::Timeout).code,
            VS_ERR_TIMEOUT
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::InvalidInput).code,
            VS_ERR_INVALID_ARG
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::InvalidConfig).code,
            VS_ERR_INVALID_ARG
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::NotFound).code,
            VS_ERR_NOT_FOUND
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::BusError).code,
            VS_ERR_INTERNAL
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::IntegrityFailure).code,
            VS_ERR_INTERNAL
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::StorageError).code,
            VS_ERR_INTERNAL
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::OverlappingRegion).code,
            VS_ERR_INTERNAL
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::KeyExpired).code,
            VS_ERR_KEY_EXPIRED
        );
        assert_eq!(
            VsResult::from_vs_error(VsError::KeyRevoked).code,
            VS_ERR_KEY_REVOKED
        );
    }

    #[test]
    fn ffi_eth_packet_zero_length_rejected() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Zero-length Ethernet frames are never valid on the wire.
        let data = [0u8; 1];
        let r = unsafe { vs_submit_eth_packet(data.as_ptr(), 0) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        reset_platform();
    }

    #[test]
    fn ffi_reinit_after_shutdown() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);
        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(100);
        assert_eq!(r.code, VS_OK);

        reset_platform();
    }

    #[test]
    fn status_to_i32_mappings() {
        assert_eq!(status_to_i32(SubsystemStatus::Ready), 0);
        assert_eq!(status_to_i32(SubsystemStatus::Degraded), 1);
        assert_eq!(status_to_i32(SubsystemStatus::Failed), 2);
        assert_eq!(status_to_i32(SubsystemStatus::NotInitialized), 3);
    }

    #[test]
    fn parse_raw_eth_packet_short() {
        let raw = [0u8; 5];
        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.ethertype, 0);
        assert!(pkt.vlan_id.is_none());
        assert!(pkt.dst_port.is_none());
    }

    #[test]
    fn parse_raw_eth_packet_vlan() {
        let mut raw = [0u8; 20];
        raw[12] = 0x81;
        raw[13] = 0x00;
        raw[14] = 0x00;
        raw[15] = 42;
        raw[16] = 0x08;
        raw[17] = 0x00;

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.vlan_id, Some(42));
        assert_eq!(pkt.ethertype, 0x0800);
        assert_eq!(pkt.payload.len(), 2);
    }

    /// Build a minimal IPv4 + TCP packet inside an Ethernet frame.
    fn build_ipv4_tcp_frame(dst_port: u16) -> Vec<u8> {
        let mut raw = vec![0u8; 14 + 20 + 4]; // eth + ip + tcp(src+dst port)
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45; // version 4, IHL 5
        raw[14 + 9] = 6; // TCP
        let port_bytes = dst_port.to_be_bytes();
        raw[14 + 20 + 2] = port_bytes[0];
        raw[14 + 20 + 3] = port_bytes[1];
        raw
    }

    #[test]
    fn parse_raw_eth_packet_ipv4_tcp_dst_port() {
        let raw = build_ipv4_tcp_frame(8080);
        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.ethertype, 0x0800);
        assert_eq!(pkt.dst_port, Some(8080));
    }

    #[test]
    fn parse_raw_eth_packet_ipv4_udp_dst_port() {
        let mut raw = vec![0u8; 14 + 20 + 4];
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45;
        raw[14 + 9] = 17; // UDP
        let port_bytes = 53u16.to_be_bytes();
        raw[14 + 20 + 2] = port_bytes[0];
        raw[14 + 20 + 3] = port_bytes[1];

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, Some(53));
    }

    #[test]
    fn parse_raw_eth_packet_ipv4_icmp_no_port() {
        let mut raw = vec![0u8; 14 + 20 + 8];
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45;
        raw[14 + 9] = 1; // ICMP

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, None);
    }

    #[test]
    fn parse_raw_eth_packet_non_ipv4_no_port() {
        let mut raw = vec![0u8; 42];
        raw[12] = 0x08;
        raw[13] = 0x06; // ARP

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.ethertype, 0x0806);
        assert_eq!(pkt.dst_port, None);
    }

    #[test]
    fn parse_raw_eth_packet_vlan_with_tcp_port() {
        let mut raw = vec![0u8; 18 + 20 + 4];
        raw[12] = 0x81;
        raw[13] = 0x00;
        raw[14] = 0x00;
        raw[15] = 100;
        raw[16] = 0x08;
        raw[17] = 0x00;
        raw[18] = 0x45;
        raw[18 + 9] = 6; // TCP
        let port_bytes = 443u16.to_be_bytes();
        raw[18 + 20 + 2] = port_bytes[0];
        raw[18 + 20 + 3] = port_bytes[1];

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.vlan_id, Some(100));
        assert_eq!(pkt.ethertype, 0x0800);
        assert_eq!(pkt.dst_port, Some(443));
    }

    #[test]
    fn parse_raw_eth_packet_truncated_ip_no_port() {
        let mut raw = vec![0u8; 14 + 10];
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45; // claims IHL=5 but only 10 bytes available

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, None);
    }

    #[test]
    fn extract_dst_port_with_ip_options() {
        // IPv4 header with options: IHL = 6 (24 bytes).
        let mut ip_payload = vec![0u8; 24 + 4];
        ip_payload[0] = 0x46; // version 4, IHL 6
        ip_payload[9] = 6; // TCP
        let port_bytes = 9090u16.to_be_bytes();
        ip_payload[24 + 2] = port_bytes[0];
        ip_payload[24 + 3] = port_bytes[1];

        assert_eq!(super::extract_dst_port(0x0800, &ip_payload), Some(9090));
    }

    // -----------------------------------------------------------------------
    // IPv6 port extraction tests (V5 fix)
    // -----------------------------------------------------------------------

    /// Build a minimal IPv6 + TCP packet payload (no Ethernet header).
    fn build_ipv6_tcp_payload(dst_port: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 40 + 4]; // IPv6 header + TCP src/dst port
        payload[0] = 0x60; // version 6
        payload[6] = 6; // Next Header: TCP
        payload[7] = 64; // Hop limit
        let port_bytes = dst_port.to_be_bytes();
        payload[40 + 2] = port_bytes[0];
        payload[40 + 3] = port_bytes[1];
        payload
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_tcp_dst_port() {
        let ipv6_payload = build_ipv6_tcp_payload(8443);
        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD; // IPv6
        raw.extend_from_slice(&ipv6_payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.ethertype, 0x86DD);
        assert_eq!(pkt.dst_port, Some(8443));
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_udp_dst_port() {
        let mut payload = vec![0u8; 40 + 4];
        payload[0] = 0x60;
        payload[6] = 17; // UDP
        let port_bytes = 5353u16.to_be_bytes();
        payload[40 + 2] = port_bytes[0];
        payload[40 + 3] = port_bytes[1];

        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw.extend_from_slice(&payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, Some(5353));
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_icmpv6_no_port() {
        let mut payload = vec![0u8; 40 + 8];
        payload[0] = 0x60;
        payload[6] = 58; // ICMPv6

        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw.extend_from_slice(&payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, None);
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_with_hop_by_hop_ext_header() {
        // IPv6 with Hop-by-Hop extension header, then TCP.
        let mut payload = vec![0u8; 40 + 8 + 4]; // IPv6 + ext header (8 bytes) + TCP ports
        payload[0] = 0x60;
        payload[6] = 0; // Next Header: Hop-by-Hop Options
                        // Extension header at offset 40:
        payload[40] = 6; // Next Header: TCP
        payload[41] = 0; // Length: 0 (meaning 8 bytes total)
                         // TCP src+dst ports at offset 48:
        let port_bytes = 9999u16.to_be_bytes();
        payload[48 + 2] = port_bytes[0];
        payload[48 + 3] = port_bytes[1];

        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw.extend_from_slice(&payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, Some(9999));
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_fragment_header() {
        // IPv6 with Fragment extension header (fixed 8 bytes), then TCP.
        let mut payload = vec![0u8; 40 + 8 + 4]; // IPv6 + fragment (8B) + TCP ports
        payload[0] = 0x60;
        payload[6] = 44; // Next Header: Fragment
                         // Fragment header at offset 40:
        payload[40] = 6; // Next Header: TCP
                         // Fragment header is 8 bytes fixed
        let port_bytes = 7777u16.to_be_bytes();
        payload[48 + 2] = port_bytes[0];
        payload[48 + 3] = port_bytes[1];

        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw.extend_from_slice(&payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, Some(7777));
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_truncated_returns_none() {
        // IPv6 packet truncated to less than 40 bytes.
        let mut raw = vec![0u8; 14 + 20];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw[14] = 0x60;

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, None);
    }

    #[test]
    fn parse_raw_eth_packet_ipv6_no_next_header() {
        // IPv6 with next_header = 59 (No Next Header).
        let mut payload = vec![0u8; 40];
        payload[0] = 0x60;
        payload[6] = 59; // No Next Header

        let mut raw = vec![0u8; 14];
        raw[12] = 0x86;
        raw[13] = 0xDD;
        raw.extend_from_slice(&payload);

        let pkt = parse_raw_eth_packet(&raw);
        assert_eq!(pkt.dst_port, None);
    }

    // -----------------------------------------------------------------------
    // Concurrent FFI tests
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_concurrent_can_frame_submission() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Spawn multiple threads submitting CAN frames concurrently.
        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                std::thread::spawn(move || {
                    let mut ok_count = 0u32;
                    let mut rate_limited_count = 0u32;
                    for i in 0..100 {
                        let frame = VsCanFrame {
                            id: (thread_id * 256 + i) & 0x7FF,
                            dlc: 8,
                            data: [thread_id as u8; 64],
                            is_extended: 0,
                            is_fd: 0,
                            timestamp_us: (i as u64 + 1) * 1000,
                        };
                        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
                        match r.code {
                            VS_OK | VS_ERR_POLICY_VIOLATION => ok_count += 1,
                            VS_ERR_RATE_LIMITED => rate_limited_count += 1,
                            other => panic!(
                                "Unexpected error code {other} from thread {thread_id} frame {i}"
                            ),
                        }
                    }
                    (ok_count, rate_limited_count)
                })
            })
            .collect();

        let mut total_ok = 0u32;
        for handle in handles {
            let (ok, _rl) = handle.join().expect("thread panicked");
            total_ok += ok;
        }
        // At least some frames should have been handled (ok or policy-denied).
        assert!(total_ok > 0, "No frames were handled");

        reset_platform();
    }

    #[test]
    fn ffi_concurrent_eth_packet_submission() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                std::thread::spawn(move || {
                    let mut ok_count = 0u32;
                    for _ in 0..50 {
                        let packet_data = [thread_id as u8; 64];
                        let r = unsafe {
                            vs_submit_eth_packet(packet_data.as_ptr(), packet_data.len())
                        };
                        if r.code == VS_OK || r.code == VS_ERR_POLICY_VIOLATION {
                            ok_count += 1;
                        }
                    }
                    ok_count
                })
            })
            .collect();

        let mut total_ok = 0u32;
        for handle in handles {
            total_ok += handle.join().expect("thread panicked");
        }
        assert!(total_ok > 0, "No packets were handled");

        reset_platform();
    }

    // -----------------------------------------------------------------------
    // Mutex recovery test
    // -----------------------------------------------------------------------

    #[test]
    fn lock_or_recover_works_on_healthy_mutex() {
        let mutex = std::sync::Mutex::new(42u32);
        let guard = super::lock_or_recover(&mutex).unwrap();
        assert_eq!(*guard, 42);
    }

    // -----------------------------------------------------------------------
    // V8: fail-closed default test
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_init_defaults_to_fail_closed() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // After default init (fail-closed), submitting a CAN frame with no
        // policy rules loaded should be blocked with PolicyViolation.
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 8,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 1_000_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        reset_platform();
    }

    #[test]
    fn ffi_init_tick_and_fail_closed_can() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let r = vs_platform_tick(1_000);
        assert_eq!(r.code, VS_OK);

        // No policy rules loaded -- always fail-closed.
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 8,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 2_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_POLICY_VIOLATION);

        reset_platform();
    }

    #[test]
    fn ffi_permissive_init_double_returns_already_initialized() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);
        let r = vs_platform_init();
        assert_eq!(r.code, VS_ERR_ALREADY_INITIALIZED);

        reset_platform();
    }

    // -----------------------------------------------------------------------
    // V8: degraded state test
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_degraded_flag_blocks_init() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        // Manually set degraded flag to simulate a poison recovery.
        DEGRADED.store(true, Ordering::Release);

        let r = vs_platform_init();
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        let r = vs_platform_init();
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        // Shutdown clears the degraded flag.
        let r = vs_platform_shutdown();
        // Returns not-initialized since platform was never init'd, but
        // still clears the degraded flag.
        assert_eq!(r.code, VS_ERR_NOT_INITIALIZED);
        assert!(!DEGRADED.load(Ordering::Acquire));

        // Now init should succeed.
        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        reset_platform();
    }

    #[test]
    fn ffi_degraded_flag_blocks_tick_and_submit() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Simulate poison recovery.
        DEGRADED.store(true, Ordering::Release);

        let r = vs_platform_tick(1_000);
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        let frame = VsCanFrame {
            id: 0x100,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 1_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        let packet = [0u8; 16];
        let r = unsafe { vs_submit_eth_packet(packet.as_ptr(), packet.len()) };
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        let mut health = VsHealth {
            crypto: -1,
            key_manager: -1,
            secure_boot: -1,
            event_logger: -1,
            can_monitor: -1,
            eth_monitor: -1,
            ids_engine: -1,
            firewall: -1,
            ota_validator: -1,
            anomaly: -1,
            integrity: -1,
            policy_engine: -1,
            storage: -1,
            hal: -1,
        };
        let r = unsafe { vs_get_health(core::ptr::from_mut(&mut health)) };
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        // vs_is_degraded should report 1.
        assert_eq!(vs_is_degraded(), 1);

        // Shutdown still works and clears the flag.
        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);
        assert_eq!(vs_is_degraded(), 0);

        reset_platform();
    }

    // -----------------------------------------------------------------------
    // V8: token bucket stall protection test
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_stall_clamps_refill() {
        let mut bucket = TokenBucket::new(10, 1000);
        let start_us = 1_000_000;

        // Drain all tokens.
        for _ in 0..10 {
            assert!(bucket.try_consume(start_us));
        }
        assert!(!bucket.try_consume(start_us));

        // Simulate a 60-second stall (VM suspend). Should only refill
        // up to MAX_STALL_US worth of tokens, not the full 60s.
        let after_stall = start_us + 60_000_000;
        // MAX_STALL_US = 30s, fill_rate = 1000/sec, so max refill = 30_000.
        // But capacity is 10, so we should get at most 10 tokens back.
        for _ in 0..10 {
            assert!(bucket.try_consume(after_stall));
        }
        assert!(!bucket.try_consume(after_stall));
    }

    #[test]
    fn token_bucket_stall_does_not_exceed_capacity() {
        let mut bucket = TokenBucket::new(5, 100);
        let start_us = 1_000_000;
        bucket.try_consume(start_us); // seed last_update_us

        // Giant time jump.
        let after = start_us + 100_000_000; // 100 seconds
                                            // fill_rate=100/sec, MAX_STALL_US=30s => max refill = 3000
                                            // but capacity=5 so can only hold 5.
        for _ in 0..5 {
            assert!(bucket.try_consume(after));
        }
        assert!(!bucket.try_consume(after));
    }

    // -----------------------------------------------------------------------
    // Concurrent + edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_can_submissions() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                std::thread::spawn(move || {
                    for i in 0..100u32 {
                        let frame = VsCanFrame {
                            id: (thread_id * 256 + i) & 0x7FF,
                            dlc: 8,
                            data: [thread_id as u8; 64],
                            is_extended: 0,
                            is_fd: 0,
                            timestamp_us: (i as u64 + 1) * 1000,
                        };
                        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
                        // Must be a valid result code, never an unknown value.
                        assert!(
                            r.code == VS_OK
                                || r.code == VS_ERR_RATE_LIMITED
                                || r.code == VS_ERR_INTERNAL
                                || r.code == VS_ERR_POLICY_VIOLATION
                                || r.code == VS_ERR_STATE_CORRUPTED,
                            "Unexpected error code {} from thread {} frame {}",
                            r.code,
                            thread_id,
                            i,
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            handle
                .join()
                .expect("thread panicked during concurrent CAN submission");
        }

        reset_platform();
    }

    #[test]
    fn degraded_state_blocks_operations() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // Manually enter degraded state.
        DEGRADED.store(true, Ordering::Release);

        // Tick should be blocked.
        let r = vs_platform_tick(1000);
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        // CAN frame submission should be blocked.
        let frame = VsCanFrame {
            id: 0x100,
            dlc: 1,
            data: [0u8; 64],
            is_extended: 0,
            is_fd: 0,
            timestamp_us: 2_000,
        };
        let r = unsafe { vs_submit_can_frame(core::ptr::from_ref(&frame)) };
        assert_eq!(r.code, VS_ERR_STATE_CORRUPTED);

        // Shutdown should clear degraded state.
        let r = vs_platform_shutdown();
        assert_eq!(r.code, VS_OK);
        assert!(!DEGRADED.load(Ordering::Acquire));

        reset_platform();
    }

    #[test]
    fn eth_min_frame_size_rejection() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_platform();

        let r = vs_platform_init();
        assert_eq!(r.code, VS_OK);

        // 10 bytes is less than the 14-byte Ethernet minimum.
        let short_packet = [0u8; 10];
        let r = unsafe { vs_submit_eth_packet(short_packet.as_ptr(), short_packet.len()) };
        assert_eq!(r.code, VS_ERR_INVALID_ARG);

        reset_platform();
    }

    // -------------------------------------------------------------------------
    // Post-quantum FFI output-buffer length-parameter regression tests.
    //
    // These exercise the `*_out_len` capacity parameters added to
    // `vs_pq_mlkem_encapsulate`, `vs_pq_mlkem_decapsulate`, and
    // `vs_pq_mldsa_sign` (breaking ABI change). The tests cover:
    //   - too-small output buffer  → VS_ERR_INVALID_ARG, no bytes written
    //   - zero-length output buffer → VS_ERR_INVALID_ARG, no bytes written
    //   - exact-size buffer        → length check passes (not rejected by
    //                                 the length guard)
    //   - oversized buffer         → trailing bytes are not touched
    //
    // The functions are only compiled with `feature = "pqc"`.
    // -------------------------------------------------------------------------

    #[cfg(feature = "pqc")]
    mod pq_buffer_validation {
        use super::*;
        use vs_crypto::{MLDSA65_SIGNATURE_LEN, MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN};

        const SENTINEL: u8 = 0xAA;

        // -- vs_pq_mlkem_encapsulate ------------------------------------------

        #[test]
        fn mlkem_encaps_too_small_ct_buffer_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let mut ct = [SENTINEL; MLKEM768_CIPHERTEXT_LEN - 1];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN];
            let r = unsafe {
                vs_pq_mlkem_encapsulate(0, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(ct.iter().all(|&b| b == SENTINEL), "ct must not be touched");
            assert!(ss.iter().all(|&b| b == SENTINEL), "ss must not be touched");
        }

        #[test]
        fn mlkem_encaps_too_small_ss_buffer_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let mut ct = [SENTINEL; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN - 1];
            let r = unsafe {
                vs_pq_mlkem_encapsulate(0, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(ct.iter().all(|&b| b == SENTINEL), "ct must not be touched");
            assert!(ss.iter().all(|&b| b == SENTINEL), "ss must not be touched");
        }

        #[test]
        fn mlkem_encaps_zero_len_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let mut ct = [SENTINEL; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN];
            let r = unsafe {
                vs_pq_mlkem_encapsulate(0, ct.as_mut_ptr(), 0, ss.as_mut_ptr(), ss.len())
            };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(ct.iter().all(|&b| b == SENTINEL));
            assert!(ss.iter().all(|&b| b == SENTINEL));
        }

        #[test]
        fn mlkem_encaps_exact_size_passes_length_check() {
            // Without a provisioned platform we cannot reach VS_OK, but we can
            // confirm that the *length* guard does not reject the call.
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            let mut ct = [SENTINEL; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN];
            let r = unsafe {
                vs_pq_mlkem_encapsulate(0, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            // The function should NOT return VS_ERR_INVALID_ARG due to the
            // length guard; instead it should report VS_ERR_NOT_INITIALIZED
            // (no platform) or another non-invalid-arg path.
            assert_ne!(r.code, VS_ERR_INVALID_ARG);
        }

        #[test]
        fn mlkem_encaps_oversized_buffer_does_not_touch_trailing_bytes() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            const PAD: usize = 16;
            let mut ct = [SENTINEL; MLKEM768_CIPHERTEXT_LEN + PAD];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN + PAD];
            let _ = unsafe {
                vs_pq_mlkem_encapsulate(0, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            // Regardless of whether the inner operation ran, no path may
            // write past the algorithm-fixed prefix.
            assert!(
                ct[MLKEM768_CIPHERTEXT_LEN..].iter().all(|&b| b == SENTINEL),
                "ct trailing bytes were written"
            );
            assert!(
                ss[MLKEM_SHARED_SECRET_LEN..].iter().all(|&b| b == SENTINEL),
                "ss trailing bytes were written"
            );
        }

        // -- vs_pq_mlkem_decapsulate ------------------------------------------

        #[test]
        fn mlkem_decaps_too_small_ss_buffer_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN - 1];
            let r = unsafe {
                vs_pq_mlkem_decapsulate(0, ct.as_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(ss.iter().all(|&b| b == SENTINEL), "ss must not be touched");
        }

        #[test]
        fn mlkem_decaps_zero_len_ss_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN];
            let r =
                unsafe { vs_pq_mlkem_decapsulate(0, ct.as_ptr(), ct.len(), ss.as_mut_ptr(), 0) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(ss.iter().all(|&b| b == SENTINEL));
        }

        #[test]
        fn mlkem_decaps_exact_size_passes_length_check() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            let ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN];
            let r = unsafe {
                vs_pq_mlkem_decapsulate(0, ct.as_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            // Length guard must not fire; we expect a downstream code
            // (not-initialized / not-found / crypto), never VS_ERR_INVALID_ARG.
            assert_ne!(r.code, VS_ERR_INVALID_ARG);
        }

        #[test]
        fn mlkem_decaps_oversized_ss_does_not_touch_trailing_bytes() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            const PAD: usize = 16;
            let ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [SENTINEL; MLKEM_SHARED_SECRET_LEN + PAD];
            let _ = unsafe {
                vs_pq_mlkem_decapsulate(0, ct.as_ptr(), ct.len(), ss.as_mut_ptr(), ss.len())
            };
            assert!(
                ss[MLKEM_SHARED_SECRET_LEN..].iter().all(|&b| b == SENTINEL),
                "ss trailing bytes were written"
            );
        }

        // -- vs_pq_mldsa_sign -------------------------------------------------

        #[test]
        fn mldsa_sign_too_small_sig_buffer_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let msg = b"hello";
            let mut sig = [SENTINEL; MLDSA65_SIGNATURE_LEN - 1];
            let r = unsafe {
                vs_pq_mldsa_sign(0, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), sig.len())
            };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(
                sig.iter().all(|&b| b == SENTINEL),
                "sig must not be touched"
            );
        }

        #[test]
        fn mldsa_sign_zero_len_sig_rejected() {
            let _lock = TEST_LOCK.lock().unwrap();
            let msg = b"hello";
            let mut sig = [SENTINEL; MLDSA65_SIGNATURE_LEN];
            let r = unsafe { vs_pq_mldsa_sign(0, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), 0) };
            assert_eq!(r.code, VS_ERR_INVALID_ARG);
            assert!(sig.iter().all(|&b| b == SENTINEL));
        }

        #[test]
        fn mldsa_sign_exact_size_passes_length_check() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            let msg = b"hello";
            let mut sig = [SENTINEL; MLDSA65_SIGNATURE_LEN];
            let r = unsafe {
                vs_pq_mldsa_sign(0, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), sig.len())
            };
            assert_ne!(r.code, VS_ERR_INVALID_ARG);
        }

        #[test]
        fn mldsa_sign_oversized_sig_does_not_touch_trailing_bytes() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset_platform();
            const PAD: usize = 16;
            let msg = b"hello";
            let mut sig = [SENTINEL; MLDSA65_SIGNATURE_LEN + PAD];
            let _ = unsafe {
                vs_pq_mldsa_sign(0, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), sig.len())
            };
            assert!(
                sig[MLDSA65_SIGNATURE_LEN..].iter().all(|&b| b == SENTINEL),
                "sig trailing bytes were written"
            );
        }
    }
}
