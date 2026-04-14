// SPDX-License-Identifier: Apache-2.0
/**
 * Craton Shield — Automotive Cybersecurity Runtime Platform
 *
 * C API for embedded vehicle OS integration.
 * Compliant with ISO/SAE 21434, UN R155, and AUTOSAR.
 *
 * This header exposes the stable C ABI for the Craton Shield runtime.
 * Link against libcratonshield.a (static) or libcratonshield.so / cratonshield.dll (shared).
 *
 * ## Thread Safety
 *
 * All vs_* functions are internally synchronized via mutexes and may be called
 * from any thread. However, the following constraints apply:
 *
 *  - vs_platform_init() / vs_platform_init_permissive() must be called exactly
 *    once before any other vs_* function. Calling init concurrently from
 *    multiple threads is safe (one will succeed, others return
 *    VS_ERR_ALREADY_INITIALIZED) but not recommended.
 *
 *  - vs_platform_shutdown() must not be called concurrently with other vs_*
 *    functions. After shutdown returns, all other calls return
 *    VS_ERR_NOT_INITIALIZED until re-initialization.
 *
 *  - vs_submit_can_frame() and vs_submit_eth_packet() may be called
 *    concurrently from different threads. Each acquires an independent rate
 *    limiter lock, then the shared platform lock.
 *
 * ## Panic Strategy
 *
 * All extern "C" functions are wrapped in catch_unwind() to prevent Rust panics
 * from unwinding across the FFI boundary (which is undefined behaviour in C).
 *
 * IMPORTANT: The vs-ffi crate MUST be compiled with panic="unwind" (NOT
 * panic="abort"). Use the `release-safe` profile:
 *
 *     cargo build -p vs-ffi --profile release-safe
 *
 * The workspace Cargo.toml defines this profile with all release optimizations
 * but panic="unwind". Do NOT build vs-ffi with the default `--release` profile
 * (which uses panic="abort"). With panic="abort", catch_unwind becomes a no-op
 * and any internal Rust panic will abort the process immediately.
 *
 * When a panic is caught, the function returns VS_ERR_STATE_CORRUPTED and the
 * platform enters degraded state. Poll vs_is_degraded() or check return codes
 * after each call. Recovery: vs_platform_shutdown() then vs_platform_init().
 */

#ifndef CRATONSHIELD_H
#define CRATONSHIELD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Result codes
 * ----------------------------------------------------------------------- */

/** Result type returned by every FFI function. */
typedef struct {
    int32_t code;
} VsResult;

/** Operation completed successfully. */
#define VS_OK                    0
/** A pointer argument was null or otherwise invalid. */
#define VS_ERR_INVALID_ARG      (-1)
/** The platform has not been initialized yet. */
#define VS_ERR_NOT_INITIALIZED  (-2)
/** An internal error occurred (e.g. mutex poisoned, unexpected failure). */
#define VS_ERR_INTERNAL         (-3)
/** The rate limiter blocked the request (too many events). */
#define VS_ERR_RATE_LIMITED     (-4)
/** The platform has already been initialized. */
#define VS_ERR_ALREADY_INITIALIZED (-5)
/** A cryptographic operation failed. */
#define VS_ERR_CRYPTO               (-6)
/** A resource limit was reached (e.g., rule table full). */
#define VS_ERR_RESOURCE_EXHAUSTED   (-7)
/** A security policy violation was detected. */
#define VS_ERR_POLICY_VIOLATION     (-8)
/** Authentication failed. */
#define VS_ERR_AUTH_FAILURE         (-9)
/** Operation timed out. */
#define VS_ERR_TIMEOUT              (-10)
/** The requested item was not found. */
#define VS_ERR_NOT_FOUND            (-11)
/** A key has expired. */
#define VS_ERR_KEY_EXPIRED          (-12)
/** A key has been revoked. */
#define VS_ERR_KEY_REVOKED          (-13)
/** Internal state corrupted after panic; shutdown + re-init required. */
#define VS_ERR_STATE_CORRUPTED      (-14)

/* -----------------------------------------------------------------------
 * CAN frame (CAN / CAN-FD)
 * ----------------------------------------------------------------------- */

/**
 * CAN / CAN-FD frame as seen by the C caller.
 *
 * NOTE: This struct's field order differs from the Rust `CanFrame` in
 * `vs-can-monitor`. The FFI layer performs the necessary field mapping.
 * Do NOT cast between `VsCanFrame*` and Rust `CanFrame*` directly.
 *
 * `is_extended` and `is_fd` use `uint8_t` instead of `bool` for FFI safety:
 * Rust's `bool` in `#[repr(C)]` requires exactly 0 or 1, while C callers may
 * pass any non-zero value for "true". Using `uint8_t` avoids undefined
 * behaviour from invalid bool representations.
 */
typedef struct {
    /** CAN arbitration ID (11-bit standard or 29-bit extended). */
    uint32_t id;
    /** Data length code. Classic CAN: 0-8, CAN-FD: 0-64. */
    uint8_t dlc;
    /** Frame payload (64 bytes to accommodate CAN-FD). */
    uint8_t data[64];
    /** Non-zero if this is a 29-bit extended frame. */
    uint8_t is_extended;
    /** Non-zero if this is a CAN-FD frame. */
    uint8_t is_fd;
    /** Monotonic timestamp in microseconds. */
    uint64_t timestamp_us;
} VsCanFrame;

/* -----------------------------------------------------------------------
 * Health status
 * ----------------------------------------------------------------------- */

/**
 * Subsystem health snapshot.
 *
 * Each field encodes a SubsystemStatus as an int32_t:
 *   0 = Ready
 *   1 = Degraded
 *   2 = Failed
 *   3 = NotInitialized
 */
typedef struct {
    int32_t crypto;
    int32_t key_manager;
    int32_t secure_boot;
    int32_t event_logger;
    int32_t can_monitor;
    int32_t eth_monitor;
    int32_t ids_engine;
    int32_t firewall;
    int32_t ota_validator;
    int32_t anomaly;
    int32_t integrity;
    int32_t policy_engine;
    int32_t storage;
    int32_t hal;
} VsHealth;

/* -----------------------------------------------------------------------
 * ABI stability guards
 *
 * These assertions catch ABI mismatches between this header and the Rust
 * FFI layer at compile time.  If a static assert fires, the header and
 * Rust struct layouts have diverged and must be reconciled.
 * ----------------------------------------------------------------------- */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(VsResult)   ==  4, "VsResult size mismatch with Rust FFI");
_Static_assert(sizeof(VsCanFrame) == 80, "VsCanFrame size mismatch with Rust FFI");
_Static_assert(sizeof(VsHealth)   == 56, "VsHealth size mismatch with Rust FFI");
#endif

/* -----------------------------------------------------------------------
 * Platform lifecycle
 * ----------------------------------------------------------------------- */

/**
 * Initialize the platform with default (fail-closed) configuration.
 *
 * Must be called before any other vs_* function.
 * Frames arriving before policy rules are loaded will be **blocked**.
 *
 * @return VS_OK on success, VS_ERR_INTERNAL on failure,
 *         VS_ERR_STATE_CORRUPTED if the platform is in degraded state.
 */
VsResult vs_platform_init(void);

/**
 * Initialize the platform in permissive (fail-open) mode.
 *
 * Identical to vs_platform_init() except that frames arriving before
 * any policy rules are loaded are **allowed** through instead of blocked.
 * Use only during development or bring-up; production should use
 * vs_platform_init().
 *
 * @return VS_OK on success, VS_ERR_INTERNAL on failure,
 *         VS_ERR_STATE_CORRUPTED if the platform is in degraded state.
 */
VsResult vs_platform_init_permissive(void);

/**
 * Tick the platform.
 *
 * Must be called periodically (recommended: every 1-10 ms).
 * Drives watchdog, telemetry flush, IDS expiry, and firewall rule cleanup.
 *
 * @param timestamp_us  Current monotonic time in microseconds.
 * @return VS_OK on success,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_INTERNAL on internal error.
 */
VsResult vs_platform_tick(uint64_t timestamp_us);

/**
 * Submit a CAN frame for analysis.
 *
 * The IDS engine, anomaly detectors, and CAN monitor process the frame.
 * Alerts are dispatched according to the active policy.
 *
 * @param frame  Pointer to a valid VsCanFrame. Must not be NULL.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if frame is NULL,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_RATE_LIMITED if the global FFI rate limit is exceeded.
 */
VsResult vs_submit_can_frame(const VsCanFrame *frame);

/**
 * Submit an Ethernet packet for analysis.
 *
 * The IDS engine, SOME/IP parser, DoIP parser, and Ethernet monitor
 * process the packet. Alerts are dispatched according to the active policy.
 *
 * @param data  Pointer to raw Ethernet frame bytes. Must not be NULL if len > 0.
 * @param len   Length of the data buffer in bytes.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if data is NULL and len > 0,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_RATE_LIMITED if the global FFI rate limit is exceeded.
 */
VsResult vs_submit_eth_packet(const uint8_t *data, size_t len);

/**
 * Retrieve the current health status of the platform.
 *
 * @param out  Pointer to a VsHealth struct to fill. Must not be NULL.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if out is NULL,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized.
 */
VsResult vs_get_health(VsHealth *out);

/**
 * Return the number of panics caught by FFI boundary guards since init.
 *
 * A non-zero value indicates internal errors that should be investigated.
 *
 * @return The cumulative panic count.
 */
uint64_t vs_get_panic_count(void);

/**
 * Return the number of poisoned mutex recoveries since init.
 *
 * A non-zero value indicates internal state corruption from a panic.
 * The platform should be shut down and re-initialized.
 *
 * @return The cumulative poisoned mutex recovery count.
 */
uint64_t vs_get_poisoned_mutex_count(void);

/**
 * Return 1 if the platform is in degraded state, 0 otherwise.
 *
 * The platform enters degraded state after a poisoned mutex recovery.
 * All FFI calls except vs_platform_shutdown() will return
 * VS_ERR_STATE_CORRUPTED until a shutdown + re-init cycle.
 *
 * IMPORTANT: C integrators should poll this function (or check for
 * VS_ERR_STATE_CORRUPTED returns) after every vs_submit_* or vs_platform_tick
 * call. When degraded, the platform's internal state may be inconsistent.
 * The recommended recovery procedure is:
 *   1. Call vs_platform_shutdown()
 *   2. Log the incident (vs_get_panic_count(), vs_get_poisoned_mutex_count())
 *   3. Call vs_platform_init() to re-initialize
 *
 * Continuing to operate in degraded state without re-initialization may
 * result in missed alerts, incorrect policy decisions, or silent failures.
 *
 * @return 1 if degraded, 0 if healthy.
 */
uint64_t vs_is_degraded(void);

/**
 * Shut down the platform and release all resources.
 *
 * After this call, all functions except vs_platform_init() will return
 * VS_ERR_NOT_INITIALIZED.
 *
 * @return VS_OK on success,
 *         VS_ERR_NOT_INITIALIZED if already shut down.
 */
VsResult vs_platform_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* CRATONSHIELD_H */
