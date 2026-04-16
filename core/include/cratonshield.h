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
 * ABI version
 *
 * Packed as (major << 16) | (minor << 8) | patch.
 *
 * This is the SINGLE SOURCE OF TRUTH for the Craton Shield core C ABI.
 * The matching Rust constant (`vs_ffi::VS_ABI_VERSION`) is verified at
 * compile time to equal this value; if you bump one you MUST bump the
 * other in the same commit.
 *
 * Versioning policy (see ABI.md at repo root):
 *   - Major bump: breaking ABI change. Pre-existing C consumers MUST
 *     refuse to dispatch (call vs_abi_version() at init and compare).
 *   - Minor bump: backward-compatible additions.
 *   - Patch bump: bug fixes / documentation that do not change layout.
 *
 * Downstream C consumers MUST call vs_abi_version() at init and abort
 * (or fall back to safe defaults) if its high 16 bits do not match the
 * high 16 bits of VS_ABI_VERSION from this header.
 * ----------------------------------------------------------------------- */

#define VS_ABI_VERSION 0x00010000

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
 * ABI version query
 * ----------------------------------------------------------------------- */

/**
 * Return the packed ABI version of the linked libcratonshield.
 *
 * Encoding: (major << 16) | (minor << 8) | patch.
 *
 * Downstream C consumers SHOULD call this immediately after loading the
 * shared library and SHOULD refuse to dispatch any further vs_* call if
 * the major component disagrees with the VS_ABI_VERSION constant defined
 * in the cratonshield.h header that the consumer was compiled against:
 *
 *     uint32_t abi = vs_abi_version();
 *     if ((abi >> 16) != (VS_ABI_VERSION >> 16)) {
 *         // ABI mismatch — refuse to dispatch.
 *         abort();
 *     }
 *
 * @return The packed ABI version.
 */
uint32_t vs_abi_version(void);

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

/* -----------------------------------------------------------------------
 * Post-quantum cryptography (feature = "pqc")
 *
 * The following functions are only present when libcratonshield is built
 * with the `pqc` Cargo feature. They expose ML-KEM-768 (FIPS 203) and
 * ML-DSA-65 (FIPS 204) operations.
 *
 * Each output-pointer parameter is paired with an explicit length parameter
 * (`*_out_len`) giving the capacity of the buffer in bytes. The FFI layer
 * validates the length BEFORE any writes; if the provided capacity is less
 * than the fixed algorithm output size, the function returns
 * VS_ERR_INVALID_ARG and does not modify the buffer. The required sizes
 * are:
 *
 *   - ML-KEM-768 ciphertext       : 1088 bytes
 *   - ML-KEM-768 shared secret    :   32 bytes
 *   - ML-DSA-65  signature        : 3309 bytes
 *   - ML-DSA-65  public key       : 1952 bytes
 *
 * Key-provisioning seeds (passed to vs_pq_provision_*) must come from a
 * cryptographically secure RNG / TRNG and have the exact lengths shown
 * below (any other length returns VS_ERR_INVALID_ARG):
 *
 *   - ML-KEM-768 seed (d || z, FIPS 203): 64 bytes
 *   - ML-DSA-65  seed (xi,      FIPS 204): 32 bytes
 * ----------------------------------------------------------------------- */

/**
 * Provision an ML-KEM-768 key slot from a 64-byte TRNG seed (FIPS 203
 * d || z byte string).
 *
 * @param slot       ML-KEM key slot index (0 .. KEY_SLOTS).
 * @param seed       Pointer to exactly 64 bytes of cryptographically random
 *                   seed material. Must not be NULL.
 * @param seed_len   Must be exactly 64. Returns VS_ERR_INVALID_ARG otherwise.
 *                   This parameter exists so callers cannot accidentally
 *                   pass a shorter buffer that would cause an out-of-bounds
 *                   read.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if seed is NULL or seed_len != 64,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO / VS_ERR_NOT_FOUND / VS_ERR_RESOURCE_EXHAUSTED on
 *         key-store errors.
 */
VsResult vs_pq_provision_mlkem_key(uint32_t slot,
                                   const uint8_t *seed, size_t seed_len);

/**
 * Provision an ML-DSA-65 signing key slot from a 32-byte TRNG seed
 * (FIPS 204 xi).
 *
 * @param slot       ML-DSA key slot index (0 .. KEY_SLOTS).
 * @param seed       Pointer to exactly 32 bytes of cryptographically random
 *                   seed material. Must not be NULL.
 * @param seed_len   Must be exactly 32. Returns VS_ERR_INVALID_ARG otherwise.
 *                   This parameter exists so callers cannot accidentally
 *                   pass a shorter buffer that would cause an out-of-bounds
 *                   read.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if seed is NULL or seed_len != 32,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO / VS_ERR_NOT_FOUND / VS_ERR_RESOURCE_EXHAUSTED on
 *         key-store errors.
 */
VsResult vs_pq_provision_mldsa_key(uint32_t slot,
                                   const uint8_t *seed, size_t seed_len);

/**
 * ML-KEM-768 encapsulation (FIPS 203).
 *
 * Writes 1088 ciphertext bytes to ct_out and 32 shared-secret bytes to
 * ss_out. Randomness is supplied internally by the PQ provider's RNG.
 *
 * @param slot        ML-KEM key slot (must have been provisioned).
 * @param ct_out      Output buffer for the 1088-byte ciphertext. Must not be NULL.
 * @param ct_out_len  Capacity of ct_out in bytes; must be >= 1088.
 * @param ss_out      Output buffer for the 32-byte shared secret. Must not be NULL.
 * @param ss_out_len  Capacity of ss_out in bytes; must be >= 32.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if any pointer is NULL or any *_out_len is too small,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO / VS_ERR_NOT_FOUND on key-slot / crypto errors.
 */
VsResult vs_pq_mlkem_encapsulate(uint32_t slot,
                                 uint8_t *ct_out, size_t ct_out_len,
                                 uint8_t *ss_out, size_t ss_out_len);

/**
 * ML-KEM-768 decapsulation (FIPS 203).
 *
 * Reads 1088 ciphertext bytes from ct_in and writes the 32-byte shared
 * secret to ss_out.
 *
 * @param slot        ML-KEM key slot (must have been provisioned).
 * @param ct_in       Pointer to the 1088-byte ciphertext.
 * @param ct_len      Must be exactly 1088 (MLKEM768_CIPHERTEXT_LEN).
 * @param ss_out      Output buffer for the 32-byte shared secret. Must not be NULL.
 * @param ss_out_len  Capacity of ss_out in bytes; must be >= 32.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if a pointer is NULL, ct_len != 1088, or
 *                            ss_out_len < 32,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO / VS_ERR_NOT_FOUND on key-slot / crypto errors.
 */
VsResult vs_pq_mlkem_decapsulate(uint32_t slot,
                                 const uint8_t *ct_in, size_t ct_len,
                                 uint8_t *ss_out, size_t ss_out_len);

/**
 * ML-DSA-65 signing (FIPS 204).
 *
 * Signs msg_len bytes from msg_in and writes the 3309-byte signature to
 * sig_out.
 *
 * @param slot         ML-DSA key slot (must have been provisioned).
 * @param msg_in       Pointer to message bytes. Must not be NULL.
 * @param msg_len      Message length in bytes. Must be in [1, 65535].
 * @param sig_out      Output buffer for the 3309-byte signature. Must not be NULL.
 * @param sig_out_len  Capacity of sig_out in bytes; must be >= 3309.
 * @return VS_OK on success,
 *         VS_ERR_INVALID_ARG if a pointer is NULL, msg_len is out of range,
 *                            or sig_out_len < 3309,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO / VS_ERR_NOT_FOUND on key-slot / crypto errors.
 */
VsResult vs_pq_mldsa_sign(uint32_t slot,
                          const uint8_t *msg_in, size_t msg_len,
                          uint8_t *sig_out, size_t sig_out_len);

/**
 * ML-DSA-65 signature verification (FIPS 204).
 *
 * Returns VS_OK if sig_in is a valid ML-DSA-65 signature over
 * msg_in[0..msg_len] for the 1952-byte public key in pub_key_in. Returns
 * VS_ERR_CRYPTO if the signature is structurally valid but does not
 * verify against the supplied key and message.
 *
 * Unlike the *_sign / *_encapsulate / *_decapsulate functions this entry
 * point does not consult any provisioned key slot — the public key is
 * supplied directly by the caller, so verification of externally-attested
 * signatures (OTA bundles, peer-supplied attestations) does not require a
 * preceding provision step.
 *
 * @param pub_key_in   Pointer to the 1952-byte ML-DSA-65 public key.
 *                     Must not be NULL.
 * @param pub_key_len  Must be exactly 1952 (MLDSA65_PUBLIC_KEY_LEN).
 * @param msg_in       Pointer to the signed message bytes. Must not be NULL.
 * @param msg_len      Message length in bytes. Must be in [1, 65535]. The
 *                     64 KiB upper bound prevents stack overflow inside the
 *                     ML-DSA internal hashing.
 * @param sig_in       Pointer to the 3309-byte signature. Must not be NULL.
 * @param sig_len      Must be exactly 3309 (MLDSA65_SIGNATURE_LEN).
 * @return VS_OK if the signature verifies,
 *         VS_ERR_INVALID_ARG if any pointer is NULL or any length is wrong,
 *         VS_ERR_NOT_INITIALIZED if the platform has not been initialized,
 *         VS_ERR_CRYPTO if the signature is structurally valid but does not
 *                       verify against (pub_key, msg).
 */
VsResult vs_pq_mldsa_verify(const uint8_t *pub_key_in, size_t pub_key_len,
                            const uint8_t *msg_in,     size_t msg_len,
                            const uint8_t *sig_in,     size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* CRATONSHIELD_H */
