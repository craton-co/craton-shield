// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//
// C header for vs-ffi-auto. Manually maintained — update when FFI surface changes.
//
// !!! ABI SYNC WARNING !!!
// This header MUST be kept in lockstep with the Rust definitions in
// `auto/ffi-auto/src/lib.rs`. If you add, remove, reorder, or change the
// signature of any field in a `#[repr(C)]` struct (in particular
// `VsCryptoCallbacks`), update BOTH sides in the same commit. Mismatched
// layouts cause the Rust side to read uninitialized memory through stale
// slots — an arbitrary-code-execution class bug.
//
// `VsCryptoCallbacks` carries a trailing `crypto_callbacks_size` field that
// every caller MUST set to `sizeof(VsCryptoCallbacks)`. The init function
// validates this matches the Rust-side `mem::size_of::<VsCryptoCallbacks>()`
// before dispatching through any callback; mismatches return
// `VS_ERR_INVALID_ARG`. This is a second line of defense — please still keep
// the header in sync.

#ifndef VS_AUTO_H
#define VS_AUTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define VS_OK                    0
#define VS_ERR_INVALID_ARG      -1
#define VS_ERR_NOT_INITIALIZED  -2
#define VS_ERR_INTERNAL         -3
#define VS_ERR_RATE_LIMITED     -4
#define VS_ERR_ALREADY_INITIALIZED -5
#define VS_ERR_INTEGRITY_FAILURE   -6
#define VS_ERR_MISALIGNED          -7

// Crypto callbacks magic number
#define VS_CRYPTO_CALLBACKS_MAGIC 0xC5A70001u

// -----------------------------------------------------------------------
// ABI version
//
// Packed as (major << 16) | (minor << 8) | patch.
//
// SINGLE SOURCE OF TRUTH for the vs-ffi-auto C ABI. The Rust constant
// `vs_ffi_auto::VS_ABI_VERSION` is verified at compile time to equal this
// value; if you bump one you MUST bump the other in the same commit.
//
// Versioning policy (see ABI.md at repo root):
//   - Major bump: breaking ABI change. Pre-existing C consumers MUST
//     refuse to dispatch.
//   - Minor bump: backward-compatible additions.
//   - Patch bump: bug fixes / documentation that do not change layout.
//
// Downstream C consumers MUST call vs_auto_abi_version() at init and
// abort (or fall back to safe defaults) if its high 16 bits do not match
// the high 16 bits of VS_ABI_VERSION from this header.
// -----------------------------------------------------------------------
#define VS_ABI_VERSION 0x00010000

typedef struct {
    int32_t code;
} VsResult;

typedef struct {
    uint32_t id;
    uint8_t dlc;
    uint8_t data[64];
    uint8_t is_extended;
    uint8_t is_fd;
    uint64_t timestamp_us;
} VsCanFrame;

typedef struct {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    uint16_t vlan_id;
    uint8_t has_vlan;
    uint8_t _padding;
    uint16_t dst_port;
    uint8_t has_dst_port;
    uint32_t payload_len;
    uint8_t payload[1500];
    uint64_t timestamp_us;
} VsEthPacket;

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
    int32_t signal_ids;
    int32_t v2x;
    int32_t diag_gateway;
} VsHealthAuto;

// Subsystem status values (returned in VsHealthAuto fields)
// 0 = Ready, 1 = Degraded, 2 = Failed, 3 = NotInitialized

typedef struct {
    uint32_t magic;     // Must be VS_CRYPTO_CALLBACKS_MAGIC
    void *context;      // Opaque context pointer forwarded to every callback
    int32_t (*sha256)(void *ctx, const uint8_t *data, size_t data_len, uint8_t *hash_out);
    int32_t (*hmac_sha256)(void *ctx, uint32_t key_id, const uint8_t *data, size_t data_len, uint8_t *mac_out);
    int32_t (*aes_gcm_encrypt)(void *ctx, uint32_t key_id, const uint8_t *nonce,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *plaintext, size_t pt_len,
                                uint8_t *ciphertext, uint8_t *tag);
    int32_t (*aes_gcm_decrypt)(void *ctx, uint32_t key_id, const uint8_t *nonce,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ciphertext, size_t ct_len,
                                const uint8_t *tag, uint8_t *plaintext);
    int32_t (*ecdh_derive_shared)(void *ctx, uint32_t key_id, const uint8_t *peer_pub, uint8_t *shared_out);
    int32_t (*sign_p256)(void *ctx, uint32_t key_id, const uint8_t *digest, uint8_t *sig_out);
    int32_t (*verify_p256)(void *ctx, const uint8_t *pub_key, const uint8_t *digest, const uint8_t *sig);
    int32_t (*random_bytes)(void *ctx, uint8_t *buf, size_t len);
    int32_t (*delete_key)(void *ctx, uint32_t key_id);
    int32_t (*generate_key)(void *ctx, uint32_t key_id, uint32_t key_type);
    // MUST be initialized by the caller to `sizeof(VsCryptoCallbacks)`.
    // `vs_auto_platform_init_with_crypto` validates this equals the
    // Rust-side `mem::size_of::<VsCryptoCallbacks>()` before invoking any
    // callback. Mismatch returns VS_ERR_INVALID_ARG and aborts init.
    // This catches ABI drift between this header and the Rust struct: if a
    // caller compiled against a stale header, trailing function-pointer
    // slots would be uninitialized memory and dispatching through them is
    // undefined behavior (potential RCE).
    size_t crypto_callbacks_size;
} VsCryptoCallbacks;

// -----------------------------------------------------------------------
// ABI version query
// -----------------------------------------------------------------------

// Return the packed ABI version of the linked libvs_ffi_auto.
//
// Encoding: (major << 16) | (minor << 8) | patch.
//
// Downstream C consumers SHOULD call this immediately after loading the
// shared library and SHOULD refuse to dispatch if the major component
// disagrees with VS_ABI_VERSION from this header:
//
//     uint32_t abi = vs_auto_abi_version();
//     if ((abi >> 16) != (VS_ABI_VERSION >> 16)) {
//         abort();
//     }
uint32_t vs_auto_abi_version(void);

// Platform lifecycle
VsResult vs_auto_platform_init(void);
VsResult vs_auto_platform_init_with_crypto(const VsCryptoCallbacks *callbacks);
VsResult vs_auto_platform_shutdown(void);

// Frame submission
VsResult vs_auto_submit_can_frame(const VsCanFrame *frame);
VsResult vs_auto_submit_eth_packet(const VsEthPacket *packet);

// LIN frame submission
typedef struct {
    uint8_t frame_id;
    uint8_t payload_len;
    uint8_t payload[8];
    uint64_t timestamp_us;
} VsLinFrame;

VsResult vs_auto_submit_lin_frame(const VsLinFrame *frame);

// FlexRay frame submission
typedef struct {
    uint16_t slot_id;
    uint8_t cycle;
    uint16_t payload_len;
    uint8_t payload[254];
    uint64_t timestamp_us;
} VsFlexRayFrame;

VsResult vs_auto_submit_flexray_frame(const VsFlexRayFrame *frame);

// UDS diagnostic gateway
typedef struct {
    uint16_t tester_addr;
    uint8_t sid;
    uint16_t payload_len;
    uint8_t payload[256];
    uint64_t timestamp_us;
} VsUdsRequest;

typedef struct {
    int32_t decision;       // 0 = Forward, 1 = Block, 2 = Challenge
    int32_t block_reason;   // 0 = Unauthorized, 1 = LockedOut, 2 = SessionExpired,
                            // 3 = PolicyDenied, 4 = SessionsFull,
                            // 5 = SecurityAccessDenied (NRC 0x33)
    uint8_t seed[16];       // Challenge seed (valid when decision == 2)
} VsUdsDecision;

VsResult vs_auto_uds_request(const VsUdsRequest *request, VsUdsDecision *decision_out);

// OTA manifest validation
typedef struct {
    uint32_t data_len;
    uint8_t data[4096];
    uint8_t expected_hash[32];
    uint64_t timestamp_us;
} VsOtaManifest;

VsResult vs_auto_validate_ota_manifest(const VsOtaManifest *manifest);

// Health monitoring
VsResult vs_auto_get_health(VsHealthAuto *out);

// Diagnostics
bool vs_auto_is_stub_crypto(void);
// Returns true if the platform was initialized via the stub (non-production)
// init path. Complements the compile-time `compile_error!` guard — C callers
// can detect at runtime whether the running library was initialized with the
// stub CryptoProvider and refuse to dispatch security-critical operations.
bool vs_auto_is_stub_initialized(void);
uint64_t vs_auto_get_panic_count(void);
bool vs_auto_is_poisoned(void);

// Lock strategy (perf review item 4)
//
// Default: single platform writer lock. Callers willing to accept the
// per-subsystem ordering documented in lib.rs may opt into
// VS_LOCK_STRATEGY_PER_SUBSYSTEM via vs_auto_set_lock_strategy().
#define VS_LOCK_STRATEGY_GLOBAL          0u
#define VS_LOCK_STRATEGY_PER_SUBSYSTEM   1u

VsResult vs_auto_set_lock_strategy(uint32_t strategy);
uint32_t vs_auto_get_lock_strategy(void);

#ifdef __cplusplus
}
#endif

#endif // VS_AUTO_H
