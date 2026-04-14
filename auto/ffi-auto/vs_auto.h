// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//
// C header for vs-ffi-auto. Manually maintained — update when FFI surface changes.

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
} VsCryptoCallbacks;

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
                            // 3 = PolicyDenied, 4 = SessionsFull
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
uint64_t vs_auto_get_panic_count(void);
bool vs_auto_is_poisoned(void);

#ifdef __cplusplus
}
#endif

#endif // VS_AUTO_H
