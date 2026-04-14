// SPDX-License-Identifier: Apache-2.0
/*
 * Craton Shield Core — C FFI Usage Example
 *
 * Demonstrates how to call the Craton Shield runtime from C through the
 * Foreign Function Interface (FFI) exported by the `vs-ffi` crate.
 *
 * NOTE: This example links against the non-production build by default.
 * Production builds require `cargo build --release -p vs-ffi --features production`
 * and a real crypto provider.
 *
 * Build instructions (Linux / macOS):
 *
 *   # 1. Build the Rust shared library first:
 *   cargo build --release -p vs-ffi
 *
 *   # 2. Compile and link this example:
 *   gcc -O2 -Wall -Wextra -o ffi_example examples/ffi_example.c \
 *       -Iinclude -L target/release -lvs_ffi -lpthread -ldl -lm
 *
 *   # 3. Run (ensure the shared library is on the library path):
 *   LD_LIBRARY_PATH=target/release ./ffi_example        # Linux
 *   DYLD_LIBRARY_PATH=target/release ./ffi_example      # macOS
 *
 * Build instructions (Windows, MSVC):
 *
 *   cargo build --release -p vs-ffi
 *   cl /W4 /O2 /Iinclude examples\ffi_example.c /link /LIBPATH:target\release vs_ffi.dll.lib
 *   set PATH=target\release;%PATH%
 *   ffi_example.exe
 */

#include <stdio.h>
#include <string.h>

#include "cratonshield.h"

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static const char *result_str(int32_t code)
{
    switch (code) {
    case VS_OK:                   return "OK";
    case VS_ERR_INVALID_ARG:      return "INVALID_ARG";
    case VS_ERR_NOT_INITIALIZED:  return "NOT_INITIALIZED";
    case VS_ERR_INTERNAL:         return "INTERNAL";
    case VS_ERR_RATE_LIMITED:     return "RATE_LIMITED";
    case VS_ERR_ALREADY_INITIALIZED:     return "ALREADY_INITIALIZED";
    default:                      return "UNKNOWN";
    }
}

static const char *status_str(int32_t status)
{
    switch (status) {
    case 0: return "Ready";
    case 1: return "Degraded";
    case 2: return "Failed";
    case 3: return "NotInitialized";
    default: return "Unknown";
    }
}

static void print_health(const VsHealth *h)
{
    printf("  crypto        : %s\n", status_str(h->crypto));
    printf("  key_manager   : %s\n", status_str(h->key_manager));
    printf("  secure_boot   : %s\n", status_str(h->secure_boot));
    printf("  event_logger  : %s\n", status_str(h->event_logger));
    printf("  can_monitor   : %s\n", status_str(h->can_monitor));
    printf("  eth_monitor   : %s\n", status_str(h->eth_monitor));
    printf("  ids_engine    : %s\n", status_str(h->ids_engine));
    printf("  firewall      : %s\n", status_str(h->firewall));
    printf("  ota_validator : %s\n", status_str(h->ota_validator));
    printf("  anomaly       : %s\n", status_str(h->anomaly));
    printf("  integrity     : %s\n", status_str(h->integrity));
    printf("  policy_engine : %s\n", status_str(h->policy_engine));
    printf("  storage       : %s\n", status_str(h->storage));
    printf("  hal           : %s\n", status_str(h->hal));
}

/* -----------------------------------------------------------------------
 * Main — full lifecycle demonstration
 * ----------------------------------------------------------------------- */

int main(void)
{
    VsResult r;

    printf("=== Craton Shield FFI Example ===\n\n");

    /* ---- 1. Initialize the platform ---------------------------------- */
    printf("[1] Initializing platform...\n");
    r = vs_platform_init();
    printf("    vs_platform_init() => %s (%d)\n\n", result_str(r.code), r.code);
    if (r.code != VS_OK) {
        fprintf(stderr, "ERROR: platform init failed\n");
        return 1;
    }

    /* ---- 2. Submit CAN frames ---------------------------------------- */
    printf("[2] Submitting CAN frames...\n");

    /* Standard CAN frame: engine RPM broadcast (ID 0x0C0) */
    VsCanFrame can1;
    memset(&can1, 0, sizeof(can1));
    can1.id           = 0x0C0;
    can1.dlc          = 8;
    can1.data[0]      = 0x00;  /* RPM high byte */
    can1.data[1]      = 0x1A;  /* RPM low byte  */
    can1.data[2]      = 0x50;  /* coolant temp   */
    can1.is_extended  = 0;
    can1.is_fd        = 0;
    can1.timestamp_us = 1000;

    r = vs_submit_can_frame(&can1);
    printf("    CAN frame 0x%03X => %s (%d)\n", can1.id, result_str(r.code), r.code);
    if (r.code != VS_OK) {
        fprintf(stderr, "WARNING: CAN frame 0x%03X submission failed\n", can1.id);
    }

    /* Extended CAN-FD frame: OBD-II diagnostic request (29-bit ID) */
    VsCanFrame can2;
    memset(&can2, 0, sizeof(can2));
    can2.id           = 0x18DAF110;
    can2.dlc          = 12;
    can2.data[0]      = 0x02;  /* service ID length */
    can2.data[1]      = 0x01;  /* service 01: show current data */
    can2.data[2]      = 0x0D;  /* PID 0x0D: vehicle speed */
    can2.is_extended  = 1;
    can2.is_fd        = 1;
    can2.timestamp_us = 2000;

    r = vs_submit_can_frame(&can2);
    printf("    CAN-FD frame 0x%08X => %s (%d)\n\n", can2.id, result_str(r.code), r.code);
    if (r.code != VS_OK) {
        fprintf(stderr, "WARNING: CAN-FD frame 0x%08X submission failed\n", can2.id);
    }

    /* ---- 3. Submit an Ethernet packet -------------------------------- */
    printf("[3] Submitting Ethernet packet...\n");

    /* Minimal Ethernet frame: 14-byte header + 46-byte payload */
    uint8_t eth_frame[60];
    memset(eth_frame, 0, sizeof(eth_frame));

    /* Destination MAC: broadcast */
    memset(&eth_frame[0], 0xFF, 6);
    /* Source MAC: 02:00:00:00:00:01 (locally administered) */
    eth_frame[6]  = 0x02;
    eth_frame[11] = 0x01;
    /* EtherType: IPv4 (0x0800) */
    eth_frame[12] = 0x08;
    eth_frame[13] = 0x00;
    /* Payload: dummy data */
    eth_frame[14] = 0x45;  /* IPv4 version + IHL */

    r = vs_submit_eth_packet(eth_frame, sizeof(eth_frame));
    printf("    ETH packet (%u bytes) => %s (%d)\n\n",
           (unsigned)sizeof(eth_frame), result_str(r.code), r.code);
    if (r.code != VS_OK) {
        fprintf(stderr, "WARNING: ETH packet submission failed\n");
    }

    /* ---- 4. Tick the platform in a loop ------------------------------ */
    printf("[4] Running tick loop (10 iterations, 1 ms apart)...\n");
    for (uint64_t t = 10000; t <= 20000; t += 1000) {
        r = vs_platform_tick(t);
        if (r.code != VS_OK) {
            printf("    tick(%llu) => %s (%d)\n",
                   (unsigned long long)t, result_str(r.code), r.code);
        }
    }
    printf("    10 ticks completed successfully\n\n");

    /* ---- 5. Query health --------------------------------------------- */
    printf("[5] Querying subsystem health...\n");
    VsHealth health;
    memset(&health, 0xFF, sizeof(health));  /* poison to detect partial writes */

    r = vs_get_health(&health);
    printf("    vs_get_health() => %s (%d)\n", result_str(r.code), r.code);
    if (r.code == VS_OK) {
        print_health(&health);
    }
    printf("\n");

    /* ---- 6. Check panic count ---------------------------------------- */
    printf("[6] Checking panic count...\n");
    uint64_t panics = vs_get_panic_count();
    printf("    vs_get_panic_count() => %llu\n", (unsigned long long)panics);
    if (panics > 0) {
        fprintf(stderr, "WARNING: %llu panic(s) caught at FFI boundary\n",
                (unsigned long long)panics);
    }
    printf("\n");

    /* ---- 7. Shut down ------------------------------------------------ */
    printf("[7] Shutting down platform...\n");
    r = vs_platform_shutdown();
    printf("    vs_platform_shutdown() => %s (%d)\n\n", result_str(r.code), r.code);

    /* ---- 8. Verify post-shutdown behavior ---------------------------- */
    printf("[8] Verifying post-shutdown behavior...\n");
    r = vs_platform_tick(99999);
    printf("    vs_platform_tick() after shutdown => %s (%d) [expected: NOT_INITIALIZED]\n",
           result_str(r.code), r.code);

    printf("\n=== Example complete ===\n");
    return 0;
}
