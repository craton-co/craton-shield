// SPDX-License-Identifier: Apache-2.0
/**
 * Craton Shield C Integration Test
 *
 * Validates the FFI interface by exercising the full platform lifecycle:
 *   init -> tick -> submit CAN/Ethernet -> get health -> shutdown
 *
 * Build (Linux/macOS):
 *   cargo build --release --package vs-ffi
 *   gcc -Wall -Wextra -Wpedantic -std=c11 -o test_vs tests/c/test.c \
 *       -I include -L target/release -lcratonshield -lpthread -ldl -lm
 *   ./test_vs
 *
 * Build (Windows / MSVC):
 *   cargo build --release --package vs-ffi
 *   cl /W4 /std:c11 tests\c\test.c /I include \
 *      target\release\cratonshield.lib ws2_32.lib userenv.lib bcrypt.lib ntdll.lib
 *   test.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cratonshield.h"

/* -----------------------------------------------------------------------
 * Test helpers
 * ----------------------------------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg)                                          \
    do {                                                                \
        tests_run++;                                                    \
        if (!(expr)) {                                                  \
            fprintf(stderr, "  FAIL: %s (line %d): %s\n",              \
                    (msg), __LINE__, #expr);                            \
            tests_failed++;                                             \
        } else {                                                        \
            printf("  PASS: %s\n", (msg));                              \
            tests_passed++;                                             \
        }                                                               \
    } while (0)

/* -----------------------------------------------------------------------
 * Tests
 * ----------------------------------------------------------------------- */

/** Before init, all operations should return VS_ERR_NOT_INITIALIZED. */
static void test_pre_init(void)
{
    printf("[test_pre_init]\n");

    VsResult r = vs_platform_tick(0);
    TEST_ASSERT(r.code == VS_ERR_NOT_INITIALIZED,
                "tick before init returns NOT_INITIALIZED");

    r = vs_platform_shutdown();
    TEST_ASSERT(r.code == VS_ERR_NOT_INITIALIZED,
                "shutdown before init returns NOT_INITIALIZED");

    VsHealth health;
    memset(&health, 0xFF, sizeof(health));
    r = vs_get_health(&health);
    TEST_ASSERT(r.code == VS_ERR_NOT_INITIALIZED,
                "get_health before init returns NOT_INITIALIZED");
}

/** Null pointer arguments should return VS_ERR_INVALID_ARG. */
static void test_null_pointers(void)
{
    printf("[test_null_pointers]\n");

    VsResult r = vs_submit_can_frame(NULL);
    TEST_ASSERT(r.code == VS_ERR_INVALID_ARG,
                "submit_can_frame(NULL) returns INVALID_ARG");

    r = vs_submit_eth_packet(NULL, 10);
    TEST_ASSERT(r.code == VS_ERR_INVALID_ARG,
                "submit_eth_packet(NULL, 10) returns INVALID_ARG");

    r = vs_get_health(NULL);
    TEST_ASSERT(r.code == VS_ERR_INVALID_ARG,
                "get_health(NULL) returns INVALID_ARG");
}

/** Platform init should succeed. */
static void test_init(void)
{
    printf("[test_init]\n");

    VsResult r = vs_platform_init();
    TEST_ASSERT(r.code == VS_OK, "platform init succeeds");
}

/** After init, tick should work. */
static void test_tick(void)
{
    printf("[test_tick]\n");

    for (uint64_t ts = 1000; ts <= 10000; ts += 1000) {
        VsResult r = vs_platform_tick(ts);
        TEST_ASSERT(r.code == VS_OK, "tick succeeds");
    }
}

/** Submit a standard CAN frame. */
static void test_submit_can_frame(void)
{
    printf("[test_submit_can_frame]\n");

    VsCanFrame frame;
    memset(&frame, 0, sizeof(frame));
    frame.id           = 0x100;
    frame.dlc          = 8;
    frame.is_extended  = 0;
    frame.is_fd        = 0;
    frame.timestamp_us = 20000;
    frame.data[0]      = 0xAA;
    frame.data[1]      = 0xBB;

    VsResult r = vs_submit_can_frame(&frame);
    TEST_ASSERT(r.code == VS_OK, "submit standard CAN frame");
}

/** Submit a CAN-FD frame. */
static void test_submit_canfd_frame(void)
{
    printf("[test_submit_canfd_frame]\n");

    VsCanFrame frame;
    memset(&frame, 0, sizeof(frame));
    frame.id           = 0x1ABCDEF0;
    frame.dlc          = 64;
    frame.is_extended  = 1;
    frame.is_fd        = 1;
    frame.timestamp_us = 30000;

    for (int i = 0; i < 64; i++) {
        frame.data[i] = (uint8_t)(i & 0xFF);
    }

    VsResult r = vs_submit_can_frame(&frame);
    TEST_ASSERT(r.code == VS_OK, "submit CAN-FD frame");
}

/** Submit an Ethernet packet (raw bytes). */
static void test_submit_eth_packet(void)
{
    printf("[test_submit_eth_packet]\n");

    /* Minimal Ethernet-like payload (not a real frame, just raw data). */
    uint8_t packet[64];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0xFF;  /* dst MAC broadcast */
    packet[1] = 0xFF;
    packet[2] = 0xFF;
    packet[3] = 0xFF;
    packet[4] = 0xFF;
    packet[5] = 0xFF;

    VsResult r = vs_submit_eth_packet(packet, sizeof(packet));
    TEST_ASSERT(r.code == VS_OK, "submit Ethernet packet");
}

/** Health check after init should report all subsystems Ready (0). */
static void test_health(void)
{
    printf("[test_health]\n");

    VsHealth health;
    memset(&health, 0xFF, sizeof(health));

    VsResult r = vs_get_health(&health);
    TEST_ASSERT(r.code == VS_OK, "get_health succeeds");

    TEST_ASSERT(health.crypto        == 0, "crypto is Ready");
    TEST_ASSERT(health.key_manager   == 0, "key_manager is Ready");
    TEST_ASSERT(health.secure_boot   == 0, "secure_boot is Ready");
    TEST_ASSERT(health.event_logger  == 0, "event_logger is Ready");
    TEST_ASSERT(health.can_monitor   == 0, "can_monitor is Ready");
    TEST_ASSERT(health.eth_monitor   == 0, "eth_monitor is Ready");
    TEST_ASSERT(health.ids_engine    == 0, "ids_engine is Ready");
    TEST_ASSERT(health.firewall      == 0, "firewall is Ready");
    TEST_ASSERT(health.ota_validator == 0, "ota_validator is Ready");
    TEST_ASSERT(health.anomaly       == 0, "anomaly is Ready");
    TEST_ASSERT(health.integrity     == 0, "integrity is Ready");
    TEST_ASSERT(health.policy_engine == 0, "policy_engine is Ready");
    TEST_ASSERT(health.storage       == 0, "storage is Ready");
    TEST_ASSERT(health.hal           == 0, "hal is Ready");
}

/** Shutdown and verify post-shutdown behavior. */
static void test_shutdown(void)
{
    printf("[test_shutdown]\n");

    VsResult r = vs_platform_shutdown();
    TEST_ASSERT(r.code == VS_OK, "shutdown succeeds");

    r = vs_platform_tick(99999);
    TEST_ASSERT(r.code == VS_ERR_NOT_INITIALIZED,
                "tick after shutdown returns NOT_INITIALIZED");

    r = vs_platform_shutdown();
    TEST_ASSERT(r.code == VS_ERR_NOT_INITIALIZED,
                "double shutdown returns NOT_INITIALIZED");
}

/** Re-init after shutdown should work (platform is reusable). */
static void test_reinit_after_shutdown(void)
{
    printf("[test_reinit_after_shutdown]\n");

    VsResult r = vs_platform_init();
    TEST_ASSERT(r.code == VS_OK, "re-init after shutdown succeeds");

    r = vs_platform_tick(1000);
    TEST_ASSERT(r.code == VS_OK, "tick after re-init succeeds");

    VsHealth health;
    r = vs_get_health(&health);
    TEST_ASSERT(r.code == VS_OK, "health after re-init succeeds");
    TEST_ASSERT(health.crypto == 0, "crypto Ready after re-init");

    r = vs_platform_shutdown();
    TEST_ASSERT(r.code == VS_OK, "final shutdown succeeds");
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== Craton Shield C Integration Test ===\n\n");

    test_pre_init();
    test_null_pointers();
    test_init();
    test_tick();
    test_submit_can_frame();
    test_submit_canfd_frame();
    test_submit_eth_packet();
    test_health();
    test_shutdown();
    test_reinit_after_shutdown();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
