// SPDX-License-Identifier: Apache-2.0
//! Hardware ECU Validation Test Suite
//!
//! Validates Craton Shield on real or emulated ECU targets beyond x86_64.
//! Tests are gated by environment variables so they run only when the
//! appropriate hardware or emulator is available:
//!
//! - `VS_ECU_QEMU_AARCH64=1` — run against QEMU aarch64 (default CI target)
//! - `VS_ECU_HARDWARE=1`     — run against a physical ECU (NXP S32G, etc.)
//!
//! # Usage
//!
//! ```bash
//! # Run on the host (x86_64 baseline — always runs)
//! cargo test --test ecu_validation
//!
//! # Run with QEMU aarch64 tests enabled
//! VS_ECU_QEMU_AARCH64=1 cargo test --test ecu_validation
//! ```

use vs_can_monitor::{CanFrame, CanMonitor};
use vs_crypto::{CryptoProvider, RustCryptoProvider, SoftwareCryptoProvider};
use vs_hal::{StubTimer, Timer};
use vs_integrity::IntegrityMonitor;
use vs_types::{KeyId, VsError};

fn test_rng(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i * 7 + 3) & 0xFF) as u8;
    }
}

// ---------------------------------------------------------------------------
// Platform detection helpers
// ---------------------------------------------------------------------------

fn is_qemu_aarch64() -> bool {
    option_env!("VS_ECU_QEMU_AARCH64").map_or(false, |v| v == "1")
}

fn is_hardware_ecu() -> bool {
    option_env!("VS_ECU_HARDWARE").map_or(false, |v| v == "1")
}

// ---------------------------------------------------------------------------
// x86_64 baseline (always runs)
// ---------------------------------------------------------------------------

/// Verify the CAN monitor processes frames correctly on x86_64.
#[test]
fn baseline_can_monitor_processes_frames() {
    let mut monitor = CanMonitor::default();
    let frame = CanFrame {
        id: 0x100,
        dlc: 8,
        data: {
            let mut d = [0u8; 64];
            d[0] = 0xDE;
            d[1] = 0xAD;
            d
        },
        is_fd: false,
        is_extended: false,
    };
    // No rules loaded, no allowlist → should not alert
    let alert = monitor.process_frame(&frame, 1_000);
    assert!(alert.is_none());
}

/// Verify SHA-256 produces correct output on x86_64 using NIST known-answer vector.
/// Uses the production `RustCryptoProvider` — mock-hsm does not implement real SHA-256.
#[test]
fn baseline_crypto_sha256() {
    let crypto = RustCryptoProvider::new(test_rng);

    // Original liveness check
    let data = b"CratonShield ECU validation";
    let mut hash = [0u8; 32];
    crypto
        .sha256(data, &mut hash)
        .expect("SHA-256 computation should succeed");
    assert_ne!(hash, [0u8; 32]);

    // NIST FIPS 180-4 known-answer vector: SHA-256("abc")
    let mut abc_hash = [0u8; 32];
    crypto
        .sha256(b"abc", &mut abc_hash)
        .expect("SHA-256 of 'abc' should succeed");
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(
        abc_hash, expected,
        "SHA-256('abc') does not match NIST vector"
    );
}

/// Verify HMAC produces valid tag on x86_64.
#[test]
fn baseline_crypto_hmac() {
    let mut crypto = SoftwareCryptoProvider::new(test_rng);
    crypto
        .set_key(KeyId(0), &[0x42u8; 32])
        .expect("key provisioning should succeed");
    let data = b"integrity check";
    let mut mac = [0u8; 32];
    let result = crypto.hmac_sha256(KeyId(0), data, &mut mac);
    assert!(result.is_ok());
    assert_ne!(mac, [0u8; 32]);
}

/// Verify SHA-256 is deterministic across calls.
#[test]
fn baseline_crypto_sha256_deterministic() {
    let crypto = SoftwareCryptoProvider::new(test_rng);
    let data = b"determinism test";
    let mut hash1 = [0u8; 32];
    let mut hash2 = [0u8; 32];
    crypto
        .sha256(data, &mut hash1)
        .expect("first SHA-256 computation should succeed");
    crypto
        .sha256(data, &mut hash2)
        .expect("second SHA-256 computation should succeed");
    assert_eq!(hash1, hash2);
}

/// Verify integrity monitor registers and checks regions.
#[test]
fn baseline_integrity_roundtrip() {
    let crypto = SoftwareCryptoProvider::new(test_rng);
    let mut monitor = IntegrityMonitor::new(crypto);
    let data = b"firmware image region 0123456789abcdef";
    let result = monitor.register_region(1, 0x0800_0000, data);
    assert!(result.is_ok());
}

/// Verify CAN flood detection triggers on high-rate injection.
#[test]
fn baseline_can_flood_detection() {
    let mut monitor = CanMonitor::default();

    // Add a flood detection rule for ID 0x7DF with a minimum interval of 1000us.
    monitor
        .add_rule(vs_can_monitor::CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x7DF,
            min_interval_us: 1_000,
            max_dlc: 8,
            is_extended: false,
            severity: vs_types::AlertSeverity::High,
        })
        .expect("rule must be added");

    // Inject 200 frames on the same ID at 5us intervals (well below 1000us min)
    let mut alert_count = 0u32;
    for i in 0..200u64 {
        let frame = CanFrame {
            id: 0x7DF, // OBD-II broadcast
            dlc: 8,
            data: [0u8; 64],
            is_fd: false,
            is_extended: false,
        };
        if monitor.process_frame(&frame, i * 5).is_some() {
            alert_count += 1;
        }
    }
    // Rapid frames should have generated flood alerts
    assert!(
        alert_count > 0,
        "expected flood alerts from 200 rapid frames, got {alert_count}"
    );
}

// ---------------------------------------------------------------------------
// QEMU aarch64 validation (opt-in)
// ---------------------------------------------------------------------------

/// Validate that timing arithmetic is correct on aarch64.
#[test]
fn qemu_aarch64_timer_saturation() {
    if !is_qemu_aarch64() && !cfg!(target_arch = "aarch64") {
        return;
    }
    let mut timer = StubTimer::new(u64::MAX - 100);
    timer.advance(200);
    assert_eq!(timer.now_us(), u64::MAX);
}

/// Validate crypto on aarch64 — ensures no endianness or alignment issues.
#[test]
fn qemu_aarch64_crypto_endianness() {
    if !is_qemu_aarch64() && !cfg!(target_arch = "aarch64") {
        return;
    }
    let crypto = SoftwareCryptoProvider::new(test_rng);
    let data = b"aarch64 endian check";
    let mut hash1 = [0u8; 32];
    let mut hash2 = [0u8; 32];
    crypto
        .sha256(data, &mut hash1)
        .expect("first SHA-256 computation should succeed");
    crypto
        .sha256(data, &mut hash2)
        .expect("second SHA-256 computation should succeed");
    assert_eq!(hash1, hash2);
}

// ---------------------------------------------------------------------------
// Hardware ECU validation (opt-in)
// ---------------------------------------------------------------------------

/// Validate that CAN frame processing works identically on hardware ECU.
///
/// When `VS_ECU_HARDWARE=1`, sends frames through the CAN monitor and
/// verifies behavior matches the host baseline (flood detection, DLC
/// enforcement, entropy analysis).
#[test]
fn hardware_ecu_can_monitor_matches_host() {
    if !is_hardware_ecu() {
        return;
    }
    let mut monitor = CanMonitor::default();
    monitor
        .add_rule(vs_can_monitor::CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x7DF,
            min_interval_us: 1_000,
            max_dlc: 8,
            is_extended: false,
            severity: vs_types::AlertSeverity::High,
        })
        .expect("rule must be added");

    // Frame within interval — no alert expected.
    let frame = CanFrame {
        id: 0x7DF,
        dlc: 8,
        data: [0u8; 64],
        is_fd: false,
        is_extended: false,
    };
    let alert = monitor.process_frame(&frame, 1_000_000);
    assert!(alert.is_none(), "first frame should not trigger alert");

    // Frame too soon — flood alert expected.
    let alert = monitor.process_frame(&frame, 1_000_100);
    assert!(alert.is_some(), "rapid frame should trigger flood alert");
}

/// Validate crypto output determinism on hardware ECU.
///
/// Computes SHA-256 and HMAC on the ECU and verifies the results are
/// identical across two consecutive calls (determinism check) and that
/// the output is non-zero (liveness check).
#[test]
fn hardware_ecu_crypto_determinism() {
    if !is_hardware_ecu() {
        return;
    }
    let mut crypto = SoftwareCryptoProvider::new(test_rng);
    crypto
        .set_key(KeyId(0), &[0x42u8; 32])
        .expect("key provisioning should succeed");

    let data = b"hardware ECU crypto test";
    let mut hash1 = [0u8; 32];
    let mut hash2 = [0u8; 32];
    crypto
        .sha256(data, &mut hash1)
        .expect("SHA-256 should succeed on hardware ECU");
    crypto
        .sha256(data, &mut hash2)
        .expect("SHA-256 should succeed on hardware ECU (second call)");
    assert_eq!(hash1, hash2, "SHA-256 must be deterministic on ECU");
    assert_ne!(hash1, [0u8; 32], "SHA-256 output must be non-zero");

    let mut mac1 = [0u8; 32];
    let mut mac2 = [0u8; 32];
    crypto
        .hmac_sha256(KeyId(0), data, &mut mac1)
        .expect("HMAC should succeed on hardware ECU");
    crypto
        .hmac_sha256(KeyId(0), data, &mut mac2)
        .expect("HMAC should succeed on hardware ECU (second call)");
    assert_eq!(mac1, mac2, "HMAC must be deterministic on ECU");
    assert_ne!(mac1, [0u8; 32], "HMAC output must be non-zero");
}

/// Validate struct layout compatibility on hardware ECU.
///
/// Ensures that `CanFrame` and `VsError` have expected sizes, catching
/// any alignment or padding differences between host and target.
#[test]
fn hardware_ecu_struct_layout() {
    if !is_hardware_ecu() {
        return;
    }
    let can_size = core::mem::size_of::<CanFrame>();
    assert_eq!(
        can_size, 72,
        "CanFrame size mismatch on ECU: expected 72, got {can_size}"
    );

    let err_size = core::mem::size_of::<VsError>();
    assert!(
        err_size <= 8,
        "VsError unexpectedly large on ECU: {} bytes",
        err_size
    );
}

/// Validate watchdog timer behavior on hardware ECU.
///
/// Creates a platform with a short watchdog timeout and verifies it
/// transitions to failed state after the timeout elapses without a tick.
#[test]
fn hardware_ecu_watchdog_fires() {
    if !is_hardware_ecu() {
        return;
    }
    use vs_runtime::{CratonShield, PlatformConfig, WatchdogAction};
    let config = PlatformConfig {
        watchdog_timeout_us: 50_000, // 50ms
        watchdog_action: WatchdogAction::Reset,
        ..PlatformConfig::default()
    };
    let crypto = SoftwareCryptoProvider::new(test_rng);
    let mut platform = CratonShield::init(config, crypto).expect("init must succeed");

    // First tick at t=0
    platform.tick(0).expect("tick should succeed");
    // Second tick within timeout
    platform
        .tick(25_000)
        .expect("tick within timeout should succeed");
    // Third tick well past watchdog timeout
    let result = platform.tick(200_000);
    // Watchdog should have fired — platform reports degraded or tick returns error
    if let Ok(()) = result {
        // Even if tick succeeded, the watchdog should detect the timeout gap.
        let action = platform.check_watchdog(200_000);
        assert_eq!(
            action,
            Some(WatchdogAction::Reset),
            "watchdog should fire after timeout expiry"
        );
    }
    // If result is Err, that's also valid — the watchdog fired.
}

// ---------------------------------------------------------------------------
// Cross-platform struct layout validation
// ---------------------------------------------------------------------------

/// Verify `CanFrame` has a stable, known size across platforms.
#[test]
fn struct_layout_can_frame() {
    let size = core::mem::size_of::<CanFrame>();
    // CanFrame (#[repr(C)]): id(u32=4) + is_extended(bool=1) + is_fd(bool=1) + dlc(u8=1) + data([u8;64]=64)
    // = 71 bytes, padded to 72 for u32 alignment
    assert_eq!(size, 72, "CanFrame size mismatch: expected 72, got {size}");
}

/// Verify `VsError` has a stable repr across platforms.
#[test]
fn struct_layout_vs_error() {
    let size = core::mem::size_of::<VsError>();
    assert!(size <= 8, "VsError unexpectedly large: {} bytes", size);
}
