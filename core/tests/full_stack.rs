// SPDX-License-Identifier: Apache-2.0
//! Full platform lifecycle integration tests.
//!
//! Verifies that the Craton Shield platform can be initialised with a real
//! `SoftwareCryptoProvider`, process CAN and Ethernet traffic, tick, report
//! healthy status, and shut down cleanly.

use vs_crypto::{
    PostQuantumProvider, SoftwareCryptoProvider, StubPostQuantumProvider, MLDSA65_SIGNATURE_LEN,
    MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN,
};
use vs_netfw::{FirewallRule, RuleAction};
use vs_ota_validator::SoftwareRollbackCounter;
use vs_policy_engine::{ActionMatcher, Effect, PolicyRule, ResourceMatcher, SubjectMatcher};
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, SubsystemStatus, WatchdogAction,
};
use vs_types::{KeyId, VsError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic RNG for tests (not cryptographically secure).
fn test_rng(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(0x42);
    }
}

/// Build a `SoftwareCryptoProvider` with key slot 0 provisioned.
fn make_crypto() -> SoftwareCryptoProvider {
    let mut cp = SoftwareCryptoProvider::new(test_rng);
    cp.set_key(KeyId(0), &[0xAA; 32]).expect("provision key 0");
    cp
}

fn default_config() -> PlatformConfig {
    PlatformConfig {
        watchdog_timeout_us: 1_000_000,
        watchdog_action: WatchdogAction::Reset,
        ids_correlation_window_us: 100_000,
    }
}

fn make_can_frame(id: u32, dlc: u8, byte_fill: u8) -> CanFrame {
    CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data: [byte_fill; 64],
    }
}

fn make_eth_packet(payload: &[u8]) -> EthPacket<'_> {
    EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload,
    }
}

/// Load a permit-all policy rule and an allow-all firewall rule so that
/// CAN/ETH submission tests pass under the fail-closed defaults.
fn allow_all_traffic(shield: &mut CratonShield<SoftwareCryptoProvider>) {
    shield
        .policy_engine_mut()
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 0,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add permit-all policy rule");
    shield
        .install_firewall_rule(FirewallRule {
            id: 1,
            priority: 0,
            action: RuleAction::Allow,
            active: true,
            ..FirewallRule::default()
        })
        .expect("add allow-all firewall rule");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn platform_init_with_software_crypto() {
    let crypto = make_crypto();
    let shield = CratonShield::init(default_config(), crypto);
    assert!(shield.is_ok(), "platform init must succeed");
    let shield = shield.expect("platform init should succeed");
    assert!(shield.is_initialized());
}

#[test]
fn all_subsystems_ready_after_init() {
    let shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    let health = shield.health_status();

    // Core subsystems are immediately ready:
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.key_manager, SubsystemStatus::Ready);
    assert_eq!(health.event_logger, SubsystemStatus::Ready);
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    assert_eq!(health.eth_monitor, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
    assert_eq!(health.firewall, SubsystemStatus::Ready);
    assert_eq!(health.anomaly, SubsystemStatus::Ready);
    assert_eq!(health.integrity, SubsystemStatus::Ready);
    assert_eq!(health.policy_engine, SubsystemStatus::Ready);
    // Subsystems requiring explicit configuration stay NotInitialized:
    assert_eq!(health.secure_boot, SubsystemStatus::NotInitialized);
    assert_eq!(health.ota_validator, SubsystemStatus::NotInitialized);
    assert_eq!(health.storage, SubsystemStatus::NotInitialized);
    assert_eq!(health.hal, SubsystemStatus::NotInitialized);
}

#[test]
fn process_can_frames_through_runtime() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let frame = make_can_frame(0x100, 8, 0x01);
    for t in 0..10u64 {
        let result = shield.submit_can_frame(&frame, t * 100_000);
        assert!(result.is_ok(), "CAN frame submission must succeed");
    }
}

#[test]
fn process_eth_packets_through_runtime() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let payload = [0u8; 64];
    let pkt = make_eth_packet(&payload);
    for t in 0..5u64 {
        let result = shield.submit_eth_packet(&pkt, t * 50_000);
        assert!(result.is_ok(), "ETH packet submission must succeed");
    }
}

#[test]
fn tick_advances_counter() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    assert_eq!(shield.tick_count(), 0);

    for i in 1..=50u64 {
        shield.tick(i * 10_000).expect("tick should succeed");
        assert_eq!(shield.tick_count(), i);
    }
}

#[test]
fn watchdog_healthy_within_timeout() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    shield.tick(0).expect("tick should succeed");
    // Within the 1-second watchdog timeout
    assert_eq!(shield.check_watchdog(500_000), None);
}

#[test]
fn watchdog_fires_after_timeout() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    shield.tick(0).expect("tick should succeed");
    // Beyond the 1-second watchdog timeout
    let action = shield.check_watchdog(2_000_000);
    assert_eq!(action, Some(WatchdogAction::Reset));
}

#[test]
fn shutdown_marks_all_not_initialized() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    assert!(shield.is_initialized());

    shield.shutdown();
    assert!(!shield.is_initialized());

    let health = shield.health_status();
    assert_eq!(health.crypto, SubsystemStatus::NotInitialized);
    assert_eq!(health.can_monitor, SubsystemStatus::NotInitialized);
    assert_eq!(health.eth_monitor, SubsystemStatus::NotInitialized);
    assert_eq!(health.ids_engine, SubsystemStatus::NotInitialized);
    assert_eq!(health.firewall, SubsystemStatus::NotInitialized);
    assert_eq!(health.policy_engine, SubsystemStatus::NotInitialized);
}

#[test]
fn tick_fails_after_shutdown() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    shield.shutdown();

    let result = shield.tick(1_000);
    assert_eq!(result, Err(VsError::NotInitialized));
}

#[test]
fn full_lifecycle_init_process_tick_shutdown() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    assert!(shield.is_initialized());

    // Process some CAN frames
    let frame = make_can_frame(0x200, 8, 0x55);
    shield
        .submit_can_frame(&frame, 1_000)
        .expect("CAN frame submission should succeed");
    shield
        .submit_can_frame(&frame, 2_000)
        .expect("CAN frame submission should succeed");

    // Process some ETH packets
    let payload = [0xCC; 32];
    let pkt = make_eth_packet(&payload);
    shield
        .submit_eth_packet(&pkt, 3_000)
        .expect("ETH packet submission should succeed");

    // Tick the platform
    shield.tick(4_000).expect("tick should succeed");
    shield.tick(5_000).expect("tick should succeed");
    assert_eq!(shield.tick_count(), 2);

    // Verify health is still good
    assert_eq!(shield.health().crypto, SubsystemStatus::Ready);
    assert_eq!(shield.health().ids_engine, SubsystemStatus::Ready);

    // Watchdog should be fine
    assert_eq!(shield.check_watchdog(6_000), None);

    // Shut down
    shield.shutdown();
    assert!(!shield.is_initialized());
    assert_eq!(shield.health().crypto, SubsystemStatus::NotInitialized);
}

// ---------------------------------------------------------------------------
// Additional tests
// ---------------------------------------------------------------------------

#[test]
fn init_with_custom_watchdog_timeout() {
    let mut config = default_config();
    config.watchdog_timeout_us = 500_000; // 500 ms instead of 1 s
    config.watchdog_action = WatchdogAction::LogOnly;
    let mut shield =
        CratonShield::init(config, make_crypto()).expect("platform init should succeed");

    shield.tick(0).expect("tick should succeed");
    // Within the 500 ms timeout -- no watchdog action.
    assert_eq!(shield.check_watchdog(400_000), None);
    // Beyond 500 ms -- should fire LogOnly.
    let action = shield.check_watchdog(600_000);
    assert_eq!(action, Some(WatchdogAction::LogOnly));
}

#[test]
fn multiple_shutdown_calls_do_not_panic() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    assert!(shield.is_initialized());

    shield.shutdown();
    assert!(!shield.is_initialized());

    // Calling shutdown again must not panic.
    shield.shutdown();
    assert!(!shield.is_initialized());

    // A third call is also fine.
    shield.shutdown();
    assert!(!shield.is_initialized());
}

#[test]
fn process_100_can_frames_in_sequence() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    let frame = make_can_frame(0x150, 8, 0xAB);

    for t in 0..100u64 {
        let result = shield.submit_can_frame(&frame, t * 20_000);
        assert!(result.is_ok(), "CAN frame #{t} must succeed");
    }
}

#[test]
fn process_100_eth_packets_in_sequence() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    let payload = [0x42u8; 128];
    let pkt = make_eth_packet(&payload);

    for t in 0..100u64 {
        let result = shield.submit_eth_packet(&pkt, t * 20_000);
        assert!(result.is_ok(), "ETH packet #{t} must succeed");
    }
}

#[test]
fn mixed_traffic_alternate_can_and_eth() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    let frame = make_can_frame(0x300, 8, 0xDD);
    let payload = [0xEE; 64];
    let pkt = make_eth_packet(&payload);

    for i in 0..50u64 {
        let ts = i * 10_000;
        let can_result = shield.submit_can_frame(&frame, ts);
        assert!(can_result.is_ok(), "CAN #{i} must succeed");

        let eth_result = shield.submit_eth_packet(&pkt, ts + 5_000);
        assert!(eth_result.is_ok(), "ETH #{i} must succeed");
    }
}

#[test]
fn tick_1000_times_in_loop() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    for i in 1..=1000u64 {
        shield.tick(i * 1_000).expect("tick should succeed");
    }
    assert_eq!(shield.tick_count(), 1000);
}

#[test]
fn health_check_after_many_ticks_still_ready() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    for i in 1..=500u64 {
        shield.tick(i * 1_000).expect("tick should succeed");
    }

    let health = shield.health_status();
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    assert_eq!(health.eth_monitor, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
    assert_eq!(health.firewall, SubsystemStatus::Ready);
    assert_eq!(health.policy_engine, SubsystemStatus::Ready);
}

#[test]
fn watchdog_fires_exactly_at_boundary() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    // watchdog_timeout_us = 1_000_000
    // check_watchdog fires when elapsed > watchdog_timeout_us (strictly greater).

    shield.tick(0).expect("tick should succeed");

    // Exactly at the timeout boundary -- elapsed == timeout, does NOT fire.
    assert_eq!(shield.check_watchdog(1_000_000), None);

    // One microsecond past the boundary -- fires.
    let action = shield.check_watchdog(1_000_001);
    assert_eq!(action, Some(WatchdogAction::Reset));

    // One microsecond before the boundary -- does not fire.
    let mut shield2 =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    shield2.tick(0).expect("tick should succeed");
    assert_eq!(shield2.check_watchdog(999_999), None);
}

#[test]
fn submit_can_frame_with_extended_id() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let frame = CanFrame {
        id: 0x18FF_00FE, // 29-bit extended CAN ID
        is_extended: true,
        is_fd: false,
        dlc: 8,
        data: [0xBB; 64],
    };

    let result = shield.submit_can_frame(&frame, 1_000);
    assert!(result.is_ok(), "extended CAN ID submission must succeed");
}

#[test]
fn submit_can_frame_with_fd_flag() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let frame = CanFrame {
        id: 0x400,
        is_extended: false,
        is_fd: true,
        dlc: 64, // CAN-FD max DLC
        data: [0xCC; 64],
    };

    let result = shield.submit_can_frame(&frame, 1_000);
    assert!(result.is_ok(), "CAN-FD frame submission must succeed");
}

#[test]
fn platform_re_init_after_shutdown() {
    // First instance: init, use, shutdown.
    let mut shield1 =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    shield1.tick(1_000).expect("tick should succeed");
    shield1.shutdown();
    assert!(!shield1.is_initialized());

    // Second instance: fresh init succeeds and works.
    let mut shield2 = CratonShield::init(default_config(), make_crypto())
        .expect("platform re-init should succeed");
    allow_all_traffic(&mut shield2);
    assert!(shield2.is_initialized());
    assert_eq!(shield2.tick_count(), 0);

    let frame = make_can_frame(0x500, 8, 0x11);
    shield2
        .submit_can_frame(&frame, 1_000)
        .expect("CAN frame submission should succeed");
    shield2.tick(2_000).expect("tick should succeed");
    assert_eq!(shield2.tick_count(), 1);

    let health = shield2.health_status();
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// OTA rollback counter tests (software provider only)
// ---------------------------------------------------------------------------

#[test]
fn rollback_counter_persistence_simulation() {
    // Simulate rollback counter persisting across OTA operations
    use vs_ota_validator::RollbackCounter;
    let mut counter = SoftwareRollbackCounter::new();
    assert_eq!(counter.read(), Ok(0));

    // Simulate 3 successful OTA updates incrementing the counter
    for expected in 1..=3u64 {
        let new_val = counter
            .increment()
            .expect("rollback counter increment should succeed");
        assert_eq!(new_val, expected);
    }

    // Counter retains state
    assert_eq!(counter.read(), Ok(3));

    // A "rollback" attempt would be rejected by HsmOtaValidator
    // because the metadata version would be <= counter value
}

// ---------------------------------------------------------------------------
// PQ crypto stub tests
// ---------------------------------------------------------------------------

#[test]
fn pq_stub_returns_not_initialized() {
    let stub = StubPostQuantumProvider;
    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
    assert_eq!(
        stub.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss),
        Err(VsError::NotInitialized)
    );

    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    assert_eq!(
        stub.mldsa_sign(KeyId(0), b"test", &mut sig),
        Err(VsError::NotInitialized)
    );
}
