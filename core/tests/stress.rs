// SPDX-License-Identifier: Apache-2.0
//! Stress and high-throughput tests for Craton Shield.
//!
//! These tests verify that the platform remains stable and correct under
//! sustained high-volume traffic, rapid state transitions, and boundary
//! conditions that might trigger capacity exhaustion.

mod common;

use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, SubsystemStatus, WatchdogAction,
};

use common::{allow_all_traffic, make_crypto};

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

// ---------------------------------------------------------------------------
// High-volume CAN stress
// ---------------------------------------------------------------------------

#[test]
fn stress_1000_can_frames_sequential() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let initial_log_count = shield.event_log_count();

    for i in 0..1_000u64 {
        let id = 0x100 + (i as u32 % 16);
        let frame = make_can_frame(id, 8, (i & 0xFF) as u8);
        let result = shield.submit_can_frame(&frame, i * 1_000);
        assert!(result.is_ok(), "CAN frame #{i} failed");
    }

    assert_eq!(shield.health_status().can_monitor, SubsystemStatus::Ready);
    assert_eq!(shield.health_status().ids_engine, SubsystemStatus::Ready);
    // Event log count must be consistent (at least as many as before, never wraps to garbage)
    let final_log_count = shield.event_log_count();
    assert!(
        final_log_count >= initial_log_count,
        "event log count must not decrease: initial={initial_log_count}, final={final_log_count}"
    );
}

#[test]
fn stress_1000_eth_packets_sequential() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    let payload = [0x55u8; 128];
    let pkt = make_eth_packet(&payload);

    for i in 0..1_000u64 {
        let result = shield.submit_eth_packet(&pkt, i * 1_000);
        assert!(result.is_ok(), "ETH packet #{i} failed");
    }

    assert_eq!(shield.health_status().eth_monitor, SubsystemStatus::Ready);
    assert_eq!(shield.health_status().firewall, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// Mixed traffic stress
// ---------------------------------------------------------------------------

#[test]
fn stress_mixed_traffic_2000_frames() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let payload = [0x42u8; 64];
    let pkt = make_eth_packet(&payload);

    for i in 0..1_000u64 {
        let ts = i * 2_000;
        let frame = make_can_frame(0x200 + (i as u32 % 8), 8, 0xAB);
        shield
            .submit_can_frame(&frame, ts)
            .expect("CAN frame submission should succeed");
        shield
            .submit_eth_packet(&pkt, ts + 1_000)
            .expect("ETH packet submission should succeed");

        // Tick every 100 frames
        if i % 100 == 99 {
            shield.tick(ts).expect("tick should succeed");
        }
    }

    let health = shield.health_status();
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    assert_eq!(health.eth_monitor, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
    assert_eq!(health.firewall, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// Rapid tick stress
// ---------------------------------------------------------------------------

#[test]
fn stress_10000_ticks() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    for i in 1..=10_000u64 {
        shield.tick(i * 100).expect("tick should succeed");
    }

    assert_eq!(shield.tick_count(), 10_000);
    assert_eq!(shield.health_status().crypto, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// Rapid init/shutdown cycles
// ---------------------------------------------------------------------------

#[test]
fn stress_init_shutdown_cycle_10_times() {
    for _ in 0..10 {
        let mut shield = CratonShield::init(default_config(), make_crypto())
            .expect("platform init should succeed");
        allow_all_traffic(&mut shield);
        assert!(shield.is_initialized());

        // Do some work
        let frame = make_can_frame(0x100, 8, 0x01);
        shield
            .submit_can_frame(&frame, 1_000)
            .expect("CAN frame submission should succeed");
        shield.tick(2_000).expect("tick should succeed");

        assert_eq!(shield.health_status().crypto, SubsystemStatus::Ready);

        shield.shutdown();
        assert!(!shield.is_initialized());
    }
}

// ---------------------------------------------------------------------------
// Many distinct CAN IDs
// ---------------------------------------------------------------------------

#[test]
fn stress_256_distinct_can_ids() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    // Send frames from 256 different CAN IDs to stress ID tracking tables
    for id in 0..256u32 {
        let frame = make_can_frame(id, 8, (id & 0xFF) as u8);
        let result = shield.submit_can_frame(&frame, (id as u64) * 10_000);
        assert!(result.is_ok(), "CAN ID 0x{id:03X} failed");
    }

    assert_eq!(shield.health_status().can_monitor, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// VLAN hopping flood — many alerts
// ---------------------------------------------------------------------------

#[test]
fn stress_100_vlan_hop_alerts() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);
    let initial = shield.event_log_count();

    for i in 0..100u64 {
        let pkt = EthPacket {
            src_mac: [1, 2, 3, 4, 5, (i & 0xFF) as u8],
            dst_mac: [0xFF; 6],
            vlan_id: Some((i as u16) + 1),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0; 32],
        };
        shield
            .submit_eth_packet(&pkt, i * 10_000)
            .expect("ETH packet submission should succeed");
    }

    // Should have generated many alerts without crashing
    assert!(shield.event_log_count() > initial);
    assert_eq!(shield.health_status().eth_monitor, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// Watchdog stress — repeated checks
// ---------------------------------------------------------------------------

#[test]
fn stress_watchdog_repeated_checks() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");

    for i in 0..100u64 {
        shield.tick(i * 100_000).expect("tick should succeed");
        // Check watchdog at current time — should never fire (within timeout)
        assert_eq!(shield.check_watchdog(i * 100_000 + 50_000), None);
    }

    // Now let the watchdog expire
    let action = shield.check_watchdog(100 * 100_000 + 2_000_000);
    assert_eq!(action, Some(WatchdogAction::Reset));
}

// ---------------------------------------------------------------------------
// CAN-FD large payload stress
// ---------------------------------------------------------------------------

#[test]
fn stress_500_can_fd_frames() {
    let mut shield =
        CratonShield::init(default_config(), make_crypto()).expect("platform init should succeed");
    allow_all_traffic(&mut shield);

    let initial_log_count = shield.event_log_count();

    for i in 0..500u64 {
        let frame = CanFrame {
            id: 0x300 + (i as u32 % 16),
            is_extended: false,
            is_fd: true,
            dlc: 64,
            data: [(i & 0xFF) as u8; 64],
        };
        assert!(shield.submit_can_frame(&frame, i * 5_000).is_ok());
    }

    let health = shield.health_status();
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    // Event log count must be consistent after CAN-FD stress
    let final_log_count = shield.event_log_count();
    assert!(
        final_log_count >= initial_log_count,
        "event log count must not decrease: initial={initial_log_count}, final={final_log_count}"
    );
}
