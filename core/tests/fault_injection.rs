// SPDX-License-Identifier: Apache-2.0
//! Fault injection tests for Craton Shield.
//!
//! These tests verify that the platform handles corrupted inputs, boundary
//! conditions, and adversarial data gracefully without panicking or entering
//! an inconsistent state.

mod common;

use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS};
use vs_event_logger::{EventLog, EventType};
use vs_integrity::{IntegrityMonitor, IntegrityStatus};
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_netfw::{Firewall, FirewallRule, RuleAction, Verdict};
use vs_ota_validator::{OtaValidator, TufRoot};
use vs_runtime::{
    CanFrame as RtCanFrame, CratonShield, EthPacket as RtEthPacket, PlatformConfig, WatchdogAction,
};
use vs_types::{AlertSeverity, KeyId};

use common::make_crypto;

// ---------------------------------------------------------------------------
// CAN monitor: malformed frame fields
// ---------------------------------------------------------------------------

#[test]
fn can_monitor_maximum_id_values() {
    let mut monitor = CanMonitor::new([0x42u8; 16]);

    // Standard max ID (11-bit)
    let frame = CanFrame {
        id: 0x7FF,
        is_extended: false,
        is_fd: false,
        dlc: 8,
        data: [0u8; 64],
    };
    let _ = monitor.process_frame(&frame, 0);

    // Extended max ID (29-bit)
    let frame = CanFrame {
        id: 0x1FFF_FFFF,
        is_extended: true,
        is_fd: false,
        dlc: 8,
        data: [0u8; 64],
    };
    let _ = monitor.process_frame(&frame, 1000);

    // ID beyond 29-bit range — should not panic
    let frame = CanFrame {
        id: u32::MAX,
        is_extended: true,
        is_fd: false,
        dlc: 8,
        data: [0u8; 64],
    };
    let _ = monitor.process_frame(&frame, 2000);
}

#[test]
fn can_monitor_dlc_beyond_valid_range() {
    let mut monitor = CanMonitor::new([0x42u8; 16]);
    let rule = CanRule {
        id: 0,
        id_mask: 0x7FF,
        id_filter: 0x100,
        min_interval_us: 10_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    };
    monitor.add_rule(rule).unwrap();

    // DLC=255 (well beyond CAN max of 8 or CAN-FD max of 64)
    let frame = CanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 255,
        data: [0xDE; 64],
    };
    // Must not panic on oversized DLC. Alert generation depends on
    // whether the DLC exceeds the rule's max_dlc, which it does (255 > 8).
    let _alert = monitor.process_frame(&frame, 0);
    // The important invariant: the monitor did not panic.
}

#[test]
fn can_fd_with_classic_dlc() {
    let mut monitor = CanMonitor::new([0x42u8; 16]);

    // CAN-FD flag set but DLC=8 (valid classic size)
    let frame = CanFrame {
        id: 0x200,
        is_extended: false,
        is_fd: true,
        dlc: 8,
        data: [0u8; 64],
    };
    let _ = monitor.process_frame(&frame, 0);

    // CAN-FD with DLC=64 (valid FD size)
    let frame = CanFrame {
        id: 0x200,
        is_extended: false,
        is_fd: true,
        dlc: 64,
        data: [0u8; 64],
    };
    let _ = monitor.process_frame(&frame, 1000);
}

// ---------------------------------------------------------------------------
// Ethernet monitor: edge-case payloads
// ---------------------------------------------------------------------------

#[test]
fn eth_monitor_empty_payload() {
    let mut monitor = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    let pkt = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[],
    };
    // Should not panic on empty payload
    let _ = monitor.inspect_packet(&pkt, 0);
}

#[test]
fn eth_monitor_single_byte_payload() {
    let mut monitor = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    let pkt = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[0xFF],
    };
    let _ = monitor.inspect_packet(&pkt, 0);
}

#[test]
fn eth_monitor_max_vlan_id() {
    let mut monitor = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    // VLAN ID at boundary (4094 is max valid)
    let pkt = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: Some(4094),
        ethertype: 0x0800,
        dst_port: None,
        payload: &[0u8; 64],
    };
    let _ = monitor.inspect_packet(&pkt, 0);
}

// ---------------------------------------------------------------------------
// Key manager: adversarial key material
// ---------------------------------------------------------------------------

#[test]
fn key_manager_rejects_short_key_material() {
    let crypto = make_crypto();
    let mut mgr = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(1),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: Some(1_000_000_000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    // AES-256-GCM requires 32 bytes; provide only 16
    let result = mgr.provision_key(KeyId(1), meta, &[0x42; 16]);
    assert!(result.is_err(), "short key material should be rejected");
}

#[test]
fn key_manager_rejects_repeating_pattern_key() {
    let crypto = make_crypto();
    let mut mgr = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(2),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: Some(1_000_000_000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    // All 0xAB bytes — uniform key rejected
    let result = mgr.provision_key(KeyId(2), meta, &[0xAB; 32]);
    assert!(result.is_err(), "uniform key material should be rejected");
}

// ---------------------------------------------------------------------------
// Integrity monitor: tampered region detection
// ---------------------------------------------------------------------------

#[test]
fn integrity_monitor_detects_single_bit_flip() {
    let crypto = make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let original = [0xAA; 128];
    monitor
        .register_region(1, 0x1000_0000, &original)
        .expect("register");

    // Flip a single bit
    let mut tampered = original;
    tampered[64] ^= 0x01;

    let result = monitor.verify_region(1, 0x1000_0000, &tampered);
    assert!(result.is_ok(), "verify should not error");
    let status = result.unwrap();
    assert_eq!(
        status.status,
        IntegrityStatus::Tampered,
        "single bit flip must be detected"
    );
}

#[test]
fn integrity_monitor_empty_region() {
    let crypto = make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    // Register with zero-length data
    let result = monitor.register_region(1, 0x1000_0000, &[]);
    // Should either succeed (empty hash) or reject — but not panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// Event logger: timestamp boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn event_logger_max_timestamp() {
    let crypto = make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 64> = EventLog::new(KeyId(0), &crypto).unwrap();

    // u64::MAX timestamp
    let result = log.append(EventType::SystemEvent, &[0x42; 8], u64::MAX, &crypto);
    assert!(result.is_ok(), "max timestamp should be accepted");
}

#[test]
fn event_logger_zero_timestamp() {
    let crypto = make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 64> = EventLog::new(KeyId(0), &crypto).unwrap();

    let result = log.append(EventType::SecurityAlert, &[0x01; 8], 0, &crypto);
    assert!(result.is_ok(), "zero timestamp should be accepted");
}

#[test]
fn event_logger_rapid_overflow() {
    let crypto = make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 64> = EventLog::new(KeyId(0), &crypto).unwrap();

    // Fill the ring buffer completely and then some
    for i in 0..114u64 {
        let _ = log.append(EventType::SystemEvent, &[i as u8; 8], i * 1000, &crypto);
    }

    // Chain should still be valid after wrapping
    assert!(
        log.verify_chain(&crypto).is_ok(),
        "chain must survive overflow"
    );
}

// ---------------------------------------------------------------------------
// Firewall: boundary condition rules
// ---------------------------------------------------------------------------

#[test]
fn firewall_max_priority_values() {
    let mut fw = Firewall::new();

    // Priority 0 (highest)
    fw.add_rule(FirewallRule {
        id: 1,
        priority: 0,
        action: RuleAction::Allow,
        ethertype: Some(0x0800),
        active: true,
        ..FirewallRule::default()
    })
    .expect("priority 0");

    // Priority u8::MAX (lowest)
    fw.add_rule(FirewallRule {
        id: 2,
        priority: u8::MAX,
        action: RuleAction::Drop,
        ethertype: Some(0x0800),
        active: true,
        ..FirewallRule::default()
    })
    .expect("priority max");

    // Priority 0 rule should match first (Allow)
    let pkt = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[0u8; 64],
    };
    let verdict = fw.evaluate(&pkt, 0);
    assert_eq!(verdict, Verdict::Allow, "lowest priority number should win");
}

// ---------------------------------------------------------------------------
// OTA validator: zero threshold
// ---------------------------------------------------------------------------

#[test]
fn ota_validator_zero_threshold() {
    let crypto = SoftwareCryptoProvider::new(common::test_rng);
    let root = TufRoot {
        version: 1,
        threshold: 0, // zero threshold — should reject
        expires_us: u64::MAX,
        root_keys: [None; 4],
        targets_keys: [None; 4],
        targets_threshold: 1,
        snapshot_keys: [None; 4],
        snapshot_threshold: 1,
        timestamp_keys: [None; 4],
        timestamp_threshold: 1,
    };

    let result = OtaValidator::new(crypto, root);
    assert!(result.is_err(), "zero threshold should be rejected");
}

// ---------------------------------------------------------------------------
// Platform: rapid init/shutdown cycling
// ---------------------------------------------------------------------------

#[test]
fn platform_rapid_init_shutdown_cycling() {
    let config = PlatformConfig {
        watchdog_timeout_us: 1_000_000,
        watchdog_action: WatchdogAction::LogOnly,
        ids_correlation_window_us: 100_000,
    };

    for _ in 0..50 {
        let crypto = make_crypto();
        let mut platform = CratonShield::init(config, crypto).expect("init");
        platform.tick(0).expect("tick");
        platform.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Platform: operations after shutdown
// ---------------------------------------------------------------------------

#[test]
fn platform_operations_after_shutdown_return_error() {
    let config = PlatformConfig::default();
    let crypto = make_crypto();
    let mut platform = CratonShield::init(config, crypto).expect("init");

    platform.shutdown();

    // All operations should fail gracefully
    let tick_result = platform.tick(1000);
    assert!(tick_result.is_err(), "tick after shutdown should fail");

    let frame = RtCanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 8,
        data: [0u8; 64],
    };
    let can_result = platform.submit_can_frame(&frame, 1000);
    assert!(
        can_result.is_err(),
        "submit_can_frame after shutdown should fail"
    );

    let pkt = RtEthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[0u8; 64],
    };
    let eth_result = platform.submit_eth_packet(&pkt, 1000);
    assert!(
        eth_result.is_err(),
        "submit_eth_packet after shutdown should fail"
    );
}

// ---------------------------------------------------------------------------
// Crypto: corrupted ciphertext detection
// ---------------------------------------------------------------------------

#[test]
fn crypto_detects_corrupted_ciphertext() {
    let crypto = {
        let mut cp = SoftwareCryptoProvider::new(common::test_rng);
        cp.set_key(KeyId(0), &[0xAA; 32]).expect("provision key 0");
        cp
    };

    let plaintext = b"sensitive automotive data!!!!!!!"; // 32 bytes
    let nonce = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
    ];
    let mut ciphertext = [0u8; 32];
    let mut tag = [0u8; 16];

    crypto
        .aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ciphertext, &mut tag)
        .expect("encrypt");

    // Corrupt one byte of ciphertext
    ciphertext[0] ^= 0xFF;

    let mut decrypted = [0u8; 32];
    let result = crypto.aes_gcm_decrypt(KeyId(0), &nonce, &ciphertext, &[], &tag, &mut decrypted);
    assert!(result.is_err(), "corrupted ciphertext must be rejected");
}

#[test]
fn crypto_detects_corrupted_tag() {
    let crypto = {
        let mut cp = SoftwareCryptoProvider::new(common::test_rng);
        cp.set_key(KeyId(0), &[0xAA; 32]).expect("provision key 0");
        cp
    };

    let plaintext = b"sensitive automotive data!!!!!!!"; // 32 bytes
    let nonce = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
    ];
    let mut ciphertext = [0u8; 32];
    let mut tag = [0u8; 16];

    crypto
        .aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ciphertext, &mut tag)
        .expect("encrypt");

    // Corrupt authentication tag
    tag[0] ^= 0x01;

    let mut decrypted = [0u8; 32];
    let result = crypto.aes_gcm_decrypt(KeyId(0), &nonce, &ciphertext, &[], &tag, &mut decrypted);
    assert!(result.is_err(), "corrupted tag must be rejected");
}

// ---------------------------------------------------------------------------
// Crypto: nonce counter saturation
// ---------------------------------------------------------------------------

#[test]
fn crypto_nonce_counter_saturation() {
    use vs_crypto::NonceCounter;
    use vs_types::VsError;

    let prefix = [0x42u8; 8];

    // Part 1: verify the counter generates nonces successfully.
    let mut nc = NonceCounter::new(prefix).unwrap();
    let mut count = 0u64;
    for _ in 0..1_000 {
        nc.next()
            .expect("nonce generation should succeed before exhaustion");
        count += 1;
    }
    assert!(count > 0, "should generate at least one nonce");

    // Part 2: verify that exhaustion returns the correct error type.
    // Use new_persisted_with_margin to start the counter at u32::MAX so the
    // very next call to next() overflows and returns ResourceExhausted.
    let mut nc_full = NonceCounter::new_persisted_with_margin(prefix, u32::MAX, 0).unwrap();
    let exhaustion_result = nc_full.next();
    assert_eq!(
        exhaustion_result,
        Err(VsError::ResourceExhausted),
        "counter at u32::MAX must return ResourceExhausted on next()"
    );
}

#[test]
fn crypto_nonce_boundary_validation() {
    use vs_crypto::NonceCounter;
    // NonceCounter::new should reject all-zero prefix
    let zero_prefix = [0u8; 8];
    // Attempt construction — if the type validates prefix, this should fail or succeed
    // based on the API. Just verify it doesn't panic.
    let result = NonceCounter::new(zero_prefix);
    // We do not mandate rejection of zero prefix at the NonceCounter level,
    // but we do verify that generated nonces (if any) are non-zero overall.
    if let Ok(mut nc) = result {
        if let Ok(nonce) = nc.next() {
            // The nonce must contain the counter value (non-zero) even if prefix is zero.
            // At minimum the last 4 bytes (counter) should be non-zero after first increment.
            assert!(nonce.iter().any(|&b| b != 0), "nonce must not be all-zero");
        }
    }
}

#[test]
fn crypto_nonce_counter_does_not_repeat() {
    use std::collections::HashSet;
    use vs_crypto::NonceCounter;

    let prefix = [0xDE_u8; 8];
    let mut nc = NonceCounter::new(prefix).unwrap();
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        match nc.next() {
            Ok(nonce) => {
                assert!(seen.insert(nonce), "nonce was repeated!");
            }
            Err(_) => break,
        }
    }
    assert!(!seen.is_empty(), "should have generated at least one nonce");
}
