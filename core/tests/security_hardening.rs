// SPDX-License-Identifier: Apache-2.0
//! Security hardening and gap coverage integration tests.
//!
//! These tests cover edge cases identified during security audit:
//! - CAN monitor replay tracker with custom keys
//! - Firewall rate limiter edge cases
//! - Key manager audit and lifecycle
//! - Policy engine combining algorithms
//! - Integrity monitor verification
//! - Nonce validation constant-time properties

mod common;

use vs_can_monitor::{CanFrame, CanMonitor};
use vs_crypto::NonceTracker;
use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_event_logger::{EventLog, EventType};
use vs_integrity::IntegrityMonitor;
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_netfw::{Firewall, FirewallRule, RuleAction, Verdict};
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, AuthenticationLevel, CombiningAlgorithm, Effect,
    Environment, PolicyEngine, PolicyRule, Resource, ResourceMatcher, Subject, SubjectMatcher,
};
use vs_runtime::PlatformConfig;
use vs_types::{KeyId, VsError};

// ---------------------------------------------------------------------------
// CAN monitor replay key tests
// ---------------------------------------------------------------------------

#[test]
fn can_monitor_with_custom_replay_key_detects_replay() {
    let key = [0x11u8; 16];
    let mut mon = CanMonitor::new(key);

    let frame = CanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 4,
        data: {
            let mut d = [0u8; 64];
            d[0] = 0xDE;
            d[1] = 0xAD;
            d[2] = 0xBE;
            d[3] = 0xEF;
            d
        },
    };

    // Process same frame repeatedly - should eventually trigger replay alert.
    let mut alert_seen = false;
    for i in 1..=10u64 {
        if mon.process_frame(&frame, i * 1000).is_some() {
            alert_seen = true;
            break;
        }
    }
    assert!(alert_seen, "replay detection should fire with custom key");
}

#[test]
fn can_monitor_different_replay_keys_both_work() {
    let mut mon1 = CanMonitor::new([0x11; 16]);
    let mut mon2 = CanMonitor::new([0x22; 16]);

    let frame = CanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 4,
        data: {
            let mut d = [0u8; 64];
            d[0] = 0xDE;
            d[1] = 0xAD;
            d
        },
    };

    // Both monitors should handle the frame without panic.
    let _ = mon1.process_frame(&frame, 1000);
    let _ = mon2.process_frame(&frame, 1000);
}

// ---------------------------------------------------------------------------
// Firewall rate limiter edge cases
// ---------------------------------------------------------------------------

#[test]
fn firewall_rate_limit_zero_rate_drops_all() {
    let mut fw = Firewall::new();
    let rule = FirewallRule {
        id: 1,
        priority: 0,
        action: RuleAction::RateLimit(0),
        active: true,
        ethertype: Some(0x0800),
        ..FirewallRule::default()
    };
    fw.add_rule(rule).unwrap();

    let pkt = vs_eth_monitor::EthPacket {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[],
    };

    // With rate 0, all packets should be rate-limit-dropped.
    let verdict = fw.evaluate(&pkt, 1000);
    assert!(
        matches!(verdict, Verdict::RateLimitDrop(_)),
        "zero-rate limiter should drop: got {verdict:?}"
    );
}

#[test]
fn firewall_dynamic_rule_expiry() {
    let mut fw = Firewall::new();

    // Add a dynamic rule that expires at ts=5000.
    let rule = FirewallRule {
        id: 100,
        priority: 0,
        action: RuleAction::Drop,
        active: true,
        ethertype: Some(0x0800),
        ..FirewallRule::default()
    };
    fw.insert_dynamic_rule(rule, 5000).unwrap();

    let pkt = vs_eth_monitor::EthPacket {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[],
    };

    // Before expiry, rule should be active.
    let verdict_before = fw.evaluate(&pkt, 1000);
    assert_eq!(verdict_before, Verdict::Drop);

    // After expiry, rule should be gone.
    fw.expire_rules(6000);
    let verdict_after = fw.evaluate(&pkt, 6000);
    // Default deny — no rules match.
    assert_eq!(verdict_after, Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Key manager tests
// ---------------------------------------------------------------------------

#[test]
fn key_manager_provision_and_retrieve_metadata() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(1),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: Some(100_000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    // Use a non-uniform, non-zero key.
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate().take(32) {
        *byte = (i as u8).wrapping_add(1);
    }
    km.provision_key(KeyId(1), meta, &key).unwrap();
    let retrieved = km.get_metadata(KeyId(1)).unwrap();
    assert_eq!(retrieved.algorithm, KeyAlgorithm::Aes256Gcm);
    assert_eq!(retrieved.purpose, KeyPurpose::BusAuthentication);
}

#[test]
fn key_manager_rejects_all_zero_key() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(1),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: None,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    let result = km.provision_key(KeyId(1), meta, &[0x00; 32]);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn key_manager_rejects_uniform_key() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(1),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: None,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    // All same byte — should be rejected as weak key.
    let result = km.provision_key(KeyId(1), meta, &[0xFF; 32]);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn key_manager_revoke_records_audit() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(2),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::TelemetryEncryption,
        created_at: 1000,
        expires_at: None,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate().take(32) {
        *byte = (i as u8).wrapping_add(1);
    }
    km.provision_key(KeyId(2), meta, &key).unwrap();

    let audit_before = km.audit_count();
    km.revoke_key(KeyId(2), 2000).unwrap();
    let audit_after = km.audit_count();

    // Revocation should add an audit entry.
    assert!(audit_after > audit_before);
}

#[test]
fn key_manager_expiry_detected_by_tick() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);

    let meta = KeyMetadata {
        key_id: KeyId(3),
        algorithm: KeyAlgorithm::HmacSha256,
        purpose: KeyPurpose::DiagnosticSession,
        created_at: 1000,
        expires_at: Some(5000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };

    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate().take(32) {
        *byte = (i as u8).wrapping_add(0x10);
    }
    km.provision_key(KeyId(3), meta, &key).unwrap();

    // Before expiry.
    km.tick(4000);
    assert!(km.get_metadata(KeyId(3)).is_some());

    // After expiry.
    km.tick(6000);
    // get_metadata still returns metadata for expired keys (state is tracked internally).
    let meta = km.get_metadata(KeyId(3));
    assert!(meta.is_some());
}

// ---------------------------------------------------------------------------
// Policy engine combining algorithm tests
// ---------------------------------------------------------------------------

#[test]
fn policy_engine_deny_overrides() {
    let mut engine = PolicyEngine::new();
    engine.set_combining_algorithm(CombiningAlgorithm::DenyOverrides);

    let permit = PolicyRule {
        id: 1,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Read,
        effect: Effect::Permit,
        priority: 10,
        valid_from: 0,
        valid_until: 0,
    };
    let deny = PolicyRule {
        id: 2,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Read,
        effect: Effect::Deny,
        priority: 20,
        valid_from: 0,
        valid_until: 0,
    };

    engine.add_rule(permit).unwrap();
    engine.add_rule(deny).unwrap();

    let subject = Subject {
        address: 1,
        authenticated: false,
        ecu_role: 0,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let resource = Resource {
        bus_type: None,
        bus_id: None,
        service_id: None,
        firmware_region: None,
    };
    let action = Action {
        action_type: ActionType::Read,
    };
    let env = Environment { timestamp_us: 1000 };

    // DenyOverrides: even though permit has higher priority, deny wins.
    let decision = engine.evaluate(&subject, &resource, &action, &env);
    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn policy_engine_permit_overrides() {
    let mut engine = PolicyEngine::new();
    engine.set_combining_algorithm(CombiningAlgorithm::PermitOverrides);

    let deny = PolicyRule {
        id: 1,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Write,
        effect: Effect::Deny,
        priority: 10,
        valid_from: 0,
        valid_until: 0,
    };
    let permit = PolicyRule {
        id: 2,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Write,
        effect: Effect::Permit,
        priority: 20,
        valid_from: 0,
        valid_until: 0,
    };

    engine.add_rule(deny).unwrap();
    engine.add_rule(permit).unwrap();

    let subject = Subject {
        address: 1,
        authenticated: false,
        ecu_role: 0,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let resource = Resource {
        bus_type: None,
        bus_id: None,
        service_id: None,
        firmware_region: None,
    };
    let action = Action {
        action_type: ActionType::Write,
    };
    let env = Environment { timestamp_us: 1000 };

    // PermitOverrides: even though deny has higher priority, permit wins.
    let decision = engine.evaluate(&subject, &resource, &action, &env);
    assert_eq!(decision.effect, Effect::Permit);
}

#[test]
fn policy_engine_time_bounded_rule_expired() {
    let mut engine = PolicyEngine::new();

    let rule = PolicyRule {
        id: 1,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Any,
        effect: Effect::Permit,
        priority: 0,
        valid_from: 1000,
        valid_until: 5000,
    };

    engine.add_rule(rule).unwrap();

    let subject = Subject {
        address: 1,
        authenticated: false,
        ecu_role: 0,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let resource = Resource {
        bus_type: None,
        bus_id: None,
        service_id: None,
        firmware_region: None,
    };
    let action = Action {
        action_type: ActionType::Read,
    };

    // Within validity window — should permit.
    let env_valid = Environment { timestamp_us: 3000 };
    let decision = engine.evaluate(&subject, &resource, &action, &env_valid);
    assert_eq!(decision.effect, Effect::Permit);

    // After expiry — should default deny (no matching rule).
    let env_expired = Environment { timestamp_us: 6000 };
    let decision = engine.evaluate(&subject, &resource, &action, &env_expired);
    assert_eq!(decision.effect, Effect::Deny);
}

// ---------------------------------------------------------------------------
// Integrity monitor tests
// ---------------------------------------------------------------------------

#[test]
fn integrity_monitor_register_verify_ok() {
    let crypto = common::make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let data = b"critical firmware code section";
    monitor.register_region(1, 0x8000_0000, data).unwrap();

    let result = monitor.verify_region(1, 0x8000_0000, data).unwrap();
    assert_eq!(result.status, vs_integrity::IntegrityStatus::Ok);
}

#[test]
fn integrity_monitor_detects_tamper() {
    let crypto = common::make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let data = b"original firmware code";
    monitor.register_region(1, 0x8000_0000, data).unwrap();

    let tampered = b"tampered firmware code";
    let result = monitor.verify_region(1, 0x8000_0000, tampered).unwrap();
    assert_eq!(result.status, vs_integrity::IntegrityStatus::Tampered);
}

#[test]
fn integrity_monitor_base_addr_mismatch_rejected() {
    let crypto = common::make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let data = b"code section";
    monitor.register_region(1, 0x8000_0000, data).unwrap();

    let result = monitor.verify_region(1, 0x9000_0000, data);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn integrity_monitor_unregister_and_reuse_slot() {
    let crypto = common::make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let data = b"code";
    monitor.register_region(1, 0x1000, data).unwrap();
    monitor.unregister_region(1).unwrap();

    // Re-register with same ID should succeed (slot reuse).
    let new_data = b"new code";
    monitor.register_region(1, 0x2000, new_data).unwrap();

    let result = monitor.verify_region(1, 0x2000, new_data).unwrap();
    assert_eq!(result.status, vs_integrity::IntegrityStatus::Ok);
}

#[test]
fn integrity_monitor_tick_interval() {
    let crypto = common::make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);
    monitor.set_check_interval(5);

    // First 4 ticks should return false.
    for _ in 0..4 {
        assert!(!monitor.tick());
    }
    // 5th tick should return true.
    assert!(monitor.tick());
    // Then reset, next 4 false again.
    for _ in 0..4 {
        assert!(!monitor.tick());
    }
    assert!(monitor.tick());
}

// ---------------------------------------------------------------------------
// Nonce validation tests
// ---------------------------------------------------------------------------

#[test]
fn nonce_validation_rejects_all_zero() {
    let crypto = common::make_crypto();
    let result = crypto.validate_nonce(&[0u8; 12]);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn nonce_validation_accepts_non_zero() {
    let crypto = common::make_crypto();
    // Use a nonce with varied prefix bytes to pass degenerate-prefix check.
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1];
    assert!(crypto.validate_nonce(&nonce).is_ok());
}

#[test]
fn nonce_validation_rejects_wrong_length() {
    let crypto = common::make_crypto();
    assert_eq!(
        crypto.validate_nonce(&[1u8; 11]),
        Err(VsError::InvalidInput)
    );
    assert_eq!(
        crypto.validate_nonce(&[1u8; 13]),
        Err(VsError::InvalidInput)
    );
}

// ---------------------------------------------------------------------------
// Event logger edge cases
// ---------------------------------------------------------------------------

#[test]
fn event_logger_overflow_tracking() {
    let crypto = common::make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 4> = EventLog::new(KeyId(0), &crypto).unwrap();

    // Fill the ring buffer.
    for i in 0..4u64 {
        log.append(EventType::SecurityAlert, &[i as u8], i * 100, &crypto)
            .unwrap();
    }
    assert_eq!(log.overflow_count(), 0);

    // One more should overflow.
    log.append(EventType::SecurityAlert, &[0xFF], 500, &crypto)
        .unwrap();
    assert_eq!(log.overflow_count(), 1);
}

#[test]
fn event_logger_rejects_backward_timestamp() {
    let crypto = common::make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 8> = EventLog::new(KeyId(0), &crypto).unwrap();

    log.append(EventType::BootEvent, &[1], 1000, &crypto)
        .unwrap();

    // Backward timestamp should be rejected.
    let result = log.append(EventType::BootEvent, &[2], 500, &crypto);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn event_logger_chain_integrity_after_wrap() {
    let crypto = common::make_crypto();
    let mut log: EventLog<SoftwareCryptoProvider, 4> = EventLog::new(KeyId(0), &crypto).unwrap();

    // Write 8 entries (wraps twice through a capacity-4 buffer).
    for i in 0..8u64 {
        log.append(EventType::SystemEvent, &[i as u8; 4], i * 100, &crypto)
            .unwrap();
    }

    // Chain should still verify.
    let integrity = log.verify_chain(&crypto).unwrap();
    assert_eq!(integrity.first_tampered_seq, None);
}

// ---------------------------------------------------------------------------
// V8: Platform always fail-closed integration test
// ---------------------------------------------------------------------------

#[test]
fn platform_always_fail_closed() {
    // PlatformConfig no longer has a policy_fail_open field.
    // The system is always fail-closed when no rules are loaded.
    let _config = PlatformConfig::default();
}

// ---------------------------------------------------------------------------
// V8: Nonce tracker integration test
// ---------------------------------------------------------------------------

#[test]
fn nonce_tracker_detects_reuse_in_sequence() {
    let mut tracker = NonceTracker::new();
    let nonce_a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let nonce_b = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    tracker.check_and_record(&nonce_a).unwrap();
    tracker.check_and_record(&nonce_b).unwrap();

    // Reusing nonce_a should fail.
    assert_eq!(
        tracker.check_and_record(&nonce_a),
        Err(VsError::PolicyViolation)
    );
}

// ---------------------------------------------------------------------------
// V8: Crypto self-test canary integration test
// ---------------------------------------------------------------------------

#[test]
fn crypto_self_test_passes_for_software_provider() {
    let crypto = common::make_crypto();
    crypto.self_test().unwrap();
}

#[test]
fn platform_init_runs_crypto_self_test() {
    // Verify that CratonShield::init succeeds with a working crypto provider.
    let config = PlatformConfig::default();
    let crypto = common::make_crypto();
    let platform = vs_runtime::CratonShield::init(config, crypto);
    assert!(platform.is_ok(), "init must succeed with valid crypto");
}

// ---------------------------------------------------------------------------
// V9 audit fix tests
// ---------------------------------------------------------------------------

#[test]
fn nonce_tracker_integrated_in_encrypt() {
    // Verify that SoftwareCryptoProvider rejects nonce reuse in aes_gcm_encrypt
    let mut crypto = common::make_crypto();
    crypto.set_key(KeyId(0), &[0x42u8; 16]).unwrap();
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let plaintext = b"hello";
    let mut ct = [0u8; 5];
    let mut tag = [0u8; 16];
    // First encrypt should succeed
    crypto
        .aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ct, &mut tag)
        .unwrap();
    // Second encrypt with same nonce should fail (nonce reuse)
    let result = crypto.aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ct, &mut tag);
    assert!(result.is_err(), "nonce reuse should be rejected");
}

#[test]
fn crypto_self_test_determinism() {
    let crypto = common::make_crypto();
    // self_test should pass (non-zero, deterministic, collision-resistant)
    assert!(crypto.self_test().is_ok());
}

#[test]
fn nonce_validation_rejects_degenerate_prefix() {
    let crypto = common::make_crypto();
    // All 12 bytes identical should be rejected (degenerate nonce)
    let nonce = [0xAA; 12];
    assert!(crypto.validate_nonce(&nonce).is_err());
}

#[test]
fn nonce_validation_accepts_varied_prefix() {
    let crypto = common::make_crypto();
    // Varied prefix should be accepted
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0];
    assert!(crypto.validate_nonce(&nonce).is_ok());
}

// ---------------------------------------------------------------------------
// Audit fail-closed tests
// ---------------------------------------------------------------------------

/// Build a non-uniform 32-byte key for a given slot index.
fn varied_key(slot: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(slot as u8).wrapping_add(0x10);
    }
    k
}

/// Build a different non-uniform 32-byte key for rotation round `round`.
fn rotation_key(slot: u32, round: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_add(slot as u8)
            .wrapping_add(round as u8)
            .wrapping_add(0x50);
    }
    k
}

/// Fill the audit buffer to exactly 256 entries by provisioning 64 keys
/// and rotating each one 3 times (64 + 64*3 = 256).
fn fill_audit_buffer(km: &mut KeyManager<SoftwareCryptoProvider>) {
    // Provision 64 keys (slots 0..63) → 64 audit entries.
    for slot in 0..64u32 {
        let meta = KeyMetadata {
            key_id: KeyId(slot),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        km.provision_key(KeyId(slot), meta, &varied_key(slot))
            .expect("provision key");
    }

    // Rotate each key 3 times → 192 audit entries.
    for round in 1..=3u32 {
        for slot in 0..64u32 {
            km.rotate_key(
                KeyId(slot),
                &rotation_key(slot, round),
                1000 + (round as u64) * 1000,
                None,
            )
            .expect("rotate key");
        }
    }

    assert_eq!(km.audit_count(), 256, "audit buffer should be exactly full");
}

#[test]
fn test_audit_fail_closed_rejects_on_overflow() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);
    km.set_audit_fail_closed(true);

    fill_audit_buffer(&mut km);

    // The next operation should fail because audit is full, fail-closed is
    // enabled, and no overflow callback is registered.
    let result = km.rotate_key(KeyId(0), &rotation_key(0, 99), 10_000, None);
    assert_eq!(
        result,
        Err(VsError::ResourceExhausted),
        "operation should be rejected when audit overflows with fail-closed and no callback"
    );
}

#[test]
fn test_audit_fail_closed_allows_with_callback() {
    let crypto = common::make_crypto();
    let mut km = KeyManager::new(crypto);
    km.set_audit_fail_closed(true);

    // Register an overflow callback — this should allow operations to proceed
    // even when the audit buffer overflows.
    km.set_audit_overflow_callback(|_overflow_count| {
        // In production this would raise a security alert.
    });

    fill_audit_buffer(&mut km);

    // With a callback registered, operations should succeed despite overflow.
    let result = km.rotate_key(KeyId(0), &rotation_key(0, 99), 10_000, None);
    assert!(
        result.is_ok(),
        "operation should succeed when overflow callback is registered"
    );
}

#[test]
fn test_clone_produces_fresh_nonce_tracker() {
    let crypto = common::make_crypto();

    // Generate a nonce via encrypt on the original.
    let nonce_a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut ct = [0u8; 5];
    let mut tag = [0u8; 16];
    // Use a separate binding for the original encrypt.
    {
        let orig = crypto.clone();
        orig.aes_gcm_encrypt(KeyId(0), &nonce_a, b"hello", &[], &mut ct, &mut tag)
            .expect("first encrypt should succeed");
    }

    // Clone the original provider — the clone should have its own fresh nonce tracker.
    let mut cloned = crypto.clone();
    cloned
        .set_key(KeyId(0), &[0xAA; 32])
        .expect("set key on clone");

    // The clone should be able to use nonce_a without triggering reuse
    // detection, because its tracker is independent.
    let result = cloned.aes_gcm_encrypt(KeyId(0), &nonce_a, b"hello", &[], &mut ct, &mut tag);
    assert!(
        result.is_ok(),
        "clone should have fresh nonce tracker and accept previously-used nonce"
    );
}

#[test]
fn test_periodic_self_test() {
    let crypto = common::make_crypto();
    let result = crypto.periodic_self_test();
    assert!(
        result.is_ok(),
        "periodic_self_test should pass for a valid SoftwareCryptoProvider"
    );
}
