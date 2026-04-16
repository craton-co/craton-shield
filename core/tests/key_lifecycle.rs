// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the key manager (`vs_key_manager`).

mod common;

use common::make_crypto;
use vs_crypto::SoftwareCryptoProvider;
use vs_key_manager::{AuditEventType, KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_manager() -> KeyManager<SoftwareCryptoProvider> {
    KeyManager::new(make_crypto())
}

fn default_metadata(key_id: KeyId, expires_at: Option<u64>) -> KeyMetadata {
    KeyMetadata {
        key_id,
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    }
}

/// Non-uniform 32-byte key material.  The key manager rejects uniform
/// (all-same-byte) keys, so we build a varied-byte buffer.
fn test_key_a() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x10);
    }
    k
}

fn test_key_b() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x50);
    }
    k
}

#[allow(dead_code)]
fn test_key_c() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x90);
    }
    k
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn key_provision_and_retrieve() {
    let mut manager = make_manager();
    let key = test_key_a();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &key)
        .expect("provision");

    assert!(manager.is_key_valid(KeyId(1), 5000));

    manager
        .with_key_material(KeyId(1), 5000, |material| {
            assert_eq!(material, &key);
        })
        .expect("get material");
}

#[test]
fn key_expired_is_invalid() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(10_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    assert!(manager.is_key_valid(KeyId(1), 5000));
    assert!(!manager.is_key_valid(KeyId(1), 20_000));
    assert!(manager.with_key_material(KeyId(1), 20_000, |_| {}).is_err());
}

#[test]
fn key_rotation() {
    let mut manager = make_manager();
    let key_b = test_key_b();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    manager
        .rotate_key(KeyId(1), &key_b, 5000, None)
        .expect("rotate");

    manager
        .with_key_material(KeyId(1), 6000, |material| {
            assert_eq!(material, &key_b);
        })
        .expect("get material");

    let meta = manager.get_metadata(KeyId(1)).expect("metadata present");
    assert!(
        meta.rotation_count >= 1,
        "rotation_count should have increased"
    );
}

#[test]
fn key_revocation() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    manager.revoke_key(KeyId(1), 5000).expect("revoke");

    assert!(!manager.is_key_valid(KeyId(1), 6000));
    assert!(manager.with_key_material(KeyId(1), 6000, |_| {}).is_err());
}

#[test]
fn key_audit_trail() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");
    manager
        .rotate_key(KeyId(1), &test_key_b(), 5000, None)
        .expect("rotate");
    manager.revoke_key(KeyId(1), 6000).expect("revoke");

    assert!(
        manager.audit_count() >= 3,
        "expected at least 3 audit entries, got {}",
        manager.audit_count()
    );

    let event_types: Vec<AuditEventType> = manager.audit_iter().map(|e| e.event_type).collect();

    assert!(
        event_types.contains(&AuditEventType::KeyProvisioned),
        "missing KeyProvisioned event"
    );
    assert!(
        event_types.contains(&AuditEventType::KeyRotated),
        "missing KeyRotated event"
    );
    assert!(
        event_types.contains(&AuditEventType::KeyRevoked),
        "missing KeyRevoked event"
    );
}

#[test]
fn key_capacity() {
    let mut manager = make_manager();

    let (used, total) = manager.key_capacity();
    assert_eq!(used, 0);
    assert_eq!(total, 64);

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    let (used, total) = manager.key_capacity();
    assert_eq!(used, 1);
    assert_eq!(total, 64);
}

#[test]
fn key_duplicate_provision_fails() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("first provision");

    let metadata2 = default_metadata(KeyId(1), Some(2_000_000));
    let result = manager.provision_key(KeyId(1), metadata2, &test_key_b());
    assert!(result.is_err(), "duplicate provision should fail");
}

#[test]
fn key_not_found() {
    let manager = make_manager();

    assert!(!manager.is_key_valid(KeyId(99), 0));
    assert!(manager.with_key_material(KeyId(99), 0, |_| {}).is_err());
}

#[test]
fn key_purpose_and_algorithm_check() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(1_000_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    // Correct purpose and algorithm — should succeed.
    let result = manager.with_key_material_for(
        KeyId(1),
        KeyPurpose::BusAuthentication,
        KeyAlgorithm::Aes256Gcm,
        5000,
        |_| {},
    );
    assert!(result.is_ok(), "matching purpose/algorithm should succeed");

    // Wrong purpose — should fail.
    let result = manager.with_key_material_for(
        KeyId(1),
        KeyPurpose::FirmwareVerification,
        KeyAlgorithm::Aes256Gcm,
        5000,
        |_| {},
    );
    assert!(result.is_err(), "mismatched purpose should fail");
}

#[test]
fn key_tick_expires_keys() {
    let mut manager = make_manager();

    let metadata = default_metadata(KeyId(1), Some(10_000));
    manager
        .provision_key(KeyId(1), metadata, &test_key_a())
        .expect("provision");

    // Key is valid before expiry.
    assert!(manager.is_key_valid(KeyId(1), 5000));

    // Advance time past expiry via tick.
    manager.tick(20_000);

    // Key should now be expired / invalid.
    assert!(!manager.is_key_valid(KeyId(1), 20_000));
}

// ---------------------------------------------------------------------------
// Audit fail-closed in key lifecycle context
// ---------------------------------------------------------------------------

/// Build a non-uniform 32-byte key for a given slot index.
fn slot_key(slot: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(slot as u8).wrapping_add(0x10);
    }
    k
}

/// Build a different non-uniform 32-byte key for rotation round.
fn rotate_key_material(slot: u32, round: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_add(slot as u8)
            .wrapping_add(round as u8)
            .wrapping_add(0x50);
    }
    k
}

#[test]
fn test_key_manager_fail_closed_audit() {
    use vs_types::VsError;

    let mut manager = make_manager();
    manager.set_audit_fail_closed(true);

    // Provision 64 keys (all available slots) → 64 audit entries.
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
        manager
            .provision_key(KeyId(slot), meta, &slot_key(slot))
            .expect("provision key");
    }

    // Rotate each key 3 times → 192 audit entries. Total = 256.
    for round in 1..=3u32 {
        for slot in 0..64u32 {
            manager
                .rotate_key(
                    KeyId(slot),
                    &rotate_key_material(slot, round),
                    1000 + (round as u64) * 1000,
                    None,
                )
                .expect("rotate key");
        }
    }

    assert_eq!(
        manager.audit_count(),
        256,
        "audit buffer should be exactly full"
    );

    // With fail-closed enabled and no callback, the next operation must fail.
    let result = manager.rotate_key(KeyId(0), &rotate_key_material(0, 99), 10_000, None);
    assert_eq!(
        result,
        Err(VsError::ResourceExhausted),
        "fail-closed audit should reject operations when buffer overflows"
    );
}
