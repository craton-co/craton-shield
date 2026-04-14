// SPDX-License-Identifier: Apache-2.0
//! Adversarial and edge-case tests for the key manager.
//!
//! These tests verify correct error differentiation (KeyExpired vs KeyRevoked
//! vs NotInitialized), audit overflow callbacks, and boundary conditions.

mod common;

use common::make_crypto;
use vs_crypto::SoftwareCryptoProvider;
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_types::{KeyId, VsError};

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

fn test_key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    k
}

// ---------------------------------------------------------------------------
// Error differentiation tests
// ---------------------------------------------------------------------------

#[test]
fn revoked_key_returns_key_revoked_error() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
    mgr.revoke_key(KeyId(0), 2000).unwrap();

    assert_eq!(
        mgr.with_key_material(KeyId(0), 3000, |_| {}),
        Err(VsError::KeyRevoked)
    );
}

#[test]
fn expired_key_returns_key_expired_error() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), Some(5000));
    mgr.provision_key(KeyId(0), meta, &test_key(0xBB)).unwrap();

    // Before expiry — should work.
    assert!(mgr.with_key_material(KeyId(0), 4999, |_| {}).is_ok());

    // After expiry — should return KeyExpired.
    assert_eq!(
        mgr.with_key_material(KeyId(0), 5000, |_| {}),
        Err(VsError::KeyExpired)
    );
}

#[test]
fn expired_key_via_tick_returns_key_expired() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), Some(5000));
    mgr.provision_key(KeyId(0), meta, &test_key(0xCC)).unwrap();

    mgr.tick(6000);

    assert_eq!(
        mgr.with_key_material(KeyId(0), 6000, |_| {}),
        Err(VsError::KeyExpired)
    );
}

#[test]
fn empty_slot_returns_not_initialized() {
    let mgr = make_manager();
    assert_eq!(
        mgr.with_key_material(KeyId(0), 1000, |_| {}),
        Err(VsError::NotInitialized)
    );
}

#[test]
fn out_of_range_key_returns_not_found() {
    let mgr = make_manager();
    assert_eq!(
        mgr.with_key_material(KeyId(999), 1000, |_| {}),
        Err(VsError::NotFound)
    );
}

#[test]
fn reprovisioning_revoked_slot_returns_key_revoked() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
    mgr.revoke_key(KeyId(0), 2000).unwrap();

    let meta2 = default_metadata(KeyId(0), None);
    assert_eq!(
        mgr.provision_key(KeyId(0), meta2, &test_key(0xBB)),
        Err(VsError::KeyRevoked)
    );
}

#[test]
fn rotating_revoked_key_returns_key_revoked() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
    mgr.revoke_key(KeyId(0), 2000).unwrap();

    assert_eq!(
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 3000, None),
        Err(VsError::KeyRevoked)
    );
}

#[test]
fn rotating_expired_key_returns_key_expired() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), Some(5000));
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
    mgr.tick(6000);

    assert_eq!(
        mgr.rotate_key(KeyId(0), &test_key(0xBB), 7000, None),
        Err(VsError::KeyExpired)
    );
}

#[test]
fn revoking_expired_key_returns_key_expired() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), Some(5000));
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();
    mgr.tick(6000);

    assert_eq!(mgr.revoke_key(KeyId(0), 7000), Err(VsError::KeyExpired));
}

#[test]
fn get_key_material_for_with_wrong_purpose_on_valid_key() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.provision_key(KeyId(0), meta, &test_key(0xDD)).unwrap();

    assert_eq!(
        mgr.with_key_material_for(
            KeyId(0),
            KeyPurpose::OtaUpdate,
            KeyAlgorithm::Aes256Gcm,
            2000,
            |_| {},
        ),
        Err(VsError::PolicyViolation)
    );
}

#[test]
fn with_key_material_callback_pattern() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    let key = test_key(0xEE);
    mgr.provision_key(KeyId(0), meta, &key).unwrap();

    let len = mgr
        .with_key_material(KeyId(0), 2000, |material| material.len())
        .unwrap();
    assert_eq!(len, 32);
}

// ---------------------------------------------------------------------------
// Audit overflow callback test (V11)
// ---------------------------------------------------------------------------

#[test]
fn audit_overflow_callback_is_invoked() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);

    fn on_overflow(count: u64) {
        OVERFLOW_COUNT.store(count, Ordering::SeqCst);
    }

    OVERFLOW_COUNT.store(0, Ordering::SeqCst);

    let mut mgr = make_manager();
    mgr.set_audit_overflow_callback(on_overflow);

    // Fill the audit buffer (capacity=256) by provisioning many keys.
    for i in 0..64u32 {
        let meta = KeyMetadata {
            key_id: KeyId(i),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: u64::from(i),
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let _ = mgr.provision_key(KeyId(i), meta, &test_key(i as u8));
    }

    // Each provision generates 1 audit entry = 64 entries.
    // Now rotate all keys multiple times to overflow the 256-entry ring.
    for round in 0..4u64 {
        for i in 0..64u32 {
            let _ = mgr.rotate_key(
                KeyId(i),
                &test_key((round * 64 + u64::from(i)) as u8),
                1000 + round * 100 + u64::from(i),
                None,
            );
        }
    }

    // 64 provisions + 256 rotations = 320 audit entries.
    // With capacity 256, at least 64 overflows should have occurred.
    let overflow = OVERFLOW_COUNT.load(Ordering::SeqCst);
    assert!(
        overflow > 0,
        "expected overflow callback to be invoked, got {overflow}"
    );
}

// ---------------------------------------------------------------------------
// Key material validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn all_zero_key_material_rejected() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    let result = mgr.provision_key(KeyId(0), meta, &[0u8; 32]);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn uniform_byte_key_material_rejected() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    let result = mgr.provision_key(KeyId(0), meta, &[0xFF; 32]);
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn wrong_length_key_material_rejected() {
    let mut mgr = make_manager();
    let meta = KeyMetadata {
        key_id: KeyId(0),
        algorithm: KeyAlgorithm::Aes128Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: None,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };
    // AES-128 expects 16 bytes, providing 32.
    let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
    assert_eq!(result, Err(VsError::InvalidInput));
}

#[test]
fn metadata_key_id_mismatch_rejected() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(99), None); // key_id=99 but provisioning to slot 0
    let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
    assert_eq!(result, Err(VsError::InvalidConfig));
}

#[test]
fn expiry_before_creation_rejected() {
    let mut mgr = make_manager();
    let meta = KeyMetadata {
        key_id: KeyId(0),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 5000,
        expires_at: Some(1000), // before created_at
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };
    let result = mgr.provision_key(KeyId(0), meta, &test_key(0xAA));
    assert_eq!(result, Err(VsError::InvalidConfig));
}

#[test]
fn generate_key_fills_slot() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.generate_key(KeyId(0), meta).unwrap();
    assert!(mgr.is_key_valid(KeyId(0), 2000));
    let len = mgr
        .with_key_material(KeyId(0), 2000, |material| material.len())
        .unwrap();
    assert_eq!(len, 32);
}

#[test]
fn keym_finalize_zeroizes_all_keys() {
    let mut mgr = make_manager();
    let meta = default_metadata(KeyId(0), None);
    mgr.provision_key(KeyId(0), meta, &test_key(0xAA)).unwrap();

    mgr.keym_finalize();

    assert!(!mgr.is_key_valid(KeyId(0), 2000));
}
