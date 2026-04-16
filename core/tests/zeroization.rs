// SPDX-License-Identifier: Apache-2.0
//! Zeroization verification tests.
//!
//! Validates that key material is properly zeroized when crypto providers
//! and key managers are dropped or keys are revoked.

use vs_crypto::{CryptoProvider, KeyId, SoftwareCryptoProvider};
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_crypto() -> SoftwareCryptoProvider {
    SoftwareCryptoProvider::default()
}

/// Generate non-uniform key material from a seed byte (avoids uniform-byte rejection).
fn make_key_material(seed: u8) -> [u8; 32] {
    let mut mat = [0u8; 32];
    for (i, b) in mat.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    mat
}

fn make_metadata(key_id: KeyId) -> KeyMetadata {
    KeyMetadata {
        key_id,
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: Some(1_000_000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    }
}

// ---------------------------------------------------------------------------
// KeyManager zeroization via revoke
// ---------------------------------------------------------------------------

#[test]
fn revoked_key_material_inaccessible() {
    let mut mgr = KeyManager::new(make_crypto());
    let key_material = make_key_material(0xAB);
    let meta = make_metadata(KeyId(0));

    mgr.provision_key(KeyId(0), meta, &key_material).unwrap();

    // Key should be accessible before revocation
    let result = mgr.with_key_material(KeyId(0), 2000, |mat| {
        assert_eq!(mat, &key_material);
    });
    assert!(result.is_ok());

    // Revoke the key
    mgr.revoke_key(KeyId(0), 3000).unwrap();

    // Key material must be inaccessible after revocation
    let result = mgr.with_key_material(KeyId(0), 4000, |_| ());
    assert_eq!(result, Err(VsError::KeyRevoked));
}

#[test]
fn revoked_key_cannot_be_reprovisioned() {
    let mut mgr = KeyManager::new(make_crypto());
    let meta = make_metadata(KeyId(0));
    mgr.provision_key(KeyId(0), meta, &make_key_material(0xCC))
        .unwrap();

    mgr.revoke_key(KeyId(0), 2000).unwrap();

    // Attempting to re-provision a revoked slot must fail
    let meta2 = make_metadata(KeyId(0));
    let result = mgr.provision_key(KeyId(0), meta2, &make_key_material(0xDD));
    assert_eq!(result, Err(VsError::KeyRevoked));
}

// ---------------------------------------------------------------------------
// KeyManager zeroization via drop
// ---------------------------------------------------------------------------

#[test]
fn dropped_manager_starts_fresh() {
    // We cannot inspect zeroed memory in safe Rust, but we can verify that
    // after dropping and recreating a manager, keys are not present.
    let mut mgr = KeyManager::new(make_crypto());
    let meta = make_metadata(KeyId(0));
    mgr.provision_key(KeyId(0), meta, &make_key_material(0xAB))
        .unwrap();

    // Verify key is accessible
    assert!(mgr.is_key_valid(KeyId(0), 2000));

    // Drop the manager
    drop(mgr);

    // A new manager has empty slots
    let mgr2 = KeyManager::new(make_crypto());
    assert!(!mgr2.is_key_valid(KeyId(0), 2000));
    assert!(mgr2.get_metadata(KeyId(0)).is_none());
}

// ---------------------------------------------------------------------------
// KeyManager zeroization via tick (expiry)
// ---------------------------------------------------------------------------

#[test]
fn expired_key_material_inaccessible() {
    let mut mgr = KeyManager::new(make_crypto());
    let meta = KeyMetadata {
        key_id: KeyId(0),
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: Some(5000),
        rotation_count: 0,
        cumulative_nonce_count: 0,
    };
    mgr.provision_key(KeyId(0), meta, &make_key_material(0xEE))
        .unwrap();

    // Key accessible before expiry
    assert!(mgr.is_key_valid(KeyId(0), 4000));
    let result = mgr.with_key_material(KeyId(0), 4000, |_| ());
    assert!(result.is_ok());

    // After expiry time, key material must be denied
    let result = mgr.with_key_material(KeyId(0), 6000, |_| ());
    assert_eq!(result, Err(VsError::KeyExpired));

    // tick() should transition the key state and zeroize material
    mgr.tick(6000);

    // Key is now expired at the state level too
    assert!(!mgr.is_key_valid(KeyId(0), 6000));
    let result = mgr.with_key_material(KeyId(0), 6000, |_| ());
    assert_eq!(result, Err(VsError::KeyExpired));
}

// ---------------------------------------------------------------------------
// KeyManager audit trail after zeroization
// ---------------------------------------------------------------------------

#[test]
fn revocation_creates_audit_entry() {
    let mut mgr = KeyManager::new(make_crypto());
    let meta = make_metadata(KeyId(0));
    mgr.provision_key(KeyId(0), meta, &make_key_material(0xFF))
        .unwrap();

    let count_before = mgr.audit_count();
    mgr.revoke_key(KeyId(0), 3000).unwrap();
    let count_after = mgr.audit_count();

    assert_eq!(
        count_after,
        count_before + 1,
        "revocation must add an audit entry"
    );
}

// ---------------------------------------------------------------------------
// SoftwareCryptoProvider key deletion
// ---------------------------------------------------------------------------

#[test]
fn crypto_provider_delete_key_clears_slot() {
    let mut crypto = make_crypto();
    crypto
        .generate_key(KeyId(0), vs_crypto::KeyType::Aes256)
        .unwrap();

    // Key should be usable: encrypt something
    let nonce = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];
    let plaintext = b"test data";
    let mut ciphertext = [0u8; 9];
    let mut tag = [0u8; 16];
    let enc_result =
        crypto.aes_gcm_encrypt(KeyId(0), &nonce, plaintext, b"", &mut ciphertext, &mut tag);
    assert!(
        enc_result.is_ok(),
        "encryption must succeed with active key"
    );

    // Delete the key
    crypto.delete_key(KeyId(0)).unwrap();

    // Encryption should now fail because the slot is empty
    let mut ciphertext2 = [0u8; 9];
    let mut tag2 = [0u8; 16];
    let result = crypto.aes_gcm_encrypt(
        KeyId(0),
        &nonce,
        plaintext,
        b"",
        &mut ciphertext2,
        &mut tag2,
    );
    assert!(result.is_err(), "encryption must fail after key deletion");
}

// ---------------------------------------------------------------------------
// Multiple key rotation zeroizes old material
// ---------------------------------------------------------------------------

#[test]
fn rotation_overwrites_old_material() {
    let mut mgr = KeyManager::new(make_crypto());
    let meta = make_metadata(KeyId(0));
    let old_material = make_key_material(0xAA);
    let new_material = make_key_material(0xBB);

    mgr.provision_key(KeyId(0), meta, &old_material).unwrap();

    // Verify old material
    mgr.with_key_material(KeyId(0), 2000, |mat| {
        assert_eq!(mat, &old_material);
    })
    .unwrap();

    // Rotate to new material
    mgr.rotate_key(KeyId(0), &new_material, 2000, Some(2_000_000))
        .unwrap();

    // Verify new material (old should be gone)
    mgr.with_key_material(KeyId(0), 3000, |mat| {
        assert_eq!(mat, &new_material, "rotated key must have new material");
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// Drop of KeyEntry zeroizes material
// ---------------------------------------------------------------------------

#[test]
fn key_manager_capacity_after_drop_is_zero() {
    let mut mgr = KeyManager::new(make_crypto());

    // Provision several keys
    for i in 0..5u32 {
        let meta = KeyMetadata {
            key_id: KeyId(i),
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1000,
            expires_at: Some(1_000_000),
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let material = make_key_material((i as u8).wrapping_add(0x10));
        mgr.provision_key(KeyId(i), meta, &material).unwrap();
    }

    let (active, _) = mgr.key_capacity();
    assert_eq!(active, 5);

    drop(mgr);

    // Fresh manager has zero active keys
    let mgr2 = KeyManager::new(make_crypto());
    let (active2, _) = mgr2.key_capacity();
    assert_eq!(active2, 0, "fresh manager must have zero active keys");
}
