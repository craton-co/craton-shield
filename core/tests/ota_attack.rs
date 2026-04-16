// SPDX-License-Identifier: Apache-2.0
//! OTA security integration tests.
//!
//! Exercises the `OtaValidator` with a `SoftwareCryptoProvider` to verify
//! TUF/Uptane root updates and target hash verification.

use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_ota_validator::{KeyType, OtaValidator, SignedMetadata, TufKey, TufRoot, TufSignature};
use vs_types::KeyId;
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic RNG for tests.
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

/// Create a `TufKey` with key_id[0] set to `id_byte`.
fn make_key(id_byte: u8) -> TufKey {
    let mut key_id = [0u8; 32];
    key_id[0] = id_byte;
    TufKey {
        key_id,
        key_type: KeyType::EcdsaP256,
        public_key: [0x04; 65],
    }
}

/// Create a `TufSignature` with key_id[0] = `key_byte` and sig[0] = `sig_byte`.
fn make_sig(key_byte: u8, sig_byte: u8) -> TufSignature {
    let mut key_id = [0u8; 32];
    key_id[0] = key_byte;
    let mut sig = [0u8; 64];
    sig[0] = sig_byte;
    TufSignature { key_id, sig }
}

/// Build a root with `n_keys` keys (key_id[0] = 1, 2, ...) and the given
/// `threshold`.
fn make_root(version: u32, expires_us: u64, n_keys: usize, threshold: u8) -> TufRoot {
    let mut root_keys: [Option<TufKey>; 4] = [None, None, None, None];
    for (i, slot) in root_keys.iter_mut().enumerate().take(n_keys.min(4)) {
        *slot = Some(make_key(i as u8 + 1));
    }
    TufRoot {
        version,
        expires_us,
        root_keys,
        threshold,
        targets_keys: [None; 4],
        targets_threshold: 0,
        snapshot_keys: [None; 4],
        snapshot_threshold: 0,
        timestamp_keys: [None; 4],
        timestamp_threshold: 0,
    }
}

/// Build signed metadata.
///
/// The `SoftwareCryptoProvider::verify_p256` does real P-256 verification,
/// so we cannot use arbitrary "mock" signatures here. Instead, the OTA
/// validator unit tests use a `TestCrypto` mock where
/// `verify_p256(pub_key, digest, sig)` returns `Ok(digest[0] == sig[0])`.
///
/// For this integration test we test against `SoftwareCryptoProvider` which
/// does real ECDSA. Since we do not have matching private keys for our
/// `TufKey` placeholders, the signatures will fail verification. This is
/// intentional for negative-path tests; for the positive-path test we
/// construct the validator with a `TestCrypto`-style mock to validate the
/// full flow.
fn make_signed_metadata(
    version: u32,
    expires_us: u64,
    sigs: &[TufSignature],
    content_hash_byte0: u8,
) -> SignedMetadata {
    let mut signatures: [Option<TufSignature>; 4] = [None, None, None, None];
    for (i, s) in sigs.iter().enumerate().take(4) {
        signatures[i] = Some(*s);
    }
    let mut content_hash = [0u8; 32];
    content_hash[0] = content_hash_byte0;
    SignedMetadata {
        version,
        expires_us,
        signatures,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Mock crypto provider for positive-path OTA tests
//
// WARNING — TEST-ONLY MOCK. DO NOT USE IN PRODUCTION.
//
// `MockOtaCrypto` performs no real cryptographic verification. It accepts
// any ECDSA signature where `sig[0] == digest[0]` (a single-byte check).
// This is intentional for unit-testing the OTA validator's control flow
// (rollback detection, expiry, threshold counting) in isolation from the
// crypto backend. Using this mock in production would be a **complete
// authentication bypass**.
// ---------------------------------------------------------------------------

/// Test-only mock crypto — accepts signatures where `sig[0] == digest[0]`.
///
/// # Safety
///
/// This type exists solely for integration tests. It is not exported, not
/// public, and not reachable from any library crate. If you need a mock for
/// a new test, prefer reusing this rather than weakening the real provider.
#[cfg(test)]
struct MockOtaCrypto;

#[cfg(test)]
impl CryptoProvider for MockOtaCrypto {
    fn aes_gcm_encrypt(
        &self,
        _: vs_crypto::KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
        _: &mut [u8; 16],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn aes_gcm_decrypt(
        &self,
        _: vs_crypto::KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &[u8; 16],
        _: &mut [u8],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Simple deterministic mixing (same as the OTA crate's TestCrypto).
        *hash_out = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash_out[i % 32] ^= byte;
            hash_out[(i.wrapping_add(7)) % 32] =
                hash_out[(i.wrapping_add(7)) % 32].wrapping_add(byte);
        }
        Ok(())
    }
    fn hmac_sha256(&self, _: vs_crypto::KeyId, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn ecdh_derive_shared(
        &self,
        _: vs_crypto::KeyId,
        _: &[u8; 65],
        _: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn sign_p256(
        &self,
        _: vs_crypto::KeyId,
        _: &[u8; 32],
        _: &mut [u8; 64],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn verify_p256(
        &self,
        _pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        // WARNING: MOCK ONLY — NOT REAL VERIFICATION.
        // Accepts any signature where the first byte matches the digest.
        // This is deliberately trivial so OTA control-flow logic can be
        // tested independently of the real P-256 implementation.
        Ok(digest[0] == sig[0])
    }
    fn random_bytes(&self, _buf: &mut [u8]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn delete_key(&mut self, _: vs_crypto::KeyId) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn generate_key(&mut self, _: vs_crypto::KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn valid_root_update_succeeds() {
    let root = make_root(1, 1_000_000, 2, 2);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // Two valid signatures: both have sig[0] == content_hash[0] == 0xAA.
    let sigs = [make_sig(1, 0xAA), make_sig(2, 0xAA)];
    let metadata = make_signed_metadata(2, 2_000_000, &sigs, 0xAA);
    let new_root = make_root(2, 2_000_000, 2, 2);

    let result = validator.verify_root_update(&metadata, &new_root, 500_000);
    assert!(result.is_ok(), "valid root update must succeed");
    assert_eq!(validator.rollback_version(), 2);
}

#[test]
fn rollback_lower_version_rejected() {
    let root = make_root(5, 10_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // Attempt to "update" to version 3 (lower than current 5).
    let sigs = [make_sig(1, 0xCC)];
    let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xCC);
    let new_root = make_root(3, 10_000_000, 2, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 1_000);
    assert_eq!(result, Err(VsError::PolicyViolation));
}

#[test]
fn rollback_same_version_rejected() {
    let root = make_root(5, 10_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // Attempt to "update" to version 5 (same as current).
    let sigs = [make_sig(1, 0xCC)];
    let metadata = make_signed_metadata(5, 10_000_000, &sigs, 0xCC);
    let new_root = make_root(5, 10_000_000, 2, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 1_000);
    assert_eq!(result, Err(VsError::PolicyViolation));
}

#[test]
fn expired_metadata_rejected() {
    let root = make_root(1, 1_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    let sigs = [make_sig(1, 0xBB)];
    // Metadata expires at 500_000 us.
    let metadata = make_signed_metadata(2, 500_000, &sigs, 0xBB);
    let new_root = make_root(2, 500_000, 2, 1);

    // Current time 600_000 >= expires 500_000 -- expired.
    let result = validator.verify_root_update(&metadata, &new_root, 600_000);
    assert_eq!(result, Err(VsError::AuthenticationFailure));
}

#[test]
fn target_hash_mismatch_rejected() {
    let root = make_root(1, 1_000_000, 1, 1);
    let validator = OtaValidator::new(make_crypto(), root).unwrap();

    let firmware = b"legitimate firmware image";
    let wrong_hash = [0xFF; 32];
    let result = validator.verify_target(&wrong_hash, firmware.len() as u64, firmware);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

#[test]
fn target_valid_hash_passes() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    // Compute the correct hash with the same crypto provider.
    let firmware = b"legitimate firmware image";
    let mut expected_hash = [0u8; 32];
    crypto
        .sha256(firmware, &mut expected_hash)
        .expect("SHA-256 computation should succeed");

    let validator = OtaValidator::new(crypto, root).unwrap();
    let result = validator.verify_target(&expected_hash, firmware.len() as u64, firmware);
    assert!(result.is_ok(), "valid target must pass verification");
}

#[test]
fn target_length_mismatch_rejected() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    let firmware = b"legitimate firmware image";
    let mut expected_hash = [0u8; 32];
    crypto
        .sha256(firmware, &mut expected_hash)
        .expect("SHA-256 computation should succeed");

    let validator = OtaValidator::new(crypto, root).unwrap();
    // Provide wrong length.
    let result = validator.verify_target(&expected_hash, 999, firmware);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

#[test]
fn insufficient_threshold_signatures_rejected() {
    // Root requires threshold=2 but we provide only 1 valid signature.
    let root = make_root(1, 1_000_000, 2, 2);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // Only key 1's signature matches the hash (sig[0]==0xAA == content_hash[0]).
    // Key 2's signature does NOT match (sig[0]==0xFF != 0xAA).
    let sigs = [make_sig(1, 0xAA), make_sig(2, 0xFF)];
    let metadata = make_signed_metadata(2, 2_000_000, &sigs, 0xAA);
    let new_root = make_root(2, 2_000_000, 2, 2);

    let result = validator.verify_root_update(&metadata, &new_root, 500_000);
    assert_eq!(result, Err(VsError::AuthenticationFailure));
}

#[test]
fn sequential_root_upgrades_advance_rollback_counter() {
    let root = make_root(1, 5_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // Upgrade 1 -> 2
    let sigs = [make_sig(1, 0xDD)];
    let meta_v2 = make_signed_metadata(2, 5_000_000, &sigs, 0xDD);
    let root_v2 = make_root(2, 5_000_000, 2, 1);
    validator
        .verify_root_update(&meta_v2, &root_v2, 100)
        .expect("root update v1->v2 should succeed");
    assert_eq!(validator.rollback_version(), 2);

    // Upgrade 2 -> 3
    let meta_v3 = make_signed_metadata(3, 5_000_000, &sigs, 0xDD);
    let root_v3 = make_root(3, 5_000_000, 2, 1);
    validator
        .verify_root_update(&meta_v3, &root_v3, 200)
        .expect("root update v2->v3 should succeed");
    assert_eq!(validator.rollback_version(), 3);

    // Downgrade attempt 3 -> 2 must fail.
    let result = validator.verify_root_update(&meta_v2, &root_v2, 300);
    assert_eq!(result, Err(VsError::PolicyViolation));
}

// ---------------------------------------------------------------------------
// Additional tests
// ---------------------------------------------------------------------------

#[test]
fn valid_target_with_large_firmware() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    // 1024-byte firmware blob.
    let firmware = [0xABu8; 1024];
    let mut expected_hash = [0u8; 32];
    crypto
        .sha256(&firmware, &mut expected_hash)
        .expect("SHA-256 computation should succeed");

    let validator = OtaValidator::new(crypto, root).unwrap();
    let result = validator.verify_target(&expected_hash, 1024, &firmware);
    assert!(result.is_ok(), "1024-byte firmware must pass verification");
}

#[test]
fn multiple_sequential_root_updates_1_to_4() {
    let root = make_root(1, 10_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    let sigs = [make_sig(1, 0xEE)];

    // Upgrade 1 -> 2
    let meta_v2 = make_signed_metadata(2, 10_000_000, &sigs, 0xEE);
    let root_v2 = make_root(2, 10_000_000, 2, 1);
    validator
        .verify_root_update(&meta_v2, &root_v2, 100)
        .expect("root update v1->v2 should succeed");
    assert_eq!(validator.rollback_version(), 2);

    // Upgrade 2 -> 3
    let meta_v3 = make_signed_metadata(3, 10_000_000, &sigs, 0xEE);
    let root_v3 = make_root(3, 10_000_000, 2, 1);
    validator
        .verify_root_update(&meta_v3, &root_v3, 200)
        .expect("root update v2->v3 should succeed");
    assert_eq!(validator.rollback_version(), 3);

    // Upgrade 3 -> 4
    let meta_v4 = make_signed_metadata(4, 10_000_000, &sigs, 0xEE);
    let root_v4 = make_root(4, 10_000_000, 2, 1);
    validator
        .verify_root_update(&meta_v4, &root_v4, 300)
        .expect("root update v3->v4 should succeed");
    assert_eq!(validator.rollback_version(), 4);
}

#[test]
fn root_threshold_1_with_1_valid_key_passes() {
    // threshold=1, 1 key, 1 valid signature.
    let root = make_root(1, 5_000_000, 1, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    let sigs = [make_sig(1, 0xBB)];
    let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xBB);
    let new_root = make_root(2, 5_000_000, 1, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 100);
    assert!(result.is_ok(), "threshold=1 with 1 valid sig must succeed");
}

#[test]
fn root_threshold_4_needs_all_4_keys() {
    // threshold=4, 4 keys. All 4 signatures must be valid.
    let root = make_root(1, 5_000_000, 4, 4);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // All 4 signatures match the content hash (0xAA).
    let sigs = [
        make_sig(1, 0xAA),
        make_sig(2, 0xAA),
        make_sig(3, 0xAA),
        make_sig(4, 0xAA),
    ];
    let metadata = make_signed_metadata(2, 5_000_000, &sigs, 0xAA);
    let new_root = make_root(2, 5_000_000, 4, 4);

    let result = validator.verify_root_update(&metadata, &new_root, 100);
    assert!(
        result.is_ok(),
        "threshold=4 with all 4 valid sigs must succeed"
    );
    assert_eq!(validator.rollback_version(), 2);
}

#[test]
fn target_empty_firmware_correct_hash() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    // Empty firmware (0 bytes).
    let firmware: &[u8] = &[];
    let mut expected_hash = [0u8; 32];
    crypto
        .sha256(firmware, &mut expected_hash)
        .expect("SHA-256 computation should succeed");

    let validator = OtaValidator::new(crypto, root).unwrap();
    let result = validator.verify_target(&expected_hash, 0, firmware);
    assert!(result.is_ok(), "empty firmware with correct hash must pass");
}

#[test]
fn expired_metadata_with_zero_expires() {
    let root = make_root(1, 1_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    let sigs = [make_sig(1, 0xCC)];
    // Metadata expires at t=0 -- any current time >= 0 makes it expired.
    let metadata = make_signed_metadata(2, 0, &sigs, 0xCC);
    let new_root = make_root(2, 0, 2, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 0);
    assert_eq!(
        result,
        Err(VsError::AuthenticationFailure),
        "metadata with expires_us=0 and current_time=0 must be rejected"
    );
}

#[test]
fn root_version_at_u32_max_boundary() {
    // Start at version u32::MAX - 1, try upgrading to u32::MAX.
    let root = make_root(u32::MAX - 1, 10_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    let sigs = [make_sig(1, 0xFF)];
    let metadata = make_signed_metadata(u32::MAX, 10_000_000, &sigs, 0xFF);
    let new_root = make_root(u32::MAX, 10_000_000, 2, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 100);
    assert!(result.is_ok(), "upgrade to u32::MAX must succeed");
    assert_eq!(validator.rollback_version(), u32::MAX);
}

#[test]
fn target_hash_computed_correctly_via_sha256() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    let firmware = b"cratonshield firmware v2.1.0 payload data block";
    let mut hash1 = [0u8; 32];
    let mut hash2 = [0u8; 32];
    crypto
        .sha256(firmware, &mut hash1)
        .expect("first SHA-256 computation should succeed");
    crypto
        .sha256(firmware, &mut hash2)
        .expect("second SHA-256 computation should succeed");

    // Same input must produce same hash.
    assert_eq!(hash1, hash2, "SHA-256 must be deterministic");

    let validator = OtaValidator::new(crypto, root).unwrap();
    let result = validator.verify_target(&hash1, firmware.len() as u64, firmware);
    assert!(result.is_ok(), "correct hash must pass verification");
}

#[test]
fn multiple_verify_target_calls_on_same_validator() {
    let crypto = make_crypto();
    let root = make_root(1, 1_000_000, 1, 1);

    let firmware_a = b"firmware image A";
    let mut hash_a = [0u8; 32];
    crypto
        .sha256(firmware_a, &mut hash_a)
        .expect("SHA-256 of firmware A should succeed");

    let firmware_b = b"firmware image B";
    let mut hash_b = [0u8; 32];
    crypto
        .sha256(firmware_b, &mut hash_b)
        .expect("SHA-256 of firmware B should succeed");

    let validator = OtaValidator::new(crypto, root).unwrap();

    // First verification.
    let result_a = validator.verify_target(&hash_a, firmware_a.len() as u64, firmware_a);
    assert!(result_a.is_ok(), "first verify_target must succeed");

    // Second verification with different firmware.
    let result_b = validator.verify_target(&hash_b, firmware_b.len() as u64, firmware_b);
    assert!(result_b.is_ok(), "second verify_target must succeed");

    // Cross-check: hash_a should NOT validate firmware_b.
    let result_cross = validator.verify_target(&hash_a, firmware_b.len() as u64, firmware_b);
    assert_eq!(result_cross, Err(VsError::IntegrityFailure));
}

#[test]
fn root_with_zero_valid_signatures_fails() {
    // Root requires threshold=1 but we provide 0 valid signatures.
    let root = make_root(1, 5_000_000, 2, 1);
    let mut validator = OtaValidator::new(MockOtaCrypto, root).unwrap();

    // No signatures at all (empty slice).
    let metadata = make_signed_metadata(2, 5_000_000, &[], 0xAA);
    let new_root = make_root(2, 5_000_000, 2, 1);

    let result = validator.verify_root_update(&metadata, &new_root, 100);
    assert_eq!(
        result,
        Err(VsError::AuthenticationFailure),
        "0 valid signatures must fail when threshold >= 1"
    );
}
