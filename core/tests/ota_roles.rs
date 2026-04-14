// SPDX-License-Identifier: Apache-2.0
//! OTA TUF delegation role verification tests.
//!
//! Tests verify_timestamp, verify_snapshot, verify_targets, and find_target_entry
//! functions with both positive and negative paths.

use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_ota_validator::*;
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Mock crypto provider for positive-path tests
//
// WARNING — TEST-ONLY MOCK. DO NOT USE IN PRODUCTION.
//
// `MockCrypto` performs no real cryptographic verification. It accepts
// any ECDSA signature where `sig[0] == digest[0]` (a single-byte check).
// This is intentional for unit-testing the OTA validator's control flow
// (expiry, version cross-references, threshold counting) in isolation from
// the crypto backend.
// ---------------------------------------------------------------------------

struct MockCrypto;

impl CryptoProvider for MockCrypto {
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
        // Simple deterministic mixing (same as OTA crate's TestCrypto).
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
// Helpers
// ---------------------------------------------------------------------------

fn make_key(id_byte: u8) -> TufKey {
    let mut key_id = [0u8; 32];
    key_id[0] = id_byte;
    TufKey {
        key_id,
        key_type: KeyType::EcdsaP256,
        public_key: [0x04; 65],
    }
}

fn make_sig(key_byte: u8, sig_byte: u8) -> TufSignature {
    let mut key_id = [0u8; 32];
    key_id[0] = key_byte;
    let mut sig = [0u8; 64];
    sig[0] = sig_byte;
    TufSignature { key_id, sig }
}

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
    let content_hash = [content_hash_byte0; 32];
    SignedMetadata {
        version,
        expires_us,
        signatures,
        content_hash,
    }
}

/// Build a root with per-role keys configured for timestamp, snapshot, and targets.
fn make_role_root(
    version: u32,
    expires_us: u64,
    n_root_keys: usize,
    root_threshold: u8,
) -> TufRoot {
    let mut root_keys: [Option<TufKey>; 4] = [None, None, None, None];
    for (i, slot) in root_keys.iter_mut().enumerate().take(n_root_keys.min(4)) {
        *slot = Some(make_key(i as u8 + 1));
    }

    // Timestamp keys: key_id[0] = 0x10, 0x11
    let timestamp_keys = [Some(make_key(0x10)), Some(make_key(0x11)), None, None];
    // Snapshot keys: key_id[0] = 0x20, 0x21
    let snapshot_keys = [Some(make_key(0x20)), Some(make_key(0x21)), None, None];
    // Targets keys: key_id[0] = 0x30, 0x31
    let targets_keys = [Some(make_key(0x30)), Some(make_key(0x31)), None, None];

    TufRoot {
        version,
        expires_us,
        root_keys,
        threshold: root_threshold,
        timestamp_keys,
        timestamp_threshold: 1,
        snapshot_keys,
        snapshot_threshold: 1,
        targets_keys,
        targets_threshold: 1,
    }
}

// ---------------------------------------------------------------------------
// verify_timestamp tests
// ---------------------------------------------------------------------------

#[test]
fn verify_timestamp_valid() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 10_000_000,
        snapshot_version: 3,
        snapshot_hash: [0xBB; 32],
    };
    // sig[0] must match content_hash[0] for MockCrypto to accept
    let sigs = [make_sig(0x10, 0xAA)];
    let metadata = make_signed_metadata(5, 10_000_000, &sigs, 0xAA);

    let result = verify_timestamp(&metadata, &timestamp, &root, 1_000, &MockCrypto);
    assert!(result.is_ok(), "valid timestamp must pass: {result:?}");
}

#[test]
fn verify_timestamp_expired() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 500_000,
        snapshot_version: 3,
        snapshot_hash: [0xBB; 32],
    };
    let sigs = [make_sig(0x10, 0xAA)];
    let metadata = make_signed_metadata(5, 500_000, &sigs, 0xAA);

    // current_time >= expires_us
    let result = verify_timestamp(&metadata, &timestamp, &root, 500_000, &MockCrypto);
    assert_eq!(result, Err(VsError::AuthenticationFailure));
}

#[test]
fn verify_timestamp_version_mismatch() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 10_000_000,
        snapshot_version: 3,
        snapshot_hash: [0xBB; 32],
    };
    // metadata version differs from timestamp version
    let sigs = [make_sig(0x10, 0xAA)];
    let metadata = make_signed_metadata(6, 10_000_000, &sigs, 0xAA);

    let result = verify_timestamp(&metadata, &timestamp, &root, 1_000, &MockCrypto);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

// ---------------------------------------------------------------------------
// verify_snapshot tests
// ---------------------------------------------------------------------------

#[test]
fn verify_snapshot_valid() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 10_000_000,
        snapshot_version: 3,
        snapshot_hash: [0xCC; 32],
    };
    let snapshot = TufSnapshot {
        version: 3,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xDD; 32],
    };
    // content_hash must match timestamp.snapshot_hash
    let sigs = [make_sig(0x20, 0xCC)];
    let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xCC);

    let result = verify_snapshot(&metadata, &snapshot, &timestamp, &root, 1_000, &MockCrypto);
    assert!(result.is_ok(), "valid snapshot must pass: {result:?}");
}

#[test]
fn verify_snapshot_version_mismatch() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 10_000_000,
        snapshot_version: 3,
        snapshot_hash: [0xCC; 32],
    };
    // snapshot.version != timestamp.snapshot_version
    let snapshot = TufSnapshot {
        version: 4,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xDD; 32],
    };
    let sigs = [make_sig(0x20, 0xCC)];
    let metadata = make_signed_metadata(4, 10_000_000, &sigs, 0xCC);

    let result = verify_snapshot(&metadata, &snapshot, &timestamp, &root, 1_000, &MockCrypto);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

#[test]
fn verify_snapshot_hash_mismatch() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let timestamp = TufTimestamp {
        version: 5,
        expires_us: 10_000_000,
        snapshot_version: 3,
        snapshot_hash: [0xCC; 32],
    };
    let snapshot = TufSnapshot {
        version: 3,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xDD; 32],
    };
    // content_hash[0] = 0xFF != timestamp.snapshot_hash[0] = 0xCC
    let sigs = [make_sig(0x20, 0xFF)];
    let metadata = make_signed_metadata(3, 10_000_000, &sigs, 0xFF);

    let result = verify_snapshot(&metadata, &snapshot, &timestamp, &root, 1_000, &MockCrypto);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

// ---------------------------------------------------------------------------
// verify_targets tests
// ---------------------------------------------------------------------------

#[test]
fn verify_targets_valid() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let snapshot = TufSnapshot {
        version: 3,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xEE; 32],
    };
    let targets = TufTargets {
        version: 2,
        expires_us: 10_000_000,
        targets: [None; 8],
    };
    let sigs = [make_sig(0x30, 0xEE)];
    let metadata = make_signed_metadata(2, 10_000_000, &sigs, 0xEE);

    let result = verify_targets(&metadata, &targets, &snapshot, &root, 1_000, &MockCrypto);
    assert!(result.is_ok(), "valid targets must pass: {result:?}");
}

#[test]
fn verify_targets_version_mismatch() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let snapshot = TufSnapshot {
        version: 3,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xEE; 32],
    };
    // targets.version != snapshot.targets_version
    let targets = TufTargets {
        version: 7,
        expires_us: 10_000_000,
        targets: [None; 8],
    };
    let sigs = [make_sig(0x30, 0xEE)];
    let metadata = make_signed_metadata(7, 10_000_000, &sigs, 0xEE);

    let result = verify_targets(&metadata, &targets, &snapshot, &root, 1_000, &MockCrypto);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

#[test]
fn verify_targets_hash_mismatch() {
    let root = make_role_root(1, 10_000_000, 2, 1);
    let snapshot = TufSnapshot {
        version: 3,
        expires_us: 10_000_000,
        targets_version: 2,
        targets_hash: [0xEE; 32],
    };
    let targets = TufTargets {
        version: 2,
        expires_us: 10_000_000,
        targets: [None; 8],
    };
    // content_hash[0] = 0x11 != snapshot.targets_hash[0] = 0xEE
    let sigs = [make_sig(0x30, 0x11)];
    let metadata = make_signed_metadata(2, 10_000_000, &sigs, 0x11);

    let result = verify_targets(&metadata, &targets, &snapshot, &root, 1_000, &MockCrypto);
    assert_eq!(result, Err(VsError::IntegrityFailure));
}

// ---------------------------------------------------------------------------
// find_target_entry tests
// ---------------------------------------------------------------------------

fn make_target_entry(id: &[u8], hash_byte: u8, length: u64) -> TufTargetEntry {
    let mut target_id = [0u8; 32];
    let id_len = id.len().min(32);
    target_id[..id_len].copy_from_slice(&id[..id_len]);
    let mut hash = [0u8; 32];
    hash[0] = hash_byte;
    TufTargetEntry {
        hash,
        length,
        target_id,
        target_id_len: id_len as u8,
    }
}

#[test]
fn find_target_entry_found() {
    let entry = make_target_entry(b"ecu-main", 0xAA, 4096);
    let mut targets_arr: [Option<TufTargetEntry>; 8] = [None; 8];
    targets_arr[0] = Some(entry);
    let targets = TufTargets {
        version: 1,
        expires_us: 10_000_000,
        targets: targets_arr,
    };

    let found = find_target_entry(&targets, b"ecu-main");
    assert!(found.is_ok(), "target entry must be found");
    let found = found.unwrap();
    assert_eq!(found.length, 4096);
    assert_eq!(found.hash[0], 0xAA);
}

#[test]
fn find_target_entry_not_found() {
    let entry = make_target_entry(b"ecu-main", 0xAA, 4096);
    let mut targets_arr: [Option<TufTargetEntry>; 8] = [None; 8];
    targets_arr[0] = Some(entry);
    let targets = TufTargets {
        version: 1,
        expires_us: 10_000_000,
        targets: targets_arr,
    };

    let result = find_target_entry(&targets, b"ecu-secondary");
    assert_eq!(result, Err(VsError::NotFound));
}

#[test]
fn find_target_entry_empty_targets() {
    let targets = TufTargets {
        version: 1,
        expires_us: 10_000_000,
        targets: [None; 8],
    };

    let result = find_target_entry(&targets, b"anything");
    assert_eq!(result, Err(VsError::NotFound));
}

// ---------------------------------------------------------------------------
// Full chain: timestamp -> snapshot -> targets -> verify_target
// ---------------------------------------------------------------------------

#[test]
fn full_delegation_chain() {
    let root = make_role_root(1, 10_000_000, 2, 1);

    // 1. Timestamp
    let timestamp = TufTimestamp {
        version: 10,
        expires_us: 10_000_000,
        snapshot_version: 7,
        snapshot_hash: [0xAA; 32],
    };
    let ts_sigs = [make_sig(0x10, 0xAA)];
    let ts_meta = make_signed_metadata(10, 10_000_000, &ts_sigs, 0xAA);
    verify_timestamp(&ts_meta, &timestamp, &root, 1_000, &MockCrypto)
        .expect("timestamp verification must pass");

    // 2. Snapshot (cross-references timestamp)
    let snapshot = TufSnapshot {
        version: 7,
        expires_us: 10_000_000,
        targets_version: 4,
        targets_hash: [0xBB; 32],
    };
    let snap_sigs = [make_sig(0x20, 0xAA)];
    let snap_meta = make_signed_metadata(7, 10_000_000, &snap_sigs, 0xAA);
    verify_snapshot(&snap_meta, &snapshot, &timestamp, &root, 1_000, &MockCrypto)
        .expect("snapshot verification must pass");

    // 3. Targets (cross-references snapshot)
    let firmware = b"test firmware payload for full chain";
    let crypto = MockCrypto;
    let mut fw_hash = [0u8; 32];
    crypto.sha256(firmware, &mut fw_hash).unwrap();

    let entry = TufTargetEntry {
        hash: fw_hash,
        length: firmware.len() as u64,
        target_id: {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(b"ecu-main");
            id
        },
        target_id_len: 8,
    };
    let mut targets_arr: [Option<TufTargetEntry>; 8] = [None; 8];
    targets_arr[0] = Some(entry);
    let targets = TufTargets {
        version: 4,
        expires_us: 10_000_000,
        targets: targets_arr,
    };
    let tgt_sigs = [make_sig(0x30, 0xBB)];
    let tgt_meta = make_signed_metadata(4, 10_000_000, &tgt_sigs, 0xBB);
    verify_targets(&tgt_meta, &targets, &snapshot, &root, 1_000, &MockCrypto)
        .expect("targets verification must pass");

    // 4. Find and verify the actual firmware target
    let found = find_target_entry(&targets, b"ecu-main").expect("target entry must be found");

    // Use the SoftwareCryptoProvider for actual hash verification
    let sw_crypto = SoftwareCryptoProvider::new(|buf: &mut [u8]| {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
    });
    let mut sw_hash = [0u8; 32];
    sw_crypto.sha256(firmware, &mut sw_hash).unwrap();

    let root_for_verify = make_role_root(1, 10_000_000, 1, 1);
    let validator = OtaValidator::new(sw_crypto, root_for_verify).unwrap();
    let result = validator.verify_target(&sw_hash, found.length, firmware);
    assert!(result.is_ok(), "firmware target verification must pass");
}
