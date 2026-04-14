// SPDX-License-Identifier: Apache-2.0
//! Post-quantum cryptography integration tests.
//!
//! Additional test coverage for ML-KEM-768 and ML-DSA-65 beyond the inline
//! unit tests in vs-crypto.

use vs_crypto::{
    KeyId, PostQuantumProvider, RustCryptoPqProvider, MLDSA65_PUBLIC_KEY_LEN,
    MLDSA65_SIGNATURE_LEN, MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN,
};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Deterministic RNG for tests
// ---------------------------------------------------------------------------

/// Counter-based deterministic RNG for reproducible tests.
fn test_rng(buf: &mut [u8]) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_1234);
    let old = STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut s| {
            for _ in 0..buf.len() {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            }
            Some(s)
        })
        .expect("closure always returns Some");
    let mut state = old;
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *b = (state >> 33) as u8;
    }
}

/// A second, independent RNG for tests that need different entropy.
fn test_rng_alt(buf: &mut [u8]) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x1234_5678_9ABC_DEF0);
    let old = STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut s| {
            for _ in 0..buf.len() {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(3);
            }
            Some(s)
        })
        .expect("closure always returns Some");
    let mut state = old;
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(3);
        *b = (state >> 33) as u8;
    }
}

fn make_provider() -> RustCryptoPqProvider {
    RustCryptoPqProvider::new(test_rng)
}

// ---------------------------------------------------------------------------
// ML-KEM tests
// ---------------------------------------------------------------------------

#[test]
fn mlkem_deterministic_keygen_from_seed() {
    let seed = [0x42u8; 64];
    let mut p1 = make_provider();
    let mut p2 = make_provider();
    p1.set_mlkem_key(KeyId(0), Some(&seed)).unwrap();
    p2.set_mlkem_key(KeyId(0), Some(&seed)).unwrap();

    let pk1 = p1.mlkem_public_key(KeyId(0)).unwrap();
    let pk2 = p2.mlkem_public_key(KeyId(0)).unwrap();
    assert_eq!(
        AsRef::<[u8]>::as_ref(&pk1),
        AsRef::<[u8]>::as_ref(&pk2),
        "same seed must produce identical public keys"
    );
}

#[test]
fn mlkem_encapsulate_wrong_slot_errors() {
    let p = make_provider();
    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];

    // Slot 3 has no key provisioned
    let result = p.mlkem_encapsulate(KeyId(3), &mut ct, &mut ss);
    assert_eq!(result, Err(VsError::NotInitialized));
}

#[test]
fn mlkem_multiple_encapsulations_differ() {
    // Using a non-deterministic (counter-based) RNG, two encapsulations
    // of the same key should produce different ciphertexts.
    let mut p = RustCryptoPqProvider::new(test_rng_alt);
    p.set_mlkem_key(KeyId(0), None).unwrap();

    let mut ct1 = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss1 = [0u8; MLKEM_SHARED_SECRET_LEN];
    p.mlkem_encapsulate(KeyId(0), &mut ct1, &mut ss1).unwrap();

    let mut ct2 = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss2 = [0u8; MLKEM_SHARED_SECRET_LEN];
    p.mlkem_encapsulate(KeyId(0), &mut ct2, &mut ss2).unwrap();

    // The ciphertexts should differ because encapsulation uses fresh randomness
    assert_ne!(
        ct1, ct2,
        "two encapsulations must produce different ciphertexts"
    );
}

#[test]
fn mlkem_tampered_ciphertext_produces_wrong_shared_secret() {
    let mut p = make_provider();
    p.set_mlkem_key(KeyId(0), None).unwrap();

    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss_enc = [0u8; MLKEM_SHARED_SECRET_LEN];
    p.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss_enc).unwrap();

    // Tamper with the ciphertext
    ct[0] ^= 0xFF;
    ct[100] ^= 0x01;

    // ML-KEM is IND-CCA2: decapsulation still succeeds but produces a
    // different (implicit rejection) shared secret.
    let mut ss_dec = [0u8; MLKEM_SHARED_SECRET_LEN];
    p.mlkem_decapsulate(KeyId(0), &ct, &mut ss_dec).unwrap();

    assert_ne!(
        ss_enc, ss_dec,
        "tampered ciphertext must produce a different shared secret"
    );
}

// ---------------------------------------------------------------------------
// ML-DSA tests
// ---------------------------------------------------------------------------

#[test]
fn mldsa_deterministic_sign_with_seed() {
    let seed = [0x77u8; 32];
    let mut p1 = make_provider();
    let mut p2 = make_provider();
    p1.set_mldsa_key(KeyId(0), Some(&seed)).unwrap();
    p2.set_mldsa_key(KeyId(0), Some(&seed)).unwrap();

    let message = b"deterministic signing test";
    let mut sig1 = [0u8; MLDSA65_SIGNATURE_LEN];
    let mut sig2 = [0u8; MLDSA65_SIGNATURE_LEN];
    p1.mldsa_sign(KeyId(0), message, &mut sig1).unwrap();
    p2.mldsa_sign(KeyId(0), message, &mut sig2).unwrap();

    assert_eq!(
        sig1, sig2,
        "same seed and message must produce identical signatures"
    );
}

#[test]
fn mldsa_tampered_signature_fails() {
    let mut p = make_provider();
    p.set_mldsa_key(KeyId(0), None).unwrap();

    let message = b"tamper test message";
    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    p.mldsa_sign(KeyId(0), message, &mut sig).unwrap();

    let vk = p.mldsa_public_key(KeyId(0)).unwrap();
    let mut vk_bytes = [0u8; MLDSA65_PUBLIC_KEY_LEN];
    vk_bytes.copy_from_slice(&vk);

    // Tamper with the signature
    sig[0] ^= 0xFF;
    sig[100] ^= 0x01;

    let valid = p.mldsa_verify(&vk_bytes, message, &sig).unwrap();
    assert!(!valid, "tampered signature must not verify");
}

#[test]
fn mldsa_different_messages_produce_different_signatures() {
    let mut p = make_provider();
    p.set_mldsa_key(KeyId(0), None).unwrap();

    let mut sig_a = [0u8; MLDSA65_SIGNATURE_LEN];
    let mut sig_b = [0u8; MLDSA65_SIGNATURE_LEN];
    p.mldsa_sign(KeyId(0), b"message alpha", &mut sig_a)
        .unwrap();
    p.mldsa_sign(KeyId(0), b"message beta", &mut sig_b).unwrap();

    assert_ne!(
        sig_a, sig_b,
        "different messages must produce different signatures"
    );
}

// ---------------------------------------------------------------------------
// Key slot management tests
// ---------------------------------------------------------------------------

#[test]
fn key_slot_overwrite() {
    let mut p = make_provider();
    let seed_a = [0x11u8; 64];
    let seed_b = [0x22u8; 64];

    p.set_mlkem_key(KeyId(0), Some(&seed_a)).unwrap();
    let pk_a = p.mlkem_public_key(KeyId(0)).unwrap();

    // Overwrite slot 0 with a different seed
    p.set_mlkem_key(KeyId(0), Some(&seed_b)).unwrap();
    let pk_b = p.mlkem_public_key(KeyId(0)).unwrap();

    assert_ne!(
        AsRef::<[u8]>::as_ref(&pk_a),
        AsRef::<[u8]>::as_ref(&pk_b),
        "overwritten key must produce different public key"
    );
}

#[test]
fn all_slots_used() {
    let mut p = make_provider();
    // PQ_MAX_KEY_SLOTS is 8 (from the source code)
    for i in 0..8u32 {
        p.set_mlkem_key(KeyId(i), None).unwrap();
    }

    // Slot 8 should be out of range
    let result = p.set_mlkem_key(KeyId(8), None);
    assert_eq!(result, Err(VsError::PolicyViolation));
}

#[test]
fn wrong_key_type_cross_use() {
    let mut p = make_provider();
    // Provision as ML-KEM, try to sign with ML-DSA
    p.set_mlkem_key(KeyId(0), None).unwrap();

    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    let result = p.mldsa_sign(KeyId(0), b"test", &mut sig);
    assert_eq!(result, Err(VsError::InvalidInput));
}

// ---------------------------------------------------------------------------
// Zeroization on drop
// ---------------------------------------------------------------------------

#[test]
fn provider_debug_redacts_seeds() {
    let mut p = make_provider();
    p.set_mlkem_key(KeyId(0), Some(&[0xAB; 64])).unwrap();

    let debug_str = format!("{p:?}");
    assert!(
        debug_str.contains("REDACTED"),
        "Debug output must redact seed material"
    );
    assert!(
        !debug_str.contains("0xab"),
        "Debug output must not contain raw seed bytes"
    );
}

#[test]
fn zeroization_observable_via_api() {
    // After dropping a provider, we cannot inspect memory directly in safe
    // Rust. Instead, verify that a new provider starts with empty slots.
    let mut p = make_provider();
    p.set_mlkem_key(KeyId(0), None).unwrap();

    // Verify key is usable
    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
    p.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss).unwrap();

    // Drop and create new provider -- slots must be empty
    drop(p);
    let p2 = make_provider();
    let result = p2.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss);
    assert_eq!(
        result,
        Err(VsError::NotInitialized),
        "new provider must have empty slots"
    );
}
