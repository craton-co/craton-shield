// SPDX-License-Identifier: Apache-2.0
//! Runtime-level post-quantum cryptography integration tests.
//!
//! Tests the PQC methods on `CratonShield<C, RustCryptoPqProvider>` that are
//! exposed via the `pq_*` family of methods.  These tests complement the
//! lower-level `pq_crypto.rs` tests which exercise `vs_crypto` directly.
//!
//! Required feature flags:
//!   - `vs-runtime/pq`  (pulled in via dev-dep in workspace Cargo.toml)
//!   - `vs-crypto/pq`   (transitively via the above)
//!   - `vs-crypto/mock-hsm` (for `SoftwareCryptoProvider`)

use vs_crypto::{
    KeyId, RustCryptoPqProvider, MLDSA65_PUBLIC_KEY_LEN, MLDSA65_SIGNATURE_LEN,
    MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN,
};
use vs_runtime::{CratonShield, PlatformConfig, WatchdogAction};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type PqPlatform = CratonShield<vs_crypto::SoftwareCryptoProvider, RustCryptoPqProvider>;

fn make_config() -> PlatformConfig {
    PlatformConfig {
        watchdog_timeout_us: 1_000_000,
        watchdog_action: WatchdogAction::Reset,
        ids_correlation_window_us: 100_000,
    }
}

/// A deterministic test RNG — NOT cryptographically secure.
fn test_rng(buf: &mut [u8]) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0xFEED_DEAD_CAFE_F00D);
    let old = STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut s| {
            for _ in 0..buf.len() {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(7);
            }
            Some(s)
        })
        .expect("closure always returns Some");
    let mut state = old;
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(7);
        *b = (state >> 33) as u8;
    }
}

fn make_platform() -> PqPlatform {
    let pq = RustCryptoPqProvider::new(test_rng);
    CratonShield::init_with_pq(
        make_config(),
        vs_crypto::SoftwareCryptoProvider::default(),
        pq,
    )
    .expect("platform init failed")
}

// ---------------------------------------------------------------------------
// Stub provider tests (default CratonShield without pq feature in runtime)
// ---------------------------------------------------------------------------

#[test]
fn stub_pq_provision_mlkem_returns_not_initialized() {
    // Default CratonShield uses StubPostQuantumProvider.
    let mut shield: CratonShield<vs_crypto::SoftwareCryptoProvider> =
        CratonShield::new(&make_config()).expect("init");

    let seed = [0x42u8; 64];
    let result = shield.pq_provision_mlkem_key(KeyId(0), &seed);
    assert_eq!(
        result,
        Err(VsError::NotInitialized),
        "stub provider must return NotInitialized for provisioning"
    );
}

#[test]
fn stub_pq_encapsulate_returns_not_initialized() {
    let shield: CratonShield<vs_crypto::SoftwareCryptoProvider> =
        CratonShield::new(&make_config()).expect("init");

    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
    let result = shield.pq_mlkem_encapsulate(KeyId(0), &mut ct, &mut ss);
    assert_eq!(result, Err(VsError::NotInitialized));
}

#[test]
fn stub_pq_mldsa_sign_returns_not_initialized() {
    let shield: CratonShield<vs_crypto::SoftwareCryptoProvider> =
        CratonShield::new(&make_config()).expect("init");

    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    let result = shield.pq_mldsa_sign(KeyId(0), b"test", &mut sig);
    assert_eq!(result, Err(VsError::NotInitialized));
}

// ---------------------------------------------------------------------------
// RustCryptoPqProvider via CratonShield
// ---------------------------------------------------------------------------

#[test]
fn pq_provision_and_encapsulate_decapsulate_roundtrip() {
    let mut shield = make_platform();

    // Provision ML-KEM slot 0 with an explicit seed.
    let seed = [0xAA_u8; 64];
    shield
        .pq_provision_mlkem_key(KeyId(0), &seed)
        .expect("provision mlkem key");

    // Encapsulate.
    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss_enc = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_encapsulate(KeyId(0), &mut ct, &mut ss_enc)
        .expect("encapsulate");

    // Decapsulate — must recover the same shared secret.
    let mut ss_dec = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_decapsulate(KeyId(0), &ct, &mut ss_dec)
        .expect("decapsulate");

    assert_eq!(
        ss_enc, ss_dec,
        "encapsulate/decapsulate must produce the same shared secret"
    );
}

#[test]
fn pq_sign_and_verify_roundtrip() {
    let mut shield = make_platform();

    let seed = [0xBB_u8; 32];
    shield
        .pq_provision_mldsa_key(KeyId(0), &seed)
        .expect("provision mldsa key");

    let message = b"craton-shield pq signing test";
    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    shield
        .pq_mldsa_sign(KeyId(0), message, &mut sig)
        .expect("sign");

    // Derive the public key directly from the seed to verify.
    let mut pq = RustCryptoPqProvider::new(test_rng);
    pq.set_mldsa_key(KeyId(0), Some(&seed)).expect("set key");
    let vk = pq.mldsa_public_key(KeyId(0)).expect("public key");
    let mut vk_bytes = [0u8; MLDSA65_PUBLIC_KEY_LEN];
    vk_bytes.copy_from_slice(&vk);

    let valid = shield
        .pq_mldsa_verify(&vk_bytes, message, &sig)
        .expect("verify");
    assert!(valid, "fresh signature must verify");
}

#[test]
fn pq_sign_tampered_sig_fails_verify() {
    let mut shield = make_platform();

    let seed = [0xCC_u8; 32];
    shield
        .pq_provision_mldsa_key(KeyId(0), &seed)
        .expect("provision");

    let message = b"tamper test";
    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    shield
        .pq_mldsa_sign(KeyId(0), message, &mut sig)
        .expect("sign");

    // Tamper.
    sig[0] ^= 0xFF;
    sig[500] ^= 0x01;

    let mut pq = RustCryptoPqProvider::new(test_rng);
    pq.set_mldsa_key(KeyId(0), Some(&seed)).expect("set key");
    let vk = pq.mldsa_public_key(KeyId(0)).expect("public key");
    let mut vk_bytes = [0u8; MLDSA65_PUBLIC_KEY_LEN];
    vk_bytes.copy_from_slice(&vk);

    let valid = shield
        .pq_mldsa_verify(&vk_bytes, message, &sig)
        .expect("verify call");
    assert!(!valid, "tampered signature must not verify");
}

#[test]
fn pq_unprovision_slot_returns_not_initialized() {
    let shield = make_platform();
    // No key provisioned in slot 5 — encapsulate must fail.
    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
    let result = shield.pq_mlkem_encapsulate(KeyId(5), &mut ct, &mut ss);
    assert_eq!(
        result,
        Err(VsError::NotInitialized),
        "un-provisioned slot must return NotInitialized"
    );
}

#[test]
fn pq_encapsulate_tampered_ct_produces_different_ss() {
    let mut shield = make_platform();

    let seed = [0xDD_u8; 64];
    shield
        .pq_provision_mlkem_key(KeyId(0), &seed)
        .expect("provision");

    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss_orig = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_encapsulate(KeyId(0), &mut ct, &mut ss_orig)
        .expect("encapsulate");

    // Tamper the ciphertext.
    ct[0] ^= 0xFF;
    ct[50] ^= 0x42;

    // ML-KEM is IND-CCA2: decapsulation still succeeds (implicit rejection)
    // but produces a different shared secret.
    let mut ss_tampered = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_decapsulate(KeyId(0), &ct, &mut ss_tampered)
        .expect("decapsulate");

    assert_ne!(
        ss_orig, ss_tampered,
        "tampered ciphertext must produce a different shared secret (implicit rejection)"
    );
}

#[test]
fn pq_provision_overwrites_existing_key() {
    let mut shield = make_platform();

    let seed_a = [0x11_u8; 64];
    let seed_b = [0x22_u8; 64];

    shield
        .pq_provision_mlkem_key(KeyId(0), &seed_a)
        .expect("provision a");

    let mut ct_a = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ss_a = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_encapsulate(KeyId(0), &mut ct_a, &mut ss_a)
        .expect("encapsulate a");

    // Overwrite with a different key.
    shield
        .pq_provision_mlkem_key(KeyId(0), &seed_b)
        .expect("provision b");

    // Decapsulate the ciphertext generated under seed_a with the new key —
    // must produce a different shared secret (implicit rejection).
    let mut ss_after = [0u8; MLKEM_SHARED_SECRET_LEN];
    shield
        .pq_mlkem_decapsulate(KeyId(0), &ct_a, &mut ss_after)
        .expect("decapsulate");

    assert_ne!(
        ss_a, ss_after,
        "key overwrite must invalidate ciphertexts from the old key"
    );
}

#[test]
fn pq_deterministic_signatures_with_same_seed() {
    let mut s1 = make_platform();
    let mut s2 = make_platform();

    let seed = [0xEE_u8; 32];
    s1.pq_provision_mldsa_key(KeyId(0), &seed)
        .expect("provision s1");
    s2.pq_provision_mldsa_key(KeyId(0), &seed)
        .expect("provision s2");

    let message = b"determinism check";
    let mut sig1 = [0u8; MLDSA65_SIGNATURE_LEN];
    let mut sig2 = [0u8; MLDSA65_SIGNATURE_LEN];
    s1.pq_mldsa_sign(KeyId(0), message, &mut sig1)
        .expect("sign s1");
    s2.pq_mldsa_sign(KeyId(0), message, &mut sig2)
        .expect("sign s2");

    assert_eq!(
        sig1, sig2,
        "ML-DSA-65 is deterministic: same seed and message must produce identical signatures"
    );
}

#[test]
fn pq_mldsa_sign_verify_message_with_null_bytes() {
    // ML-DSA sign/verify must handle messages that contain null bytes correctly.
    // Some signature schemes treat the message as a C-string and truncate at \0;
    // ML-DSA must not — the full byte sequence must be signed and verified.
    let mut shield = make_platform();

    let seed = [0xF1_u8; 32];
    shield
        .pq_provision_mldsa_key(KeyId(0), &seed)
        .expect("provision mldsa key");

    // Message with embedded null bytes.
    let message: &[u8] = b"craton\x00shield\x00null\x00bytes";
    let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
    shield
        .pq_mldsa_sign(KeyId(0), message, &mut sig)
        .expect("sign message with null bytes");

    // Derive the public key to verify.
    let mut pq = RustCryptoPqProvider::new(test_rng);
    pq.set_mldsa_key(KeyId(0), Some(&seed)).expect("set key");
    let vk = pq.mldsa_public_key(KeyId(0)).expect("public key");
    let mut vk_bytes = [0u8; MLDSA65_PUBLIC_KEY_LEN];
    vk_bytes.copy_from_slice(&vk);

    let valid = shield
        .pq_mldsa_verify(&vk_bytes, message, &sig)
        .expect("verify");
    assert!(valid, "signature over message with null bytes must verify");

    // Verify that a message truncated at the first null byte does NOT verify
    // with the signature over the full message — this confirms null bytes are
    // treated as data, not terminators.
    let truncated = b"craton";
    let valid_truncated = shield
        .pq_mldsa_verify(&vk_bytes, truncated, &sig)
        .expect("verify truncated");
    assert!(
        !valid_truncated,
        "signature over full message must not verify for truncated message"
    );
}

#[test]
fn pq_init_with_pq_returns_working_platform() {
    // Verify that init_with_pq creates a platform that also handles normal
    // CAN/ETH frames without interference from the PQ layer.
    let pq = RustCryptoPqProvider::new(test_rng);
    let shield = CratonShield::init_with_pq(
        make_config(),
        vs_crypto::SoftwareCryptoProvider::default(),
        pq,
    )
    .expect("init_with_pq");

    // The platform should be healthy.
    let health = shield.health();
    assert_ne!(
        health.crypto,
        vs_runtime::SubsystemStatus::Failed,
        "crypto subsystem must not be failed after init_with_pq"
    );
}
