// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::{CryptoProvider, KeyId, KeyType, SoftwareCryptoProvider};

/// Deterministic no-op RNG for fuzzing (not cryptographically secure).
fn fuzz_rng(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
}

fuzz_target!(|data: &[u8]| {
    // Fuzz AES-GCM encrypt/decrypt roundtrip.
    // The crypto provider must not panic on any input.
    if data.len() < 12 {
        return;
    }

    let mut crypto = SoftwareCryptoProvider::new(fuzz_rng);
    let key_id = KeyId(0);

    // Generate a key in slot 0.
    if crypto.generate_key(key_id, KeyType::Aes256).is_err() {
        return;
    }

    let nonce: &[u8; 12] = data[..12].try_into().unwrap();
    let plaintext = &data[12..];
    if plaintext.len() > 1024 {
        return; // cap size to avoid excessive allocations
    }

    let mut ciphertext = [0u8; 1024];
    let mut tag = [0u8; 16];

    if crypto
        .aes_gcm_encrypt(
            key_id,
            nonce,
            plaintext,
            &[],
            &mut ciphertext[..plaintext.len()],
            &mut tag,
        )
        .is_ok()
    {
        // 1. Verify decryption produces original plaintext.
        let mut decrypted = [0u8; 1024];
        let dec_result = crypto.aes_gcm_decrypt(
            key_id,
            nonce,
            &ciphertext[..plaintext.len()],
            &[],
            &tag,
            &mut decrypted[..plaintext.len()],
        );
        assert!(dec_result.is_ok(), "decryption of valid ciphertext must succeed");
        assert_eq!(
            &decrypted[..plaintext.len()],
            plaintext,
            "decrypted output must match original plaintext"
        );

        // 2. Corrupt ciphertext (flip first byte) — decryption must fail.
        if !plaintext.is_empty() {
            let mut corrupted_ct = [0u8; 1024];
            corrupted_ct[..plaintext.len()].copy_from_slice(&ciphertext[..plaintext.len()]);
            corrupted_ct[0] ^= 0xFF;
            let mut dec_buf = [0u8; 1024];
            let bad_ct_result = crypto.aes_gcm_decrypt(
                key_id,
                nonce,
                &corrupted_ct[..plaintext.len()],
                &[],
                &tag,
                &mut dec_buf[..plaintext.len()],
            );
            assert!(bad_ct_result.is_err(), "corrupted ciphertext must fail decryption");
        }

        // 3. Corrupt tag (flip first byte) — decryption must fail.
        let mut corrupted_tag = tag;
        corrupted_tag[0] ^= 0xFF;
        let mut dec_buf2 = [0u8; 1024];
        let bad_tag_result = crypto.aes_gcm_decrypt(
            key_id,
            nonce,
            &ciphertext[..plaintext.len()],
            &[],
            &corrupted_tag,
            &mut dec_buf2[..plaintext.len()],
        );
        assert!(bad_tag_result.is_err(), "corrupted tag must fail decryption");
    }

    // Also exercise with fuzzed AAD.
    if data.len() > 24 {
        let aad = &data[12..24];
        let plaintext2 = &data[24..];
        if plaintext2.len() <= 1024 {
            let mut ct2 = [0u8; 1024];
            let mut tag2 = [0u8; 16];
            if crypto
                .aes_gcm_encrypt(
                    key_id,
                    nonce,
                    plaintext2,
                    aad,
                    &mut ct2[..plaintext2.len()],
                    &mut tag2,
                )
                .is_ok()
            {
                // Verify AAD roundtrip: decryption with correct AAD must succeed.
                let mut dec2 = [0u8; 1024];
                let dec2_result = crypto.aes_gcm_decrypt(
                    key_id,
                    nonce,
                    &ct2[..plaintext2.len()],
                    aad,
                    &tag2,
                    &mut dec2[..plaintext2.len()],
                );
                assert!(dec2_result.is_ok(), "AAD decryption must succeed");
                assert_eq!(
                    &dec2[..plaintext2.len()],
                    plaintext2,
                    "AAD decrypted output must match plaintext"
                );
            }
        }
    }
});
