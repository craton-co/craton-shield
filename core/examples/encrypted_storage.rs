// SPDX-License-Identifier: Apache-2.0
//! Encrypted storage example.
//!
//! Demonstrates the `EncryptedStorageProvider` wrapper that transparently
//! encrypts all values with AES-GCM before writing to the underlying
//! storage backend.
//!
//! ```
//! cargo run --example encrypted_storage --features "mock-hsm"
//! ```

use vs_crypto::{KeyId, SoftwareCryptoProvider};
use vs_storage::{EncryptedStorageProvider, RamStorageProvider, StorageProvider, MAX_VALUE_LEN};

fn main() {
    println!("Craton Shield — Encrypted Storage Example");
    println!("==========================================\n");

    // 1. Set up a crypto provider with an AES key
    let mut crypto = SoftwareCryptoProvider::default();
    crypto
        .set_key(KeyId(0), &[0x42u8; 16])
        .expect("failed to provision AES key");
    println!("Provisioned AES-128-GCM key (KeyId=0)");

    // 2. Create a RAM storage backend and wrap it with encryption
    let store = RamStorageProvider::new();
    let mut encrypted = EncryptedStorageProvider::new(store, &crypto, KeyId(0), 0);
    println!("Created EncryptedStorageProvider wrapping RamStorageProvider\n");

    // 3. Write a secret value
    let secret = b"my-api-token-12345";
    encrypted
        .write(b"api_token", secret)
        .expect("failed to write encrypted value");
    println!("Wrote encrypted value for key 'api_token'");
    println!("  Plaintext length: {} bytes", secret.len());

    // 4. Read it back — decryption is transparent
    let mut buf = [0u8; MAX_VALUE_LEN];
    let len = encrypted
        .read(b"api_token", &mut buf)
        .expect("failed to read encrypted value");
    assert_eq!(&buf[..len], secret);
    println!("  Decrypted length:  {} bytes", len);
    println!("  Round-trip: OK\n");

    // 5. Verify the underlying storage has ciphertext, not plaintext
    let mut raw = [0u8; MAX_VALUE_LEN];
    let raw_len = encrypted
        .inner()
        .read(b"api_token", &mut raw)
        .expect("failed to read raw storage");
    println!(
        "Raw encrypted blob: {} bytes (nonce + ciphertext + tag)",
        raw_len
    );
    println!(
        "  Overhead: {} bytes (12-byte nonce + 16-byte tag)",
        raw_len - secret.len()
    );

    // Check that plaintext doesn't appear in the raw storage
    let plaintext_found = raw[..raw_len].windows(secret.len()).any(|w| w == secret);
    assert!(!plaintext_found, "plaintext leaked into encrypted storage!");
    println!("  Plaintext leak check: PASS (not found in raw blob)");

    // 6. Show nonce counter state
    println!(
        "\nNonce counter: {} (persist this value for safe restart)",
        encrypted.nonce_counter()
    );

    // 7. Demonstrate tamper detection
    println!("\n--- Tamper Detection ---");
    raw[20] ^= 0xFF; // flip a byte in the ciphertext
    encrypted
        .inner_mut()
        .write(b"api_token", &raw[..raw_len])
        .expect("failed to write tampered data");
    let result = encrypted.read(b"api_token", &mut buf);
    match result {
        Err(e) => println!("Tampered read correctly rejected: {:?}", e),
        Ok(_) => panic!("tampered data should have been rejected!"),
    }

    println!("\nDone.");
}
