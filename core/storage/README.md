# vs-storage

Persistent storage abstraction for configuration and key material.

## Overview

This crate defines a `StorageProvider` trait for key-value storage that can be
backed by RAM, flash, EEPROM, or filesystem depending on the target platform.
All implementations are fixed-size and heap-free, suitable for `#![no_std]`
embedded use. A `RamStorageProvider` is included for testing, and a
`FileStorageProvider` is available behind the `std` feature flag.

## Key Types

- `StorageProvider` — trait for key-value read/write/delete/contains operations
- `RamStorageProvider` — in-memory implementation for testing and prototyping
- `FileStorageProvider` — filesystem-backed implementation (requires `std` feature)

## Usage

```rust,no_run
use vs_storage::{StorageProvider, RamStorageProvider};
use vs_types::VsError;

fn example() -> Result<(), VsError> {
    let mut store = RamStorageProvider::new();
    store.write(b"config.key", b"value")?;
    let mut buf = [0u8; 64];
    let _len = store.read(b"config.key", &mut buf)?;
    Ok(())
}
```

### Encrypted storage (requires `encrypted` feature)

Wrap any `StorageProvider` with `EncryptedStorageProvider` to transparently
encrypt all values at rest using AES-GCM. Available when the `encrypted`
feature is enabled (pulls in `vs-crypto`):

```rust,ignore
// Cargo.toml: vs-storage = { version = "0.7", features = ["encrypted"] }
use vs_storage::{EncryptedStorageProvider, RamStorageProvider, StorageProvider};
use vs_crypto::{KeyId, RustCryptoProvider};

let mut crypto = RustCryptoProvider::default();
// AES-256-GCM requires a 32-byte key. The real `RustCryptoProvider`
// rejects any other length with `VsError::InvalidInput`.
crypto.set_key(KeyId(0), &[0x42u8; 32])?;

let inner = RamStorageProvider::new();
// `new_persistent` stores the AES-GCM nonce counter inside `inner` under a
// reserved key, so it is reloaded automatically on the next boot and a nonce
// can never be reused. Prefer it over `new(.., nonce_start)`.
let mut enc = EncryptedStorageProvider::new_persistent(inner, &crypto, KeyId(0))?;
enc.write(b"secret.key", b"plaintext-value")?;
```

## Feature Flags

See [feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
