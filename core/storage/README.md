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

```rust
use vs_storage::{StorageProvider, RamStorageProvider};

let mut store = RamStorageProvider::new();
store.write(b"config.key", b"value")?;
let mut buf = [0u8; 64];
let len = store.read(b"config.key", &mut buf)?;
```

### Encrypted storage (requires `encrypted` feature)

Wrap any `StorageProvider` with `EncryptedStorageProvider` to transparently
encrypt all values at rest using AES-GCM. Available when the `encrypted`
feature is enabled (pulls in `vs-crypto`):

```rust,ignore
// Cargo.toml: vs-storage = { version = "0.7", features = ["encrypted"] }
use vs_storage::{EncryptedStorageProvider, RamStorageProvider, StorageProvider};
use vs_crypto::{KeyId, SoftwareCryptoProvider};

let mut crypto = SoftwareCryptoProvider::default();
crypto.set_key(KeyId(0), &[0x42u8; 16])?;

let inner = RamStorageProvider::new();
// `nonce_start` MUST be greater than any previously used nonce for this key;
// persist `enc.nonce_counter()` after each write and restore it on next boot.
let mut enc = EncryptedStorageProvider::new(inner, &crypto, KeyId(0), 0);
enc.write(b"secret.key", b"plaintext-value")?;
```

## Feature Flags

See [feature-flags.md](../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
