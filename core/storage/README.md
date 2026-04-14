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

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
