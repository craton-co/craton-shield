# vs-ota-validator

TUF/Uptane OTA update validation with rollback protection.

## Overview

This crate validates over-the-air firmware updates following TUF (The Update
Framework) and Uptane principles. It performs threshold-of-N signature
verification on root metadata, enforces rollback protection via monotonic
version counters, and verifies firmware target hashes before installation.

## Key Types

- `OtaValidator<C>` — stateful validator over a [`CryptoProvider`], holding
  the trusted root and an in-memory rollback counter
- `PersistentOtaValidator<C, S>` — same, but persists the rollback counter
  through a [`StorageProvider`] backend (flash/EEPROM)
- `HsmOtaValidator<C, R>` — uses a [`RollbackCounter`] (typically backed by
  HSM OTP fuses) for permanently-irreversible rollback protection
- `TufRoot` — trusted root metadata defining signing keys and thresholds per role
- `TufKey` — a public key with fingerprint, algorithm, and key material
- `TufRole` — TUF metadata roles (Root, Targets, Snapshot, Timestamp)
- `RollbackCounter` — trait for monotonic version counter backends (HSM or software)

## Usage

```rust,ignore
use vs_ota_validator::{OtaValidator, TufRoot};

// `crypto` is any `vs_crypto::CryptoProvider`, `root` is a `TufRoot`.
let validator = OtaValidator::new(crypto, root)?;

// Verify a firmware blob against its expected SHA-256 hash and length.
validator.verify_target(&expected_hash, firmware_bytes.len() as u64, firmware_bytes)?;
```

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
