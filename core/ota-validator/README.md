# vs-ota-validator

TUF/Uptane OTA update validation with rollback protection.

## Overview

This crate validates over-the-air firmware updates following TUF (The Update
Framework) and Uptane principles. It performs threshold-of-N signature
verification on root metadata, enforces rollback protection via monotonic
version counters, and verifies firmware target hashes before installation.

## Key Types

- `OtaValidator<C>` — validates OTA metadata and firmware images against a TUF root of trust
- `TufRoot` — trusted root metadata defining signing keys and thresholds per role
- `TufKey` — a public key with fingerprint, algorithm, and key material
- `TufRole` — TUF metadata roles (Root, Targets, Snapshot, Timestamp)
- `RollbackCounter` — trait for monotonic version counter backends (HSM or software)

## Usage

```rust
use vs_ota_validator::{OtaValidator, TufRoot};

let validator = OtaValidator::new(crypto, storage, root)?;
validator.validate_metadata(&signed_metadata)?;
validator.verify_target(&firmware_hash, &target_info)?;
```

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
