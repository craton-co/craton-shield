# vs-key-manager

Key lifecycle management with zeroization and audit trails for Craton Shield.

## Overview

This crate manages cryptographic key provisioning, rotation, revocation, and
expiration for the Craton Shield platform. All key material is stored in
fixed-size slots with automatic zeroization on drop, and every lifecycle
operation is recorded in an auditable ring buffer.

## Key Types

- `KeyManager<C>` — central key store with fixed-size table and audit trail
- `KeyMetadata` — per-key metadata (id, algorithm, purpose, creation/expiry timestamps)
- `KeyAlgorithm` — supported algorithms (AES-128/256-GCM, HMAC-SHA256, ECDSA/ECDH P-256)
- `KeyPurpose` — authorized key usage (bus auth, firmware verification, diagnostics, telemetry, OTA)
- `AuditEntry` — timestamped record of a key lifecycle event

## Usage

```rust
use vs_key_manager::{KeyManager, KeyAlgorithm, KeyPurpose};

let mut km = KeyManager::<MyCrypto>::new();
km.provision(key_id, KeyAlgorithm::Aes256Gcm, KeyPurpose::BusAuthentication,
             &material, now_us, None)?;
km.rotate(key_id, &new_material, now_us)?;
km.revoke(key_id, now_us)?;
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
