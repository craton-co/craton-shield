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

```rust,ignore
use vs_crypto::{KeyId, SoftwareCryptoProvider};
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};

let mut km = KeyManager::new(SoftwareCryptoProvider::default());

let key_id = KeyId(0);
let mut material = [0u8; 32];
for (i, b) in material.iter_mut().enumerate() {
    *b = i as u8;
}

let meta = KeyMetadata {
    key_id,
    algorithm: KeyAlgorithm::Aes256Gcm,
    purpose: KeyPurpose::BusAuthentication,
    created_at: 1_000,
    expires_at: None,
    rotation_count: 0,
    cumulative_nonce_count: 0,
};

km.provision_key(key_id, meta, &material).unwrap();

let mut new_material = [0u8; 32];
for (i, b) in new_material.iter_mut().enumerate() {
    *b = (i as u8).wrapping_add(0x10);
}
km.rotate_key(key_id, &new_material, 2_000, None).unwrap();

km.revoke_key(key_id, 3_000).unwrap();
```

See the crate-level rustdoc on `KeyManager::new` for a runnable doc-test.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
