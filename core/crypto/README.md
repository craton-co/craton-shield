# vs-crypto

Cryptographic provider traits for Craton Shield.

This crate defines the `CryptoProvider` and `PostQuantumProvider` traits used
throughout Craton Shield. It also provides a `SoftwareCryptoProvider` (behind
the `mock-hsm` feature flag) for testing and development, a
`RustCryptoProvider` (available via the `software` feature), and a
`StubPostQuantumProvider` placeholder. Production-grade HSM-backed
implementations are available in
[Craton Shield Platform](https://github.com/craton-co/craton-shield-enterprise).

## Traits

| Trait | Operations |
|:------|:-----------|
| `CryptoProvider` | AES-128/256-GCM, SHA-256, HMAC-SHA-256, ECDSA P-256 sign/verify, ECDH P-256, RNG |
| `PostQuantumProvider` | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) |

## Feature Flags

| Flag | Description |
|:-----|:------------|
| `mock-hsm` | Software mock of the HSM interface for testing. **Never enable in production.** |
| `software` | Production-ready RustCrypto-based `RustCryptoProvider` (AES-GCM, SHA-256, HMAC, ECDSA P-256, ECDH). |
| `pq-software` | Software post-quantum stub (`StubPostQuantumProvider`). |
| `pq` | Production-ready post-quantum `RustCryptoPqProvider` (ML-KEM-768, ML-DSA-65). Adds `ml-kem` and `ml-dsa` deps. |

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## Usage

```rust
use vs_crypto::CryptoProvider;

fn hash_firmware<C: CryptoProvider>(crypto: &C, data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    crypto.sha256(data, &mut hash).expect("sha256");
    hash
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
