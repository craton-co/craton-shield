# FIPS 140-3 Module Boundary Definition

> Craton Shield 0.7.0 | Date: 2026-03-13

## Scope

FIPS 140-3 "Security Requirements for Cryptographic Modules" defines requirements for cryptographic modules used in federal systems. This document defines the logical boundary of the Craton Shield cryptographic module as preparation for FIPS 140-3 Level 1 validation.

**Target level: Level 1** (software-only module; Level 2+ requires physical tamper evidence on hardware).

## Module Identification

| Field | Value |
|-------|-------|
| Module name | Craton Shield Cryptographic Module |
| Version | 0.6.0 |
| Type | Software |
| Embodiment | Multi-chip standalone (runs on general-purpose processor) |
| FIPS 140-3 level | Level 1 (target) |
| Operational environment | Limited (no_std, single-threaded, bare-metal or RTOS) |

## Cryptographic Boundary

The FIPS 140-3 module boundary encompasses the `vs-crypto` crate and its direct cryptographic dependencies. All cryptographic operations enter and exit through the `CryptoProvider` trait interface.

```
┌─────────────────────────────────────────────────┐
│              FIPS 140-3 MODULE BOUNDARY          │
│                                                   │
│  ┌──────────────────────────────────────────┐    │
│  │            vs-crypto crate                │    │
│  │                                            │    │
│  │  CryptoProvider trait (public interface)    │    │
│  │  ├── sha256()                              │    │
│  │  ├── hmac_sha256()                         │    │
│  │  ├── aes_gcm_encrypt() / decrypt()         │    │
│  │  ├── sign_p256() / verify_p256()           │    │
│  │  ├── ecdh_derive_shared()                  │    │
│  │  └── random_bytes()                        │    │
│  │                                            │    │
│  │  SoftwareCryptoProvider (implementation)    │    │
│  │  ├── KeyStore (32 slots × 32 bytes)        │    │
│  │  └── RNG function pointer                  │    │
│  │                                            │    │
│  │  PostQuantumProvider trait (experimental)   │    │
│  │  ├── ML-KEM-768 encapsulate/decapsulate    │    │
│  │  └── ML-DSA-65 sign/verify                 │    │
│  └──────────────────────────────────────────┘    │
│                                                   │
│  ┌──────────────────────────────────────────┐    │
│  │         Cryptographic Dependencies        │    │
│  │  aes-gcm 0.10  (AES-256-GCM)             │    │
│  │  sha2 0.10     (SHA-256)                  │    │
│  │  hmac 0.12     (HMAC-SHA-256)             │    │
│  │  p256 0.13     (ECDSA P-256, ECDH)        │    │
│  │  zeroize 1.x   (secure memory wiping)     │    │
│  │  subtle 2.x    (constant-time ops)        │    │
│  │  ml-kem        (ML-KEM-768) [pq-software] │    │
│  │  fips204       (ML-DSA-65)  [pq-software] │    │
│  └──────────────────────────────────────────┘    │
│                                                   │
└─────────────────────────────────────────────────┘
```

### Inside the Boundary

| Component | Purpose | FIPS Category |
|-----------|---------|---------------|
| `SoftwareCryptoProvider` | Core crypto implementation | Cryptographic module |
| `KeyStore` (32 slots) | Symmetric key storage | Critical Security Parameter (CSP) storage |
| AES-256-GCM routines | Authenticated encryption | Approved algorithm |
| SHA-256 routines | Hashing | Approved algorithm |
| HMAC-SHA-256 routines | Message authentication | Approved algorithm |
| ECDSA P-256 sign/verify | Digital signatures | Approved algorithm |
| ECDH P-256 | Key agreement | Approved algorithm |
| RNG interface | Random number generation | RNG (Approved DRBG required) |
| `zeroize` operations | CSP destruction | Key management |

### Outside the Boundary

| Component | Reason |
|-----------|--------|
| vs-key-manager | Key lifecycle management (uses CryptoProvider) |
| vs-ota-validator | OTA verification (consumer of crypto) |
| vs-secure-boot | Boot attestation (consumer of crypto) |
| vs-integrity | Hash verification (consumer of crypto) |
| vs-event-logger | HMAC chaining (consumer of crypto) |
| vs-hal / vs-hal-linux / vs-hal-qnx | Hardware abstraction (no crypto) |
| vs-ffi | C ABI layer (passes through to CryptoProvider) |
| All detection/protection crates | Application logic |

### Excluded from Validation Scope

| Component | Reason |
|-----------|--------|
| `PostQuantumProvider` (ML-KEM, ML-DSA) | NIST PQC standards not yet in FIPS 140-3 IG |
| `MockHsmHardware` (mock-hsm feature) | Testing-only; never enabled in production |

## Approved Algorithms

| Algorithm | Standard | Key Size | Use in Module |
|-----------|----------|----------|---------------|
| AES-256-GCM | FIPS 197 + SP 800-38D | 256-bit | Authenticated encryption of OTA payloads, secure channels |
| SHA-256 | FIPS 180-4 | 256-bit output | Firmware hashing, TUF metadata hashing |
| HMAC-SHA-256 | FIPS 198-1 | 256-bit key | Event log chaining, key derivation |
| ECDSA P-256 | FIPS 186-5 | 256-bit | TUF metadata signatures, boot attestation |
| ECDH P-256 | SP 800-56Ar3 | 256-bit | Shared secret derivation for secure channels |

### Non-Approved Algorithms

| Algorithm | Standard | Status | Notes |
|-----------|----------|--------|-------|
| ML-KEM-768 | FIPS 203 (draft) | Experimental | Gated by `pq-software` feature; excluded from FIPS boundary |
| ML-DSA-65 | FIPS 204 (draft) | Experimental | Gated by `pq-software` feature; excluded from FIPS boundary |

## Critical Security Parameters (CSPs)

| CSP | Type | Storage | Protection | Destruction |
|-----|------|---------|------------|-------------|
| AES-256 keys | Symmetric | KeyStore slots (stack) | Not exportable via API | `zeroize` on drop |
| HMAC keys | Symmetric | KeyStore slots (stack) | Not exportable via API | `zeroize` on drop |
| ECDSA private keys | Asymmetric | KeyStore slots (stack) | Not exportable via API | `zeroize` on drop |
| ECDH private keys | Asymmetric | Ephemeral (stack) | Never stored | `zeroize` after derivation |
| RNG seed/state | Internal | RNG function closure | Not accessible | Caller-managed |

### CSP Lifecycle

1. **Generation**: Via `random_bytes()` (requires approved DRBG in FIPS mode)
2. **Import**: Via `set_key(slot_id, &key_material)` — copies into KeyStore
3. **Use**: Indexed by `KeyId` (u32 slot number)
4. **Destruction**: Automatic `zeroize` on `SoftwareCryptoProvider` drop; explicit via `clear_key(slot_id)`

## Interfaces

### Data Input Interface

| Function | Input | CSP Access |
|----------|-------|------------|
| `sha256(data, hash_out)` | Plaintext data | None |
| `aes_gcm_encrypt(key_id, nonce, plaintext, aad, ct_out, tag_out)` | Plaintext + AAD | Key by ID |
| `sign_p256(key_id, digest, sig_out)` | Message digest | Key by ID |

### Data Output Interface

| Function | Output | CSP Exposure |
|----------|--------|-------------|
| `sha256(data, hash_out)` | Hash digest | None |
| `aes_gcm_decrypt(key_id, nonce, ct, aad, tag, pt_out)` | Plaintext | None (key stays internal) |
| `verify_p256(key_id, pub_key, digest, sig)` | Boolean | None |
| `ecdh_derive_shared(key_id, peer_pub, shared_out)` | Shared secret | Derived key (CSP) |

### Control Input Interface

| Function | Purpose |
|----------|---------|
| `SoftwareCryptoProvider::new(rng)` | Module initialization |
| `set_key(slot_id, material)` | CSP import |

### Status Output Interface

| Function | Purpose |
|----------|---------|
| Return `Result<(), VsError>` | Operation success/failure |

## Self-Tests

### Power-On Self-Tests (POST)

| Test | Algorithm | Method | Status |
|------|-----------|--------|--------|
| SHA-256 KAT (empty string) | SHA-256 | Known-answer: SHA-256("") == e3b0c44... | IMPLEMENTED in `self_test()` |
| SHA-256 KAT ("abc") | SHA-256 | Known-answer: SHA-256("abc") == ba7816bf... | IMPLEMENTED in `self_test()` |
| AES-256-GCM KAT | AES-256-GCM | Encrypt + decrypt + compare | IMPLEMENTED in `self_test()` |
| HMAC-SHA-256 KAT | HMAC-SHA-256 | Known-answer per RFC 4231 test vector | IMPLEMENTED in `self_test()` |
| ECDSA P-256 KAT | ECDSA | Sign + verify with test vector | GAP — need to implement |
| RNG health test | DRBG | Continuous health test | GAP — need approved DRBG |

A `periodic_self_test()` function is also available for runtime re-validation of all
implemented KATs.

### Conditional Self-Tests

| Trigger | Test | Status |
|---------|------|--------|
| Key pair generation | Pairwise consistency test | GAP |
| DRBG reseed | Continuous RNG test | GAP |
| Firmware load | Software integrity test | PRESENT (boot attestation) |

## Gap Summary for FIPS 140-3 Level 1

| Requirement | Status | Gap Description | Effort |
|-------------|--------|-----------------|--------|
| Module boundary documentation | PRESENT | This document | Done |
| Algorithm validation (CAVP) | GAP | Need CAVP test vectors for all algorithms | 4 weeks |
| Power-on self-tests (KATs) | PARTIAL | SHA-256, AES-256-GCM, HMAC-SHA-256 KATs implemented in `self_test()`; `periodic_self_test()` available; ECDSA P-256 KAT still needed | 1 week |
| Conditional self-tests | GAP | Pairwise consistency, RNG health | 1 week |
| Approved DRBG | GAP | Current RNG is caller-provided; need FIPS-approved HMAC-DRBG or CTR-DRBG (SP 800-90A) | 2 weeks |
| Error indicator | PRESENT | `VsError` return codes on all functions | Done |
| Key zeroization | PRESENT | `zeroize` crate on all CSPs | Done |
| Operator guidance | GAP | Need Security Policy document | 1 week |
| Finite state model | GAP | Need formal state machine document | 1 week |
| Physical security | N/A | Level 1 = no physical requirements | N/A |

**Total estimated effort: 8-9 weeks (1 engineer) for Level 1 submission readiness**

## Recommended Next Steps

1. Implement ECDSA P-256 KAT to complete POST coverage for all approved algorithms
2. Add FIPS-approved HMAC-DRBG (SP 800-90A) as the approved RNG
3. Run NIST CAVP test vectors for AES-256-GCM, SHA-256, HMAC-SHA-256, ECDSA P-256
4. Write Security Policy document (FIPS 140-3 format)
5. Define finite state model (pre-init → initialized → operational → error → zeroized)
6. Submit to CMVP-accredited lab for validation testing
