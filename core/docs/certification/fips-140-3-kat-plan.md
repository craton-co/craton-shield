# Craton Shield -- FIPS 140-3 Known Answer Test (KAT) Implementation Plan

**Version**: 1.0.0 | **Date**: 2026-03-15
**Target Module**: vs-crypto (Craton Shield Cryptographic Module)
**Target Level**: FIPS 140-3 Level 1 (Software Module)
**Applicable Standard**: FIPS 140-3 (ISO/IEC 19790:2012)

---

## 1 Overview

This document defines the Known Answer Test (KAT) implementation plan for the
Craton Shield cryptographic module (`vs-crypto`). FIPS 140-3 requires that a cryptographic
module perform self-tests at power-on and under specific conditional triggers to verify
correct operation of approved security functions before any cryptographic service is
available.

All self-tests must pass before `vs-crypto` transitions from the pre-operational state to
the operational state. If any self-test fails, the module enters an error state and all
cryptographic services return `CryptoError::SelfTestFailed`.

---

## 2 Approved Security Functions

The following algorithms are within the module boundary and require KATs:

| Algorithm | Standard | Usage in Craton Shield |
|-----------|----------|----------------------|
| AES-256-GCM | FIPS 197, SP 800-38D | OTA image encryption, secure channel |
| SHA-256 | FIPS 180-4 | Firmware integrity, TUF metadata hashing |
| HMAC-SHA-256 | FIPS 198-1 | Message authentication, key derivation |
| ECDSA P-256 | FIPS 186-5 | OTA signature verification, V2X authentication |
| ECDH P-256 | SP 800-56Ar3 | Key agreement for secure sessions |

---

## 3 Power-On Self-Tests (POST)

Power-on self-tests execute during `vs-crypto::init()` before any cryptographic service
is made available. All POST must complete successfully.

### 3.1 AES-256-GCM KAT

**Objective**: Verify correct encryption and decryption with authenticated data.

**Test procedure**:
1. Load known test vector (key, nonce, AAD, plaintext, expected ciphertext, expected tag)
   from NIST CAVP AES-GCM test vectors (GCMEncryptExtIV256.rsp).
2. Encrypt plaintext with known key, nonce, and AAD.
3. Compare output ciphertext and authentication tag against expected values.
4. Decrypt the ciphertext using the same key, nonce, and AAD.
5. Compare recovered plaintext against original.
6. PASS if both encryption and decryption outputs match. FAIL otherwise.

**Test vector source**: NIST CAVP -- AESGCM (AES-GCM Validation System)
- File: `GCMEncryptExtIV256.rsp`, Count 0 (256-bit key, 96-bit IV, 128-bit tag)

**Status**: **IMPLEMENTED** in `run_self_test_kats()`. The AES-256-GCM KAT encrypts a known
plaintext, compares the ciphertext and tag against expected values, then decrypts and
verifies round-trip correctness.

### 3.2 SHA-256 KAT

**Objective**: Verify correct hash computation.

**Test procedure**:
1. Compute SHA-256 of the empty string and compare against the well-known digest
   (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
2. Compute SHA-256 of `"abc"` and compare against the well-known digest
   (`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`).
3. PASS if both match. FAIL otherwise.

**Test vector source**: NIST FIPS 180-4 example values (empty string and "abc")

**Status**: **IMPLEMENTED** in `run_self_test_kats()`. Two KAT vectors are checked: SHA-256 of the
empty string and SHA-256 of `"abc"`.

### 3.3 HMAC-SHA-256 KAT

**Objective**: Verify correct keyed hash computation.

**Test procedure**:
1. Load known key, input message, and expected MAC from RFC 4231 test vectors.
2. Compute HMAC-SHA-256 with the known key and message.
3. Compare output MAC against expected value.
4. PASS if match. FAIL otherwise.

**Test vector source**: RFC 4231 (HMAC-SHA-256 test vectors)

**Status**: **IMPLEMENTED** in `run_self_test_kats()`. Uses an RFC 4231 test vector for
known-answer comparison.

### 3.4 ECDSA P-256 Sign/Verify KAT

**Objective**: Verify correct ECDSA signature generation and verification.

**Test procedure**:
1. Load known private key, message digest, and expected signature (r, s) from NIST CAVP
   ECDSA test vectors.
2. Sign the known digest with the known private key using deterministic ECDSA (RFC 6979).
3. Compare output signature (r, s) against expected values.
4. Verify the signature against the corresponding public key and digest.
5. PASS if signature matches expected values AND verification succeeds. FAIL otherwise.

**Note**: Because deterministic ECDSA (RFC 6979) is used, the signature output is
reproducible and can be compared against known values.

**Test vector source**: NIST CAVP -- ECDSA (ECDSA2 Validation System)
- File: `SigGen.txt`, P-256 section
- File: `SigVer.txt`, P-256 section (for verification-only vector)

**Status**: **IMPLEMENTED** in `run_self_test_kats()`. Uses RFC 6979 test vector for deterministic ECDSA P-256 sign and verify.

### 3.5 ECDH P-256 KAT

**Objective**: Verify correct key agreement computation.

**Test procedure**:
1. Load known static private key, known peer public key, and expected shared secret from
   NIST CAVP ECC CDH test vectors.
2. Compute ECDH shared secret using the private key and peer public key.
3. Compare output shared secret against expected value.
4. PASS if match. FAIL otherwise.

**Test vector source**: NIST CAVP -- ECC CDH (Component Validation System)
- File: `KAS_ECC_CDH_PrimitiveTest.txt`, P-256 section, Count=0

**Status**: **IMPLEMENTED** in `run_self_test_kats()`. Uses the NIST CAVP ECC CDH P-256
Count=0 test vector to verify ECDH key agreement against a known shared secret.

---

## 4 Conditional Self-Tests

Conditional self-tests execute when specific events occur during operation.

### 4.1 Key Pair Consistency Test

**Trigger**: After every ECDSA P-256 key pair generation.

**Test procedure**:
1. Sign a fixed test message with the newly generated private key.
2. Verify the signature with the corresponding public key.
3. PASS if verification succeeds. FAIL otherwise.

**Rationale**: Detects key generation faults that produce inconsistent key pairs.

**Estimated effort**: 0.5 days

### 4.2 DRBG Health Test

**Trigger**: At instantiation and on every reseed of the approved DRBG.

**Test procedure**:
1. Instantiate DRBG with known seed, nonce, and personalization string.
2. Generate output block.
3. Compare against expected output from NIST DRBG test vectors.
4. PASS if match. FAIL otherwise.

**Test vector source**: NIST CAVP -- DRBG (DRBG Validation System)
- HMAC_DRBG with SHA-256, no prediction resistance

**Note**: Craton Shield currently uses a platform-provided RNG. If an approved DRBG is
implemented within the module boundary, this test becomes mandatory.

**Estimated effort**: 1 day (if DRBG is brought in-module)

### 4.3 Firmware Integrity Test

**Trigger**: At power-on (included in POST sequence).

**Test procedure**:
1. Compute SHA-256 over the `vs-crypto` module binary region (text + rodata sections).
2. Compare against the expected hash stored in a protected, read-only location (e.g.,
   flash info block or secure boot chain).
3. PASS if match. FAIL otherwise.

**Implementation notes**:
- The module binary region boundaries are provided by the linker script symbols
  `__vs_crypto_start` and `__vs_crypto_end`.
- The expected hash is computed at build time and embedded in the secure boot metadata.
- On targets without MMU, the integrator must ensure the module region is not writable
  at runtime.

**Estimated effort**: 1.5 days

---

## 4.4 Periodic Self-Test

**Status**: **IMPLEMENTED** via `periodic_self_test()`.

A `periodic_self_test()` function is available for runtime re-validation. It re-executes
all implemented KATs (SHA-256, AES-256-GCM, HMAC-SHA-256, ECDSA P-256, ECDH P-256) and can be called at any time
to verify continued correct operation of the cryptographic module. This satisfies the
FIPS 140-3 recommendation for periodic self-testing during long-running operation.

---

## 5 Error State Behavior

If any self-test fails:

1. The module sets an internal flag `self_test_failed = true`.
2. All public API functions return `Err(CryptoError::SelfTestFailed)`.
3. The `PlatformHealth` subsystem status for crypto is set to
   `SubsystemStatus::InitFailed`.
4. The module cannot be recovered without a full system reset and re-initialization.

This behavior satisfies FIPS 140-3 Section 7.10.1 (Error State).

---

## 6 Implementation Plan

### 6.1 Module Structure

```
crates/crypto/src/
    fips/
        mod.rs          -- POST orchestration, error state management
        aes_gcm_kat.rs  -- AES-256-GCM KAT
        sha256_kat.rs   -- SHA-256 KAT
        hmac_kat.rs     -- HMAC-SHA-256 KAT
        ecdsa_kat.rs    -- ECDSA P-256 KAT
        ecdh_kat.rs     -- ECDH P-256 KAT
        vectors.rs      -- Compiled-in NIST CAVP test vectors (const arrays)
        integrity.rs    -- Firmware integrity self-test
```

### 6.2 Feature Gate

KAT execution is controlled by a Cargo feature flag:

```toml
[features]
fips-kat = []  # Enable FIPS 140-3 Known Answer Tests at init
```

When `fips-kat` is not enabled, the POST phase is skipped and the module transitions
directly to operational state. This allows development and testing without the overhead
of self-tests.

### 6.3 Effort Summary

| Task | Estimated Effort |
|------|-----------------|
| AES-256-GCM KAT | Done (implemented in `run_self_test_kats()`) |
| SHA-256 KAT | Done (implemented in `run_self_test_kats()`) |
| HMAC-SHA-256 KAT | Done (implemented in `run_self_test_kats()`) |
| Periodic self-test | Done (implemented as `periodic_self_test()`) |
| ECDSA P-256 KAT | Done (implemented in `run_self_test_kats()`) |
| ECDH P-256 KAT | Done (implemented in `run_self_test_kats()`) |
| Key pair consistency test | 0.5 days |
| DRBG health test | 1.0 day |
| Firmware integrity test | 1.5 days |
| POST orchestration and error state | 1.0 day |
| Test vector encoding and validation | 1.0 day |
| Integration testing and CI | 1.0 day |
| Documentation and review | 1.0 day |
| **Total remaining** | **6.0 days** |

### 6.4 Test Vector Management

All NIST CAVP test vectors are encoded as `const` byte arrays in `vectors.rs`. This
ensures:

- No file I/O at runtime (compatible with `#![no_std]`).
- Vectors are included in the module binary and covered by the firmware integrity test.
- Vectors can be independently verified against the NIST CAVP response files.

Test vector provenance:

| Algorithm | CAVP File | Vector ID |
|-----------|-----------|-----------|
| AES-256-GCM | GCMEncryptExtIV256.rsp | Keylen=256, IVlen=96, PTlen=128, AADlen=128, Taglen=128, Count=0 |
| SHA-256 | SHA256ShortMsg.rsp | Len=24, Count=0 |
| HMAC-SHA-256 | HMAC.rsp | L=32, Count=0 |
| ECDSA P-256 sign | SigGen.txt | P-256, first entry |
| ECDSA P-256 verify | SigVer.txt | P-256, first valid entry |
| ECDH P-256 | KAS_ECC_CDH_PrimitiveTest.txt | P-256, Count=0 |

---

## 7 Compliance Mapping

| FIPS 140-3 Requirement | Section | Implementation |
|------------------------|---------|----------------|
| 7.10.1 Power-on self-tests | Sec. 3 | POST in `vs-crypto::init()` |
| 7.10.2 Conditional self-tests | Sec. 4 | On keygen, DRBG reseed |
| 7.10.1 Error state | Sec. 5 | `CryptoError::SelfTestFailed` |
| 7.10.3 Integrity test | Sec. 4.3 | SHA-256 of module binary |
| 7.7 Module interfaces | -- | Defined in `vs-crypto::CryptoProvider` trait |
| 7.5 Software security | -- | `#![no_std]`, no heap, zeroize on drop |

---

## 8 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-15 | Craton Shield Team | Initial KAT implementation plan |
