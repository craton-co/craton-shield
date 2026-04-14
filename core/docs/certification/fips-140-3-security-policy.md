# FIPS 140-3 Security Policy

**Module**: Craton Shield Cryptographic Module | **Version**: 0.6.0 | **Date**: 2026-03-28
**Target Level**: FIPS 140-3 Level 1 (Software Module)

---

## 1. Module Identification

| Field | Value |
|-------|-------|
| Module name | Craton Shield Cryptographic Module |
| Crate | `vs-crypto` |
| Version | 0.6.0 |
| Type | Software |
| Embodiment | Multi-chip standalone (general-purpose processor) |
| FIPS 140-3 level | Level 1 (target) |
| Operational environment | Limited (`no_std`, single-threaded, bare-metal or RTOS) |
| Interfaces | `CryptoProvider` trait (Rust API); C FFI bindings via `vs-ffi` |

---

## 2. Cryptographic Boundary

The FIPS 140-3 module boundary encompasses the `vs-crypto` crate and its direct cryptographic dependencies. All cryptographic operations enter and exit through the `CryptoProvider` trait interface.

### 2.1 Components Within Boundary

| Component | Role |
|-----------|------|
| `CryptoProvider` trait | Public interface for all cryptographic services |
| `SoftwareCryptoProvider` | Software implementation of `CryptoProvider` |
| `KeyStore` | Stack-allocated key storage (32 slots, 32 bytes each) |
| `aes-gcm` 0.10 | AES-256-GCM implementation |
| `sha2` 0.10 | SHA-256 implementation |
| `hmac` 0.12 | HMAC-SHA-256 implementation |
| `p256` 0.13 | ECDSA P-256 and ECDH P-256 implementation |
| `zeroize` 1.x | Secure memory clearing |
| `subtle` 2.x | Constant-time comparison operations |

### 2.2 Components Outside Boundary

All other Craton Shield crates (e.g., `vs-can-monitor`, `vs-ota-validator`, `vs-key-manager`) are outside the cryptographic boundary. They invoke cryptographic services solely through the `CryptoProvider` trait.

Full boundary diagram: `docs/certification/fips-140-3-boundary.md`.

---

## 3. Approved Algorithms

| Algorithm | Standard | Key/Digest Size | Usage |
|-----------|----------|-----------------|-------|
| AES-256-GCM | FIPS 197 + SP 800-38D | 256-bit key, 96-bit IV, 128-bit tag | OTA image encryption, secure channel |
| SHA-256 | FIPS 180-4 | 256-bit digest | Firmware integrity, TUF metadata hashing |
| HMAC-SHA-256 | FIPS 198-1 | 256-bit key, 256-bit tag | Message authentication, key derivation, log chaining |
| ECDSA P-256 | FIPS 186-5 | 256-bit key pair | OTA signature verification, V2X authentication |
| ECDH P-256 | SP 800-56Ar3 | 256-bit key pair | Key agreement for secure sessions |

---

## 4. Non-Approved Algorithms

The following algorithms are feature-gated behind the `pq-software` feature flag and are excluded from the FIPS 140-3 module boundary:

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM-768 | FIPS 203 (draft) | Experimental; post-quantum key encapsulation |
| ML-DSA-65 | FIPS 204 (draft) | Experimental; post-quantum digital signature |

These algorithms are accessed through the separate `PostQuantumProvider` trait. When the `pq-software` feature is disabled (default), no post-quantum code is compiled.

**Operator requirement**: For FIPS-validated operation, the `pq-software` feature must remain disabled.

---

## 5. Key Management

### 5.1 Key Storage

| Property | Value |
|----------|-------|
| Storage model | Stack-allocated fixed-size slots |
| Maximum slots | 32 |
| Key size | 32 bytes per slot |
| Heap allocation | None |

### 5.2 Key Lifecycle

| Phase | Mechanism |
|-------|-----------|
| Generation | External RNG function pointer provided at initialization |
| Storage | Written to `KeyStore` slot via `CryptoProvider` interface |
| Usage | Referenced by slot index; key material never exposed through public API |
| Zeroization | `Zeroize` trait implemented on `KeyStore`; all key material zeroed on drop |

### 5.3 Key Zeroization

- All types containing key material derive `Zeroize` and `ZeroizeOnDrop`.
- Key material is zeroed when the `SoftwareCryptoProvider` is dropped.
- Explicit zeroization is available through the `zeroize()` method.
- Stack-based storage eliminates heap residue risk.
- Zeroization is verified through dedicated tests (`tests/zeroization.rs`).

---

## 6. Self-Tests

### 6.1 Power-On Self-Tests (POST)

The module executes Known Answer Tests (KATs) during `vs-crypto::init()` before any cryptographic service is available. All POST must pass for the module to enter the Operational state.

| Test | Algorithm | Method |
|------|-----------|--------|
| AES-256-GCM KAT | AES-256-GCM | Encrypt/decrypt with NIST CAVP test vector; compare against known answer |
| SHA-256 KAT | SHA-256 | Hash known input; compare against known digest |
| HMAC-SHA-256 KAT | HMAC-SHA-256 | Compute MAC on known input with known key; compare against known tag |
| ECDSA P-256 KAT | ECDSA P-256 | Sign known message; verify signature; compare against known-good result |
| ECDH P-256 KAT | ECDH P-256 | Derive shared secret from known key pairs; compare against expected value |

Full KAT specification: `docs/certification/fips-140-3-kat-plan.md`.

### 6.2 Periodic Self-Tests

The `periodic_self_test()` function re-executes all POST KATs on demand. Integrators should invoke this function at a frequency appropriate for their deployment context (recommended: at least once per ignition cycle for automotive applications).

### 6.3 Self-Test Failure

If any self-test fails:
1. The module transitions to the Error state.
2. All cryptographic service functions return `VsError::SelfTestFailed`.
3. No cryptographic output is produced.
4. The module remains in the Error state until re-initialized.

---

## 7. Error Reporting

All errors are reported through the `VsError` return type. The module does not use exceptions, panics, or global error state.

| Error Code | Meaning |
|------------|---------|
| `VsError::SelfTestFailed` | A KAT or integrity check failed; module is in Error state |
| `VsError::CryptoError` | A cryptographic operation failed (invalid input, authentication failure) |
| `VsError::InvalidSlot` | Referenced key slot is out of range or uninitialized |
| `VsError::BufferTooSmall` | Output buffer is insufficient for the requested operation |

---

## 8. Operator Guidance

### 8.1 FIPS-Validated Operation

To operate the module in FIPS-validated mode, operators must:

1. Disable the `pq-software` feature flag (default configuration).
2. Provide a cryptographically secure RNG function pointer at initialization.
3. Call `vs-crypto::init()` and verify successful return before using any cryptographic service.
4. Invoke `periodic_self_test()` at appropriate intervals.
5. Ensure the `SoftwareCryptoProvider` is properly dropped (or `zeroize()` called) when the module is no longer needed.

### 8.2 Physical Security

FIPS 140-3 Level 1 does not impose physical security requirements beyond production-grade components. For deployments requiring higher assurance, operators should consider:

- Hardware security modules (HSM) for key storage
- Secure boot enforcement at the platform level
- Physical tamper detection on the gateway ECU

### 8.3 Firmware Update

When updating the module:
1. Verify the update image signature using the OTA validator before applying.
2. After update, the module will re-execute POST on next initialization.
3. Confirm POST passes before resuming operations.

---

## 9. References

| Document | Location |
|----------|----------|
| FIPS 140-3 module boundary definition | `docs/certification/fips-140-3-boundary.md` |
| FIPS 140-3 KAT implementation plan | `docs/certification/fips-140-3-kat-plan.md` |
| FIPS 140-3 finite state machine | `docs/certification/fips-140-3-state-machine.md` |
| NIST FIPS 140-3 | ISO/IEC 19790:2012 |
| NIST SP 800-140 series | Implementation guidance for FIPS 140-3 |
