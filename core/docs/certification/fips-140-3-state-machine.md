# FIPS 140-3 Finite State Machine

**Module**: Craton Shield Cryptographic Module | **Version**: 0.6.0 | **Date**: 2026-03-28
**Target Level**: FIPS 140-3 Level 1 (Software Module)
**Applicable Standard**: FIPS 140-3 (ISO/IEC 19790:2012), SP 800-140D

---

## 1. Purpose

This document specifies the finite state machine (FSM) for the Craton Shield cryptographic module (`vs-crypto`). The FSM defines all module states, permitted transitions, and conditions governing each transition, as required by FIPS 140-3 Section 7.2.2.

---

## 2. States

| State | Description |
|-------|-------------|
| **Uninitialized** | Module code is loaded but `init()` has not been called. No cryptographic services are available. Key store is empty. |
| **Self-Test** | Module is executing power-on self-tests (KATs). No cryptographic services are available during this state. |
| **Operational** | All self-tests passed. Cryptographic services are available. This is the only state in which approved security functions may be invoked. |
| **Error** | A self-test failed or a critical operational error occurred. All cryptographic service calls return `VsError::SelfTestFailed`. No cryptographic output is produced. |
| **Zeroized** | All key material and critical security parameters (CSPs) have been securely erased. Module cannot provide cryptographic services. |

---

## 3. State Diagram

```
                    +-----------------+
                    |  Uninitialized  |
                    +--------+--------+
                             |
                         init() called
                             |
                             v
                    +--------+--------+
                    |    Self-Test    |
                    +--------+--------+
                            / \
                           /   \
                All pass  /     \  Any fail
                         /       \
                        v         v
              +---------+--+  +--+---------+
              | Operational |  |   Error    |
              +---------+--+  +--+---------+
                        |         |
         periodic_self_ |         | init() called
         test() fails   |         | (re-initialize)
                        |         |
                        v         v
                   +----+----+  Self-Test
                   |  Error  |  (returns to
                   +----+----+   Self-Test state)
                        |
                        |
             +----------+----------+
             |                     |
         init() called       zeroize() or
         (re-initialize)     drop
             |                     |
             v                     v
        Self-Test           +------+------+
                            |  Zeroized   |
                            +-------------+

         Operational --(zeroize() or drop)--> Zeroized
```

---

## 4. State Transitions

### 4.1 Uninitialized --> Self-Test

| Field | Value |
|-------|-------|
| Trigger | `init()` is called with a valid RNG function pointer |
| Precondition | Module is in Uninitialized state |
| Action | Begin executing power-on self-tests (KATs) for all approved algorithms |
| Postcondition | Module is in Self-Test state |

### 4.2 Self-Test --> Operational

| Field | Value |
|-------|-------|
| Trigger | All KATs complete successfully |
| Precondition | Module is in Self-Test state; all KATs passed |
| Action | Enable cryptographic services; initialize key store |
| Postcondition | Module is in Operational state; all `CryptoProvider` functions are available |

### 4.3 Self-Test --> Error

| Field | Value |
|-------|-------|
| Trigger | Any KAT fails (computed output does not match known answer) |
| Precondition | Module is in Self-Test state |
| Action | Record which self-test failed; disable all cryptographic services |
| Postcondition | Module is in Error state; all service calls return `VsError::SelfTestFailed` |

### 4.4 Operational --> Error

| Field | Value |
|-------|-------|
| Trigger | `periodic_self_test()` is called and any KAT fails |
| Precondition | Module is in Operational state |
| Action | Disable all cryptographic services; record failure |
| Postcondition | Module is in Error state; all service calls return `VsError::SelfTestFailed` |

### 4.5 Error --> Self-Test

| Field | Value |
|-------|-------|
| Trigger | `init()` is called to re-initialize the module |
| Precondition | Module is in Error state |
| Action | Clear error state; begin executing power-on self-tests |
| Postcondition | Module is in Self-Test state |

### 4.6 Operational --> Zeroized

| Field | Value |
|-------|-------|
| Trigger | `zeroize()` is called explicitly, or `SoftwareCryptoProvider` is dropped |
| Precondition | Module is in Operational state |
| Action | Zero all key material in `KeyStore`; zero all intermediate cryptographic state; disable all cryptographic services |
| Postcondition | Module is in Zeroized state; no CSPs remain in memory |

### 4.7 Error --> Zeroized

| Field | Value |
|-------|-------|
| Trigger | `zeroize()` is called explicitly, or `SoftwareCryptoProvider` is dropped |
| Precondition | Module is in Error state |
| Action | Zero all key material and intermediate state |
| Postcondition | Module is in Zeroized state |

---

## 5. Prohibited Transitions

The following transitions are not permitted:

| From | To | Reason |
|------|----|--------|
| Uninitialized | Operational | Self-tests must execute before services are available |
| Uninitialized | Error | Error state is only reached through self-test failure |
| Self-Test | Zeroized | Self-tests must complete (pass or fail) before zeroization |
| Zeroized | Operational | A zeroized module must be fully re-initialized |
| Zeroized | Self-Test | Re-initialization from Zeroized state requires constructing a new `SoftwareCryptoProvider` instance, which starts in Uninitialized |

---

## 6. Error Handling Behavior

### 6.1 Error State Behavior

When the module is in the Error state:

- All calls to `sha256()`, `hmac_sha256()`, `aes_gcm_encrypt()`, `aes_gcm_decrypt()`, `sign_p256()`, `verify_p256()`, and `ecdh_derive_shared()` return `Err(VsError::SelfTestFailed)`.
- No cryptographic output is produced.
- The error state is persistent until `init()` is called to re-initialize.
- The operator may call `zeroize()` to transition to Zeroized and then construct a new instance.

### 6.2 Operational Error Handling

During normal operation, individual cryptographic function failures (e.g., authentication tag mismatch during decryption, invalid signature) return appropriate `VsError` variants but do not cause a state transition. The module remains in the Operational state. Only self-test failures cause transition to Error.

### 6.3 Recovery Procedure

To recover from the Error state:

1. Call `init()` to re-enter Self-Test.
2. If self-tests pass, the module transitions to Operational.
3. If self-tests fail again, the module remains in Error. The operator should investigate the root cause (corrupted module, hardware fault) before retrying.

---

## 7. References

| Document | Location |
|----------|----------|
| FIPS 140-3 module boundary definition | `docs/certification/fips-140-3-boundary.md` |
| FIPS 140-3 KAT implementation plan | `docs/certification/fips-140-3-kat-plan.md` |
| FIPS 140-3 security policy | `docs/certification/fips-140-3-security-policy.md` |
