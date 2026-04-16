# Dependent Failure Analysis (DFA) Report

**Project**: Craton Shield | **Standard**: ISO 26262-9 Clause 7 | **Version**: 0.6.0 | **Date**: 2026-03-15

---

## 1. Purpose

This report documents the Dependent Failure Analysis (DFA) for Craton Shield as required by ISO 26262-9 Clause 7 for ASIL-B components. The DFA identifies common cause failures, cascading failures, and failures due to shared resources that could compromise the independence of safety mechanisms or violate multiple safety goals simultaneously.

---

## 2. Scope

The analysis covers all safety-relevant Craton Shield subsystems at ASIL-B:

- CAN monitoring (vs-can-monitor, vs-anomaly)
- Ethernet firewall (vs-eth-monitor, vs-netfw)
- Cryptographic services (vs-crypto, vs-key-manager)
- Secure boot verification (vs-secure-boot)
- OTA integrity validation (vs-ota-validator)
- Runtime integrity monitoring (vs-integrity)
- Runtime orchestration (vs-runtime)

> **Note**: Automotive-specific crates (signal-ids, diag-gateway, v2x, autosar, hal-qnx, vsoc-telemetry) are available in the [auto/](../../../auto/) repository.

Safety goals under analysis: SG-01 through SG-06 as defined in the Craton Shield Safety Case.

---

## 3. Common Cause Failures

### 3.1 CCF-01: Shared Cryptographic Provider

| Field | Description |
|-------|-------------|
| **Failure ID** | CCF-01 |
| **Shared Resource** | `CryptoProvider` trait (implemented by `SoftwareCryptoProvider` in vs-crypto) |
| **Description** | All authentication and integrity functions depend on a single cryptographic provider instance. A fault in vs-crypto (algorithm bug, key corruption, or provider initialization failure) disables signature verification, HMAC chain validation, and authenticated encryption across all consumers simultaneously. |
| **Affected Safety Goals** | SG-03 (protect cryptographic key material with zeroization), SG-04 (validate OTA update signatures before installation), SG-05 (maintain tamper-evident audit trail) |
| **Affected Crates** | vs-ota-validator, vs-secure-boot, vs-integrity, vs-key-manager |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | Known-answer tests (KAT) for all crypto primitives (ECDSA P-256, AES-GCM, SHA-256, HMAC) executed at init time and in CI | Detects algorithmic faults before deployment |
| 2 | Provider returns typed errors (`CryptoError::NotInitialized`, `CryptoError::VerificationFailed`) rather than silent failure; consumers treat crypto errors as deny | Fail-safe: crypto failure blocks operations rather than permitting them |
| 3 | Secure boot can halt the boot process independently if PCR verification fails, without relying on vs-crypto for the halt decision | Independent safety mechanism for boot path |
| 4 | OEM integrator assumption A-08 requires HSM/TEE in production, providing hardware-isolated crypto | Hardware isolation eliminates single software provider as sole dependency |

**Residual Risk**: In software-only configurations (development/test), a single bug in the `p256` or `aes-gcm` crate could compromise all authentication. This is mitigated by using audited RustCrypto crates and requiring HSM delegation in production (assumption A-08).

---

### 3.2 CCF-02: Shared Memory (Stack-Only Architecture)

| Field | Description |
|-------|-------------|
| **Failure ID** | CCF-02 |
| **Shared Resource** | Stack memory shared across all subsystems (no heap, no memory isolation) |
| **Description** | Craton Shield operates in a single-threaded, stack-only execution model. All subsystems share the same address space and stack. A stack overflow or memory corruption in any subsystem could corrupt data structures of other subsystems. |
| **Affected Safety Goals** | SG-01 through SG-06 (all safety goals) |
| **Affected Crates** | All production crates |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | Rust ownership and borrowing system prevents use-after-free, double-free, buffer overflow, and data races at compile time | Eliminates entire classes of memory corruption by construction |
| 2 | `#![deny(unsafe_code)]` enforced on all crates except vs-ffi, vs-hal-linux, and vs-storage; unsafe blocks confined to FFI, HAL, and storage layers (37 items in production: 6 in vs-ffi, 29 in vs-hal-linux, 2 in vs-storage) | Safety-relevant crates have zero unsafe code |
| 3 | No heap allocation (`#![no_std]`, no `alloc` crate); all data structures use fixed-size arrays on the stack | Eliminates heap fragmentation, use-after-free of heap objects, and out-of-memory conditions |
| 4 | No recursion in any production code path; all loops have compile-time or configuration-bounded iteration counts | Stack depth is statically bounded and analyzable |
| 5 | Stack watermark analysis recommended for target hardware (integrator responsibility, assumption A-11) | Detects stack exhaustion before deployment |

**Residual Risk**: A bug in the Rust compiler could generate incorrect code that violates memory safety. This is mitigated by using stable Rust releases (MSRV 1.82+), running the full test suite on each target, and the Rust compiler's own extensive test infrastructure. Hardware MPU-based stack isolation between subsystems is not implemented and would require architectural changes.

---

### 3.3 CCF-03: Shared Monotonic Clock

| Field | Description |
|-------|-------------|
| **Failure ID** | CCF-03 |
| **Shared Resource** | Monotonic timer provided via the `Timer` trait by the OEM integrator |
| **Description** | All time-dependent subsystems rely on a single monotonic time source: CAN flood detection (frame rate calculation), OTA metadata expiry checks, replay window enforcement, and EWMA decay calculations. A clock failure (stuck, jumping, or drifting beyond tolerance) would simultaneously affect all time-dependent detection and validation logic. |
| **Affected Safety Goals** | SG-01 (CAN anomaly timing), SG-04 (OTA metadata expiry), SG-05 (certificate validity period) |
| **Affected Crates** | vs-can-monitor, vs-anomaly, vs-ota-validator, vs-runtime |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | Timeout-based decisions default to deny: if time source is unreliable, expired checks reject rather than accept | Fail-safe behavior on clock failure |
| 2 | Integrator assumption A-01 requires monotonic time source with <=1 ms jitter | Contractual requirement on integrator to provide reliable clock |
| 3 | External hardware watchdog (integrator-provided, assumption A-12) operates on an independent timer and detects if `tick()` is not called within the expected period | Independent timing mechanism detects clock-related hangs |
| 4 | CAN flood detection uses frame-count-per-tick ratios rather than absolute timestamps, reducing sensitivity to clock drift | Relative timing more robust than absolute |

**Residual Risk**: If the integrator's time source silently drifts (returns monotonically increasing but inaccurate values), replay windows and expiry checks may accept stale data. This is bounded by the jitter requirement in A-01 and the watchdog in A-12.

---

### 3.4 CCF-04: Shared CAN Bus Interface

| Field | Description |
|-------|-------------|
| **Failure ID** | CCF-04 |
| **Shared Resource** | CAN bus interface (single point of ingress for all CAN traffic to Craton Shield) |
| **Description** | Craton Shield receives CAN frames through a single interface provided by the HAL. A CAN bus-off condition, hardware transceiver failure, or driver bug would prevent all CAN frames from reaching Craton Shield, disabling CAN monitoring, CAN-based anomaly detection, and signal-level IDS simultaneously. |
| **Affected Safety Goals** | SG-01 (CAN anomaly detection) |
| **Affected Crates** | vs-can-monitor, vs-anomaly, vs-ids-engine |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | Bus-off detection: vs-can-monitor tracks frame reception rate; zero frames over multiple ticks triggers a `BusOff` alert | Detects loss of CAN input |
| 2 | Ethernet monitoring path (vs-eth-monitor, vs-netfw) operates independently of CAN and is unaffected by CAN bus failure | Independent detection path for Ethernet-based attacks |
| 3 | `PlatformHealth` reports `CanMonitor` subsystem status; external watchdog can detect degraded state | Integrator can take recovery action |
| 4 | Integrator assumption A-03 requires frame delivery without silent drops | Contractual requirement on CAN driver integrity |

**Residual Risk**: If the CAN transceiver fails silently (no bus-off error flag, just stops receiving), Craton Shield cannot distinguish between "no traffic on bus" and "hardware failure." The frame-rate-based detection mitigates this for active buses but cannot detect failure on idle buses.

---

## 4. Cascading Failure Analysis

### 4.1 CSF-01: Runtime Crash Disables All Monitoring

| Field | Description |
|-------|-------------|
| **Failure ID** | CSF-01 |
| **Trigger** | A panic, stack overflow, or unrecoverable error in vs-runtime or any subsystem invoked during `tick()` |
| **Cascade Path** | `tick()` aborts -> no subsystem processing -> CAN monitoring stops -> Ethernet firewall stops -> OTA verification unavailable -> diagnostic gateway unresponsive -> all security monitoring disabled |
| **Affected Safety Goals** | SG-01 through SG-06 (complete loss of security monitoring) |
| **HARA Reference** | HE-07 (Runtime crash disables all security monitoring, ASIL-C before decomposition) |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | `panic=abort` configuration: on panic, execution halts immediately rather than unwinding, preventing corrupted-state operation | Fail-stop rather than fail-corrupt |
| 2 | External hardware watchdog (assumption A-12) detects that `tick()` has stopped and triggers ECU reset | Independent recovery mechanism |
| 3 | No recursion, no heap, bounded loops: eliminates common causes of stack overflow and unbounded execution | Prevents the triggering condition |
| 4 | Rust type system prevents null dereference, use-after-free, and buffer overflow that cause crashes in C/C++ | Eliminates most crash-inducing bugs by construction |
| 5 | 1,014 unit tests + 180 integration tests exercise error paths and boundary conditions | High confidence in robustness |

**Residual Risk**: A compiler bug generating incorrect code, or a hardware fault (bit-flip in code memory, power glint) could still cause a crash. The watchdog provides recovery, but there is a window between crash and watchdog-triggered reset during which no monitoring occurs. This window is bounded by the watchdog timeout period (integrator-configured, typically 50-200 ms).

---

### 4.2 CSF-02: Crypto Initialization Failure Cascade

| Field | Description |
|-------|-------------|
| **Failure ID** | CSF-02 |
| **Trigger** | `SoftwareCryptoProvider::new()` fails during `CratonShield::init()` (e.g., key provisioning failure, RNG failure) |
| **Cascade Path** | Crypto provider unavailable -> OTA signature verification returns `NotInitialized` -> secure boot verification returns `NotInitialized` -> integrity HMAC verification returns `NotInitialized` -> diagnostic authentication returns `NotInitialized` |
| **Affected Safety Goals** | SG-03, SG-04, SG-05 |

**Independence Measures**:

| # | Measure | Effectiveness |
|---|---------|---------------|
| 1 | All crypto consumers check for `NotInitialized` and fail closed (deny the operation) | Fail-safe: no authentication means no access |
| 2 | `PlatformHealth` reports crypto subsystem as `InitFailed`; integrator can halt boot or enter safe state | Integrator-level recovery |
| 3 | CAN monitoring (SG-01) and Ethernet firewall (SG-02) do not depend on crypto for their core detection function | Independent safety functions remain operational |

**Residual Risk**: If the integrator does not check `PlatformHealth` and continues operating with a failed crypto provider, all authentication-dependent functions are degraded to deny-all mode. This is safe but not functional.

---

## 5. Summary of Common Cause and Cascading Failures

| ID | Type | Shared Resource / Trigger | Safety Goals Affected | Independence Adequate | Residual Risk Level |
|----|------|--------------------------|----------------------|----------------------|-------------------|
| CCF-01 | Common Cause | Crypto provider | SG-03, SG-04, SG-05 | Yes (with HSM, assumption A-08) | Low (production), Medium (dev) |
| CCF-02 | Common Cause | Stack memory | SG-01 through SG-06 | Yes (Rust memory safety) | Low |
| CCF-03 | Common Cause | Monotonic clock | SG-01, SG-04, SG-05 | Yes (fail-deny + watchdog) | Low |
| CCF-04 | Common Cause | CAN bus interface | SG-01 | Partial (Ethernet path independent) | Medium |
| CSF-01 | Cascading | Runtime crash | SG-01 through SG-06 | Yes (watchdog recovery) | Medium (bounded by watchdog timeout) |
| CSF-02 | Cascading | Crypto init failure | SG-03, SG-04, SG-05 | Yes (fail-deny) | Low |

---

## 6. Recommendations

1. **Hardware memory protection**: For ASIL-C or higher applications, consider partitioning Craton Shield subsystems into separate MPU regions to provide hardware-enforced memory isolation (addresses CCF-02 residual risk).

2. **Redundant CAN interface**: For safety-critical CAN bus monitoring, the integrator should consider providing a redundant CAN transceiver or using CAN FD with error-detection capabilities to reduce CCF-04 residual risk.

3. **Watchdog timeout tuning**: The integrator should configure the hardware watchdog timeout to be no greater than 2x the `tick()` period (e.g., 20 ms for a 10 ms tick) to minimize the CSF-01 monitoring gap window.

4. **Independent clock validation**: Consider adding a secondary timer source (e.g., hardware RTC) to cross-check the primary monotonic timer at startup and periodically during operation (addresses CCF-03).

5. **Crypto provider health monitoring**: Implement periodic KAT execution (not just at init) to detect latent crypto faults during operation. This could be performed as a background task during idle tick cycles.

6. **HSM mandate for production**: Formally require HSM/TEE-backed crypto in all production deployments to eliminate the single software provider dependency (strengthens CCF-01 mitigation).

---

## 7. References

- ISO 26262-9:2018, Clause 7 — Analysis of dependent failures
- ISO 26262-9:2018, Annex D — Dependent failure analysis methods
- Craton Shield Safety Case (`docs/iso26262-safety-case.md`), Sections 3-4
- Craton Shield Safety Manual (`docs/safety-manual.md`), Section 3 — Assumptions of Use
- Craton Shield ASIL-B Pre-Assessment (`docs/certification/iso-26262-asil-b-assessment.md`), DFA section
