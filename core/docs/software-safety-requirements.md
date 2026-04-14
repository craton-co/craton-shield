# Craton Shield -- Software Safety Requirements Specification

**Version**: 1.1.0 | **Date**: 2026-03-24 | **Classification**: ASIL-B
**Document ID**: VS-SSR-001 | **Status**: Released
**Safety Case Version**: VS-SC-001 v1.2.0
**Applicable Standard**: ISO 26262:2018 Part 6

---

## 1 Scope and Applicability

This document specifies the Software Safety Requirements (SSRs) for Craton Shield v0.6.0
and later. It applies to all production crates rated ASIL-B or higher as defined in the
ISO 26262 Safety Case (VS-SC-001).

### 1.1 System Under Consideration

Craton Shield is a `#![no_std]`, zero-heap intrusion detection and prevention platform
designed as a Safety Element out of Context (SEooC). It executes on automotive ECUs and
monitors CAN, Ethernet, OTA, and network interfaces. Additional automotive-specific monitors (diagnostic gateway, V2X) are available in the [`auto/`](../../auto/) repository.

### 1.2 ASIL Classification

The overall system is classified ASIL-B. Individual subsystems may carry QM or ASIL-B(D)
ratings per the ASIL decomposition defined in the safety case.

### 1.3 Referenced Documents

| ID | Title | Version |
|----|-------|---------|
| VS-SC-001 | ISO 26262 ASIL-B Safety Case | 1.2.0 |
| VS-TARA-001 | TARA Threat and Risk Analysis | 2.0 |
| VS-SM-001 | Safety Manual | 1.0.0 |

---

## 2 Safety Goals

The SSRs trace to the following safety goals derived from the HARA in VS-SC-001.

| ID | Description | ASIL | Derived From |
|----|-------------|------|--------------|
| SG-01 | Detect malicious CAN frames within 50 us WCET | B | HE-01, HE-06 |
| SG-02 | Enforce network firewall default-deny policy | B | HE-02 |
| SG-03 | Protect cryptographic key material with zeroization | B | HE-08 |
| SG-04 | Validate OTA update signatures before installation | B | HE-04 |
| SG-05 | Maintain tamper-evident audit trail | B | HE-03, HE-08 |
| SG-06 | Detect boot chain integrity violations | B | HE-04 |
| SG-07 | Runtime shall remain operational under all input conditions (no panic) | B | HE-07 |

---

## 3 Software Safety Requirements

### 3.1 Requirements Table

| ID | Requirement | ASIL | Rationale | Traces To | Verification Method | Test Case | Status |
|----|-------------|------|-----------|-----------|---------------------|-----------|--------|
| SSR-01 | CAN frame processing shall complete within 50 us WCET on target | B | Exceeding the WCET budget causes watchdog timeout and loss of monitoring. The 50 us budget allows processing at maximum CAN bus load (1 Mbit/s). | SG-01, SG-07 | WCET analysis on target hardware | WCET measurement on Cortex-M4 target | Pending |
| SSR-02 | CAN allowlist shall reject frames with unknown arbitration IDs | B | Allowing unknown arbitration IDs permits injection of malicious frames onto safety-critical CAN bus segments. | SG-01 | Unit test | `test_allowlist_rejects_unknown_id` | Verified |
| SSR-03 | Ethernet firewall shall enforce default-deny policy | B | An empty rule table must not degrade to allow-all, which would violate the default-deny security model and expose unprotected services. | SG-02 | Unit test | `test_empty_rules_reject_all` | Verified |
| SSR-04 | OTA validator shall verify Ed25519/P-256 signatures before applying updates | B | Installing tampered firmware enables arbitrary code execution on the ECU, compromising all safety functions. | SG-04 | Integration test | `test_ota_signature_verification` | Verified |
| SSR-05 | Cryptographic operations shall use SoftwareCryptoProvider or HSM-backed provider | B | Ad-hoc cryptographic implementations are error-prone and may introduce vulnerabilities that compromise authentication guarantees. | SG-03 | Unit test | `test_crypto_provider_operations` | Verified |
| SSR-06 | Key material shall be zeroized on drop | B | Residual key material in memory can be extracted by an attacker with physical access or via a memory disclosure vulnerability. | SG-03 | Unit test | `test_key_zeroize_on_drop` | Verified |
| SSR-07 | Event log shall maintain HMAC chain integrity | B | A broken HMAC chain allows an attacker to tamper with or delete log entries without detection, destroying forensic evidence. | SG-05 | Unit test | `test_event_log_hmac_chain` | Verified |
| SSR-08 | Anomaly detector shall flag statistical outliers using EWMA and entropy methods | B | Statistical anomaly detection complements allowlist-based detection by identifying novel attack patterns that evade signature-based filters. | SG-01 | Unit test | `test_anomaly_detection_ewma_entropy` | Verified |
| SSR-09 | Secure boot shall verify firmware hash chain | B | An unverified boot chain allows execution of tampered firmware, compromising all downstream safety functions. | SG-06 | Unit test | `test_secure_boot_hash_chain` | Verified |
| SSR-10 | Runtime integrity checks shall detect memory corruption | B | Undetected memory corruption can silently alter security policy data or monitoring thresholds, disabling protection. | SG-06 | Unit test | `test_runtime_integrity_corruption` | Verified |
| SSR-11 | Policy engine shall evaluate security rules without allocation | B | Heap allocation introduces non-deterministic latency and fragmentation that can cause out-of-memory failures on resource-constrained ECUs. | SG-07 | Unit test | `test_policy_engine_no_alloc` | Verified |
| SSR-12 | IDS engine shall coordinate detection across all monitors | B | Uncoordinated monitors may miss multi-vector attacks that span CAN and Ethernet interfaces simultaneously. | SG-01, SG-02 | Unit test | `test_ids_engine_coordination` | Verified |
| SSR-13 | All security alerts shall include monotonic timestamps | B | Non-monotonic timestamps prevent reliable event ordering, making forensic analysis of multi-stage attacks impossible. | SG-05 | Unit test | `test_alert_monotonic_timestamps` | Verified |
| SSR-14 | Rate limiting shall prevent event log flooding | B | Unbounded logging under attack conditions can exhaust storage and mask critical alerts among noise. | SG-05 | Unit test | `test_rate_limiting` | Verified |
| SSR-15 | OTA rollback protection shall use monotonic version counter | B | Without rollback protection, an attacker can downgrade firmware to a version with known vulnerabilities. | SG-04 | Integration test | `test_ota_rollback_protection` | Verified |
| SSR-16 | FFI boundary shall catch panics and return error codes | B | Uncaught panics propagating across the FFI boundary cause undefined behavior and disable all security monitoring. | SG-07 | Unit test | `test_ffi_panic_catch` | Verified |

---

## 4 Traceability Matrix

### 4.1 Safety Goal to SSR Mapping

| Safety Goal | SSRs |
|-------------|------|
| SG-01 | SSR-01, SSR-02, SSR-08, SSR-12 |
| SG-02 | SSR-03, SSR-12 |
| SG-03 | SSR-05, SSR-06 |
| SG-04 | SSR-04, SSR-15 |
| SG-05 | SSR-07, SSR-13, SSR-14 |
| SG-06 | SSR-09, SSR-10 |
| SG-07 | SSR-01, SSR-11, SSR-16 |

### 4.2 SSR to Source and Test Mapping

| SSR | Source Location | Test Location |
|-----|-----------------|---------------|
| SSR-01 | `crates/can-monitor/src/lib.rs` -- `process_frame()` | Target WCET measurement |
| SSR-02 | `crates/can-monitor/src/lib.rs` -- `check_allowlist()` | `crates/can-monitor/src/lib.rs` (unit test) |
| SSR-03 | `crates/netfw/src/lib.rs` -- `evaluate()` | `crates/netfw/src/lib.rs` (unit test) |
| SSR-04 | `crates/ota-validator/src/lib.rs` -- `verify_signature()` | `tests/ota_attack.rs` |
| SSR-05 | `crates/crypto/src/software.rs` -- `SoftwareCryptoProvider` | `crates/crypto/src/lib.rs` (unit test) |
| SSR-06 | `crates/key-manager/src/lib.rs` -- `Drop for KeyEntry` | `crates/key-manager/src/lib.rs` (unit test) |
| SSR-07 | `crates/event-logger/src/lib.rs` -- `append()` | `crates/event-logger/src/lib.rs` (unit test) |
| SSR-08 | `crates/anomaly/src/lib.rs` -- `detect()` | `crates/anomaly/src/lib.rs` (unit test) |
| SSR-09 | `crates/secure-boot/src/lib.rs` -- `verify_chain()` | `crates/secure-boot/src/lib.rs` (unit test) |
| SSR-10 | `crates/integrity/src/lib.rs` -- `verify_region()` | `crates/integrity/src/lib.rs` (unit test) |
| SSR-11 | `crates/policy-engine/src/lib.rs` -- `evaluate()` | `crates/policy-engine/src/lib.rs` (unit test) |
| SSR-12 | `crates/ids-engine/src/lib.rs` -- `coordinate()` | `crates/ids-engine/src/lib.rs` (unit test) |
| SSR-13 | `crates/types/src/lib.rs` -- `SecurityAlert` | `crates/event-logger/src/lib.rs` (unit test) |
| SSR-14 | `crates/event-logger/src/lib.rs` -- `rate_limit()` | `crates/event-logger/src/lib.rs` (unit test) |
| SSR-15 | `crates/ota-validator/src/lib.rs` -- `check_rollback()` | `tests/ota_attack.rs` |
| SSR-16 | `crates/ffi/src/lib.rs` -- `catch_unwind()` | `crates/ffi/src/lib.rs` (unit test) |

---

## 5 Verification Summary

| Status | Count | Percentage |
|--------|-------|------------|
| Verified | 15 | 93.8% |
| Pending | 1 | 6.2% |
| Total | 16 | 100% |

**Pending items:**

- **SSR-01** (WCET analysis): Requires measurement on physical Cortex-M4 target hardware.
  Blocked until HILS test bench is available. Software simulation shows the implementation
  is within budget, but formal WCET analysis has not been performed.

---

## 6 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-15 | Craton Shield Team | Initial release, 15 SSRs extracted from safety case |
| 1.1.0 | 2026-03-24 | Craton Shield Team | Aligned with safety case v1.2.0: 7 safety goals (SG-01 through SG-07), 16 SSRs (SSR-01 through SSR-16), moved automotive-domain (`auto/`) SSRs out of scope |
