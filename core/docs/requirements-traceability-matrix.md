# Craton Shield -- Requirements Traceability Matrix

**Document ID**: VS-RTM-001 | **Version**: 1.0.0 | **Date**: 2026-03-21
**Classification**: ASIL-B | **Standard**: ISO 26262:2018 Part 6, Part 8

---

## 1 Safety Goals

| ID | Description | ASIL |
|----|-------------|------|
| SG-01 | Detect malicious CAN frames within 50 us WCET | B |
| SG-02 | Enforce network firewall default-deny policy | B |
| SG-03 | Protect cryptographic key material with zeroization | B |
| SG-04 | Validate OTA update signatures before installation | B |
| SG-05 | Maintain tamper-evident audit trail | B |
| SG-06 | Detect boot chain integrity violations | B |
| SG-07 | Runtime shall remain operational under all input conditions (no panic) | B |

---

## 2 Safety Goal to SSR Mapping

| Safety Goal | Software Safety Requirements |
|-------------|------------------------------|
| SG-01 | SSR-01, SSR-02, SSR-08, SSR-12 |
| SG-02 | SSR-03, SSR-12 |
| SG-03 | SSR-05, SSR-06 |
| SG-04 | SSR-04, SSR-15 |
| SG-05 | SSR-07, SSR-13, SSR-14 |
| SG-06 | SSR-09, SSR-10 |
| SG-07 | SSR-01, SSR-11, SSR-16 |

---

## 3 Full Traceability Matrix

| SSR | Requirement | Safety Goal | Crate | Key Function(s) | Test Case(s) | Test File |
|-----|-------------|-------------|-------|------------------|--------------|-----------|
| SSR-01 | CAN frame processing shall complete within 50 us WCET on target | SG-01 | `can-monitor` | `CanMonitor::process_frame()` | `baseline_can_monitor_processes_frames` | `tests/ecu_validation.rs` |
| SSR-02 | CAN allowlist shall reject frames with unknown arbitration IDs | SG-01 | `can-monitor` | `CanMonitor::allow_id()`, `process_frame()` | `baseline_can_flood_detection` | `tests/ecu_validation.rs` |
| SSR-03 | Ethernet firewall shall enforce default-deny policy | SG-02 | `netfw` | `Firewall::evaluate()` | `test_empty_rules_reject_all` | `crates/netfw/src/lib.rs` |
| SSR-04 | OTA validator shall verify ECDSA P-256 signatures before applying updates | SG-04 | `ota-validator` | `OtaValidator::verify_root_update()` | `rollback_lower_version_rejected`, `expired_metadata_rejected`, `insufficient_threshold_signatures_rejected` | `tests/ota_attack.rs` |
| SSR-05 | Cryptographic operations shall use SoftwareCryptoProvider or HSM-backed provider | SG-03 | `crypto` | `SoftwareCryptoProvider::verify_p256()` | `test_bad_signature_rejected` | `crates/crypto/src/lib.rs` |
| SSR-06 | Key material shall be zeroized on drop | SG-03 | `key-manager` | `KeyManager::drop()` | Unit tests in `key-manager` | `crates/key-manager/src/lib.rs` |
| SSR-07 | Event log shall maintain HMAC chain integrity | SG-05 | `event-logger` | `EventLogger::log()` | Unit tests in `event-logger` | `crates/event-logger/src/lib.rs` |
| SSR-08 | Anomaly detector shall flag statistical outliers (EWMA/entropy) | SG-01 | `anomaly` | `AnomalyDetector::update()` | Unit tests in `anomaly` | `crates/anomaly/src/lib.rs` |
| SSR-09 | Secure boot shall verify firmware hash chain | SG-06 | `secure-boot` | `SecureBoot::verify_chain()` | Unit tests in `secure-boot` | `crates/secure-boot/src/lib.rs` |
| SSR-10 | Runtime integrity checks shall detect memory corruption | SG-06 | `integrity` | `verify_region()` | `baseline_integrity_roundtrip` | `tests/ecu_validation.rs` |
| SSR-11 | Policy engine shall evaluate security rules without allocation | SG-07 | `policy-engine` | `PolicyEngine::evaluate()` | Unit tests in `policy-engine` | `crates/policy-engine/src/lib.rs` |
| SSR-12 | IDS engine shall coordinate detection across all monitors | SG-01 | `ids-engine` | `IdsEngine::correlate()` | Unit tests in `ids-engine` | `crates/ids-engine/src/lib.rs` |
| SSR-13 | All security alerts shall include monotonic timestamps | SG-05 | `event-logger` | `EventLogger::log()` | Unit tests in `event-logger` | `crates/event-logger/src/lib.rs` |
| SSR-14 | Rate limiting shall prevent event log flooding | SG-05 | `event-logger` | `EventLogger::log()` | Unit tests in `event-logger` | `crates/event-logger/src/lib.rs` |
| SSR-15 | OTA rollback protection via monotonic version counter | SG-04 | `ota-validator` | `verify_root_update()`, `verify_target()` | `sequential_root_upgrades_advance_rollback_counter`, `multiple_sequential_root_updates_1_to_4` | `tests/ota_attack.rs` |
| SSR-16 | FFI boundary shall catch panics and return error codes | SG-07 | `ffi` | FFI exported functions | Unit tests in `ffi` | `crates/ffi/src/lib.rs` |

---

## 4 Integration and System Test Coverage

| Test File | Test Count | Safety Goals Covered | Scope |
|-----------|------------|----------------------|-------|
| `tests/attack_scenarios.rs` | 26 | SG-01, SG-02 | CAN/ETH attack detection scenarios |
| `tests/can_advanced.rs` | 9 | SG-01 | Advanced CAN protocol scenarios |
| `tests/ecu_validation.rs` | 14 | SG-01, SG-06 | Cross-platform baseline validation |
| `tests/eth_advanced.rs` | 12 | SG-02 | Advanced Ethernet protocol scenarios |
| `tests/event_log.rs` | 8 | SG-05 | Event logging integrity |
| `tests/firewall.rs` | 10 | SG-02 | Network firewall rule evaluation |
| `tests/full_stack.rs` | 23 | SG-01, SG-02, SG-06 | Runtime lifecycle, watchdog, mixed traffic |
| `tests/integrity.rs` | 10 | SG-06 | Runtime integrity verification |
| `tests/key_lifecycle.rs` | 10 | SG-03 | Key management lifecycle |
| `tests/ota_attack.rs` | 19 | SG-04 | TUF root update, rollback, hash/sig attacks |
| `tests/policy.rs` | 12 | SG-07 | Policy engine evaluation |
| `tests/secure_boot.rs` | 5 | SG-06 | Secure boot chain verification |
| `tests/stress.rs` | 9 | SG-01, SG-02, SG-06 | High-volume traffic, repeated init/shutdown |
| `tests/wcet_stats.rs` | 13 | SG-01 | Worst-case execution time statistics |

> **Note:** Automotive-specific integration tests (e.g., `diag_session.rs`) are in the
> [`auto/`](../../auto/) repository.

---

## 5 Unit Test Coverage by Crate

| Crate | Unit Tests | Primary Safety Goal(s) |
|-------|------------|------------------------|
| `anomaly` | 42 | SG-01 |
| `can-monitor` | 92 | SG-01 |
| `crypto` | 13 | SG-03 |
| `eth-monitor` | 129 | SG-02 |
| `event-logger` | 37 | SG-05 |
| `ffi` | 28 | SG-07 |
| `hal` | 46 | Cross-cutting |
| `hal-linux` | 27 | Cross-cutting |
| `ids-engine` | 48 | SG-01, SG-02 |
| `integrity` | 56 | SG-06 |
| `key-manager` | 64 | SG-03 |
| `netfw` | 61 | SG-02 |
| `ota-validator` | 99 | SG-04 |
| `policy-engine` | 79 | SG-07 |
| `runtime` | 33 | SG-06 |
| `secure-boot` | 47 | SG-06 |
| `storage` | 52 | SG-05 |
| `types` | 61 | Cross-cutting |

> **Note:** Automotive-specific crates (`autosar`, `v2x`, `signal-ids`, `diag-gateway`) and their
> tests are in the [`auto/`](../../auto/) repository.

---

## 6 Coverage Summary

| Metric | Value |
|--------|-------|
| Safety Goals defined | 7 |
| Software Safety Requirements | 16 |
| SSRs with implementation traced | 16 / 16 (100%) |
| SSRs with test cases traced | 16 / 16 (100%) |
| Total unit tests (across 18 crates) | 1,014 |
| Total integration tests (14 files) | 180 |
| **Total test count** | **1,194** |
| Untested SSRs | 0 |
| Pending verification (WCET on target HW) | SSR-01 |

---

## 7 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-21 | Craton Shield Team | Initial RTM covering SG-01 through SG-07, SSR-01 through SSR-16 |
