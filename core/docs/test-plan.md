# Craton Shield -- Test Plan

**Test Plan Identifier**: Craton Shield-TP-001
**Version**: 1.0.0 | **Date**: 2026-03-21 | **Release**: v0.6.0 | **Classification**: ASIL-B
**Standard**: IEEE 829-2008 | **Applicable**: ISO 26262:2018 Part 6

---

## 1 Scope

This test plan covers all verification activities for Craton Shield Core v0.6.x, including unit testing, integration testing, system-level testing, stress testing, and cross-compilation validation. Testing applies to all 21 production crates, the FFI layer, and the integration test suite.

---

## 2 Test Items

| Item | Version | Description |
|------|---------|-------------|
| `anomaly` | 0.6.0 | Statistical anomaly detection engine |
| `can-monitor` | 0.6.0 | CAN frame IDS with allowlist, entropy, and rate analysis |
| `crypto` | 0.6.0 | SHA-256, HMAC, ECDSA P-256, constant-time operations |
| `eth-monitor` | 0.6.0 | Ethernet IDS: SOME/IP, SOME/IP-SD, DoIP, VLAN, ARP monitoring |
| `event-logger` | 0.6.0 | Tamper-evident append-only event log |
| `ffi` | 0.6.0 | C-compatible FFI bindings |
| `hal` / `hal-linux` | 0.6.0 | Hardware abstraction layer |
| `ids-engine` | 0.6.0 | Central IDS policy engine and alert dispatch |
| `integrity` | 0.6.0 | Runtime memory region integrity checks |
| `key-manager` | 0.6.0 | Key storage, rotation, and zeroization |
| `netfw` | 0.6.0 | Stateful Ethernet firewall with default-deny policy |
| `ota-validator` | 0.6.0 | TUF-compliant OTA firmware validation |
| `policy-engine` | 0.6.0 | Rule-based policy evaluation |
| `runtime` | 0.6.0 | Platform lifecycle, watchdog, subsystem orchestration |
| `secure-boot` | 0.6.0 | Boot chain integrity verification |
| `storage` | 0.6.0 | Persistent storage abstraction |
| `types` | 0.6.0 | Shared types, error codes, alert definitions |
| `report-iec62443` | 0.6.0 | IEC 62443-4-2 compliance gap analysis report generation |
| `report-iso21434` | 0.6.0 | ISO/SAE 21434 TARA report generation |
| `report-iec62304` | 0.6.0 | IEC 62304 software safety traceability matrix generation |

> **Note:** Additional automotive-specific crates (signal-ids, diag-gateway, v2x, autosar, vsoc-telemetry) are available in the [auto/](../../auto/) repository.

---

## 3 Features to Be Tested

1. **CAN IDS** -- Frame filtering, allowlist enforcement, entropy analysis, flood detection, bus-off detection
2. **Ethernet IDS** -- SOME/IP validation, SD service tracking, DoIP monitoring, VLAN enforcement, ARP anomaly detection
3. **OTA Validation** -- TUF root update, rollback protection, metadata expiry, target hash/length verification, threshold signatures
4. **Firewall** -- Default-deny evaluation, rule matching, stateful connection tracking
5. **Cryptography** -- SHA-256 correctness, HMAC verification, ECDSA P-256 sign/verify, RNG entropy validation, key zeroization
6. **Key Management** -- Key provisioning, rotation, secure deletion
7. **Secure Boot** -- Boot chain verification, stage-by-stage validation
8. **Integrity** -- Memory region hashing and tamper detection
9. **Anomaly Detection** -- Statistical baseline, deviation scoring
10. **IDS Engine** -- Monitor coordination, alert dispatch
11. **Policy Engine** -- Rule-based evaluation, no-allocation guarantee
12. **Runtime** -- Init/shutdown lifecycle, watchdog health, no-panic guarantee

---

## 4 Test Approach

### 4.1 Requirements-Based Testing
Each SSR from VS-SSR-001 has at least one corresponding test case. Traceability is maintained in VS-RTM-001.

### 4.2 Structural Testing
Unit tests target individual functions and error paths. Branch coverage is measured via `cargo-llvm-cov`.

### 4.3 Fault Injection
- Invalid CAN IDs, oversized DLC, malformed SOME/IP headers
- Expired TUF metadata, mismatched hashes, insufficient threshold signatures
- Wrong UDS security access keys, exceeded lockout counters

### 4.4 Fuzz Testing
`cargo-fuzz` targets for CAN frame parsing, Ethernet packet parsing, nonce counter validation, and OTA JSON metadata parsing. UDS request handling fuzz targets are available in [auto/](../../auto/).

### 4.5 Stress Testing
`tests/stress.rs` exercises high-volume scenarios: 1000+ CAN frames, 1000+ ETH packets, 10000 ticks, repeated init/shutdown cycles.

---

## 5 Pass/Fail Criteria

| Criterion | Threshold |
|-----------|-----------|
| Test pass rate | 100% (all tests must pass) |
| Clippy warnings | 0 (deny all warnings) |
| Runtime panics | 0 (verified by stress tests and `#![no_std]` constraints) |
| CAN frame processing latency | < 500 ns per frame (host benchmark) |
| Cross-compilation | Must build for `thumbv7em-none-eabihf` with no errors |
| Unsafe code | 0 blocks outside FFI and HAL layers |
| Heap allocations | 0 in production crates (`#![no_std]`, no `alloc`) |

---

## 6 Test Deliverables

| Deliverable | Format | Location |
|-------------|--------|----------|
| Unit + integration test results | `cargo test` stdout | CI pipeline artifacts |
| Coverage report | HTML / LCOV | `target/llvm-cov/html/` |
| Benchmark output | Criterion JSON | `target/criterion/` |
| Cross-compilation check | CI pass/fail | GitHub Actions log |
| Clippy lint report | CI pass/fail | GitHub Actions log |

---

## 7 Test Schedule

| Trigger | Tests Executed |
|---------|----------------|
| Every push | Unit tests, integration tests, clippy, `cargo check --target thumbv7em-none-eabihf` |
| Every pull request | Full suite including stress tests and coverage report |
| Nightly | Fuzz targets (30-minute runs), extended stress |
| Release tag | Full suite + benchmark comparison against previous release |

---

## 8 Test Environment

| Environment | Architecture | OS / Target | Purpose |
|-------------|-------------|-------------|---------|
| CI primary | `x86_64-unknown-linux-gnu` | Ubuntu 22.04 | Unit, integration, system tests |
| CI cross-compile | `thumbv7em-none-eabihf` | Bare-metal Cortex-M4 | `no_std` build validation |
| CI cross-compile | `aarch64-unknown-linux-gnu` | Linux / QEMU | ARM64 functional tests |
| Local dev | `x86_64-pc-windows-msvc` | Windows 11 | Developer testing |
| HILS (planned) | `thumbv7em-none-eabihf` | Physical ECU | WCET measurement, vCAN |
| vCAN | `x86_64-unknown-linux-gnu` | Linux `vcan0` | CAN bus integration testing |

---

## 9 Coverage Metrics

| Category | Test Count | Crates / Files Covered |
|----------|------------|------------------------|
| Unit tests | 1,248 | 21 crates |
| Integration tests | 341 | 24 test files |
| **Total** | **1,589** | -- |

### Per-Crate Unit Test Breakdown

| Crate | Tests | | Crate | Tests |
|-------|-------|-|-------|-------|
| `eth-monitor` | 129 | | `policy-engine` | 79 |
| `ota-validator` | 99 | | `key-manager` | 64 |
| `can-monitor` | 92 | | `netfw` | 61 |
| `types` | 61 | | `integrity` | 56 |
| `storage` | 52 | | `ids-engine` | 48 |
| `secure-boot` | 47 | | `hal` | 46 |
| `anomaly` | 42 | | `event-logger` | 37 |
| `runtime` | 33 | | `ffi` | 28 |
| `hal-linux` | 27 | | `crypto` | 13 |

> **Note:** Additional automotive-specific crates (signal-ids, diag-gateway, v2x, autosar) and their tests are in the [`auto/`](../../auto/) directory.

---

## 10 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-21 | Craton Shield Team | Initial test plan for v0.6.0 release |
