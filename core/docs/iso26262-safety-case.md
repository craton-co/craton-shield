# Craton Shield — ISO 26262 ASIL-B Safety Case

**Version**: 1.2.0 | **Date**: 2026-03-13 | **Classification**: ASIL-B (QM decomposition where applicable)

---

## 1 Executive Summary

Craton Shield is a `#![no_std]` automotive intrusion detection and prevention platform designed as a **Safety Element out of Context (SEooC)** per ISO 26262-10. This safety case covers the security-relevant functions that execute on vehicle ECUs and whose failure could propagate to safety-critical domains (powertrain, chassis, ADAS) via the CAN, Ethernet, or diagnostic interfaces.

**Scope of ASIL-B qualification:**

| Function | Subsystem Crates | ASIL |
|----------|-----------------|------|
| CAN frame anomaly detection | vs-can-monitor, vs-anomaly | ASIL-B |
| Ethernet / SOME/IP firewall | vs-eth-monitor, vs-netfw | ASIL-B |
| OTA integrity verification | vs-ota-validator, vs-crypto | ASIL-B |
| Runtime orchestration | vs-runtime | ASIL-B |
| Event logging / telemetry | vs-event-logger, vs-storage | QM |

> **Note:** Additional automotive-specific crates are available in the [auto/](../../auto/) repository.

---

## 2 Safety Concept — SEooC Assumptions

Craton Shield is integrated by an OEM into an ECU whose system-level safety concept assigns the cybersecurity monitoring function an ASIL rating. The following **assumptions of use** apply:

1. **A-01**: The integrator provides a monotonic time source with ≤1 ms jitter to `Craton Shield::tick()`.
2. **A-02**: The integrator invokes `tick()` at the configured period (default 10 ms) without unbounded delay.
3. **A-03**: CAN frames are delivered to Craton Shield in reception order with no silent drops.
4. **A-04**: The hardware watchdog is configured externally; Craton Shield reports health via `PlatformHealth`.
5. **A-05**: Cryptographic key material is provisioned before `init()` returns and is protected by an HSM or TEE.
6. **A-06**: The stack memory budget advertised in `PlatformHealth::peak_stack_bytes` is allocated by the integrator.
7. **A-07**: The integrator routes `SecurityAlert` events to a downstream VSOC or DTC handler within the vehicle's fault management strategy.

---

## 3 Hazard Analysis and Risk Assessment (HARA)

Per ISO 26262-3 Clause 7, the following hazardous events are identified:

| ID | Hazardous Event | S | E | C | ASIL |
|----|----------------|---|---|---|------|
| HE-01 | Malicious CAN injection to braking ECU undetected → unintended deceleration | S3 | E4 | C3 | D |
| HE-02 | Firewall bypass allows unauthorized SOME/IP service control → actuator command injection | S3 | E3 | C3 | C |
| HE-03 | Diagnostic session hijack enables ECU reflash → loss of safety function | S3 | E2 | C3 | B |
| HE-04 | OTA update with tampered firmware installed → arbitrary code execution | S3 | E2 | C3 | B |
| HE-05 | V2X spoofed BSM accepted as genuine → incorrect collision avoidance | S3 | E3 | C2 | B |
| HE-06 | False-positive CAN alert suppresses legitimate braking command | S3 | E3 | C2 | B |
| HE-07 | Runtime crash (panic/stack overflow) disables all security monitoring | S2 | E4 | C3 | C |
| HE-08 | Crypto key compromise enables authenticated attacker access | S3 | E1 | C3 | A |

### Safety Goals

| SG | Derived From | Description | ASIL |
|----|-------------|-------------|------|
| SG-01 | HE-01, HE-06 | Detect malicious CAN frames within 50 µs WCET | B |
| SG-02 | HE-02 | Enforce network firewall default-deny policy | B |
| SG-03 | HE-08 | Protect cryptographic key material with zeroization | B |
| SG-04 | HE-04 | Validate OTA update signatures before installation | B |
| SG-05 | HE-03, HE-08 | Maintain tamper-evident audit trail | B |
| SG-06 | HE-04 | Detect boot chain integrity violations | B |
| SG-07 | HE-07 | Runtime shall remain operational under all input conditions (no panic) | B |

---

## 4 FMEA — Software Component Failure Modes

### 4.1 CAN Monitor (`vs-can-monitor`, `vs-anomaly`)

| Failure Mode | Effect | Severity | Detection | Mitigation |
|-------------|--------|----------|-----------|------------|
| FM-CAN-01: Missed detection (threshold too high) | Malicious frame reaches target ECU | High | Integration test with known-attack dataset | Configurable thresholds, dual-detector ensemble |
| FM-CAN-02: False positive (threshold too low) | Legitimate frame blocked | High | Statistical validation in CI | EWMA warm-up period, z-score calibration |
| FM-CAN-03: Frame counter overflow | Incorrect frequency calculation | Medium | Compile-time overflow checks (`wrapping_add`) | Explicit wrapping arithmetic, tick reset |
| FM-CAN-04: Signal extraction out-of-bounds read | Undefined behavior | Critical | `#![deny(unsafe_code)]`, bounds checks | All bit extraction uses checked indexing |

### 4.2 Ethernet Firewall (`vs-eth-monitor`, `vs-netfw`)

| Failure Mode | Effect | Severity | Detection | Mitigation |
|-------------|--------|----------|-----------|------------|
| FM-ETH-01: Rule table corruption | Firewall bypass | Critical | CRC32 integrity check on rule table | `check_integrity()` on every `tick()` |
| FM-ETH-02: Default-deny not enforced | Unconfigured traffic passes | High | Test: empty rule table rejects all | `DefaultPolicy::Deny` is compile-time default |
| FM-ETH-03: SOME/IP-SD flood not detected | DoS on service discovery | Medium | Rate threshold test | `SD_FLOOD_THRESHOLD` constant, per-tick counter |

### 4.3 Cryptographic Provider (`vs-crypto`)

| Failure Mode | Effect | Severity | Detection | Mitigation |
|-------------|--------|----------|-----------|------------|
| FM-CRY-01: Key material leak via memory | Key compromise | Critical | Zeroize-on-drop test | `zeroize` crate, `Drop` impl on `KeyEntry` |
| FM-CRY-02: ECDSA verification accepts invalid signature | Authentication bypass | Critical | Known-answer tests (KAT) | RustCrypto p256 crate (audited) |
| FM-CRY-03: AES-GCM authentication tag not checked | Ciphertext tampering undetected | Critical | Modified-ciphertext test | `aes-gcm` crate AEAD API enforces tag check |
| FM-CRY-04: RNG returns predictable output (e.g., all zeros) | Predictable keys/nonces | Critical | RNG output validation test | `default_rng()` rejects zero-entropy output (S1 fix) |
| FM-CRY-05: Timing side-channel in comparison | Key/signature leak via timing | High | Constant-time verification test | `subtle::ConstantTimeEq` (S9 fix) |

### 4.4 Runtime (`vs-runtime`)

| Failure Mode | Effect | Severity | Detection | Mitigation |
|-------------|--------|----------|-----------|------------|
| FM-RT-01: Init failure not reported | Subsystem silently disabled | High | `PlatformHealth` test for `NotInitialized` states | All 18 subsystem statuses checked |
| FM-RT-02: Tick exceeds WCET budget | Watchdog timeout | High | WCET measurement on target | Bounded-loop design, no heap allocation |
| FM-RT-03: Stack overflow | Undefined behavior | Critical | Stack watermark analysis | Fixed-size arrays, no recursion |

---

## 5 Software Safety Requirements (SSR)

| ID | Requirement | ASIL | Traces To | Verified By |
|----|------------|------|-----------|-------------|
| SSR-01 | CAN frame processing shall complete within 50 µs WCET | B | SG-01, SG-07 | WCET analysis on target |
| SSR-02 | CAN allowlist shall reject unknown arbitration IDs | B | SG-01 | `test_allowlist_rejects_unknown_id` |
| SSR-03 | Ethernet firewall shall enforce default-deny policy | B | SG-02 | `test_empty_rules_reject_all` |
| SSR-04 | OTA signature verification shall support ECDSA P-256 | B | SG-04 | `test_ota_signature_verification` |
| SSR-05 | Cryptographic operations shall use SoftwareCryptoProvider or HSM | B | SG-03 | `test_crypto_provider_operations` |
| SSR-06 | Key material shall be zeroized on drop | B | SG-03 | `test_key_zeroize_on_drop` |
| SSR-07 | Event log shall maintain HMAC chain integrity | B | SG-05 | `test_event_log_hmac_chain` |
| SSR-08 | Anomaly detection shall use EWMA and entropy methods | B | SG-01 | `test_anomaly_detection_ewma_entropy` |
| SSR-09 | Secure boot shall verify firmware hash chain | B | SG-06 | `test_secure_boot_hash_chain` |
| SSR-10 | Runtime integrity shall detect memory corruption | B | SG-06 | `test_runtime_integrity_corruption` |
| SSR-11 | Policy engine shall evaluate without allocation | B | SG-07 | `test_policy_engine_no_alloc` |
| SSR-12 | IDS engine shall coordinate all monitors | B | SG-01, SG-02 | `test_ids_engine_coordination` |
| SSR-13 | Security alerts shall include monotonic timestamps | B | SG-05 | `test_alert_monotonic_timestamps` |
| SSR-14 | Rate limiting shall prevent log flooding | B | SG-05 | `test_rate_limiting` |
| SSR-15 | OTA rollback protection shall use monotonic counter | B | SG-04 | `test_ota_rollback_protection` |
| SSR-16 | FFI shall catch panics and return error codes | B | SG-07 | `test_ffi_panic_catch` |

---

## 6 ASIL Decomposition

Per ISO 26262-9 Clause 5, the following decomposition is applied:

| Component | ASIL | Rationale |
|-----------|------|-----------|
| vs-runtime | ASIL-B | Orchestrates all safety-relevant subsystems |
| vs-can-monitor | ASIL-B | Directly protects CAN bus safety functions |
| vs-anomaly | ASIL-B | Core detection algorithm for CAN IDS |
| vs-eth-monitor | ASIL-B | Ethernet/SOME/IP firewall enforcement |
| vs-netfw | ASIL-B | Network firewall rule engine |
| vs-crypto | ASIL-B | Authentication for OTA and key operations |
| vs-ota-validator | ASIL-B | OTA integrity verification |
| vs-key-manager | ASIL-B | Key storage, rotation, and zeroization |
| vs-secure-boot | ASIL-B | Boot chain integrity verification |
| vs-integrity | ASIL-B | Runtime memory integrity checks |
| vs-ids-engine | ASIL-B | Central IDS coordination |
| vs-policy-engine | ASIL-B | Rule-based policy evaluation |
| vs-types | ASIL-B | Shared types used by all ASIL components |
| vs-hal / vs-hal-linux | QM | Hardware abstraction layer |
| vs-event-logger | QM | Logging/telemetry, no safety function |
| vs-storage | QM | Persistent storage, no safety function |
| vs-ffi | QM | Foreign function interface layer |
| vs-report-iec62443 | QM | IEC 62443 compliance report generation |
| vs-report-iso21434 | QM | ISO/SAE 21434 TARA report generation |
| vs-report-iec62304 | QM | IEC 62304 traceability matrix generation |

> **Note:** The workspace contains 21 crates in total (17 listed above plus the 3 report crates and vs-hal-linux). Additional automotive-specific crates (signal-ids, diag-gateway, v2x, autosar) are available in the [auto/](../../auto/) repository.

### 6.1 SG-06 ASIL Retention and Independence Argument

Safety Goal SG-06 ("Detect boot chain integrity violations") is retained at ASIL-B without further decomposition. Per ISO 26262-9 Clause 5.4.3, ASIL decomposition may be omitted when an independent safety mechanism provides sufficient diagnostic coverage for the safety goal.

In the Craton Shield integration architecture, the external hardware watchdog (configured by the integrator per assumption A-04) serves as an independent safety mechanism that is:

1. **Independent of Craton Shield software** — the watchdog runs on dedicated hardware outside the monitored ECU's application core, with its own clock domain and power supply.
2. **Capable of detecting SG-06 failures** — if the secure boot verification in `vs-secure-boot` fails or hangs (i.e., `verify_chain()` does not complete within the configured watchdog timeout), the watchdog triggers a reset, preventing execution of unverified firmware.
3. **Not subject to common-cause failure** — the watchdog is not implemented in Rust, does not share memory with Craton Shield, and is not affected by software faults in the boot chain verification logic.

Because the external hardware watchdog provides an independent detection path for boot chain integrity failures, the conditions of ISO 26262-9 Clause 5.4.3 are satisfied, and SG-06 is retained at ASIL-B for the `vs-secure-boot` and `vs-integrity` crates without decomposition to lower ASIL sub-elements.

> **Integrator obligation:** The integrator shall configure the hardware watchdog timeout to be no greater than the secure boot WCET budget documented in Section 9.4, ensuring that a stalled or failed boot verification is detected before control is passed to application software.

---

## 7 Traceability Matrix

| SSR | Test Case(s) | Source Location |
|-----|-------------|----------------|
| SSR-01 | WCET measurement (target) | `crates/can-monitor/src/lib.rs` — `process_frame()` |
| SSR-02 | `allowlist_rejects_unknown_id` | `crates/can-monitor/src/lib.rs` — `check_allowlist()` |
| SSR-03 | `empty_rule_table_rejects` | `crates/netfw/src/lib.rs` — `evaluate()` |
| SSR-04 | `ota_signature_verification` | `crates/ota-validator/src/lib.rs` — `verify_signature()` |
| SSR-05 | `crypto_provider_operations` | `crates/crypto/src/software.rs` — `SoftwareCryptoProvider` |
| SSR-06 | `key_zeroize_on_drop` | `crates/key-manager/src/lib.rs` — `Drop for KeyEntry` |
| SSR-07 | `event_log_hmac_chain` | `crates/event-logger/src/lib.rs` — `append()` |
| SSR-08 | `anomaly_detection_ewma_entropy` | `crates/anomaly/src/lib.rs` — `detect()` |
| SSR-09 | `secure_boot_hash_chain` | `crates/secure-boot/src/lib.rs` — `verify_chain()` |
| SSR-10 | `runtime_integrity_corruption` | `crates/integrity/src/lib.rs` — `verify_region()` |
| SSR-11 | `policy_engine_no_alloc` | `crates/policy-engine/src/lib.rs` — `evaluate()` |
| SSR-12 | `ids_engine_coordination` | `crates/ids-engine/src/lib.rs` — `coordinate()` |
| SSR-13 | `alert_monotonic_timestamps` | `crates/types/src/lib.rs` — `SecurityAlert` |
| SSR-14 | `rate_limiting` | `crates/event-logger/src/lib.rs` — `rate_limit()` |
| SSR-15 | `ota_rollback_protection` | `crates/ota-validator/src/lib.rs` — `check_rollback()` |
| SSR-16 | `ffi_panic_catch` | `crates/ffi/src/lib.rs` — `catch_unwind()` |

---

## 8 Tool Qualification (ISO 26262-8 Clause 11)

| Tool | Version | TCL | Qualification Method |
|------|---------|-----|---------------------|
| Rust compiler (`rustc`) | 1.82+ | TCL2 | Validation suite (Rust test suite), community audit |

> **Note on compiler qualification:** The community `rustc` compiler is not
> formally qualified under ISO 26262. For series-production ASIL-B deployment,
> integrators should use the [Ferrocene](https://ferrocene.dev/) qualified Rust
> compiler, which provides ISO 26262 TCL2 and IEC 61508 T3 qualification
> evidence. Craton Shield is compatible with Ferrocene; no source changes are
> required.
| Clippy | Latest | TCL1 | Static analysis tool, advisory only |
| cargo-llvm-cov | 0.6+ | TCL1 | Coverage measurement, no code generation |
| cargo-audit | Latest | TCL1 | Dependency vulnerability scanner |
| GitHub Actions CI | N/A | TCL1 | Build automation, no code transformation |

**TI 1 (Tool Impact)**: Tools generate or transform code → TCL2 (rustc only)
**TD 1 (Tool Detection)**: Output verified by test suite → high confidence

---

## 9 Verification and Validation Plan

### 9.1 Unit Tests
- **Coverage target**: ≥80% line coverage (measured by `cargo-llvm-cov`)
- **Current**: 1,589 tests (1,248 unit + 341 integration) across 21 crates, zero clippy warnings
- **Framework**: `#[cfg(test)]` in-crate tests, `tests/` integration tests

### 9.2 Integration Tests
- Full-stack tests in `tests/full_stack.rs` exercising runtime init → tick → alert flow
- OTA attack simulation in `tests/ota_attack.rs`
- 25 integration test files with 341 tests total (see test plan for full breakdown)

> **Note:** Diagnostic session tests are maintained in the [auto/](../../auto/) repository.

### 9.3 Static Analysis
- `cargo clippy --workspace --all-targets -- -D warnings` (zero warnings enforced)
- `#![deny(unsafe_code)]` on all crates except `vs-ffi`, `vs-hal-linux`, and `vs-storage`, which require unsafe for C-ABI, libc FFI, and memory-locking respectively and use `#![allow(unsafe_code)]` with per-block safety comments — 37 `unsafe` items in production code (6 in `vs-ffi`, 29 in `vs-hal-linux`, 2 in `vs-storage`)
- `#![no_std]` verified via `--target thumbv7em-none-eabihf` cross-compilation

### 9.4 WCET Analysis
- To be measured on target hardware (Cortex-M4 @ 150 MHz or Cortex-A53 @ 1.2 GHz)
- Budget: `tick()` ≤ 1 ms, `process_frame()` ≤ 50 µs, `inspect_packet()` ≤ 100 µs

### 9.5 Penetration Testing
- Third-party pentest before series production release
- Scope: CAN injection, SOME/IP fuzzing, OTA MITM, secure boot bypass, key extraction
- Acceptance: no critical or high findings

### 9.6 Formal Review
- Architecture review per ISO 26262-6 Table 1 (ASIL-B methods)
- Code review: all changes reviewed before merge (enforced by CI branch protection)

---

## 10 Configuration Management

- **Version control**: Git with signed commits
- **Branch protection**: `main` requires CI pass + code review
- **Release tagging**: Semantic versioning (e.g., `v1.1.0`)
- **SBOM**: Generated via `cargo-cyclonedx` for each release
- **Artifact hashes**: SHA-256 of release binaries stored in release notes

---

## Appendix A — Glossary

| Term | Definition |
|------|-----------|
| SEooC | Safety Element out of Context (ISO 26262-10) |
| ASIL | Automotive Safety Integrity Level (A–D) |
| HARA | Hazard Analysis and Risk Assessment |
| FMEA | Failure Mode and Effects Analysis |
| SSR | Software Safety Requirement |
| WCET | Worst-Case Execution Time |
| TCL | Tool Confidence Level |
| PSID | Provider Service Identifier (IEEE 1609.2) |
| SPDU | Secured Protocol Data Unit (IEEE 1609.2) |
| BSM | Basic Safety Message (SAE J2735) |
