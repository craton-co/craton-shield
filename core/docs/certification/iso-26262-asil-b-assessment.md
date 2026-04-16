# ISO 26262 ASIL-B Pre-Assessment

> Craton Shield 0.7.0 | Date: 2026-03-13

## Scope

ISO 26262 "Road vehicles — Functional safety" defines safety lifecycle processes for automotive E/E systems. Craton Shield targets **ASIL-B** classification as a QM+ cybersecurity component that monitors but does not directly control vehicle dynamics. The Ferrocene qualified Rust toolchain covers ISO 26262 alongside IEC 61508 and DO-178C DAL, enabling the same compiler qualification evidence to support multi-domain certification (industrial via IEC 61508 SIL 2, medical via IEC 62304, avionics via DO-178C DAL C).

**Rationale for ASIL-B**: Craton Shield is a monitoring/protection layer. It does not actuate brakes, steering, or throttle. Failure modes are limited to missed detections (fail-safe: vehicle continues operating) or false positives (fail-safe: conservative deny). ASIL-B covers components where malfunction can contribute to injury severity S2 (severe) with controllability C2 (normally controllable).

## Part 6 — Software Development

### Table 1: Methods for Software Development (ASIL-B Requirements)

| Topic | ISO 26262 Method | Craton Shield Status | Evidence |
|-------|-----------------|---------------------|----------|
| **6.4.2** Design principles | Semi-formal notation | PARTIAL | Rust type system as semi-formal spec; need architecture diagrams |
| **6.4.3** Modular design | Hierarchical modules | PRESENT | 18 crates, 4-layer architecture, clear dependency DAG |
| **6.4.4** Design verification | Static analysis | PRESENT | `clippy::pedantic` + `deny(unsafe_code)` on all non-FFI crates |
| **6.4.5** Code review | Formal code review | PARTIAL | PR template requires review; no records yet (no git repo) |
| **6.4.6** Programming language subset | Safe subset | PRESENT | Rust safe subset; `unsafe` only at FFI, HAL, and storage layers (37 items in production code: 6 in vs-ffi, 29 in vs-hal-linux, 2 in vs-storage) |
| **6.4.7** Naming conventions | Enforced | PRESENT | `cargo fmt`, `clippy::pedantic`, Rust naming conventions |
| **6.4.8** Type safety | Strongly typed | PRESENT | Rust's type system + `#[repr(C)]` for FFI |

### Table 5: Methods for Software Unit Testing (ASIL-B)

| Method | Required Level | Craton Shield Status | Evidence |
|--------|---------------|---------------------|----------|
| Requirements-based testing | Recommended | PRESENT | 1,085+ unit tests covering positive + negative paths |
| Interface testing | Recommended | PRESENT | CryptoProvider trait tests across all consumers |
| Fault injection testing | Recommended | PARTIAL | Error-path tests present; no systematic fault injection |
| Resource usage testing | Recommended | PRESENT | WCET harness, criterion benchmarks, binary size tracking |
| Back-to-back testing | — | N/A | No model-based design |

### Table 7: Methods for Software Integration Testing (ASIL-B)

| Method | Required Level | Craton Shield Status | Evidence |
|--------|---------------|---------------------|----------|
| Requirements-based testing | Highly Recommended | PRESENT | 335+ integration tests (full_stack, attack_scenarios, etc.) |
| Interface testing | Highly Recommended | PRESENT | Cross-crate integration tests, FFI roundtrip tests |
| Fault injection | Recommended | PRESENT | `ota_attack.rs`: signature tampering, expired metadata, replay |

### Table 9: Methods for Verification of Software Safety Requirements (ASIL-B)

| Method | Required Level | Craton Shield Status |
|--------|---------------|---------------------|
| Walk-through | Recommended | GAP — need documented review sessions |
| Inspection | Recommended | GAP — need formal inspection records |
| Semi-formal verification | Recommended | PARTIAL — Rust type system provides static guarantees |
| Static analysis | Highly Recommended | PRESENT — clippy pedantic + deny(unsafe_code) |
| Unit testing | Highly Recommended | PRESENT — 1,085+ unit tests |
| Integration testing | Highly Recommended | PRESENT — 335+ integration tests |

## Software Safety Analysis

### Failure Mode and Effects Analysis (FMEA)

| Component | Failure Mode | Effect | Severity | Detection | Mitigation |
|-----------|-------------|--------|----------|-----------|------------|
| vs-can-monitor | Missed flood detection | Attacker CAN injection undetected | S2 | Configurable thresholds, multi-detector | IDS correlation in vs-ids-engine |
| vs-crypto | Key compromise | Unauthorized OTA update | S3 | Zeroization, HSM delegation | Hardware key storage (HSM) |
| vs-crypto | RNG failure | Predictable keys/nonces | S3 | RNG output validation (S1 fix) | Hardware RNG via HSM |
| vs-ota-validator | Signature bypass | Malicious firmware installed | S3 | Threshold signatures, TUF delegation | Boot attestation fallback |
| vs-netfw | Rule bypass | Unauthorized network access | S2 | Default-deny policy | Defense in depth (IDS + firewall) |
| vs-secure-boot | Boot verification failure | Tampered firmware executes | S3 | PCR measurements, policy enforcement | Halt or rollback on failure |
| vs-integrity | Hash collision | Tampered region undetected | S1 | SHA-256 (collision resistant) | Periodic re-measurement |
| vs-event-logger | Log tampering | Forensic evidence destroyed | S1 | HMAC chain verification | Detect chain break |

### Dependent Failure Analysis (DFA)

| Common Cause | Affected Components | Independence Measure |
|-------------|--------------------|--------------------|
| Crypto provider failure | vs-crypto consumers (OTA, boot, integrity) | Separate verification paths; boot can halt |
| Memory corruption | All crates | Rust ownership prevents; no heap; stack-only |
| Clock failure | Timer-dependent crates | Timeout defaults to deny; watchdog monitors |
| CAN bus failure | vs-can-monitor, vs-ids-engine | Bus-off detection; Ethernet path independent |

## Software Metrics

| Metric | Value | ASIL-B Target |
|--------|-------|---------------|
| Unit test count | 1,085+ | N/A (coverage more relevant) |
| Integration test count | 335+ | N/A |
| Fuzz targets | 4 | N/A |
| Unsafe blocks | 37 (production: 6 in vs-ffi, 29 in vs-hal-linux, 2 in vs-storage) | Minimize (FFI, HAL, and storage layers only) |
| Clippy warnings | 0 (pedantic mode) | 0 |
| Known vulnerabilities | 0 (cargo audit) | 0 |
| Binary size (release) | 254 KB | N/A |
| CAN frame latency | ~265 ns (x86_64) | < 1 ms |
| Firewall worst case | ~166 ns (worst case, 128-rule last-match) | < 10 ms |

## Gap Summary

| ISO 26262 Requirement | Status | Gap Description | Effort |
|----------------------|--------|-----------------|--------|
| Software architecture description | PARTIAL | Need formal diagrams (SysML/UML) | 1 week |
| Software safety requirements spec | COMPLETE | Traced in `docs/requirements-traceability-matrix.md` | Done |
| Code review records | GAP | Need documented review sessions | Ongoing |
| Formal inspection records | GAP | Need structured inspection evidence | 1 week |
| Fault injection test plan | PARTIAL | Extend beyond OTA attack scenarios | 2 weeks |
| Software qualification report | GAP | Required for tool qualification | 1 week |
| Dependent failure analysis (formal) | GAP | Need formal DFA report | 1 week |
| Safety manual | COMPLETE | See `docs/safety-manual.md` | Done |

**Total estimated effort: 6-8 weeks (1 engineer) for ASIL-B pre-assessment completion**

## Recommendation

Craton Shield's technical implementation is well-suited for ASIL-B. The Rust language provides compile-time guarantees that satisfy many ISO 26262 Part 6 requirements by construction (memory safety, type safety, data race freedom). Primary gaps are in process documentation, not technical controls.

Recommended sequence:
1. Generate architecture diagrams (SysML or equivalent)
2. Establish code review records (git history will provide once repo is initialized)
3. Extend fault injection to all safety-relevant crates

> **Note**: Automotive-specific crates (signal-ids, diag-gateway, v2x, autosar, hal-qnx, vsoc-telemetry) are available in the [auto/](../../../auto/) repository.
