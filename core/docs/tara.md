# Threat Analysis and Risk Assessment (TARA)

> Per ISO/SAE 21434 Annex E
> Craton Shield v0.6.0 — Phase 6

---

## 1. Item Definition

**Item**: Craton Shield embedded security runtime platform
**Scope**: CAN bus monitoring, Automotive Ethernet inspection, UDS diagnostic gateway, OTA update validation, network firewall, cryptographic key management, tamper-evident logging, VSOC telemetry uplink. The universal security core (secure boot, key management, OTA, crypto, firewall, integrity, logging) is applicable to industrial, medical, energy, and defense domains; this TARA addresses the automotive deployment context.
**Boundary**: The Craton Shield binary runs on a central gateway ECU (automotive) or equivalent embedded controller. It processes frames/packets received via HAL traits (`CanBus`, `EthernetPhy`) and exposes a C FFI for integration. It does not control actuators directly.
**Target hardware**: NXP S32G3 (Cortex-A53), Infineon AURIX TC3xx (planned), any Cortex-M3+ with 256 KB+ flash
**Operating context**: Series-production passenger vehicles (UN R155 regulated markets). Future: industrial OT (IEC 62443), medical devices (IEC 62304 / FDA), smart grid (NERC CIP / NIS2), defense/avionics (DO-178C)

---

## 2. Asset Identification

| Asset ID | Asset | Confidentiality | Integrity | Availability |
|:---------|:------|:---------------:|:---------:|:------------:|
| A1 | Cryptographic key material (AES-256, ECDSA P-256, HMAC-SHA256) | Critical | Critical | High |
| A2 | Firmware images (OTA payloads) | Medium | Critical | High |
| A3 | CAN bus message integrity | Low | Critical | Critical |
| A4 | Diagnostic session credentials | Critical | Critical | Medium |
| A5 | Tamper-evident audit log (HMAC-chained) | Medium | Critical | High |
| A6 | VSOC telemetry channel | Medium | High | Medium |
| A7 | Boot chain measurements (PCR values) | Low | Critical | High |
| A8 | Monotonic rollback counter | Low | Critical | Critical |
| A9 | Firewall/policy rule sets | Low | Critical | High |
| A10 | Platform health state | Low | High | High |

---

## 3. Threat Scenarios

### 3.1 CAN Bus Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-CAN-01 | CAN arbitration ID spoofing — attacker injects frames with legitimate IDs | Spoofing | A3 |
| T-CAN-02 | CAN bus flooding — high-rate frame injection to cause DoS | Denial of Service | A3 |
| T-CAN-03 | CAN DLC manipulation — invalid data length codes to trigger parser faults | Tampering | A3 |
| T-CAN-04 | CAN payload replay — re-transmission of captured legitimate frames | Spoofing | A3 |
| T-CAN-05 | CAN fuzzing — random payloads to discover parsing vulnerabilities | Tampering | A3 |

### 3.2 Ethernet Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-ETH-01 | ARP spoofing — redirect Ethernet traffic via forged ARP | Spoofing | A3 |
| T-ETH-02 | VLAN hopping — escape network segmentation | Elevation of Privilege | A3, A9 |
| T-ETH-03 | SOME/IP message injection — unauthorized service calls | Spoofing | A3 |
| T-ETH-04 | IPv6 extension header chain abuse — evasion of L3 inspection | Tampering | A9 |
| T-ETH-05 | TCP state manipulation — RST injection, SYN flood | Denial of Service | A3 |

### 3.3 Diagnostic Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-DIAG-01 | UDS SecurityAccess brute-force — guess HMAC key via repeated attempts | Spoofing | A4 |
| T-DIAG-02 | Unauthorized programming session — flash malicious firmware via UDS 0x34/0x36 | Elevation of Privilege | A2 |
| T-DIAG-03 | Diagnostic session hijacking — reuse expired session tokens | Spoofing | A4 |
| T-DIAG-04 | Audit log evasion — perform unauthorized actions without logging | Repudiation | A5 |

### 3.4 OTA / Firmware Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-OTA-01 | Firmware downgrade — flash older vulnerable version | Tampering | A2, A8 |
| T-OTA-02 | Unsigned firmware injection — bypass signature verification | Tampering | A2 |
| T-OTA-03 | TUF metadata rollback — replay old metadata with valid signatures | Spoofing | A2, A8 |
| T-OTA-04 | Threshold bypass — compromise fewer keys than threshold requires | Elevation of Privilege | A1, A2 |

### 3.5 Cryptographic / Key Management Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-KEY-01 | Key material extraction — read key bytes from memory dump | Information Disclosure | A1 |
| T-KEY-02 | Side-channel attack — timing analysis on HMAC/ECDSA operations | Information Disclosure | A1 |
| T-KEY-03 | HMAC key compromise — forge event log entries | Tampering | A1, A5 |
| T-KEY-04 | Nonce reuse in AES-GCM — break ciphertext confidentiality | Information Disclosure | A1, A6 |

### 3.6 Platform Integrity Threats

| ID | Threat | STRIDE | Target Asset |
|:---|:-------|:-------|:-------------|
| T-INT-01 | Boot chain bypass — skip secure boot verification | Elevation of Privilege | A7 |
| T-INT-02 | Memory region tampering — modify code/data regions at runtime | Tampering | A7 |
| T-INT-03 | Log tampering — alter HMAC-chained audit entries | Tampering | A5 |
| T-INT-04 | Telemetry interception — eavesdrop on VSOC uplink | Information Disclosure | A6 |

---

## 4. Impact Rating

Impact assessed on Safety (S), Financial (F), Operational (O), Privacy (P) per ISO 21434 §8.5.

| Threat ID | S | F | O | P | Overall |
|:----------|:-:|:-:|:-:|:-:|:-------:|
| T-CAN-01 | Severe | Major | Major | Negligible | **Critical** |
| T-CAN-02 | Major | Moderate | Severe | Negligible | **Critical** |
| T-CAN-03 | Moderate | Minor | Moderate | Negligible | **Major** |
| T-CAN-04 | Major | Moderate | Major | Negligible | **Major** |
| T-CAN-05 | Moderate | Minor | Moderate | Negligible | **Moderate** |
| T-ETH-01 | Moderate | Moderate | Major | Negligible | **Major** |
| T-ETH-02 | Moderate | Major | Major | Minor | **Major** |
| T-ETH-03 | Major | Moderate | Major | Negligible | **Major** |
| T-ETH-04 | Moderate | Minor | Moderate | Negligible | **Moderate** |
| T-ETH-05 | Moderate | Minor | Major | Negligible | **Moderate** |
| T-DIAG-01 | Major | Major | Major | Moderate | **Critical** |
| T-DIAG-02 | Severe | Major | Severe | Moderate | **Critical** |
| T-DIAG-03 | Major | Moderate | Major | Minor | **Major** |
| T-DIAG-04 | Moderate | Minor | Major | Minor | **Moderate** |
| T-OTA-01 | Severe | Major | Severe | Moderate | **Critical** |
| T-OTA-02 | Severe | Major | Severe | Moderate | **Critical** |
| T-OTA-03 | Major | Major | Major | Moderate | **Major** |
| T-OTA-04 | Severe | Major | Severe | Moderate | **Critical** |
| T-KEY-01 | Major | Major | Major | Major | **Critical** |
| T-KEY-02 | Major | Major | Major | Major | **Critical** |
| T-KEY-03 | Major | Moderate | Major | Moderate | **Major** |
| T-KEY-04 | Moderate | Moderate | Moderate | Major | **Major** |
| T-INT-01 | Severe | Major | Severe | Moderate | **Critical** |
| T-INT-02 | Major | Moderate | Major | Minor | **Major** |
| T-INT-03 | Moderate | Minor | Major | Minor | **Moderate** |
| T-INT-04 | Minor | Minor | Minor | Major | **Moderate** |

---

## 5. Attack Feasibility Rating

Per ISO 21434 §8.6, using the attack potential framework:

| Factor | Scale |
|:-------|:------|
| Elapsed time | ≤1 day (0), ≤1 week (1), ≤1 month (4), ≤6 months (10), >6 months (19) |
| Specialist expertise | Layman (0), Proficient (3), Expert (6), Multiple experts (8) |
| Knowledge of item | Public (0), Restricted (3), Confidential (7), Strictly confidential (11) |
| Window of opportunity | Unlimited (0), Easy (1), Moderate (4), Difficult (10) |
| Equipment | Standard (0), Specialized (4), Bespoke (7), Multiple bespoke (9) |

| Threat ID | Time | Expertise | Knowledge | Window | Equipment | Total | Feasibility |
|:----------|:----:|:---------:|:---------:|:------:|:---------:|:-----:|:------------|
| T-CAN-01 | 0 | 3 | 3 | 0 | 4 | **10** | High |
| T-CAN-02 | 0 | 0 | 0 | 0 | 4 | **4** | High |
| T-CAN-03 | 0 | 3 | 3 | 0 | 4 | **10** | High |
| T-CAN-04 | 0 | 3 | 3 | 0 | 4 | **10** | High |
| T-CAN-05 | 0 | 0 | 0 | 0 | 4 | **4** | High |
| T-ETH-01 | 0 | 3 | 3 | 1 | 4 | **11** | High |
| T-ETH-02 | 1 | 6 | 3 | 4 | 4 | **18** | Medium |
| T-ETH-03 | 1 | 3 | 3 | 1 | 4 | **12** | High |
| T-ETH-04 | 1 | 6 | 3 | 4 | 4 | **18** | Medium |
| T-ETH-05 | 0 | 3 | 0 | 1 | 4 | **8** | High |
| T-DIAG-01 | 1 | 3 | 7 | 4 | 4 | **19** | Medium |
| T-DIAG-02 | 4 | 6 | 7 | 4 | 4 | **25** | Low |
| T-DIAG-03 | 1 | 3 | 7 | 4 | 4 | **19** | Medium |
| T-DIAG-04 | 1 | 6 | 7 | 4 | 0 | **18** | Medium |
| T-OTA-01 | 4 | 6 | 7 | 4 | 4 | **25** | Low |
| T-OTA-02 | 10 | 8 | 11 | 10 | 7 | **46** | Very Low |
| T-OTA-03 | 4 | 6 | 7 | 4 | 4 | **25** | Low |
| T-OTA-04 | 19 | 8 | 11 | 10 | 9 | **57** | Very Low |
| T-KEY-01 | 4 | 6 | 7 | 10 | 7 | **34** | Low |
| T-KEY-02 | 10 | 8 | 7 | 4 | 7 | **36** | Low |
| T-KEY-03 | 4 | 6 | 7 | 4 | 4 | **25** | Low |
| T-KEY-04 | 1 | 6 | 7 | 4 | 4 | **22** | Medium |
| T-INT-01 | 4 | 6 | 7 | 10 | 7 | **34** | Low |
| T-INT-02 | 4 | 6 | 7 | 10 | 7 | **34** | Low |
| T-INT-03 | 4 | 6 | 7 | 4 | 0 | **21** | Medium |
| T-INT-04 | 1 | 3 | 3 | 1 | 4 | **12** | High |

---

## 6. Risk Determination

Risk = Impact x Feasibility

| Risk Level | Criteria |
|:-----------|:---------|
| **1 (Negligible)** | Low impact, very low feasibility |
| **2 (Low)** | Moderate impact with low feasibility, or low impact with medium feasibility |
| **3 (Medium)** | Major impact with low feasibility, or moderate impact with high feasibility |
| **4 (High)** | Critical impact with medium feasibility, or major impact with high feasibility |
| **5 (Critical)** | Critical impact with high feasibility |

| Threat ID | Impact | Feasibility | Risk | Treatment |
|:----------|:------:|:------------|:----:|:----------|
| T-CAN-01 | Critical | High | **5** | Mitigate |
| T-CAN-02 | Critical | High | **5** | Mitigate |
| T-CAN-04 | Major | High | **4** | Mitigate |
| T-DIAG-01 | Critical | Medium | **4** | Mitigate |
| T-DIAG-02 | Critical | Low | **3** | Mitigate |
| T-OTA-01 | Critical | Low | **3** | Mitigate |
| T-OTA-02 | Critical | Very Low | **2** | Mitigate |
| T-KEY-01 | Critical | Low | **3** | Mitigate |
| T-KEY-02 | Critical | Low | **3** | Mitigate |
| T-INT-01 | Critical | Low | **3** | Mitigate |

---

## 7. Risk Treatment

### 7.1 Mitigations Implemented

| Threat | Mitigation | Subsystem | Residual Risk |
|:-------|:-----------|:----------|:-------------|
| T-CAN-01 | Arbitration ID allowlist (512 IDs) | vs-can-monitor | Attacker uses IDs in allowlist |
| T-CAN-02 | Per-ID flood detection with EWMA rate monitoring | vs-can-monitor | Slow-rate flooding below threshold |
| T-CAN-03 | DLC validation against expected ranges | vs-can-monitor | None — deterministic check |
| T-CAN-04 | FNV-1a hash replay detection (3-identical threshold, 256-ID capacity) | vs-can-monitor | Hash collision (FNV is non-cryptographic) |
| T-CAN-05 | Shannon entropy detector (threshold 3.5 bits) | vs-can-monitor | Crafted payloads with normal entropy |
| T-ETH-01 | ARP spoofing detection | vs-eth-monitor | Attacks not using ARP |
| T-ETH-04 | IPv6 extension header chain walking with safety limit | vs-eth-monitor | Fragmented evasion |
| T-ETH-05 | TCP state tracking (64 connections, 30s timeout, RST handling) | vs-eth-monitor | State table exhaustion |
| T-DIAG-01 | Brute-force lockout (3 failures → 10s lockout per tester) | vs-diag-gateway ([auto/](../../auto/)) | Distributed multi-tester attack |
| T-DIAG-02 | SID policy enforcement (default-deny, always-auth for 0x31/0x34/0x36/0x37) | vs-diag-gateway ([auto/](../../auto/)) | Policy misconfiguration |
| T-DIAG-03 | Session timeout (5s default), seed cleared after each attempt | vs-diag-gateway ([auto/](../../auto/)) | None — deterministic |
| T-DIAG-04 | 512-entry ring buffer audit log with monotonic sequence numbers | vs-diag-gateway ([auto/](../../auto/)) | Log overflow overwrites oldest entries |
| T-OTA-01 | Persistent monotonic counter via StorageProvider | vs-ota-validator | Storage corruption |
| T-OTA-02 | Threshold-of-N ECDSA P-256 signature verification with full TUF 4-role delegation chain (S5): root → timestamp → snapshot → targets | vs-ota-validator | Compromise of N keys |
| T-OTA-03 | Version monotonicity check (new > current); TUF timestamp freshness and snapshot cross-reference verification | vs-ota-validator | None — deterministic |
| T-KEY-01 | Zeroization on revoke; HSM-backed keys never leave hardware; mock-hsm provides full HMAC-SHA-256 and ECDH P-256 (S2) | vs-key-manager, vs-crypto | Cold boot attack on RAM keys |
| T-KEY-02 | Constant-time comparison via `subtle::ConstantTimeEq` (S9, replaces custom XOR accumulator) | vs-crypto | Power analysis (requires HW countermeasures) |
| T-KEY-03 | HMAC chain in event logger; key stored in HSM when available | vs-event-logger | HSM bypass |
| T-KEY-04 | Nonce management is caller responsibility; documented in API | vs-crypto | Integration error |
| T-INT-01 | PCR extension chain with `extend_pcr()`, `read_pcr()`, and PCR digest computation (S7); boot failure policy enforcement via `verify_boot_chain_with_policy()` (S8) | vs-secure-boot | Physical attack on boot ROM |
| T-INT-02 | Periodic SHA-256 integrity checks on registered memory regions | vs-integrity | Check interval gap |
| T-INT-03 | HMAC chain provides ordering and tamper evidence | vs-event-logger | Key compromise |
| T-INT-04 | AES-GCM encryption of telemetry uplink | vs-vsoc-telemetry (in [auto/](../../auto/)) | Key compromise |

### 7.2 Accepted Risks

| Risk | Justification |
|:-----|:-------------|
| FNV hash collision in CAN replay detection | FNV-1a is chosen for performance (sub-microsecond). Cryptographic hash would exceed CAN gateway latency budget. Collision probability at 32-bit is acceptable for detection (not prevention). |
| AES-GCM nonce uniqueness not enforced | Enforcement requires either a hardware counter or caller discipline. Documented as integration requirement in Safety Manual. HSM mock provides full ECDH P-256; production HSM will supply hardware nonce counters. |
| Audit log overwrites oldest entries on overflow | Ring buffer design is intentional for bounded memory. Overflow counter is tracked and surfaced in PlatformHealth. Critical events are prioritized via severity-based shedding in telemetry uplink. |

### 7.3 Mitigations Completed Since Initial TARA (Phases 2-5)

| Risk | Mitigation Implemented | Phase | Reference |
|:-----|:----------------------|:------|:----------|
| Default RNG returns all zeros | `default_rng()` now rejects zero-entropy output; validates RNG produces non-zero bytes | Phase 2 | S1 |
| HSM provider returns `NotInitialized` | Mock-HSM provides full HMAC-SHA-256 and ECDH P-256 operations | Phase 3 | S2 |
| Post-quantum crypto non-functional | ML-KEM-768 encapsulate/decapsulate and ML-DSA-65 sign/verify fully operational via `pq-software` feature | Phase 3 | S3 |
| Key material silently discarded on import | `import_key()` now stores key material correctly in KeyStore | Phase 3 | S4 |
| TUF single-role only (root) | Full 4-role delegation: timestamp → snapshot → targets with cross-reference verification | Phase 4 | S5 |
| JSON parser returns zero content hash | `parse_tuf_root_with_hash()` computes SHA-256 of signed metadata portion | Phase 4 | S6 |
| TPM attestation incomplete | `extend_pcr()`, `read_pcr()`, and PCR digest computation implemented | Phase 4 | S7 |
| No boot failure policy enforcement | `verify_boot_chain_with_policy()` with `Halt`, `Rollback`, `ReportAndContinue` | Phase 4 | S8 |
| Custom constant-time comparison (potential timing leak) | Replaced with `subtle::ConstantTimeEq` from audited crate | Phase 4 | S9 |
| QNX HAL panics with `todo!()` | Proper FFI bindings (`clock_gettime`, `ClockCycles`) with error returns | Phase 5 | S10 |

### 7.4 Planned Mitigations (Future Phases)

| Risk | Planned Mitigation | Phase |
|:-----|:-------------------|:------|
| Software key extraction on production hardware | Production HSM integration (NXP HSE) — keys never leave hardware | Phase 7+ |
| Power analysis side-channel | HSM hardware countermeasures | Phase 7+ |
| No SecOC for CAN freshness | AUTOSAR SecOC integration with MAC-based freshness values | Phase 7+ |
| Physical boot ROM attack | Hardware root of trust via HSM OTP fuses | Phase 7+ |

---

## 8. Compliance Mapping

| ISO 21434 Clause | Requirement | TARA Coverage |
|:-----------------|:-----------|:-------------|
| §7.4.1 | Asset identification | Section 2 |
| §7.4.2 | Threat scenario identification | Section 3 |
| §8.3 | Impact rating | Section 4 |
| §8.5 | Attack feasibility rating | Section 5 |
| §8.6 | Risk determination | Section 6 |
| §8.7 | Risk treatment decision | Section 7 |

---

## Revision History

| Version | Date | Changes |
|:--------|:-----|:--------|
| 1.0 | March 2026 | Initial TARA for v0.5.0 Phase 2 release |
| 2.0 | March 2026 | Updated for v0.6.0 Phase 6: added Section 7.3 (completed mitigations S1-S10), updated mitigations in 7.1 (TUF delegation, constant-time, TPM PCR, HSM), renumbered planned mitigations to 7.4 |
