# Threat Model

**Version**: 1.0.0 | **Date**: 2026-03-28 | **Methodology**: STRIDE | **Classification**: Confidential

---

## 1. Document Purpose

This threat model provides a broad security analysis of the Craton Shield embedded security runtime. It complements the ISO/SAE 21434 TARA (`docs/tara.md`) with a methodology-neutral, implementation-grounded perspective. Where the TARA focuses on automotive risk ratings and compliance, this document maps threats directly to crate-level mitigations and identifies residual risks and assumptions.

---

## 2. System Overview

Craton Shield is a `#![no_std]`, zero-heap embedded security runtime implemented in Rust. It runs on a central gateway ECU (NXP S32G3 Cortex-A53 or equivalent Cortex-M3+ with 256 KB+ flash) and provides:

- **CAN bus intrusion detection** -- rate monitoring, ID allowlisting, replay detection, entropy analysis (`vs-can-monitor`, `vs-anomaly`)
- **Automotive Ethernet inspection** -- SOME/IP parsing, ARP spoofing detection, IPv6 extension header analysis, TCP state tracking (`vs-eth-monitor`)
- **Network firewall** -- layer 3/4 rule evaluation with default-deny, token-bucket rate limiting (`vs-netfw`)
- **OTA update validation** -- TUF 4-role delegation chain (root, timestamp, snapshot, targets), monotonic rollback counter, threshold-of-N ECDSA P-256 signature verification (`vs-ota-validator`)
- **Cryptographic key management** -- slot-based key storage (64 slots), zeroize-on-drop, algorithm-bound key purposes (`vs-key-manager`, `vs-crypto`)
- **Measured secure boot** -- PCR extension chain, boot failure policy enforcement (`vs-secure-boot`)
- **Runtime integrity monitoring** -- periodic SHA-256 checks on registered memory regions (`vs-integrity`)
- **Tamper-evident event logging** -- HMAC-SHA-256 chained ring buffer with monotonic sequence numbers (`vs-event-logger`)
- **C FFI integration** -- opaque-handle API with `catch_unwind` guards for panic safety (`vs-ffi`)

The system processes frames and packets received via HAL traits (`CanBus`, `EthernetPhy`, `Timer`, `HsmHardware`) and does not control actuators directly.

---

## 3. Trust Boundaries

The following trust boundaries exist within the system. Data crossing a boundary must be validated before it reaches trusted components.

| ID | Boundary | Untrusted Side | Trusted Side | Crossing Mechanism |
|:---|:---------|:---------------|:-------------|:-------------------|
| TB-1 | External CAN bus to CAN monitor | CAN bus (external ECUs, potential attacker access) | `vs-can-monitor::process_frame()` | HAL `CanBus::receive()` trait |
| TB-2 | External network to Ethernet monitor / Firewall | Ethernet PHY (external network traffic) | `vs-eth-monitor::inspect_packet()`, `vs-netfw::evaluate()` | HAL `EthernetPhy::receive()` trait |
| TB-3 | OTA server to OTA validator | Remote update server (TUF metadata, firmware images) | `vs-ota-validator` (signature verification, rollback check) | TUF metadata JSON parsing, ECDSA P-256 verification |
| TB-4 | Diagnostic tool to Policy engine | External diagnostic tester (UDS requests) | `vs-policy-engine::evaluate()` | Subject/resource/action matching with `Effect::Deny` default |
| TB-5 | Application code to FFI boundary | C/C++ integrator code | `vs-ffi` extern "C" functions | Opaque handles, `catch_unwind` guards, input validation |
| TB-6 | User space to HAL (hardware) | Software runtime | Hardware peripherals (CAN controller, HSM, timer, flash) | `vs-hal` trait implementations (`HsmHardware`, `StorageProvider`) |

---

## 4. Assets

| ID | Asset | Description | Confidentiality | Integrity | Availability |
|:---|:------|:------------|:---------------:|:---------:|:------------:|
| A1 | Key material | AES-256-GCM, ECDSA P-256, HMAC-SHA-256 keys in `vs-key-manager` (64 slots, 32-byte max) | Critical | Critical | High |
| A2 | Firmware images | OTA update payloads validated by `vs-ota-validator` | Medium | Critical | High |
| A3 | Audit logs | HMAC-chained `LogEntry` records in `vs-event-logger` ring buffer (210 bytes/entry) | Medium | Critical | High |
| A4 | Configuration | Firewall rules (`FirewallRule` in `vs-netfw`, up to 128/256/512 rules), policy rules (`vs-policy-engine`, up to 64 rules), CAN allowlist (512 IDs) | Low | Critical | High |
| A5 | Runtime state | `PlatformHealth`, CAN per-ID statistics (1024 entries), TCP connection table (64 entries), rate limiter state (32 buckets) | Low | High | High |
| A6 | Boot measurements | PCR values managed by `vs-secure-boot::extend_pcr()` and `read_pcr()` | Low | Critical | High |
| A7 | Monotonic counter | Rollback counter persisted via `StorageProvider` for OTA version enforcement | Low | Critical | Critical |

---

## 5. Threat Categories (STRIDE)

### 5.1 Spoofing

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| S-1 | CAN frame injection with legitimate arbitration IDs | A4, A5 | Attacker on the CAN bus transmits frames using valid IDs from the 512-entry allowlist |
| S-2 | CAN payload replay | A5 | Re-transmission of previously captured legitimate CAN frames |
| S-3 | MAC address spoofing on Ethernet | A5 | Forged source MAC addresses to bypass firewall rules that match on `src_mac` |
| S-4 | ARP spoofing | A5 | Forged ARP replies to redirect Ethernet traffic |
| S-5 | False OTA metadata | A2, A7 | Attacker serves crafted TUF metadata (timestamp, snapshot, targets) with valid structure but unauthorized content |
| S-6 | SOME/IP service injection | A5 | Unauthorized SOME/IP method calls with spoofed service/method IDs |
| S-7 | Diagnostic session impersonation | A1 | Reuse of expired session tokens or brute-force of SecurityAccess HMAC |

### 5.2 Tampering

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| T-1 | Firmware image modification | A2 | Altered OTA payload that bypasses or precedes signature verification |
| T-2 | Audit log manipulation | A3 | Direct modification of `LogEntry` records in the ring buffer storage |
| T-3 | Key material extraction and replacement | A1 | Overwrite key slots in `vs-key-manager` with attacker-controlled material |
| T-4 | Firewall rule injection | A4 | Unauthorized addition of permissive `FirewallRule` entries to `vs-netfw` |
| T-5 | CAN DLC manipulation | A5 | Invalid data length codes to trigger parser faults or buffer over-reads |
| T-6 | IPv6 extension header chain abuse | A4 | Crafted extension header chains to evade L3 inspection in `vs-eth-monitor` |
| T-7 | Boot measurement corruption | A6 | Modification of PCR values to mask a compromised boot stage |

### 5.3 Repudiation

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| R-1 | HMAC log chain bypass | A3 | Attacker performs unauthorized actions and breaks or replaces the HMAC chain in `vs-event-logger` to erase evidence |
| R-2 | Timestamp manipulation | A3 | Feeding false timestamps via the `Timer` HAL trait to create misleading log ordering |
| R-3 | Sequence number reset | A3 | Resetting the monotonic sequence counter in `vs-event-logger` to overwrite existing entries without detection |
| R-4 | Log overflow exploitation | A3 | Intentionally flooding events to cause ring buffer wrap-around, overwriting evidence of earlier malicious activity |

### 5.4 Information Disclosure

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| I-1 | Key material leakage via timing side-channels | A1 | Timing analysis on HMAC-SHA-256 or ECDSA P-256 operations in `vs-crypto` |
| I-2 | Key material leakage via memory dumps | A1 | Reading process memory (cold boot, JTAG, debug port) to extract key bytes from `vs-key-manager` slots |
| I-3 | Residual key material after revocation | A1 | Incomplete zeroization leaving key bytes in memory after `revoke_key()` |
| I-4 | FFI handle information leak | A5 | C callers dereferencing or inspecting opaque handles to infer internal state |
| I-5 | CAN/Ethernet traffic analysis | A5 | Passive observation of alert patterns to infer detection thresholds and allowlist contents |

### 5.5 Denial of Service

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| D-1 | CAN bus flooding | A5 | High-rate frame injection exceeding the EWMA rate monitoring window |
| D-2 | Ethernet SYN flood / RST injection | A5 | TCP state table exhaustion (64-connection limit, 30s timeout in `vs-eth-monitor`) |
| D-3 | Firewall rule table overflow | A4 | Inserting rules up to `MAX_RULES` capacity to prevent addition of legitimate rules |
| D-4 | Token-bucket exhaustion | A5 | Sustained traffic at exactly the rate limit boundary to starve legitimate traffic through `RateLimit` rules |
| D-5 | OTA validation resource consumption | A5 | Submitting large or malformed TUF metadata to consume processing time during `vs-ota-validator` parsing |
| D-6 | Event log saturation | A3 | Generating a high volume of security events to wrap the ring buffer and lose historical entries |

### 5.6 Elevation of Privilege

| ID | Threat | Target Asset | Attack Vector |
|:---|:-------|:-------------|:-------------|
| E-1 | Diagnostic session hijacking | A1, A2 | Exploiting a valid diagnostic session to execute privileged UDS services (0x31, 0x34, 0x36, 0x37) |
| E-2 | Policy engine bypass | A4 | Crafting requests that do not match any rule, relying on a misconfigured default (the engine defaults to `Effect::Deny`, but misconfiguration could change this) |
| E-3 | VLAN hopping | A4 | Escaping Ethernet network segmentation to reach protected network zones |
| E-4 | FFI boundary escape | A1, A5 | Exploiting `unsafe` blocks in `vs-ffi` (6 items) or `vs-hal-linux` (29 items) to access internal state |
| E-5 | TUF threshold bypass | A1, A2 | Compromising fewer signing keys than the configured threshold requires, exploiting a threshold misconfiguration |

---

## 6. Mitigations

### 6.1 Spoofing Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| S-1 | Arbitration ID allowlist (512 IDs); unknown IDs generate alerts | `vs-can-monitor` -- `ALLOWLIST_CAPACITY`, allowlist check in `process_frame()` |
| S-2 | FNV-1a hash replay detection with 3-identical threshold across 256 tracked IDs | `vs-can-monitor` -- `REPLAY_CAPACITY`, `REPLAY_ALERT_INTERVAL` |
| S-3 | Firewall rules match on `src_mac` / `dst_mac` fields; unmatched packets hit default-deny | `vs-netfw` -- `FirewallRule::src_mac`, `Verdict::Drop` default |
| S-4 | ARP spoofing detection | `vs-eth-monitor` -- ARP reply validation |
| S-5 | TUF 4-role delegation chain with threshold-of-N ECDSA P-256 signature verification; timestamp freshness and snapshot cross-reference | `vs-ota-validator` -- root, timestamp, snapshot, targets role verification |
| S-6 | SOME/IP header parsing and service discovery tracking | `vs-eth-monitor` -- SOME/IP inspection |
| S-7 | Session timeout (5s default); seed cleared after each attempt; brute-force lockout (3 failures, 10s lockout) | Diagnostic gateway in [`auto/`](../../auto/) |

### 6.2 Tampering Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| T-1 | Threshold-of-N ECDSA P-256 signature verification; SHA-256 content hash in TUF metadata | `vs-ota-validator` -- `parse_tuf_root_with_hash()`, signature chain |
| T-2 | HMAC-SHA-256 chain linking each `LogEntry` to the previous; `prev_hash` and `entry_hmac` fields (210-byte serialized entry) | `vs-event-logger` -- HMAC chain with `subtle::ConstantTimeEq` verification |
| T-3 | Key slots zeroized on `revoke_key()` via `zeroize::Zeroize`; key purpose binding prevents cross-purpose use | `vs-key-manager` -- `KeyPurpose` enum, `Zeroize` derive on key material |
| T-4 | Firewall rules are set at initialization; no runtime external API for rule insertion beyond FFI control | `vs-netfw` -- rules configured through trusted FFI path |
| T-5 | DLC validation against expected ranges; `payload_len()` applies `min()` bounds (8 for classic CAN, ISO 11898-1 mapping for CAN-FD) | `vs-can-monitor` -- `CanFrame::payload_len()`, `CAN_FD_DLC_TO_LEN` table |
| T-6 | IPv6 extension header chain walking with safety limit to prevent infinite loops | `vs-eth-monitor` -- bounded header traversal |
| T-7 | PCR extension is append-only (`extend_pcr()`); PCR values cannot be reset without full platform re-initialization | `vs-secure-boot` -- `extend_pcr()`, `read_pcr()` |

### 6.3 Repudiation Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| R-1 | Each log entry includes an HMAC computed over the entry content and the previous entry's HMAC; chain breakage is detectable | `vs-event-logger` -- `entry_hmac` field, HMAC key stored in HSM when available |
| R-2 | Monotonic sequence numbers in `LogEntry` detect out-of-order or missing entries; timestamp source is the HAL `Timer` trait (trusted) | `vs-event-logger` -- `sequence` field (8 bytes) |
| R-3 | Sequence numbers are monotonically increasing; reset detection is possible by verifying the chain from any known-good entry | `vs-event-logger` -- monotonic sequence enforcement |
| R-4 | Overflow counter tracked and surfaced in `PlatformHealth`; critical events prioritized via severity-based shedding | `vs-event-logger` -- ring buffer overflow counter; `vs-runtime` -- `PlatformHealth` |

### 6.4 Information Disclosure Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| I-1 | Constant-time comparison for all secret-dependent operations using `subtle::ConstantTimeEq` | `vs-crypto` -- replaces custom XOR accumulator; `vs-event-logger`, `vs-integrity` |
| I-2 | Zeroize-on-drop for all key material; HSM-backed keys never leave hardware in production | `vs-key-manager` -- `Zeroize` derive; `vs-hal` -- `HsmHardware` trait |
| I-3 | `revoke_key()` explicitly zeroizes the key slot; `Zeroize` derive ensures drop-time cleanup | `vs-key-manager` -- `zeroize::Zeroize` on `KeyMetadata` and key material buffer |
| I-4 | FFI layer uses opaque handles; callers cannot dereference internal pointers; `catch_unwind` prevents stack unwinding information leakage | `vs-ffi` -- opaque handle pattern, `catch_unwind` guards |
| I-5 | No direct mitigation at the software level; this is an inherent property of any detection system | Accepted risk -- see Section 8 |

### 6.5 Denial of Service Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| D-1 | Per-ID EWMA rate monitoring with flood detection; bus-off detection at error count threshold (255) | `vs-can-monitor` -- `STATS_CAPACITY` (1024), `BUS_OFF_ERROR_THRESHOLD` |
| D-2 | TCP connection table with 64-entry limit and 30s timeout; RST injection handling | `vs-eth-monitor` -- `CONN_TIMEOUT_US` (5s in firewall); bounded connection table |
| D-3 | Fixed-size rule table (`MAX_RULES` = 128/256/512 depending on feature); rule addition fails gracefully when full | `vs-netfw` -- `MAX_RULES` constant, `VsError` return on overflow |
| D-4 | Token-bucket rate limiters (32 concurrent) with configurable packets-per-second | `vs-netfw` -- `MAX_RATE_LIMITERS`, `RuleAction::RateLimit(u32)`, `TOKEN_SCALE` |
| D-5 | All parsing uses bounded reads with explicit length checks; no heap allocation prevents memory exhaustion | `vs-ota-validator` -- bounded JSON parsing; `#![no_std]` zero-heap design |
| D-6 | Ring buffer design is intentional for bounded memory; overflow counter in `PlatformHealth` | `vs-event-logger` -- fixed-size ring buffer; overflow is a known trade-off |

### 6.6 Elevation of Privilege Mitigations

| Threat | Mitigation | Crate / Mechanism |
|:-------|:-----------|:------------------|
| E-1 | Policy engine enforces per-SID access control; programming services (0x31, 0x34, 0x36, 0x37) require `AuthenticationLevel::Extended` | `vs-policy-engine` -- `SubjectMatcher::AuthenticatedWithLevel()`, `Effect::Deny` default |
| E-2 | Policy engine defaults to `Effect::Deny` when no rule matches; `DenyAudit` variant triggers audit logging | `vs-policy-engine` -- default-deny evaluation, `Effect::DenyAudit` |
| E-3 | Firewall operates at L3/L4 with default-deny; VLAN awareness requires HAL-level support | `vs-netfw` -- `Verdict::Drop` default; VLAN filtering depends on HAL implementation |
| E-4 | All `unsafe` blocks have documented SAFETY comments; verified by `cargo-geiger` in CI; `#![forbid(unsafe_code)]` on all crates except `vs-ffi` and `vs-hal-linux` | `vs-ffi` -- 6 unsafe items; `vs-hal-linux` -- 29 unsafe items; `vs-storage` -- 2 unsafe items; CI `unsafe-audit` job |
| E-5 | TUF threshold verification requires N-of-M valid signatures; threshold is configured at initialization | `vs-ota-validator` -- threshold-of-N ECDSA verification |

---

## 7. Residual Risks

The following risks are outside the scope of Craton Shield's software mitigations or are only partially addressed.

| ID | Residual Risk | Reason | Potential Impact |
|:---|:-------------|:-------|:----------------|
| RR-1 | Physical access to the ECU | Software cannot prevent JTAG/debug port access, bus probing, or chip decapping. Requires hardware countermeasures (fuse-locked debug, tamper-evident enclosures). | Key extraction, firmware dumping, boot bypass |
| RR-2 | Compromised compiler or toolchain | A malicious Rust compiler or linker could inject backdoors. Mitigated organizationally by using official Rust toolchains and reproducible builds, but not verifiable at the application level. | Arbitrary code execution |
| RR-3 | Hardware faults | Bit-flips from radiation, voltage glitching, or silicon defects can corrupt memory, skip instructions, or alter control flow. Software integrity checks (`vs-integrity`) detect some of these but cannot prevent them. | Integrity check bypass, key corruption |
| RR-4 | FNV-1a hash collisions in CAN replay detection | FNV-1a is a non-cryptographic hash chosen for performance (sub-microsecond). Collision probability at 32 bits is non-negligible for a motivated attacker. | Replay attack evasion |
| RR-5 | AES-GCM nonce uniqueness not enforced | Nonce management is the caller's responsibility per the `vs-crypto` API. Nonce reuse breaks ciphertext confidentiality and authentication. | Confidentiality and integrity loss for encrypted data |
| RR-6 | Slow-rate CAN flooding below detection threshold | EWMA rate monitoring has a detection threshold. An attacker injecting frames at a rate just below the threshold can avoid detection. | Undetected CAN injection |
| RR-7 | Ring buffer log overflow | The event log is a fixed-size ring buffer. Under sustained attack, oldest entries are overwritten. The overflow counter in `PlatformHealth` provides awareness but not prevention. | Loss of historical forensic evidence |
| RR-8 | Side-channel attacks beyond timing | Power analysis (SPA/DPA) and electromagnetic analysis require hardware countermeasures (HSM with shielding). `subtle::ConstantTimeEq` addresses timing only. | Key material extraction |
| RR-9 | Supply chain compromise of dependencies | Craton Shield depends on external crates (`zeroize`, `subtle`, RustCrypto). A compromised dependency could introduce vulnerabilities. Mitigated by `cargo audit`, `cargo deny`, and SBOM tracking. | Arbitrary impact depending on compromised crate |
| RR-10 | Post-quantum threat to ECDSA/ECDH | Current production cryptography uses P-256 curves. ML-KEM-768 and ML-DSA-65 are available under feature flags (`pq-software`) but are experimental and not FIPS-approved. | Long-term key compromise via quantum computing |

---

## 8. Assumptions

The threat model assumes the following conditions hold. If any assumption is violated, the corresponding mitigations may be ineffective.

| ID | Assumption | Dependent Mitigations |
|:---|:-----------|:---------------------|
| AS-1 | The boot chain is trusted and measured. The platform boots through a verified chain (hardware root of trust, secure bootloader) before Craton Shield initialization. | All secure boot mitigations (T-7, E-1); PCR measurements in `vs-secure-boot` |
| AS-2 | The HAL implementation is correct and trustworthy. The concrete implementations of `CanBus`, `EthernetPhy`, `Timer`, `HsmHardware`, and `StorageProvider` traits faithfully represent hardware behavior. | All mitigations that depend on HAL data (TB-1 through TB-6); timestamp integrity (R-2) |
| AS-3 | Key provisioning is performed securely. Initial key material is loaded into `vs-key-manager` through a trusted provisioning process (manufacturing line, secure channel) before the system enters operation. | All cryptographic mitigations; HMAC chain integrity (T-2, R-1); OTA signature verification (T-1, S-5) |
| AS-4 | The HSM (when present) correctly implements its cryptographic operations and provides side-channel resistance. | I-1, I-2, RR-8 mitigations |
| AS-5 | The Rust compiler produces correct code. The `rustc` compiler and LLVM backend do not introduce bugs that violate memory safety or alter program semantics. | All memory safety guarantees; `#![forbid(unsafe_code)]` enforcement |
| AS-6 | The integrator configures the policy engine, firewall rules, and CAN allowlist correctly for the deployment context. | E-2 (policy bypass via misconfiguration); S-1 (allowlist effectiveness); D-3 (rule table sizing) |
| AS-7 | The `mock-hsm` and `pq-software` features are never enabled in production builds. Compile-time guards (`compile_error!`) enforce this for release builds. | All cryptographic security properties |
| AS-8 | The operating environment provides basic isolation. The ECU OS (or bare-metal runtime) prevents other processes from reading Craton Shield's memory space. | I-2 (memory dump protection); A1 confidentiality |

---

## 9. References

| Document | Path |
|:---------|:-----|
| Threat Analysis and Risk Assessment (TARA) | `docs/tara.md` |
| Architecture | `docs/architecture.md` |
| Security Policy | `SECURITY.md` |
| Cybersecurity Case | `docs/certification/cybersecurity-case.md` |
| FIPS 140-3 Module Boundary | `docs/certification/fips-140-3-boundary.md` |
| ISO 26262 ASIL-B Assessment | `docs/certification/iso-26262-asil-b-assessment.md` |
| ISO 21434 Gap Analysis | `docs/certification/iso-21434-gap-analysis.md` |
| Test Plan | `docs/test-plan.md` |
| Requirements Traceability Matrix | `docs/requirements-traceability-matrix.md` |

---

## Revision History

| Version | Date | Changes |
|:--------|:-----|:--------|
| 1.0.0 | 2026-03-28 | Initial threat model based on Craton Shield v0.6.0 |
| 1.1.0 | 2026-04-13 | Updated for Craton Shield v0.7.0; multi-domain workspace context added |
