# Craton Shield — Safety Manual for OEM Integrators

**Document Version**: 1.0.0 | **Date**: 2026-03-13 | **Classification**: ASIL-B SEooC
**Software Version**: 0.7.0

> **Note:** The document version (1.0.0) tracks the revision of this safety manual and follows its own versioning cycle, independent of the Craton Shield software version (0.7.0).

> This document is the integration safety manual required by ISO 26262-10 for Safety Elements out of Context (SEooC). It defines the assumptions of use, integration requirements, configuration constraints, and residual risks that the OEM integrator must address to maintain ASIL-B compliance.

---

## 1. Document Purpose

This Safety Manual provides integrators with the information necessary to safely integrate Craton Shield into an embedded system while preserving the target safety integrity level. While this document focuses on the automotive context (ASIL-B per ISO 26262), the universal security core is applicable to other safety-critical domains including industrial (IEC 61508 SIL 2, IEC 62443), medical (IEC 62304 Class B), and avionics (DO-178C DAL C). Domain-specific safety manuals will be provided as those certification paths are completed. This manual covers:

1. Assumptions of use (constraints the integrator must satisfy)
2. Hardware and software integration requirements
3. Configuration guidelines and constraints
4. Known limitations and residual risks
5. Diagnostic and monitoring requirements
6. Decommissioning procedures

---

## 2. Component Identification

| Field | Value |
|-------|-------|
| Component name | Craton Shield |
| Version | 0.7.0 |
| Safety classification | ASIL-B SEooC |
| Applicable standards | ISO 26262 (automotive), ISO/SAE 21434, UN R155/R156; future: IEC 62304 (medical), IEC 62443/61508 (industrial), DO-178C (avionics) |
| Binary size | ~280 KiB (Standard tier) (release, opt-level=z, LTO, panic=abort) |
| Memory model | Stack-only (`#![no_std]`, zero heap allocations) |
| Supported targets | x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, thumbv7em-none-eabihf |
| Qualified targets | NXP S32G3 (Cortex-A53), Infineon AURIX TC3xx (planned), any Cortex-M3+ with 256 KB+ flash |

---

## 3. Assumptions of Use

The following assumptions **must** be satisfied by the integrator. Failure to meet any assumption invalidates the ASIL-B safety case.

### 3.1 Timing Assumptions

| ID | Assumption | Consequence of Violation |
|----|-----------|--------------------------|
| A-01 | The integrator provides a monotonic time source with ≤1 ms jitter to `Craton Shield::tick()` via the `Timer` trait | Incorrect rate calculations in CAN flood detection; missed replay detection windows |
| A-02 | The integrator invokes `tick()` at the configured period (default 10 ms) without unbounded delay | Alert latency exceeds safety budget; watchdog timeout |
| A-03 | Tick period is ≤ 10 ms for CAN monitoring and ≤ 100 ms for Ethernet monitoring | Flood detection thresholds become unreliable |

### 3.2 Input Assumptions

| ID | Assumption | Consequence of Violation |
|----|-----------|--------------------------|
| A-04 | CAN frames are delivered to Craton Shield in reception order with no silent drops | Replay detection may miss reordered attacks; sequence-based alerts may false-positive |
| A-05 | Ethernet packets are delivered with valid headers (minimum 14-byte Ethernet II) | Parser returns error; packet is not inspected |
| A-06 | The integrator does not modify CAN frame content between reception and delivery to `process_frame()` | Integrity of detection is compromised |

### 3.3 Cryptographic Assumptions

| ID | Assumption | Consequence of Violation |
|----|-----------|--------------------------|
| A-07 | Cryptographic key material is provisioned before `init()` returns | Crypto operations return `NotInitialized`; OTA verification fails open |
| A-08 | Keys are protected by an HSM or TEE in production; software-only keys are acceptable only for development/testing | Key material vulnerable to memory dump extraction |
| A-09 | AES-GCM nonces are unique per key; the integrator manages nonce generation or provides a hardware counter | Nonce reuse breaks AES-GCM confidentiality (catastrophic) |
| A-10 | The RNG function provided to `SoftwareCryptoProvider::new(rng)` produces cryptographically secure random bytes | Predictable keys and nonces |

### 3.4 Resource Assumptions

| ID | Assumption | Consequence of Violation |
|----|-----------|--------------------------|
| A-11 | The integrator allocates the stack budget reported by `PlatformHealth::peak_stack_bytes` | Stack overflow (undefined behavior) |
| A-12 | The hardware watchdog is configured externally; Craton Shield reports health via `PlatformHealth` | No automatic recovery from hangs |
| A-13 | The integrator routes `SecurityAlert` events to a downstream VSOC or DTC handler | Detected attacks are not acted upon |

### 3.5 Boot and Update Assumptions

| ID | Assumption | Consequence of Violation |
|----|-----------|--------------------------|
| A-14 | Secure boot measurements (PCR values) are provided by a hardware TPM or TEE | Software-only PCR values can be spoofed |
| A-15 | OTA update metadata is received over an integrity-protected channel (TLS or equivalent) | Metadata tampering before Craton Shield verification |
| A-16 | The monotonic rollback counter is stored in tamper-resistant non-volatile memory | Rollback attacks bypass version monotonicity check |

---

## 4. Integration Requirements

### 4.1 HAL Trait Implementation

The integrator must provide platform-specific implementations of the following traits:

| Trait | Crate | Methods | Safety Relevance |
|-------|-------|---------|-----------------|
| `Timer` | vs-hal | `now_us(&self) -> u64`, `cycle_count(&self) -> Option<u64>` | Monotonic microsecond clock; ASIL-B |
| `CanBus` | vs-hal | `receive(&mut self)`, `transmit(&mut self, frame)` | CAN frame I/O; ASIL-B |
| `EthernetPhy` | vs-hal | `receive(&mut self, buf)`, `transmit(&mut self, buf)` | Ethernet I/O; ASIL-B |
| `HsmHardware` | vs-hal | `store_key()`, `load_key()`, `delete_key()` | Crypto delegation; ASIL-B |

Reference implementations are provided for Linux (`vs-hal-linux`) and QNX Neutrino (`vs-hal-qnx`). Note that the QNX HAL (`vs-hal-qnx`) is maintained in the [`auto/`](../../auto/) directory, not in craton-shield-core. See `docs/porting-guide.md` for step-by-step instructions.

### 4.2 Initialization Sequence (7-Step)

The following 7-step sequence **must** be followed in order. Skipping
or reordering steps leads to undefined behavior.

| Step | Action | Rationale |
|:----:|--------|-----------|
| 1 | Create HAL instances (`Timer`, `CanBus`, `EthernetPhy`) | Hardware must be available before any subsystem can sample time or receive frames. |
| 2 | Create `CryptoProvider` (with FIPS-approved RNG) | All subsequent steps depend on cryptographic primitives. |
| 3 | Provision keys via `set_key()` or HSM `import_key()` | Secure boot, event logging, and integrity checks require keying material. |
| 4 | Call `CratonShield::init(&config)` | Initializes all subsystems; registers CAN/ETH rules, policy, firewall. |
| 5 | Verify `PlatformHealth`: all subsystems report `Healthy` | Catches misconfiguration before the system goes live. |
| 6 | Start `tick()` loop at configured period (recommended <= 10 ms) (default: 10 ms per safety-manual A-02) | Begins active monitoring; must not be called before step 4 returns `Ok`. |
| 7 | Configure external watchdog to reset on `PlatformHealth` degradation | Ensures the ECU resets if the security runtime becomes unresponsive. |

**Critical**: Do not call `tick()` before `init()` returns successfully. Subsystems are not initialized and will produce undefined results.

### 4.3 C FFI Integration

For non-Rust integrators, Craton Shield exposes a C ABI via `vs-ffi`:

| Function | Purpose |
|----------|---------|
| `vs_init(config_ptr) -> VsResult` | Initialize all subsystems |
| `vs_tick(timestamp_us) -> VsResult` | Process one tick cycle |
| `vs_process_can_frame(frame_ptr) -> VsResult` | Process a single CAN frame |
| `vs_process_eth_packet(pkt_ptr, len) -> VsResult` | Process an Ethernet packet |
| `vs_get_health(health_ptr) -> VsResult` | Read platform health snapshot |
| `vs_shutdown() -> VsResult` | Zeroize keys and shut down |

The C header is generated by `cbindgen` and included in each release as `cratonshield.h`. All public types use `#[repr(C)]` for ABI compatibility.

---

## 5. Configuration Guidelines

### 5.1 CAN Monitor Thresholds

| Parameter | Default | Range | Guidance |
|-----------|---------|-------|----------|
| Flood threshold (frames/tick) | 100 | 10-1000 | Set based on expected bus load; lower = more sensitive |
| EWMA alpha | 0.1 | 0.01-0.5 | Lower = smoother, slower response; higher = faster but noisier |
| Replay hash capacity | 256 IDs | 64-1024 | Must cover all monitored arbitration IDs |
| Entropy threshold | 3.5 bits | 2.0-6.0 | Lower = catches more fuzzing; higher = fewer false positives |

### 5.2 Firewall Rules

- **Maximum rules**: 128 per instance (default; 256 with `capacity-large`, 512 with `capacity-xl`)
- **Default policy**: `Deny` (compile-time default; do not change to `Allow`)
- **Rule evaluation**: Sorted-priority early exit; worst-case latency ~166 ns at 128 rules (last-match)
- **Guidance**: Rules are evaluated in priority order with early exit on first match

### 5.3 OTA Validation

| Parameter | Default | Guidance |
|-----------|---------|----------|
| Signature threshold | 2-of-3 | Must match TUF root metadata configuration |
| Metadata expiration check | Enabled | Do not disable; prevents rollback via expired metadata |
| Rollback counter | Required | Must be backed by non-volatile tamper-resistant storage |

### 5.4 Diagnostic Gateway

> **Note**: The diagnostic gateway (`vs-diag-gateway`) is provided in [auto/](../../auto/), not in craton-shield-core. The parameters below apply to that crate.

| Parameter | Default | Guidance |
|-----------|---------|----------|
| Brute-force lockout | 3 failures → 10s | Increase lockout for production; 3/30s recommended |
| Session timeout | 5 seconds | Reduce to 2s for production to limit session hijack window |
| Always-auth SIDs | 0x31, 0x34, 0x36, 0x37 | Never remove these from the always-auth list |

---

## 6. Diagnostic and Monitoring

### 6.1 PlatformHealth Structure

The integrator shall poll `PlatformHealth` (via `vs_get_health()` or direct Rust API) at least once per second and map degraded subsystems to DTCs:

| Subsystem Status | DTC Action |
|-----------------|------------|
| `Healthy` | Clear corresponding DTC |
| `Degraded` | Set warning DTC; continue operation |
| `InitFailed` | Set critical DTC; trigger safe state if ASIL-relevant |
| `NotInitialized` | Set critical DTC; block safety function until initialized |

### 6.2 Security Alerts

`SecurityAlert` events include a severity level:

| Severity | Integrator Action |
|----------|-------------------|
| `Critical` | Forward to VSOC immediately; consider ECU-level response |
| `High` | Forward to VSOC; log locally |
| `Medium` | Log locally; batch forward to VSOC |
| `Low` | Log locally |

### 6.3 Event Log

The HMAC-chained event log provides tamper-evident forensic data:

- Ring buffer: 256 entries (configurable)
- Chain verification: Call `verify_chain()` periodically; a broken chain indicates tampering
- Overflow: Oldest entries overwritten; overflow counter in `PlatformHealth`
- **Integrator responsibility**: Offload log entries to persistent storage before overflow

---

## 7. Known Limitations and Residual Risks

| Limitation | Impact | Integrator Mitigation |
|-----------|--------|----------------------|
| FNV-1a hash for CAN replay detection (non-cryptographic) | Theoretical hash collision at 32-bit | Accept for performance; use IDS correlation for high-assurance scenarios |
| AES-GCM nonce management is caller responsibility | Nonce reuse breaks confidentiality | Provide hardware nonce counter or implement monotonic nonce tracking |
| Audit log ring buffer overwrites oldest entries | Loss of oldest forensic data on overflow | Offload entries to non-volatile storage; monitor overflow counter |
| Software-only crypto (no HSM in default config) | Keys vulnerable to memory extraction | Provide HSM via `HsmHardware` trait for production |
| QNX HAL requires Neutrino-specific FFI | Limited to QNX 7.1+ | Validate on target QNX version before deployment |
| Post-quantum crypto (ML-KEM, ML-DSA) is experimental | Not FIPS 140-3 validated | Do not rely on PQ crypto for compliance; use classical algorithms |
| No AUTOSAR SecOC integration | CAN frames lack message-level authentication | Integrate with OEM SecOC stack for high-value CAN signals |

---

## 8. Decommissioning

When removing Craton Shield from an ECU or replacing with a new version:

1. Call `vs_shutdown()` to zeroize all key material
2. Verify `PlatformHealth` reports all subsystems `NotInitialized`
3. Erase any persistent storage used for rollback counters and event logs
4. Update the vehicle's SBOM to reflect the component removal/change

---

## 9. Contact and Support

| Channel | Contact |
|---------|---------|
| Security vulnerabilities | security@craton.com.ar |
| Integration support | dev@craton.com.ar |
| Documentation | https://github.com/craton-co/craton-shield |
| Response SLA | Security: 48h acknowledgment, 72h patch |

---

## Appendix A — Compliance Cross-Reference

| Standard | Requirement | Safety Manual Section |
|----------|------------|----------------------|
| ISO 26262-10 §6.4.1 | Assumptions of use | Section 3 |
| ISO 26262-10 §6.4.2 | Integration requirements | Section 4 |
| ISO 26262-10 §6.4.3 | Configuration constraints | Section 5 |
| ISO 26262-10 §6.4.4 | Diagnostic requirements | Section 6 |
| ISO 26262-6 §9.4 | Known limitations | Section 7 |
| ISO 21434 §7.4.3 | Interface agreement | Sections 3, 4 |
| UN R155 7.2.2.2(h) | Secure software updates | Section 5.3 |

---

## Appendix B — Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-13 | Initial release for Craton Shield 0.6.0 |
| 1.1.0 | 2026-04-13 | Updated for Craton Shield 0.7.0; version references corrected |
