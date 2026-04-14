# Craton Shield -- Penetration Test Plan

**Version**: 1.0.0 | **Date**: 2026-03-15
**Target**: Craton Shield Core Platform v0.6.0
**Classification**: Confidential

---

## 1 Scope

This penetration test covers the Craton Shield v0.6.0 core platform, comprising 18 Rust
crates that implement automotive intrusion detection and prevention. Testing targets the
compiled binary as integrated on a reference ECU, the FFI interface, and all external
input surfaces.

### 1.1 In Scope

- CAN bus input processing (vs-can-monitor, vs-anomaly)
- Ethernet/SOME/IP firewall (vs-eth-monitor, vs-netfw)
- OTA update validation (vs-ota-validator, vs-crypto)
- V2X message authentication (vs-crypto)
- Cryptographic operations and key management (vs-crypto, vs-key-manager)
- Runtime orchestration (vs-runtime)
- FFI boundary (vs-ffi)

### 1.2 Out of Scope

- OEM-specific HAL implementations
- ECU hardware (separate hardware security assessment)
- Backend VSOC infrastructure
- Vehicle-level system integration

### 1.3 Acceptance Criteria

The penetration test passes if:
- **Zero critical findings** (remote code execution, authentication bypass, key extraction)
- **Zero high findings** (firewall bypass, signature forgery, denial of safety function)
- Medium and low findings are documented for remediation tracking

---

## 2 Test Categories

### 2.1 CAN Injection Attacks

**Objective**: Determine whether Craton Shield correctly detects and alerts on malicious
CAN frames, and verify that the detection engine cannot be evaded.

**Approach**:
1. Replay known attack datasets (e.g., SynCAN, ROAD dataset) through the HAL CAN
   interface.
2. Craft evasion attempts: gradual frequency drift to avoid EWMA thresholds, signal
   values at exact boundary conditions, interleaved legitimate and malicious frames.
3. Attempt counter overflow attacks by sending frames at maximum bus rate for extended
   periods.
4. Test with arbitration IDs not in the configured monitoring set.
5. Send frames with DLC mismatches (declared length vs. actual payload).

**Tools**:
- CANoe / CANalyzer (Vector)
- python-can with custom injection scripts
- SavvyCAN
- Custom CAN frame generator targeting boundary conditions

**Success criteria**:
- All known attack patterns generate alerts within configured thresholds.
- No evasion technique causes a missed detection for monitored arbitration IDs.
- Counter overflow does not crash the runtime or produce incorrect frequency calculations.

### 2.2 SOME/IP Fuzzing

**Objective**: Identify parsing vulnerabilities, crashes, or firewall bypasses in the
Ethernet/SOME/IP processing path.

**Approach**:
1. Fuzz SOME/IP message headers with randomized and boundary values (service ID, method
   ID, length, protocol version, interface version, message type, return code).
2. Fuzz SOME/IP-SD entries with malformed option arrays, oversized entry counts, and
   truncated payloads.
3. Attempt firewall bypass by crafting packets that match allow rules with unexpected
   payload structures.
4. Send fragmented IP packets containing SOME/IP messages.
5. Test with maximum concurrent connections to verify table overflow behavior.

**Tools**:
- Defensics SOME/IP test suite (Synopsys)
- Boofuzz with custom SOME/IP protocol definition
- Scapy with SOME/IP dissector
- Custom Rust fuzzer using `cargo-fuzz` / `libfuzzer`

**Success criteria**:
- No panics, crashes, or undefined behavior under any fuzzed input.
- Firewall rules correctly applied regardless of malformed header fields.
- Service discovery table rejects entries beyond `MAX_SD_SERVICES`.
- All malformed packets are either dropped or generate alerts.

### 2.3 OTA Man-in-the-Middle (MITM)

**Objective**: Verify that tampered, replayed, or downgraded OTA updates are rejected by
the validation chain.

**Approach**:
1. Intercept an OTA update package and modify the firmware binary while preserving
   original metadata.
2. Replace the firmware signature with a signature from an attacker-controlled key.
3. Replay a previously valid update package (rollback attack).
4. Tamper with individual TUF metadata files (timestamp, snapshot, targets) while leaving
   others intact.
5. Present an update with a valid signature but expired timestamp metadata.
6. Attempt partial update delivery (truncated image).

**Tools**:
- mitmproxy for update channel interception
- Custom TUF metadata manipulation scripts
- OpenSSL / RustCrypto for key generation and re-signing
- Binary patching tools (radare2, hex editors)

**Success criteria**:
- All tampered firmware images are rejected with appropriate error codes.
- Rollback attacks are detected by version/sequence number validation.
- Partial TUF chain breaks cause full rejection (not partial acceptance).
- Truncated images are rejected before any flash write occurs.

### 2.4 Diagnostic Session Hijack

**Objective**: Verify that the diagnostic gateway enforces authentication and session
management correctly.

**Approach**:
1. Attempt session transitions (default to programming, default to extended) without
   prior authentication.
2. Replay captured authentication tokens from a previous valid session.
3. Brute-force authentication challenges (verify rate limiting or lockout).
4. Attempt session state confusion by sending interleaved requests from multiple sources.
5. Send malformed UDS (ISO 14229) requests: oversized payloads, invalid service IDs,
   truncated sub-functions.
6. Attempt security access (0x27) with known seed prediction techniques.

**Tools**:
- CANoe Diagnostic Console
- UDS scanner (custom Python tool using python-can + udsoncan)
- CAN injection hardware (PCAN, Kvaser)

**Success criteria**:
- No session transition occurs without valid authentication.
- Replayed tokens are rejected.
- Malformed UDS requests do not crash the gateway or leave it in an inconsistent state.
- Security access rejects incorrect keys and enforces attempt limits.

### 2.5 V2X Replay and Spoofing

**Objective**: Verify that the V2X authentication layer correctly rejects spoofed,
replayed, and malformed IEEE 1609.2 SPDUs.

**Approach**:
1. Capture valid BSM (Basic Safety Message) SPDUs and replay them after a configurable
   time window.
2. Modify BSM payload fields (position, speed, heading) while preserving the original
   signature.
3. Present SPDUs signed with expired certificates.
4. Present SPDUs signed with certificates from an untrusted root.
5. Present SPDUs with valid signatures but mismatched PSID (Provider Service Identifier).
6. Fuzz the IEEE 1609.2 SPDU header and certificate fields.

**Tools**:
- Cohda Wireless MK6 OBU (or equivalent V2X hardware)
- Custom SPDU generator (Rust or Python)
- CAMP Security Credential Management System (SCMS) test environment
- Wireshark with IEEE 1609.2 dissector

**Success criteria**:
- Replayed messages outside the time window are rejected.
- Modified payloads with original signatures are rejected (signature verification).
- Expired certificates return `ExpiredCertificate` error.
- Untrusted roots return `UntrustedIssuer` error.
- PSID mismatches are detected and rejected.

### 2.6 Cryptographic Side-Channel Analysis

**Objective**: Evaluate resistance to timing and power analysis side-channel attacks on
cryptographic operations.

**Approach**:
1. Timing analysis: Measure execution time of ECDSA verification with valid vs. invalid
   signatures across a large sample. Statistical analysis (t-test) to detect timing
   leaks.
2. Timing analysis: Measure execution time of HMAC comparison for messages with varying
   prefix match lengths.
3. Cache timing: Monitor cache access patterns during AES-GCM operations on targets with
   shared cache (Cortex-A class).
4. Verify that `subtle::ConstantTimeEq` is used for all security-critical comparisons.
5. Code review of all comparison paths in authentication and verification logic.

**Tools**:
- Custom timing measurement harness (cycle-accurate counters, CYCCNT on ARM)
- Daredevil / ChipWhisperer (for power analysis if hardware target available)
- Valgrind / Cachegrind (for cache behavior analysis on Linux target)
- dudect (constant-time testing framework)

**Success criteria**:
- No statistically significant timing variation (p < 0.001) between valid and invalid
  inputs across 10,000+ samples.
- All security-critical comparisons use `subtle::ConstantTimeEq`.
- No data-dependent branches or memory accesses in signature verification hot path.

### 2.7 Denial of Service / Resource Exhaustion

**Objective**: Verify that Craton Shield remains operational under sustained high-load
conditions and does not exhaust fixed-size resources.

**Approach**:
1. Flood CAN interface at maximum bus rate (1 Mbit/s CAN, 5 Mbit/s CAN-FD) for 60
   minutes. Monitor for missed detections, memory corruption, or runtime degradation.
2. Flood Ethernet interface at line rate with SOME/IP packets. Verify firewall continues
   to enforce rules correctly.
3. Fill all fixed-size tables to capacity (event log ring buffer, SD service table,
   firewall rule table) and verify graceful handling of additional entries.
4. Rapid init/deinit cycles to check for resource leaks.
5. Send maximum-size CAN frames (CAN-FD 64 bytes) with every arbitration ID (0x000
   through 0x7FF) in rapid succession.
6. Measure tick execution time under sustained load. Verify WCET budget is not exceeded.

**Tools**:
- Vector VN1610/VN5640 (high-speed CAN/Ethernet interface)
- iperf3 (Ethernet traffic generation)
- Custom load generator scripts
- Logic analyzer / oscilloscope for tick timing measurement

**Success criteria**:
- Runtime does not crash, panic, or enter an unrecoverable state under any load
  condition.
- All fixed-size tables handle overflow gracefully (reject new entries, not corrupt).
- Tick execution time remains within WCET budget under sustained maximum load.
- Event log entries are not lost silently (ring buffer overwrites oldest with indication).
- PlatformHealth correctly reflects system status throughout the test.

---

## 3 Test Environment

### 3.1 Required Equipment

| Item | Purpose |
|------|---------|
| Reference ECU (Cortex-M4 or Cortex-A53) | Primary test target |
| Linux host (x86_64) | Secondary target (vs-hal-linux), fuzzing host |
| Vector VN1610 or equivalent | CAN bus interface |
| Vector VN5640 or equivalent | Automotive Ethernet interface |
| PCAN-USB Pro FD | Additional CAN-FD interface |
| Oscilloscope (2+ channels, 1 GHz) | Timing measurements |
| Logic analyzer (8+ channels) | GPIO/timing observation |
| Cohda MK6 OBU or equivalent | V2X message generation |
| ChipWhisperer (optional) | Power analysis side-channel |

### 3.2 Software Environment

| Tool | Version | Purpose |
|------|---------|---------|
| CANoe | 17.0+ | CAN/Ethernet simulation and analysis |
| Wireshark | 4.0+ | Packet capture and analysis |
| Boofuzz | Latest | Protocol fuzzing framework |
| cargo-fuzz | Latest | Rust-native fuzzing |
| mitmproxy | 10.0+ | OTA MITM testing |
| Python 3.12+ | N/A | Custom test scripts |
| Rust toolchain | 1.82+ (MSRV) | Building test harnesses |

### 3.3 Network Configuration

```
+-------------------+        +-------------------+
|   Attack Host     |        |   Reference ECU   |
|   (Linux x86_64)  |        |   (Cortex-M4/A53) |
|                   |        |                   |
|  CAN0 (VN1610) --+--------+-- CAN Bus         |
|  ETH0 (VN5640) --+--------+-- Eth (100BASE-T1)|
|  V2X  (MK6)    --+- - - - +-- V2X Radio       |
+-------------------+        +-------------------+
```

---

## 4 Timeline

| Phase | Duration | Activities |
|-------|----------|------------|
| Preparation | 1 week | Environment setup, tool configuration, test script development |
| CAN injection testing | 3 days | Sections 2.1 |
| SOME/IP fuzzing | 3 days | Section 2.2 |
| OTA MITM testing | 2 days | Section 2.3 |
| Diagnostic session testing | 2 days | Section 2.4 |
| V2X testing | 2 days | Section 2.5 |
| Side-channel analysis | 3 days | Section 2.6 |
| DoS/resource exhaustion | 2 days | Section 2.7 |
| Analysis and reporting | 3 days | Finding classification, report writing |
| Retest (if needed) | 1 week | Verify remediations |
| **Total** | **5-6 weeks** | |

---

## 5 Finding Classification

Findings are classified using the following severity scale:

| Severity | Definition | Examples |
|----------|-----------|----------|
| Critical | Remote code execution, complete authentication bypass, cryptographic key extraction | Buffer overflow leading to code execution, signature verification always returns true |
| High | Firewall bypass, signature forgery for specific cases, persistent denial of safety function | Rule table corruption allowing traffic, ECDSA nonce reuse |
| Medium | Detection evasion for specific patterns, information disclosure, temporary DoS | Timing side-channel with practical exploitation path, SD table overflow causing missed alerts |
| Low | Minor information leak, defense-in-depth weakness, non-exploitable code quality issue | Verbose error messages revealing internal state, unused code paths |
| Informational | Best practice recommendation, hardening suggestion | Additional logging, defense-in-depth improvements |

---

## 6 Deliverables

1. **Penetration Test Report** -- Detailed findings with reproduction steps, evidence,
   severity classification, and remediation recommendations.
2. **Executive Summary** -- One-page summary for management review.
3. **Test Evidence Package** -- Packet captures, logs, screenshots, and timing data.
4. **Retest Report** -- Verification of remediation effectiveness (if applicable).

---

## 7 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-15 | Craton Shield Team | Initial penetration test plan |
