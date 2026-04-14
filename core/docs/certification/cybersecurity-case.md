# Cybersecurity Case

**Project**: Craton Shield | **Standard**: ISO/SAE 21434 Clause 6.4.2 | **Version**: 0.6.0 | **Date**: 2026-03-28

---

## 1. Purpose

This cybersecurity case aggregates all evidence demonstrating that Craton Shield satisfies cybersecurity requirements for its intended operating context. It serves as the top-level cybersecurity argument per ISO/SAE 21434 Clause 6.4.2.

---

## 2. Scope

**Item**: Craton Shield embedded security runtime platform
**Boundary**: Software component running on a central gateway ECU (NXP S32G3 Cortex-A53 or equivalent). Processes CAN/Ethernet frames via HAL traits, exposes C FFI for integration. Does not control actuators directly.
**Target context**: Series-production passenger vehicles (UN R155 regulated markets).

---

## 3. Cybersecurity Claim

Craton Shield provides defense-in-depth protection for automotive embedded systems through:

- Real-time CAN and Ethernet intrusion detection
- Policy-driven network firewall
- Secure OTA update validation (TUF/Uptane)
- Cryptographic key lifecycle management
- Measured secure boot chain
- Runtime integrity monitoring
- Tamper-evident event logging

All identified threats from the TARA have corresponding mitigations, and all mitigations are verified through automated testing.

---

## 4. Evidence Index

### 4.1 Threat Analysis (TARA)

| Document | Reference |
|----------|-----------|
| Threat Analysis and Risk Assessment | `docs/tara.md` |

The TARA identifies 26 threat scenarios across six domains (CAN bus, Ethernet, OTA, key management, secure boot, operational) using STRIDE methodology. Risk is assessed using attack feasibility ratings and damage potential per ISO/SAE 21434 Annex E.

### 4.2 Implemented Mitigations

| Mitigation | Crate | TARA Coverage |
|------------|-------|---------------|
| CAN intrusion detection (rate, ID, sequence, entropy) | `vs-can-monitor`, `vs-ids-engine`, `vs-anomaly` | T-CAN-01 through T-CAN-05 |
| Ethernet packet inspection (SOME/IP, DoIP, protocol filtering) | `vs-eth-monitor`, `vs-ids-engine` | T-ETH-01 through T-ETH-05 |
| Network firewall (layer 3/4 filtering, rate limiting) | `vs-netfw`, `vs-policy-engine` | T-ETH-02, T-ETH-04 |
| OTA update validation (TUF metadata, rollback protection, signature verification) | `vs-ota-validator` | T-OTA-01 through T-OTA-05 |
| Cryptographic key management (slot-based, zeroize-on-drop) | `vs-key-manager`, `vs-crypto` | T-KEY-01 through T-KEY-04 |
| Secure boot chain verification (measured boot, PCR extension) | `vs-secure-boot` | T-BOOT-01, T-BOOT-02 |
| Runtime integrity monitoring (memory, configuration) | `vs-integrity` | T-BOOT-03, T-OPS-01 |
| Tamper-evident audit logging (HMAC-chained) | `vs-event-logger` | T-OPS-02, T-OPS-03 |

### 4.3 Security Design Principles

| Principle | Implementation |
|-----------|----------------|
| Memory safety | `#![forbid(unsafe_code)]` on all crates except `vs-ffi` (audited) |
| Constant-time operations | `subtle` crate for comparisons; no secret-dependent branching |
| Zeroization | `zeroize` derive on all key material; verified via dedicated tests |
| Fail-closed | All error paths return deny/reject; no silent degradation |
| Minimal attack surface | `no_std` compatible; no heap allocation in core path |
| Defense in depth | Multiple independent detection layers per threat domain |

### 4.4 Cryptographic Controls

| Algorithm | Standard | Usage |
|-----------|----------|-------|
| AES-256-GCM | FIPS 197 + SP 800-38D | OTA image encryption, secure channel |
| SHA-256 | FIPS 180-4 | Firmware integrity, TUF metadata hashing |
| HMAC-SHA-256 | FIPS 198-1 | Message authentication, key derivation, log chaining |
| ECDSA P-256 | FIPS 186-5 | OTA signature verification, V2X authentication |
| ECDH P-256 | SP 800-56Ar3 | Key agreement for secure sessions |

See also: `docs/certification/fips-140-3-boundary.md`, `docs/certification/fips-140-3-kat-plan.md`.

### 4.5 Verification Evidence

| Category | Count | Reference |
|----------|-------|-----------|
| Unit tests | 1,014+ | `cargo test` across all workspace crates |
| Integration tests | 180+ | `tests/` directory (attack scenarios, crypto vectors, fault injection, concurrency, stress) |
| Fuzz targets | 4 | `fuzz/fuzz_targets/` (CAN frame, Ethernet parse, nonce counter, OTA JSON) |
| Property-based tests | Present | `tests/property_tests.rs` |
| WCET analysis | Present | `tests/wcet_stats.rs`, `benches/wcet_harness.rs` |
| ECU validation suite | Present | `tests/ecu_validation.rs` |
| Competitive benchmarks | Present | `benches/competitive_benchmarks.rs` |

### 4.6 CI/CD Controls

| Control | Tool | Purpose |
|---------|------|---------|
| Static analysis | `clippy` (pedantic) | Lint enforcement on every commit |
| Dependency audit | `cargo audit` | Known vulnerability detection (weekly + CI) |
| License and supply-chain policy | `cargo deny` | License allowlist, advisory DB check, duplicate detection |
| SBOM generation | CI workflow | Software Bill of Materials for each release |
| SLSA attestation | CI workflow | Build provenance and supply-chain integrity |
| Branch protection | GitHub | Required reviews, signed commits, status checks |
| Dependabot | GitHub | Automated dependency update PRs |

### 4.7 Process and Compliance Documents

| Document | Reference |
|----------|-----------|
| ISO 26262 ASIL-B assessment | `docs/certification/iso-26262-asil-b-assessment.md` |
| ISO/SAE 21434 gap analysis | `docs/certification/iso-21434-gap-analysis.md` |
| FIPS 140-3 module boundary | `docs/certification/fips-140-3-boundary.md` |
| FIPS 140-3 KAT plan | `docs/certification/fips-140-3-kat-plan.md` |
| UN R155/R156 evidence | `docs/certification/un-r155-r156-evidence.md` |
| Tool qualification report | `docs/certification/tool-qualification-report.md` |
| Penetration test plan | `docs/certification/penetration-test-plan.md` |
| DFA report | `docs/certification/dfa-report.md` |
| Code review records | `docs/certification/code-review-records.md` |
| Security policy (SECURITY.md) | `SECURITY.md` |
| Architecture | `docs/architecture.md` |
| Test plan | `docs/test-plan.md` |
| Requirements traceability matrix | `docs/requirements-traceability-matrix.md` |

---

## 5. Residual Risk Assessment

All 26 threat scenarios identified in the TARA have corresponding mitigations implemented and verified. Residual risks are:

1. **Hardware-dependent attacks** (side-channel, fault injection on physical hardware) -- mitigated at software level through constant-time operations; full mitigation requires hardware countermeasures outside Craton Shield scope.
2. **Zero-day vulnerabilities in dependencies** -- mitigated through automated auditing, SBOM tracking, and 48-hour acknowledgment / 72-hour patch SLA.
3. **Post-quantum threat to ECDSA/ECDH** -- mitigated by feature-gated ML-KEM-768 and ML-DSA-65 readiness (experimental, not yet FIPS-approved).

---

## 6. Conclusion

This cybersecurity case demonstrates that Craton Shield 0.7.0 satisfies the cybersecurity requirements for its intended deployment context. All TARA-identified threats have implemented and verified mitigations. The evidence chain from threat identification through implementation, verification, and operational monitoring is complete and traceable.
