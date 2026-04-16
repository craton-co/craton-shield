# UN R155/R156 Evidence Package

> Craton Shield 0.7.0 | Date: 2026-03-13

## Scope

- **UN R155**: Uniform provisions concerning the approval of vehicles with regards to cyber security and cyber security management system (CSMS)
- **UN R156**: Uniform provisions concerning the approval of vehicles with regards to software update and software update management system (SUMS)

This document maps Craton Shield's capabilities to the technical requirements. Type approval is obtained by the vehicle OEM; Craton Shield provides the component-level evidence.

## UN R155 — Cyber Security

### Annex 5: Threats and Mitigations

UN R155 Annex 5 lists threat categories that must be addressed. Craton Shield's coverage:

| Annex 5 Ref | Threat Category | Craton Shield Mitigation | Crate |
|-------------|-----------------|--------------------------|-------|
| A5.1 | Back-end server threats | N/A (Craton Shield is on-vehicle) | — |
| A5.2 | Communication channel threats | AES-GCM encryption, ECDH key exchange | vs-crypto |
| A5.3 | Update procedure threats | TUF/Uptane 4-role delegation, signed metadata | vs-ota-validator |
| A5.4 | Unintended human actions | Default-deny policy engine, role-based UDS access | vs-policy-engine (vs-diag-gateway in [auto/](../../../auto/)) |
| A5.5 | External connectivity threats | Network firewall (128 rules), packet inspection | vs-netfw, vs-eth-monitor |
| A5.6 | Data/code threats | Integrity monitoring (SHA-256), HMAC-chained logging | vs-integrity, vs-event-logger |
| A5.7 | Insufficient hardening | no_std, zero heap, pedantic linting, cargo audit | All crates |

### 7.2.2.2 — Technical Requirements Mapping

| UN R155 Clause | Requirement | Evidence | Status |
|----------------|-------------|----------|--------|
| 7.2.2.2(a) | Secure by design | no_std, zero heap, Rust memory safety, default-deny | PRESENT |
| 7.2.2.2(b) | Risk assessment | ISO 21434 TARA (see gap analysis) | GAP |
| 7.2.2.2(c) | Detect/prevent cyber attacks | IDS engine: CAN flood/DLC/fuzz/replay + Ethernet anomaly | PRESENT |
| 7.2.2.2(d) | Monitor/respond to attacks | Event logger + VSOC telemetry + alert severity mapping | PRESENT |
| 7.2.2.2(e) | Forensic data capture | Tamper-evident HMAC-chained log, 256-entry ring buffer | PRESENT |
| 7.2.2.2(f) | Secure communication | AES-256-GCM + ECDH P-256 + post-quantum (experimental) | PRESENT |
| 7.2.2.2(g) | Protect stored data | Key zeroization, no persistent storage in default config | PRESENT |
| 7.2.2.2(h) | Secure software updates | TUF/Uptane with root → timestamp → snapshot → targets chain | PRESENT |

### CSMS Evidence (OEM Responsibility — Craton Shield Contributions)

| CSMS Element | Craton Shield Contribution |
|--------------|---------------------------|
| Risk management | TARA input from threat model (to be created) |
| Security monitoring | cargo audit (weekly), SBOM generation, Dependabot |
| Incident response | SECURITY.md: 48h ack, 72h patch, CVE via GitHub CNA |
| Security testing | 1,194 tests, 4 fuzz targets, CI on every push |
| Configuration management | deny.toml, Cargo.lock, SBOM artifacts |
| Supply chain security | deny.toml bans unsafe deps, license allowlist enforced |

## UN R156 — Software Update

### 7.1 — Software Update Management System (SUMS)

| Requirement | Evidence | Status |
|-------------|----------|--------|
| SUMS established | TUF/Uptane validator in vs-ota-validator | PRESENT |
| RX SUID assignment | Software identification via `TufRoot.version` | PRESENT |
| Software version tracking | Semantic versioning, CHANGELOG.md | PRESENT |
| Over-the-air capability | OTA metadata verification with rollback support | PRESENT |
| Update validation | SHA-256 content hash, multi-signature threshold | PRESENT |
| Rollback protection | `BootVerificationOutcome::RequestRollback` policy | PRESENT |

### 7.2 — Vehicle Type Requirements

| Requirement | Evidence | Status |
|-------------|----------|--------|
| 7.2.1 Secure update delivery | TUF timestamp freshness + expiration checks | PRESENT |
| 7.2.2 Integrity verification | SHA-256 hash of signed metadata portion | PRESENT |
| 7.2.3 Authenticity verification | ECDSA P-256 multi-signature with configurable threshold | PRESENT |
| 7.2.4 Protect against unauthorized updates | Root-of-trust key hierarchy, per-role delegation | PRESENT |
| 7.2.5 Record update attempts | Event logger captures OTA events | PRESENT |
| 7.2.6 Rollback capability | Boot failure policy with rollback option | PRESENT |
| 7.2.7 Inform user of update status | Via C FFI `vs_get_health()` — OTA subsystem status | PRESENT |

### Software Identification

| Field | Value |
|-------|-------|
| Software name | Craton Shield |
| Version | 0.6.0 |
| License | Apache-2.0 (SDK) / BSL-1.1 (platform adapters) |
| SBOM format | CycloneDX (generated in CI) |
| Binary size | 254 KB (release, opt-level=z, LTO) |
| Target architectures | x86_64, aarch64, thumbv7em |

## Gap Summary

| Area | Status | Action Required |
|------|--------|-----------------|
| Technical controls (R155) | 6/7 categories covered | Complete TARA for R155 7.2.2.2(b) |
| OTA security (R156) | All requirements met | None (implementation complete) |
| CSMS documentation | Partial | OEM-level CSMS document needed |
| SUMS documentation | Partial | OEM-level SUMS document needed |
| Type approval submission | Not started | OEM responsibility; provide evidence package |

## Deliverables for OEM Integration

Craton Shield provides these artifacts for the OEM's type approval submission:

1. This evidence mapping document
2. SBOM (CycloneDX, generated per release)
3. Test reports (1,194 tests, fuzz coverage)
4. Source code audit trail (CHANGELOG.md, git history)
5. Security vulnerability handling process (SECURITY.md)
6. Dependency audit report (deny.toml + cargo audit)
