# Craton Shield Roadmap

> **Current version: 0.7.0 (pre-1.0)**
>
> Craton Shield is a safety-critical embedded security runtime in Rust,
> comprising 49 crates across four domains: core infrastructure, automotive
> (ISO 21434 / AUTOSAR), embedded IoT (IEC 62443), and industrial OT/ICS.
> This roadmap describes the path from the current release to a stable 1.0
> and beyond.

---

## Phase 0.7.x — Initial Public Release

Focus: ship the existing 49-crate workspace to the public registry at the
current pre-1.0 version line. Publication is incremental and decoupled from
the 1.0 stability commitment.

| Area | Deliverable |
|:---|:---|
| Initial crates.io publish | Initial crates.io publish of all 49 workspace members at 0.7.x |
| Release tooling | Workspace-aware release scripts for ordered, dependency-correct publication |
| Version metadata | Verify license, repository, and documentation metadata on every published crate |

---

## Phase 1 — v0.8.0: Stability

Focus: harden APIs, expand test coverage, prepare migration tooling.

| Area | Deliverable |
|:---|:---|
| API stabilization | Freeze public API surface for all core crates; deprecate pre-0.7 interfaces |
| Formal SRS document | Publish a Software Requirements Specification covering safety-critical modules |
| FIPS 140-3 KAT vectors | Add Known Answer Test vectors for AES-GCM-256, SHA-256, HMAC-SHA-256, ECDSA P-256 |
| Migration validation | Complete and document 0.6 to 0.7 migration path with automated verification |

---

## Phase 2 — v0.9.0: Certification Readiness

Focus: produce formal evidence artifacts for automotive and industrial certifications.

| Area | Deliverable |
|:---|:---|
| ISO 26262 ASIL-B | Formal safety artifacts: HARA, FMEA, safety manual, traceability matrix |
| Code review records | Formalize review process with auditable records for all safety-critical changes |
| Ferrocene compiler | Validate against the Ferrocene qualified Rust compiler toolchain |
| IEC 62443 SL-2 | Evidence package for Security Level 2 compliance (zones, conduits, component requirements) |

---

## Phase 3 — v1.0.0: Stable Release

Focus: production-ready stable release with long-term support guarantees.

| Area | Deliverable |
|:---|:---|
| Stable public API | Semver-stable public API with backward compatibility commitment |
| ABI guarantees | ABI backward compatibility policy for C FFI consumers |
| 1.0.0 release tag | Tag 1.0.0 release on crates.io (one further publish of the already-published 49 crates) |
| Post-quantum crypto | Production-ready post-quantum cryptographic primitives (ML-KEM, ML-DSA) |

---

## Future

Items under consideration for post-1.0 releases:

- **CAN-FD deep inspection** -- Extended frame parsing and anomaly detection for CAN-FD networks
- **AUTOSAR SecOC native integration** -- Native Secure Onboard Communication protocol binding
- **RISC-V bare-metal HAL** -- Hardware abstraction layer for RISC-V targets without an OS
- **DO-178C DAL C evidence package** -- Avionics software assurance artifacts at Design Assurance Level C
- **IEC 62304 Class B evidence** -- Medical device software lifecycle process artifacts

---

## Enterprise Edition

Hardware-backed cryptography (HSM via PKCS#11, TPM 2.0), QNX Neutrino RTOS
support, SIEM/SOC connectors, and fleet-scale correlation are available in the
separate **Craton Shield Enterprise** edition under BSL-1.1. See
[craton-shield-enterprise](https://github.com/craton-co/craton-shield-enterprise)
for the enterprise edition and its roadmap.

---

## Disclaimer

This roadmap reflects current plans and is subject to change based on community
feedback, customer requirements, and evolving standards. Dates are targets, not
commitments. We welcome input -- please share your priorities and use cases via
[GitHub Discussions](https://github.com/craton-co/craton-shield/discussions).
