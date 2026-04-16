# ISO/SAE 21434 Gap Analysis

> Craton Shield 0.7.0 | Date: 2026-03-13

## Scope

ISO/SAE 21434 "Road vehicles — Cybersecurity engineering" defines the cybersecurity engineering process for the full vehicle lifecycle. This gap analysis maps Craton Shield's current state against key work products and clauses.

## Executive Summary

Craton Shield satisfies the technical implementation requirements for a cybersecurity software component. Gaps are primarily in process documentation, organizational evidence, and formal threat analysis artifacts. No code changes are required — gaps are documentation and process work.

**Compliance estimate: ~65% (technical controls present, process artifacts missing)**

## Clause-by-Clause Assessment

### Clause 5 — Organizational Cybersecurity Management

| Requirement | Status | Gap |
|-------------|--------|-----|
| 5.4.1 Cybersecurity governance | PARTIAL | Need formal cybersecurity policy document |
| 5.4.2 Cybersecurity culture | PARTIAL | CONTRIBUTING.md + code review present; no formal training records |
| 5.4.3 Information sharing | GAP | No ISAC membership or information sharing agreements |
| 5.4.4 Management systems | PARTIAL | CI/CD present; need CSMS (Cybersecurity Management System) document |

### Clause 6 — Project-Dependent Cybersecurity Management

| Requirement | Status | Gap |
|-------------|--------|-----|
| 6.4.1 Cybersecurity plan | GAP | Need formal cybersecurity plan per project/vehicle program |
| 6.4.2 Cybersecurity case | GAP | Need cybersecurity case document aggregating all evidence |
| 6.4.3 Cybersecurity assessment | GAP | Need independent assessment (external auditor) |
| 6.4.4 Release for post-development | GAP | Need release criteria checklist |

### Clause 7 — Distributed Cybersecurity Activities

| Requirement | Status | Gap |
|-------------|--------|-----|
| 7.4.1 Supplier capability | N/A | Craton Shield is the supplier component |
| 7.4.2 Request for quotation | N/A | Applies to OEM procurement |
| 7.4.3 Alignment of interfaces | PARTIAL | C FFI defined; need formal interface agreement template |

### Clause 8 — Continual Cybersecurity Activities

| Requirement | Status | Gap |
|-------------|--------|-----|
| 8.3 Cybersecurity monitoring | PRESENT | `cargo audit` weekly, Dependabot, SBOM generation |
| 8.4 Cybersecurity event evaluation | PARTIAL | SECURITY.md defines process; need formal triage procedure |
| 8.5 Vulnerability analysis | PARTIAL | Security review completed; need formal vulnerability register |
| 8.6 Vulnerability management | PRESENT | 48-hour acknowledgment, 72-hour patch SLA documented |

### Clause 9 — Concept Phase (TARA)

| Requirement | Status | Gap |
|-------------|--------|-----|
| 9.3 Item definition | PARTIAL | Architecture documented; need formal item definition |
| 9.4 Threat analysis (TARA) | COMPLETE | See `docs/tara.md` |
| 9.5 Risk determination | COMPLETE | Risk matrix with attack feasibility ratings in `docs/tara.md` Sections 5-6 |
| 9.6 Risk treatment | PARTIAL | Controls implemented; need traceability to TARA |
| 9.7 Cybersecurity concept | PARTIAL | Defense-in-depth present; need formal concept document |

### Clause 10 — Product Development

| Requirement | Status | Gap |
|-------------|--------|-----|
| 10.4.1 Cybersecurity specifications | PARTIAL | Feature docs present; need formal cybersecurity requirements |
| 10.4.2 Cybersecurity requirements allocation | PRESENT | Crate-level separation with clear responsibility |
| 10.4.3 Design verification | PRESENT | 1,194 tests, clippy pedantic, fuzz targets |
| 10.4.4 Integration and verification | PRESENT | 180 integration tests, QEMU aarch64, ECU validation suite |
| 10.4.5 Cybersecurity validation | PARTIAL | Tests present; need formal validation plan |

### Clause 11 — Post-Development

| Requirement | Status | Gap |
|-------------|--------|-----|
| 11.4.1 Cybersecurity incident response | PRESENT | SECURITY.md with CVE process |
| 11.4.2 Updates | PRESENT | OTA validator with TUF/Uptane |

### Clause 15 — Threat Analysis and Risk Assessment (TARA)

| Requirement | Status | Gap |
|-------------|--------|-----|
| 15.3 Asset identification | PARTIAL | Crypto keys, firmware images identified as assets in design |
| 15.4 Threat scenario identification | COMPLETE | Formal threat catalog in `docs/tara.md` Section 3 |
| 15.5 Impact rating | COMPLETE | Safety/financial/operational/privacy impact ratings in `docs/tara.md` Section 4 |
| 15.6 Attack path analysis | COMPLETE | Attack feasibility framework in `docs/tara.md` Section 5 |
| 15.7 Attack feasibility rating | COMPLETE | Feasibility assessment per attack path in `docs/tara.md` Section 5 |
| 15.8 Risk determination | COMPLETE | Risk matrix combining impact and feasibility in `docs/tara.md` Section 6 |
| 15.9 Risk treatment decision | COMPLETE | Accept/mitigate/transfer/avoid per risk in `docs/tara.md` Section 7 |

## Work Products Inventory

| Work Product (WP) | ISO 21434 Ref | Status | Notes |
|--------------------|---------------|--------|-------|
| Cybersecurity policy | WP-05-01 | GAP | Organizational document |
| Cybersecurity plan | WP-06-01 | GAP | Per-program plan |
| Cybersecurity case | WP-06-02 | GAP | Evidence aggregation |
| TARA report | WP-15-01 | COMPLETE | See `docs/tara.md` |
| Cybersecurity goals | WP-09-04 | PARTIAL | Derived from TARA; see `docs/iso26262-safety-case.md` for safety goals |
| Cybersecurity concept | WP-09-05 | PARTIAL | Architecture docs serve as informal concept |
| Cybersecurity requirements | WP-10-01 | PARTIAL | Implied in design; need explicit specification |
| Verification report | WP-10-03 | PRESENT | CI reports, test results |
| Vulnerability register | WP-08-03 | GAP | Need formal tracking beyond GitHub issues |
| Incident response plan | WP-08-01 | PRESENT | SECURITY.md |

## Technical Controls Present

These Craton Shield features directly satisfy ISO 21434 technical expectations:

1. **Secure communication**: AES-GCM encryption, ECDH key exchange
2. **Secure boot**: TPM attestation with PCR measurements, boot policy enforcement
3. **Secure update**: TUF/Uptane with 4-role delegation chain
4. **Intrusion detection**: CAN flood/DLC/fuzz/replay detection, Ethernet anomaly detection
5. **Access control**: UDS SecurityAccess with challenge-response, default-deny firewall
6. **Integrity verification**: SHA-256 region monitoring, constant-time comparison
7. **Tamper-evident logging**: HMAC-chained event log
8. **Key management**: Hierarchical key storage with zeroization
9. **Network firewall**: Rule-based Ethernet filtering

## Remediation Roadmap

| Priority | Gap | Effort | Target |
|----------|-----|--------|--------|
| 1 (Critical) | TARA report | Done | Complete — see `docs/tara.md` |
| 2 (High) | Cybersecurity requirements spec | 2 weeks | Q3 2026 |
| 3 (High) | Cybersecurity plan template | 1 week | Q3 2026 |
| 4 (Medium) | Cybersecurity case document | 2 weeks | Q3 2026 |
| 5 (Medium) | Vulnerability register | 1 week | Q3 2026 |
| 6 (Medium) | Formal cybersecurity policy | 1 week | Q3 2026 |
| 7 (Low) | Independent assessment | External | Q4 2026 |

**Total estimated effort: 10-12 weeks (1 engineer)**
