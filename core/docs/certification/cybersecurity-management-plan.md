# Cybersecurity Management Plan

**Project**: Craton Shield | **Standard**: ISO/SAE 21434 Clause 6.4.1 | **Version**: 0.6.0 | **Date**: 2026-03-28

---

## 1. Purpose

This document defines the cybersecurity management plan for the Craton Shield project per ISO/SAE 21434 Clause 6.4.1. It establishes governance, lifecycle processes, tool qualification, configuration management, vulnerability management, and incident response procedures applicable to each vehicle program integration.

---

## 2. Cybersecurity Governance and Responsibilities

### 2.1 Organizational Structure

| Role | Responsibility |
|------|----------------|
| Cybersecurity Manager | Overall accountability for cybersecurity activities; approves cybersecurity case and release decisions |
| Security Architect | Defines security architecture, reviews TARA, approves cryptographic design |
| Development Lead | Ensures implementation follows cybersecurity specifications; enforces coding standards |
| Verification Engineer | Executes test plan, fuzz campaigns, and penetration testing; reports findings |
| Configuration Manager | Maintains build integrity, SBOM, release signing, and artifact provenance |
| Incident Response Lead | Triages vulnerability reports, coordinates patches, manages CVE lifecycle |

### 2.2 Governance Activities

- Cybersecurity reviews at each lifecycle milestone (concept, design, implementation, verification, release)
- Periodic TARA updates when threat landscape or item definition changes
- Quarterly review of dependency audit findings and vulnerability register
- Annual cybersecurity training for all contributors

---

## 3. Development Lifecycle

### 3.1 Requirements Phase

| Activity | Output | Reference |
|----------|--------|-----------|
| Item definition and asset identification | TARA Section 1-2 | `docs/tara.md` |
| Threat analysis and risk assessment | 26 threat scenarios with risk ratings | `docs/tara.md` |
| Cybersecurity requirements derivation | Cybersecurity specifications per crate | Crate-level README files |
| Traceability | Requirements-to-test mapping | `docs/requirements-traceability-matrix.md` |

### 3.2 Design Phase

| Activity | Output | Reference |
|----------|--------|-----------|
| Architecture design | Crate decomposition with security boundaries | `docs/architecture.md` |
| Cryptographic design | Algorithm selection, key management model | `docs/certification/fips-140-3-boundary.md` |
| Interface specification | C FFI header with safety contracts | `include/cratonshield.h` |
| Safety/security co-design | ASIL-B allocation and DFA | `docs/certification/iso-26262-asil-b-assessment.md`, `docs/certification/dfa-report.md` |

### 3.3 Implementation Phase

| Activity | Control |
|----------|---------|
| Coding standard | `#![forbid(unsafe_code)]` (except audited FFI); `clippy::pedantic` enforcement |
| Memory safety | Rust ownership model; no raw pointer arithmetic in core crates |
| Constant-time operations | `subtle` crate for secret-dependent comparisons |
| Zeroization | `zeroize` derive on all key material types |
| Code review | All changes require at least one approved review before merge |

### 3.4 Verification Phase

| Activity | Method | Reference |
|----------|--------|-----------|
| Unit testing | 1,085+ tests across workspace crates | `cargo test` |
| Integration testing | 335+ tests covering attack scenarios, crypto vectors, fault injection | `tests/` directory |
| Fuzz testing | 4 fuzz targets with seed corpora | `fuzz/` directory |
| Property-based testing | Randomized invariant checking | `tests/property_tests.rs` |
| Static analysis | `clippy::pedantic`, `cargo deny`, `cargo audit` | CI pipeline |
| WCET analysis | Worst-case execution time measurement | `benches/wcet_harness.rs` |

### 3.5 Validation Phase

| Activity | Method | Reference |
|----------|--------|-----------|
| ECU validation | On-target test suite (NXP S32G3, QEMU aarch64) | `tests/ecu_validation.rs` |
| Penetration testing | Structured test plan against TARA threats | `docs/certification/penetration-test-plan.md` |
| Performance validation | Competitive benchmarks against acceptance criteria | `benches/competitive_benchmarks.rs` |

---

## 4. Tool Qualification

Per ISO 26262-8 Clause 11, all tools in the development and verification toolchain are classified and qualified.

| Tool | Purpose | TCL | Qualification Method |
|------|---------|-----|---------------------|
| rustc (Rust compiler) | Code generation | TCL2 | Increased confidence from use (widespread adoption, extensive test suite) |
| clippy | Static analysis / lint enforcement | TCL1 | Verification of output (CI enforcement, independent review) |
| cargo-audit | Known vulnerability detection | TCL1 | Verification of output (advisory DB cross-check) |
| cargo-deny | License and supply-chain policy | TCL1 | Verification of output (policy-as-code review) |
| cargo-fuzz (libFuzzer) | Fuzz testing | TCL1 | Verification of output (known-bug seeding) |

Full details: `docs/certification/tool-qualification-report.md`.

---

## 5. Configuration Management

### 5.1 Source Control

| Control | Implementation |
|---------|----------------|
| Version control system | Git |
| Hosting | GitHub with branch protection rules |
| Branch strategy | Feature branches; all merges to `main` require review and passing CI |
| Signed commits | Required for release-tagged commits |
| Toolchain pinning | `rust-toolchain.toml` pins compiler version |
| Dependency lockfile | `Cargo.lock` committed to repository |

### 5.2 Release Management

| Control | Implementation |
|---------|----------------|
| Versioning | Semantic versioning (MAJOR.MINOR.PATCH) |
| Release artifacts | Signed tarballs with SHA-256 checksums |
| SBOM | Generated per release via CI workflow |
| SLSA attestation | Build provenance recorded per CI workflow |
| Changelog | `CHANGELOG.md` maintained per release |

---

## 6. Vulnerability Management Process

### 6.1 Monitoring

- `cargo audit` runs in CI on every PR and weekly on the default branch
- Dependabot monitors all direct and transitive dependencies
- SBOM enables downstream vulnerability correlation

### 6.2 Triage and Response

| Step | Timeline | Responsible |
|------|----------|-------------|
| Vulnerability report received (via SECURITY.md process) | T+0 | Incident Response Lead |
| Acknowledgment to reporter | T+48 hours | Incident Response Lead |
| Severity assessment (CVSS scoring) | T+48 hours | Security Architect |
| Patch development | T+72 hours (target) | Development Lead |
| Internal review and testing | Before release | Verification Engineer |
| Advisory publication and release | After patch validation | Cybersecurity Manager |
| CVE assignment (if applicable) | Coordinated with reporter | Incident Response Lead |

### 6.3 Vulnerability Register

A vulnerability register is maintained tracking:
- CVE identifier (if assigned)
- Affected versions
- CVSS score
- Remediation status
- Verification evidence

---

## 7. Incident Response Process

### 7.1 Incident Classification

| Severity | Description | Response |
|----------|-------------|----------|
| Critical | Active exploitation or trivially exploitable RCE | Immediate patch; notify all known integrators |
| High | Exploitable vulnerability with significant impact | Patch within 72 hours |
| Medium | Vulnerability requiring specific preconditions | Patch in next scheduled release |
| Low | Defense-in-depth improvement or hardening | Backlog and prioritize |

### 7.2 Communication

- Security advisories published via GitHub Security Advisories
- Integrators notified through documented contact channels
- Post-incident review conducted within 14 days of resolution

### 7.3 Lessons Learned

Each incident triggers:
- TARA review to assess whether new threat scenarios are needed
- Test gap analysis to add coverage for the incident vector
- Process improvement review

---

## 8. Tailoring Per Vehicle Program

This plan serves as a template. For each vehicle program integration, the following must be tailored:

1. **Item definition** -- update TARA scope for specific vehicle architecture
2. **Interface agreements** -- define integration interfaces with OEM systems
3. **Test environment** -- specify target ECU hardware and network topology
4. **Release criteria** -- define program-specific acceptance criteria
5. **Incident contacts** -- establish program-specific escalation paths
