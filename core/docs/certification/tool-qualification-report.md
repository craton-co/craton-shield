# Tool Qualification Report

**Project**: Craton Shield | **Standard**: ISO 26262-8 Clause 11 | **Version**: 0.6.0 | **Date**: 2026-03-15

---

## 1. Purpose

This report documents the qualification of software tools used in Craton Shield development, as required by ISO 26262-8 Clause 11 for ASIL-B software. Tool qualification ensures that tools do not introduce undetected errors into the safety-relevant software or fail to detect errors they are expected to find.

---

## 2. Classification Method

Tools are classified per ISO 26262-8 Clause 11.4.5 using two dimensions:

**Tool Impact (TI):**
- **TI 1**: Tool can introduce or fail to detect errors in a safety-relevant work product (e.g., code generators, compilers)
- **TI 2**: Tool provides information used for verification but does not modify work products

**Tool Error Detection (TD):**
- **TD 1**: High confidence that a tool error will be detected (strong downstream verification)
- **TD 2**: Medium confidence in detecting tool errors
- **TD 3**: Low confidence in detecting tool errors

**Tool Confidence Level (TCL):**

| | TD 1 | TD 2 | TD 3 |
|--|------|------|------|
| **TI 1** | TCL1 | TCL2 | TCL3 |
| **TI 2** | TCL1 | TCL1 | TCL2 |

---

## 3. Tool Inventory and Classification

### 3.1 Rust Compiler (rustc)

| Field | Value |
|-------|-------|
| **Tool Name** | rustc (Rust compiler) |
| **Version** | 1.82.0 or later (stable channel) |
| **Supplier** | The Rust Project (open source, governed by the Rust Foundation) |
| **Purpose** | Compiles Rust source code into machine code for target platforms; enforces memory safety, type safety, and borrow-checking rules at compile time |
| **Tool Impact** | TI 1 — generates executable code; a compiler bug could produce incorrect machine code |
| **Tool Detection** | TD 2 — output is verified by 1,014 unit tests + 180 integration tests + fuzz targets, but not all generated code paths are exercised |
| **Tool Confidence Level** | **TCL2** |

**Qualification Method** (ISO 26262-8 Clause 11.4.7, Method 1 — Increased confidence from use):

| Evidence | Description |
|----------|-------------|
| Validation suite | Craton Shield's test suite (1,194 tests) is executed on every build for each supported target. Tests cover safety requirements SSR-01 through SSR-16. |
| Community audit | The Rust compiler is used by millions of projects and undergoes continuous community testing. The Rust project maintains over 18,000 compiler test cases. Known miscompilation bugs are tracked and regression-tested. |
| Stable release channel | Only stable releases are used (never nightly). Stable releases undergo a 6-week beta period before promotion. |
| Cross-compilation verification | Craton Shield is built and tested on three targets (x86_64-linux, aarch64-linux, thumbv7em-none-eabihf); target-divergent behavior would be detected. |
| Deterministic builds | Release builds use pinned toolchain versions via `rust-toolchain.toml` to ensure reproducibility. |

**Residual Risk**: A compiler bug affecting a code path not covered by tests could produce incorrect behavior. Mitigation: maintain high test coverage (target >=80% line coverage) and monitor Rust compiler issue tracker for safety-relevant bugs.

---

### 3.2 Clippy

| Field | Value |
|-------|-------|
| **Tool Name** | Clippy (Rust linter) |
| **Version** | Bundled with rustc (same version as compiler) |
| **Supplier** | The Rust Project |
| **Purpose** | Static analysis tool that detects common programming errors, style violations, and suspicious patterns; enforced in pedantic mode with `deny(warnings)` |
| **Tool Impact** | TI 2 — advisory only; does not modify source code or generated output |
| **Tool Detection** | TD 1 — Clippy findings are reviewed by developers; false negatives (missed warnings) do not introduce errors, only fail to detect them; code correctness is verified independently by testing |
| **Tool Confidence Level** | **TCL1** |

**Qualification Method** (ISO 26262-8 Clause 11.4.7 — TCL1, no additional qualification required):

Clippy is an advisory tool whose output is consumed by human reviewers. It does not generate or transform code. A Clippy false negative (failing to warn about an issue) is detected by code review and testing. No additional qualification measures are required for TCL1 tools.

---

### 3.3 cargo-llvm-cov

| Field | Value |
|-------|-------|
| **Tool Name** | cargo-llvm-cov |
| **Version** | 0.6.x or later |
| **Supplier** | Open source (Taiki Endo) |
| **Purpose** | Measures code coverage (line and branch) by instrumenting test execution via LLVM source-based coverage; produces coverage reports for safety analysis |
| **Tool Impact** | TI 2 — measures coverage of existing tests; does not modify source or production binaries |
| **Tool Detection** | TD 1 — coverage reports are reviewed by developers; incorrect coverage data (over-reporting) would not introduce errors into the product; under-reporting is conservative (leads to more testing, not less) |
| **Tool Confidence Level** | **TCL1** |

**Qualification Method** (ISO 26262-8 Clause 11.4.7 — TCL1, no additional qualification required):

cargo-llvm-cov is a measurement tool. It instruments test builds (not production builds) and reports which lines were executed. Coverage data informs testing decisions but does not affect the production binary. A tool error resulting in under-reported coverage would lead to additional testing (conservative). Over-reported coverage is detectable by manual inspection of coverage reports against source code.

---

### 3.4 cargo-audit

| Field | Value |
|-------|-------|
| **Tool Name** | cargo-audit |
| **Version** | Latest |
| **Supplier** | RustSec (open source advisory database) |
| **Purpose** | Scans `Cargo.lock` for dependencies with known security vulnerabilities listed in the RustSec Advisory Database |
| **Tool Impact** | TI 2 — advisory only; reports known vulnerabilities but does not modify code |
| **Tool Detection** | TD 1 — a false negative (missed vulnerability) is bounded by the RustSec database completeness; positive findings are verified by reviewing the advisory; the tool does not produce false positives that could introduce errors |
| **Tool Confidence Level** | **TCL1** |

**Qualification Method** (ISO 26262-8 Clause 11.4.7 — TCL1, no additional qualification required):

cargo-audit is a vulnerability scanner. It compares dependency versions against a known-vulnerability database. A tool error (failing to flag a vulnerability) results in a missed detection, which is mitigated by periodic manual review of dependency changelogs and the broader security community. The tool does not modify any work product.

---

### 3.5 GitHub Actions CI

| Field | Value |
|-------|-------|
| **Tool Name** | GitHub Actions (CI/CD platform) |
| **Version** | GitHub-hosted runners (Ubuntu latest) |
| **Supplier** | GitHub (Microsoft) |
| **Purpose** | Automates build, test, lint, coverage, and audit pipelines; enforces branch protection (CI pass required for merge) |
| **Tool Impact** | TI 2 — orchestrates tool execution but does not transform code; build commands are defined in workflow YAML files under version control |
| **Tool Detection** | TD 1 — CI pipeline failures are visible to all developers; a CI pass/fail decision is verified by the test results it reports; CI does not modify source or binary artifacts beyond what the underlying tools (rustc, clippy, etc.) produce |
| **Tool Confidence Level** | **TCL1** |

**Qualification Method** (ISO 26262-8 Clause 11.4.7 — TCL1, no additional qualification required):

GitHub Actions is a build automation platform. It executes commands defined in version-controlled workflow files. The CI system does not transform or generate code; it invokes the Rust toolchain (qualified separately above). A CI false pass (reporting success when a test failed) is detectable by reviewing build logs and is mitigated by the deterministic nature of the test commands. Workflow definitions are reviewed as part of the standard code review process.

---

## 4. Summary

| Tool | Version | TI | TD | TCL | Qualification Method | Status |
|------|---------|----|----|-----|---------------------|--------|
| rustc | 1.82+ | TI 1 | TD 2 | **TCL2** | Validation suite + community audit + cross-compilation | Qualified |
| Clippy | Bundled with rustc | TI 2 | TD 1 | **TCL1** | No additional qualification required | Qualified |
| cargo-llvm-cov | 0.6+ | TI 2 | TD 1 | **TCL1** | No additional qualification required | Qualified |
| cargo-audit | Latest | TI 2 | TD 1 | **TCL1** | No additional qualification required | Qualified |
| GitHub Actions CI | N/A | TI 2 | TD 1 | **TCL1** | No additional qualification required | Qualified |

---

## 5. Conclusion

All tools used in Craton Shield development have been classified per ISO 26262-8 Clause 11. The Rust compiler (rustc) is the only tool classified at TCL2 due to its role in code generation (TI 1). It is qualified through a combination of the project's comprehensive test suite (1,194 tests across 3 targets), the Rust project's own validation infrastructure, and the use of stable releases with pinned toolchain versions.

All remaining tools (Clippy, cargo-llvm-cov, cargo-audit, GitHub Actions) are classified at TCL1 as advisory or measurement tools (TI 2) with high detection confidence (TD 1). Per ISO 26262-8 Clause 11.4.6, TCL1 tools do not require additional qualification measures beyond their intended use.

No tool qualification gaps have been identified for ASIL-B compliance.

---

## 6. References

- ISO 26262-8:2018, Clause 11 — Qualification of software tools
- ISO 26262-8:2018, Table 4 — Determination of the required Tool Confidence Level
- Craton Shield Safety Case (`docs/iso26262-safety-case.md`), Section 8 — Tool Qualification
- Craton Shield ASIL-B Pre-Assessment (`docs/certification/iso-26262-asil-b-assessment.md`)
