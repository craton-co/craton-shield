<!-- SPDX-License-Identifier: Apache-2.0 -->

# vs-report-iec62304

> **Disclaimer:** Unofficial IEC 62304 traceability helper; not an official
> IEC product. "IEC 62304" is referenced for interoperability only; this
> crate is neither endorsed nor certified by the IEC.

IEC 62304 software safety traceability matrix generator for the Craton Shield
automotive/medical cybersecurity platform.

## Overview

IEC 62304 defines the lifecycle requirements for medical device software and is
increasingly referenced in automotive safety standards. A key obligation is
**software traceability**: every software requirement must be linked to
verification activities (unit tests, integration tests, static analysis, etc.)
whose rigour depends on the software safety classification (Class A, B, or C).

This crate provides a fully `no_std`, zero-allocation engine that:

- Models software modules, requirements, test cases, and trace links.
- Automatically determines coverage status per requirement.
- Identifies compliance gaps based on the IEC 62304 safety class rules.
- Produces a `TraceabilityReport` summarising coverage, gaps, and pass/fail
  status.

## Safety classifications

| Class   | Risk level                  | Verification required                          |
|---------|-----------------------------|-------------------------------------------------|
| Class A | No injury possible          | No mandatory verification                      |
| Class B | Non-serious injury possible | Unit test, integration test, detailed design    |
| Class C | Death / serious injury      | All of Class B plus static analysis             |

## Evidence semantics: failing tests do not count

Under IEC 62304, only *passing* test executions constitute verification
evidence. A linked test case whose `passed` field is `false` is treated as
**absent** for coverage classification:

- A failing test does **not** satisfy the verification method it nominally
  targets (a failing `UnitTest` row never makes a requirement count as
  unit-tested).
- A requirement whose only linked tests have `passed == false` is reported as
  `TraceStatus::NotCovered`, not `FullyCovered`.
- The corresponding compliance gap is still recorded so the failure is
  surfaced rather than silently swept into `PartiallyCovered`.

The trace link's `test_ids` list still records every linked test (passing and
failing) so reviewers can see what verification was attempted; only the
`status` field hides failures.

## Quick start

```rust
use vs_report_iec62304::{
    TraceabilityInput, SoftwareModule, SoftwareRequirement, TestCase,
    generate_traceability,
};
use vs_report_iec62304::classification::{
    SafetyClass, LifecyclePhase, LifecycleProcess, VerificationMethod,
    RequirementCategory,
};

// 1. Populate a TraceabilityInput with modules, requirements, and test cases.
// 2. Call generate_traceability(&input, generated_at) to obtain an
//    Evidence<TraceabilityReport> envelope.
// 3. Inspect env.payload().is_compliant() and env.payload().coverage_percent().
// 4. Use env.payload().entries() / .gaps() for the valid prefix slices (no
//    ghost rows from the fixed-capacity backing arrays).
// 5. Drive per-module lifecycle moves with LifecycleProcess::transition_to,
//    which rejects illegal phase jumps per IEC 62304 clauses 5-9.
```

## Design constraints

- `#![no_std]` and `#![forbid(unsafe_code)]` -- suitable for embedded targets.
- Zero heap allocations -- all data structures use fixed-size arrays on the stack.
- Dependencies: `vs-types` (shared `VsError`) and `vs-evidence-envelope`
  (provenance metadata wrapper).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
