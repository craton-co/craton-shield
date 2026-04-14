# vs-report-iec62304

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

## Quick start

```rust
use vs_report_iec62304::{
    TraceabilityInput, SoftwareModule, SoftwareRequirement, TestCase,
    generate_traceability,
};
use vs_report_iec62304::classification::{
    SafetyClass, LifecyclePhase, VerificationMethod, RequirementCategory,
};

// 1. Populate a TraceabilityInput with modules, requirements, and test cases.
// 2. Call generate_traceability(&input) to obtain a TraceabilityReport.
// 3. Inspect report.is_compliant() and report.coverage_percent().
```

## Design constraints

- `#![no_std]` and `#![forbid(unsafe_code)]` -- suitable for embedded targets.
- Zero heap allocations -- all data structures use fixed-size arrays on the stack.
- Single dependency: `vs-types` for the shared `VsError` type.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
