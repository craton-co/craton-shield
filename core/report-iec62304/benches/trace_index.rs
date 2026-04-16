// SPDX-License-Identifier: Apache-2.0
//! Criterion bench for the IEC 62304 traceability inverted-index optimisation.
//!
//! Pre-fix: each requirement scanned all `test_case_count` tests, yielding
//! O(R·T) ≈ 8192 visits at the maxima (R = 64, T = 128).
//!
//! Post-fix: a one-shot inverted index reduces per-requirement work to the
//! size of that requirement's bucket, plus an O(R log R) sort + O(T log R)
//! build at startup. Expected total work drops to roughly O(R + T log R)
//! ≈ a few hundred operations.
//!
//! Run with:  `cargo bench -p vs-report-iec62304 --features bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vs_report_iec62304::{
    classification::{LifecyclePhase, RequirementCategory, SafetyClass, VerificationMethod},
    generate_traceability, SoftwareModule, SoftwareRequirement, TestCase, TraceabilityInput,
    MAX_MODULES, MAX_REQUIREMENTS, MAX_TEST_CASES,
};

fn make_module(id: u16) -> SoftwareModule {
    SoftwareModule {
        id,
        name: [0u8; 32],
        name_len: 0,
        safety_class: SafetyClass::ClassB,
        phase: LifecyclePhase::Development,
        version_major: 0,
        version_minor: 1,
        version_patch: 0,
    }
}

fn make_req(id: u16, module_id: u16) -> SoftwareRequirement {
    SoftwareRequirement {
        id,
        category: RequirementCategory::Functional,
        module_id,
        safety_class: SafetyClass::ClassB,
        label: [0u8; 48],
        label_len: 0,
    }
}

fn make_tc(id: u16, requirement_id: u16, method: VerificationMethod) -> TestCase {
    TestCase {
        id,
        requirement_id,
        method,
        passed: true,
        label: [0u8; 48],
        label_len: 0,
    }
}

fn full_input() -> TraceabilityInput {
    // Build a worst-case input: every slot populated, every test pointing at
    // a real requirement so the inner loops actually exercise the index.
    let mut input = TraceabilityInput {
        modules: [make_module(1); MAX_MODULES],
        module_count: 1,
        requirements: [make_req(0, 1); MAX_REQUIREMENTS],
        requirement_count: MAX_REQUIREMENTS,
        test_cases: [make_tc(0, 0, VerificationMethod::UnitTest); MAX_TEST_CASES],
        test_case_count: MAX_TEST_CASES,
    };
    for r in 0..MAX_REQUIREMENTS {
        input.requirements[r] = make_req((r + 1) as u16, 1);
    }
    for t in 0..MAX_TEST_CASES {
        let req_id = ((t % MAX_REQUIREMENTS) + 1) as u16;
        let method = match t % 3 {
            0 => VerificationMethod::UnitTest,
            1 => VerificationMethod::IntegrationTest,
            _ => VerificationMethod::StaticAnalysis,
        };
        input.test_cases[t] = make_tc(t as u16 + 1, req_id, method);
    }
    input
}

fn bench_generate(c: &mut Criterion) {
    let input = full_input();
    c.bench_function("iec62304_generate_traceability_full", |b| {
        b.iter(|| {
            let report = generate_traceability(black_box(&input), 0u64).expect("traceability");
            black_box(report);
        });
    });
}

criterion_group!(benches, bench_generate);
criterion_main!(benches);
