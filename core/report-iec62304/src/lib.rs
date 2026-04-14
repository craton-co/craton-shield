// SPDX-License-Identifier: Apache-2.0
//! IEC 62304 software safety traceability matrix generator.
//!
//! Provides a `no_std`, zero-allocation engine for building and evaluating
//! software traceability matrices as required by IEC 62304.  The primary
//! entry point is [`generate_traceability`], which consumes a
//! [`TraceabilityInput`] and produces a [`TraceabilityReport`] detailing
//! coverage status and compliance gaps.

#![no_std]
#![forbid(unsafe_code)]

pub mod classification;

use classification::{LifecyclePhase, RequirementCategory, SafetyClass, VerificationMethod};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of software modules that can be tracked.
pub const MAX_MODULES: usize = 32;

/// Maximum number of software requirements.
pub const MAX_REQUIREMENTS: usize = 64;

/// Maximum number of test cases.
pub const MAX_TEST_CASES: usize = 128;

/// Maximum number of trace links (test case references) per requirement.
pub const MAX_TRACES_PER_REQ: usize = 8;

/// Returns `true` if the given counts are within the capacity limits of an
/// IEC 62304 traceability assessment.
#[must_use]
pub const fn is_input_valid_size(
    module_count: usize,
    requirement_count: usize,
    test_case_count: usize,
) -> bool {
    module_count <= MAX_MODULES
        && requirement_count <= MAX_REQUIREMENTS
        && test_case_count <= MAX_TEST_CASES
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A software module (software item) tracked in the traceability matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareModule {
    /// Unique module identifier.
    pub id: u16,
    /// UTF-8 module name, null-padded.
    pub name: [u8; 32],
    /// Length of the valid portion of `name`.
    pub name_len: u8,
    /// IEC 62304 safety classification.
    pub safety_class: SafetyClass,
    /// Current lifecycle phase.
    pub phase: LifecyclePhase,
    /// Semantic version -- major component.
    pub version_major: u8,
    /// Semantic version -- minor component.
    pub version_minor: u8,
    /// Semantic version -- patch component.
    pub version_patch: u8,
}

/// A software requirement linked to a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareRequirement {
    /// Unique requirement identifier.
    pub id: u16,
    /// Requirement category.
    pub category: RequirementCategory,
    /// Identifier of the parent [`SoftwareModule`].
    pub module_id: u16,
    /// Safety class (inherited from module or explicitly assigned).
    pub safety_class: SafetyClass,
    /// UTF-8 requirement label, null-padded.
    pub label: [u8; 48],
    /// Length of the valid portion of `label`.
    pub label_len: u8,
}

/// A test case that verifies a software requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestCase {
    /// Unique test case identifier.
    pub id: u16,
    /// Identifier of the [`SoftwareRequirement`] this test verifies.
    pub requirement_id: u16,
    /// Verification method employed.
    pub method: VerificationMethod,
    /// Whether the test case passed.
    pub passed: bool,
    /// UTF-8 test case label, null-padded.
    pub label: [u8; 48],
    /// Length of the valid portion of `label`.
    pub label_len: u8,
}

/// A trace link connecting a requirement to its verification test cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceLink {
    /// Requirement being traced.
    pub requirement_id: u16,
    /// Test case identifiers linked to this requirement.
    pub test_ids: [u16; MAX_TRACES_PER_REQ],
    /// Number of valid entries in `test_ids`.
    pub test_count: u8,
    /// Overall coverage status.
    pub status: TraceStatus,
}

/// Coverage status of a trace link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    /// All required verification methods are covered by passing tests.
    FullyCovered,
    /// Some but not all required verification methods are covered.
    PartiallyCovered,
    /// No test cases reference this requirement.
    NotCovered,
    /// Verification is not applicable (e.g. Class A with no mandated tests).
    NotApplicable,
}

/// Input to the traceability matrix generator.
#[derive(Clone)]
pub struct TraceabilityInput {
    /// Registered software modules.
    pub modules: [SoftwareModule; MAX_MODULES],
    /// Number of valid entries in `modules`.
    pub module_count: usize,
    /// Registered software requirements.
    pub requirements: [SoftwareRequirement; MAX_REQUIREMENTS],
    /// Number of valid entries in `requirements`.
    pub requirement_count: usize,
    /// Registered test cases.
    pub test_cases: [TestCase; MAX_TEST_CASES],
    /// Number of valid entries in `test_cases`.
    pub test_case_count: usize,
}

/// A compliance gap identified during traceability analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplianceGap {
    /// Requirement that has a gap.
    pub requirement_id: u16,
    /// Safety class of the requirement.
    pub safety_class: SafetyClass,
    /// Verification method that is missing.
    pub missing_method: VerificationMethod,
}

/// Result of the traceability matrix analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceabilityReport {
    /// Trace links for each requirement.
    pub traces: [TraceLink; MAX_REQUIREMENTS],
    /// Number of valid entries in `traces`.
    pub trace_count: usize,
    /// Identified compliance gaps.
    pub gaps: [ComplianceGap; MAX_REQUIREMENTS],
    /// Number of valid entries in `gaps`.
    pub gap_count: usize,
    /// Total number of requirements analysed.
    pub total_requirements: usize,
    /// Number of fully covered requirements.
    pub fully_covered: usize,
    /// Number of partially covered requirements.
    pub partially_covered: usize,
    /// Number of uncovered requirements.
    pub not_covered: usize,
    /// Requirements classified as Class A.
    pub class_a_count: usize,
    /// Requirements classified as Class B.
    pub class_b_count: usize,
    /// Requirements classified as Class C.
    pub class_c_count: usize,
    /// Whether every test case in the input passed.
    pub all_tests_passing: bool,
}

impl TraceabilityReport {
    /// Returns `true` if there are no compliance gaps and all tests pass.
    #[must_use]
    pub const fn is_compliant(&self) -> bool {
        self.gap_count == 0 && self.all_tests_passing
    }

    /// Percentage of requirements that are fully covered (0--100).
    ///
    /// Returns 0 when there are no requirements.
    #[must_use]
    pub const fn coverage_percent(&self) -> u8 {
        if self.total_requirements == 0 {
            return 0;
        }
        let pct = (self.fully_covered * 100) / self.total_requirements;
        if pct > 100 {
            100
        } else {
            pct as u8
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in module catalog
// ---------------------------------------------------------------------------

/// Pre-populated catalog of Craton Shield software modules for IEC 62304
/// traceability.
pub const CRATON_SHIELD_MODULES: [SoftwareModule; 18] = [
    // 8 chars + 24 pad = 32
    make_module(
        1,
        b"vs-types\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        8,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    // 9 chars + 23 pad = 32
    make_module(
        2,
        b"vs-crypto\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        9,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    // 14 chars + 18 pad = 32
    make_module(
        3,
        b"vs-key-manager\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    // 14 chars + 18 pad = 32
    make_module(
        4,
        b"vs-secure-boot\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    // 16 chars + 16 pad = 32
    make_module(
        5,
        b"vs-policy-engine\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        16,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 15 chars + 17 pad = 32
    make_module(
        6,
        b"vs-event-logger\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        15,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 14 chars + 18 pad = 32
    make_module(
        7,
        b"vs-can-monitor\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 14 chars + 18 pad = 32
    make_module(
        8,
        b"vs-eth-monitor\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 13 chars + 19 pad = 32
    make_module(
        9,
        b"vs-ids-engine\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        13,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 10 chars + 22 pad = 32
    make_module(
        10,
        b"vs-anomaly\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    // 12 chars + 20 pad = 32
    make_module(
        11,
        b"vs-integrity\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        12,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    // 16 chars + 16 pad = 32
    make_module(
        12,
        b"vs-ota-validator\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        16,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    // 8 chars + 24 pad = 32
    make_module(
        13,
        b"vs-netfw\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        8,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 10 chars + 22 pad = 32
    make_module(
        14,
        b"vs-runtime\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 10 chars + 22 pad = 32
    make_module(
        15,
        b"vs-storage\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    // 6 chars + 26 pad = 32
    make_module(
        16,
        b"vs-hal\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        6,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 12 chars + 20 pad = 32
    make_module(
        17,
        b"vs-hal-linux\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        12,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    // 6 chars + 26 pad = 32
    make_module(
        18,
        b"vs-ffi\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        6,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
];

/// Helper to construct a [`SoftwareModule`] for the built-in catalog.
const fn make_module(
    id: u16,
    name: &[u8; 32],
    name_len: u8,
    safety_class: SafetyClass,
    phase: LifecyclePhase,
) -> SoftwareModule {
    SoftwareModule {
        id,
        name: *name,
        name_len,
        safety_class,
        phase,
        version_major: 0,
        version_minor: 6,
        version_patch: 0,
    }
}

// ---------------------------------------------------------------------------
// Traceability engine
// ---------------------------------------------------------------------------

/// Generate an IEC 62304 traceability report from the given input.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if any count exceeds its maximum or if a
/// requirement references a non-existent module.
pub fn generate_traceability(input: &TraceabilityInput) -> Result<TraceabilityReport, VsError> {
    validate_input(input)?;

    let all_tests_passing = check_all_tests_passing(input);

    let mut report = TraceabilityReport {
        traces: [TraceLink {
            requirement_id: 0,
            test_ids: [0u16; MAX_TRACES_PER_REQ],
            test_count: 0,
            status: TraceStatus::NotCovered,
        }; MAX_REQUIREMENTS],
        trace_count: 0,
        gaps: [ComplianceGap {
            requirement_id: 0,
            safety_class: SafetyClass::ClassA,
            missing_method: VerificationMethod::UnitTest,
        }; MAX_REQUIREMENTS],
        gap_count: 0,
        total_requirements: input.requirement_count,
        fully_covered: 0,
        partially_covered: 0,
        not_covered: 0,
        class_a_count: 0,
        class_b_count: 0,
        class_c_count: 0,
        all_tests_passing,
    };

    let mut ri = 0;
    while ri < input.requirement_count {
        process_requirement(input, &input.requirements[ri], &mut report);
        ri += 1;
    }

    Ok(report)
}

/// Validate that input counts are within bounds and all module references
/// are valid.
fn validate_input(input: &TraceabilityInput) -> Result<(), VsError> {
    if input.module_count > MAX_MODULES
        || input.requirement_count > MAX_REQUIREMENTS
        || input.test_case_count > MAX_TEST_CASES
    {
        return Err(VsError::InvalidInput);
    }

    let mut i = 0;
    while i < input.requirement_count {
        if !module_exists(input, input.requirements[i].module_id) {
            return Err(VsError::InvalidInput);
        }
        i += 1;
    }

    Ok(())
}

/// Check whether a module with the given `id` exists in the input.
fn module_exists(input: &TraceabilityInput, id: u16) -> bool {
    let mut i = 0;
    while i < input.module_count {
        if input.modules[i].id == id {
            return true;
        }
        i += 1;
    }
    false
}

/// Returns `true` if every test case in the input passed.
fn check_all_tests_passing(input: &TraceabilityInput) -> bool {
    let mut t = 0;
    while t < input.test_case_count {
        if !input.test_cases[t].passed {
            return false;
        }
        t += 1;
    }
    true
}

/// Analyse a single requirement: build its trace link, update coverage
/// counters, and record any compliance gaps.
#[allow(clippy::similar_names)]
fn process_requirement(
    input: &TraceabilityInput,
    req: &SoftwareRequirement,
    report: &mut TraceabilityReport,
) {
    // Count by class
    match req.safety_class {
        SafetyClass::ClassA => report.class_a_count += 1,
        SafetyClass::ClassB => report.class_b_count += 1,
        SafetyClass::ClassC => report.class_c_count += 1,
    }

    // Collect test cases for this requirement
    let mut link = TraceLink {
        requirement_id: req.id,
        test_ids: [0u16; MAX_TRACES_PER_REQ],
        test_count: 0,
        status: TraceStatus::NotCovered,
    };

    let mut has_unit = false;
    let mut has_integration = false;
    let mut has_static = false;

    let mut ti = 0;
    while ti < input.test_case_count {
        let tc = &input.test_cases[ti];
        if tc.requirement_id == req.id && (link.test_count as usize) < MAX_TRACES_PER_REQ {
            link.test_ids[link.test_count as usize] = tc.id;
            link.test_count = link.test_count.saturating_add(1);

            match tc.method {
                VerificationMethod::UnitTest => has_unit = true,
                VerificationMethod::IntegrationTest => has_integration = true,
                VerificationMethod::StaticAnalysis => has_static = true,
                VerificationMethod::SystemTest
                | VerificationMethod::CodeReview
                | VerificationMethod::FormalVerification => {}
            }
        }
        ti += 1;
    }

    // Determine coverage status
    if link.test_count == 0 {
        link.status = TraceStatus::NotCovered;
        report.not_covered += 1;
    } else {
        let all_methods_present = (!req.safety_class.requires_unit_testing() || has_unit)
            && (!req.safety_class.requires_integration_testing() || has_integration)
            && (!req.safety_class.requires_static_analysis() || has_static);

        if all_methods_present {
            link.status = TraceStatus::FullyCovered;
            report.fully_covered += 1;
        } else {
            link.status = TraceStatus::PartiallyCovered;
            report.partially_covered += 1;
        }
    }

    report.traces[report.trace_count] = link;
    report.trace_count += 1;

    // Record compliance gaps
    record_gap_if_missing(req, VerificationMethod::UnitTest, has_unit, report);
    record_gap_if_missing(
        req,
        VerificationMethod::IntegrationTest,
        has_integration,
        report,
    );
    record_gap_if_missing(req, VerificationMethod::StaticAnalysis, has_static, report);
}

/// Record a compliance gap if the requirement's safety class mandates the
/// given method and the method was not found.
fn record_gap_if_missing(
    req: &SoftwareRequirement,
    method: VerificationMethod,
    present: bool,
    report: &mut TraceabilityReport,
) {
    let required = match method {
        VerificationMethod::UnitTest => req.safety_class.requires_unit_testing(),
        VerificationMethod::IntegrationTest => req.safety_class.requires_integration_testing(),
        VerificationMethod::StaticAnalysis => req.safety_class.requires_static_analysis(),
        VerificationMethod::SystemTest
        | VerificationMethod::CodeReview
        | VerificationMethod::FormalVerification => false,
    };

    if required && !present && report.gap_count < MAX_REQUIREMENTS {
        report.gaps[report.gap_count] = ComplianceGap {
            requirement_id: req.id,
            safety_class: req.safety_class,
            missing_method: method,
        };
        report.gap_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use classification::{LifecyclePhase, RequirementCategory, SafetyClass, VerificationMethod};

    /// Create a zeroed `TraceabilityInput`.
    fn empty_input() -> TraceabilityInput {
        TraceabilityInput {
            modules: [SoftwareModule {
                id: 0,
                name: [0u8; 32],
                name_len: 0,
                safety_class: SafetyClass::ClassA,
                phase: LifecyclePhase::Development,
                version_major: 0,
                version_minor: 0,
                version_patch: 0,
            }; MAX_MODULES],
            module_count: 0,
            requirements: [SoftwareRequirement {
                id: 0,
                category: RequirementCategory::Functional,
                module_id: 0,
                safety_class: SafetyClass::ClassA,
                label: [0u8; 48],
                label_len: 0,
            }; MAX_REQUIREMENTS],
            requirement_count: 0,
            test_cases: [TestCase {
                id: 0,
                requirement_id: 0,
                method: VerificationMethod::UnitTest,
                passed: true,
                label: [0u8; 48],
                label_len: 0,
            }; MAX_TEST_CASES],
            test_case_count: 0,
        }
    }

    fn make_test_module(id: u16, safety_class: SafetyClass) -> SoftwareModule {
        SoftwareModule {
            id,
            name: [0u8; 32],
            name_len: 0,
            safety_class,
            phase: LifecyclePhase::Development,
            version_major: 0,
            version_minor: 1,
            version_patch: 0,
        }
    }

    fn make_test_requirement(
        id: u16,
        module_id: u16,
        safety_class: SafetyClass,
    ) -> SoftwareRequirement {
        SoftwareRequirement {
            id,
            category: RequirementCategory::Functional,
            module_id,
            safety_class,
            label: [0u8; 48],
            label_len: 0,
        }
    }

    fn make_test_case(
        id: u16,
        requirement_id: u16,
        method: VerificationMethod,
        passed: bool,
    ) -> TestCase {
        TestCase {
            id,
            requirement_id,
            method,
            passed,
            label: [0u8; 48],
            label_len: 0,
        }
    }

    // 1. Empty input produces empty report with 0 coverage.
    #[test]
    fn empty_input_produces_empty_report() {
        let input = empty_input();
        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.total_requirements, 0);
        assert_eq!(report.fully_covered, 0);
        assert_eq!(report.gap_count, 0);
        assert_eq!(report.coverage_percent(), 0);
        assert!(report.all_tests_passing);
        assert!(report.is_compliant());
    }

    // 2. Single module + requirement + passing test gives FullyCovered, 100%.
    #[test]
    fn single_fully_covered_requirement() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 2;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.fully_covered, 1);
        assert_eq!(report.coverage_percent(), 100);
        assert_eq!(report.gap_count, 0);
        assert!(report.is_compliant());
    }

    // 3. Requirement with no tests gives NotCovered; Class B produces gaps.
    #[test]
    fn no_tests_class_b_produces_gaps() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.not_covered, 1);
        assert_eq!(report.traces[0].status, TraceStatus::NotCovered);
        // Class B requires unit test + integration test = 2 gaps
        assert_eq!(report.gap_count, 2);
        assert!(!report.is_compliant());
    }

    // 4. Class A with no tests gives NotCovered but no gap.
    #[test]
    fn class_a_no_tests_no_gap() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.not_covered, 1);
        assert_eq!(report.gap_count, 0);
        assert!(report.is_compliant());
    }

    // 5. Class C requirement missing static analysis produces gap.
    #[test]
    fn class_c_missing_static_analysis_gap() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        // Provide unit test and integration test but no static analysis
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 2;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.partially_covered, 1);
        assert_eq!(report.gap_count, 1);
        assert_eq!(
            report.gaps[0].missing_method,
            VerificationMethod::StaticAnalysis
        );
        assert_eq!(report.gaps[0].safety_class, SafetyClass::ClassC);
        assert!(!report.is_compliant());
    }

    // 6. Multiple requirements with mixed coverage.
    #[test]
    fn mixed_coverage_percentages() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.modules[1] = make_test_module(2, SafetyClass::ClassB);
        input.module_count = 2;

        // Req 10: Class A, will have a test -> FullyCovered (Class A has no
        // mandatory methods, so any test makes it fully covered)
        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        // Req 11: Class B, no tests -> NotCovered
        input.requirements[1] = make_test_requirement(11, 2, SafetyClass::ClassB);
        // Req 12: Class B, fully covered
        input.requirements[2] = make_test_requirement(12, 2, SafetyClass::ClassB);
        input.requirement_count = 3;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 12, VerificationMethod::UnitTest, true);
        input.test_cases[2] = make_test_case(102, 12, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 3;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.total_requirements, 3);
        assert_eq!(report.fully_covered, 2);
        assert_eq!(report.not_covered, 1);
        // 2/3 = 66%
        assert_eq!(report.coverage_percent(), 66);
        assert_eq!(report.class_a_count, 1);
        assert_eq!(report.class_b_count, 2);
    }

    // 7. All tests passing vs one failing.
    #[test]
    fn all_tests_passing_flag() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, false);
        input.test_case_count = 2;

        let report = generate_traceability(&input).unwrap();

        assert!(!report.all_tests_passing);
        assert!(!report.is_compliant());
    }

    // 8. is_compliant returns false when gaps exist.
    #[test]
    fn is_compliant_false_with_gaps() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        // No tests at all -> gaps for unit, integration, static analysis
        let report = generate_traceability(&input).unwrap();

        assert!(!report.is_compliant());
        assert!(report.gap_count > 0);
    }

    // 9. Module count exceeds MAX produces InvalidInput.
    #[test]
    fn module_count_exceeds_max() {
        let mut input = empty_input();
        input.module_count = MAX_MODULES + 1;

        let result = generate_traceability(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // 10. Built-in catalog has correct count and classifications.
    #[test]
    fn craton_shield_catalog_correctness() {
        assert_eq!(CRATON_SHIELD_MODULES.len(), 18);

        // vs-types is Class A
        assert_eq!(CRATON_SHIELD_MODULES[0].safety_class, SafetyClass::ClassA);
        assert_eq!(CRATON_SHIELD_MODULES[0].id, 1);

        // vs-crypto is Class C
        assert_eq!(CRATON_SHIELD_MODULES[1].safety_class, SafetyClass::ClassC);
        assert_eq!(CRATON_SHIELD_MODULES[1].id, 2);

        // vs-policy-engine is Class B
        assert_eq!(CRATON_SHIELD_MODULES[4].safety_class, SafetyClass::ClassB);
        assert_eq!(CRATON_SHIELD_MODULES[4].id, 5);

        // vs-anomaly is Class A
        assert_eq!(CRATON_SHIELD_MODULES[9].safety_class, SafetyClass::ClassA);

        // vs-storage is Class A
        assert_eq!(CRATON_SHIELD_MODULES[14].safety_class, SafetyClass::ClassA);

        // Class C modules are in Verification phase, others in Development
        for m in &CRATON_SHIELD_MODULES {
            match m.safety_class {
                SafetyClass::ClassC => assert_eq!(m.phase, LifecyclePhase::Verification),
                _ => assert_eq!(m.phase, LifecyclePhase::Development),
            }
        }
    }

    // 11. TraceLink correctly counts test_ids per requirement.
    #[test]
    fn trace_link_test_id_count() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::SystemTest, true);
        input.test_case_count = 3;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.traces[0].test_count, 3);
        assert_eq!(report.traces[0].test_ids[0], 100);
        assert_eq!(report.traces[0].test_ids[1], 101);
        assert_eq!(report.traces[0].test_ids[2], 102);
        assert_eq!(report.traces[0].status, TraceStatus::FullyCovered);
    }

    // 12. Invalid module reference produces error.
    #[test]
    fn invalid_module_reference() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        // Requirement references module_id 99 which does not exist
        input.requirements[0] = make_test_requirement(10, 99, SafetyClass::ClassA);
        input.requirement_count = 1;

        let result = generate_traceability(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // 13. Safety class method checks.
    #[test]
    fn safety_class_method_requirements() {
        assert!(!SafetyClass::ClassA.requires_unit_testing());
        assert!(!SafetyClass::ClassA.requires_static_analysis());

        assert!(SafetyClass::ClassB.requires_unit_testing());
        assert!(SafetyClass::ClassB.requires_integration_testing());
        assert!(!SafetyClass::ClassB.requires_static_analysis());

        assert!(SafetyClass::ClassC.requires_unit_testing());
        assert!(SafetyClass::ClassC.requires_integration_testing());
        assert!(SafetyClass::ClassC.requires_static_analysis());
        assert!(SafetyClass::ClassC.requires_detailed_design());
        assert!(SafetyClass::ClassC.requires_traceability());
    }

    #[test]
    fn test_class_c_full_traceability() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        // Provide all three required methods: unit, integration, and static analysis
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::StaticAnalysis, true);
        input.test_case_count = 3;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.fully_covered, 1);
        assert_eq!(report.traces[0].status, TraceStatus::FullyCovered);
        assert_eq!(report.gap_count, 0);
        assert!(report.is_compliant());
    }

    #[test]
    fn test_multiple_modules_mixed_classes() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.modules[1] = make_test_module(2, SafetyClass::ClassB);
        input.modules[2] = make_test_module(3, SafetyClass::ClassC);
        input.module_count = 3;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 2, SafetyClass::ClassB);
        input.requirements[2] = make_test_requirement(12, 3, SafetyClass::ClassC);
        input.requirement_count = 3;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.class_a_count, 1);
        assert_eq!(report.class_b_count, 1);
        assert_eq!(report.class_c_count, 1);
        assert_eq!(report.total_requirements, 3);
    }

    #[test]
    fn test_requirement_count_exceeds_max() {
        let mut input = empty_input();
        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;
        input.requirement_count = MAX_REQUIREMENTS + 1;

        let result = generate_traceability(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_test_case_count_exceeds_max() {
        let mut input = empty_input();
        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;
        input.test_case_count = MAX_TEST_CASES + 1;

        let result = generate_traceability(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_coverage_percent_100() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 1, SafetyClass::ClassA);
        input.requirement_count = 2;

        // Class A has no mandatory methods, so any test makes it FullyCovered
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 11, VerificationMethod::UnitTest, true);
        input.test_case_count = 2;

        let report = generate_traceability(&input).unwrap();
        assert_eq!(report.coverage_percent(), 100);
    }

    #[test]
    fn test_coverage_percent_0() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 1, SafetyClass::ClassA);
        input.requirement_count = 2;

        // No test cases at all
        let report = generate_traceability(&input).unwrap();
        assert_eq!(report.coverage_percent(), 0);
    }

    #[test]
    fn test_coverage_percent_partial() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 1, SafetyClass::ClassA);
        input.requirement_count = 2;

        // Only cover the first requirement
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let report = generate_traceability(&input).unwrap();
        assert_eq!(report.coverage_percent(), 50);
    }

    #[test]
    fn test_max_traces_per_req_limit() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        // Add more than MAX_TRACES_PER_REQ test cases for the same requirement
        let total = MAX_TRACES_PER_REQ + 4;
        for i in 0..total {
            input.test_cases[i] =
                make_test_case((100 + i) as u16, 10, VerificationMethod::UnitTest, true);
        }
        input.test_case_count = total;

        let report = generate_traceability(&input).unwrap();

        // The trace link should be capped at MAX_TRACES_PER_REQ
        assert_eq!(
            report.traces[0].test_count as usize, MAX_TRACES_PER_REQ,
            "test_count should be capped at MAX_TRACES_PER_REQ"
        );
    }

    #[test]
    fn test_verification_methods_integration() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        // Only provide integration test (Class B also needs unit test)
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 1;

        let report = generate_traceability(&input).unwrap();

        // IntegrationTest is recognized -- partially covered because unit test
        // is still missing.
        assert_eq!(report.partially_covered, 1);
        assert_eq!(report.traces[0].status, TraceStatus::PartiallyCovered);
        // Gap should be for UnitTest, not IntegrationTest
        let has_unit_gap = report.gaps[..report.gap_count]
            .iter()
            .any(|g| g.missing_method == VerificationMethod::UnitTest);
        assert!(has_unit_gap, "Missing UnitTest gap expected");
        let has_integration_gap = report.gaps[..report.gap_count]
            .iter()
            .any(|g| g.missing_method == VerificationMethod::IntegrationTest);
        assert!(!has_integration_gap, "IntegrationTest should not be a gap");
    }

    #[test]
    fn test_verification_methods_static_analysis() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        // Provide unit test + integration test + static analysis
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::StaticAnalysis, true);
        input.test_case_count = 3;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.fully_covered, 1);
        assert_eq!(report.gap_count, 0);
        // Verify static analysis is recognized by checking no gap exists for it
        let has_static_gap = report.gaps[..report.gap_count]
            .iter()
            .any(|g| g.missing_method == VerificationMethod::StaticAnalysis);
        assert!(!has_static_gap, "StaticAnalysis should not be a gap");
    }

    #[test]
    fn test_class_b_missing_integration_gap() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        // Only provide unit test -- Class B also requires integration test
        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let report = generate_traceability(&input).unwrap();

        assert_eq!(report.partially_covered, 1);
        assert_eq!(report.gap_count, 1);
        assert_eq!(
            report.gaps[0].missing_method,
            VerificationMethod::IntegrationTest
        );
        assert_eq!(report.gaps[0].safety_class, SafetyClass::ClassB);
    }

    #[test]
    fn test_lifecycle_phases_distinct() {
        let phases = [
            LifecyclePhase::Development,
            LifecyclePhase::Verification,
            LifecyclePhase::Maintenance,
            LifecyclePhase::Decommissioning,
        ];
        for i in 0..phases.len() {
            for j in (i + 1)..phases.len() {
                assert_ne!(
                    phases[i], phases[j],
                    "LifecyclePhase variants at index {} and {} should be distinct",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_requirement_categories_distinct() {
        let categories = [
            RequirementCategory::Functional,
            RequirementCategory::Performance,
            RequirementCategory::Interface,
            RequirementCategory::Safety,
            RequirementCategory::Security,
        ];
        for i in 0..categories.len() {
            for j in (i + 1)..categories.len() {
                assert_ne!(
                    categories[i], categories[j],
                    "RequirementCategory variants at index {} and {} should be distinct",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_is_input_valid_size() {
        assert!(is_input_valid_size(0, 0, 0));
        assert!(is_input_valid_size(
            MAX_MODULES,
            MAX_REQUIREMENTS,
            MAX_TEST_CASES
        ));
        assert!(!is_input_valid_size(MAX_MODULES + 1, 0, 0));
        assert!(!is_input_valid_size(0, MAX_REQUIREMENTS + 1, 0));
        assert!(!is_input_valid_size(0, 0, MAX_TEST_CASES + 1));
    }
}
