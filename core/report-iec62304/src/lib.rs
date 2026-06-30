// SPDX-License-Identifier: Apache-2.0
//! IEC 62304 software safety traceability matrix generator.
//!
//! Implements a traceability matrix generator for IEC 62304:2006 + A1:2015
//! compliance evidence (Medical device software -- Software life cycle
//! processes). Provides a `no_std`, zero-allocation engine for building and
//! evaluating software traceability matrices as required by IEC 62304. The
//! primary entry point is [`generate_traceability`], which consumes a
//! [`TraceabilityInput`] and produces a [`TraceabilityReport`] detailing
//! coverage status and compliance gaps.
//!
//! # Public API stability
//!
//! Pre-1.0 (workspace version 0.7.0); the [`REPORT_SCHEMA_VERSION`] payload
//! schema is bumped independently per IEC-62304 traceability stability so
//! that report consumers can pin against the *report* contract while the
//! crate version itself continues to track the wider workspace cadence.
//! The `generate_traceability` entry point, the `TraceabilityInput` /
//! `TraceabilityReport` types, and the `SafetyClass` / `VerificationMethod`
//! / `LifecyclePhase` / `RequirementCategory` classification enums form
//! the public surface and are governed by `DEPRECATION.md` once we reach
//! 1.0.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod classification;

use classification::{LifecyclePhase, RequirementCategory, SafetyClass, VerificationMethod};
use vs_evidence_envelope::{Evidence, GeneratedAt, GeneratorVersion, SchemaVersion, Standard};
use vs_types::VsError;

// Re-export the envelope types so downstream callers don't need to add
// `vs-evidence-envelope` to their Cargo.toml just to read accessor results.
pub use vs_evidence_envelope as evidence_envelope;

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

/// Schema version of the [`TraceabilityReport`] payload.  Bumped when the
/// payload's wire/struct shape changes in an observable way.
pub const REPORT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(0, 9, 0);

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
// Compile-time version derivation
// ---------------------------------------------------------------------------

/// Major component of the producing crate's semantic version, derived from
/// `CARGO_PKG_VERSION` at compile time.
pub const CRATE_VERSION_MAJOR: u8 = parse_version_component(env!("CARGO_PKG_VERSION"), 0);

/// Minor component of the producing crate's semantic version, derived from
/// `CARGO_PKG_VERSION` at compile time.
pub const CRATE_VERSION_MINOR: u8 = parse_version_component(env!("CARGO_PKG_VERSION"), 1);

/// Patch component of the producing crate's semantic version, derived from
/// `CARGO_PKG_VERSION` at compile time.
pub const CRATE_VERSION_PATCH: u8 = parse_version_component(env!("CARGO_PKG_VERSION"), 2);

/// Const-fn parser for one of the three semver components in a string like
/// `"0.7.0"` or `"0.7.0-rc1"`.  Stops at the first non-digit that is not a
/// dot, returns 0 on parse failure.  `component` is 0 (major), 1 (minor),
/// or 2 (patch).
const fn parse_version_component(s: &str, component: u8) -> u8 {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut dots_seen: u8 = 0;
    let mut acc: u32 = 0;
    let mut have_digit = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            if dots_seen == component {
                // Finished the target component.
                break;
            }
            dots_seen += 1;
            acc = 0;
            have_digit = false;
        } else if b >= b'0' && b <= b'9' {
            if dots_seen == component {
                acc = acc * 10 + (b - b'0') as u32;
                have_digit = true;
            }
            // else: still scanning past earlier components.
        } else {
            // End of the target component (e.g. '-' in pre-release) or
            // some non-digit garbage before the target -- stop either way.
            break;
        }
        i += 1;
    }
    if !have_digit && dots_seen < component {
        return 0;
    }
    if acc > 255 {
        255
    } else {
        acc as u8
    }
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
    ///
    /// **IEC 62304 semantic:** only test cases with `passed == true` count as
    /// verification evidence. A linked-but-failing test is treated identically
    /// to an absent test for the purpose of coverage classification: it does
    /// **not** satisfy the verification method it nominally targets, and a
    /// requirement whose only linked tests have `passed == false` is reported
    /// as [`TraceStatus::NotCovered`].
    pub passed: bool,
    /// UTF-8 test case label, null-padded.
    pub label: [u8; 48],
    /// Length of the valid portion of `label`.
    pub label_len: u8,
}

/// A trace link connecting a requirement to its verification test cases.
///
/// `test_ids` records *every* linked test (passing or failing) so the report
/// faithfully shows what verification was attempted. The `status` field, by
/// contrast, is computed using only **passing** tests, because under IEC 62304
/// a failing test is not valid verification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceLink {
    /// Requirement being traced.
    pub requirement_id: u16,
    /// Identifiers of every test case linked to this requirement, whether the
    /// test passed or failed.
    pub test_ids: [u16; MAX_TRACES_PER_REQ],
    /// Number of valid entries in `test_ids`.
    pub test_count: u8,
    /// Overall coverage status, derived from passing tests only.
    pub status: TraceStatus,
    /// Whether `test_ids` was truncated because more than
    /// [`MAX_TRACES_PER_REQ`] tests reference this requirement.
    pub truncated: bool,
}

/// Coverage status of a trace link.
///
/// Status classification considers only test cases with [`TestCase::passed`]
/// set to `true`. A linked-but-failing test does not contribute toward
/// `FullyCovered` or `PartiallyCovered`; a requirement whose every linked test
/// failed is therefore reported as `NotCovered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    /// Every verification method mandated by the requirement's safety class is
    /// satisfied by at least one **passing** test, and at least one passing
    /// test is linked to the requirement.
    FullyCovered,
    /// At least one passing test is linked, but one or more verification
    /// methods mandated by the safety class are not satisfied by a passing
    /// test.
    PartiallyCovered,
    /// No passing test is linked to this requirement. Either no test cases
    /// reference it at all, or every test that does reference it has
    /// `passed == false` (failing tests are not IEC 62304 evidence).
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
///
/// Fields are `pub(crate)`; consumers read them via the accessor methods.
/// This prevents external code from mutating an analysed report and lets
/// the crate enforce invariants (e.g. valid prefix lengths) at the API
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceabilityReport {
    /// Trace links for each requirement (only the first `trace_count` are
    /// valid; the rest are zeroed ghost rows).  Use [`Self::entries`] to
    /// get the live slice.
    pub(crate) traces: [TraceLink; MAX_REQUIREMENTS],
    pub(crate) trace_count: usize,
    pub(crate) gaps: [ComplianceGap; MAX_REQUIREMENTS],
    pub(crate) gap_count: usize,
    pub(crate) total_requirements: usize,
    pub(crate) fully_covered: usize,
    pub(crate) partially_covered: usize,
    pub(crate) not_covered: usize,
    pub(crate) class_a_count: usize,
    pub(crate) class_b_count: usize,
    pub(crate) class_c_count: usize,
    pub(crate) all_tests_passing: bool,
    /// Set when more than [`MAX_REQUIREMENTS`] compliance gaps were
    /// detected and the overflow was dropped.
    pub(crate) gaps_truncated: bool,
    /// Set when at least one requirement had more than
    /// [`MAX_TRACES_PER_REQ`] linked tests and the extras were dropped.
    pub(crate) traces_truncated: bool,
}

impl TraceabilityReport {
    /// Returns `true` if there are no compliance gaps and all tests pass.
    #[must_use]
    pub const fn is_compliant(&self) -> bool {
        self.gap_count == 0 && self.all_tests_passing && !self.gaps_truncated
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

    /// Live trace entries -- the valid prefix only, no ghost rows.
    #[must_use]
    pub fn entries(&self) -> &[TraceLink] {
        &self.traces[..self.trace_count]
    }

    /// Live compliance gaps -- the valid prefix only, no ghost rows.
    #[must_use]
    pub fn gaps(&self) -> &[ComplianceGap] {
        &self.gaps[..self.gap_count]
    }

    /// Number of valid trace entries.
    #[must_use]
    pub const fn trace_count(&self) -> usize {
        self.trace_count
    }

    /// Number of valid compliance gaps.
    #[must_use]
    pub const fn gap_count(&self) -> usize {
        self.gap_count
    }

    /// Total requirements analysed.
    #[must_use]
    pub const fn total_requirements(&self) -> usize {
        self.total_requirements
    }

    /// Number of fully covered requirements.
    #[must_use]
    pub const fn fully_covered(&self) -> usize {
        self.fully_covered
    }

    /// Number of partially covered requirements.
    #[must_use]
    pub const fn partially_covered(&self) -> usize {
        self.partially_covered
    }

    /// Number of uncovered requirements.
    #[must_use]
    pub const fn not_covered(&self) -> usize {
        self.not_covered
    }

    /// Number of Class A requirements.
    #[must_use]
    pub const fn class_a_count(&self) -> usize {
        self.class_a_count
    }

    /// Number of Class B requirements.
    #[must_use]
    pub const fn class_b_count(&self) -> usize {
        self.class_b_count
    }

    /// Number of Class C requirements.
    #[must_use]
    pub const fn class_c_count(&self) -> usize {
        self.class_c_count
    }

    /// Whether every test case in the input passed.
    #[must_use]
    pub const fn all_tests_passing(&self) -> bool {
        self.all_tests_passing
    }

    /// Whether the gaps buffer was filled to capacity and overflow was
    /// dropped.  When `true`, [`Self::is_compliant`] cannot be trusted to
    /// return `true` even with `gap_count == 0`.
    #[must_use]
    pub const fn gaps_truncated(&self) -> bool {
        self.gaps_truncated
    }

    /// Whether any requirement had more linked tests than
    /// [`MAX_TRACES_PER_REQ`] and the extras were dropped.
    #[must_use]
    pub const fn traces_truncated(&self) -> bool {
        self.traces_truncated
    }
}

// ---------------------------------------------------------------------------
// Built-in module catalog
// ---------------------------------------------------------------------------

/// Pre-populated catalog of Craton Shield software modules for IEC 62304
/// traceability.
pub const CRATON_SHIELD_MODULES: [SoftwareModule; 18] = [
    make_module(
        1,
        b"vs-types\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        8,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    make_module(
        2,
        b"vs-crypto\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        9,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    make_module(
        3,
        b"vs-key-manager\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    make_module(
        4,
        b"vs-secure-boot\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    make_module(
        5,
        b"vs-policy-engine\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        16,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        6,
        b"vs-event-logger\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        15,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        7,
        b"vs-can-monitor\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        8,
        b"vs-eth-monitor\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        14,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        9,
        b"vs-ids-engine\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        13,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        10,
        b"vs-anomaly\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    make_module(
        11,
        b"vs-integrity\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        12,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    make_module(
        12,
        b"vs-ota-validator\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        16,
        SafetyClass::ClassC,
        LifecyclePhase::Verification,
    ),
    make_module(
        13,
        b"vs-netfw\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        8,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        14,
        b"vs-runtime\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        15,
        b"vs-storage\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        10,
        SafetyClass::ClassA,
        LifecyclePhase::Development,
    ),
    make_module(
        16,
        b"vs-hal\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        6,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        17,
        b"vs-hal-linux\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        12,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
    make_module(
        18,
        b"vs-ffi\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        6,
        SafetyClass::ClassB,
        LifecyclePhase::Development,
    ),
];

/// Helper to construct a [`SoftwareModule`] for the built-in catalog.
///
/// Version components are derived at compile time from
/// `CARGO_PKG_VERSION`.
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
        version_major: CRATE_VERSION_MAJOR,
        version_minor: CRATE_VERSION_MINOR,
        version_patch: CRATE_VERSION_PATCH,
    }
}

// ---------------------------------------------------------------------------
// Traceability engine
// ---------------------------------------------------------------------------

/// Sentinel value indicating "no test in this bucket / unknown req".
///
/// We use `u8::MAX` since `MAX_TEST_CASES` (128) and `MAX_REQUIREMENTS` (64)
/// both fit comfortably below 255.
const NIL: u8 = u8::MAX;

/// Inverted index from requirement (by position in `input.requirements`) to
/// its test cases.
///
/// Built once at the start of [`generate_traceability`] in O(R log R + T log R),
/// then queried per-requirement in O(tests_for_this_req). Replaces the prior
/// per-requirement O(T) scan, dropping worst-case from O(R·T) ≈ 8192 visits
/// to O(R + T log R) ≈ a few hundred for IEC 62304 inputs.
///
/// Bucket layout: per-requirement linked list embedded in `tc_next`. For
/// requirement at index `r`, `req_first_tc[r]` is the first test case index;
/// each subsequent test is found via `tc_next[i]`. Sentinel = [`NIL`].
struct TestIndex {
    /// `req_first_tc[r]` = index of the first test for requirement at
    /// position `r` in `input.requirements`, or [`NIL`] if no tests.
    req_first_tc: [u8; MAX_REQUIREMENTS],
    /// `tc_next[i]` = index of the next test in the same bucket, or [`NIL`]
    /// to terminate the list.
    tc_next: [u8; MAX_TEST_CASES],
}

impl TestIndex {
    /// Build the inverted index over `input.test_cases`.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if any test case references a
    /// `requirement_id` that does not appear in `input.requirements[..
    /// input.requirement_count]`. Silently dropping such dangling links
    /// would let typos in traceability spreadsheets erase verification
    /// evidence without raising an error, which is unacceptable under
    /// IEC 62304.
    fn build(input: &TraceabilityInput) -> Result<Self, VsError> {
        let mut req_first_tc = [NIL; MAX_REQUIREMENTS];
        let mut tc_next = [NIL; MAX_TEST_CASES];

        // Build a sorted (req_id, req_idx) table for binary search.
        // O(R log R) via insertion sort — R ≤ 64 so this is tiny.
        let mut sorted_ids: [(u16, u8); MAX_REQUIREMENTS] = [(0u16, 0u8); MAX_REQUIREMENTS];
        let r_count = input.requirement_count;
        for r in 0..r_count {
            sorted_ids[r] = (input.requirements[r].id, r as u8);
        }
        // Insertion sort by id.
        let mut i = 1;
        while i < r_count {
            let key = sorted_ids[i];
            let mut j = i;
            while j > 0 && sorted_ids[j - 1].0 > key.0 {
                sorted_ids[j] = sorted_ids[j - 1];
                j -= 1;
            }
            sorted_ids[j] = key;
            i += 1;
        }

        // Bucket each test case. We iterate tests in reverse so the resulting
        // linked list yields tests in *forward* order on traversal, matching
        // the original sequential-scan semantics for stable test_ids ordering.
        let t_count = input.test_case_count;
        let active = &sorted_ids[..r_count];
        let mut t_rev = t_count;
        while t_rev > 0 {
            t_rev -= 1;
            let tc = &input.test_cases[t_rev];
            match active.binary_search_by_key(&tc.requirement_id, |&(id, _)| id) {
                Ok(mid) => {
                    let r = active[mid].1 as usize;
                    tc_next[t_rev] = req_first_tc[r];
                    req_first_tc[r] = t_rev as u8;
                }
                Err(_) => return Err(VsError::InvalidInput),
            }
        }

        Ok(Self {
            req_first_tc,
            tc_next,
        })
    }
}

/// Generate an IEC 62304 traceability report from the given input.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if any count exceeds its maximum, if
/// a requirement references a non-existent module, if a test case
/// references a `requirement_id` that does not appear in
/// `input.requirements`, or if any module, requirement, or test-case `id`
/// is duplicated within its collection (an ambiguous traceability matrix
/// is rejected rather than silently mis-analysed).
///
/// # Example
///
/// Minimal end-to-end use: register one module, one Class-A requirement,
/// one passing unit test, and inspect the resulting evidence envelope.
///
/// ```
/// use vs_report_iec62304::{
///     generate_traceability, SoftwareModule, SoftwareRequirement, TestCase,
///     TraceabilityInput, MAX_MODULES, MAX_REQUIREMENTS, MAX_TEST_CASES,
/// };
/// use vs_report_iec62304::classification::{
///     LifecyclePhase, RequirementCategory, SafetyClass, VerificationMethod,
/// };
///
/// let module = SoftwareModule {
///     id: 1,
///     name: [0u8; 32],
///     name_len: 0,
///     safety_class: SafetyClass::ClassA,
///     phase: LifecyclePhase::Development,
///     version_major: 0,
///     version_minor: 1,
///     version_patch: 0,
/// };
/// let requirement = SoftwareRequirement {
///     id: 10,
///     category: RequirementCategory::Functional,
///     module_id: 1,
///     safety_class: SafetyClass::ClassA,
///     label: [0u8; 48],
///     label_len: 0,
/// };
/// let test_case = TestCase {
///     id: 100,
///     requirement_id: 10,
///     method: VerificationMethod::UnitTest,
///     passed: true,
///     label: [0u8; 48],
///     label_len: 0,
/// };
///
/// let mut input = TraceabilityInput {
///     modules: [module; MAX_MODULES],
///     module_count: 1,
///     requirements: [requirement; MAX_REQUIREMENTS],
///     requirement_count: 1,
///     test_cases: [test_case; MAX_TEST_CASES],
///     test_case_count: 1,
/// };
/// // Only the first slot of each fixed-size array is "live"; the rest are
/// // ghost rows hidden by `entries()` / `gaps()`.
/// input.modules[0] = module;
/// input.requirements[0] = requirement;
/// input.test_cases[0] = test_case;
///
/// let envelope = generate_traceability(&input, 0).expect("valid input");
/// let report = envelope.payload();
/// assert!(report.is_compliant());
/// assert_eq!(report.coverage_percent(), 100);
/// ```
pub fn generate_traceability(
    input: &TraceabilityInput,
    generated_at: u64,
) -> Result<Evidence<TraceabilityReport>, VsError> {
    let report = generate_traceability_report(input)?;
    Ok(Evidence::new(
        Standard::Iec62304,
        REPORT_SCHEMA_VERSION,
        GeneratedAt::new(generated_at),
        GeneratorVersion::from_str(env!("CARGO_PKG_VERSION")),
        report,
    ))
}

/// Generate a bare [`TraceabilityReport`] without the [`Evidence`]
/// envelope.  Useful in tests and internal callers; new code should prefer
/// [`generate_traceability`].
///
/// # Errors
///
/// See [`generate_traceability`].
pub fn generate_traceability_report(
    input: &TraceabilityInput,
) -> Result<TraceabilityReport, VsError> {
    validate_input(input)?;

    let all_tests_passing = check_all_tests_passing(input);

    let mut report = TraceabilityReport {
        traces: [TraceLink {
            requirement_id: 0,
            test_ids: [0u16; MAX_TRACES_PER_REQ],
            test_count: 0,
            status: TraceStatus::NotCovered,
            truncated: false,
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
        gaps_truncated: false,
        traces_truncated: false,
    };

    // Build the requirement→tests inverted index ONCE. Returns
    // `Err(InvalidInput)` if any test case points at a non-existent
    // requirement, which we deliberately surface rather than silently
    // dropping the evidence.
    let index = TestIndex::build(input)?;

    let mut ri = 0;
    while ri < input.requirement_count {
        process_requirement(input, &index, ri, &mut report);
        ri += 1;
    }

    Ok(report)
}

/// Validate that input counts are within bounds, all module references are
/// valid, and every entity's `id` is unique within its collection.
///
/// Duplicate identifiers are rejected fail-closed: under IEC 62304 the
/// traceability matrix must be unambiguous, and a duplicate requirement `id`
/// in particular corrupts the inverted index built by [`TestIndex::build`]
/// (binary search would map a test to an arbitrary one of the colliding
/// requirements, leaving the other(s) with an empty bucket and a spurious
/// compliance gap). Duplicate module and test-case ids are likewise rejected
/// because their `id` fields are documented as unique and an ambiguous matrix
/// must never be silently accepted in compliance evidence.
fn validate_input(input: &TraceabilityInput) -> Result<(), VsError> {
    if input.module_count > MAX_MODULES
        || input.requirement_count > MAX_REQUIREMENTS
        || input.test_case_count > MAX_TEST_CASES
    {
        return Err(VsError::InvalidInput);
    }

    // Reject duplicate module ids.
    let mut i = 0;
    while i < input.module_count {
        let mut j = i + 1;
        while j < input.module_count {
            if input.modules[i].id == input.modules[j].id {
                return Err(VsError::InvalidInput);
            }
            j += 1;
        }
        i += 1;
    }

    // Reject duplicate requirement ids and validate module references.
    let mut i = 0;
    while i < input.requirement_count {
        if !module_exists(input, input.requirements[i].module_id) {
            return Err(VsError::InvalidInput);
        }
        let mut j = i + 1;
        while j < input.requirement_count {
            if input.requirements[i].id == input.requirements[j].id {
                return Err(VsError::InvalidInput);
            }
            j += 1;
        }
        i += 1;
    }

    // Reject duplicate test-case ids.
    let mut i = 0;
    while i < input.test_case_count {
        let mut j = i + 1;
        while j < input.test_case_count {
            if input.test_cases[i].id == input.test_cases[j].id {
                return Err(VsError::InvalidInput);
            }
            j += 1;
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
///
/// Uses the pre-computed [`TestIndex`] bucket for this requirement instead of
/// scanning all test cases, dropping the per-requirement cost from O(T) to
/// O(tests_for_this_req).
#[allow(clippy::similar_names)]
fn process_requirement(
    input: &TraceabilityInput,
    index: &TestIndex,
    req_idx: usize,
    report: &mut TraceabilityReport,
) {
    let req = &input.requirements[req_idx];
    // Count by class
    match req.safety_class {
        SafetyClass::ClassA => report.class_a_count += 1,
        SafetyClass::ClassB => report.class_b_count += 1,
        SafetyClass::ClassC => report.class_c_count += 1,
    }

    // Collect test cases for this requirement via the inverted index bucket.
    let mut link = TraceLink {
        requirement_id: req.id,
        test_ids: [0u16; MAX_TRACES_PER_REQ],
        test_count: 0,
        status: TraceStatus::NotCovered,
        truncated: false,
    };

    // Per IEC 62304, only *passing* tests count as verification evidence.
    // A linked-but-failing test must be treated identically to an absent test
    // for the purpose of coverage classification, so these per-method flags
    // are only set when the matched test row has `passed == true`. We also
    // track `passing_count` separately from `link.test_count` so a requirement
    // whose every linked test failed is classified as `NotCovered` rather than
    // `FullyCovered`.
    let mut has_unit = false;
    let mut has_integration = false;
    let mut has_static = false;
    let mut passing_count: u32 = 0;

    // Walk this requirement's bucket: a linked list embedded in `tc_next`.
    // Match original cap semantics: tests beyond MAX_TRACES_PER_REQ are
    // skipped entirely (they do NOT contribute to has_unit / has_integration
    // / has_static either). Truncation is reflected on the link below.
    let mut cursor = index.req_first_tc[req_idx];
    while cursor != NIL {
        let ti = cursor as usize;
        if (link.test_count as usize) < MAX_TRACES_PER_REQ {
            let tc = &input.test_cases[ti];
            link.test_ids[link.test_count as usize] = tc.id;
            link.test_count = link.test_count.saturating_add(1);
            // Per IEC 62304, only *passing* tests count as verification
            // evidence: gate the per-method flags and the passing counter
            // on `tc.passed == true`. The test id was recorded above so the
            // failure is still surfaced for review.
            if tc.passed {
                passing_count = passing_count.saturating_add(1);
                match tc.method {
                    VerificationMethod::UnitTest => has_unit = true,
                    VerificationMethod::IntegrationTest => has_integration = true,
                    VerificationMethod::StaticAnalysis => has_static = true,
                    // System test, code review and formal verification act as
                    // substitutes for the methods nominally mandated by the
                    // safety class, mirroring the prior gating semantics.
                    VerificationMethod::SystemTest => {
                        has_integration = true;
                    }
                    VerificationMethod::CodeReview => {
                        has_static = true;
                    }
                    VerificationMethod::FormalVerification => {
                        has_unit = true;
                        has_integration = true;
                        has_static = true;
                    }
                }
            }
        } else {
            link.truncated = true;
            report.traces_truncated = true;
        }
        cursor = index.tc_next[ti];
    }

    // Determine coverage status. A requirement with only failing tests is
    // classified `NotCovered` (failing tests are not IEC 62304 evidence).
    if passing_count == 0 {
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

    if required && !present {
        if report.gap_count < MAX_REQUIREMENTS {
            report.gaps[report.gap_count] = ComplianceGap {
                requirement_id: req.id,
                safety_class: req.safety_class,
                missing_method: method,
            };
            report.gap_count += 1;
        } else {
            report.gaps_truncated = true;
        }
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

    fn report_of(input: &TraceabilityInput) -> TraceabilityReport {
        generate_traceability_report(input).unwrap()
    }

    // 1. Empty input produces empty report with 0 coverage.
    #[test]
    fn empty_input_produces_empty_report() {
        let input = empty_input();
        let report = report_of(&input);

        assert_eq!(report.total_requirements(), 0);
        assert_eq!(report.fully_covered(), 0);
        assert_eq!(report.gap_count(), 0);
        assert_eq!(report.coverage_percent(), 0);
        assert!(report.all_tests_passing());
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

        let report = report_of(&input);

        assert_eq!(report.fully_covered(), 1);
        assert_eq!(report.coverage_percent(), 100);
        assert_eq!(report.gap_count(), 0);
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

        let report = report_of(&input);

        assert_eq!(report.not_covered(), 1);
        assert_eq!(report.entries()[0].status, TraceStatus::NotCovered);
        // Class B requires unit test + integration test = 2 gaps
        assert_eq!(report.gap_count(), 2);
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

        let report = report_of(&input);

        assert_eq!(report.not_covered(), 1);
        assert_eq!(report.gap_count(), 0);
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

        let report = report_of(&input);

        assert_eq!(report.partially_covered(), 1);
        assert_eq!(report.gap_count(), 1);
        assert_eq!(
            report.gaps()[0].missing_method,
            VerificationMethod::StaticAnalysis
        );
        assert_eq!(report.gaps()[0].safety_class, SafetyClass::ClassC);
        assert!(!report.is_compliant());
    }

    // 6. Multiple requirements with mixed coverage.
    #[test]
    fn mixed_coverage_percentages() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.modules[1] = make_test_module(2, SafetyClass::ClassB);
        input.module_count = 2;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 2, SafetyClass::ClassB);
        input.requirements[2] = make_test_requirement(12, 2, SafetyClass::ClassB);
        input.requirement_count = 3;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 12, VerificationMethod::UnitTest, true);
        input.test_cases[2] = make_test_case(102, 12, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 3;

        let report = report_of(&input);

        assert_eq!(report.total_requirements(), 3);
        assert_eq!(report.fully_covered(), 2);
        assert_eq!(report.not_covered(), 1);
        assert_eq!(report.coverage_percent(), 66);
        assert_eq!(report.class_a_count(), 1);
        assert_eq!(report.class_b_count(), 2);
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

        let report = report_of(&input);

        assert!(!report.all_tests_passing());
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

        let report = report_of(&input);

        assert!(!report.is_compliant());
        assert!(report.gap_count() > 0);
    }

    // 9. Module count exceeds MAX produces InvalidInput.
    #[test]
    fn module_count_exceeds_max() {
        let mut input = empty_input();
        input.module_count = MAX_MODULES + 1;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // 10. Built-in catalog has correct count and classifications.
    #[test]
    fn craton_shield_catalog_correctness() {
        assert_eq!(CRATON_SHIELD_MODULES.len(), 18);

        assert_eq!(CRATON_SHIELD_MODULES[0].safety_class, SafetyClass::ClassA);
        assert_eq!(CRATON_SHIELD_MODULES[0].id, 1);

        assert_eq!(CRATON_SHIELD_MODULES[1].safety_class, SafetyClass::ClassC);
        assert_eq!(CRATON_SHIELD_MODULES[1].id, 2);

        assert_eq!(CRATON_SHIELD_MODULES[4].safety_class, SafetyClass::ClassB);
        assert_eq!(CRATON_SHIELD_MODULES[4].id, 5);

        assert_eq!(CRATON_SHIELD_MODULES[9].safety_class, SafetyClass::ClassA);
        assert_eq!(CRATON_SHIELD_MODULES[14].safety_class, SafetyClass::ClassA);

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

        let report = report_of(&input);

        let entries = report.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].test_count, 3);
        assert_eq!(entries[0].test_ids[0], 100);
        assert_eq!(entries[0].test_ids[1], 101);
        assert_eq!(entries[0].test_ids[2], 102);
        assert_eq!(entries[0].status, TraceStatus::FullyCovered);
    }

    // 12. Invalid module reference produces error.
    #[test]
    fn invalid_module_reference() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 99, SafetyClass::ClassA);
        input.requirement_count = 1;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // Duplicate requirement ids must be rejected: they would otherwise
    // corrupt the inverted index (binary search maps every test to an
    // arbitrary one of the colliding requirements, leaving the other with
    // an empty bucket and a spurious compliance gap).
    #[test]
    fn duplicate_requirement_id_rejected() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 2;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // Duplicate module ids make the traceability matrix ambiguous and are
    // rejected fail-closed.
    #[test]
    fn duplicate_module_id_rejected() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.modules[1] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 2;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // Duplicate test-case ids are rejected fail-closed.
    #[test]
    fn duplicate_test_case_id_rejected() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(100, 10, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 2;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

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

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::StaticAnalysis, true);
        input.test_case_count = 3;

        let report = report_of(&input);

        assert_eq!(report.fully_covered(), 1);
        assert_eq!(report.entries()[0].status, TraceStatus::FullyCovered);
        assert_eq!(report.gap_count(), 0);
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

        let report = report_of(&input);

        assert_eq!(report.class_a_count(), 1);
        assert_eq!(report.class_b_count(), 1);
        assert_eq!(report.class_c_count(), 1);
        assert_eq!(report.total_requirements(), 3);
    }

    #[test]
    fn test_requirement_count_exceeds_max() {
        let mut input = empty_input();
        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;
        input.requirement_count = MAX_REQUIREMENTS + 1;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_test_case_count_exceeds_max() {
        let mut input = empty_input();
        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;
        input.test_case_count = MAX_TEST_CASES + 1;

        let result = generate_traceability_report(&input);
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

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 11, VerificationMethod::UnitTest, true);
        input.test_case_count = 2;

        let report = report_of(&input);
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

        let report = report_of(&input);
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

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let report = report_of(&input);
        assert_eq!(report.coverage_percent(), 50);
    }

    #[test]
    fn test_verification_methods_integration() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::IntegrationTest, true);
        input.test_case_count = 1;

        let report = report_of(&input);

        assert_eq!(report.partially_covered(), 1);
        assert_eq!(report.entries()[0].status, TraceStatus::PartiallyCovered);
        let has_unit_gap = report
            .gaps()
            .iter()
            .any(|g| g.missing_method == VerificationMethod::UnitTest);
        assert!(has_unit_gap, "Missing UnitTest gap expected");
        let has_integration_gap = report
            .gaps()
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

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::StaticAnalysis, true);
        input.test_case_count = 3;

        let report = report_of(&input);

        assert_eq!(report.fully_covered(), 1);
        assert_eq!(report.gap_count(), 0);
        let has_static_gap = report
            .gaps()
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

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let report = report_of(&input);

        assert_eq!(report.partially_covered(), 1);
        assert_eq!(report.gap_count(), 1);
        assert_eq!(
            report.gaps()[0].missing_method,
            VerificationMethod::IntegrationTest
        );
        assert_eq!(report.gaps()[0].safety_class, SafetyClass::ClassB);
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

    #[test]
    fn test_max_traces_per_req_limit() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        let total = MAX_TRACES_PER_REQ + 4;
        for i in 0..total {
            input.test_cases[i] =
                make_test_case((100 + i) as u16, 10, VerificationMethod::UnitTest, true);
        }
        input.test_case_count = total;

        let report = report_of(&input);

        assert_eq!(
            report.entries()[0].test_count as usize,
            MAX_TRACES_PER_REQ,
            "test_count should be capped at MAX_TRACES_PER_REQ"
        );
        assert!(report.entries()[0].truncated);
        assert!(report.traces_truncated());
    }

    // ----- v0.9 regression tests --------------------------------------

    /// Wrap-in-Evidence: the public entry point returns an envelope with
    /// metadata pinned to IEC 62304 and the crate version.
    #[test]
    fn v09_evidence_envelope_metadata() {
        let input = empty_input();
        let env = generate_traceability(&input, 42).unwrap();

        assert_eq!(env.standard(), Standard::Iec62304);
        assert_eq!(env.schema_version(), REPORT_SCHEMA_VERSION);
        assert_eq!(env.generated_at().value(), 42);
        assert_eq!(env.generator_version().as_str(), env!("CARGO_PKG_VERSION"));
        assert_eq!(env.payload().total_requirements(), 0);
    }

    /// `entries()` returns only the valid prefix -- no ghost rows.
    #[test]
    fn v09_entries_no_ghost_rows() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirements[1] = make_test_requirement(11, 1, SafetyClass::ClassA);
        input.requirement_count = 2;

        let report = report_of(&input);
        assert_eq!(report.entries().len(), 2);
        // Despite the backing array being MAX_REQUIREMENTS long, only the
        // valid prefix is exposed.
        assert!(report.entries().len() < MAX_REQUIREMENTS);
    }

    /// `gaps()` returns only the valid prefix.
    #[test]
    fn v09_gaps_no_ghost_rows() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        let report = report_of(&input);
        // Class C with no tests yields 3 gaps (unit, integration, static).
        assert_eq!(report.gaps().len(), 3);
    }

    /// SystemTest passed=true should satisfy the integration-test
    /// requirement for a Class B module.
    #[test]
    fn v09_system_test_gates_integration_for_class_b() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::SystemTest, true);
        input.test_case_count = 2;

        let report = report_of(&input);
        assert_eq!(
            report.entries()[0].status,
            TraceStatus::FullyCovered,
            "SystemTest must satisfy integration coverage"
        );
        assert_eq!(report.gap_count(), 0);
    }

    /// SystemTest passed=false must NOT contribute to coverage.
    #[test]
    fn v09_system_test_failed_does_not_gate() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::SystemTest, false);
        input.test_case_count = 2;

        let report = report_of(&input);
        assert_eq!(report.entries()[0].status, TraceStatus::PartiallyCovered);
        // Integration gap remains.
        assert!(report
            .gaps()
            .iter()
            .any(|g| g.missing_method == VerificationMethod::IntegrationTest));
    }

    /// CodeReview passed=true substitutes for static analysis (Class C).
    #[test]
    fn v09_code_review_gates_static_analysis_for_class_c() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, true);
        input.test_cases[1] = make_test_case(101, 10, VerificationMethod::IntegrationTest, true);
        input.test_cases[2] = make_test_case(102, 10, VerificationMethod::CodeReview, true);
        input.test_case_count = 3;

        let report = report_of(&input);
        assert_eq!(report.entries()[0].status, TraceStatus::FullyCovered);
        assert_eq!(report.gap_count(), 0);
    }

    /// FormalVerification passed=true satisfies all three required methods
    /// at once.
    #[test]
    fn v09_formal_verification_covers_all_for_class_c() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassC);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::FormalVerification, true);
        input.test_case_count = 1;

        let report = report_of(&input);
        assert_eq!(report.entries()[0].status, TraceStatus::FullyCovered);
        assert_eq!(report.gap_count(), 0);
    }

    /// Traces truncated when more than MAX_TRACES_PER_REQ link to one req.
    #[test]
    fn v09_traces_truncated_flag_set() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        let total = MAX_TRACES_PER_REQ + 1;
        for i in 0..total {
            input.test_cases[i] =
                make_test_case((200 + i) as u16, 10, VerificationMethod::UnitTest, true);
        }
        input.test_case_count = total;

        let report = report_of(&input);
        assert!(report.traces_truncated());
        assert!(report.entries()[0].truncated);
        assert!(!report.gaps_truncated());
    }

    /// Gaps truncated when more than MAX_REQUIREMENTS gaps are generated.
    /// Each Class C requirement without tests creates 3 gaps; with 64 of
    /// them the first 64 gaps fill the buffer and the rest set the flag.
    #[test]
    fn v09_gaps_truncated_flag_set() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassC);
        input.module_count = 1;

        for i in 0..MAX_REQUIREMENTS {
            input.requirements[i] = make_test_requirement(10 + i as u16, 1, SafetyClass::ClassC);
        }
        input.requirement_count = MAX_REQUIREMENTS;

        let report = report_of(&input);
        assert_eq!(report.gap_count(), MAX_REQUIREMENTS);
        assert!(report.gaps_truncated());
        // Truncated gaps invalidate is_compliant even if buffer looks full.
        assert!(!report.is_compliant());
    }

    /// `version_minor` on built-in modules tracks `CARGO_PKG_VERSION`, not
    /// the old hardcoded `6`.
    #[test]
    fn v09_module_version_from_cargo_pkg_version() {
        let pkg = env!("CARGO_PKG_VERSION");
        let (major, minor, patch) = parse_semver(pkg);

        assert_eq!(CRATE_VERSION_MAJOR, major);
        assert_eq!(CRATE_VERSION_MINOR, minor);
        assert_eq!(CRATE_VERSION_PATCH, patch);

        for m in &CRATON_SHIELD_MODULES {
            assert_eq!(m.version_major, major);
            assert_eq!(m.version_minor, minor);
            assert_eq!(m.version_patch, patch);
        }
    }

    fn parse_semver(s: &str) -> (u8, u8, u8) {
        // Strip pre-release / build metadata.
        let core_part = s.split('-').next().unwrap_or(s);
        let core_part = core_part.split('+').next().unwrap_or(core_part);
        let mut iter = core_part.split('.');
        let major: u8 = iter.next().unwrap().parse().unwrap();
        let minor: u8 = iter.next().unwrap().parse().unwrap();
        let patch: u8 = iter.next().unwrap().parse().unwrap();
        (major, minor, patch)
    }

    /// Cargo.toml description carries the trademark disclaimer.
    #[test]
    fn v09_cargo_description_has_disclaimer() {
        let desc = env!("CARGO_PKG_DESCRIPTION");
        assert!(
            desc.contains("Unofficial IEC 62304 traceability helper")
                && desc.contains("not an official IEC product"),
            "Cargo.toml description missing trademark disclaimer: {desc:?}"
        );
    }

    /// A test case whose `requirement_id` does not appear in
    /// `input.requirements` must be rejected up front rather than silently
    /// dropped — a typo in a traceability spreadsheet would otherwise erase
    /// verification evidence with no signal back to the caller.
    #[test]
    fn dangling_test_requirement_id_is_rejected() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassB);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassB);
        input.requirement_count = 1;

        // Test case references requirement_id 999 which doesn't exist.
        input.test_cases[0] = make_test_case(100, 999, VerificationMethod::UnitTest, true);
        input.test_case_count = 1;

        let result = generate_traceability_report(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    /// A requirement whose only linked test failed must be classified
    /// `NotCovered`, not `FullyCovered` or `PartiallyCovered`. This guards
    /// the IEC-62304 "passing tests = evidence" semantic — failing tests
    /// are not verification evidence and must not satisfy the safety class.
    #[test]
    fn failing_only_test_yields_not_covered() {
        let mut input = empty_input();

        input.modules[0] = make_test_module(1, SafetyClass::ClassA);
        input.module_count = 1;

        input.requirements[0] = make_test_requirement(10, 1, SafetyClass::ClassA);
        input.requirement_count = 1;

        input.test_cases[0] = make_test_case(100, 10, VerificationMethod::UnitTest, false);
        input.test_case_count = 1;

        let report = report_of(&input);
        assert_eq!(report.not_covered(), 1);
        assert_eq!(report.fully_covered(), 0);
        assert_eq!(report.entries()[0].status, TraceStatus::NotCovered);
    }
}
