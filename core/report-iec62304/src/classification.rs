// SPDX-License-Identifier: Apache-2.0
//! IEC 62304 software safety classification model.
//!
//! Defines the safety classes (A, B, C), lifecycle phases, verification
//! methods, and requirement categories mandated by the standard.
//!
//! Disclaimer: Unofficial IEC 62304 traceability helper; not an official
//! IEC product.

/// IEC 62304 software safety classification.
///
/// The safety class determines the rigour of verification activities required
/// for a software item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyClass {
    /// Class A -- no injury possible.
    ClassA,
    /// Class B -- non-serious injury possible.
    ClassB,
    /// Class C -- death or serious injury possible.
    ClassC,
}

impl SafetyClass {
    /// Human-readable label for this safety class.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ClassA => "Class A",
            Self::ClassB => "Class B",
            Self::ClassC => "Class C",
        }
    }

    /// Whether this class requires unit testing.
    ///
    /// Required for Class B and Class C.
    #[must_use]
    pub const fn requires_unit_testing(self) -> bool {
        match self {
            Self::ClassA => false,
            Self::ClassB | Self::ClassC => true,
        }
    }

    /// Whether this class requires integration testing.
    ///
    /// Required for Class B and Class C.
    #[must_use]
    pub const fn requires_integration_testing(self) -> bool {
        match self {
            Self::ClassA => false,
            Self::ClassB | Self::ClassC => true,
        }
    }

    /// Whether this class requires static analysis.
    ///
    /// Required for Class C only.
    #[must_use]
    pub const fn requires_static_analysis(self) -> bool {
        match self {
            Self::ClassA | Self::ClassB => false,
            Self::ClassC => true,
        }
    }

    /// Whether this class requires detailed design documentation.
    ///
    /// Required for Class B and Class C.
    #[must_use]
    pub const fn requires_detailed_design(self) -> bool {
        match self {
            Self::ClassA => false,
            Self::ClassB | Self::ClassC => true,
        }
    }

    /// Whether this class requires full traceability.
    ///
    /// Required for Class B and Class C.
    #[must_use]
    pub const fn requires_traceability(self) -> bool {
        match self {
            Self::ClassA => false,
            Self::ClassB | Self::ClassC => true,
        }
    }
}

/// Software lifecycle phase per IEC 62304 clauses 5-9.
///
/// The canonical chain is `Planning → Requirements → Architecture →
/// Integration → SystemTesting → Release → Maintenance` (with
/// `Decommissioning` as the terminal state after `Maintenance`).  The
/// coarser-grained `Development` and `Verification` aliases coexist with
/// the clause-aligned variants and are treated as `Architecture` and
/// `SystemTesting` respectively by the state machine; they remain a
/// supported way to label modules whose lifecycle is tracked at process
/// granularity rather than clause granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecyclePhase {
    /// IEC 62304 clause 5.1 -- software development planning.
    Planning,
    /// IEC 62304 clause 5.2 -- software requirements analysis.
    Requirements,
    /// IEC 62304 clauses 5.3/5.4 -- architecture and detailed design.
    Architecture,
    /// IEC 62304 clause 5.5/5.6 -- unit implementation and integration.
    Integration,
    /// IEC 62304 clause 5.7 -- system testing.
    SystemTesting,
    /// IEC 62304 clause 5.8 -- software release.
    Release,
    /// IEC 62304 clause 6 -- post-release maintenance.
    Maintenance,
    /// End-of-life decommissioning.
    Decommissioning,

    /// Coarse-grained alias covering architecture and unit implementation
    /// (maps to `Architecture` in the state machine).
    Development,
    /// Coarse-grained alias covering integration through system testing
    /// (maps to `SystemTesting` in the state machine).
    Verification,
}

impl LifecyclePhase {
    /// Canonical position in the IEC 62304 lifecycle chain.  Used by the
    /// state machine to validate legal forward/backward transitions.  The
    /// coarser-grained aliases (`Development`, `Verification`) are mapped
    /// to the equivalent canonical position.
    #[must_use]
    const fn canonical_index(self) -> u8 {
        match self {
            Self::Planning => 0,
            Self::Requirements => 1,
            // Architecture and the Development alias share a slot.
            Self::Architecture | Self::Development => 2,
            Self::Integration => 3,
            // SystemTesting and the Verification alias share a slot.
            Self::SystemTesting | Self::Verification => 4,
            Self::Release => 5,
            Self::Maintenance => 6,
            Self::Decommissioning => 7,
        }
    }

    /// Whether `self → next` is a legal IEC 62304 lifecycle transition.
    ///
    /// The state machine permits:
    ///
    /// - Forward moves by exactly one canonical step (e.g. `Planning →
    ///   Requirements`).
    /// - Same-phase "tick" transitions (e.g. re-entering `Integration` after
    ///   a fix), which are a no-op but legal.
    /// - From `Maintenance`, a re-entry into the chain at `Requirements`
    ///   (post-release change requests trigger a new requirements cycle per
    ///   clause 6.2).
    ///
    /// All other transitions -- including phase jumps, backward moves, and
    /// any transition out of `Decommissioning` -- are rejected.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        let a = self.canonical_index();
        let b = next.canonical_index();

        // Decommissioning is terminal.
        if a == 7 {
            return false;
        }

        // Same-phase tick is always legal (idempotent).
        if a == b {
            return true;
        }

        // Maintenance may loop back to Requirements (post-release change).
        if a == 6 && b == 1 {
            return true;
        }

        // Otherwise only forward-by-one.
        b == a + 1
    }
}

/// Per-module lifecycle process tracker.
///
/// Stores the current `LifecyclePhase` for up to [`Self::MAX_TRACKED_MODULES`]
/// software modules and validates phase transitions against the IEC 62304
/// canonical chain.  Rejects illegal jumps with [`LifecycleError`].
///
/// All state is stack-allocated; no heap, `no_std` compatible.
pub struct LifecycleProcess {
    entries: [LifecycleEntry; Self::MAX_TRACKED_MODULES],
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LifecycleEntry {
    module_id: u16,
    phase: LifecyclePhase,
}

/// Error returned by [`LifecycleProcess`] when a transition is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    /// The requested module has not been registered with `start`.
    UnknownModule,
    /// The internal table is full -- raise [`LifecycleProcess::MAX_TRACKED_MODULES`].
    CapacityExceeded,
    /// The phase transition is not legal per IEC 62304.
    IllegalTransition {
        /// Phase the module was in when the transition was attempted.
        from: LifecyclePhase,
        /// Phase the caller asked to move into.
        to: LifecyclePhase,
    },
}

impl Default for LifecycleProcess {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleProcess {
    /// Maximum number of modules whose lifecycle can be tracked.
    pub const MAX_TRACKED_MODULES: usize = 32;

    /// Construct an empty tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [LifecycleEntry {
                module_id: 0,
                phase: LifecyclePhase::Planning,
            }; Self::MAX_TRACKED_MODULES],
            len: 0,
        }
    }

    /// Register a module's initial phase.  Returns `CapacityExceeded` if the
    /// table is full.  If the module is already registered, its phase is
    /// overwritten (the new phase is taken as ground truth without a
    /// transition check).
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::CapacityExceeded`] when the internal table
    /// has no slot available.
    pub fn start(&mut self, module_id: u16, phase: LifecyclePhase) -> Result<(), LifecycleError> {
        if let Some(idx) = self.index_of(module_id) {
            self.entries[idx].phase = phase;
            return Ok(());
        }
        if self.len >= Self::MAX_TRACKED_MODULES {
            return Err(LifecycleError::CapacityExceeded);
        }
        self.entries[self.len] = LifecycleEntry { module_id, phase };
        self.len += 1;
        Ok(())
    }

    /// Current lifecycle phase for `module_id`, or `None` if not registered.
    #[must_use]
    pub fn phase_of(&self, module_id: u16) -> Option<LifecyclePhase> {
        self.index_of(module_id).map(|i| self.entries[i].phase)
    }

    /// Attempt to move `module_id` from its current phase to `next`.
    ///
    /// # Errors
    ///
    /// - [`LifecycleError::UnknownModule`] if the module has not been
    ///   registered.
    /// - [`LifecycleError::IllegalTransition`] if the move is not allowed
    ///   by [`LifecyclePhase::can_transition_to`].
    pub fn transition_to(
        &mut self,
        module_id: u16,
        next: LifecyclePhase,
    ) -> Result<(), LifecycleError> {
        let idx = self
            .index_of(module_id)
            .ok_or(LifecycleError::UnknownModule)?;
        let current = self.entries[idx].phase;
        if !current.can_transition_to(next) {
            return Err(LifecycleError::IllegalTransition {
                from: current,
                to: next,
            });
        }
        self.entries[idx].phase = next;
        Ok(())
    }

    /// Number of modules tracked.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the tracker has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn index_of(&self, module_id: u16) -> Option<usize> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].module_id == module_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

/// Verification method used to validate a software requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationMethod {
    /// Unit-level testing.
    UnitTest,
    /// Integration-level testing.
    IntegrationTest,
    /// Full system-level testing.
    SystemTest,
    /// Automated static analysis (e.g. Clippy, MISRA checker).
    StaticAnalysis,
    /// Manual or tool-assisted code review.
    CodeReview,
    /// Formal mathematical verification.
    FormalVerification,
}

impl VerificationMethod {
    /// Human-readable label for this verification method.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnitTest => "Unit Test",
            Self::IntegrationTest => "Integration Test",
            Self::SystemTest => "System Test",
            Self::StaticAnalysis => "Static Analysis",
            Self::CodeReview => "Code Review",
            Self::FormalVerification => "Formal Verification",
        }
    }
}

/// Category of a software requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequirementCategory {
    /// Functional behaviour.
    Functional,
    /// Performance and timing constraints.
    Performance,
    /// External interface contracts.
    Interface,
    /// Safety-related requirements.
    Safety,
    /// Security-related requirements.
    Security,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_class_labels() {
        assert_eq!(SafetyClass::ClassA.label(), "Class A");
        assert_eq!(SafetyClass::ClassB.label(), "Class B");
        assert_eq!(SafetyClass::ClassC.label(), "Class C");
    }

    #[test]
    fn safety_class_ordering() {
        assert!(SafetyClass::ClassA < SafetyClass::ClassB);
        assert!(SafetyClass::ClassB < SafetyClass::ClassC);
        assert!(SafetyClass::ClassA < SafetyClass::ClassC);
    }

    #[test]
    fn requires_unit_testing() {
        assert!(!SafetyClass::ClassA.requires_unit_testing());
        assert!(SafetyClass::ClassB.requires_unit_testing());
        assert!(SafetyClass::ClassC.requires_unit_testing());
    }

    #[test]
    fn requires_integration_testing() {
        assert!(!SafetyClass::ClassA.requires_integration_testing());
        assert!(SafetyClass::ClassB.requires_integration_testing());
        assert!(SafetyClass::ClassC.requires_integration_testing());
    }

    #[test]
    fn requires_static_analysis() {
        assert!(!SafetyClass::ClassA.requires_static_analysis());
        assert!(!SafetyClass::ClassB.requires_static_analysis());
        assert!(SafetyClass::ClassC.requires_static_analysis());
    }

    #[test]
    fn requires_detailed_design() {
        assert!(!SafetyClass::ClassA.requires_detailed_design());
        assert!(SafetyClass::ClassB.requires_detailed_design());
        assert!(SafetyClass::ClassC.requires_detailed_design());
    }

    #[test]
    fn requires_traceability() {
        assert!(!SafetyClass::ClassA.requires_traceability());
        assert!(SafetyClass::ClassB.requires_traceability());
        assert!(SafetyClass::ClassC.requires_traceability());
    }

    #[test]
    fn lifecycle_phase_equality() {
        assert_eq!(LifecyclePhase::Development, LifecyclePhase::Development);
        assert_eq!(LifecyclePhase::Verification, LifecyclePhase::Verification);
        assert_ne!(LifecyclePhase::Development, LifecyclePhase::Maintenance);
        assert_ne!(
            LifecyclePhase::Verification,
            LifecyclePhase::Decommissioning
        );
    }

    #[test]
    fn verification_method_labels() {
        assert_eq!(VerificationMethod::UnitTest.label(), "Unit Test");
        assert_eq!(
            VerificationMethod::IntegrationTest.label(),
            "Integration Test"
        );
        assert_eq!(VerificationMethod::SystemTest.label(), "System Test");
        assert_eq!(
            VerificationMethod::StaticAnalysis.label(),
            "Static Analysis"
        );
        assert_eq!(VerificationMethod::CodeReview.label(), "Code Review");
        assert_eq!(
            VerificationMethod::FormalVerification.label(),
            "Formal Verification"
        );
    }

    #[test]
    fn requirement_category_variants_exist() {
        let _ = RequirementCategory::Functional;
        let _ = RequirementCategory::Performance;
        let _ = RequirementCategory::Interface;
        let _ = RequirementCategory::Safety;
        let _ = RequirementCategory::Security;
    }

    // -- LifecyclePhase state machine -----------------------------------

    #[test]
    fn lifecycle_canonical_chain_legal_forward_moves() {
        let chain = [
            LifecyclePhase::Planning,
            LifecyclePhase::Requirements,
            LifecyclePhase::Architecture,
            LifecyclePhase::Integration,
            LifecyclePhase::SystemTesting,
            LifecyclePhase::Release,
            LifecyclePhase::Maintenance,
            LifecyclePhase::Decommissioning,
        ];
        for w in chain.windows(2) {
            assert!(
                w[0].can_transition_to(w[1]),
                "{:?} -> {:?} should be legal",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn lifecycle_phase_jumps_rejected() {
        // Skipping Requirements is illegal.
        assert!(!LifecyclePhase::Planning.can_transition_to(LifecyclePhase::Architecture));
        // Going from Planning straight to Release is illegal.
        assert!(!LifecyclePhase::Planning.can_transition_to(LifecyclePhase::Release));
        // Backwards moves are illegal.
        assert!(!LifecyclePhase::Architecture.can_transition_to(LifecyclePhase::Planning));
        // Decommissioning is terminal.
        assert!(!LifecyclePhase::Decommissioning.can_transition_to(LifecyclePhase::Maintenance));
        assert!(!LifecyclePhase::Decommissioning.can_transition_to(LifecyclePhase::Planning));
    }

    #[test]
    fn lifecycle_same_phase_tick_legal() {
        assert!(LifecyclePhase::Integration.can_transition_to(LifecyclePhase::Integration));
        assert!(LifecyclePhase::Maintenance.can_transition_to(LifecyclePhase::Maintenance));
    }

    #[test]
    fn lifecycle_maintenance_loopback_to_requirements_legal() {
        assert!(LifecyclePhase::Maintenance.can_transition_to(LifecyclePhase::Requirements));
        // But not back to Planning.
        assert!(!LifecyclePhase::Maintenance.can_transition_to(LifecyclePhase::Planning));
    }

    #[test]
    fn lifecycle_process_start_and_query() {
        let mut lp = LifecycleProcess::new();
        assert!(lp.is_empty());
        lp.start(42, LifecyclePhase::Planning).unwrap();
        assert_eq!(lp.phase_of(42), Some(LifecyclePhase::Planning));
        assert_eq!(lp.phase_of(99), None);
        assert_eq!(lp.len(), 1);
    }

    #[test]
    fn lifecycle_process_legal_transition() {
        let mut lp = LifecycleProcess::new();
        lp.start(1, LifecyclePhase::Planning).unwrap();
        lp.transition_to(1, LifecyclePhase::Requirements).unwrap();
        assert_eq!(lp.phase_of(1), Some(LifecyclePhase::Requirements));
    }

    #[test]
    fn lifecycle_process_rejects_illegal_jump() {
        let mut lp = LifecycleProcess::new();
        lp.start(1, LifecyclePhase::Planning).unwrap();
        let err = lp
            .transition_to(1, LifecyclePhase::Release)
            .expect_err("should reject");
        assert!(matches!(err, LifecycleError::IllegalTransition { .. }));
        // Phase unchanged.
        assert_eq!(lp.phase_of(1), Some(LifecyclePhase::Planning));
    }

    #[test]
    fn lifecycle_process_unknown_module() {
        let mut lp = LifecycleProcess::new();
        let err = lp
            .transition_to(7, LifecyclePhase::Requirements)
            .expect_err("should reject");
        assert!(matches!(err, LifecycleError::UnknownModule));
    }

    #[test]
    fn lifecycle_process_capacity_exceeded() {
        let mut lp = LifecycleProcess::new();
        for i in 0..LifecycleProcess::MAX_TRACKED_MODULES {
            lp.start(i as u16 + 1, LifecyclePhase::Planning).unwrap();
        }
        let err = lp
            .start(9999, LifecyclePhase::Planning)
            .expect_err("should reject");
        assert!(matches!(err, LifecycleError::CapacityExceeded));
    }

    #[test]
    fn lifecycle_process_full_canonical_walk() {
        let mut lp = LifecycleProcess::new();
        lp.start(1, LifecyclePhase::Planning).unwrap();
        for next in [
            LifecyclePhase::Requirements,
            LifecyclePhase::Architecture,
            LifecyclePhase::Integration,
            LifecyclePhase::SystemTesting,
            LifecyclePhase::Release,
            LifecyclePhase::Maintenance,
        ] {
            lp.transition_to(1, next).unwrap();
        }
        assert_eq!(lp.phase_of(1), Some(LifecyclePhase::Maintenance));
    }

    #[test]
    fn lifecycle_legacy_aliases_map_to_canonical() {
        // Development is equivalent to Architecture in the state machine.
        assert!(LifecyclePhase::Requirements.can_transition_to(LifecyclePhase::Development));
        assert!(LifecyclePhase::Development.can_transition_to(LifecyclePhase::Integration));
        // Verification is equivalent to SystemTesting.
        assert!(LifecyclePhase::Integration.can_transition_to(LifecyclePhase::Verification));
        assert!(LifecyclePhase::Verification.can_transition_to(LifecyclePhase::Release));
    }
}
