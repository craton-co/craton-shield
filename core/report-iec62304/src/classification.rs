// SPDX-License-Identifier: Apache-2.0
//! IEC 62304 software safety classification model.
//!
//! Defines the safety classes (A, B, C), lifecycle phases, verification
//! methods, and requirement categories mandated by the standard.

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

/// Software lifecycle phase per IEC 62304.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// Active development.
    Development,
    /// Verification and validation in progress.
    Verification,
    /// Post-release maintenance.
    Maintenance,
    /// End-of-life decommissioning.
    Decommissioning,
}

/// Verification method used to validate a software requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}
