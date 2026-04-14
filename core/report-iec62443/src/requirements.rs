// SPDX-License-Identifier: Apache-2.0
//! Domain model for IEC 62443-4-2 Foundational Requirements, Component
//! Requirements, and Security Levels.

use core::fmt;

/// IEC 62443 Security Level (SL-1 through SL-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Protection against casual or coincidental violation.
    Sl1,
    /// Protection against intentional violation using simple means.
    Sl2,
    /// Protection against sophisticated attack with moderate resources.
    Sl3,
    /// Protection against state-sponsored attack with extensive resources.
    Sl4,
}

impl SecurityLevel {
    /// Short label for this Security Level (e.g. "SL-1").
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sl1 => "SL-1",
            Self::Sl2 => "SL-2",
            Self::Sl3 => "SL-3",
            Self::Sl4 => "SL-4",
        }
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sl1 => f.write_str("SL-1"),
            Self::Sl2 => f.write_str("SL-2"),
            Self::Sl3 => f.write_str("SL-3"),
            Self::Sl4 => f.write_str("SL-4"),
        }
    }
}

/// Compliance status for a single Component Requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    /// The requirement is fully met at the target Security Level.
    Compliant,
    /// The requirement is not met at all.
    NonCompliant,
    /// The requirement is partially met (some but not all controls present).
    PartiallyCompliant,
    /// The requirement does not apply at the target Security Level.
    NotApplicable,
    /// The requirement has not been assessed.
    NotAssessed,
}

/// IEC 62443-4-2 Foundational Requirement (FR 1 -- FR 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationalRequirement {
    /// FR 1: Identification and Authentication Control.
    Iac,
    /// FR 2: Use Control.
    Uc,
    /// FR 3: System Integrity.
    Si,
    /// FR 4: Data Confidentiality.
    Dc,
    /// FR 5: Restricted Data Flow.
    Rdf,
    /// FR 6: Timely Response to Events.
    Tre,
    /// FR 7: Resource Availability.
    Ra,
}

impl FoundationalRequirement {
    /// Human-readable name for this Foundational Requirement.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Iac => "Identification and Authentication Control",
            Self::Uc => "Use Control",
            Self::Si => "System Integrity",
            Self::Dc => "Data Confidentiality",
            Self::Rdf => "Restricted Data Flow",
            Self::Tre => "Timely Response to Events",
            Self::Ra => "Resource Availability",
        }
    }
}

/// IEC 62443-4-2 Component Requirement identifier.
///
/// Each variant maps to a specific CR within a Foundational Requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum ComponentRequirement {
    // FR 1 -- Identification and Authentication Control
    /// CR 1.1: Human user identification and authentication.
    Cr1_1,
    /// CR 1.2: Software process and device identification and authentication.
    Cr1_2,
    /// CR 1.3: Account management.
    Cr1_3,
    /// CR 1.4: Identifier management.
    Cr1_4,
    /// CR 1.5: Authenticator management.
    Cr1_5,
    /// CR 1.7: Strength of password-based authentication.
    Cr1_7,
    /// CR 1.8: Public key infrastructure certificates.
    Cr1_8,
    /// CR 1.9: Strength of public key authentication.
    Cr1_9,
    /// CR 1.10: Authenticator feedback.
    Cr1_10,
    /// CR 1.11: Unsuccessful login attempts.
    Cr1_11,
    /// CR 1.12: System use notification.
    Cr1_12,
    /// CR 1.13: Access via untrusted networks.
    Cr1_13,
    /// CR 1.14: Strength of symmetric key authentication.
    Cr1_14,

    // FR 2 -- Use Control
    /// CR 2.1: Authorization enforcement.
    Cr2_1,
    /// CR 2.5: Session lock.
    Cr2_5,
    /// CR 2.6: Remote session termination.
    Cr2_6,
    /// CR 2.7: Concurrent session control.
    Cr2_7,
    /// CR 2.8: Auditable events.
    Cr2_8,
    /// CR 2.9: Audit storage capacity.
    Cr2_9,
    /// CR 2.10: Response to audit processing failures.
    Cr2_10,
    /// CR 2.11: Timestamps.
    Cr2_11,
    /// CR 2.12: Non-repudiation.
    Cr2_12,

    // FR 3 -- System Integrity
    /// CR 3.3: Security functionality verification.
    Cr3_3,
    /// CR 3.4: Software and information integrity.
    Cr3_4,
    /// CR 3.5: Input validation.
    Cr3_5,
    /// CR 3.7: Error handling.
    Cr3_7,
    /// CR 3.8: Session integrity.
    Cr3_8,
    /// CR 3.9: Protection of audit information.
    Cr3_9,

    // FR 4 -- Data Confidentiality
    /// CR 4.1: Information confidentiality.
    Cr4_1,
    /// CR 4.2: Information persistence protection.
    Cr4_2,
    /// CR 4.3: Use of cryptography.
    Cr4_3,

    // FR 5 -- Restricted Data Flow
    /// CR 5.1: Network segmentation.
    Cr5_1,

    // FR 6 -- Timely Response to Events
    /// CR 6.1: Audit log accessibility.
    Cr6_1,
    /// CR 6.2: Continuous monitoring.
    Cr6_2,

    // FR 7 -- Resource Availability
    /// CR 7.1: Denial of service protection.
    Cr7_1,
    /// CR 7.2: Resource management.
    Cr7_2,
    /// CR 7.3: Control system backup.
    Cr7_3,
    /// CR 7.4: Control system recovery and reconstitution.
    Cr7_4,
    /// CR 7.6: Network and security configuration settings.
    Cr7_6,
    /// CR 7.7: Least functionality.
    Cr7_7,
}

/// All `ComponentRequirement` variants in declaration order.
pub const ALL_REQUIREMENTS: [ComponentRequirement; 40] = [
    ComponentRequirement::Cr1_1,
    ComponentRequirement::Cr1_2,
    ComponentRequirement::Cr1_3,
    ComponentRequirement::Cr1_4,
    ComponentRequirement::Cr1_5,
    ComponentRequirement::Cr1_7,
    ComponentRequirement::Cr1_8,
    ComponentRequirement::Cr1_9,
    ComponentRequirement::Cr1_10,
    ComponentRequirement::Cr1_11,
    ComponentRequirement::Cr1_12,
    ComponentRequirement::Cr1_13,
    ComponentRequirement::Cr1_14,
    ComponentRequirement::Cr2_1,
    ComponentRequirement::Cr2_5,
    ComponentRequirement::Cr2_6,
    ComponentRequirement::Cr2_7,
    ComponentRequirement::Cr2_8,
    ComponentRequirement::Cr2_9,
    ComponentRequirement::Cr2_10,
    ComponentRequirement::Cr2_11,
    ComponentRequirement::Cr2_12,
    ComponentRequirement::Cr3_3,
    ComponentRequirement::Cr3_4,
    ComponentRequirement::Cr3_5,
    ComponentRequirement::Cr3_7,
    ComponentRequirement::Cr3_8,
    ComponentRequirement::Cr3_9,
    ComponentRequirement::Cr4_1,
    ComponentRequirement::Cr4_2,
    ComponentRequirement::Cr4_3,
    ComponentRequirement::Cr5_1,
    ComponentRequirement::Cr6_1,
    ComponentRequirement::Cr6_2,
    ComponentRequirement::Cr7_1,
    ComponentRequirement::Cr7_2,
    ComponentRequirement::Cr7_3,
    ComponentRequirement::Cr7_4,
    ComponentRequirement::Cr7_6,
    ComponentRequirement::Cr7_7,
];

impl ComponentRequirement {
    /// The Foundational Requirement this CR belongs to.
    #[must_use]
    pub const fn fr(self) -> FoundationalRequirement {
        match self {
            Self::Cr1_1
            | Self::Cr1_2
            | Self::Cr1_3
            | Self::Cr1_4
            | Self::Cr1_5
            | Self::Cr1_7
            | Self::Cr1_8
            | Self::Cr1_9
            | Self::Cr1_10
            | Self::Cr1_11
            | Self::Cr1_12
            | Self::Cr1_13
            | Self::Cr1_14 => FoundationalRequirement::Iac,

            Self::Cr2_1
            | Self::Cr2_5
            | Self::Cr2_6
            | Self::Cr2_7
            | Self::Cr2_8
            | Self::Cr2_9
            | Self::Cr2_10
            | Self::Cr2_11
            | Self::Cr2_12 => FoundationalRequirement::Uc,

            Self::Cr3_3 | Self::Cr3_4 | Self::Cr3_5 | Self::Cr3_7 | Self::Cr3_8 | Self::Cr3_9 => {
                FoundationalRequirement::Si
            }

            Self::Cr4_1 | Self::Cr4_2 | Self::Cr4_3 => FoundationalRequirement::Dc,

            Self::Cr5_1 => FoundationalRequirement::Rdf,

            Self::Cr6_1 | Self::Cr6_2 => FoundationalRequirement::Tre,

            Self::Cr7_1 | Self::Cr7_2 | Self::Cr7_3 | Self::Cr7_4 | Self::Cr7_6 | Self::Cr7_7 => {
                FoundationalRequirement::Ra
            }
        }
    }

    /// Human-readable label for this Component Requirement.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cr1_1 => "Human user identification and authentication",
            Self::Cr1_2 => "Software process and device identification and authentication",
            Self::Cr1_3 => "Account management",
            Self::Cr1_4 => "Identifier management",
            Self::Cr1_5 => "Authenticator management",
            Self::Cr1_7 => "Strength of password-based authentication",
            Self::Cr1_8 => "Public key infrastructure certificates",
            Self::Cr1_9 => "Strength of public key authentication",
            Self::Cr1_10 => "Authenticator feedback",
            Self::Cr1_11 => "Unsuccessful login attempts",
            Self::Cr1_12 => "System use notification",
            Self::Cr1_13 => "Access via untrusted networks",
            Self::Cr1_14 => "Strength of symmetric key authentication",
            Self::Cr2_1 => "Authorization enforcement",
            Self::Cr2_5 => "Session lock",
            Self::Cr2_6 => "Remote session termination",
            Self::Cr2_7 => "Concurrent session control",
            Self::Cr2_8 => "Auditable events",
            Self::Cr2_9 => "Audit storage capacity",
            Self::Cr2_10 => "Response to audit processing failures",
            Self::Cr2_11 => "Timestamps",
            Self::Cr2_12 => "Non-repudiation",
            Self::Cr3_3 => "Security functionality verification",
            Self::Cr3_4 => "Software and information integrity",
            Self::Cr3_5 => "Input validation",
            Self::Cr3_7 => "Error handling",
            Self::Cr3_8 => "Session integrity",
            Self::Cr3_9 => "Protection of audit information",
            Self::Cr4_1 => "Information confidentiality",
            Self::Cr4_2 => "Information persistence protection",
            Self::Cr4_3 => "Use of cryptography",
            Self::Cr5_1 => "Network segmentation",
            Self::Cr6_1 => "Audit log accessibility",
            Self::Cr6_2 => "Continuous monitoring",
            Self::Cr7_1 => "Denial of service protection",
            Self::Cr7_2 => "Resource management",
            Self::Cr7_3 => "Control system backup",
            Self::Cr7_4 => "Control system recovery and reconstitution",
            Self::Cr7_6 => "Network and security configuration settings",
            Self::Cr7_7 => "Least functionality",
        }
    }

    /// Minimum Security Level at which this CR applies.
    ///
    /// Most CRs apply from SL-1. Some enhanced requirements only become
    /// relevant at SL-2 or above.
    #[must_use]
    pub const fn min_sl(self) -> SecurityLevel {
        match self {
            // SL-2+ requirements
            Self::Cr1_8 | Self::Cr1_9 | Self::Cr1_14 | Self::Cr2_12 | Self::Cr3_7 | Self::Cr6_2 => {
                SecurityLevel::Sl2
            }

            // SL-3+ requirements
            Self::Cr1_12 | Self::Cr2_7 => SecurityLevel::Sl3,

            // Everything else applies from SL-1
            _ => SecurityLevel::Sl1,
        }
    }
}

/// Per-CR assessment result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequirementAssessment {
    /// The Component Requirement that was assessed.
    pub requirement: ComponentRequirement,
    /// The target Security Level for this assessment.
    pub target_sl: SecurityLevel,
    /// The Security Level actually achieved for this CR.
    pub achieved_sl: SecurityLevel,
    /// Overall compliance status for this CR against the target.
    pub status: ComplianceStatus,
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;

    #[test]
    fn security_level_labels() {
        assert_eq!(SecurityLevel::Sl1.label(), "SL-1");
        assert_eq!(SecurityLevel::Sl2.label(), "SL-2");
        assert_eq!(SecurityLevel::Sl3.label(), "SL-3");
        assert_eq!(SecurityLevel::Sl4.label(), "SL-4");
    }

    #[test]
    fn security_level_ordering() {
        assert!(SecurityLevel::Sl1 < SecurityLevel::Sl2);
        assert!(SecurityLevel::Sl2 < SecurityLevel::Sl3);
        assert!(SecurityLevel::Sl3 < SecurityLevel::Sl4);
    }

    #[test]
    fn security_level_display() {
        assert_eq!(format!("{}", SecurityLevel::Sl1), "SL-1");
        assert_eq!(format!("{}", SecurityLevel::Sl2), "SL-2");
        assert_eq!(format!("{}", SecurityLevel::Sl3), "SL-3");
        assert_eq!(format!("{}", SecurityLevel::Sl4), "SL-4");
    }

    #[test]
    fn compliance_status_variants() {
        let _ = ComplianceStatus::Compliant;
        let _ = ComplianceStatus::NonCompliant;
        let _ = ComplianceStatus::PartiallyCompliant;
        let _ = ComplianceStatus::NotApplicable;
        let _ = ComplianceStatus::NotAssessed;
    }

    #[test]
    fn foundational_requirement_labels() {
        assert_eq!(
            FoundationalRequirement::Iac.label(),
            "Identification and Authentication Control"
        );
        assert_eq!(FoundationalRequirement::Uc.label(), "Use Control");
        assert_eq!(FoundationalRequirement::Si.label(), "System Integrity");
        assert_eq!(FoundationalRequirement::Dc.label(), "Data Confidentiality");
        assert_eq!(FoundationalRequirement::Rdf.label(), "Restricted Data Flow");
        assert_eq!(
            FoundationalRequirement::Tre.label(),
            "Timely Response to Events"
        );
        assert_eq!(FoundationalRequirement::Ra.label(), "Resource Availability");
    }

    #[test]
    fn component_requirement_fr_mapping() {
        // One sample from each FR group
        assert_eq!(
            ComponentRequirement::Cr1_1.fr(),
            FoundationalRequirement::Iac
        );
        assert_eq!(
            ComponentRequirement::Cr1_14.fr(),
            FoundationalRequirement::Iac
        );
        assert_eq!(
            ComponentRequirement::Cr2_1.fr(),
            FoundationalRequirement::Uc
        );
        assert_eq!(
            ComponentRequirement::Cr2_12.fr(),
            FoundationalRequirement::Uc
        );
        assert_eq!(
            ComponentRequirement::Cr3_3.fr(),
            FoundationalRequirement::Si
        );
        assert_eq!(
            ComponentRequirement::Cr3_9.fr(),
            FoundationalRequirement::Si
        );
        assert_eq!(
            ComponentRequirement::Cr4_1.fr(),
            FoundationalRequirement::Dc
        );
        assert_eq!(
            ComponentRequirement::Cr4_3.fr(),
            FoundationalRequirement::Dc
        );
        assert_eq!(
            ComponentRequirement::Cr5_1.fr(),
            FoundationalRequirement::Rdf
        );
        assert_eq!(
            ComponentRequirement::Cr6_1.fr(),
            FoundationalRequirement::Tre
        );
        assert_eq!(
            ComponentRequirement::Cr6_2.fr(),
            FoundationalRequirement::Tre
        );
        assert_eq!(
            ComponentRequirement::Cr7_1.fr(),
            FoundationalRequirement::Ra
        );
        assert_eq!(
            ComponentRequirement::Cr7_7.fr(),
            FoundationalRequirement::Ra
        );
    }

    #[test]
    fn component_requirement_labels() {
        assert_eq!(
            ComponentRequirement::Cr1_1.label(),
            "Human user identification and authentication"
        );
        assert_eq!(
            ComponentRequirement::Cr2_1.label(),
            "Authorization enforcement"
        );
        assert_eq!(ComponentRequirement::Cr3_5.label(), "Input validation");
        assert_eq!(ComponentRequirement::Cr4_3.label(), "Use of cryptography");
        assert_eq!(ComponentRequirement::Cr5_1.label(), "Network segmentation");
        assert_eq!(
            ComponentRequirement::Cr7_1.label(),
            "Denial of service protection"
        );
    }

    #[test]
    fn min_sl_sl2_requirements() {
        assert_eq!(ComponentRequirement::Cr1_8.min_sl(), SecurityLevel::Sl2);
        assert_eq!(ComponentRequirement::Cr1_9.min_sl(), SecurityLevel::Sl2);
        assert_eq!(ComponentRequirement::Cr1_14.min_sl(), SecurityLevel::Sl2);
        assert_eq!(ComponentRequirement::Cr2_12.min_sl(), SecurityLevel::Sl2);
        assert_eq!(ComponentRequirement::Cr3_7.min_sl(), SecurityLevel::Sl2);
        assert_eq!(ComponentRequirement::Cr6_2.min_sl(), SecurityLevel::Sl2);
    }

    #[test]
    fn min_sl_sl3_requirements() {
        assert_eq!(ComponentRequirement::Cr1_12.min_sl(), SecurityLevel::Sl3);
        assert_eq!(ComponentRequirement::Cr2_7.min_sl(), SecurityLevel::Sl3);
    }

    #[test]
    fn min_sl_default_is_sl1() {
        assert_eq!(ComponentRequirement::Cr1_1.min_sl(), SecurityLevel::Sl1);
        assert_eq!(ComponentRequirement::Cr2_1.min_sl(), SecurityLevel::Sl1);
        assert_eq!(ComponentRequirement::Cr3_3.min_sl(), SecurityLevel::Sl1);
        assert_eq!(ComponentRequirement::Cr4_1.min_sl(), SecurityLevel::Sl1);
        assert_eq!(ComponentRequirement::Cr7_1.min_sl(), SecurityLevel::Sl1);
    }

    #[test]
    fn all_requirements_has_40_elements() {
        assert_eq!(ALL_REQUIREMENTS.len(), 40);
    }

    #[test]
    fn requirement_assessment_construction() {
        let assessment = RequirementAssessment {
            requirement: ComponentRequirement::Cr1_1,
            target_sl: SecurityLevel::Sl3,
            achieved_sl: SecurityLevel::Sl2,
            status: ComplianceStatus::PartiallyCompliant,
        };
        assert_eq!(assessment.requirement, ComponentRequirement::Cr1_1);
        assert_eq!(assessment.target_sl, SecurityLevel::Sl3);
        assert_eq!(assessment.achieved_sl, SecurityLevel::Sl2);
        assert_eq!(assessment.status, ComplianceStatus::PartiallyCompliant);
    }
}
