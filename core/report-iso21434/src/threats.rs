// SPDX-License-Identifier: Apache-2.0
//
//! Threat catalog, STRIDE categories, and attack feasibility ratings
//! for ISO/SAE 21434 TARA assessments.

/// STRIDE threat classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl StrideCategory {
    /// Returns a human-readable label for this STRIDE category.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Spoofing => "Spoofing",
            Self::Tampering => "Tampering",
            Self::Repudiation => "Repudiation",
            Self::InformationDisclosure => "Information Disclosure",
            Self::DenialOfService => "Denial of Service",
            Self::ElevationOfPrivilege => "Elevation of Privilege",
        }
    }
}

/// Attack feasibility rating per ISO/SAE 21434.
///
/// Ordered from lowest (hardest to exploit) to highest (easiest to exploit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackFeasibility {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Attack vector classification indicating the proximity required for exploitation.
///
/// Ordered from hardest (`Physical`) to easiest (`Network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackVector {
    Physical,
    Local,
    AdjacentNetwork,
    Network,
}

/// A single threat scenario describing an attack against an automotive asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatScenario {
    /// Unique threat identifier (e.g. 1 for T-01).
    pub id: u16,
    /// STRIDE category of this threat.
    pub category: StrideCategory,
    /// Identifier of the asset targeted by this threat.
    pub asset_id: u16,
    /// Attack vector required for exploitation.
    pub vector: AttackVector,
    /// Assessed feasibility of this attack.
    pub feasibility: AttackFeasibility,
    /// Short descriptive label, e.g. "CAN bus injection".
    pub description_tag: &'static str,
}

/// Built-in automotive threat catalog covering 20 common vehicle cyber threats.
///
/// Each threat uses `asset_id = 0` as a placeholder; callers should map threats
/// to their own asset inventory.
pub const AUTOMOTIVE_THREAT_CATALOG: [ThreatScenario; 20] = [
    ThreatScenario {
        id: 1,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        description_tag: "CAN bus message injection",
    },
    ThreatScenario {
        id: 2,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        description_tag: "Replay attack on CAN frames",
    },
    ThreatScenario {
        id: 3,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        description_tag: "OTA firmware manipulation",
    },
    ThreatScenario {
        id: 4,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Medium,
        description_tag: "ECU key extraction via debug port",
    },
    ThreatScenario {
        id: 5,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::High,
        description_tag: "Diagnostic session hijacking",
    },
    ThreatScenario {
        id: 6,
        category: StrideCategory::DenialOfService,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::VeryHigh,
        description_tag: "Denial of bus service via flood",
    },
    ThreatScenario {
        id: 7,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Ethernet SOME/IP spoofing",
    },
    ThreatScenario {
        id: 8,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Low,
        description_tag: "Telematics backdoor",
    },
    ThreatScenario {
        id: 9,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Memory corruption via crafted UDS",
    },
    ThreatScenario {
        id: 10,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        description_tag: "Sensor data manipulation",
    },
    ThreatScenario {
        id: 11,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::High,
        description_tag: "Unauthorized parameter write",
    },
    ThreatScenario {
        id: 12,
        category: StrideCategory::Repudiation,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Log tampering / audit evasion",
    },
    ThreatScenario {
        id: 13,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Low,
        description_tag: "Cryptographic key compromise",
    },
    ThreatScenario {
        id: 14,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        description_tag: "Side-channel key extraction",
    },
    ThreatScenario {
        id: 15,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Malicious OTA downgrade",
    },
    ThreatScenario {
        id: 16,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        description_tag: "VSOC telemetry interception",
    },
    ThreatScenario {
        id: 17,
        category: StrideCategory::DenialOfService,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Watchdog timer bypass",
    },
    ThreatScenario {
        id: 18,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        description_tag: "Boot chain bypass",
    },
    ThreatScenario {
        id: 19,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::Medium,
        description_tag: "Gateway ACL circumvention",
    },
    ThreatScenario {
        id: 20,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        description_tag: "Bluetooth pairing exploit",
    },
];

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn stride_category_labels() {
        assert_eq!(StrideCategory::Spoofing.label(), "Spoofing");
        assert_eq!(StrideCategory::Tampering.label(), "Tampering");
        assert_eq!(StrideCategory::Repudiation.label(), "Repudiation");
        assert_eq!(
            StrideCategory::InformationDisclosure.label(),
            "Information Disclosure"
        );
        assert_eq!(StrideCategory::DenialOfService.label(), "Denial of Service");
        assert_eq!(
            StrideCategory::ElevationOfPrivilege.label(),
            "Elevation of Privilege"
        );
    }

    #[test]
    fn attack_feasibility_ordering() {
        assert!(AttackFeasibility::Low < AttackFeasibility::Medium);
        assert!(AttackFeasibility::Medium < AttackFeasibility::High);
        assert!(AttackFeasibility::High < AttackFeasibility::VeryHigh);
    }

    #[test]
    fn attack_vector_ordering() {
        assert!(AttackVector::Physical < AttackVector::Local);
        assert!(AttackVector::Local < AttackVector::AdjacentNetwork);
        assert!(AttackVector::AdjacentNetwork < AttackVector::Network);
    }

    #[test]
    fn catalog_has_20_entries() {
        assert_eq!(AUTOMOTIVE_THREAT_CATALOG.len(), 20);
    }

    #[test]
    fn catalog_ids_are_1_through_20_and_unique() {
        let mut ids = BTreeSet::new();
        for threat in &AUTOMOTIVE_THREAT_CATALOG {
            assert!(
                threat.id >= 1 && threat.id <= 20,
                "id {} out of range",
                threat.id
            );
            assert!(ids.insert(threat.id), "duplicate id {}", threat.id);
        }
        assert_eq!(ids.len(), 20);
    }

    #[test]
    fn all_stride_categories_represented() {
        let has = |cat: StrideCategory| AUTOMOTIVE_THREAT_CATALOG.iter().any(|t| t.category == cat);
        assert!(has(StrideCategory::Spoofing));
        assert!(has(StrideCategory::Tampering));
        assert!(has(StrideCategory::Repudiation));
        assert!(has(StrideCategory::InformationDisclosure));
        assert!(has(StrideCategory::DenialOfService));
        assert!(has(StrideCategory::ElevationOfPrivilege));
    }

    #[test]
    fn threat_scenario_descriptions_not_empty() {
        for threat in &AUTOMOTIVE_THREAT_CATALOG {
            assert!(
                !threat.description_tag.is_empty(),
                "threat id {} has empty description_tag",
                threat.id
            );
        }
    }
}
