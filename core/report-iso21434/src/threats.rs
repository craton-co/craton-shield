// SPDX-License-Identifier: Apache-2.0
//
//! Threat catalog, STRIDE categories, and attack feasibility ratings
//! for ISO/SAE 21434 TARA assessments.

/// STRIDE threat classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrideCategory {
    /// Spoofing identity — impersonating a legitimate principal.
    Spoofing,
    /// Tampering — unauthorized modification of data or code.
    Tampering,
    /// Repudiation — denying performed actions, weak audit trail.
    Repudiation,
    /// Information disclosure — exposure of confidential data.
    InformationDisclosure,
    /// Denial of service — disruption of legitimate availability.
    DenialOfService,
    /// Elevation of privilege — gaining unauthorized capabilities.
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
    /// Low feasibility — hard to exploit.
    Low,
    /// Medium feasibility — exploitable with moderate effort.
    Medium,
    /// High feasibility — readily exploitable.
    High,
    /// Very high feasibility — trivial to exploit.
    VeryHigh,
}

/// Attack vector classification indicating the proximity required for exploitation.
///
/// Ordered from hardest (`Physical`) to easiest (`Network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackVector {
    /// Physical access to the target hardware required.
    Physical,
    /// Local access (logged-in or on-device process) required.
    Local,
    /// Adjacent-network access (in-vehicle bus or short-range radio) required.
    AdjacentNetwork,
    /// Networked / remote access sufficient.
    Network,
}

/// CVSS-style "elapsed time" component of attack potential per
/// ISO/SAE 21434 Annex G.
///
/// Lower variants describe attacks that need less elapsed time and are
/// therefore more feasible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ElapsedTime {
    /// <= 1 day.
    LessThanDay = 0,
    /// <= 1 week.
    LessThanWeek = 1,
    /// <= 1 month.
    LessThanMonth = 2,
    /// <= 6 months.
    LessThanSixMonths = 3,
    /// > 6 months.
    MoreThanSixMonths = 4,
}

/// CVSS-style "expertise" component of attack potential per
/// ISO/SAE 21434 Annex G.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Expertise {
    /// Layperson — no special skills required.
    Layman = 0,
    /// Proficient — familiar with the security behaviour of the target.
    Proficient = 1,
    /// Expert — familiar with underlying algorithms / protocols / hardware.
    Expert = 2,
    /// Multiple expert disciplines required.
    MultipleExperts = 3,
}

/// CVSS-style "knowledge of the item" component of attack potential per
/// ISO/SAE 21434 Annex G.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Knowledge {
    /// Public information.
    Public = 0,
    /// Restricted to a controlled community (e.g. customers / partners).
    Restricted = 1,
    /// Sensitive — kept inside the manufacturer.
    Sensitive = 2,
    /// Critical / strictly internal.
    Critical = 3,
}

/// CVSS-style "window of opportunity" component of attack potential per
/// ISO/SAE 21434 Annex G.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Window {
    /// Unlimited window — remote and always reachable.
    Unlimited = 0,
    /// Easy access (e.g. workshop / driveway).
    Easy = 1,
    /// Moderate — needs co-located access for a non-trivial time.
    Moderate = 2,
    /// Difficult — physical disassembly or rare circumstances.
    Difficult = 3,
    /// None — only one shot.
    None = 4,
}

/// CVSS-style "equipment" component of attack potential per
/// ISO/SAE 21434 Annex G.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Equipment {
    /// Standard — commodity tools (laptop, OBD-II dongle).
    Standard = 0,
    /// Specialized — protocol analyzers, soldering rework, JTAG.
    Specialized = 1,
    /// Bespoke — custom equipment built for this target.
    Bespoke = 2,
    /// Multiple bespoke setups required.
    MultipleBespoke = 3,
}

/// A single threat scenario describing an attack against an automotive asset.
///
/// `elapsed_time`, `expertise`, `knowledge`, `window`, and `equipment` carry
/// the CVSS-style attack-potential breakdown defined in ISO/SAE 21434
/// Annex G; analysts use them to derive — and to justify — the aggregated
/// [`AttackFeasibility`] rating.
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
    /// Time the attacker must invest (Annex G).
    pub elapsed_time: ElapsedTime,
    /// Expertise the attacker must possess (Annex G).
    pub expertise: Expertise,
    /// Knowledge of the item / TOE required (Annex G).
    pub knowledge: Knowledge,
    /// Window of opportunity available to the attacker (Annex G).
    pub window: Window,
    /// Equipment the attacker must possess (Annex G).
    pub equipment: Equipment,
    /// Short descriptive label, e.g. "CAN bus injection".
    pub description_tag: &'static str,
}

/// Built-in automotive threat catalog covering 20 common vehicle cyber threats.
///
/// Each threat uses `asset_id = 0` as a placeholder; callers must supply a
/// remap of valid asset identifiers when feeding the catalog to
/// `generate_tara_from_catalog`.
pub const AUTOMOTIVE_THREAT_CATALOG: [ThreatScenario; 20] = [
    ThreatScenario {
        id: 1,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        elapsed_time: ElapsedTime::LessThanWeek,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Easy,
        equipment: Equipment::Standard,
        description_tag: "CAN bus message injection",
    },
    ThreatScenario {
        id: 2,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        elapsed_time: ElapsedTime::LessThanWeek,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Easy,
        equipment: Equipment::Standard,
        description_tag: "Replay attack on CAN frames",
    },
    ThreatScenario {
        id: 3,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Unlimited,
        equipment: Equipment::Specialized,
        description_tag: "OTA firmware manipulation",
    },
    ThreatScenario {
        id: 4,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Difficult,
        equipment: Equipment::Specialized,
        description_tag: "ECU key extraction via debug port",
    },
    ThreatScenario {
        id: 5,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::High,
        elapsed_time: ElapsedTime::LessThanWeek,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Easy,
        equipment: Equipment::Standard,
        description_tag: "Diagnostic session hijacking",
    },
    ThreatScenario {
        id: 6,
        category: StrideCategory::DenialOfService,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::VeryHigh,
        elapsed_time: ElapsedTime::LessThanDay,
        expertise: Expertise::Layman,
        knowledge: Knowledge::Public,
        window: Window::Easy,
        equipment: Equipment::Standard,
        description_tag: "Denial of bus service via flood",
    },
    ThreatScenario {
        id: 7,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Moderate,
        equipment: Equipment::Specialized,
        description_tag: "Ethernet SOME/IP spoofing",
    },
    ThreatScenario {
        id: 8,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Low,
        elapsed_time: ElapsedTime::MoreThanSixMonths,
        expertise: Expertise::MultipleExperts,
        knowledge: Knowledge::Critical,
        window: Window::Difficult,
        equipment: Equipment::Bespoke,
        description_tag: "Telematics backdoor",
    },
    ThreatScenario {
        id: 9,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Moderate,
        equipment: Equipment::Specialized,
        description_tag: "Memory corruption via crafted UDS",
    },
    ThreatScenario {
        id: 10,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        elapsed_time: ElapsedTime::LessThanSixMonths,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Difficult,
        equipment: Equipment::Bespoke,
        description_tag: "Sensor data manipulation",
    },
    ThreatScenario {
        id: 11,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::High,
        elapsed_time: ElapsedTime::LessThanWeek,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Easy,
        equipment: Equipment::Standard,
        description_tag: "Unauthorized parameter write",
    },
    ThreatScenario {
        id: 12,
        category: StrideCategory::Repudiation,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Moderate,
        equipment: Equipment::Standard,
        description_tag: "Log tampering / audit evasion",
    },
    ThreatScenario {
        id: 13,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Low,
        elapsed_time: ElapsedTime::LessThanSixMonths,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Moderate,
        equipment: Equipment::Bespoke,
        description_tag: "Cryptographic key compromise",
    },
    ThreatScenario {
        id: 14,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        elapsed_time: ElapsedTime::LessThanSixMonths,
        expertise: Expertise::MultipleExperts,
        knowledge: Knowledge::Critical,
        window: Window::Difficult,
        equipment: Equipment::Bespoke,
        description_tag: "Side-channel key extraction",
    },
    ThreatScenario {
        id: 15,
        category: StrideCategory::Tampering,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Restricted,
        window: Window::Unlimited,
        equipment: Equipment::Specialized,
        description_tag: "Malicious OTA downgrade",
    },
    ThreatScenario {
        id: 16,
        category: StrideCategory::InformationDisclosure,
        asset_id: 0,
        vector: AttackVector::Network,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Unlimited,
        equipment: Equipment::Standard,
        description_tag: "VSOC telemetry interception",
    },
    ThreatScenario {
        id: 17,
        category: StrideCategory::DenialOfService,
        asset_id: 0,
        vector: AttackVector::Local,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Expert,
        knowledge: Knowledge::Sensitive,
        window: Window::Moderate,
        equipment: Equipment::Specialized,
        description_tag: "Watchdog timer bypass",
    },
    ThreatScenario {
        id: 18,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        elapsed_time: ElapsedTime::LessThanSixMonths,
        expertise: Expertise::MultipleExperts,
        knowledge: Knowledge::Critical,
        window: Window::Difficult,
        equipment: Equipment::Bespoke,
        description_tag: "Boot chain bypass",
    },
    ThreatScenario {
        id: 19,
        category: StrideCategory::ElevationOfPrivilege,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::Medium,
        elapsed_time: ElapsedTime::LessThanMonth,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Restricted,
        window: Window::Moderate,
        equipment: Equipment::Specialized,
        description_tag: "Gateway ACL circumvention",
    },
    ThreatScenario {
        id: 20,
        category: StrideCategory::Spoofing,
        asset_id: 0,
        vector: AttackVector::AdjacentNetwork,
        feasibility: AttackFeasibility::High,
        elapsed_time: ElapsedTime::LessThanWeek,
        expertise: Expertise::Proficient,
        knowledge: Knowledge::Public,
        window: Window::Easy,
        equipment: Equipment::Standard,
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

    #[test]
    fn cvss_fields_populated_for_all_catalog_entries() {
        // Every catalog entry must specify a concrete CVSS-style breakdown so
        // the aggregated feasibility rating is traceable to Annex G inputs.
        // The compiler enforces that the fields exist; this test guards
        // against catalog regressions where someone copy-pastes a default.
        let mut elapsed_seen = false;
        let mut expertise_seen = false;
        let mut knowledge_seen = false;
        let mut window_seen = false;
        let mut equipment_seen = false;
        for t in &AUTOMOTIVE_THREAT_CATALOG {
            if t.elapsed_time != ElapsedTime::LessThanDay {
                elapsed_seen = true;
            }
            if t.expertise != Expertise::Layman {
                expertise_seen = true;
            }
            if t.knowledge != Knowledge::Public {
                knowledge_seen = true;
            }
            if t.window != Window::Unlimited {
                window_seen = true;
            }
            if t.equipment != Equipment::Standard {
                equipment_seen = true;
            }
        }
        // The catalog must exercise non-default values for every CVSS axis,
        // otherwise the fields would be vestigial.
        assert!(elapsed_seen, "no non-default elapsed_time in catalog");
        assert!(expertise_seen, "no non-default expertise in catalog");
        assert!(knowledge_seen, "no non-default knowledge in catalog");
        assert!(window_seen, "no non-default window in catalog");
        assert!(equipment_seen, "no non-default equipment in catalog");
    }

    #[test]
    fn cvss_enums_are_ordered_low_to_high() {
        assert!(ElapsedTime::LessThanDay < ElapsedTime::MoreThanSixMonths);
        assert!(Expertise::Layman < Expertise::MultipleExperts);
        assert!(Knowledge::Public < Knowledge::Critical);
        assert!(Window::Unlimited < Window::None);
        assert!(Equipment::Standard < Equipment::MultipleBespoke);
    }
}
