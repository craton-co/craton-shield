#![no_std]
#![forbid(unsafe_code)]
//! ISO/SAE 21434 Threat Analysis and Risk Assessment (TARA) report generator.
//!
//! Produces fully stack-allocated TARA reports for automotive cybersecurity
//! assessments. Includes a built-in catalog of 20 common automotive threat
//! scenarios and a standard 4x4 risk matrix.

pub mod risk;
pub mod threats;

use risk::{compute_risk, DamageScenario, RiskLevel, TreatmentDecision};
use threats::{AttackFeasibility, ThreatScenario, AUTOMOTIVE_THREAT_CATALOG};
use vs_types::VsError;

/// Maximum number of threat scenarios in a single TARA assessment.
pub const MAX_THREATS: usize = 32;

/// Maximum number of assets that can be assessed.
pub const MAX_ASSETS: usize = 16;

/// An automotive cybersecurity asset subject to threat analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asset {
    /// Unique asset identifier.
    pub id: u16,
    /// UTF-8 label stored in a fixed-size buffer, null-terminated.
    pub label: [u8; 32],
    /// Number of valid bytes in `label`.
    pub label_len: u8,
    /// Whether this asset is relevant for cybersecurity analysis.
    pub cybersecurity_relevant: bool,
}

/// Per-threat assessment result combining threat, damage, risk, and treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatAssessment {
    /// The threat scenario being assessed.
    pub threat: ThreatScenario,
    /// The associated damage scenario.
    pub damage: DamageScenario,
    /// Computed risk level from the risk matrix.
    pub risk_level: RiskLevel,
    /// Selected treatment decision.
    pub treatment: TreatmentDecision,
    /// `true` if a security control exists that mitigates this threat.
    pub mitigated: bool,
}

/// Input data for a TARA assessment.
///
/// The caller populates this struct with assets, threats, damage scenarios,
/// and mitigation status before calling [`generate_tara`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaraInput {
    /// Asset inventory.
    pub assets: [Asset; MAX_ASSETS],
    /// Number of valid assets in the `assets` array.
    pub asset_count: usize,
    /// Threat scenarios to assess.
    pub threats: [ThreatScenario; MAX_THREATS],
    /// Number of valid threats in the `threats` array.
    pub threat_count: usize,
    /// Damage scenarios, one per threat (matched by `threat_id`).
    pub damages: [DamageScenario; MAX_THREATS],
    /// Number of valid damage scenarios.
    pub damage_count: usize,
    /// Per-threat mitigation status (indexed by threat position).
    pub mitigations: [bool; MAX_THREATS],
    /// Default treatment for unmitigated threats.
    pub default_treatment: TreatmentDecision,
}

/// Output of a TARA assessment containing all per-threat results and summary
/// statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaraReport {
    /// Per-threat assessment results.
    pub assessments: [ThreatAssessment; MAX_THREATS],
    /// Number of valid assessments.
    pub count: usize,
    /// Number of threats with `Critical` risk level.
    pub critical_count: usize,
    /// Number of threats with `High` risk level.
    pub high_count: usize,
    /// Number of threats with `Medium` risk level.
    pub medium_count: usize,
    /// Number of threats with `Low` risk level.
    pub low_count: usize,
    /// Number of threats that have an active mitigation.
    pub mitigated_count: usize,
    /// Number of unmitigated threats at `High` or `Critical` risk.
    pub residual_risk_count: usize,
}

impl TaraReport {
    /// Returns `true` if any unmitigated threats remain at `High` or `Critical`
    /// risk.
    #[must_use]
    pub fn has_residual_risk(&self) -> bool {
        self.residual_risk_count > 0
    }

    /// Returns the highest risk level found across all assessed threats.
    ///
    /// Returns `RiskLevel::Low` if the report contains no assessments.
    #[must_use]
    pub fn highest_risk(&self) -> RiskLevel {
        let mut highest = RiskLevel::Low;
        let mut i = 0;
        while i < self.count {
            if self.assessments[i].risk_level > highest {
                highest = self.assessments[i].risk_level;
            }
            i += 1;
        }
        highest
    }
}

/// Finds the damage scenario for a given `threat_id` in the damages array.
fn find_damage(
    damages: &[DamageScenario; MAX_THREATS],
    damage_count: usize,
    threat_id: u16,
) -> Option<DamageScenario> {
    let mut i = 0;
    while i < damage_count {
        if damages[i].threat_id == threat_id {
            return Some(damages[i]);
        }
        i += 1;
    }
    None
}

/// Creates a zeroed `ThreatAssessment` for use as array padding.
const fn zeroed_assessment() -> ThreatAssessment {
    ThreatAssessment {
        threat: ThreatScenario {
            id: 0,
            category: threats::StrideCategory::Spoofing,
            asset_id: 0,
            vector: threats::AttackVector::Physical,
            feasibility: AttackFeasibility::Low,
            description_tag: "",
        },
        damage: DamageScenario {
            threat_id: 0,
            safety_impact: risk::ImpactLevel::Negligible,
            financial_impact: risk::ImpactLevel::Negligible,
            operational_impact: risk::ImpactLevel::Negligible,
            privacy_impact: risk::ImpactLevel::Negligible,
        },
        risk_level: RiskLevel::Low,
        treatment: TreatmentDecision::Accept,
        mitigated: false,
    }
}

/// Creates a zeroed `Asset` for use as array padding.
const fn zeroed_asset() -> Asset {
    Asset {
        id: 0,
        label: [0u8; 32],
        label_len: 0,
        cybersecurity_relevant: false,
    }
}

/// Creates a zeroed `ThreatScenario` for use as array padding.
const fn zeroed_threat() -> ThreatScenario {
    ThreatScenario {
        id: 0,
        category: threats::StrideCategory::Spoofing,
        asset_id: 0,
        vector: threats::AttackVector::Physical,
        feasibility: AttackFeasibility::Low,
        description_tag: "",
    }
}

/// Creates a zeroed `DamageScenario` for use as array padding.
const fn zeroed_damage() -> DamageScenario {
    DamageScenario {
        threat_id: 0,
        safety_impact: risk::ImpactLevel::Negligible,
        financial_impact: risk::ImpactLevel::Negligible,
        operational_impact: risk::ImpactLevel::Negligible,
        privacy_impact: risk::ImpactLevel::Negligible,
    }
}

/// Returns `true` if the given counts are within the capacity limits of a
/// TARA assessment.
///
/// Use this before constructing a [`TaraInput`] to detect whether the input
/// will be truncated or rejected.
#[must_use]
pub const fn is_input_valid_size(threat_count: usize, asset_count: usize) -> bool {
    threat_count <= MAX_THREATS && asset_count <= MAX_ASSETS
}

/// Creates a default `TaraInput` with all fields zeroed.
#[must_use]
pub fn empty_input() -> TaraInput {
    TaraInput {
        assets: [zeroed_asset(); MAX_ASSETS],
        asset_count: 0,
        threats: [zeroed_threat(); MAX_THREATS],
        threat_count: 0,
        damages: [zeroed_damage(); MAX_THREATS],
        damage_count: 0,
        mitigations: [false; MAX_THREATS],
        default_treatment: TreatmentDecision::Accept,
    }
}

/// Generates a TARA report from the provided input.
///
/// # Errors
///
/// Returns `VsError::InvalidInput` if:
/// - `threat_count` exceeds `MAX_THREATS`
/// - `damage_count` exceeds `MAX_THREATS`
/// - `asset_count` exceeds `MAX_ASSETS`
/// - Any threat has `asset_id == 0` (placeholder value)
/// - A threat has no matching damage scenario
pub fn generate_tara(input: &TaraInput) -> Result<TaraReport, VsError> {
    if input.threat_count > MAX_THREATS {
        return Err(VsError::InvalidInput);
    }
    if input.damage_count > MAX_THREATS {
        return Err(VsError::InvalidInput);
    }
    if input.asset_count > MAX_ASSETS {
        return Err(VsError::InvalidInput);
    }

    // Reject threats with placeholder asset_id == 0.
    let mut j = 0;
    while j < input.threat_count {
        if input.threats[j].asset_id == 0 {
            return Err(VsError::InvalidInput);
        }
        j += 1;
    }

    let mut report = TaraReport {
        assessments: [zeroed_assessment(); MAX_THREATS],
        count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        mitigated_count: 0,
        residual_risk_count: 0,
    };

    let mut i = 0;
    while i < input.threat_count {
        let threat = input.threats[i];
        let Some(damage) = find_damage(&input.damages, input.damage_count, threat.id) else {
            return Err(VsError::InvalidInput);
        };

        let risk_level = compute_risk(threat.feasibility, damage.max_impact());
        let mitigated = input.mitigations[i];

        let treatment = if mitigated {
            TreatmentDecision::Reduce
        } else if risk_level == RiskLevel::Critical {
            TreatmentDecision::Avoid
        } else {
            input.default_treatment
        };

        report.assessments[i] = ThreatAssessment {
            threat,
            damage,
            risk_level,
            treatment,
            mitigated,
        };

        match risk_level {
            RiskLevel::Critical => report.critical_count += 1,
            RiskLevel::High => report.high_count += 1,
            RiskLevel::Medium => report.medium_count += 1,
            RiskLevel::Low => report.low_count += 1,
        }

        if mitigated {
            report.mitigated_count += 1;
        }

        if !mitigated && (risk_level >= RiskLevel::High) {
            report.residual_risk_count += 1;
        }

        i += 1;
    }

    report.count = input.threat_count;
    Ok(report)
}

/// Convenience function that generates a TARA report using the built-in
/// [`AUTOMOTIVE_THREAT_CATALOG`] as the threat source.
///
/// Only threats whose `asset_id` appears in `asset_ids` are included.
/// The caller provides damage scenarios and mitigation flags for the
/// matching threats.
///
/// # Errors
///
/// Returns `VsError::InvalidInput` if `damage_count` exceeds `MAX_THREATS`
/// or a matching threat lacks a damage scenario.
pub fn generate_tara_from_catalog(
    asset_ids: &[u16],
    damages: &[DamageScenario],
    mitigations: &[bool],
    damage_count: usize,
) -> Result<TaraReport, VsError> {
    if damage_count > MAX_THREATS {
        return Err(VsError::InvalidInput);
    }

    let mut input = empty_input();

    let mut threat_idx = 0;
    for catalog_threat in &AUTOMOTIVE_THREAT_CATALOG {
        if threat_idx >= MAX_THREATS {
            break;
        }
        let mut matched = false;
        for aid in asset_ids {
            if catalog_threat.asset_id == *aid {
                matched = true;
                break;
            }
        }
        if matched {
            input.threats[threat_idx] = *catalog_threat;
            if threat_idx < mitigations.len() {
                input.mitigations[threat_idx] = mitigations[threat_idx];
            }
            threat_idx += 1;
        }
    }
    input.threat_count = threat_idx;

    let copy_len = damage_count.min(MAX_THREATS).min(damages.len());
    let mut d = 0;
    while d < copy_len {
        input.damages[d] = damages[d];
        d += 1;
    }
    input.damage_count = copy_len;

    input.default_treatment = TreatmentDecision::Accept;

    generate_tara(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{DamageScenario, ImpactLevel, RiskLevel, TreatmentDecision};
    use crate::threats::{
        AttackFeasibility, AttackVector, StrideCategory, ThreatScenario, AUTOMOTIVE_THREAT_CATALOG,
    };

    fn make_threat(id: u16, feasibility: AttackFeasibility) -> ThreatScenario {
        ThreatScenario {
            id,
            category: StrideCategory::Tampering,
            asset_id: 1,
            vector: AttackVector::Network,
            feasibility,
            description_tag: "test threat",
        }
    }

    fn make_damage(threat_id: u16, impact: ImpactLevel) -> DamageScenario {
        DamageScenario {
            threat_id,
            safety_impact: impact,
            financial_impact: ImpactLevel::Negligible,
            operational_impact: ImpactLevel::Negligible,
            privacy_impact: ImpactLevel::Negligible,
        }
    }

    fn single_threat_input(
        feasibility: AttackFeasibility,
        impact: ImpactLevel,
        mitigated: bool,
    ) -> TaraInput {
        let mut input = empty_input();
        input.threats[0] = make_threat(1, feasibility);
        input.threat_count = 1;
        input.damages[0] = make_damage(1, impact);
        input.damage_count = 1;
        input.mitigations[0] = mitigated;
        input.default_treatment = TreatmentDecision::Accept;
        input
    }

    #[test]
    fn empty_input_produces_empty_report() {
        let input = empty_input();
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count, 0);
        assert_eq!(report.critical_count, 0);
        assert_eq!(report.high_count, 0);
        assert_eq!(report.medium_count, 0);
        assert_eq!(report.low_count, 0);
        assert!(!report.has_residual_risk());
    }

    #[test]
    fn single_threat_negligible_impact_is_low() {
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Negligible, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count, 1);
        assert_eq!(report.assessments[0].risk_level, RiskLevel::Low);
        assert_eq!(report.low_count, 1);
    }

    #[test]
    fn single_threat_severe_veryhigh_is_critical() {
        let input = single_threat_input(AttackFeasibility::VeryHigh, ImpactLevel::Severe, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.assessments[0].risk_level, RiskLevel::Critical);
        assert_eq!(report.critical_count, 1);
    }

    #[test]
    fn risk_matrix_all_16_combinations() {
        let feasibilities = [
            AttackFeasibility::Low,
            AttackFeasibility::Medium,
            AttackFeasibility::High,
            AttackFeasibility::VeryHigh,
        ];
        let impacts = [
            ImpactLevel::Negligible,
            ImpactLevel::Moderate,
            ImpactLevel::Major,
            ImpactLevel::Severe,
        ];
        // Expected results row-by-row (impact varies rows, feasibility varies columns)
        let expected: [[RiskLevel; 4]; 4] = [
            // Negligible
            [
                RiskLevel::Low,
                RiskLevel::Low,
                RiskLevel::Low,
                RiskLevel::Low,
            ],
            // Moderate
            [
                RiskLevel::Low,
                RiskLevel::Medium,
                RiskLevel::Medium,
                RiskLevel::High,
            ],
            // Major
            [
                RiskLevel::Medium,
                RiskLevel::Medium,
                RiskLevel::High,
                RiskLevel::Critical,
            ],
            // Severe
            [
                RiskLevel::Medium,
                RiskLevel::High,
                RiskLevel::Critical,
                RiskLevel::Critical,
            ],
        ];

        for (i_idx, impact) in impacts.iter().enumerate() {
            for (f_idx, feasibility) in feasibilities.iter().enumerate() {
                let result = compute_risk(*feasibility, *impact);
                assert_eq!(
                    result, expected[i_idx][f_idx],
                    "Mismatch at impact={i_idx}, feasibility={f_idx}"
                );
            }
        }
    }

    #[test]
    fn mitigation_sets_treatment_to_reduce() {
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, true);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.assessments[0].treatment, TreatmentDecision::Reduce);
        assert!(report.assessments[0].mitigated);
        assert_eq!(report.mitigated_count, 1);
    }

    #[test]
    fn unmitigated_critical_increases_residual_risk() {
        let input = single_threat_input(AttackFeasibility::VeryHigh, ImpactLevel::Severe, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.residual_risk_count, 1);
        assert!(report.has_residual_risk());
        // Unmitigated critical should get Avoid treatment
        assert_eq!(report.assessments[0].treatment, TreatmentDecision::Avoid);
    }

    #[test]
    fn full_automotive_catalog_assessment() {
        let mut input = empty_input();
        let catalog = &AUTOMOTIVE_THREAT_CATALOG;

        for (i, threat) in catalog.iter().enumerate() {
            let mut t = *threat;
            // Remap placeholder asset_id to a valid value.
            t.asset_id = 1;
            input.threats[i] = t;
            input.damages[i] = DamageScenario {
                threat_id: threat.id,
                safety_impact: ImpactLevel::Moderate,
                financial_impact: ImpactLevel::Moderate,
                operational_impact: ImpactLevel::Moderate,
                privacy_impact: ImpactLevel::Negligible,
            };
        }
        input.threat_count = 20;
        input.damage_count = 20;
        input.default_treatment = TreatmentDecision::Accept;

        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count, 20);
        // All counts should sum to 20
        let total =
            report.critical_count + report.high_count + report.medium_count + report.low_count;
        assert_eq!(total, 20);
    }

    #[test]
    fn invalid_input_threat_count_exceeds_max() {
        let mut input = empty_input();
        input.threat_count = MAX_THREATS + 1;
        let result = generate_tara(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn has_residual_risk_with_unmitigated_high() {
        // High feasibility + Major impact = High risk
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.assessments[0].risk_level, RiskLevel::High);
        assert!(report.has_residual_risk());
    }

    #[test]
    fn highest_risk_returns_correct_maximum() {
        let mut input = empty_input();
        // Threat 1: Low risk (Negligible impact)
        input.threats[0] = make_threat(1, AttackFeasibility::Low);
        input.damages[0] = make_damage(1, ImpactLevel::Negligible);
        // Threat 2: High risk (Major + High)
        input.threats[1] = make_threat(2, AttackFeasibility::High);
        input.damages[1] = make_damage(2, ImpactLevel::Major);
        // Threat 3: Medium risk (Moderate + Medium)
        input.threats[2] = make_threat(3, AttackFeasibility::Medium);
        input.damages[2] = make_damage(3, ImpactLevel::Moderate);

        input.threat_count = 3;
        input.damage_count = 3;
        input.default_treatment = TreatmentDecision::Accept;

        let report = generate_tara(&input).unwrap();
        assert_eq!(report.highest_risk(), RiskLevel::High);
    }

    #[test]
    fn missing_damage_scenario_returns_error() {
        let mut input = empty_input();
        input.threats[0] = make_threat(99, AttackFeasibility::High);
        input.threat_count = 1;
        // No damage for threat id 99
        input.damage_count = 0;
        let result = generate_tara(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn damage_scenario_max_impact_picks_worst() {
        let d = DamageScenario {
            threat_id: 1,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Severe,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Major,
        };
        assert_eq!(d.max_impact(), ImpactLevel::Severe);
    }

    #[test]
    fn generate_tara_from_catalog_short_damages_no_oob() {
        // Regression: damage_count > damages.len() must not OOB.
        let asset_ids = [1u16, 2];
        let damages = [make_damage(1, ImpactLevel::Moderate)]; // len=1
        let mitigations = [false; 0];
        // damage_count=1, damages.len()=1 — should not panic
        let _ = generate_tara_from_catalog(&asset_ids, &damages, &mitigations, 1);
    }

    #[test]
    fn generate_tara_from_catalog_zero_damages_no_match() {
        // asset_id=1 has no matching threats in the catalog (all are asset_id=0),
        // so the result is an empty report, not an error.
        let asset_ids = [1u16];
        let damages: [DamageScenario; 0] = [];
        let mitigations: [bool; 0] = [];
        let result = generate_tara_from_catalog(&asset_ids, &damages, &mitigations, 0);
        let report = result.unwrap();
        assert_eq!(report.count, 0);
    }

    #[test]
    fn generate_tara_from_catalog_matching_threat_no_damage_errors() {
        // asset_id=0 matches catalog threats; now rejected because asset_id==0
        // is the placeholder value.
        let asset_ids = [0u16];
        let damages: [DamageScenario; 0] = [];
        let mitigations: [bool; 0] = [];
        let result = generate_tara_from_catalog(&asset_ids, &damages, &mitigations, 0);
        assert!(result.is_err());
    }

    #[test]
    fn generate_tara_from_catalog_damage_count_larger_than_slice() {
        // damage_count says 5, but slice only has 2 elements.
        // The fix clamps copy_len to damages.len().
        let asset_ids = [1u16];
        let damages = [
            make_damage(1, ImpactLevel::Moderate),
            make_damage(2, ImpactLevel::Severe),
        ];
        let mitigations = [false; 2];
        // damage_count=5 > damages.len()=2 — must NOT panic
        let _ = generate_tara_from_catalog(&asset_ids, &damages, &mitigations, 5);
    }

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
    fn test_max_impact_all_categories() {
        // Financial is highest
        let d_fin = DamageScenario {
            threat_id: 1,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Severe,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Major,
        };
        assert_eq!(d_fin.max_impact(), ImpactLevel::Severe);

        // Operational is highest
        let d_ops = DamageScenario {
            threat_id: 2,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Moderate,
            operational_impact: ImpactLevel::Severe,
            privacy_impact: ImpactLevel::Major,
        };
        assert_eq!(d_ops.max_impact(), ImpactLevel::Severe);

        // Privacy is highest
        let d_priv = DamageScenario {
            threat_id: 3,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Moderate,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Severe,
        };
        assert_eq!(d_priv.max_impact(), ImpactLevel::Severe);

        // Safety is highest
        let d_safety = DamageScenario {
            threat_id: 4,
            safety_impact: ImpactLevel::Severe,
            financial_impact: ImpactLevel::Moderate,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Moderate,
        };
        assert_eq!(d_safety.max_impact(), ImpactLevel::Severe);
    }

    #[test]
    fn test_treatment_decisions_distinct() {
        let variants = [
            TreatmentDecision::Avoid,
            TreatmentDecision::Reduce,
            TreatmentDecision::Transfer,
            TreatmentDecision::Accept,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i], variants[j],
                    "TreatmentDecision variants at index {} and {} should be distinct",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_attack_vectors_distinct() {
        let variants = [
            AttackVector::Physical,
            AttackVector::Local,
            AttackVector::AdjacentNetwork,
            AttackVector::Network,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i], variants[j],
                    "AttackVector variants at index {} and {} should be distinct",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_mitigated_high_no_residual_risk() {
        // High risk but mitigated -- should NOT count as residual risk
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, true);
        let report = generate_tara(&input).unwrap();

        assert_eq!(report.assessments[0].risk_level, RiskLevel::High);
        assert!(report.assessments[0].mitigated);
        assert_eq!(report.residual_risk_count, 0);
        assert!(!report.has_residual_risk());
    }

    #[test]
    fn test_multiple_threats_mixed_risk() {
        let mut input = empty_input();

        // Low risk: Low feasibility + Negligible impact
        input.threats[0] = make_threat(1, AttackFeasibility::Low);
        input.damages[0] = make_damage(1, ImpactLevel::Negligible);

        // Medium risk: Medium feasibility + Moderate impact
        input.threats[1] = make_threat(2, AttackFeasibility::Medium);
        input.damages[1] = make_damage(2, ImpactLevel::Moderate);

        // High risk: High feasibility + Major impact
        input.threats[2] = make_threat(3, AttackFeasibility::High);
        input.damages[2] = make_damage(3, ImpactLevel::Major);

        // Critical risk: VeryHigh feasibility + Severe impact
        input.threats[3] = make_threat(4, AttackFeasibility::VeryHigh);
        input.damages[3] = make_damage(4, ImpactLevel::Severe);

        input.threat_count = 4;
        input.damage_count = 4;
        input.default_treatment = TreatmentDecision::Accept;

        let report = generate_tara(&input).unwrap();

        assert_eq!(report.count, 4);
        assert_eq!(report.low_count, 1);
        assert_eq!(report.medium_count, 1);
        assert_eq!(report.high_count, 1);
        assert_eq!(report.critical_count, 1);
    }

    #[test]
    fn test_generate_tara_from_catalog_with_all_assets() {
        // Catalog threats use asset_id=0 (placeholder), which is now rejected.
        // Build a custom input with remapped asset_ids instead.
        let mut input = empty_input();
        for (i, threat) in AUTOMOTIVE_THREAT_CATALOG.iter().enumerate() {
            let mut t = *threat;
            t.asset_id = 1; // Remap placeholder to valid id.
            input.threats[i] = t;
            input.damages[i] = DamageScenario {
                threat_id: threat.id,
                safety_impact: ImpactLevel::Moderate,
                financial_impact: ImpactLevel::Moderate,
                operational_impact: ImpactLevel::Moderate,
                privacy_impact: ImpactLevel::Negligible,
            };
        }
        input.threat_count = 20;
        input.damage_count = 20;
        input.default_treatment = TreatmentDecision::Accept;

        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count, 20);

        let total =
            report.critical_count + report.high_count + report.medium_count + report.low_count;
        assert_eq!(total, 20);
    }

    #[test]
    fn test_highest_risk_empty_report() {
        let input = empty_input();
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.highest_risk(), RiskLevel::Low);
    }

    #[test]
    fn test_asset_count_exceeds_max() {
        let mut input = empty_input();
        input.asset_count = MAX_ASSETS + 1;
        let result = generate_tara(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_damage_count_exceeds_max() {
        let mut input = empty_input();
        input.damage_count = MAX_THREATS + 1;
        let result = generate_tara(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_asset_id_zero_rejected() {
        let mut input = empty_input();
        input.threats[0] = ThreatScenario {
            id: 1,
            category: StrideCategory::Tampering,
            asset_id: 0, // placeholder -- must be rejected
            vector: AttackVector::Network,
            feasibility: AttackFeasibility::High,
            description_tag: "test",
        };
        input.threat_count = 1;
        input.damages[0] = make_damage(1, ImpactLevel::Moderate);
        input.damage_count = 1;
        let result = generate_tara(&input);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn test_asset_id_nonzero_accepted() {
        let mut input = empty_input();
        input.threats[0] = make_threat(1, AttackFeasibility::High);
        input.threat_count = 1;
        input.damages[0] = make_damage(1, ImpactLevel::Moderate);
        input.damage_count = 1;
        let result = generate_tara(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_input_valid_size() {
        assert!(is_input_valid_size(0, 0));
        assert!(is_input_valid_size(MAX_THREATS, MAX_ASSETS));
        assert!(!is_input_valid_size(MAX_THREATS + 1, 0));
        assert!(!is_input_valid_size(0, MAX_ASSETS + 1));
    }
}
