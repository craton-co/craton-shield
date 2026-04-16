#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Unofficial ISO/SAE 21434 TARA helper; not an official ISO/SAE product.
//!
//! Implements a Threat Analysis and Risk Assessment (TARA) report generator
//! for ISO/SAE 21434:2021 §15 compliance evidence (Road vehicles --
//! Cybersecurity engineering). Produces fully stack-allocated TARA reports
//! for automotive cybersecurity assessments. Includes a built-in catalog of
//! 20 common automotive threat scenarios and a standard 4x4 risk matrix.
//!
//! # Public API (Pre-1.0 — workspace version 0.7.0)
//!
//! The `TaraReport` builder, the `ThreatScenario` / `DamageScenario` /
//! `RiskLevel` types, and the `compute_risk` standalone function form the
//! pre-1.0 surface and are governed by `DEPRECATION.md`.

pub mod risk;
pub mod threats;

use risk::{compute_risk, DamageScenario, RiskLevel, TreatmentDecision};
use threats::{
    AttackFeasibility, ElapsedTime, Equipment, Expertise, Knowledge, ThreatScenario, Window,
    AUTOMOTIVE_THREAT_CATALOG,
};
use vs_evidence_envelope::{Evidence, EvidenceMetadata, Standard};
use vs_types::VsError;

/// Maximum number of threat scenarios in a single TARA assessment.
pub const MAX_THREATS: usize = 32;

/// Maximum number of assets that can be assessed.
pub const MAX_ASSETS: usize = 16;

/// Cybersecurity goal an asset contributes to per ISO/SAE 21434 §15.
///
/// Used to link assets to the C/I/A triad so the resulting TARA can be
/// cross-referenced against high-level cybersecurity goals. Marked
/// `#[non_exhaustive]` so additional goals (e.g. authenticity, non-repudiation)
/// can be added without breaking downstream code.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CiaClass {
    /// Confidentiality — protection from unauthorized disclosure.
    Confidentiality = 0,
    /// Integrity — protection from unauthorized modification.
    Integrity = 1,
    /// Availability — protection from disruption of access.
    Availability = 2,
}

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
    /// Primary cybersecurity goal this asset supports.
    pub cia: CiaClass,
}

impl Asset {
    /// Constructs a new [`Asset`].
    ///
    /// `label_len` must be `<= 32`; in debug builds this is asserted, in
    /// release builds the value is clamped before storage so the `label`
    /// slice never reports more bytes than the buffer can hold.
    #[must_use]
    pub fn new(
        id: u16,
        label: [u8; 32],
        label_len: u8,
        cybersecurity_relevant: bool,
        cia: CiaClass,
    ) -> Self {
        debug_assert!(
            label_len as usize <= 32,
            "Asset::label_len must fit inside the 32-byte buffer"
        );
        let clamped_len = if label_len as usize > 32 {
            32
        } else {
            label_len
        };
        Self {
            id,
            label,
            label_len: clamped_len,
            cybersecurity_relevant,
            cia,
        }
    }
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

/// A per-threat mitigation flag keyed by `threat_id`.
///
/// Stored separately so callers can supply mitigations in any order without
/// having to keep them positionally aligned with the threats array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mitigation {
    /// Identifier of the threat this mitigation flag applies to.
    pub threat_id: u16,
    /// `true` if a security control mitigates the referenced threat.
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
    /// Damage scenarios keyed by `threat_id` (lookup, not positional).
    pub damages: [DamageScenario; MAX_THREATS],
    /// Number of valid damage scenarios.
    pub damage_count: usize,
    /// Per-threat mitigation flags keyed by `threat_id` (lookup, not positional).
    pub mitigations: [Mitigation; MAX_THREATS],
    /// Number of valid mitigation entries.
    pub mitigation_count: usize,
    /// Default treatment for unmitigated threats.
    pub default_treatment: TreatmentDecision,
}

/// Output of a TARA assessment containing all per-threat results and summary
/// statistics.
///
/// Fields are `pub(crate)` and exposed via accessor methods so callers cannot
/// accidentally mutate a report after it has been wrapped in
/// [`vs_evidence_envelope::Evidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaraReport {
    /// Per-threat assessment results.
    pub(crate) assessments: [ThreatAssessment; MAX_THREATS],
    /// Number of valid assessments.
    pub(crate) count: usize,
    /// Number of threats with `Critical` risk level.
    pub(crate) critical_count: usize,
    /// Number of threats with `High` risk level.
    pub(crate) high_count: usize,
    /// Number of threats with `Medium` risk level.
    pub(crate) medium_count: usize,
    /// Number of threats with `Low` risk level.
    pub(crate) low_count: usize,
    /// Number of threats that have an active mitigation.
    pub(crate) mitigated_count: usize,
    /// Number of unmitigated threats at `High` or `Critical` risk.
    pub(crate) residual_risk_count: usize,
}

impl TaraReport {
    /// Returns the per-threat assessment slice (length = `count`).
    #[must_use]
    pub fn assessments(&self) -> &[ThreatAssessment] {
        &self.assessments[..self.count]
    }

    /// Returns the number of assessed threats.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the number of `Critical`-risk threats.
    #[must_use]
    pub const fn critical_count(&self) -> usize {
        self.critical_count
    }

    /// Returns the number of `High`-risk threats.
    #[must_use]
    pub const fn high_count(&self) -> usize {
        self.high_count
    }

    /// Returns the number of `Medium`-risk threats.
    #[must_use]
    pub const fn medium_count(&self) -> usize {
        self.medium_count
    }

    /// Returns the number of `Low`-risk threats.
    #[must_use]
    pub const fn low_count(&self) -> usize {
        self.low_count
    }

    /// Returns the number of mitigated threats.
    #[must_use]
    pub const fn mitigated_count(&self) -> usize {
        self.mitigated_count
    }

    /// Returns the count of unmitigated `High`/`Critical` threats.
    #[must_use]
    pub const fn residual_risk_count(&self) -> usize {
        self.residual_risk_count
    }

    /// Returns `true` if any unmitigated threats remain at `High` or `Critical`
    /// risk.
    #[must_use]
    pub const fn has_residual_risk(&self) -> bool {
        self.residual_risk_count > 0
    }

    /// Returns the highest risk level found across all assessed threats.
    ///
    /// Returns `RiskLevel::Low` if the report contains no assessments. The
    /// scan short-circuits as soon as `RiskLevel::Critical` is observed —
    /// there is no higher level to upgrade to.
    #[must_use]
    pub fn highest_risk(&self) -> RiskLevel {
        let mut highest = RiskLevel::Low;
        let mut i = 0;
        while i < self.count {
            if self.assessments[i].risk_level > highest {
                highest = self.assessments[i].risk_level;
                if highest == RiskLevel::Critical {
                    return highest;
                }
            }
            i += 1;
        }
        highest
    }
}

/// Returns `true` if every threat in the slice carries a unique `id`.
///
/// Uses an O(n^2) scan because the bounded array (`MAX_THREATS == 32`) makes
/// this cheaper than any heap-backed alternative in a `no_std`, no-heap
/// environment.
fn validate_no_duplicate_threat_ids(
    threats: &[ThreatScenario; MAX_THREATS],
    threat_count: usize,
) -> bool {
    let mut i = 0;
    while i < threat_count {
        let mut j = i + 1;
        while j < threat_count {
            if threats[i].id == threats[j].id {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
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

/// Finds the mitigation flag for a given `threat_id`.
///
/// Returns `None` if no mitigation entry references the threat; callers
/// should treat a missing entry as "not mitigated".
fn find_mitigation(
    mitigations: &[Mitigation; MAX_THREATS],
    mitigation_count: usize,
    threat_id: u16,
) -> Option<bool> {
    let mut i = 0;
    while i < mitigation_count {
        if mitigations[i].threat_id == threat_id {
            return Some(mitigations[i].mitigated);
        }
        i += 1;
    }
    None
}

/// Creates a zeroed `ThreatAssessment` for use as array padding.
const fn zeroed_assessment() -> ThreatAssessment {
    ThreatAssessment {
        threat: zeroed_threat(),
        damage: zeroed_damage(),
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
        cia: CiaClass::Confidentiality,
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
        elapsed_time: ElapsedTime::LessThanDay,
        expertise: Expertise::Layman,
        knowledge: Knowledge::Public,
        window: Window::Unlimited,
        equipment: Equipment::Standard,
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

/// Creates a zeroed `Mitigation` for use as array padding.
const fn zeroed_mitigation() -> Mitigation {
    Mitigation {
        threat_id: 0,
        mitigated: false,
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
        mitigations: [zeroed_mitigation(); MAX_THREATS],
        mitigation_count: 0,
        default_treatment: TreatmentDecision::Accept,
    }
}

/// Generates a TARA report from the provided input.
///
/// The returned report is bare; use [`generate_tara_evidence`] to obtain an
/// envelope with provenance metadata attached.
///
/// # Errors
///
/// Returns `VsError::InvalidInput` if:
/// - `threat_count` exceeds `MAX_THREATS`
/// - `damage_count` exceeds `MAX_THREATS`
/// - `asset_count` exceeds `MAX_ASSETS`
/// - `mitigation_count` exceeds `MAX_THREATS`
/// - Any threat has `asset_id == 0` (placeholder value)
/// - Two threats share the same `id`
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
    if input.mitigation_count > MAX_THREATS {
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

    // Reject duplicate threat ids — `find_damage` / `find_mitigation` return
    // the first match silently and would otherwise mask catalog mistakes.
    if !validate_no_duplicate_threat_ids(&input.threats, input.threat_count) {
        return Err(VsError::InvalidInput);
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
        let mitigated =
            find_mitigation(&input.mitigations, input.mitigation_count, threat.id).unwrap_or(false);

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
            RiskLevel::Critical => {
                report.critical_count = report.critical_count.saturating_add(1);
            }
            RiskLevel::High => {
                report.high_count = report.high_count.saturating_add(1);
            }
            RiskLevel::Medium => {
                report.medium_count = report.medium_count.saturating_add(1);
            }
            RiskLevel::Low => {
                report.low_count = report.low_count.saturating_add(1);
            }
        }

        if mitigated {
            report.mitigated_count = report.mitigated_count.saturating_add(1);
        }

        if !mitigated && (risk_level >= RiskLevel::High) {
            report.residual_risk_count = report.residual_risk_count.saturating_add(1);
        }

        i += 1;
    }

    report.count = input.threat_count;
    Ok(report)
}

/// Generates a TARA report and wraps it in an [`Evidence`] envelope.
///
/// `metadata` carries provenance (assessor, tool version, input hash, schema
/// version, timestamp) that downstream verifiers can use to audit the report.
///
/// # Errors
///
/// Forwards any error from [`generate_tara`].
pub fn generate_tara_evidence(
    input: &TaraInput,
    metadata: EvidenceMetadata,
) -> Result<Evidence<TaraReport>, VsError> {
    let report = generate_tara(input)?;
    Ok(Evidence::with_metadata(
        report,
        Standard::Iso21434,
        metadata,
    ))
}

/// Convenience function that generates a TARA report using the built-in
/// [`AUTOMOTIVE_THREAT_CATALOG`] as the threat source.
///
/// Because every catalog entry uses the placeholder `asset_id == 0`, the
/// caller must supply `asset_ids` — a parallel slice with the same length
/// as the slice of catalog entries it wants to include — describing the
/// real asset each threat should be remapped to. The Nth element of
/// `asset_ids` is applied to the Nth catalog entry; an `asset_id` of `0` in
/// the remap skips that catalog entry. This avoids the prior behaviour
/// where the placeholder `0` caused every catalog entry to be rejected.
///
/// `mitigations` are keyed by `threat_id` (not positional) and `damages`
/// supplies a damage scenario per included threat (looked up by `threat_id`).
///
/// # Errors
///
/// Returns `VsError::InvalidInput` if `damage_count` exceeds `MAX_THREATS`,
/// `mitigations.len()` exceeds `MAX_THREATS`, `asset_ids` is shorter than the
/// catalog, `damage_count` exceeds `damages.len()` (which would silently
/// truncate the input), or a matching threat lacks a damage scenario.
pub fn generate_tara_from_catalog(
    asset_ids: &[u16],
    damages: &[DamageScenario],
    mitigations: &[Mitigation],
    damage_count: usize,
) -> Result<TaraReport, VsError> {
    if damage_count > MAX_THREATS {
        return Err(VsError::InvalidInput);
    }
    if mitigations.len() > MAX_THREATS {
        return Err(VsError::InvalidInput);
    }
    if asset_ids.len() < AUTOMOTIVE_THREAT_CATALOG.len() {
        return Err(VsError::InvalidInput);
    }
    // Reject silently-truncating inputs: if the caller claims more damages
    // than the supplied slice can provide we must surface the mismatch.
    if damage_count > damages.len() {
        return Err(VsError::InvalidInput);
    }

    let mut input = empty_input();

    let mut threat_idx = 0;
    for (cat_idx, catalog_threat) in AUTOMOTIVE_THREAT_CATALOG.iter().enumerate() {
        if threat_idx >= MAX_THREATS {
            break;
        }
        let remapped_id = asset_ids[cat_idx];
        if remapped_id == 0 {
            // Caller chose to skip this catalog entry.
            continue;
        }
        let mut t = *catalog_threat;
        t.asset_id = remapped_id;
        input.threats[threat_idx] = t;
        threat_idx += 1;
    }
    input.threat_count = threat_idx;

    // The three bounds above already guarantee
    // `damage_count <= damages.len()` and `damage_count <= MAX_THREATS`, so
    // no clamping is required — copying exactly `damage_count` is correct.
    let mut d = 0;
    while d < damage_count {
        input.damages[d] = damages[d];
        d += 1;
    }
    input.damage_count = damage_count;

    let mit_copy = mitigations.len().min(MAX_THREATS);
    let mut m = 0;
    while m < mit_copy {
        input.mitigations[m] = mitigations[m];
        m += 1;
    }
    input.mitigation_count = mit_copy;

    input.default_treatment = TreatmentDecision::Accept;

    generate_tara(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{DamageScenario, ImpactLevel, RiskLevel, TreatmentDecision};
    use crate::threats::{
        AttackFeasibility, AttackVector, ElapsedTime, Equipment, Expertise, Knowledge,
        StrideCategory, ThreatScenario, Window, AUTOMOTIVE_THREAT_CATALOG,
    };

    fn make_threat(id: u16, feasibility: AttackFeasibility) -> ThreatScenario {
        ThreatScenario {
            id,
            category: StrideCategory::Tampering,
            asset_id: 1,
            vector: AttackVector::Network,
            feasibility,
            elapsed_time: ElapsedTime::LessThanWeek,
            expertise: Expertise::Proficient,
            knowledge: Knowledge::Restricted,
            window: Window::Easy,
            equipment: Equipment::Standard,
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

    fn make_mitigation(threat_id: u16, mitigated: bool) -> Mitigation {
        Mitigation {
            threat_id,
            mitigated,
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
        input.mitigations[0] = make_mitigation(1, mitigated);
        input.mitigation_count = 1;
        input.default_treatment = TreatmentDecision::Accept;
        input
    }

    fn dummy_metadata() -> EvidenceMetadata {
        EvidenceMetadata {
            generated_at_ns: 1,
            assessor_id: [0u8; 16],
            tool_version: *b"vs-iso21434/0.7\0",
            input_hash: [0u8; 32],
            schema_version: 1,
        }
    }

    #[test]
    fn empty_input_produces_empty_report() {
        let input = empty_input();
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count(), 0);
        assert_eq!(report.critical_count(), 0);
        assert_eq!(report.high_count(), 0);
        assert_eq!(report.medium_count(), 0);
        assert_eq!(report.low_count(), 0);
        assert!(!report.has_residual_risk());
        assert!(report.assessments().is_empty());
    }

    #[test]
    fn single_threat_negligible_impact_is_low() {
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Negligible, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.count(), 1);
        assert_eq!(report.assessments()[0].risk_level, RiskLevel::Low);
        assert_eq!(report.low_count(), 1);
    }

    #[test]
    fn single_threat_severe_veryhigh_is_critical() {
        let input = single_threat_input(AttackFeasibility::VeryHigh, ImpactLevel::Severe, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.assessments()[0].risk_level, RiskLevel::Critical);
        assert_eq!(report.critical_count(), 1);
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
        let expected: [[RiskLevel; 4]; 4] = [
            [
                RiskLevel::Low,
                RiskLevel::Low,
                RiskLevel::Low,
                RiskLevel::Low,
            ],
            [
                RiskLevel::Low,
                RiskLevel::Medium,
                RiskLevel::Medium,
                RiskLevel::High,
            ],
            [
                RiskLevel::Medium,
                RiskLevel::Medium,
                RiskLevel::High,
                RiskLevel::Critical,
            ],
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
        assert_eq!(report.assessments()[0].treatment, TreatmentDecision::Reduce);
        assert!(report.assessments()[0].mitigated);
        assert_eq!(report.mitigated_count(), 1);
    }

    #[test]
    fn unmitigated_critical_increases_residual_risk() {
        let input = single_threat_input(AttackFeasibility::VeryHigh, ImpactLevel::Severe, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.residual_risk_count(), 1);
        assert!(report.has_residual_risk());
        assert_eq!(report.assessments()[0].treatment, TreatmentDecision::Avoid);
    }

    #[test]
    fn full_automotive_catalog_assessment() {
        let mut input = empty_input();
        let catalog = &AUTOMOTIVE_THREAT_CATALOG;

        for (i, threat) in catalog.iter().enumerate() {
            let mut t = *threat;
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
        assert_eq!(report.count(), 20);
        let total = report.critical_count()
            + report.high_count()
            + report.medium_count()
            + report.low_count();
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
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, false);
        let report = generate_tara(&input).unwrap();
        assert_eq!(report.assessments()[0].risk_level, RiskLevel::High);
        assert!(report.has_residual_risk());
    }

    #[test]
    fn highest_risk_returns_correct_maximum() {
        let mut input = empty_input();
        input.threats[0] = make_threat(1, AttackFeasibility::Low);
        input.damages[0] = make_damage(1, ImpactLevel::Negligible);
        input.threats[1] = make_threat(2, AttackFeasibility::High);
        input.damages[1] = make_damage(2, ImpactLevel::Major);
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
        let d_fin = DamageScenario {
            threat_id: 1,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Severe,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Major,
        };
        assert_eq!(d_fin.max_impact(), ImpactLevel::Severe);

        let d_ops = DamageScenario {
            threat_id: 2,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Moderate,
            operational_impact: ImpactLevel::Severe,
            privacy_impact: ImpactLevel::Major,
        };
        assert_eq!(d_ops.max_impact(), ImpactLevel::Severe);

        let d_priv = DamageScenario {
            threat_id: 3,
            safety_impact: ImpactLevel::Negligible,
            financial_impact: ImpactLevel::Moderate,
            operational_impact: ImpactLevel::Moderate,
            privacy_impact: ImpactLevel::Severe,
        };
        assert_eq!(d_priv.max_impact(), ImpactLevel::Severe);

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
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, true);
        let report = generate_tara(&input).unwrap();

        assert_eq!(report.assessments()[0].risk_level, RiskLevel::High);
        assert!(report.assessments()[0].mitigated);
        assert_eq!(report.residual_risk_count(), 0);
        assert!(!report.has_residual_risk());
    }

    #[test]
    fn test_multiple_threats_mixed_risk() {
        let mut input = empty_input();

        input.threats[0] = make_threat(1, AttackFeasibility::Low);
        input.damages[0] = make_damage(1, ImpactLevel::Negligible);

        input.threats[1] = make_threat(2, AttackFeasibility::Medium);
        input.damages[1] = make_damage(2, ImpactLevel::Moderate);

        input.threats[2] = make_threat(3, AttackFeasibility::High);
        input.damages[2] = make_damage(3, ImpactLevel::Major);

        input.threats[3] = make_threat(4, AttackFeasibility::VeryHigh);
        input.damages[3] = make_damage(4, ImpactLevel::Severe);

        input.threat_count = 4;
        input.damage_count = 4;
        input.default_treatment = TreatmentDecision::Accept;

        let report = generate_tara(&input).unwrap();

        assert_eq!(report.count(), 4);
        assert_eq!(report.low_count(), 1);
        assert_eq!(report.medium_count(), 1);
        assert_eq!(report.high_count(), 1);
        assert_eq!(report.critical_count(), 1);
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
            asset_id: 0,
            vector: AttackVector::Network,
            feasibility: AttackFeasibility::High,
            elapsed_time: ElapsedTime::LessThanWeek,
            expertise: Expertise::Proficient,
            knowledge: Knowledge::Restricted,
            window: Window::Easy,
            equipment: Equipment::Standard,
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

    // ---------------------------------------------------------------
    // v0.9 regression tests
    // ---------------------------------------------------------------

    /// The catalog remap must produce a report when callers supply non-zero
    /// asset ids — the previous behaviour rejected every entry because the
    /// catalog uses `asset_id == 0` as a placeholder.
    #[test]
    fn catalog_remap_produces_assessments() {
        let asset_ids = [7u16; AUTOMOTIVE_THREAT_CATALOG.len()];
        // Provide one damage per catalog threat (matched by threat_id).
        let mut damages_buf = [zeroed_damage(); MAX_THREATS];
        for (i, t) in AUTOMOTIVE_THREAT_CATALOG.iter().enumerate() {
            damages_buf[i] = make_damage(t.id, ImpactLevel::Moderate);
        }
        let damages = &damages_buf[..AUTOMOTIVE_THREAT_CATALOG.len()];
        let mitigations: [Mitigation; 0] = [];

        let report = generate_tara_from_catalog(
            &asset_ids,
            damages,
            &mitigations,
            AUTOMOTIVE_THREAT_CATALOG.len(),
        )
        .expect("catalog remap must succeed");

        assert_eq!(report.count(), AUTOMOTIVE_THREAT_CATALOG.len());
        // Every assessed threat must carry the remapped asset id.
        for a in report.assessments() {
            assert_eq!(a.threat.asset_id, 7);
        }
    }

    /// A zero in the remap must skip the corresponding catalog entry, not
    /// reject the whole assessment.
    #[test]
    fn catalog_remap_zero_skips_entry() {
        let mut asset_ids = [1u16; AUTOMOTIVE_THREAT_CATALOG.len()];
        asset_ids[3] = 0; // skip catalog[3]
        let mut damages_buf = [zeroed_damage(); MAX_THREATS];
        let mut included = 0;
        for (i, t) in AUTOMOTIVE_THREAT_CATALOG.iter().enumerate() {
            if asset_ids[i] != 0 {
                damages_buf[included] = make_damage(t.id, ImpactLevel::Moderate);
                included += 1;
            }
        }
        let damages = &damages_buf[..included];
        let mitigations: [Mitigation; 0] = [];

        let report =
            generate_tara_from_catalog(&asset_ids, damages, &mitigations, included).unwrap();
        assert_eq!(report.count(), AUTOMOTIVE_THREAT_CATALOG.len() - 1);
    }

    /// Mitigations must be looked up by `threat_id`, not by array position.
    /// This test mitigates threat id `2` but the matching threat is in
    /// position 0 of the input — under the old positional scheme, the
    /// mitigation would have applied to whatever threat sat at index 1.
    #[test]
    fn mitigation_keyed_by_threat_id_not_position() {
        let mut input = empty_input();
        // Threat at position 0 has id=2; position 1 has id=1.
        input.threats[0] = make_threat(2, AttackFeasibility::High);
        input.threats[1] = make_threat(1, AttackFeasibility::High);
        input.threat_count = 2;
        input.damages[0] = make_damage(2, ImpactLevel::Major);
        input.damages[1] = make_damage(1, ImpactLevel::Major);
        input.damage_count = 2;
        // Mitigation entry references threat_id == 2 only.
        input.mitigations[0] = make_mitigation(2, true);
        input.mitigation_count = 1;

        let report = generate_tara(&input).unwrap();
        let a = report.assessments();
        // Position 0 is threat_id=2 — should be mitigated.
        assert_eq!(a[0].threat.id, 2);
        assert!(a[0].mitigated);
        assert_eq!(a[0].treatment, TreatmentDecision::Reduce);
        // Position 1 is threat_id=1 — must NOT pick up the mitigation.
        assert_eq!(a[1].threat.id, 1);
        assert!(!a[1].mitigated);
    }

    /// Confirm that mitigation lookup works regardless of input order.
    #[test]
    fn find_mitigation_lookup_independent_of_order() {
        let mut input = empty_input();
        input.threats[0] = make_threat(10, AttackFeasibility::High);
        input.threat_count = 1;
        input.damages[0] = make_damage(10, ImpactLevel::Major);
        input.damage_count = 1;
        // Put unrelated mitigations before the relevant one to ensure search,
        // not positional indexing, is what matches.
        input.mitigations[0] = make_mitigation(99, false);
        input.mitigations[1] = make_mitigation(42, false);
        input.mitigations[2] = make_mitigation(10, true);
        input.mitigation_count = 3;

        let report = generate_tara(&input).unwrap();
        assert!(report.assessments()[0].mitigated);
    }

    /// Every catalog entry must carry concrete CVSS-style breakdown values.
    /// We sample a representative entry to confirm the fields are populated
    /// with meaningful (non-default) data.
    #[test]
    fn cvss_fields_present_in_catalog_entries() {
        // Threat id 8 (Telematics backdoor) is the high-effort scenario and
        // should pin the upper bounds of the CVSS axes.
        let backdoor = AUTOMOTIVE_THREAT_CATALOG
            .iter()
            .find(|t| t.id == 8)
            .expect("catalog must contain id 8");
        assert!(backdoor.elapsed_time >= ElapsedTime::LessThanSixMonths);
        assert!(backdoor.expertise >= Expertise::Expert);
        assert!(backdoor.knowledge >= Knowledge::Sensitive);
        assert!(backdoor.equipment >= Equipment::Bespoke);

        // Threat id 6 (DoS flood) should be the most feasible CVSS profile.
        let dos = AUTOMOTIVE_THREAT_CATALOG
            .iter()
            .find(|t| t.id == 6)
            .expect("catalog must contain id 6");
        assert_eq!(dos.elapsed_time, ElapsedTime::LessThanDay);
        assert_eq!(dos.expertise, Expertise::Layman);
        assert_eq!(dos.knowledge, Knowledge::Public);
        assert_eq!(dos.equipment, Equipment::Standard);
    }

    /// The `CiaClass` enum is `#[non_exhaustive]` and assets carry a goal.
    #[test]
    fn asset_carries_cia_class() {
        let mut input = empty_input();
        input.assets[0] = Asset {
            id: 1,
            label: [0u8; 32],
            label_len: 0,
            cybersecurity_relevant: true,
            cia: CiaClass::Integrity,
        };
        input.asset_count = 1;
        assert_eq!(input.assets[0].cia, CiaClass::Integrity);
    }

    /// Reports wrapped in `Evidence<T>` round-trip their metadata.
    #[test]
    fn generate_tara_evidence_wraps_report() {
        let input = single_threat_input(AttackFeasibility::High, ImpactLevel::Major, false);
        let evidence = generate_tara_evidence(&input, dummy_metadata()).unwrap();
        assert_eq!(evidence.payload().count(), 1);
        // `with_metadata` packs the `EvidenceMetadata::schema_version` u32 into
        // a `SchemaVersion(major, minor, patch)` triple: schema_version = 1
        // unpacks to `(0, 0, 1)`.
        let sv = evidence.schema_version();
        assert_eq!(sv.major(), 0);
        assert_eq!(sv.minor(), 0);
        assert_eq!(sv.patch(), 1);
        assert_eq!(evidence.standard(), Standard::Iso21434);
    }

    /// Catalog remap with a too-short asset_ids slice must be rejected.
    #[test]
    fn catalog_remap_short_slice_rejected() {
        let asset_ids = [1u16; 5]; // shorter than catalog (20)
        let damages: [DamageScenario; 0] = [];
        let mitigations: [Mitigation; 0] = [];
        let res = generate_tara_from_catalog(&asset_ids, &damages, &mitigations, 0);
        assert_eq!(res, Err(VsError::InvalidInput));
    }
}
