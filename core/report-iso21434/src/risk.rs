// SPDX-License-Identifier: Apache-2.0
//
//! Risk matrix, impact/likelihood assessment, and treatment options
//! for ISO/SAE 21434 TARA.

use crate::threats::AttackFeasibility;

/// Impact severity level per ISO/SAE 21434 damage scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImpactLevel {
    /// Negligible impact — no meaningful harm.
    Negligible,
    /// Moderate impact — limited, recoverable harm.
    Moderate,
    /// Major impact — significant harm requiring active response.
    Major,
    /// Severe impact — catastrophic harm (safety-critical or systemic).
    Severe,
}

/// ISO/SAE 21434 damage categories used to assess impact across different
/// dimensions of harm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactCategory {
    /// Vehicle / occupant safety harm.
    Safety,
    /// Repair, liability, recall, and reputational cost.
    Financial,
    /// Loss of vehicle availability or functionality.
    Operational,
    /// Exposure of personal or sensitive data.
    Privacy,
}

/// A damage scenario linking a threat to its assessed impact across all
/// four ISO/SAE 21434 damage categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DamageScenario {
    /// Identifier of the threat this damage scenario relates to.
    pub threat_id: u16,
    /// Impact on vehicle or occupant safety.
    pub safety_impact: ImpactLevel,
    /// Financial impact (repair costs, liability, recalls).
    pub financial_impact: ImpactLevel,
    /// Operational impact (vehicle availability, functionality).
    pub operational_impact: ImpactLevel,
    /// Privacy impact (personal data exposure).
    pub privacy_impact: ImpactLevel,
}

impl DamageScenario {
    /// Returns the worst (highest) impact across all four damage categories.
    #[must_use]
    pub fn max_impact(&self) -> ImpactLevel {
        [
            self.safety_impact,
            self.financial_impact,
            self.operational_impact,
            self.privacy_impact,
        ]
        .into_iter()
        .max()
        .unwrap_or(ImpactLevel::Negligible)
    }
}

/// Final risk level resulting from the combination of attack feasibility
/// and impact severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Low risk — treated under business-as-usual processes.
    Low,
    /// Medium risk — flagged for review.
    Medium,
    /// High risk — requires a defined mitigation plan.
    High,
    /// Critical risk — must be mitigated or avoided before release.
    Critical,
}

/// Risk treatment decision per ISO/SAE 21434.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreatmentDecision {
    /// Avoid the risk by removing the exposed functionality.
    Avoid,
    /// Reduce the risk through a security control.
    Reduce,
    /// Transfer the risk (e.g. insurance, supplier contract).
    Transfer,
    /// Accept the risk under management sign-off.
    Accept,
}

/// Computes the risk level from the standard 4x4 risk matrix.
///
/// The matrix maps (`AttackFeasibility`, `ImpactLevel`) pairs to a `RiskLevel`:
///
/// | Impact \ Feasibility | Low    | Medium | High     | `VeryHigh` |
/// |----------------------|--------|--------|----------|------------|
/// | Negligible           | Low    | Low    | Low      | Low        |
/// | Moderate             | Low    | Medium | Medium   | High       |
/// | Major                | Medium | Medium | High     | Critical   |
/// | Severe               | Medium | High   | Critical | Critical   |
#[must_use]
pub fn compute_risk(feasibility: AttackFeasibility, impact: ImpactLevel) -> RiskLevel {
    match (impact, feasibility) {
        (ImpactLevel::Negligible, _) | (ImpactLevel::Moderate, AttackFeasibility::Low) => {
            RiskLevel::Low
        }

        (ImpactLevel::Moderate, AttackFeasibility::Medium | AttackFeasibility::High)
        | (ImpactLevel::Major, AttackFeasibility::Low | AttackFeasibility::Medium)
        | (ImpactLevel::Severe, AttackFeasibility::Low) => RiskLevel::Medium,

        (ImpactLevel::Moderate, AttackFeasibility::VeryHigh)
        | (ImpactLevel::Major, AttackFeasibility::High)
        | (ImpactLevel::Severe, AttackFeasibility::Medium) => RiskLevel::High,

        (ImpactLevel::Major, AttackFeasibility::VeryHigh)
        | (ImpactLevel::Severe, AttackFeasibility::High | AttackFeasibility::VeryHigh) => {
            RiskLevel::Critical
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threats::AttackFeasibility;

    /// Exhaustiveness test: every combination of `AttackFeasibility` x
    /// `ImpactLevel` must return a valid `RiskLevel` without panicking.
    /// This guards against gaps if new variants are added in the future.
    #[test]
    fn risk_matrix_exhaustive_all_combinations_valid() {
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
        let valid_levels = [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];

        for feasibility in &feasibilities {
            for impact in &impacts {
                let result = compute_risk(*feasibility, *impact);
                assert!(
                    valid_levels.contains(&result),
                    "compute_risk({feasibility:?}, {impact:?}) returned unexpected {result:?}"
                );
            }
        }
    }
}
