# vs-report-iso21434

ISO/SAE 21434 Threat Analysis and Risk Assessment (TARA) report generator for the Craton Shield automotive cybersecurity platform.

## Overview

This crate implements a `no_std`, zero-allocation TARA engine that follows the ISO/SAE 21434 standard for automotive cybersecurity engineering. It provides:

- **STRIDE-based threat modeling** with six standard categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
- **A built-in automotive threat catalog** containing 20 common vehicle cyber threats covering CAN bus attacks, OTA manipulation, diagnostic exploits, and more.
- **A 4x4 risk matrix** combining attack feasibility and impact severity across four ISO 21434 damage categories (Safety, Financial, Operational, Privacy).
- **Treatment decisions** (Avoid, Reduce, Transfer, Accept) with automatic escalation for critical unmitigated risks.

## Quick Start

```rust
use vs_report_iso21434::{generate_tara, empty_input, MAX_THREATS};
use vs_report_iso21434::threats::{AttackFeasibility, AttackVector, StrideCategory};
use vs_report_iso21434::risk::{DamageScenario, ImpactLevel, TreatmentDecision};

let mut input = empty_input();

// Define a threat
input.threats[0].id = 1;
input.threats[0].category = StrideCategory::Tampering;
input.threats[0].asset_id = 1;
input.threats[0].vector = AttackVector::AdjacentNetwork;
input.threats[0].feasibility = AttackFeasibility::High;
input.threats[0].description_tag = "CAN bus injection";
input.threat_count = 1;

// Define its damage scenario
input.damages[0] = DamageScenario {
    threat_id: 1,
    safety_impact: ImpactLevel::Major,
    financial_impact: ImpactLevel::Moderate,
    operational_impact: ImpactLevel::Moderate,
    privacy_impact: ImpactLevel::Negligible,
};
input.damage_count = 1;
input.default_treatment = TreatmentDecision::Accept;

let report = generate_tara(&input).unwrap();
assert!(report.count == 1);
```

## Built-in Threat Catalog

The `AUTOMOTIVE_THREAT_CATALOG` constant provides 20 pre-defined threat scenarios covering common automotive attack surfaces including CAN bus, OTA updates, diagnostic interfaces, Ethernet/SOME-IP, telematics, and Bluetooth. Use `generate_tara_from_catalog` for a streamlined assessment workflow.

## Design Constraints

- `#![no_std]` and `#![forbid(unsafe_code)]`
- All data structures are fixed-size and stack-allocated
- Zero heap allocations

## License

Apache-2.0. See [LICENSE](../../LICENSE).
