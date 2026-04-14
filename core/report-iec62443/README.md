# vs-report-iec62443

IEC 62443-4-2 Security Level compliance assessor for the Craton Shield
automotive cybersecurity platform.

This crate evaluates a system's capabilities against the Component
Requirements (CRs) defined in IEC 62443-4-2, producing a gap analysis for
a chosen target Security Level (SL-1 through SL-4).

## Features

- `no_std` compatible -- zero heap allocations, stack-only operation
- Covers all seven Foundational Requirements (FR 1 -- FR 7)
- Approximately 30 Component Requirements assessed per run
- Returns per-CR compliance status and an overall achieved Security Level

## Quick start

```rust
use vs_report_iec62443::{assess, SecurityLevel, SystemCapabilities};

// Describe the system under test
let mut caps = SystemCapabilities::default();
caps.has_user_authentication = true;
caps.has_authorization_enforcement = true;
caps.has_cryptography = true;
caps.crypto_key_length_bits = 256;
caps.has_audit_logging = true;
// ... populate remaining fields ...

// Run the assessment against SL-2
let report = assess(&caps, SecurityLevel::Sl2);

if report.is_compliant() {
    // Target SL achieved
} else {
    // Inspect gaps
    for i in 0..report.gap_count() {
        if let Some(gap) = report.gap_at(i) {
            // gap.requirement, gap.status, gap.achieved_sl ...
        }
    }
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
