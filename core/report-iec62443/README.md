# vs-report-iec62443

> **Disclaimer:** Unofficial IEC 62443 self-assessment helper; not an
> official IEC/ISA product. "IEC 62443" and "ISA" are trademarks of their
> respective owners; their use here describes the standard being assessed
> and does not imply endorsement, certification, or affiliation.

IEC 62443-4-2 Security Level compliance assessor for the Craton Shield
automotive cybersecurity platform.

This crate evaluates a system's capabilities against the Component
Requirements (CRs) defined in IEC 62443-4-2, producing a gap analysis for
a chosen target Security Level (SL-1 through SL-4).

## Features

- `no_std` compatible -- zero heap allocations, stack-only operation
- Covers all seven Foundational Requirements (FR 1 -- FR 7)
- 40 Component Requirements assessed per run
- Returns per-CR compliance status and an overall achieved Security Level

## Scope

This is a 0.7.0-scope assessor; full IEC 62443-4-2 coverage is targeted for
the 1.0.0 release. The following Component Requirements are **not** currently
covered and will be added before 1.0.0:

- CR 1.6 (wireless access management)
- CR 2.2, CR 2.3, CR 2.4 (wireless use control, use control for portable and
  mobile devices, mobile code)
- CR 3.1, CR 3.2 (communication integrity, malicious code protection)
- CR 3.6 (deterministic output)
- CR 7.5 (emergency power)
- CR 7.8 (control system component inventory)

All other CRs from FR 1 through FR 7 (40 in total) are covered.

## Quick start

```rust,ignore
use vs_report_iec62443::{assess, SecurityLevel, SystemCapabilities};

// Describe the system under test
let mut caps = SystemCapabilities::default();
caps.has_user_authentication = true;
caps.max_failed_login_attempts = 3;
caps.has_authorization_enforcement = true;
caps.has_cryptography = true;
caps.crypto_key_length_bits = 256;
caps.has_audit_logging = true;
// ... populate remaining fields ...

// Run the assessment against SL-2
let evidence = assess(&caps, SecurityLevel::Sl2).unwrap();
let report = evidence.payload();

if report.is_compliant() {
    // Target SL achieved
} else {
    // Inspect gaps
    for gap in report.iter_gaps() {
        // gap.requirement, gap.status, gap.achieved_sl ...
        let _ = gap;
    }
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
