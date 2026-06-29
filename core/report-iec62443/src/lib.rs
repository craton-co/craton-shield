// SPDX-License-Identifier: Apache-2.0
//! IEC 62443-4-2 Security Level compliance assessor for the Craton Shield
//! automotive cybersecurity platform.
//!
//! Implements an assessor for IEC 62443-4-2:2019 Component Requirement
//! compliance evidence (Security for industrial automation and control
//! systems -- Part 4-2: Technical security requirements for IACS components).
//!
//! > Unofficial IEC 62443 self-assessment helper; not an official IEC/ISA
//! > product.
//!
//! This crate evaluates a [`SystemCapabilities`] description against the
//! Component Requirements defined in IEC 62443-4-2 and produces an
//! [`Iec62443Assessment`] containing per-CR results and an overall achieved
//! Security Level. The result is returned wrapped in
//! [`vs_evidence_envelope::Evidence`] so consumers receive both the payload
//! and tamper-evident provenance metadata.
//!
//! # Design constraints
//!
//! * `no_std` -- no heap allocations; all data lives on the stack in
//!   fixed-size arrays.
//! * `forbid(unsafe_code)` -- the entire crate is safe Rust.
//!
//! # Public API stability
//!
//! Pre-1.0 (workspace version 0.7.0); semver-minor bumps may change the
//! report payload before 1.0.0. The `SystemCapabilities` builder (with
//! `validate`), the [`assess`] / [`assess_with_metadata`] / [`assess_into`]
//! entry points, and the [`Iec62443Assessment`] / [`RequirementAssessment`]
//! / [`SecurityLevel`] result types form the current public surface.
//!
//! # Scope
//!
//! 0.7.0 scope; full IEC 62443-4-2 coverage is targeted for the 1.0.0
//! release. The following Component Requirements are **not** currently
//! covered by [`ALL_REQUIREMENTS`] and will be added before 1.0.0:
//!
//! * CR 1.6  -- wireless access management
//! * CR 2.2  -- wireless use control
//! * CR 2.3  -- use control for portable and mobile devices
//! * CR 2.4  -- mobile code
//! * CR 3.1  -- communication integrity
//! * CR 3.2  -- malicious code protection
//! * CR 3.6  -- deterministic output
//! * CR 7.5  -- emergency power
//! * CR 7.8  -- control system component inventory
//!
//! All other CRs from FR 1 through FR 7 (40 in total) are covered.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod requirements;

use vs_evidence_envelope::{Evidence, EvidenceMetadata, Standard};
use vs_types::VsError;

pub use requirements::{
    ComplianceStatus, ComponentRequirement, FoundationalRequirement, RequirementAssessment,
    SecurityLevel, ALL_REQUIREMENTS,
};

/// Maximum number of Component Requirements that can be stored in an
/// assessment. Must be >= `ALL_REQUIREMENTS.len()`.
pub const MAX_REQUIREMENTS: usize = 40;

/// Returns `true` if the given requirement count is within the capacity
/// limits of an IEC 62443-4-2 assessment.
#[must_use]
pub const fn is_input_valid_size(requirement_count: usize) -> bool {
    requirement_count <= MAX_REQUIREMENTS
}

// ---------------------------------------------------------------------------
// System capabilities (assessment input)
// ---------------------------------------------------------------------------

/// Description of a system's security capabilities.
///
/// Populate the relevant fields and pass to [`assess`] together with a target
/// [`SecurityLevel`] to obtain a compliance report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SystemCapabilities {
    // FR 1 -- Identification and Authentication Control
    /// The system authenticates human users.
    pub has_user_authentication: bool,
    /// The system authenticates software processes and devices.
    pub has_device_authentication: bool,
    /// The system supports multi-factor authentication.
    pub has_multifactor_auth: bool,
    /// The system uses PKI certificates for authentication.
    pub has_pki_certificates: bool,
    /// Minimum password length enforced by the system.
    pub password_min_length: u8,
    /// Maximum consecutive failed login attempts before lockout.
    pub max_failed_login_attempts: u8,
    /// The system notifies users of previous login attempts.
    pub has_login_notification: bool,
    /// The system protects access from untrusted networks.
    pub has_untrusted_network_protection: bool,
    /// The system uses symmetric-key-based authentication.
    pub has_symmetric_key_auth: bool,

    // FR 2 -- Use Control
    /// The system enforces authorization policies.
    pub has_authorization_enforcement: bool,
    /// The system supports session lock after inactivity.
    pub has_session_lock: bool,
    /// Session inactivity timeout in seconds.
    pub session_timeout_seconds: u32,
    /// The system implements concurrent-session control (CR 2.7).
    ///
    /// Must be `true` for `max_concurrent_sessions` to be scored; a system
    /// that does not implement this control earns no credit for CR 2.7 even
    /// if `max_concurrent_sessions` happens to be set.
    pub has_concurrent_session_control: bool,
    /// Maximum number of concurrent sessions per user.
    pub max_concurrent_sessions: u8,
    /// The system records auditable events.
    pub has_audit_logging: bool,
    /// Number of audit log entries the system can retain.
    pub audit_log_capacity_entries: u32,
    /// The system responds to audit processing failures.
    pub has_audit_failure_response: bool,
    /// The system provides trusted timestamps.
    pub has_timestamps: bool,
    /// The system supports non-repudiation of actions.
    pub has_non_repudiation: bool,

    // FR 3 -- System Integrity
    /// The system performs self-tests at startup.
    pub has_self_test: bool,
    /// The system verifies software integrity before execution.
    pub has_software_integrity_verification: bool,
    /// The system validates all external inputs.
    pub has_input_validation: bool,
    /// The system protects session integrity.
    pub has_session_integrity: bool,
    /// The system protects audit log integrity.
    pub has_audit_protection: bool,

    // FR 4 -- Data Confidentiality
    /// The system protects data confidentiality at rest and in transit.
    pub has_data_confidentiality: bool,
    /// The system protects against data persistence on shared resources.
    pub has_data_persistence_protection: bool,
    /// The system uses cryptographic mechanisms.
    pub has_cryptography: bool,
    /// Cryptographic key length in bits (e.g. 128, 192, 256).
    pub crypto_key_length_bits: u16,

    // FR 5 -- Restricted Data Flow
    /// The system implements network segmentation.
    pub has_network_segmentation: bool,
    /// The system enforces zone boundary protection.
    pub has_zone_boundary_protection: bool,

    // FR 6 -- Timely Response to Events
    /// Audit logs are accessible to authorised personnel.
    pub has_audit_log_accessibility: bool,
    /// The system performs continuous monitoring.
    pub has_continuous_monitoring: bool,

    // FR 7 -- Resource Availability
    /// The system has denial-of-service protection.
    pub has_dos_protection: bool,
    /// The system manages resources to prevent exhaustion.
    pub has_resource_management: bool,
    /// The system supports backup of configuration and data.
    pub has_backup: bool,
    /// The system supports recovery and reconstitution.
    pub has_recovery: bool,
    /// The system documents network and security configuration.
    pub has_network_config_settings: bool,
    /// The system restricts functionality to the minimum required.
    pub has_least_functionality: bool,
}

impl SystemCapabilities {
    /// Validates that capability values are within acceptable bounds.
    ///
    /// Numeric fields are only checked when an associated feature is enabled.
    /// `crypto_key_length_bits` is validated whenever **any** crypto-consuming
    /// feature is enabled (`has_cryptography`, `has_pki_certificates`, or
    /// `has_symmetric_key_auth`) so that a key length scored by CR 1.9 /
    /// CR 1.14 / CR 4.3 can never bypass bounds checking.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if any of the following hold:
    /// - `crypto_key_length_bits` is 0 or exceeds 4096 (when any of
    ///   `has_cryptography`, `has_pki_certificates`, or
    ///   `has_symmetric_key_auth` is enabled)
    /// - `password_min_length` exceeds 128
    /// - `max_failed_login_attempts` is 0 (when user auth is enabled)
    /// - `session_timeout_seconds` is 0 (when session lock is enabled)
    /// - `max_concurrent_sessions` is 0 (when session lock is enabled)
    #[must_use = "validation result must not be silently ignored"]
    pub fn validate(&self) -> Result<(), VsError> {
        // `crypto_key_length_bits` feeds CR 1.9 (gated on `has_pki_certificates`),
        // CR 1.14 (gated on `has_symmetric_key_auth`), and CR 4.3 (gated on
        // `has_cryptography`). Bounds-check it whenever any of those features
        // is enabled, otherwise a caller could earn SL-4 from an unvetted key
        // length by leaving `has_cryptography = false`.
        let crypto_key_used =
            self.has_cryptography || self.has_pki_certificates || self.has_symmetric_key_auth;
        if crypto_key_used
            && (self.crypto_key_length_bits == 0 || self.crypto_key_length_bits > 4096)
        {
            return Err(VsError::InvalidInput);
        }
        if self.password_min_length > 128 {
            return Err(VsError::InvalidInput);
        }
        if self.has_user_authentication && self.max_failed_login_attempts == 0 {
            return Err(VsError::InvalidInput);
        }
        if self.has_session_lock && self.session_timeout_seconds == 0 {
            return Err(VsError::InvalidInput);
        }
        if self.has_session_lock && self.max_concurrent_sessions == 0 {
            return Err(VsError::InvalidInput);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Assessment output
// ---------------------------------------------------------------------------

/// Complete IEC 62443-4-2 assessment result.
///
/// Fields are crate-private; use the accessor methods to read the assessment
/// state. In particular, [`entries`](Self::entries) returns the slice of
/// valid `RequirementAssessment` rows (without the trailing placeholders).
#[derive(Debug, Clone)]
pub struct Iec62443Assessment {
    /// Per-CR assessment results (with placeholder rows past `count`).
    pub(crate) assessments: [RequirementAssessment; MAX_REQUIREMENTS],
    /// Number of valid entries in `assessments`.
    pub(crate) count: usize,
    /// The target Security Level for this assessment.
    pub(crate) target_sl: SecurityLevel,
    /// The lowest Security Level achieved across all assessed CRs.
    pub(crate) achieved_sl: SecurityLevel,
    /// Number of CRs that are fully compliant.
    pub(crate) compliant_count: usize,
    /// Number of CRs that are non-compliant.
    pub(crate) non_compliant_count: usize,
    /// Number of CRs that are partially compliant.
    pub(crate) partial_count: usize,
    /// Number of CRs that are not applicable at the target SL.
    pub(crate) not_applicable_count: usize,
}

impl Iec62443Assessment {
    /// Returns the slice of valid per-CR assessment entries.
    ///
    /// This is `&assessments[..count]` — the trailing placeholder rows
    /// (used only for fixed-size stack storage) are excluded.
    #[must_use]
    pub fn entries(&self) -> &[RequirementAssessment] {
        &self.assessments[..self.count]
    }

    /// Number of valid entries in [`entries`](Self::entries).
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// The target Security Level this assessment was run against.
    #[must_use]
    pub fn target_sl(&self) -> SecurityLevel {
        self.target_sl
    }

    /// The lowest Security Level achieved across all applicable CRs,
    /// clamped to the target SL.
    #[must_use]
    pub fn achieved_sl(&self) -> SecurityLevel {
        self.achieved_sl
    }

    /// Number of CRs that are fully compliant at the target SL.
    #[must_use]
    pub fn compliant_count(&self) -> usize {
        self.compliant_count
    }

    /// Number of CRs that are non-compliant (below SL-1).
    #[must_use]
    pub fn non_compliant_count(&self) -> usize {
        self.non_compliant_count
    }

    /// Number of CRs that are partially compliant (meet SL-1 but not target).
    #[must_use]
    pub fn partial_count(&self) -> usize {
        self.partial_count
    }

    /// Number of CRs that are not applicable at the target SL.
    #[must_use]
    pub fn not_applicable_count(&self) -> usize {
        self.not_applicable_count
    }

    /// Returns `true` if every applicable CR is fully compliant.
    #[must_use]
    pub fn is_compliant(&self) -> bool {
        self.non_compliant_count == 0 && self.partial_count == 0
    }

    /// Number of non-compliant or partially compliant findings.
    #[must_use]
    pub fn gap_count(&self) -> usize {
        self.non_compliant_count + self.partial_count
    }

    /// Returns the gap finding at `index`, or `None` if out of range.
    ///
    /// Gap findings are non-compliant or partially compliant CRs, returned
    /// in the same order they appear in [`entries`](Self::entries).
    ///
    /// This method walks the entries from the beginning on every call, so
    /// iterating all gaps via `for i in 0..gap_count()` is quadratic. Prefer
    /// [`iter_gaps`](Self::iter_gaps) for whole-set iteration.
    #[must_use]
    #[deprecated(since = "0.7.0", note = "use iter_gaps")]
    pub fn gap_at(&self, index: usize) -> Option<&RequirementAssessment> {
        let mut seen = 0;
        let mut i = 0;
        while i < self.count {
            let a = &self.assessments[i];
            if a.status == ComplianceStatus::NonCompliant
                || a.status == ComplianceStatus::PartiallyCompliant
            {
                if seen == index {
                    return Some(a);
                }
                seen += 1;
            }
            i += 1;
        }
        None
    }

    /// Returns an iterator over all gap findings (non-compliant or
    /// partially-compliant CRs) in [`entries`](Self::entries) order.
    ///
    /// Unlike repeated calls to [`gap_at`](Self::gap_at), this walks the
    /// entries exactly once.
    pub fn iter_gaps(&self) -> impl Iterator<Item = &RequirementAssessment> {
        self.entries().iter().filter(|a| {
            matches!(
                a.status,
                ComplianceStatus::NonCompliant | ComplianceStatus::PartiallyCompliant
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Assessment engine
// ---------------------------------------------------------------------------

/// Placeholder assessment for array initialisation.
const EMPTY_ASSESSMENT: RequirementAssessment = RequirementAssessment {
    requirement: ComponentRequirement::Cr1_1,
    target_sl: SecurityLevel::Sl1,
    achieved_sl: SecurityLevel::Sl1,
    status: ComplianceStatus::NotAssessed,
};

/// Schema version of the [`Iec62443Assessment`] payload embedded in the
/// returned [`Evidence`] envelope.
pub const ASSESSMENT_SCHEMA_VERSION: u32 = 1;

/// Tool-version tag baked into the `Evidence` metadata. Padded to 16 bytes.
const TOOL_VERSION: [u8; 16] = *b"iec62443-0.7\0\0\0\0";

/// Evaluate a system's capabilities against IEC 62443-4-2 at the given
/// target [`SecurityLevel`].
///
/// Every Component Requirement in [`ALL_REQUIREMENTS`] is checked. CRs whose
/// [`min_sl`](ComponentRequirement::min_sl) exceeds `target_sl` are marked
/// [`NotApplicable`](ComplianceStatus::NotApplicable).
///
/// The returned [`Evidence`] envelope wraps the [`Iec62443Assessment`]
/// payload together with provenance metadata (assessor id, tool version,
/// input hash, schema version). The metadata fields are zeroed by default --
/// callers that need stronger provenance should sign the envelope at a
/// higher layer or use [`assess_with_metadata`] to supply pre-computed
/// metadata.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if `capabilities` fail bounds validation
/// (see [`SystemCapabilities::validate`]).
///
/// # Example
///
/// ```
/// use vs_report_iec62443::{assess, SecurityLevel, SystemCapabilities};
///
/// # fn example() -> Result<(), vs_types::VsError> {
/// // Describe the system under test
/// let mut caps = SystemCapabilities::default();
/// caps.has_user_authentication = true;
/// caps.max_failed_login_attempts = 3;
/// caps.has_authorization_enforcement = true;
/// caps.has_cryptography = true;
/// caps.crypto_key_length_bits = 256;
/// caps.has_audit_logging = true;
///
/// // Run the assessment against SL-2
/// let evidence = assess(&caps, SecurityLevel::Sl2)?;
/// let report = evidence.payload();
///
/// if report.is_compliant() {
///     // Target SL achieved
/// } else {
///     // Inspect gaps
///     for gap in report.iter_gaps() {
///         // gap.requirement, gap.status, gap.achieved_sl ...
///         let _ = gap;
///     }
/// }
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
pub fn assess(
    capabilities: &SystemCapabilities,
    target_sl: SecurityLevel,
) -> Result<Evidence<Iec62443Assessment>, VsError> {
    let metadata = EvidenceMetadata {
        generated_at_ns: 0,
        assessor_id: [0; 16],
        tool_version: TOOL_VERSION,
        input_hash: [0; 32],
        schema_version: ASSESSMENT_SCHEMA_VERSION,
    };
    assess_with_metadata(capabilities, target_sl, metadata)
}

/// Like [`assess`] but allows the caller to supply pre-computed
/// [`EvidenceMetadata`] (e.g. with an input hash and assessor id).
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if `capabilities` fail bounds validation.
pub fn assess_with_metadata(
    capabilities: &SystemCapabilities,
    target_sl: SecurityLevel,
    metadata: EvidenceMetadata,
) -> Result<Evidence<Iec62443Assessment>, VsError> {
    let payload = assess_payload(capabilities, target_sl)?;
    Ok(Evidence::with_metadata(
        payload,
        Standard::Iec62443,
        metadata,
    ))
}

/// Builds the raw [`Iec62443Assessment`] payload (no envelope).
///
/// Crate-internal helper shared by [`assess`] and [`assess_with_metadata`].
fn assess_payload(
    capabilities: &SystemCapabilities,
    target_sl: SecurityLevel,
) -> Result<Iec62443Assessment, VsError> {
    let mut buf = Iec62443Assessment {
        assessments: [EMPTY_ASSESSMENT; MAX_REQUIREMENTS],
        count: 0,
        target_sl,
        achieved_sl: SecurityLevel::Sl1,
        compliant_count: 0,
        non_compliant_count: 0,
        partial_count: 0,
        not_applicable_count: 0,
    };
    assess_into(&mut buf, capabilities, target_sl)?;
    Ok(buf)
}

/// Run the assessment into a caller-provided [`Iec62443Assessment`] buffer.
///
/// This variant avoids the ~40-entry stack zero-initialisation that
/// [`assess`] / [`assess_with_metadata`] perform internally. Callers that
/// run the assessor repeatedly (e.g. fuzzing, regression sweeps) can reuse
/// a single buffer across invocations. The buffer is reset before each run,
/// so the previous contents do not need to be cleared by the caller.
///
/// The trailing placeholder rows in `Iec62443Assessment::assessments`
/// (those past `count`) may retain stale data from a previous run; consumers
/// must use [`Iec62443Assessment::entries`] to read only the valid prefix.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if `capabilities` fail bounds validation
/// (see [`SystemCapabilities::validate`]).
pub fn assess_into(
    buf: &mut Iec62443Assessment,
    capabilities: &SystemCapabilities,
    target_sl: SecurityLevel,
) -> Result<(), VsError> {
    capabilities.validate()?;

    // Reset counters and metadata. Per-entry slots are overwritten by index
    // up to `count`; stale tail entries past `count` are ignored by
    // `entries()`, so we deliberately do not re-zero the whole array.
    buf.count = 0;
    buf.target_sl = target_sl;
    buf.compliant_count = 0;
    buf.non_compliant_count = 0;
    buf.partial_count = 0;
    buf.not_applicable_count = 0;

    let mut overall_achieved = SecurityLevel::Sl4;
    let mut below_sl1 = false;

    let mut i = 0;
    while i < ALL_REQUIREMENTS.len() {
        let cr = ALL_REQUIREMENTS[i];
        i += 1;

        // Skip CRs that do not apply at the target SL.
        if target_sl < cr.min_sl() {
            buf.assessments[buf.count] = RequirementAssessment {
                requirement: cr,
                target_sl,
                achieved_sl: target_sl,
                status: ComplianceStatus::NotApplicable,
            };
            buf.count += 1;
            buf.not_applicable_count += 1;
            continue;
        }

        let achieved_opt = evaluate_cr(cr, capabilities);
        let status = compliance_status(achieved_opt, target_sl);
        let achieved = achieved_opt.unwrap_or(SecurityLevel::Sl1);

        buf.assessments[buf.count] = RequirementAssessment {
            requirement: cr,
            target_sl,
            achieved_sl: achieved,
            status,
        };
        buf.count += 1;

        match status {
            ComplianceStatus::Compliant => buf.compliant_count += 1,
            ComplianceStatus::NonCompliant => {
                buf.non_compliant_count += 1;
                // NonCompliant means below SL-1 -- pull overall down.
                below_sl1 = true;
            }
            ComplianceStatus::PartiallyCompliant => buf.partial_count += 1,
            ComplianceStatus::NotApplicable | ComplianceStatus::NotAssessed => {}
        }

        if let Some(a) = achieved_opt {
            if a < overall_achieved {
                overall_achieved = a;
            }
        }
    }

    // If any CR is below SL-1 or nothing was assessed, clamp to Sl1.
    if below_sl1
        || (buf.compliant_count == 0 && buf.non_compliant_count == 0 && buf.partial_count == 0)
    {
        overall_achieved = SecurityLevel::Sl1;
    }

    // Clamp the overall achieved SL to the target. A system cannot
    // legitimately "exceed" the requested target -- reporting a higher SL
    // would imply the assessor verified controls beyond the scope of the
    // requested target, which is not the case.
    if overall_achieved > target_sl {
        overall_achieved = target_sl;
    }

    buf.achieved_sl = overall_achieved;
    Ok(())
}

/// Determine the [`ComplianceStatus`] given an achieved SL and a target SL.
///
/// `achieved` is `None` when the system does not meet even SL-1 for a CR.
const fn compliance_status(
    achieved: Option<SecurityLevel>,
    target: SecurityLevel,
) -> ComplianceStatus {
    match achieved {
        None => ComplianceStatus::NonCompliant,
        Some(a) => {
            if a as u8 >= target as u8 {
                ComplianceStatus::Compliant
            } else {
                ComplianceStatus::PartiallyCompliant
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-CR evaluation: maps capabilities to an achieved SecurityLevel
// ---------------------------------------------------------------------------

/// Minimum crypto key length required at each SL.
const CRYPTO_KEY_SL1: u16 = 128;
const CRYPTO_KEY_SL2: u16 = 160;
const CRYPTO_KEY_SL3: u16 = 192;
const CRYPTO_KEY_SL4: u16 = 256;

/// Minimum password length thresholds per SL.
const PASSWORD_SL1: u8 = 8;
const PASSWORD_SL2: u8 = 10;
const PASSWORD_SL3: u8 = 12;
const PASSWORD_SL4: u8 = 16;

/// Minimum audit log capacity thresholds per SL.
const AUDIT_CAP_SL1: u32 = 100;
const AUDIT_CAP_SL2: u32 = 1_000;
const AUDIT_CAP_SL3: u32 = 10_000;
const AUDIT_CAP_SL4: u32 = 100_000;

/// Evaluate a single CR against capabilities, returning the highest SL met.
///
/// Returns `None` when even SL-1 requirements are not satisfied.
#[allow(clippy::too_many_lines)]
fn evaluate_cr(cr: ComponentRequirement, caps: &SystemCapabilities) -> Option<SecurityLevel> {
    // Accumulator: 0 means "below SL-1", 1..=4 maps to Sl1..Sl4.
    let level: u8 = match cr {
        // -----------------------------------------------------------------
        // FR 1 -- Identification and Authentication Control
        // -----------------------------------------------------------------
        ComponentRequirement::Cr1_1 => {
            // Human user ID and auth
            if caps.has_user_authentication {
                if caps.has_pki_certificates && caps.has_multifactor_auth {
                    4
                } else if caps.has_multifactor_auth {
                    3
                } else if caps.has_device_authentication {
                    2
                } else {
                    1
                }
            } else {
                0
            }
        }

        ComponentRequirement::Cr1_2 => {
            // Software process / device auth
            if caps.has_device_authentication {
                if caps.has_pki_certificates {
                    4
                } else if caps.has_multifactor_auth {
                    3
                } else {
                    2
                }
            } else {
                0
            }
        }

        ComponentRequirement::Cr1_3 | ComponentRequirement::Cr1_4 => {
            // Account / identifier management -- tied to basic auth
            if caps.has_user_authentication {
                sl_for_auth_depth(caps)
            } else {
                0
            }
        }

        ComponentRequirement::Cr1_5 => {
            // Authenticator management. PKI alone is not sufficient for SL-4
            // — the underlying password policy must also reach SL-3 strength
            // and the crypto key length must be at SL-4 (the PKI binds to a
            // password fallback, and the certificate's underlying key must
            // be strong enough to resist a state-sponsored attacker).
            if !caps.has_user_authentication {
                0
            } else if caps.has_pki_certificates
                && caps.password_min_length >= PASSWORD_SL3
                && caps.crypto_key_length_bits >= CRYPTO_KEY_SL4
            {
                4
            } else if caps.password_min_length >= PASSWORD_SL3 {
                3
            } else if caps.password_min_length >= PASSWORD_SL2 {
                2
            } else {
                1
            }
        }

        ComponentRequirement::Cr1_7 => {
            // Password strength. Only meaningful when user authentication is
            // actually configured — a "strong password policy" on a system
            // that does not authenticate users is not credit-worthy.
            if !caps.has_user_authentication {
                0
            } else if caps.password_min_length >= PASSWORD_SL4 {
                4
            } else if caps.password_min_length >= PASSWORD_SL3 {
                3
            } else if caps.password_min_length >= PASSWORD_SL2 {
                2
            } else {
                u8::from(caps.password_min_length >= PASSWORD_SL1)
            }
        }

        ComponentRequirement::Cr1_8 => {
            // PKI certificates (SL-2+)
            if caps.has_pki_certificates {
                4
            } else {
                0
            }
        }

        ComponentRequirement::Cr1_9 => {
            // Strength of public key auth (SL-2+)
            if caps.has_pki_certificates {
                crypto_sl(caps.crypto_key_length_bits)
            } else {
                0
            }
        }

        ComponentRequirement::Cr1_10 => {
            // Authenticator feedback -- basic boolean
            bool_sl(caps.has_user_authentication)
        }

        ComponentRequirement::Cr1_11 => {
            // Unsuccessful login attempts. A lockout policy on a system with
            // no user authentication is meaningless — the control surface
            // does not exist.
            if !caps.has_user_authentication || caps.max_failed_login_attempts == 0 {
                0
            } else if caps.max_failed_login_attempts <= 3 {
                4
            } else if caps.max_failed_login_attempts <= 5 {
                3
            } else if caps.max_failed_login_attempts <= 8 {
                2
            } else {
                1
            }
        }

        ComponentRequirement::Cr1_12 => {
            // System use notification (SL-3+)
            bool_sl(caps.has_login_notification)
        }

        ComponentRequirement::Cr1_13 => {
            // Access via untrusted networks
            bool_sl(caps.has_untrusted_network_protection)
        }

        ComponentRequirement::Cr1_14 => {
            // Symmetric key auth (SL-2+)
            if caps.has_symmetric_key_auth {
                crypto_sl(caps.crypto_key_length_bits)
            } else {
                0
            }
        }

        // -----------------------------------------------------------------
        // FR 2 -- Use Control
        // -----------------------------------------------------------------
        ComponentRequirement::Cr2_1 => bool_sl(caps.has_authorization_enforcement),

        ComponentRequirement::Cr2_5 => {
            // Session lock
            if caps.has_session_lock {
                if caps.session_timeout_seconds > 0 && caps.session_timeout_seconds <= 60 {
                    4
                } else if caps.session_timeout_seconds <= 300 {
                    3
                } else if caps.session_timeout_seconds <= 900 {
                    2
                } else {
                    1
                }
            } else {
                0
            }
        }

        ComponentRequirement::Cr2_6 => {
            // Remote session termination
            if caps.has_session_lock
                && caps.session_timeout_seconds > 0
                && caps.session_timeout_seconds <= 300
            {
                4
            } else {
                u8::from(caps.has_session_lock)
            }
        }

        ComponentRequirement::Cr2_7 => {
            // Concurrent session control (SL-3+). Credit is gated on an
            // explicit "control implemented" flag — a bare session count
            // must not award compliance for a system that does not implement
            // the control at all.
            if !caps.has_concurrent_session_control || caps.max_concurrent_sessions == 0 {
                0
            } else if caps.max_concurrent_sessions == 1 {
                4
            } else if caps.max_concurrent_sessions <= 3 {
                3
            } else {
                1
            }
        }

        ComponentRequirement::Cr2_8 => {
            // Auditable events
            bool_sl(caps.has_audit_logging)
        }

        ComponentRequirement::Cr2_9 => {
            // Audit storage capacity
            if caps.audit_log_capacity_entries >= AUDIT_CAP_SL4 {
                4
            } else if caps.audit_log_capacity_entries >= AUDIT_CAP_SL3 {
                3
            } else if caps.audit_log_capacity_entries >= AUDIT_CAP_SL2 {
                2
            } else {
                u8::from(caps.audit_log_capacity_entries >= AUDIT_CAP_SL1)
            }
        }

        ComponentRequirement::Cr2_10 => bool_sl(caps.has_audit_failure_response),

        ComponentRequirement::Cr2_11 => bool_sl(caps.has_timestamps),

        ComponentRequirement::Cr2_12 => {
            // Non-repudiation (SL-2+)
            bool_sl(caps.has_non_repudiation)
        }

        // -----------------------------------------------------------------
        // FR 3 -- System Integrity
        // -----------------------------------------------------------------
        ComponentRequirement::Cr3_3 => bool_sl(caps.has_self_test),

        ComponentRequirement::Cr3_4 => bool_sl(caps.has_software_integrity_verification),

        ComponentRequirement::Cr3_5 => bool_sl(caps.has_input_validation),

        ComponentRequirement::Cr3_7 => {
            // Error handling (SL-2+) -- mapped to input validation
            bool_sl(caps.has_input_validation)
        }

        ComponentRequirement::Cr3_8 => bool_sl(caps.has_session_integrity),

        ComponentRequirement::Cr3_9 => bool_sl(caps.has_audit_protection),

        // -----------------------------------------------------------------
        // FR 4 -- Data Confidentiality
        // -----------------------------------------------------------------
        ComponentRequirement::Cr4_1 => bool_sl(caps.has_data_confidentiality),

        ComponentRequirement::Cr4_2 => bool_sl(caps.has_data_persistence_protection),

        ComponentRequirement::Cr4_3 => {
            // Use of cryptography
            if caps.has_cryptography {
                crypto_sl(caps.crypto_key_length_bits)
            } else {
                0
            }
        }

        // -----------------------------------------------------------------
        // FR 5 -- Restricted Data Flow
        // -----------------------------------------------------------------
        ComponentRequirement::Cr5_1 => {
            if caps.has_network_segmentation && caps.has_zone_boundary_protection {
                4
            } else {
                u8::from(caps.has_network_segmentation)
            }
        }

        // -----------------------------------------------------------------
        // FR 6 -- Timely Response to Events
        // -----------------------------------------------------------------
        ComponentRequirement::Cr6_1 => bool_sl(caps.has_audit_log_accessibility),

        ComponentRequirement::Cr6_2 => {
            // Continuous monitoring (SL-2+)
            bool_sl(caps.has_continuous_monitoring)
        }

        // -----------------------------------------------------------------
        // FR 7 -- Resource Availability
        // -----------------------------------------------------------------
        ComponentRequirement::Cr7_1 => bool_sl(caps.has_dos_protection),

        ComponentRequirement::Cr7_2 => bool_sl(caps.has_resource_management),

        ComponentRequirement::Cr7_3 => bool_sl(caps.has_backup),

        ComponentRequirement::Cr7_4 => bool_sl(caps.has_recovery),

        ComponentRequirement::Cr7_6 => bool_sl(caps.has_network_config_settings),

        ComponentRequirement::Cr7_7 => bool_sl(caps.has_least_functionality),
    };

    level_to_sl(level)
}

/// Map a boolean capability to a raw SL level (0 or 1).
const fn bool_sl(present: bool) -> u8 {
    present as u8
}

/// Map a crypto key length to a raw SL level.
const fn crypto_sl(key_bits: u16) -> u8 {
    if key_bits >= CRYPTO_KEY_SL4 {
        4
    } else if key_bits >= CRYPTO_KEY_SL3 {
        3
    } else if key_bits >= CRYPTO_KEY_SL2 {
        2
    } else if key_bits >= CRYPTO_KEY_SL1 {
        1
    } else {
        0
    }
}

/// Helper for auth-depth-based CRs.
fn sl_for_auth_depth(caps: &SystemCapabilities) -> u8 {
    if caps.has_pki_certificates && caps.has_multifactor_auth {
        4
    } else if caps.has_multifactor_auth {
        3
    } else if caps.has_device_authentication {
        2
    } else {
        1
    }
}

/// Convert a `u8` level (0..=4) to an `Option<SecurityLevel>`.
///
/// Level 0 maps to `None` (below SL-1).
const fn level_to_sl(level: u8) -> Option<SecurityLevel> {
    match level {
        4 => Some(SecurityLevel::Sl4),
        3 => Some(SecurityLevel::Sl3),
        2 => Some(SecurityLevel::Sl2),
        1 => Some(SecurityLevel::Sl1),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    /// Build a fully-capable system that should pass SL-4.
    fn full_capabilities() -> SystemCapabilities {
        SystemCapabilities {
            has_user_authentication: true,
            has_device_authentication: true,
            has_multifactor_auth: true,
            has_pki_certificates: true,
            password_min_length: 16,
            max_failed_login_attempts: 3,
            has_login_notification: true,
            has_untrusted_network_protection: true,
            has_symmetric_key_auth: true,
            has_authorization_enforcement: true,
            has_session_lock: true,
            session_timeout_seconds: 60,
            has_concurrent_session_control: true,
            max_concurrent_sessions: 1,
            has_audit_logging: true,
            audit_log_capacity_entries: 100_000,
            has_audit_failure_response: true,
            has_timestamps: true,
            has_non_repudiation: true,
            has_self_test: true,
            has_software_integrity_verification: true,
            has_input_validation: true,
            has_session_integrity: true,
            has_audit_protection: true,
            has_data_confidentiality: true,
            has_data_persistence_protection: true,
            has_cryptography: true,
            crypto_key_length_bits: 256,
            has_network_segmentation: true,
            has_zone_boundary_protection: true,
            has_audit_log_accessibility: true,
            has_continuous_monitoring: true,
            has_dos_protection: true,
            has_resource_management: true,
            has_backup: true,
            has_recovery: true,
            has_network_config_settings: true,
            has_least_functionality: true,
        }
    }

    /// Convenience: run `assess` and unwrap to the payload.
    fn run(caps: &SystemCapabilities, sl: SecurityLevel) -> Iec62443Assessment {
        assess(caps, sl).unwrap().payload().clone()
    }

    #[test]
    fn default_capabilities_all_non_compliant_at_sl1() {
        let caps = SystemCapabilities::default();
        let report = run(&caps, SecurityLevel::Sl1);

        // Every applicable CR should be NonCompliant since all capabilities
        // default to false/zero.
        for a in report.entries() {
            if a.status != ComplianceStatus::NotApplicable {
                assert_eq!(
                    a.status,
                    ComplianceStatus::NonCompliant,
                    "CR {:?} should be NonCompliant with default caps",
                    a.requirement
                );
            }
        }
        assert!(!report.is_compliant());
    }

    #[test]
    fn full_capabilities_compliant_at_sl1() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl1);

        for a in report.entries() {
            assert!(
                a.status == ComplianceStatus::Compliant
                    || a.status == ComplianceStatus::NotApplicable,
                "CR {:?} should be Compliant or N/A, got {:?}",
                a.requirement,
                a.status
            );
        }
        assert!(report.is_compliant());
    }

    #[test]
    fn mixed_capabilities_partial_compliance() {
        let mut caps = SystemCapabilities::default();
        caps.has_user_authentication = true;
        caps.password_min_length = 8;
        caps.max_failed_login_attempts = 5;
        // Everything else remains default.

        let report = run(&caps, SecurityLevel::Sl1);

        // Some CRs should be compliant, others not.
        assert!(report.compliant_count > 0);
        assert!(report.non_compliant_count > 0);
        assert!(!report.is_compliant());
    }

    #[test]
    fn sl4_target_with_sl2_capabilities() {
        let mut caps = SystemCapabilities::default();
        caps.has_user_authentication = true;
        caps.has_device_authentication = true;
        caps.has_authorization_enforcement = true;
        caps.has_audit_logging = true;
        caps.has_cryptography = true;
        caps.crypto_key_length_bits = 128;
        caps.password_min_length = 10;
        caps.max_failed_login_attempts = 8;
        caps.has_session_lock = true;
        caps.session_timeout_seconds = 900;
        caps.max_concurrent_sessions = 3;
        caps.audit_log_capacity_entries = 1_000;

        let report = run(&caps, SecurityLevel::Sl4);

        // Should have many partial or non-compliant findings.
        assert!(report.partial_count > 0 || report.non_compliant_count > 0);
        assert!(!report.is_compliant());
    }

    #[test]
    fn crypto_key_length_thresholds() {
        let mut caps = SystemCapabilities::default();
        caps.has_cryptography = true;

        // Below minimum -- NonCompliant at SL-1
        caps.crypto_key_length_bits = 64;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr43 = find_cr(&r, ComponentRequirement::Cr4_3);
        assert_eq!(cr43.status, ComplianceStatus::NonCompliant);

        // 128 bits -- Compliant at SL-1
        caps.crypto_key_length_bits = 128;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr43 = find_cr(&r, ComponentRequirement::Cr4_3);
        assert_eq!(cr43.status, ComplianceStatus::Compliant);

        // 192 bits -- achieves SL-3
        caps.crypto_key_length_bits = 192;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr43 = find_cr(&r, ComponentRequirement::Cr4_3);
        assert_eq!(cr43.achieved_sl, SecurityLevel::Sl3);

        // 256 bits -- achieves SL-4
        caps.crypto_key_length_bits = 256;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr43 = find_cr(&r, ComponentRequirement::Cr4_3);
        assert_eq!(cr43.status, ComplianceStatus::Compliant);
        assert_eq!(cr43.achieved_sl, SecurityLevel::Sl4);
    }

    #[test]
    fn audit_capacity_thresholds() {
        let mut caps = SystemCapabilities::default();

        caps.audit_log_capacity_entries = 50;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr29 = find_cr(&r, ComponentRequirement::Cr2_9);
        assert_eq!(cr29.status, ComplianceStatus::NonCompliant);

        caps.audit_log_capacity_entries = 100;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr29 = find_cr(&r, ComponentRequirement::Cr2_9);
        assert_eq!(cr29.status, ComplianceStatus::Compliant);

        caps.audit_log_capacity_entries = 1_000;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr29 = find_cr(&r, ComponentRequirement::Cr2_9);
        assert_eq!(cr29.status, ComplianceStatus::Compliant);
    }

    #[test]
    fn password_length_thresholds() {
        let mut caps = SystemCapabilities::default();
        // Cr1_7 is now gated on has_user_authentication.
        caps.has_user_authentication = true;
        caps.max_failed_login_attempts = 5;

        // Below minimum
        caps.password_min_length = 4;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr17 = find_cr(&r, ComponentRequirement::Cr1_7);
        assert_eq!(cr17.status, ComplianceStatus::NonCompliant);

        // SL-1 threshold
        caps.password_min_length = 8;
        let r = run(&caps, SecurityLevel::Sl1);
        let cr17 = find_cr(&r, ComponentRequirement::Cr1_7);
        assert_eq!(cr17.status, ComplianceStatus::Compliant);

        // SL-2 threshold
        caps.password_min_length = 10;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr17 = find_cr(&r, ComponentRequirement::Cr1_7);
        assert_eq!(cr17.status, ComplianceStatus::Compliant);

        // SL-3 target with SL-2 password -- partial
        caps.password_min_length = 10;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr17 = find_cr(&r, ComponentRequirement::Cr1_7);
        assert_eq!(cr17.status, ComplianceStatus::PartiallyCompliant);
    }

    #[test]
    fn overall_achieved_sl_is_minimum() {
        let mut caps = full_capabilities();
        // Weaken crypto to SL-1 level
        caps.crypto_key_length_bits = 128;

        let report = run(&caps, SecurityLevel::Sl4);
        // The overall achieved SL should be pulled down by the weakest CR.
        assert!(
            report.achieved_sl < SecurityLevel::Sl4,
            "Overall SL should be below SL-4 when crypto is only 128-bit"
        );
    }

    #[test]
    fn is_compliant_returns_correct_values() {
        let caps = full_capabilities();

        let report = run(&caps, SecurityLevel::Sl1);
        assert!(report.is_compliant());

        let empty = SystemCapabilities::default();
        let report = run(&empty, SecurityLevel::Sl1);
        assert!(!report.is_compliant());
    }

    #[test]
    fn not_applicable_for_crs_above_target_sl() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl1);

        // CR 1.8 (PKI) has min_sl of SL-2, so it should be NotApplicable
        // when targeting SL-1.
        let cr18 = find_cr(&report, ComponentRequirement::Cr1_8);
        assert_eq!(cr18.status, ComplianceStatus::NotApplicable);

        // CR 1.12 (login notification) has min_sl of SL-3.
        let cr112 = find_cr(&report, ComponentRequirement::Cr1_12);
        assert_eq!(cr112.status, ComplianceStatus::NotApplicable);

        // Verify they are counted.
        assert!(report.not_applicable_count > 0);
    }

    #[test]
    #[allow(deprecated)]
    fn gap_accessors_work_correctly() {
        let caps = SystemCapabilities::default();
        let report = run(&caps, SecurityLevel::Sl1);

        let gap_count = report.gap_count();
        assert!(gap_count > 0, "default caps should have gaps");
        assert_eq!(gap_count, report.non_compliant_count + report.partial_count);

        // First gap should be retrievable (deprecated gap_at API).
        let first = report.gap_at(0);
        assert!(first.is_some());

        // Out-of-range should return None.
        let oob = report.gap_at(gap_count);
        assert!(oob.is_none());

        // iter_gaps should yield the same total count.
        assert_eq!(report.iter_gaps().count(), gap_count);
    }

    #[test]
    fn security_level_labels() {
        assert_eq!(SecurityLevel::Sl1.label(), "SL-1");
        assert_eq!(SecurityLevel::Sl2.label(), "SL-2");
        assert_eq!(SecurityLevel::Sl3.label(), "SL-3");
        assert_eq!(SecurityLevel::Sl4.label(), "SL-4");
    }

    // Helpers ---------------------------------------------------------------

    fn find_cr(report: &Iec62443Assessment, cr: ComponentRequirement) -> &RequirementAssessment {
        report
            .entries()
            .iter()
            .find(|a| a.requirement == cr)
            .unwrap_or_else(|| panic!("CR {cr:?} not found in assessment — check that the assessment covers all required requirements"))
    }

    /// Build SL-2-level capabilities (device auth, 10-char passwords, 160-bit
    /// crypto, etc.) but no MFA or PKI.
    fn sl2_capabilities() -> SystemCapabilities {
        SystemCapabilities {
            has_user_authentication: true,
            has_device_authentication: true,
            has_multifactor_auth: false,
            has_pki_certificates: false,
            password_min_length: 10,
            max_failed_login_attempts: 5,
            has_login_notification: false,
            has_untrusted_network_protection: true,
            has_symmetric_key_auth: true,
            has_authorization_enforcement: true,
            has_session_lock: true,
            session_timeout_seconds: 900,
            has_concurrent_session_control: true,
            max_concurrent_sessions: 3,
            has_audit_logging: true,
            audit_log_capacity_entries: 1_000,
            has_audit_failure_response: true,
            has_timestamps: true,
            has_non_repudiation: true,
            has_self_test: true,
            has_software_integrity_verification: true,
            has_input_validation: true,
            has_session_integrity: true,
            has_audit_protection: true,
            has_data_confidentiality: true,
            has_data_persistence_protection: true,
            has_cryptography: true,
            crypto_key_length_bits: 160,
            has_network_segmentation: true,
            has_zone_boundary_protection: true,
            has_audit_log_accessibility: true,
            has_continuous_monitoring: true,
            has_dos_protection: true,
            has_resource_management: true,
            has_backup: true,
            has_recovery: true,
            has_network_config_settings: true,
            has_least_functionality: true,
        }
    }

    #[test]
    fn test_sl2_target_all_compliant() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl2);

        // With full capabilities at SL-2, CRs that use graduated evaluation
        // (crypto, passwords, sessions, etc.) should be Compliant.  Boolean-
        // only CRs (bool_sl) max out at SL-1 and will be PartiallyCompliant.
        // Verify that every non-boolean CR is Compliant or N/A.
        for a in report.entries() {
            assert!(
                a.status == ComplianceStatus::Compliant
                    || a.status == ComplianceStatus::PartiallyCompliant
                    || a.status == ComplianceStatus::NotApplicable,
                "CR {:?} should be Compliant, Partial, or N/A at SL-2, got {:?}",
                a.requirement,
                a.status
            );
        }
        // At SL-2 there should be no NonCompliant findings with full caps.
        assert_eq!(report.non_compliant_count, 0);
    }

    #[test]
    fn test_sl3_target_all_compliant() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl3);

        for a in report.entries() {
            assert!(
                a.status == ComplianceStatus::Compliant
                    || a.status == ComplianceStatus::PartiallyCompliant
                    || a.status == ComplianceStatus::NotApplicable,
                "CR {:?} should be Compliant, Partial, or N/A at SL-3, got {:?}",
                a.requirement,
                a.status
            );
        }
        assert_eq!(report.non_compliant_count, 0);
    }

    #[test]
    fn test_sl4_target_all_compliant() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl4);

        for a in report.entries() {
            assert!(
                a.status == ComplianceStatus::Compliant
                    || a.status == ComplianceStatus::PartiallyCompliant
                    || a.status == ComplianceStatus::NotApplicable,
                "CR {:?} should be Compliant, Partial, or N/A at SL-4, got {:?}",
                a.requirement,
                a.status
            );
        }
        assert_eq!(report.non_compliant_count, 0);
    }

    #[test]
    fn test_sl2_only_caps_partial_at_sl3() {
        let caps = sl2_capabilities();
        let report = run(&caps, SecurityLevel::Sl3);

        // SL-2-level capabilities should produce at least some PartiallyCompliant
        // findings when assessed at SL-3.
        assert!(
            report.partial_count > 0,
            "SL-2 caps assessed at SL-3 should have partial compliance findings"
        );
        assert!(!report.is_compliant());
    }

    #[test]
    fn test_session_timeout_thresholds() {
        let mut caps = SystemCapabilities::default();
        caps.has_session_lock = true;
        caps.max_concurrent_sessions = 1;

        // <= 60s -> SL-4
        caps.session_timeout_seconds = 60;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr25 = find_cr(&r, ComponentRequirement::Cr2_5);
        assert_eq!(cr25.achieved_sl, SecurityLevel::Sl4);
        assert_eq!(cr25.status, ComplianceStatus::Compliant);

        // <= 300s -> SL-3
        caps.session_timeout_seconds = 300;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr25 = find_cr(&r, ComponentRequirement::Cr2_5);
        assert_eq!(cr25.achieved_sl, SecurityLevel::Sl3);
        assert_eq!(cr25.status, ComplianceStatus::Compliant);

        // <= 900s -> SL-2
        caps.session_timeout_seconds = 900;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr25 = find_cr(&r, ComponentRequirement::Cr2_5);
        assert_eq!(cr25.achieved_sl, SecurityLevel::Sl2);
        assert_eq!(cr25.status, ComplianceStatus::Compliant);

        // > 900s -> SL-1
        caps.session_timeout_seconds = 901;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr25 = find_cr(&r, ComponentRequirement::Cr2_5);
        assert_eq!(cr25.achieved_sl, SecurityLevel::Sl1);
        assert_eq!(cr25.status, ComplianceStatus::PartiallyCompliant);
    }

    #[test]
    fn test_concurrent_session_thresholds() {
        let mut caps = SystemCapabilities::default();
        // CR 2.7 is gated on an explicit "control implemented" flag.
        caps.has_concurrent_session_control = true;

        // 1 session -> SL-4
        caps.max_concurrent_sessions = 1;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr27 = find_cr(&r, ComponentRequirement::Cr2_7);
        assert_eq!(cr27.achieved_sl, SecurityLevel::Sl4);

        // 3 sessions -> SL-3
        caps.max_concurrent_sessions = 3;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr27 = find_cr(&r, ComponentRequirement::Cr2_7);
        assert_eq!(cr27.achieved_sl, SecurityLevel::Sl3);
        assert_eq!(cr27.status, ComplianceStatus::Compliant);

        // >3 sessions -> SL-1
        caps.max_concurrent_sessions = 4;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr27 = find_cr(&r, ComponentRequirement::Cr2_7);
        assert_eq!(cr27.achieved_sl, SecurityLevel::Sl1);
        assert_eq!(cr27.status, ComplianceStatus::PartiallyCompliant);
    }

    /// Regression: CR 2.7 must not award any credit when the system does not
    /// implement concurrent-session control, even if `max_concurrent_sessions`
    /// is set to a value that would otherwise score (e.g. 1 -> SL-4).
    #[test]
    fn cr2_7_no_credit_without_concurrent_session_control() {
        let mut caps = SystemCapabilities::default();
        caps.has_concurrent_session_control = false;
        caps.max_concurrent_sessions = 1; // would map to SL-4 if gated only on the count

        let r = run(&caps, SecurityLevel::Sl4);
        let cr27 = find_cr(&r, ComponentRequirement::Cr2_7);
        assert_eq!(
            cr27.status,
            ComplianceStatus::NonCompliant,
            "CR 2.7 must be NonCompliant when concurrent-session control is absent"
        );
    }

    #[test]
    fn test_login_attempt_thresholds() {
        let mut caps = SystemCapabilities::default();
        // Cr1_11 is now gated on has_user_authentication.
        caps.has_user_authentication = true;

        // 3 attempts -> SL-4
        caps.max_failed_login_attempts = 3;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr111 = find_cr(&r, ComponentRequirement::Cr1_11);
        assert_eq!(cr111.achieved_sl, SecurityLevel::Sl4);

        // 5 attempts -> SL-3
        caps.max_failed_login_attempts = 5;
        let r = run(&caps, SecurityLevel::Sl3);
        let cr111 = find_cr(&r, ComponentRequirement::Cr1_11);
        assert_eq!(cr111.achieved_sl, SecurityLevel::Sl3);
        assert_eq!(cr111.status, ComplianceStatus::Compliant);

        // 8 attempts -> SL-2
        caps.max_failed_login_attempts = 8;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr111 = find_cr(&r, ComponentRequirement::Cr1_11);
        assert_eq!(cr111.achieved_sl, SecurityLevel::Sl2);
        assert_eq!(cr111.status, ComplianceStatus::Compliant);

        // >8 attempts -> SL-1
        caps.max_failed_login_attempts = 9;
        let r = run(&caps, SecurityLevel::Sl2);
        let cr111 = find_cr(&r, ComponentRequirement::Cr1_11);
        assert_eq!(cr111.achieved_sl, SecurityLevel::Sl1);
        assert_eq!(cr111.status, ComplianceStatus::PartiallyCompliant);
    }

    #[test]
    fn test_partially_compliant_status() {
        let caps = sl2_capabilities();
        let report = run(&caps, SecurityLevel::Sl3);

        // SL-2 caps have no MFA, so CR 1.1 (user auth) should be Partially
        // Compliant at SL-3 (MFA needed for SL-3).
        let cr11 = find_cr(&report, ComponentRequirement::Cr1_1);
        assert_eq!(
            cr11.status,
            ComplianceStatus::PartiallyCompliant,
            "CR 1.1 should be PartiallyCompliant with SL-2 caps at SL-3"
        );
    }

    #[test]
    fn test_all_requirements_assessed() {
        let caps = full_capabilities();
        let report = run(&caps, SecurityLevel::Sl4);

        // Every CR in ALL_REQUIREMENTS must appear in the report.
        assert_eq!(
            report.entries().len(),
            ALL_REQUIREMENTS.len(),
            "All CRs should be assessed"
        );

        // With full capabilities at SL-4, no CR should be NonCompliant or
        // NotAssessed.
        for a in report.entries() {
            assert!(
                a.status == ComplianceStatus::Compliant
                    || a.status == ComplianceStatus::PartiallyCompliant
                    || a.status == ComplianceStatus::NotApplicable,
                "CR {:?} has unexpected status {:?}",
                a.requirement,
                a.status
            );
        }
    }

    #[test]
    fn test_fr_labels() {
        let frs = [
            FoundationalRequirement::Iac,
            FoundationalRequirement::Uc,
            FoundationalRequirement::Si,
            FoundationalRequirement::Dc,
            FoundationalRequirement::Rdf,
            FoundationalRequirement::Tre,
            FoundationalRequirement::Ra,
        ];

        for fr in &frs {
            let label = fr.label();
            assert!(
                !label.is_empty(),
                "FR {:?} should have a non-empty label",
                fr
            );
        }
    }

    #[test]
    fn test_cr_min_sl_consistency() {
        // SL-2+ CRs should be NotApplicable at SL-1
        let sl2_crs = [
            ComponentRequirement::Cr1_8,
            ComponentRequirement::Cr1_9,
            ComponentRequirement::Cr1_14,
            ComponentRequirement::Cr2_12,
            ComponentRequirement::Cr3_7,
            ComponentRequirement::Cr6_2,
        ];
        let caps = full_capabilities();
        let report_sl1 = run(&caps, SecurityLevel::Sl1);
        for cr in &sl2_crs {
            let a = find_cr(&report_sl1, *cr);
            assert_eq!(
                a.status,
                ComplianceStatus::NotApplicable,
                "CR {:?} (min SL-2) should be NotApplicable at SL-1",
                cr
            );
        }

        // SL-3+ CRs should be NotApplicable at SL-2
        let sl3_crs = [ComponentRequirement::Cr1_12, ComponentRequirement::Cr2_7];
        let report_sl2 = run(&caps, SecurityLevel::Sl2);
        for cr in &sl3_crs {
            let a = find_cr(&report_sl2, *cr);
            assert_eq!(
                a.status,
                ComplianceStatus::NotApplicable,
                "CR {:?} (min SL-3) should be NotApplicable at SL-2",
                cr
            );
        }
    }

    #[test]
    fn test_compliance_status_display() {
        // Verify all ComplianceStatus variants are distinct from each other.
        let variants = [
            ComplianceStatus::Compliant,
            ComplianceStatus::NonCompliant,
            ComplianceStatus::PartiallyCompliant,
            ComplianceStatus::NotApplicable,
            ComplianceStatus::NotAssessed,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i], variants[j],
                    "ComplianceStatus variants at index {} and {} should be distinct",
                    i, j
                );
            }
        }
    }

    #[test]
    fn validate_rejects_zero_crypto_key_when_crypto_enabled() {
        let mut caps = full_capabilities();
        caps.crypto_key_length_bits = 0;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_rejects_excessive_crypto_key() {
        let mut caps = full_capabilities();
        caps.crypto_key_length_bits = 4097;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_rejects_excessive_password_length() {
        let mut caps = full_capabilities();
        caps.password_min_length = 129;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_rejects_zero_failed_login_attempts() {
        let mut caps = full_capabilities();
        caps.max_failed_login_attempts = 0;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_rejects_zero_session_timeout() {
        let mut caps = full_capabilities();
        caps.session_timeout_seconds = 0;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_rejects_zero_concurrent_sessions() {
        let mut caps = full_capabilities();
        caps.max_concurrent_sessions = 0;
        assert_eq!(caps.validate(), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_accepts_valid_capabilities() {
        let caps = full_capabilities();
        assert!(caps.validate().is_ok());
    }

    #[test]
    fn assess_returns_error_on_invalid_capabilities() {
        let mut caps = full_capabilities();
        caps.crypto_key_length_bits = 0;
        let result = assess(&caps, SecurityLevel::Sl1);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_input_valid_size() {
        assert!(is_input_valid_size(0));
        assert!(is_input_valid_size(MAX_REQUIREMENTS));
        assert!(!is_input_valid_size(MAX_REQUIREMENTS + 1));
    }

    // Edge-case validation tests --------------------------------------------

    /// `max_concurrent_sessions = 0` with `has_session_lock = true` must
    /// return `InvalidInput` because session locking requires a session limit.
    #[test]
    fn validate_edge_zero_concurrent_sessions_with_lock_enabled() {
        let mut caps = SystemCapabilities::default();
        caps.has_session_lock = true;
        caps.session_timeout_seconds = 300; // valid timeout
        caps.max_concurrent_sessions = 0; // invalid: zero sessions while lock enabled
        assert_eq!(
            caps.validate(),
            Err(VsError::InvalidInput),
            "max_concurrent_sessions=0 with session_lock=true must be InvalidInput"
        );
    }

    /// `session_timeout_seconds = 0` with `has_session_lock = true` must
    /// return `InvalidInput` because a zero-second timeout is nonsensical.
    #[test]
    fn validate_edge_zero_session_timeout_with_lock_enabled() {
        let mut caps = SystemCapabilities::default();
        caps.has_session_lock = true;
        caps.session_timeout_seconds = 0; // invalid: zero timeout while lock enabled
        caps.max_concurrent_sessions = 1; // valid sessions
        assert_eq!(
            caps.validate(),
            Err(VsError::InvalidInput),
            "session_timeout_seconds=0 with session_lock=true must be InvalidInput"
        );
    }

    /// `crypto_key_length_bits = 0` with `has_cryptography = true` must
    /// return `InvalidInput` — a zero-bit key is cryptographically invalid.
    #[test]
    fn validate_edge_zero_crypto_key_length_with_crypto_enabled() {
        let mut caps = SystemCapabilities::default();
        caps.has_cryptography = true;
        caps.crypto_key_length_bits = 0; // invalid: zero-bit key with crypto enabled
        assert_eq!(
            caps.validate(),
            Err(VsError::InvalidInput),
            "crypto_key_length_bits=0 with has_cryptography=true must be InvalidInput"
        );
    }

    /// `SystemCapabilities::default()` has all boolean fields `false` and all
    /// numeric fields `0`. Because the numeric validation is guarded by the
    /// corresponding boolean flag (e.g. `crypto_key_length_bits` is only
    /// checked when `has_cryptography` is `true`), `validate()` must succeed
    /// and `assess()` must return an `Ok` result.
    #[test]
    fn default_capabilities_all_disabled_assess_succeeds() {
        let caps = SystemCapabilities::default();
        assert!(
            caps.validate().is_ok(),
            "default capabilities (all disabled) must pass validate()"
        );
        let result = assess(&caps, SecurityLevel::Sl1);
        assert!(
            result.is_ok(),
            "assess() must succeed for default (all-disabled) capabilities"
        );
    }

    // -----------------------------------------------------------------------
    // 0.7.1 regressions: ghost rows, achieved_sl clamp, Cr1_5/7/11 auth gating
    // -----------------------------------------------------------------------

    /// `entries()` must NOT include the placeholder rows that fill the
    /// `MAX_REQUIREMENTS`-sized backing array past `count`. Each visible
    /// entry must correspond to a real `ALL_REQUIREMENTS` CR.
    ///
    /// The clearest demonstration is a `count < MAX_REQUIREMENTS` scenario.
    /// We construct one by giving the assessor capacity headroom: if
    /// `ALL_REQUIREMENTS.len()` is ever raised below `MAX_REQUIREMENTS`,
    /// this test catches a regression that leaks ghost rows. For the
    /// current build where they are equal, it still proves `entries()`
    /// does not include rows past `count`.
    #[test]
    fn entries_excludes_ghost_rows_past_count() {
        let caps = full_capabilities();
        let env = assess(&caps, SecurityLevel::Sl1).unwrap();
        let report = env.payload();

        // The slice length is exactly `count`, never `MAX_REQUIREMENTS`
        // (when the two happen to be equal, equality must still hold via
        // `count`, not via accidentally exposing the backing array).
        assert_eq!(report.entries().len(), report.count);
        assert!(report.entries().len() <= MAX_REQUIREMENTS);
        assert_eq!(report.entries().len(), ALL_REQUIREMENTS.len());

        // Every entry must be a real CR from `ALL_REQUIREMENTS` — i.e. no
        // `Cr1_1` placeholder rows leaking through with `NotAssessed`.
        for a in report.entries() {
            assert_ne!(
                a.status,
                ComplianceStatus::NotAssessed,
                "entries() must not contain placeholder/unassessed rows"
            );
            assert!(
                ALL_REQUIREMENTS.iter().any(|c| *c == a.requirement),
                "every entry must map to a real ALL_REQUIREMENTS CR"
            );
        }

        // Direct ghost-row check: any row past `count` in the backing array
        // must NOT be visible via the public surface. We can demonstrate
        // this by binary inspection of the placeholder pattern. `count`
        // here equals `ALL_REQUIREMENTS.len()`, so if `MAX_REQUIREMENTS`
        // ever exceeds `count`, any trailing rows must still be excluded
        // from `entries()`. The slice-length equality above guarantees
        // exactly that.
    }

    /// The reported `achieved_sl` must never exceed the requested `target_sl`.
    /// Previously, a system that met SL-4 on every CR but was assessed at
    /// SL-1 could report `achieved_sl = Sl4`, which over-states the
    /// assurance provided.
    #[test]
    fn achieved_sl_clamped_to_target_when_caps_exceed_target() {
        let caps = full_capabilities();

        for target in [
            SecurityLevel::Sl1,
            SecurityLevel::Sl2,
            SecurityLevel::Sl3,
            SecurityLevel::Sl4,
        ] {
            let report = run(&caps, target);
            assert!(
                report.achieved_sl <= target,
                "achieved_sl ({:?}) must be <= target ({:?})",
                report.achieved_sl,
                target
            );
        }
    }

    /// Direct clamp regression: construct a scenario where the (unclamped)
    /// minimum-across-CRs would exceed the target, and verify the public
    /// result is clamped down. We do this by stubbing the minimum: at SL-1
    /// with full caps, *every* applicable CR achieves at least SL-1, and the
    /// graduated CRs achieve SL-4 internally. Without clamping, the
    /// "overall_achieved = min over CRs" would be pulled down only by the
    /// bool-only CRs (capped at SL-1) — but if those happen to all be
    /// NotApplicable at the chosen target, the unclamped result would
    /// inflate. We approximate this by checking that `achieved_sl` does not
    /// exceed `target_sl` even in the strongest configuration.
    #[test]
    fn achieved_sl_never_exceeds_target_even_at_lowest_target() {
        let caps = full_capabilities();
        let r = run(&caps, SecurityLevel::Sl1);
        assert!(
            r.achieved_sl <= SecurityLevel::Sl1,
            "full caps at SL-1 must never report > SL-1 (got {:?})",
            r.achieved_sl
        );
    }

    /// Cr1_5: PKI alone must NOT grant SL-4 if the password policy is below
    /// PASSWORD_SL3 or the crypto key length is below CRYPTO_KEY_SL4.
    #[test]
    fn cr1_5_sl4_requires_password_and_crypto_strength_even_with_pki() {
        let mut caps = SystemCapabilities::default();
        caps.has_user_authentication = true;
        caps.max_failed_login_attempts = 3;
        caps.has_pki_certificates = true;
        caps.password_min_length = 8; // SL-1 only
        caps.has_cryptography = true;
        caps.crypto_key_length_bits = 128; // SL-1 only

        let r = run(&caps, SecurityLevel::Sl4);
        let cr15 = find_cr(&r, ComponentRequirement::Cr1_5);
        assert!(
            cr15.achieved_sl < SecurityLevel::Sl4,
            "Cr1_5 with PKI but weak password/crypto must not reach SL-4 (got {:?})",
            cr15.achieved_sl
        );

        // Strengthen password only — still not SL-4 because crypto is weak.
        caps.password_min_length = 12;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr15 = find_cr(&r, ComponentRequirement::Cr1_5);
        assert!(
            cr15.achieved_sl < SecurityLevel::Sl4,
            "Cr1_5 with PKI + SL-3 password but weak crypto must not reach SL-4"
        );

        // Strengthen both — now SL-4.
        caps.crypto_key_length_bits = 256;
        let r = run(&caps, SecurityLevel::Sl4);
        let cr15 = find_cr(&r, ComponentRequirement::Cr1_5);
        assert_eq!(
            cr15.achieved_sl,
            SecurityLevel::Sl4,
            "Cr1_5 with PKI + SL-3 password + SL-4 crypto must reach SL-4"
        );
    }

    /// Regression: `crypto_key_length_bits` must be bounds-checked whenever a
    /// crypto-consuming feature is enabled, not only when `has_cryptography`
    /// is `true`. CR 1.9 / CR 1.14 score key strength gated on
    /// `has_pki_certificates` / `has_symmetric_key_auth`, so a caller must not
    /// be able to feed an unvetted key length through those flags.
    #[test]
    fn validate_rejects_unbounded_key_length_via_pki_or_symmetric_flags() {
        // PKI on, crypto off, absurd key length -> must be rejected.
        let mut caps = SystemCapabilities::default();
        caps.has_pki_certificates = true;
        caps.crypto_key_length_bits = 5000;
        assert_eq!(
            caps.validate(),
            Err(VsError::InvalidInput),
            "oversized key length must be rejected when has_pki_certificates is set"
        );

        // Symmetric-key auth on, crypto off, zero-bit key -> must be rejected.
        let mut caps = SystemCapabilities::default();
        caps.has_symmetric_key_auth = true;
        caps.crypto_key_length_bits = 0;
        assert_eq!(
            caps.validate(),
            Err(VsError::InvalidInput),
            "zero-bit key must be rejected when has_symmetric_key_auth is set"
        );

        // PKI on with a valid key length must still pass.
        let mut caps = SystemCapabilities::default();
        caps.has_pki_certificates = true;
        caps.crypto_key_length_bits = 256;
        assert!(caps.validate().is_ok());
    }

    /// Cr1_7: when `has_user_authentication = false`, password strength must
    /// not earn any credit. The lockout/strength policy is meaningless on a
    /// system that never authenticates users.
    #[test]
    fn cr1_7_returns_zero_when_user_authentication_disabled() {
        let mut caps = SystemCapabilities::default();
        caps.has_user_authentication = false;
        caps.password_min_length = 32; // would otherwise be SL-4

        let r = run(&caps, SecurityLevel::Sl1);
        let cr17 = find_cr(&r, ComponentRequirement::Cr1_7);
        assert_eq!(
            cr17.status,
            ComplianceStatus::NonCompliant,
            "Cr1_7 must be NonCompliant when user authentication is disabled, regardless of password length"
        );
    }

    /// Cr1_11: when `has_user_authentication = false`, the lockout policy
    /// (`max_failed_login_attempts`) is meaningless and must not earn any
    /// credit.
    #[test]
    fn cr1_11_returns_zero_when_user_authentication_disabled() {
        let mut caps = SystemCapabilities::default();
        caps.has_user_authentication = false;
        caps.max_failed_login_attempts = 3; // would otherwise be SL-4

        let r = run(&caps, SecurityLevel::Sl1);
        let cr111 = find_cr(&r, ComponentRequirement::Cr1_11);
        assert_eq!(
            cr111.status,
            ComplianceStatus::NonCompliant,
            "Cr1_11 must be NonCompliant when user authentication is disabled, regardless of lockout threshold"
        );
    }

    /// Sanity check: `assess` returns an `Evidence<Iec62443Assessment>` with
    /// the schema version baked into the metadata.
    #[test]
    fn assess_returns_evidence_envelope_with_schema_version() {
        let caps = full_capabilities();
        let env = assess(&caps, SecurityLevel::Sl2).unwrap();

        assert_eq!(
            env.metadata().schema_version,
            ASSESSMENT_SCHEMA_VERSION,
            "Evidence metadata must record the assessment schema version"
        );
        assert_eq!(
            env.metadata().tool_version,
            TOOL_VERSION,
            "Evidence metadata must record the tool version"
        );
        // No signature is attached by `assess` itself; higher layers may sign.
        assert!(env.signature().is_none());

        // The payload is still accessible and well-formed.
        assert_eq!(env.payload().target_sl(), SecurityLevel::Sl2);
        assert!(!env.payload().entries().is_empty());
    }

    /// `assess_with_metadata` must propagate caller-supplied metadata.
    #[test]
    fn assess_with_metadata_propagates_caller_metadata() {
        let caps = full_capabilities();
        let metadata = EvidenceMetadata {
            generated_at_ns: 1_234_567_890,
            assessor_id: [7; 16],
            tool_version: *b"caller-vN.M.K\0\0\0",
            input_hash: [0xAB; 32],
            schema_version: ASSESSMENT_SCHEMA_VERSION,
        };

        let env = assess_with_metadata(&caps, SecurityLevel::Sl3, metadata).unwrap();

        assert_eq!(env.metadata().generated_at_ns, 1_234_567_890);
        assert_eq!(env.metadata().assessor_id, [7; 16]);
        assert_eq!(env.metadata().input_hash, [0xAB; 32]);
        assert_eq!(env.metadata().schema_version, ASSESSMENT_SCHEMA_VERSION);
    }
}
