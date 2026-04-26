// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! UDS (ISO 14229) diagnostic gateway with security enforcement.
//!
//! Provides session management, `SecurityAccess` (0x27) with multi-level seed/key exchange,
//! brute-force lockout with exponential backoff, SID-level authorization policies,
//! and a ring-buffer audit log.

#![no_std]

use vs_crypto::{CryptoProvider, KeyId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent diagnostic sessions.
const MAX_SESSIONS: usize = 4;

// Compile-time assertion: MAX_SESSIONS must fit in a u8 bitmask.
const _: () = assert!(MAX_SESSIONS <= 8);

/// Maximum lockout entries for brute-force prevention.
const MAX_LOCKOUT_ENTRIES: usize = 16;

/// Number of failed `SecurityAccess` attempts before lockout.
const LOCKOUT_THRESHOLD: u8 = 3;

/// Minimum interval (microseconds) between seed requests from the same tester.
const MIN_SEED_INTERVAL_US: u64 = 100_000; // 100 ms

/// Audit-log ring-buffer capacity. Must be a power of 2 for bitmask indexing.
const AUDIT_LOG_CAPACITY: usize = 512;
const _: () = assert!(AUDIT_LOG_CAPACITY.is_power_of_two());

// UDS SID constants
const SID_DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
const SID_SECURITY_ACCESS: u8 = 0x27;
const SID_ROUTINE_CONTROL: u8 = 0x31;
const SID_REQUEST_DOWNLOAD: u8 = 0x34;
const SID_TRANSFER_DATA: u8 = 0x36;
const SID_REQUEST_TRANSFER_EXIT: u8 = 0x37;

/// UDS DiagnosticSessionControl (SID 0x10) sub-function for the default session.
const DSC_DEFAULT_SESSION: u8 = 0x01;

// SecurityAccess sub-functions (used in tests)
#[cfg(test)]
const SA_REQUEST_SEED: u8 = 0x01;
#[cfg(test)]
const SA_SEND_KEY: u8 = 0x02;

/// Upper limit for valid `SecurityAccess` sub-functions (UDS standard).
const SA_MAX_SUB_FUNCTION: u8 = 0x42;

// Decision codes for audit log entries.
const DECISION_FORWARD: u8 = 0;
const DECISION_BLOCK: u8 = 1;
const DECISION_MONITOR: u8 = 2;

// ---------------------------------------------------------------------------
// UdsPolicy
// ---------------------------------------------------------------------------

/// Allow-list policy for UDS Service Identifiers.
///
/// Each SID can be marked as allowed without authentication, or as requiring
/// authentication before it is forwarded. Each SID may also carry a
/// per-SID minimum security access level (per ISO 14229) — requests received
/// while the session's current security level is below this threshold are
/// rejected with NRC 0x33 (`securityAccessDenied`).
pub struct UdsPolicy {
    /// SIDs allowed without prior authentication.
    pub allowed_sids: [bool; 256],
    /// SIDs that require an authenticated session.
    pub require_auth_sids: [bool; 256],
    /// Minimum `SecurityAccess` level required for each SID (0 = no minimum).
    /// A request whose session's current level is below this value is rejected
    /// with NRC 0x33 (`securityAccessDenied`).
    pub min_security_levels: [u8; 256],
}

impl Default for UdsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl UdsPolicy {
    /// Create a new policy with no SIDs allowed.
    pub const fn new() -> Self {
        Self {
            allowed_sids: [false; 256],
            require_auth_sids: [false; 256],
            min_security_levels: [0; 256],
        }
    }

    /// Mark a SID as allowed without authentication.
    ///
    /// Clears any `require_auth` flag for the same SID to prevent
    /// conflicting configuration. A SID can be either open or auth-required,
    /// not both.
    pub fn allow_sid(&mut self, sid: u8) {
        let idx = sid as usize;
        self.allowed_sids[idx] = true;
        self.require_auth_sids[idx] = false;
    }

    /// Mark a SID as requiring authentication.
    ///
    /// Clears any `allowed` flag for the same SID to prevent conflicting
    /// configuration. Auth-required takes precedence.
    pub fn require_auth_for_sid(&mut self, sid: u8) {
        let idx = sid as usize;
        self.require_auth_sids[idx] = true;
        self.allowed_sids[idx] = false;
    }

    /// Set the minimum required `SecurityAccess` level for a SID.
    ///
    /// Requests carrying this SID are rejected with NRC 0x33
    /// (`securityAccessDenied`) when the active session's `security_level`
    /// is below `level`. A `level` of 0 disables the per-SID check.
    pub fn set_min_security_level(&mut self, sid: u8, level: u8) {
        self.min_security_levels[sid as usize] = level;
    }

    /// Returns the minimum required security level for `sid` (0 if none).
    pub fn min_security_level(&self, sid: u8) -> u8 {
        self.min_security_levels[sid as usize]
    }

    /// Validate that no SID is marked both allowed and auth-required.
    /// Returns the conflicting SID on failure.
    #[allow(clippy::cast_possible_truncation)]
    pub fn validate(&self) -> Result<(), u8> {
        for i in 0..256usize {
            if self.allowed_sids[i] && self.require_auth_sids[i] {
                // i is in 0..256, so truncation to u8 wraps 256→0, but
                // 256 is excluded from the range so this is always safe.
                return Err(i as u8);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DiagSession
// ---------------------------------------------------------------------------

/// A single diagnostic session.
#[derive(Clone, Copy)]
pub struct DiagSession {
    /// UDS session type (e.g. 0x01 = default, 0x02 = programming, 0x03 = extended).
    pub session_type: u8,
    /// Address of the tester holding this session.
    pub tester_address: u16,
    /// Whether the session has completed `SecurityAccess`.
    pub authenticated: bool,
    /// Security level achieved via `SecurityAccess` (derived as `(sub_function + 1) / 2`).
    pub security_level: u8,
    /// Timestamp (microseconds) when the session was created.
    pub started_at: u64,
    /// Timestamp (microseconds) of last activity.
    pub last_activity_us: u64,
    /// `true` if this slot is occupied.
    active: bool,
    /// Pending seed for `SecurityAccess` challenge/response.
    pending_seed: Option<[u8; 16]>,
    /// Timestamp of the last seed request (for rate limiting).
    last_seed_request_us: u64,
}

impl DiagSession {
    const fn empty() -> Self {
        Self {
            session_type: 0,
            tester_address: 0,
            authenticated: false,
            security_level: 0,
            started_at: 0,
            last_activity_us: 0,
            active: false,
            pending_seed: None,
            last_seed_request_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DiagDecision
// ---------------------------------------------------------------------------

/// Reason a request was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// The session is not authenticated for the requested SID.
    Unauthorized,
    /// The tester is locked out due to too many failed attempts.
    LockedOut,
    /// The session has expired due to inactivity.
    SessionExpired,
    /// The SID is not in the allow-list policy.
    PolicyDenied,
    /// All session slots are occupied by authenticated testers.
    SessionsFull,
    /// The session is authenticated but has not reached the minimum
    /// `SecurityAccess` level required for the requested SID.
    /// Mapped to UDS NRC 0x33 (`securityAccessDenied`).
    SecurityAccessDenied,
}

// UDS NRC (Negative Response Code) values per ISO 14229.
/// NRC 0x33 — `securityAccessDenied`.
pub const NRC_SECURITY_ACCESS_DENIED: u8 = 0x33;
/// NRC 0x7F — `serviceNotSupportedInActiveSession`.
pub const NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION: u8 = 0x7F;
/// NRC 0x37 — `requiredTimeDelayNotExpired` (used here for lockout).
pub const NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED: u8 = 0x37;
/// NRC 0x11 — `serviceNotSupported`.
pub const NRC_SERVICE_NOT_SUPPORTED: u8 = 0x11;
/// NRC 0x24 — `requestSequenceError` (used for session-related errors).
pub const NRC_REQUEST_SEQUENCE_ERROR: u8 = 0x24;
/// NRC 0x72 — `generalProgrammingFailure` (used as a generic fallback).
pub const NRC_GENERAL_PROGRAMMING_FAILURE: u8 = 0x72;

impl BlockReason {
    /// Map this block reason to its UDS Negative Response Code (NRC).
    ///
    /// See ISO 14229-1 § 7.5 (Negative Response Codes).
    #[must_use]
    pub fn nrc(self) -> u8 {
        match self {
            BlockReason::Unauthorized | BlockReason::SecurityAccessDenied => {
                NRC_SECURITY_ACCESS_DENIED
            }
            BlockReason::LockedOut => NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED,
            BlockReason::SessionExpired => NRC_REQUEST_SEQUENCE_ERROR,
            BlockReason::PolicyDenied => NRC_SERVICE_NOT_SUPPORTED,
            BlockReason::SessionsFull => NRC_GENERAL_PROGRAMMING_FAILURE,
        }
    }
}

/// A security challenge returned to the tester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityChallenge {
    /// Random seed that must be signed and returned.
    pub seed: [u8; 16],
}

/// The gateway's decision for an incoming UDS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DiagDecision {
    /// Forward the request to the target ECU.
    Forward,
    /// Block the request for the given reason.
    Block(BlockReason),
    /// Challenge the tester with a seed.
    Challenge(SecurityChallenge),
}

// ---------------------------------------------------------------------------
// Lockout tracking
// ---------------------------------------------------------------------------

/// Tracks brute-force `SecurityAccess` failures per tester address.
///
/// Uses exponential backoff: each successive lockout doubles in duration
/// (capped at 8x the base duration) to discourage persistent attackers.
#[derive(Clone, Copy)]
pub struct LockoutEntry {
    pub tester_address: u16,
    pub fail_count: u8,
    pub locked_until_us: u64,
    /// Number of times lockout has been triggered (for exponential backoff).
    pub lockout_generation: u8,
    pub active: bool,
}

impl LockoutEntry {
    const fn empty() -> Self {
        Self {
            tester_address: 0,
            fail_count: 0,
            locked_until_us: 0,
            lockout_generation: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DiagAuditLog
// ---------------------------------------------------------------------------

/// A single audit-log entry.
#[derive(Clone, Copy, Debug)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Tester address that sent the request.
    pub tester_addr: u16,
    /// UDS SID.
    pub sid: u8,
    /// Encoded decision (0 = Forward, 1 = Block, 2 = Challenge).
    pub decision_code: u8,
    /// Timestamp in microseconds.
    pub timestamp: u64,
}

impl AuditEntry {
    const fn empty() -> Self {
        Self {
            sequence: 0,
            tester_addr: 0,
            sid: 0,
            decision_code: 0,
            timestamp: 0,
        }
    }
}

/// Ring buffer of audit entries.
pub struct DiagAuditLog {
    entries: [AuditEntry; AUDIT_LOG_CAPACITY],
    head: usize,
    count: usize,
    next_seq: u64,
    overflow_count: u64,
}

impl Default for DiagAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagAuditLog {
    /// Create an empty audit log.
    pub const fn new() -> Self {
        Self {
            entries: [AuditEntry::empty(); AUDIT_LOG_CAPACITY],
            head: 0,
            count: 0,
            next_seq: 1,
            overflow_count: 0,
        }
    }

    /// Record a new audit entry.
    pub fn record(&mut self, tester_addr: u16, sid: u8, decision_code: u8, timestamp: u64) {
        if self.count == AUDIT_LOG_CAPACITY {
            self.overflow_count = self.overflow_count.saturating_add(1);
        }
        self.entries[self.head] = AuditEntry {
            sequence: self.next_seq,
            tester_addr,
            sid,
            decision_code,
            timestamp,
        };
        self.head = (self.head + 1) & (AUDIT_LOG_CAPACITY - 1);
        if self.count < AUDIT_LOG_CAPACITY {
            self.count = self.count.saturating_add(1);
        }
        self.next_seq = self.next_seq.saturating_add(1);
    }

    /// Number of entries that were overwritten due to ring buffer overflow.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Total number of entries currently stored.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Retrieve the most recent entry, if any.
    pub fn latest(&self) -> Option<&AuditEntry> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            AUDIT_LOG_CAPACITY - 1
        } else {
            self.head - 1
        };
        Some(&self.entries[idx])
    }

    /// Retrieve an entry by its position from oldest (0) to newest.
    pub fn get(&self, index: usize) -> Option<&AuditEntry> {
        if index >= self.count {
            return None;
        }
        let start = if self.count < AUDIT_LOG_CAPACITY {
            0
        } else {
            self.head
        };
        let actual = (start + index) & (AUDIT_LOG_CAPACITY - 1);
        Some(&self.entries[actual])
    }
}

// ---------------------------------------------------------------------------
// AuditPersistence — external persistence interface
// ---------------------------------------------------------------------------

/// Trait for persisting audit log entries and lockout state to non-volatile
/// storage (e.g. flash, EEPROM, or a remote logging service).
///
/// Implementations should be provided by the platform integrator. The default
/// `NoOpPersistence` discards all entries (in-memory only).
///
/// # Safety considerations
///
/// Implementations must not block indefinitely — they are called from the
/// UDS request processing path and blocking would stall the diagnostic
/// gateway. Use bounded queues or DMA-backed writes.
pub trait AuditPersistence {
    /// Persist a single audit entry to non-volatile storage.
    fn persist_entry(&mut self, entry: &AuditEntry);

    /// Persist lockout state so it survives ECU resets.
    /// Called whenever a tester's lockout state changes.
    fn persist_lockout(
        &mut self,
        tester_address: u16,
        fail_count: u8,
        locked_until_us: u64,
        lockout_generation: u8,
    );

    /// Restore lockout entries from persistent storage.
    ///
    /// Called during gateway initialization. Returns the number of
    /// entries restored into the provided slice.
    ///
    /// After constructing a `DiagGateway`, callers should use this method
    /// to read lockout entries from flash/EEPROM, then pass the result to
    /// [`DiagGateway::restore_lockouts_from`] to repopulate the in-memory
    /// lockout table. This ensures brute-force lockout state survives ECU
    /// resets.
    fn restore_lockouts(&mut self, _lockouts: &mut [LockoutEntry]) -> usize {
        0
    }
}

/// No-op persistence backend (default). All state is in-memory only
/// and lost on ECU reset.
///
/// # Security warning
///
/// With this backend, UDS brute-force lockout counters are lost on ECU
/// reset. An attacker can power-cycle the ECU to reset the fail counter
/// and retry `SecurityAccess` indefinitely. Production deployments **must**
/// provide a real `AuditPersistence` implementation backed by flash,
/// EEPROM, or a remote logging service.
///
/// See `THREAT_MODEL.md` § T4 for details on UDS lockout bypass risks.
#[cfg(any(debug_assertions, test, feature = "stub"))]
#[deprecated(
    since = "0.8.0",
    note = "NoOpPersistence discards audit logs and lockout state on ECU reset, \
            enabling brute-force lockout bypass. Provide a real AuditPersistence \
            implementation for production."
)]
pub struct NoOpPersistence;

#[cfg(any(debug_assertions, test, feature = "stub"))]
#[allow(deprecated)]
impl AuditPersistence for NoOpPersistence {
    fn persist_entry(&mut self, _entry: &AuditEntry) {}
    fn persist_lockout(
        &mut self,
        _tester_address: u16,
        _fail_count: u8,
        _locked_until_us: u64,
        _lockout_generation: u8,
    ) {
    }
}

// ---------------------------------------------------------------------------
// DiagGateway
// ---------------------------------------------------------------------------

/// UDS diagnostics gateway that enforces session management, authentication,
/// brute-force lockout, and SID-level policy.
pub struct DiagGateway<C: CryptoProvider> {
    crypto: C,
    sessions: [DiagSession; MAX_SESSIONS],
    lockouts: [LockoutEntry; MAX_LOCKOUT_ENTRIES],
    policy: UdsPolicy,
    audit: DiagAuditLog,
    /// Duration (microseconds) after which an idle session is terminated.
    session_timeout_us: u64,
    /// Duration (microseconds) a tester is locked out after too many failures.
    lockout_duration_us: u64,
    /// HMAC key slot used for seed/key verification and audit.
    hmac_key_id: KeyId,
    /// Tester addresses whose sessions were expired in the most recent
    /// `expire_sessions` call. Used to emit `SessionExpired` instead of
    /// `Unauthorized`.
    ///
    /// Each slot is `Some(tester_address)` if a session for that tester was
    /// expired in the most recent `expire_sessions` call, or `None` if unused.
    /// Using `Option<u16>` avoids the sentinel-collision problem where tester
    /// address 0x0000 would be indistinguishable from an unused zero-initialized
    /// slot (see Q3 fix).
    recently_expired: [Option<u16>; MAX_SESSIONS],
    /// Bitmask of occupied session slots (bit `i` = session\[i\].active).
    /// Avoids iterating Option values for session lookups.
    active_sessions_mask: u8,
    /// Earliest absolute expiry timestamp across all active sessions.
    /// If `now < nearest_expiry_us`, `expire_sessions` can skip the scan.
    nearest_expiry_us: u64,
    /// Last accepted timestamp for monotonicity enforcement.
    last_timestamp_us: u64,
    /// Optional callback to persist audit entries to non-volatile storage.
    /// Set via `set_persistence_callbacks`.
    persist_entry_fn: Option<fn(&AuditEntry)>,
    /// Optional callback to persist lockout state changes to non-volatile storage.
    /// Signature: `fn(tester_address, fail_count, locked_until_us, lockout_generation)`.
    /// Set via `set_persistence_callbacks`.
    persist_lockout_fn: Option<fn(u16, u8, u64, u8)>,
}

impl<C: CryptoProvider> DiagGateway<C> {
    /// Minimum acceptable value for `session_timeout_us` and `lockout_duration_us` (1 second).
    const MIN_DURATION_US: u64 = 1_000_000;

    /// Create a new diagnostics gateway.
    ///
    /// Both `session_timeout_us` and `lockout_duration_us` are clamped to a
    /// minimum of 1 second (`1_000_000` us) to prevent misconfiguration that
    /// could disable session expiry or lockout protection.
    pub fn new(
        crypto: C,
        policy: UdsPolicy,
        session_timeout_us: u64,
        lockout_duration_us: u64,
        hmac_key_id: KeyId,
    ) -> Self {
        // Clamp to minimum to prevent zero-duration misconfiguration.
        let session_timeout_us = if session_timeout_us < Self::MIN_DURATION_US {
            Self::MIN_DURATION_US
        } else {
            session_timeout_us
        };
        let lockout_duration_us = if lockout_duration_us < Self::MIN_DURATION_US {
            Self::MIN_DURATION_US
        } else {
            lockout_duration_us
        };

        Self {
            crypto,
            sessions: [DiagSession::empty(); MAX_SESSIONS],
            lockouts: [LockoutEntry::empty(); MAX_LOCKOUT_ENTRIES],
            policy,
            audit: DiagAuditLog::new(),
            session_timeout_us,
            lockout_duration_us,
            hmac_key_id,
            recently_expired: [None; MAX_SESSIONS],
            active_sessions_mask: 0,
            nearest_expiry_us: u64::MAX,
            last_timestamp_us: 0,
            persist_entry_fn: None,
            persist_lockout_fn: None,
        }
    }

    /// Access the audit log.
    pub fn audit_log(&self) -> &DiagAuditLog {
        &self.audit
    }

    /// Session timeout duration in microseconds.
    pub fn session_timeout_us(&self) -> u64 {
        self.session_timeout_us
    }

    /// Lockout duration in microseconds.
    pub fn lockout_duration_us(&self) -> u64 {
        self.lockout_duration_us
    }

    /// Returns the last accepted timestamp for monotonicity verification.
    pub fn last_timestamp_us(&self) -> u64 {
        self.last_timestamp_us
    }

    /// Register persistence callbacks for audit entries and lockout state.
    ///
    /// When set, the gateway will invoke `persist_entry` for every audit log
    /// entry and `persist_lockout` whenever a tester's lockout state changes
    /// (failure recorded, lockout triggered, or lockout cleared). This allows
    /// non-volatile storage backends (flash, EEPROM) to be wired in without
    /// requiring a generic parameter on `DiagGateway`.
    ///
    /// # Arguments
    /// * `persist_entry`  - Called with each `AuditEntry` after it is recorded.
    /// * `persist_lockout` - Called with `(tester_address, fail_count, locked_until_us, lockout_generation)`.
    pub fn set_persistence_callbacks(
        &mut self,
        persist_entry: fn(&AuditEntry),
        persist_lockout: fn(u16, u8, u64, u8),
    ) {
        self.persist_entry_fn = Some(persist_entry);
        self.persist_lockout_fn = Some(persist_lockout);
    }

    /// Restore lockout state from persistent storage.
    ///
    /// Call this after construction to repopulate lockout entries that were
    /// persisted before an ECU reset. Each entry in `entries` that has
    /// `active == true` is copied into the gateway's lockout table.
    ///
    /// # Returns
    /// The number of entries actually restored (limited by `MAX_LOCKOUT_ENTRIES`).
    pub fn restore_lockouts_from(&mut self, entries: &[LockoutEntry]) -> usize {
        let mut restored = 0usize;
        for src in entries {
            if !src.active {
                continue;
            }
            if restored >= MAX_LOCKOUT_ENTRIES {
                break;
            }
            // Find a free slot or an existing entry for the same tester.
            let mut target_idx = None;
            for (i, slot) in self.lockouts.iter().enumerate() {
                if !slot.active {
                    target_idx = Some(i);
                    break;
                }
                if slot.tester_address == src.tester_address {
                    target_idx = Some(i);
                    break;
                }
            }
            if let Some(idx) = target_idx {
                self.lockouts[idx] = *src;
                restored += 1;
            }
        }
        restored
    }

    /// Proactively expire timed-out sessions without processing a UDS request.
    ///
    /// Call this from a periodic tick to free session slots occupied by idle
    /// testers, preventing slot exhaustion when no new UDS traffic arrives.
    pub fn expire_sessions_proactive(&mut self, ts_us: u64) {
        // Enforce timestamp monotonicity for proactive expiry.
        if ts_us < self.last_timestamp_us {
            // Log the timestamp regression for forensic purposes,
            // matching the blocking behavior of receive_uds_request.
            self.audit
                .record(0, 0, DECISION_BLOCK, self.last_timestamp_us);
            return;
        }
        self.last_timestamp_us = ts_us;
        self.expire_sessions(ts_us);
    }

    /// Process an incoming UDS request and return a decision.
    ///
    /// # Arguments
    /// * `tester_addr` - Source address of the diagnostic tester.
    /// * `sid`         - UDS Service Identifier.
    /// * `payload`     - Sub-function and data bytes following the SID.
    /// * `ts_us`       - Current timestamp in microseconds.
    pub fn receive_uds_request(
        &mut self,
        tester_addr: u16,
        sid: u8,
        payload: &[u8],
        ts_us: u64,
    ) -> DiagDecision {
        // Expire timed-out sessions first.
        self.expire_sessions(ts_us);

        // Enforce timestamp monotonicity: reject requests with timestamps
        // earlier than the last processed request. Non-monotonic timestamps
        // could allow attackers to bypass lockout durations by supplying a
        // timestamp in the past.
        if ts_us < self.last_timestamp_us {
            self.audit.record(tester_addr, sid, DECISION_BLOCK, ts_us);
            return DiagDecision::Block(BlockReason::PolicyDenied);
        }
        self.last_timestamp_us = ts_us;

        let decision = self.evaluate(tester_addr, sid, payload, ts_us);

        let code = match &decision {
            DiagDecision::Forward => DECISION_FORWARD,
            DiagDecision::Block(_) => DECISION_BLOCK,
            DiagDecision::Challenge(_) => DECISION_MONITOR,
        };
        self.audit.record(tester_addr, sid, code, ts_us);

        // Persist the audit entry to non-volatile storage if a callback is set.
        if let Some(persist_fn) = self.persist_entry_fn {
            if let Some(entry) = self.audit.latest() {
                persist_fn(entry);
            }
        }

        decision
    }

    // ---- internal evaluation ---------------------------------------------

    fn evaluate(&mut self, tester_addr: u16, sid: u8, payload: &[u8], ts_us: u64) -> DiagDecision {
        // Check lockout
        if self.is_locked_out(tester_addr, ts_us) {
            return DiagDecision::Block(BlockReason::LockedOut);
        }

        // Per-SID minimum-security-level pre-check. Applies to every SID
        // except SecurityAccess itself (which is the very mechanism by which
        // the level is raised) and the DiagnosticSessionControl service
        // (since transitioning to the default session intentionally drops
        // the level back to 0 — we evaluate that case below).
        if sid != SID_SECURITY_ACCESS && sid != SID_DIAGNOSTIC_SESSION_CONTROL {
            let required = self.policy.min_security_levels[sid as usize];
            if required > 0 {
                let current = self
                    .find_session(tester_addr)
                    .map_or(0, |i| self.sessions[i].security_level);
                if current < required {
                    return DiagDecision::Block(BlockReason::SecurityAccessDenied);
                }
            }
        }

        match sid {
            SID_SECURITY_ACCESS => self.handle_security_access(tester_addr, payload, ts_us),
            SID_DIAGNOSTIC_SESSION_CONTROL => {
                self.handle_session_control(tester_addr, payload, sid, ts_us)
            }
            // SIDs 0x31 (RoutineControl), 0x34 (RequestDownload), 0x36
            // (TransferData), and 0x37 (RequestTransferExit) are
            // unconditionally treated as auth-required, regardless of the
            // UdsPolicy configuration. These services can reflash firmware,
            // execute arbitrary routines, or exfiltrate data — allowing them
            // without authentication would be a critical security defect. The
            // UdsPolicy can further restrict other SIDs but cannot override
            // this built-in protection for high-risk services.
            SID_ROUTINE_CONTROL
            | SID_REQUEST_DOWNLOAD
            | SID_TRANSFER_DATA
            | SID_REQUEST_TRANSFER_EXIT => self.handle_auth_required_sid(tester_addr, ts_us),
            _ => self.handle_policy_sid(tester_addr, sid, ts_us),
        }
    }

    /// Handle a `DiagnosticSessionControl` (SID 0x10) request.
    ///
    /// Per ISO 14229, switching back to the default session (sub-function
    /// 0x01) MUST clear all `SecurityAccess` state for the session. The
    /// authenticated flag is reset, the security level drops to 0, and any
    /// pending seed challenge is discarded so a stale handshake cannot be
    /// completed against the new session.
    ///
    /// Policy enforcement is delegated to [`Self::handle_policy_sid`] —
    /// the session-state reset only runs after the policy returns
    /// [`DiagDecision::Forward`].
    fn handle_session_control(
        &mut self,
        tester_addr: u16,
        payload: &[u8],
        sid: u8,
        ts_us: u64,
    ) -> DiagDecision {
        let sub_fn = payload.first().copied().unwrap_or(0);

        // Run the same policy check as any other SID — if the policy denies
        // 0x10 the auth state must NOT be reset (an attacker could otherwise
        // use a denied request to clear a victim's level).
        let decision = self.handle_policy_sid(tester_addr, sid, ts_us);
        if decision != DiagDecision::Forward {
            return decision;
        }

        if let Some(idx) = self.find_session(tester_addr) {
            self.sessions[idx].session_type = sub_fn;
            if sub_fn == DSC_DEFAULT_SESSION {
                self.sessions[idx].authenticated = false;
                self.sessions[idx].security_level = 0;
                // Volatile-zeroize any pending seed to prevent its use after
                // the security context has been reset.
                if let Some(ref mut s) = self.sessions[idx].pending_seed {
                    #[allow(unsafe_code)]
                    for b in s.iter_mut() {
                        // SAFETY: `b` is a valid, aligned, dereferenceable
                        // pointer derived from a live mutable reference.
                        unsafe { core::ptr::write_volatile(b, 0) };
                    }
                }
                core::hint::black_box(self.sessions[idx].pending_seed.as_ref().map(|s| s.as_ptr()));
                self.sessions[idx].pending_seed = None;
            }
        }
        DiagDecision::Forward
    }

    // ---- SecurityAccess (SID 0x27) ---------------------------------------

    fn handle_security_access(
        &mut self,
        tester_addr: u16,
        payload: &[u8],
        ts_us: u64,
    ) -> DiagDecision {
        let Some(&sub_fn) = payload.first() else {
            return DiagDecision::Block(BlockReason::PolicyDenied);
        };

        // Reject sub-functions beyond the UDS-defined limit (0x42).
        if sub_fn == 0 || sub_fn > SA_MAX_SUB_FUNCTION {
            return DiagDecision::Block(BlockReason::PolicyDenied);
        }

        // Odd sub-functions (0x01, 0x03, ..., 0x41) are seed requests.
        // Even sub-functions (0x02, 0x04, ..., 0x42) are key sends.
        // The security level is derived as (sub_function + 1) / 2.
        if sub_fn % 2 == 1 {
            // Seed request -- security level = (sub_fn + 1) / 2
            let level = sub_fn.div_ceil(2);
            self.handle_seed_request(tester_addr, ts_us, level)
        } else {
            // Key send -- security level = sub_fn / 2
            let level = sub_fn / 2;
            self.handle_send_key(tester_addr, payload, ts_us, level)
        }
    }

    fn handle_seed_request(
        &mut self,
        tester_addr: u16,
        ts_us: u64,
        security_level: u8,
    ) -> DiagDecision {
        // Ensure the tester has a session (create one if capacity allows).
        let Some(session_idx) = self.get_or_create_session(tester_addr, ts_us) else {
            return DiagDecision::Block(BlockReason::SessionsFull);
        };

        // Rate-limit seed requests from the same tester.
        let last = self.sessions[session_idx].last_seed_request_us;
        if last > 0 && ts_us.saturating_sub(last) < MIN_SEED_INTERVAL_US {
            return DiagDecision::Block(BlockReason::PolicyDenied);
        }

        // Generate a random seed.
        let mut seed = [0u8; 16];
        if self.crypto.random_bytes(&mut seed).is_err() {
            return DiagDecision::Block(BlockReason::PolicyDenied);
        }

        // Store the seed and requested security level in the session.
        self.sessions[session_idx].pending_seed = Some(seed);
        self.sessions[session_idx].security_level = security_level;
        self.sessions[session_idx].last_activity_us = ts_us;
        self.sessions[session_idx].last_seed_request_us = ts_us;

        DiagDecision::Challenge(SecurityChallenge { seed })
    }

    fn handle_send_key(
        &mut self,
        tester_addr: u16,
        payload: &[u8],
        ts_us: u64,
        security_level: u8,
    ) -> DiagDecision {
        // Payload layout: [sub_fn(even), key_bytes(32)]
        if payload.len() < 33 {
            return DiagDecision::Block(BlockReason::Unauthorized);
        }

        let Some(session_idx) = self.find_session(tester_addr) else {
            return DiagDecision::Block(BlockReason::Unauthorized);
        };

        // Verify the security level matches the pending seed request.
        if self.sessions[session_idx].security_level != security_level {
            return DiagDecision::Block(BlockReason::Unauthorized);
        }

        let Some(seed) = self.sessions[session_idx].pending_seed else {
            return DiagDecision::Block(BlockReason::Unauthorized);
        };

        // Compute expected HMAC-SHA256(seed) using the crypto provider.
        let mut expected_mac = [0u8; 32];
        if self
            .crypto
            .hmac_sha256(self.hmac_key_id, &seed, &mut expected_mac)
            .is_err()
        {
            return DiagDecision::Block(BlockReason::PolicyDenied);
        }

        let provided_key = &payload[1..33];

        // Constant-time comparison (no short-circuit).
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= expected_mac[i] ^ provided_key[i];
        }
        // Prevent the compiler from optimizing away the constant-time
        // XOR accumulation loop above. Without this barrier, an aggressive
        // optimizer could short-circuit the comparison, leaking timing
        // information about which byte position differs first.
        let diff = core::hint::black_box(diff);

        // Zeroize expected_mac to prevent extraction from memory dumps.
        #[allow(unsafe_code)]
        for b in &mut expected_mac {
            // SAFETY: `b` is a valid, aligned, dereferenceable pointer
            // derived from a live mutable reference.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::hint::black_box(expected_mac.as_ptr());

        // Zeroize and clear the pending seed regardless of outcome
        // to prevent extraction from memory dumps.
        if let Some(ref mut s) = self.sessions[session_idx].pending_seed {
            // Use volatile writes to prevent the compiler from eliding
            // the zeroization. Plain writes followed by a drop can be
            // optimized away since the compiler sees the value is unused.
            // SAFETY: the pointer is derived from a valid mutable reference
            // and is properly aligned. The volatile write prevents elision.
            #[allow(unsafe_code)]
            for b in s.iter_mut() {
                // SAFETY: `b` is a valid, aligned, dereferenceable pointer
                // derived from a live mutable reference.
                unsafe { core::ptr::write_volatile(b, 0) };
            }
        }
        // Compiler barrier: prevent elision of the volatile writes above.
        core::hint::black_box(
            self.sessions[session_idx]
                .pending_seed
                .as_ref()
                .map(|s| s.as_ptr()),
        );
        self.sessions[session_idx].pending_seed = None;

        if diff == 0 {
            // Authentication succeeded.
            self.sessions[session_idx].authenticated = true;
            self.sessions[session_idx].security_level = security_level;
            self.sessions[session_idx].last_activity_us = ts_us;
            self.refresh_nearest_expiry();
            self.clear_lockout(tester_addr);
            DiagDecision::Forward
        } else {
            // Authentication failed -- track for lockout.
            self.record_failure(tester_addr, ts_us);
            DiagDecision::Block(BlockReason::Unauthorized)
        }
    }

    // ---- SIDs that always require authentication -------------------------

    fn handle_auth_required_sid(&mut self, tester_addr: u16, ts_us: u64) -> DiagDecision {
        match self.find_session(tester_addr) {
            Some(idx) if self.sessions[idx].authenticated => {
                self.sessions[idx].last_activity_us = ts_us;
                let expiry = self.compute_expiry(ts_us);
                if expiry < self.nearest_expiry_us {
                    self.nearest_expiry_us = expiry;
                }
                DiagDecision::Forward
            }
            _ => {
                if self.was_recently_expired(tester_addr) {
                    DiagDecision::Block(BlockReason::SessionExpired)
                } else {
                    DiagDecision::Block(BlockReason::Unauthorized)
                }
            }
        }
    }

    // ---- Policy-based SIDs -----------------------------------------------

    fn handle_policy_sid(&mut self, tester_addr: u16, sid: u8, ts_us: u64) -> DiagDecision {
        let sid_idx = sid as usize;

        // If the SID requires auth, verify the session is authenticated.
        if self.policy.require_auth_sids[sid_idx] {
            return self.handle_auth_required_sid(tester_addr, ts_us);
        }

        // If the SID is in the open allow-list, forward it.
        if self.policy.allowed_sids[sid_idx] {
            // Touch the session if one exists.
            if let Some(idx) = self.find_session(tester_addr) {
                self.sessions[idx].last_activity_us = ts_us;
                let expiry = self.compute_expiry(ts_us);
                if expiry < self.nearest_expiry_us {
                    self.nearest_expiry_us = expiry;
                }
            }
            return DiagDecision::Forward;
        }

        DiagDecision::Block(BlockReason::PolicyDenied)
    }

    // ---- Session management ----------------------------------------------

    fn find_session(&self, tester_addr: u16) -> Option<usize> {
        let mut mask = self.active_sessions_mask;
        while mask != 0 {
            let i = mask.trailing_zeros() as usize;
            if self.sessions[i].tester_address == tester_addr {
                return Some(i);
            }
            mask &= mask - 1; // clear lowest set bit
        }
        None
    }

    fn get_or_create_session(&mut self, tester_addr: u16, ts_us: u64) -> Option<usize> {
        // Return existing session if present.
        if let Some(idx) = self.find_session(tester_addr) {
            return Some(idx);
        }

        // Don't allocate sessions for locked-out testers.
        if self.is_locked_out(tester_addr, ts_us) {
            return None;
        }

        // Find a free slot using the inverted bitmask.
        let free_mask = !self.active_sessions_mask & ((1u8 << MAX_SESSIONS) - 1);
        if free_mask != 0 {
            let free = free_mask.trailing_zeros() as usize;
            self.sessions[free] = DiagSession {
                session_type: 0x01,
                tester_address: tester_addr,
                authenticated: false,
                security_level: 0,
                started_at: ts_us,
                last_activity_us: ts_us,
                active: true,
                pending_seed: None,
                // New sessions start with 0 so the tester can request a seed
                // immediately (the `last > 0` guard in handle_seed_request
                // skips rate-limiting on the very first request).
                last_seed_request_us: 0,
            };
            self.active_sessions_mask |= 1 << free;
            let expiry = self.compute_expiry(ts_us);
            if expiry < self.nearest_expiry_us {
                self.nearest_expiry_us = expiry;
            }
            return Some(free);
        }

        // No free slot — evict the oldest unauthenticated session that does
        // NOT have a pending seed (to prevent disrupting an in-progress
        // authentication handshake, which could be exploited as a timing attack).
        let mut oldest_idx: Option<usize> = None;
        let mut oldest_ts = u64::MAX;
        for (i, s) in self.sessions.iter().enumerate() {
            if s.active && !s.authenticated && s.pending_seed.is_none() && s.started_at < oldest_ts
            {
                oldest_ts = s.started_at;
                oldest_idx = Some(i);
            }
        }
        // If all unauthenticated sessions have pending seeds, fall back to
        // evicting the oldest unauthenticated session regardless.
        if oldest_idx.is_none() {
            for (i, s) in self.sessions.iter().enumerate() {
                if s.active && !s.authenticated && s.started_at < oldest_ts {
                    oldest_ts = s.started_at;
                    oldest_idx = Some(i);
                }
            }
        }

        let evict = oldest_idx?;

        // If the tester is evicting their OWN previous session (self-eviction),
        // preserve the old last_seed_request_us to prevent a rate-limit bypass
        // where the tester evicts its session to reset the seed request timer.
        // For other-tester evictions, the new session is genuinely fresh (no
        // prior seed requests from this tester) so last_seed_request_us = 0.
        let preserved_last_seed = if self.sessions[evict].tester_address == tester_addr {
            self.sessions[evict].last_seed_request_us
        } else {
            0
        };

        // Volatile-zeroize the pending seed from the evicted session to
        // prevent cryptographic material from lingering in memory. This
        // matches the zeroization pattern in handle_send_key.
        if let Some(ref mut s) = self.sessions[evict].pending_seed {
            #[allow(unsafe_code)]
            for b in s.iter_mut() {
                // SAFETY: `b` is a valid, aligned, dereferenceable pointer
                // derived from a live mutable reference.
                unsafe { core::ptr::write_volatile(b, 0) };
            }
        }
        core::hint::black_box(
            self.sessions[evict]
                .pending_seed
                .as_ref()
                .map(|s| s.as_ptr()),
        );

        self.sessions[evict] = DiagSession {
            session_type: 0x01,
            tester_address: tester_addr,
            authenticated: false,
            security_level: 0,
            started_at: ts_us,
            last_activity_us: ts_us,
            active: true,
            pending_seed: None,
            last_seed_request_us: preserved_last_seed,
        };
        // Slot was already active (eviction), so bitmask stays the same.
        let expiry = self.compute_expiry(ts_us);
        if expiry < self.nearest_expiry_us {
            self.nearest_expiry_us = expiry;
        }
        Some(evict)
    }

    fn expire_sessions(&mut self, ts_us: u64) {
        self.recently_expired = [None; MAX_SESSIONS];

        // Fast path: if no session can possibly be expired yet, skip the scan.
        if ts_us < self.nearest_expiry_us {
            return;
        }

        let mut expired_count = 0usize;
        let mut new_nearest = u64::MAX;
        for i in 0..MAX_SESSIONS {
            if (self.active_sessions_mask >> i) & 1 == 0 {
                continue;
            }
            let last_activity = self.sessions[i].last_activity_us;
            let expiry = last_activity
                .saturating_add(self.session_timeout_us)
                .saturating_add(1);
            if ts_us >= expiry {
                if expired_count < MAX_SESSIONS {
                    self.recently_expired[expired_count] = Some(self.sessions[i].tester_address);
                    expired_count += 1;
                }
                self.sessions[i] = DiagSession::empty();
                self.active_sessions_mask &= !(1 << i);
            } else if expiry < new_nearest {
                new_nearest = expiry;
            }
        }
        self.nearest_expiry_us = new_nearest;
    }

    /// Recompute `nearest_expiry_us` from all active sessions.
    fn refresh_nearest_expiry(&mut self) {
        let mut nearest = u64::MAX;
        let mut mask = self.active_sessions_mask;
        while mask != 0 {
            let i = mask.trailing_zeros() as usize;
            let expiry = self.compute_expiry(self.sessions[i].last_activity_us);
            if expiry < nearest {
                nearest = expiry;
            }
            mask &= mask - 1;
        }
        self.nearest_expiry_us = nearest;
    }

    fn was_recently_expired(&self, tester_addr: u16) -> bool {
        for slot in &self.recently_expired {
            if *slot == Some(tester_addr) {
                return true;
            }
        }
        false
    }

    /// Compute the absolute expiry timestamp for a session whose last
    /// activity was at `last_activity_us`. Uses `saturating_add` to avoid
    /// overflow. The `+1` converts the `>` semantics (expire when
    /// `now > last_activity + timeout`) to `>=` semantics for the fast-path
    /// comparison.
    fn compute_expiry(&self, last_activity_us: u64) -> u64 {
        last_activity_us
            .saturating_add(self.session_timeout_us)
            .saturating_add(1)
    }

    /// Set the UDS session type for an existing session identified by
    /// `tester_addr`. Session types: 0x01 = default, 0x02 = programming,
    /// 0x03 = extended diagnostic.
    ///
    /// Returns `true` if the session was found and updated, `false` otherwise.
    pub fn set_session_type(&mut self, tester_addr: u16, session_type: u8, ts_us: u64) -> bool {
        if let Some(idx) = self.find_session(tester_addr) {
            self.sessions[idx].session_type = session_type;
            self.sessions[idx].last_activity_us = ts_us;
            let expiry = self.compute_expiry(ts_us);
            if expiry < self.nearest_expiry_us {
                self.nearest_expiry_us = expiry;
            }
            true
        } else {
            false
        }
    }

    // ---- Lockout management ----------------------------------------------

    fn is_locked_out(&self, tester_addr: u16, ts_us: u64) -> bool {
        for entry in &self.lockouts {
            if entry.active
                && entry.tester_address == tester_addr
                && entry.fail_count >= LOCKOUT_THRESHOLD
                && ts_us < entry.locked_until_us
            {
                return true;
            }
        }
        false
    }

    fn record_failure(&mut self, tester_addr: u16, ts_us: u64) {
        // Find existing entry.
        for entry in &mut self.lockouts {
            if entry.active && entry.tester_address == tester_addr {
                // If a previous lockout has expired, reset the counter so the
                // tester gets a fresh set of attempts.
                if entry.fail_count >= LOCKOUT_THRESHOLD && ts_us >= entry.locked_until_us {
                    entry.fail_count = 0;
                }
                entry.fail_count = entry.fail_count.saturating_add(1);
                if entry.fail_count >= LOCKOUT_THRESHOLD {
                    // Exponential backoff: each successive lockout doubles
                    // the duration, capped at 8x (generation 3).
                    let multiplier = 1u64 << entry.lockout_generation.min(3);
                    let duration = self.lockout_duration_us.saturating_mul(multiplier);
                    entry.locked_until_us = ts_us.saturating_add(duration);
                    entry.lockout_generation = entry.lockout_generation.saturating_add(1);
                }
                if let Some(persist_fn) = self.persist_lockout_fn {
                    persist_fn(
                        entry.tester_address,
                        entry.fail_count,
                        entry.locked_until_us,
                        entry.lockout_generation,
                    );
                }
                return;
            }
        }
        // Allocate new entry in a free slot.
        for entry in &mut self.lockouts {
            if !entry.active {
                *entry = LockoutEntry {
                    tester_address: tester_addr,
                    fail_count: 1,
                    locked_until_us: 0,
                    lockout_generation: 0,
                    active: true,
                };
                if let Some(persist_fn) = self.persist_lockout_fn {
                    persist_fn(
                        entry.tester_address,
                        entry.fail_count,
                        entry.locked_until_us,
                        entry.lockout_generation,
                    );
                }
                return;
            }
        }
        // All slots full — evict using a priority scheme that protects
        // high-fail entries from displacement by low-fail flooding:
        //
        // 1. First try expired lockout entries (lockout has elapsed).
        // 2. Among non-expired entries, only evict entries whose fail_count
        //    is below the lockout threshold. This reserves slots for entries
        //    that have reached lockout, ensuring an attacker cannot flood
        //    slots with single-failure addresses to prevent tracking of
        //    real brute-force attacks.
        // 3. If all non-expired entries have reached the lockout threshold,
        //    evict the one with the oldest lockout expiry (closest to expiring).
        let mut evict_idx: Option<usize> = None;
        let mut evict_priority = u64::MAX; // lower = better candidate
        let mut evict_fail_count = u8::MAX;

        for (i, entry) in self.lockouts.iter().enumerate() {
            if !entry.active {
                continue;
            }
            // Expired lockout entries are always preferred for eviction.
            if ts_us >= entry.locked_until_us && entry.fail_count >= LOCKOUT_THRESHOLD {
                if entry.locked_until_us < evict_priority {
                    evict_priority = entry.locked_until_us;
                    evict_fail_count = 0; // expired = best candidate
                    evict_idx = Some(i);
                }
            } else if evict_fail_count > 0 && entry.fail_count < LOCKOUT_THRESHOLD {
                // Only evict entries that have NOT reached lockout threshold.
                // This protects active lockout entries from being displaced.
                if entry.fail_count < evict_fail_count
                    || (entry.fail_count == evict_fail_count
                        && entry.locked_until_us < evict_priority)
                {
                    evict_fail_count = entry.fail_count;
                    evict_priority = entry.locked_until_us;
                    evict_idx = Some(i);
                }
            }
        }

        // Last resort: if all entries are at or above lockout threshold and
        // none are expired, evict the entry closest to expiring.
        if evict_idx.is_none() {
            let mut closest_expiry = u64::MAX;
            for (i, entry) in self.lockouts.iter().enumerate() {
                if entry.active && entry.locked_until_us < closest_expiry {
                    closest_expiry = entry.locked_until_us;
                    evict_idx = Some(i);
                }
            }
        }

        if let Some(idx) = evict_idx {
            self.lockouts[idx] = LockoutEntry {
                tester_address: tester_addr,
                fail_count: 1,
                locked_until_us: 0,
                lockout_generation: 0,
                active: true,
            };
            if let Some(persist_fn) = self.persist_lockout_fn {
                persist_fn(tester_addr, 1, 0, 0);
            }
        }
    }

    fn clear_lockout(&mut self, tester_addr: u16) {
        for entry in &mut self.lockouts {
            if entry.active && entry.tester_address == tester_addr {
                // Successful authentication resets all failure tracking so
                // subsequent lockout cycles use the base duration again.
                entry.fail_count = 0;
                entry.locked_until_us = 0;
                entry.lockout_generation = 0;
                if let Some(persist_fn) = self.persist_lockout_fn {
                    persist_fn(
                        entry.tester_address,
                        entry.fail_count,
                        entry.locked_until_us,
                        entry.lockout_generation,
                    );
                }
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use vs_crypto::SoftwareCryptoProvider;

    /// Deterministic RNG for tests.
    fn test_rng(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x42);
        }
    }

    /// Build a `SoftwareCryptoProvider` with key 0 provisioned.
    fn make_crypto() -> SoftwareCryptoProvider {
        let mut cp = SoftwareCryptoProvider::new(test_rng);
        cp.set_key(KeyId(0), &[0xAA; 32]).expect("set key");
        cp
    }

    /// Build a gateway with a permissive-enough policy for testing.
    fn make_gateway() -> DiagGateway<SoftwareCryptoProvider> {
        let mut policy = UdsPolicy::new();
        // Allow SID 0x10 (DiagnosticSessionControl) without auth.
        policy.allow_sid(0x10);
        // SID 0x22 (ReadDataByIdentifier) requires auth via policy.
        policy.require_auth_for_sid(0x22);

        DiagGateway::new(
            make_crypto(),
            policy,
            5_000_000,  // 5 s timeout
            10_000_000, // 10 s lockout
            KeyId(0),   // HMAC key_id
        )
    }

    /// Helper: perform a full `SecurityAccess` seed/key exchange and return
    /// whether authentication succeeded.
    fn authenticate(
        gw: &mut DiagGateway<SoftwareCryptoProvider>,
        tester_addr: u16,
        ts_us: u64,
    ) -> bool {
        // Step 1: request seed
        let decision =
            gw.receive_uds_request(tester_addr, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], ts_us);

        let seed = match decision {
            DiagDecision::Challenge(c) => c.seed,
            _ => return false,
        };

        // Step 2: compute correct key = HMAC-SHA256(key, seed)
        let mut key = [0u8; 32];
        gw.crypto
            .hmac_sha256(gw.hmac_key_id, &seed, &mut key)
            .expect("hmac");

        // Step 3: send key (payload = [sub_fn, key...])
        let mut payload = [0u8; 33];
        payload[0] = SA_SEND_KEY;
        payload[1..33].copy_from_slice(&key);

        let decision =
            gw.receive_uds_request(tester_addr, SID_SECURITY_ACCESS, &payload, ts_us + 1);

        decision == DiagDecision::Forward
    }

    /// Helper: send a bad `SecurityAccess` key.
    fn send_bad_key(
        gw: &mut DiagGateway<SoftwareCryptoProvider>,
        tester_addr: u16,
        ts_us: u64,
    ) -> DiagDecision {
        // Request seed
        let decision =
            gw.receive_uds_request(tester_addr, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], ts_us);
        assert!(
            matches!(decision, DiagDecision::Challenge(_)),
            "expected challenge"
        );

        // Send wrong key
        let mut payload = [0u8; 33];
        payload[0] = SA_SEND_KEY;
        payload[1..33].copy_from_slice(&[0xFF; 32]); // wrong key

        gw.receive_uds_request(tester_addr, SID_SECURITY_ACCESS, &payload, ts_us + 1)
    }

    // ---- Test cases -------------------------------------------------------

    #[test]
    fn authorized_sid_passes_after_authentication() {
        let mut gw = make_gateway();
        let tester = 0x0F01;

        // SID 0x31 should be blocked before auth.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Authenticate.
        assert!(authenticate(&mut gw, tester, 2000));

        // Now SID 0x31 should pass.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 3000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn unauthorized_sid_returns_block() {
        let mut gw = make_gateway();
        // SID 0x99 is not in any allow-list.
        let d = gw.receive_uds_request(0x0F01, 0x99, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::PolicyDenied));
    }

    #[test]
    fn third_failed_security_access_triggers_lockout() {
        let mut gw = make_gateway();
        let tester = 0x0F02;

        // Fail #1
        let d = send_bad_key(&mut gw, tester, 1_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Fail #2
        let d = send_bad_key(&mut gw, tester, 2_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Fail #3 -- triggers lockout
        let d = send_bad_key(&mut gw, tester, 3_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Subsequent request should be LockedOut.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 4_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));
    }

    #[test]
    fn session_timeout_terminates_idle_session() {
        let mut gw = make_gateway();
        let tester = 0x0F03;

        // Authenticate at t=1000
        assert!(authenticate(&mut gw, tester, 1000));

        // Confirm session works at t=2000
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 2000);
        assert_eq!(d, DiagDecision::Forward);

        // Jump forward past timeout (> 5_000_000 us).
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 10_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::SessionExpired));
    }

    #[test]
    fn audit_log_records_entries() {
        let mut gw = make_gateway();

        // Allowed SID
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 1000);
        assert_eq!(gw.audit_log().len(), 1);

        // Blocked SID
        let _ = gw.receive_uds_request(0x0F01, 0x99, &[], 2000);
        assert_eq!(gw.audit_log().len(), 2);

        // Verify latest entry
        let latest = gw.audit_log().latest().expect("entry");
        assert_eq!(latest.tester_addr, 0x0F01);
        assert_eq!(latest.sid, 0x99);
        assert_eq!(latest.decision_code, DECISION_BLOCK);
        assert_eq!(latest.timestamp, 2000);
        assert_eq!(latest.sequence, 2);
    }

    #[test]
    fn sid_0x31_blocked_without_auth_allowed_with_auth() {
        let mut gw = make_gateway();
        let tester = 0x0F04;

        // Blocked without auth.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Authenticate.
        assert!(authenticate(&mut gw, tester, 2000));

        // Allowed with auth.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 3000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn session_capacity_fifth_unauthenticated_evicts_oldest() {
        let mut gw = make_gateway();

        // Create 4 unauthenticated sessions (MAX_SESSIONS).
        for i in 0..4u16 {
            let tester = 0x0F00 + i;
            let d = gw.receive_uds_request(
                tester,
                SID_SECURITY_ACCESS,
                &[SA_REQUEST_SEED],
                (i as u64 + 1) * 1000,
            );
            assert!(
                matches!(d, DiagDecision::Challenge(_)),
                "session {i} should get a challenge"
            );
        }

        // 5th session should evict the oldest unauthenticated session (0x0F00).
        let d = gw.receive_uds_request(
            0x0F10,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            200_000, // well past rate limit
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "5th tester should evict oldest unauthenticated session"
        );
    }

    #[test]
    fn session_capacity_rejects_when_all_authenticated() {
        let mut gw = make_gateway();

        // Create 4 authenticated sessions (MAX_SESSIONS).
        // Use timestamps close together so none expire before the 5th attempt.
        for i in 0..4u16 {
            let tester = 0x0F00 + i;
            assert!(
                authenticate(&mut gw, tester, 1_000_000 + (i as u64) * 200_000),
                "tester {tester:#06X} should authenticate"
            );
        }

        // 5th session should be rejected (all sessions authenticated, no eviction).
        // Use timestamp within session_timeout_us of all sessions.
        let d = gw.receive_uds_request(0x0F10, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 2_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::SessionsFull));
    }

    #[test]
    fn download_sids_blocked_without_auth() {
        let mut gw = make_gateway();
        let tester = 0x0F05;

        for &sid in &[
            SID_REQUEST_DOWNLOAD,
            SID_TRANSFER_DATA,
            SID_REQUEST_TRANSFER_EXIT,
        ] {
            let d = gw.receive_uds_request(tester, sid, &[], 1000);
            assert_eq!(
                d,
                DiagDecision::Block(BlockReason::Unauthorized),
                "SID 0x{sid:02X} should be blocked without auth"
            );
        }
    }

    #[test]
    fn policy_allowed_sid_forwards_without_auth() {
        let mut gw = make_gateway();
        // SID 0x10 is in the open allow-list.
        let d = gw.receive_uds_request(0x0F01, 0x10, &[], 1000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn policy_require_auth_sid_blocked_then_allowed() {
        let mut gw = make_gateway();
        let tester = 0x0F06;

        // SID 0x22 requires auth via policy.
        let d = gw.receive_uds_request(tester, 0x22, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));

        // Authenticate.
        assert!(authenticate(&mut gw, tester, 2000));

        // Now allowed.
        let d = gw.receive_uds_request(tester, 0x22, &[], 3000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn lockout_expires_after_duration() {
        let mut gw = make_gateway();
        let tester = 0x0F07;

        // Trigger lockout (3 failures).
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester, (i + 1) * 1_000_000);
        }

        // Locked out at t=4_000_000.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 4_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // After lockout duration (10_000_000), should be able to try again.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 20_000_000);
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "lockout should have expired"
        );
    }

    #[test]
    fn audit_log_ring_buffer_wraps() {
        let mut log = DiagAuditLog::new();

        // Fill beyond capacity.
        for i in 0..600u64 {
            log.record(0x01, 0x10, 0, i);
        }

        // Should cap at capacity.
        assert_eq!(log.len(), AUDIT_LOG_CAPACITY);

        // Latest should be the last one recorded.
        let latest = log.latest().expect("entry");
        assert_eq!(latest.sequence, 600);
        assert_eq!(latest.timestamp, 599);
    }

    // ---- New tests below ----

    #[test]
    fn sid_0x34_blocked_without_auth() {
        let mut gw = make_gateway();
        let tester = 0x0F10;
        let d = gw.receive_uds_request(tester, SID_REQUEST_DOWNLOAD, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn sid_0x36_blocked_without_auth() {
        let mut gw = make_gateway();
        let tester = 0x0F11;
        let d = gw.receive_uds_request(tester, SID_TRANSFER_DATA, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn sid_0x37_blocked_without_auth() {
        let mut gw = make_gateway();
        let tester = 0x0F12;
        let d = gw.receive_uds_request(tester, SID_REQUEST_TRANSFER_EXIT, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn security_access_wrong_sub_function_blocked() {
        let mut gw = make_gateway();
        let tester = 0x0F13;

        // Sub-function 0x00 is invalid (below the valid range).
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[0x00], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::PolicyDenied));

        // Sub-function 0x43 exceeds the UDS limit (SA_MAX_SUB_FUNCTION = 0x42).
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[0x43], 2000);
        assert_eq!(d, DiagDecision::Block(BlockReason::PolicyDenied));
    }

    #[test]
    fn security_access_multi_level_sub_functions() {
        let mut gw = make_gateway();
        let tester = 0x0F14;

        // Sub-function 0x03 is a valid seed request for security level 2.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[0x03], 1_000_000);
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "sub-function 0x03 should return a challenge"
        );
    }

    #[test]
    fn two_testers_authenticate_independently() {
        let mut gw = make_gateway();
        let tester_a = 0x0F20;
        let tester_b = 0x0F21;

        // Authenticate tester A.
        assert!(authenticate(&mut gw, tester_a, 1000));
        // Authenticate tester B.
        assert!(authenticate(&mut gw, tester_b, 2000));

        // Both should be able to use auth-required SIDs.
        let d = gw.receive_uds_request(tester_a, SID_ROUTINE_CONTROL, &[], 3000);
        assert_eq!(d, DiagDecision::Forward);

        let d = gw.receive_uds_request(tester_b, SID_ROUTINE_CONTROL, &[], 4000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn session_reuse_same_tester_gets_same_session() {
        let mut gw = make_gateway();
        let tester = 0x0F22;

        // First seed request creates a session.
        let d1 = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_000_000);
        assert!(matches!(d1, DiagDecision::Challenge(_)));

        // Second seed request from the same tester reuses the session.
        let d2 = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            1_200_000, // past rate limit interval
        );
        assert!(matches!(d2, DiagDecision::Challenge(_)));

        // A different tester can still get a session (not blocked).
        let d3 = gw.receive_uds_request(0x0F23, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_400_000);
        assert!(matches!(d3, DiagDecision::Challenge(_)));
    }

    #[test]
    fn audit_log_sequence_numbers_are_monotonic() {
        let mut gw = make_gateway();

        // Generate several audit entries.
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 1000);
        let _ = gw.receive_uds_request(0x0F01, 0x99, &[], 2000);
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 3000);
        let _ = gw.receive_uds_request(0x0F01, 0x22, &[], 4000);
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 5000);

        let log = gw.audit_log();
        assert_eq!(log.len(), 5);

        // Verify sequence numbers are strictly increasing.
        for i in 0..log.len() - 1 {
            let current = log.get(i).expect("entry");
            let next = log.get(i + 1).expect("next entry");
            assert!(
                next.sequence > current.sequence,
                "seq {} should be > seq {}",
                next.sequence,
                current.sequence
            );
        }
    }

    #[test]
    fn lockout_on_one_tester_does_not_affect_another() {
        let mut gw = make_gateway();
        let tester_locked = 0x0F30;
        let tester_ok = 0x0F31;

        // Trigger lockout on tester_locked (3 failures).
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester_locked, (i + 1) * 1_000_000);
        }

        // tester_locked is now locked out.
        let d = gw.receive_uds_request(
            tester_locked,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            5_000_000,
        );
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // tester_ok should still be able to request a seed.
        let d = gw.receive_uds_request(
            tester_ok,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            6_000_000,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "tester_ok should not be affected by tester_locked's lockout"
        );
    }

    #[test]
    fn policy_require_auth_takes_precedence_over_allowed() {
        // If a SID is in both allowed and require_auth lists, require_auth
        // should take precedence.
        let mut policy = UdsPolicy::new();
        policy.allow_sid(0x3E); // TesterPresent
        policy.require_auth_for_sid(0x3E); // Also require auth

        let gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));

        // Without authentication, the SID should be blocked (require_auth wins).
        let mut gw = gw;
        let d = gw.receive_uds_request(0x0F40, 0x3E, &[], 1000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn session_timeout_boundary_request_at_exactly_timeout() {
        let mut gw = make_gateway();
        let tester = 0x0F50;

        // Authenticate at t=0.
        assert!(authenticate(&mut gw, tester, 0));

        // The session's last_activity_us = 1 (from authenticate helper which
        // sends the key at ts+1).
        // session_timeout_us = 5_000_000.
        // expire_sessions checks: ts - last_activity > timeout
        // At exactly timeout: 5_000_001 - 1 = 5_000_000, which is NOT > 5_000_000.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 5_000_001);
        assert_eq!(d, DiagDecision::Forward);

        // The previous request at 5_000_001 refreshed last_activity_us.
        // To trigger a timeout we need a fresh session without the refresh.
        let mut gw2 = make_gateway();
        let tester2 = 0x0F51;
        assert!(authenticate(&mut gw2, tester2, 0));
        // At one microsecond past boundary: 5_000_002 - 1 = 5_000_001 > 5_000_000.
        let d = gw2.receive_uds_request(tester2, SID_ROUTINE_CONTROL, &[], 5_000_002);
        assert_eq!(d, DiagDecision::Block(BlockReason::SessionExpired));
    }

    #[test]
    fn max_sessions_with_different_tester_addresses() {
        let mut gw = make_gateway();

        // Create MAX_SESSIONS (4) sessions with different testers.
        for i in 0..4u16 {
            let tester = 0x0F60 + i;
            assert!(
                authenticate(&mut gw, tester, (i as u64 + 1) * 1000),
                "tester {tester:#06X} should authenticate"
            );
        }

        // All 4 testers should be authenticated and able to use auth-required SIDs.
        for i in 0..4u16 {
            let tester = 0x0F60 + i;
            let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 50_000);
            assert_eq!(
                d,
                DiagDecision::Forward,
                "tester {tester:#06X} should be forwarded"
            );
        }
    }

    #[test]
    fn security_access_sub_fn_0x01_always_returns_challenge() {
        let mut gw = make_gateway();
        let tester = 0x0F70;

        // First seed request.
        let d1 = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_000_000);
        assert!(
            matches!(d1, DiagDecision::Challenge(_)),
            "first seed request should return Challenge"
        );

        // Second seed request from same tester (past rate limit).
        let d2 = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_200_000);
        assert!(
            matches!(d2, DiagDecision::Challenge(_)),
            "second seed request should also return Challenge"
        );

        // Third seed request from different tester.
        let d3 = gw.receive_uds_request(0x0F71, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_400_000);
        assert!(
            matches!(d3, DiagDecision::Challenge(_)),
            "seed request from new tester should return Challenge"
        );
    }

    #[test]
    fn audit_log_latest_on_empty_returns_none() {
        let log = DiagAuditLog::new();
        assert!(log.latest().is_none());
        assert!(log.is_empty());
    }

    #[test]
    fn audit_log_get_out_of_bounds_returns_none() {
        let mut log = DiagAuditLog::new();
        log.record(0x100, 0x10, 0, 1000);
        assert!(log.get(0).is_some());
        assert!(log.get(1).is_none());
        assert!(log.get(999).is_none());
    }

    #[test]
    fn uds_policy_require_auth_clears_allow() {
        let mut policy = UdsPolicy::new();
        policy.allow_sid(0x22);
        assert!(policy.allowed_sids[0x22]);
        // Switching to require_auth should clear the allow flag —
        // a SID cannot be both open and auth-required.
        policy.require_auth_for_sid(0x22);
        assert!(!policy.allowed_sids[0x22]);
        assert!(policy.require_auth_sids[0x22]);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn uds_policy_default_denies_all() {
        let policy = UdsPolicy::default();
        for i in 0..=255u8 {
            assert!(!policy.allowed_sids[i as usize]);
            assert!(!policy.require_auth_sids[i as usize]);
        }
    }

    #[test]
    fn block_reason_variants_are_distinct() {
        let reasons = [
            BlockReason::Unauthorized,
            BlockReason::LockedOut,
            BlockReason::SessionExpired,
            BlockReason::PolicyDenied,
            BlockReason::SessionsFull,
            BlockReason::SecurityAccessDenied,
        ];
        for i in 0..reasons.len() {
            for j in i + 1..reasons.len() {
                assert_ne!(reasons[i], reasons[j]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Per-SID minimum security level + default-session reset tests
    // -----------------------------------------------------------------------

    #[test]
    fn block_reason_security_access_denied_maps_to_nrc_0x33() {
        assert_eq!(BlockReason::SecurityAccessDenied.nrc(), 0x33);
        // The Unauthorized variant — caused by missing SecurityAccess entirely
        // — also maps to NRC 0x33 per ISO 14229.
        assert_eq!(BlockReason::Unauthorized.nrc(), 0x33);
        // Locked-out testers map to 0x37 (requiredTimeDelayNotExpired).
        assert_eq!(BlockReason::LockedOut.nrc(), 0x37);
    }

    #[test]
    fn per_sid_min_level_blocks_request_below_threshold() {
        // SID 0x22 (ReadDataByIdentifier) configured to require security level 2.
        // After SecurityAccess sub-function 0x01 the session is at level 1,
        // so a 0x22 request must be rejected with SecurityAccessDenied (NRC 0x33).
        let mut policy = UdsPolicy::new();
        policy.allow_sid(0x22);
        policy.set_min_security_level(0x22, 2);

        let mut gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));
        let tester = 0x0F80;

        // Authenticate at level 1 (sub-function 0x01).
        assert!(authenticate(&mut gw, tester, 1_000));

        let d = gw.receive_uds_request(tester, 0x22, &[], 2_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::SecurityAccessDenied));
        // The block reason must map to UDS NRC 0x33.
        if let DiagDecision::Block(r) = d {
            assert_eq!(r.nrc(), 0x33);
        } else {
            panic!("expected Block, got {d:?}");
        }
    }

    #[test]
    fn per_sid_min_level_allows_request_at_or_above_threshold() {
        // Same configuration as the previous test, but authenticate at the
        // exact level required (level 2 via sub-function 0x03) and verify the
        // request is forwarded.
        let mut policy = UdsPolicy::new();
        policy.allow_sid(0x22);
        policy.set_min_security_level(0x22, 2);

        let mut gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));
        let tester = 0x0F81;

        // Seed request for level 2 (sub-function 0x03).
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[0x03], 1_000_000);
        let seed = match d {
            DiagDecision::Challenge(c) => c.seed,
            other => panic!("expected Challenge, got {other:?}"),
        };

        // Compute the expected key and send sub-function 0x04.
        let mut key = [0u8; 32];
        gw.crypto
            .hmac_sha256(gw.hmac_key_id, &seed, &mut key)
            .expect("hmac");
        let mut payload = [0u8; 33];
        payload[0] = 0x04;
        payload[1..33].copy_from_slice(&key);
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &payload, 1_000_001);
        assert_eq!(d, DiagDecision::Forward);

        // 0x22 with min_security_level=2 should now be forwarded.
        let d = gw.receive_uds_request(tester, 0x22, &[], 2_000_000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn per_sid_min_level_default_zero_does_not_block_unauthenticated_open_sid() {
        // A SID with no minimum (default 0) and `allow_sid` should remain
        // forwardable without authentication.
        let mut policy = UdsPolicy::new();
        policy.allow_sid(0x10);
        let mut gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));
        let d = gw.receive_uds_request(0x0F90, 0x10, &[], 1_000);
        assert_eq!(d, DiagDecision::Forward);
    }

    #[test]
    fn default_session_transition_clears_security_state() {
        // After authenticating, transitioning back to the default session
        // (DSC sub-function 0x01) MUST drop the security level back to 0
        // and clear the authenticated flag, even though the session itself
        // remains alive.
        let mut policy = UdsPolicy::new();
        policy.allow_sid(SID_DIAGNOSTIC_SESSION_CONTROL);
        let mut gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));
        let tester = 0x0FA0;

        // Authenticate at level 1.
        assert!(authenticate(&mut gw, tester, 1_000));

        // Confirm authenticated.
        let idx = gw.find_session(tester).expect("session exists");
        assert!(gw.sessions[idx].authenticated);
        assert_eq!(gw.sessions[idx].security_level, 1);

        // Transition to default session — should reset auth state.
        let d = gw.receive_uds_request(
            tester,
            SID_DIAGNOSTIC_SESSION_CONTROL,
            &[DSC_DEFAULT_SESSION],
            2_000,
        );
        assert_eq!(d, DiagDecision::Forward);

        let idx = gw.find_session(tester).expect("session still alive");
        assert!(
            !gw.sessions[idx].authenticated,
            "auth flag must be cleared on default-session transition"
        );
        assert_eq!(
            gw.sessions[idx].security_level, 0,
            "security level must reset to 0 on default-session transition"
        );
        assert!(
            gw.sessions[idx].pending_seed.is_none(),
            "pending seed must be discarded on default-session transition"
        );

        // Subsequent auth-required SID should now be Unauthorized.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 3_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn extended_session_transition_preserves_security_state() {
        // Switching to a non-default session (e.g. extended diagnostic = 0x03)
        // must NOT clear authentication — only the default session reset does.
        let mut policy = UdsPolicy::new();
        policy.allow_sid(SID_DIAGNOSTIC_SESSION_CONTROL);
        let mut gw = DiagGateway::new(make_crypto(), policy, 5_000_000, 10_000_000, KeyId(0));
        let tester = 0x0FA1;

        assert!(authenticate(&mut gw, tester, 1_000));

        let d = gw.receive_uds_request(
            tester,
            SID_DIAGNOSTIC_SESSION_CONTROL,
            &[0x03], // extended diagnostic session
            2_000,
        );
        assert_eq!(d, DiagDecision::Forward);

        let idx = gw.find_session(tester).expect("session still alive");
        assert!(
            gw.sessions[idx].authenticated,
            "auth flag must be preserved on non-default session transition"
        );
        assert_eq!(gw.sessions[idx].security_level, 1);
        assert_eq!(gw.sessions[idx].session_type, 0x03);
    }

    #[test]
    fn audit_log_latest_returns_most_recent() {
        let mut log = DiagAuditLog::new();
        log.record(0x100, 0x10, 0, 1000);
        log.record(0x200, 0x22, 1, 2000);
        log.record(0x300, 0x31, 2, 3000);
        let latest = log.latest().unwrap();
        assert_eq!(latest.tester_addr, 0x300);
        assert_eq!(latest.sid, 0x31);
        assert_eq!(latest.timestamp, 3000);
    }

    // -----------------------------------------------------------------------
    // Security property assertion tests
    // -----------------------------------------------------------------------

    #[test]
    fn security_lockout_engages_after_exactly_threshold_failures() {
        let mut gw = make_gateway();
        let tester_addr = 0x100;

        // Exactly LOCKOUT_THRESHOLD (3) bad keys should trigger lockout.
        for attempt in 0..LOCKOUT_THRESHOLD {
            let ts = (attempt as u64 + 1) * 1_000_000;
            let decision = send_bad_key(&mut gw, tester_addr, ts);
            // Before the final attempt, should get Block(Unauthorized).
            if attempt < LOCKOUT_THRESHOLD - 1 {
                assert_eq!(
                    decision,
                    DiagDecision::Block(BlockReason::Unauthorized),
                    "attempt {attempt}"
                );
            }
        }

        // Next request from same tester should be locked out.
        let decision = gw.receive_uds_request(
            tester_addr,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            (LOCKOUT_THRESHOLD as u64 + 1) * 1_000_000,
        );
        assert_eq!(decision, DiagDecision::Block(BlockReason::LockedOut));
    }

    #[test]
    fn security_lockout_duration_enforced() {
        let mut gw = make_gateway();
        let tester_addr = 0x200;

        // Trigger lockout.
        for i in 0..LOCKOUT_THRESHOLD {
            let _ = send_bad_key(&mut gw, tester_addr, (i as u64 + 1) * 1_000_000);
        }

        // Lockout was set at the 3rd failure (ts=3_000_000), so
        // locked_until_us = 3_000_000 + 10_000_000 = 13_000_000.
        // During lockout period, requests rejected.
        let mid_lockout = 8_000_000;
        let decision = gw.receive_uds_request(
            tester_addr,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            mid_lockout,
        );
        assert_eq!(decision, DiagDecision::Block(BlockReason::LockedOut));

        // After lockout expires (> 13_000_000), should work again.
        let after_lockout = 14_000_000;
        let decision = gw.receive_uds_request(
            tester_addr,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            after_lockout,
        );
        assert!(
            matches!(decision, DiagDecision::Challenge(_)),
            "lockout should have expired, got {decision:?}"
        );
    }

    #[test]
    fn security_seed_is_populated_from_rng() {
        let mut gw = make_gateway();

        let d1 = gw.receive_uds_request(0x100, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 0);
        let seed = match d1 {
            DiagDecision::Challenge(c) => c.seed,
            other => panic!("expected Challenge, got {other:?}"),
        };

        // Seed should be populated (non-zero), drawn from the RNG.
        assert!(
            seed.iter().any(|&b| b != 0),
            "seed must be populated from RNG, not all zeros"
        );
        assert_eq!(seed.len(), 16, "seed must be 16 bytes");
    }

    #[test]
    fn security_audit_log_records_failed_auth() {
        let mut gw = make_gateway();
        let _ = send_bad_key(&mut gw, 0x300, 5000);

        let latest = gw.audit.latest().expect("audit entry");
        assert_eq!(latest.tester_addr, 0x300);
        assert_eq!(latest.sid, SID_SECURITY_ACCESS);
    }

    #[test]
    fn security_session_timeout_enforced() {
        let mut gw = make_gateway();
        let tester_addr = 0x400;

        // Authenticate at time 0.
        assert!(authenticate(&mut gw, tester_addr, 0));

        // Access protected SID within timeout — should succeed.
        let decision = gw.receive_uds_request(tester_addr, 0x22, &[], 100_000);
        assert_eq!(decision, DiagDecision::Forward);

        // Access well after timeout — should fail.
        // Session last touched at 100_000; timeout is 5_000_000.
        // So session expires after 5_100_000. Use 20_000_000 to be safe.
        let well_after_timeout = 20_000_000;
        let decision = gw.receive_uds_request(tester_addr, 0x22, &[], well_after_timeout);
        // Expired sessions are reaped and the gateway returns SessionExpired
        // to distinguish from "never authenticated".
        assert_eq!(
            decision,
            DiagDecision::Block(BlockReason::SessionExpired),
            "session should have been reaped after timeout"
        );
    }

    #[test]
    fn security_lockout_threshold_constant_is_3() {
        // Security property: lockout threshold must be exactly 3 attempts.
        // Changing this without review would weaken brute-force protection.
        assert_eq!(LOCKOUT_THRESHOLD, 3, "lockout after exactly 3 failures");
    }

    // -----------------------------------------------------------------------
    // New tests for security fixes
    // -----------------------------------------------------------------------

    #[test]
    fn lockout_eviction_prefers_expired_entries() {
        // Fill all lockout slots with entries for different testers,
        // then expire some and verify the expired one gets evicted.
        let mut gw = make_gateway();

        // Trigger lockouts on MAX_LOCKOUT_ENTRIES testers.
        for i in 0..MAX_LOCKOUT_ENTRIES as u16 {
            let tester = 0x1000 + i;
            for attempt in 0..LOCKOUT_THRESHOLD {
                let ts = (i as u64) * 1_000_000 + (attempt as u64) * 100_000;
                let _ = send_bad_key(&mut gw, tester, ts);
            }
        }

        // All slots are full and locked. Now try a new tester after all
        // lockouts have expired (well past lockout_duration_us = 10_000_000).
        let late_ts = 100_000_000u64;
        let new_tester = 0x2000;

        // This should evict an expired entry.
        let _ = send_bad_key(&mut gw, new_tester, late_ts);

        // The new tester should now have a lockout entry (fail_count = 1).
        // Verify by sending 2 more failures to trigger lockout.
        let _ = send_bad_key(&mut gw, new_tester, late_ts + 1_000_000);
        let _ = send_bad_key(&mut gw, new_tester, late_ts + 2_000_000);

        // Should now be locked out.
        let d = gw.receive_uds_request(
            new_tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            late_ts + 3_000_000,
        );
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));
    }

    #[test]
    fn lockout_does_not_evict_active_lockouts() {
        let mut gw = make_gateway();

        // Trigger lockouts on MAX_LOCKOUT_ENTRIES testers at recent timestamps.
        // Each tester needs 3 send_bad_key calls with timestamps spaced > MIN_SEED_INTERVAL_US.
        for i in 0..MAX_LOCKOUT_ENTRIES as u16 {
            let tester = 0x1000 + i;
            for attempt in 0..LOCKOUT_THRESHOLD {
                let ts = 1_000_000 + (i as u64) * 1_000_000 + (attempt as u64) * 200_000;
                let _ = send_bad_key(&mut gw, tester, ts);
            }
        }

        // All slots are full and still locked (within lockout_duration_us).
        // A new tester's failure should be silently dropped (no eviction).
        // Use a timestamp that is monotonically after all previous ones
        // (last was 16_400_001 from the send_bad_key ts+1).
        let new_tester = 0x2000;
        let _ = send_bad_key(&mut gw, new_tester, 17_000_000);

        // The new tester should NOT be locked out (failure wasn't recorded).
        let d = gw.receive_uds_request(
            new_tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            17_500_000,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "new tester should not be locked out since failure was dropped"
        );
    }

    #[test]
    fn lockout_counter_resets_after_expiry() {
        let mut gw = make_gateway();
        let tester = 0x0FA0;

        // Trigger lockout (3 failures).
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester, (i + 1) * 1_000_000);
        }

        // Confirm locked out.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 5_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // After lockout expires, tester gets a full set of LOCKOUT_THRESHOLD
        // attempts again (not immediately re-locked on first failure).
        let after_lockout = 20_000_000u64;

        // Fail once — should NOT be locked out yet.
        let _ = send_bad_key(&mut gw, tester, after_lockout);
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            after_lockout + 1_000_000,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "should not be locked out after just 1 failure post-expiry"
        );
    }

    #[test]
    fn clear_lockout_preserves_entry_slot() {
        let mut gw = make_gateway();
        let tester = 0x0FB0;

        // Fail twice (below threshold).
        let _ = send_bad_key(&mut gw, tester, 1_000_000);
        let _ = send_bad_key(&mut gw, tester, 2_000_000);

        // Authenticate successfully.
        assert!(authenticate(&mut gw, tester, 3_000_000));

        // After auth, fail_count should be reset. Failing once should NOT
        // trigger lockout.
        let _ = send_bad_key(&mut gw, tester, 4_000_000);
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 4_500_000);
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "should not be locked out after 1 failure post-auth"
        );
    }

    #[test]
    fn seed_rate_limiting_rejects_rapid_requests() {
        let mut gw = make_gateway();
        let tester = 0x0FC0;

        // First seed request at t=1_000_000.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_000_000);
        assert!(matches!(d, DiagDecision::Challenge(_)));

        // Second request 50ms later (below MIN_SEED_INTERVAL_US = 100ms).
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_050_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::PolicyDenied));

        // Third request 200ms after first (above interval) — should succeed.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1_200_000);
        assert!(matches!(d, DiagDecision::Challenge(_)));
    }

    #[test]
    fn audit_log_overflow_counter() {
        let mut log = DiagAuditLog::new();

        // Fill to capacity.
        for i in 0..AUDIT_LOG_CAPACITY as u64 {
            log.record(0x01, 0x10, 0, i);
        }
        assert_eq!(log.overflow_count(), 0);

        // One more triggers overflow.
        log.record(0x01, 0x10, 0, 9999);
        assert_eq!(log.overflow_count(), 1);

        // Several more.
        for i in 0..10u64 {
            log.record(0x01, 0x10, 0, 10000 + i);
        }
        assert_eq!(log.overflow_count(), 11);
    }

    #[test]
    fn session_expired_returned_for_timed_out_session() {
        let mut gw = make_gateway();
        let tester = 0x0FD0;

        // Authenticate at t=0.
        assert!(authenticate(&mut gw, tester, 0));

        // Access well after timeout — should get SessionExpired, not Unauthorized.
        let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 20_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::SessionExpired));
    }

    #[test]
    fn session_timeout_getters_match_constructor() {
        let gw = make_gateway();
        assert_eq!(gw.session_timeout_us(), 5_000_000);
        assert_eq!(gw.lockout_duration_us(), 10_000_000);
    }

    #[test]
    fn session_eviction_prefers_unauthenticated() {
        let mut gw = make_gateway();

        // Authenticate 3 testers with close timestamps.
        for i in 0..3u16 {
            let tester = 0x0FE0 + i;
            assert!(authenticate(
                &mut gw,
                tester,
                1_000_000 + (i as u64) * 200_000
            ));
        }

        // 4th tester only requests a seed (unauthenticated).
        let unauth_tester = 0x0FE3;
        let d = gw.receive_uds_request(
            unauth_tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            2_000_000,
        );
        assert!(matches!(d, DiagDecision::Challenge(_)));

        // 5th tester should evict the unauthenticated one.
        let new_tester = 0x0FE4;
        let d = gw.receive_uds_request(
            new_tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            2_200_000,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "5th tester should get a session by evicting the unauthenticated one"
        );

        // The 3 authenticated testers should still work (within timeout).
        for i in 0..3u16 {
            let tester = 0x0FE0 + i;
            let d = gw.receive_uds_request(tester, SID_ROUTINE_CONTROL, &[], 2_400_000);
            assert_eq!(
                d,
                DiagDecision::Forward,
                "authenticated tester {tester:#06X} should still work"
            );
        }
    }

    #[test]
    fn seed_cleared_after_key_submission() {
        let mut gw = make_gateway();
        let tester = 0x0F01;

        // Request seed.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 1000);
        assert!(matches!(d, DiagDecision::Challenge(_)));

        // Send a bad key (clears the pending seed).
        let mut payload = [0u8; 33];
        payload[0] = SA_SEND_KEY;
        payload[1..33].copy_from_slice(&[0xFF; 32]);
        let _ = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &payload, 1001);

        // Without requesting a new seed, another send_key should be rejected
        // because pending_seed was cleared.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &payload, 1002);
        assert_eq!(d, DiagDecision::Block(BlockReason::Unauthorized));
    }

    #[test]
    fn non_monotonic_timestamp_rejected() {
        let mut gw = make_gateway();
        // First request at t=2_000_000
        let _ = gw.receive_uds_request(0x0100, 0x10, &[], 2_000_000);
        // Second request at t=1_000_000 (earlier) should be blocked
        let decision = gw.receive_uds_request(0x0100, 0x10, &[], 1_000_000);
        assert_eq!(decision, DiagDecision::Block(BlockReason::PolicyDenied));
        // Third request at t=3_000_000 should succeed
        let decision = gw.receive_uds_request(0x0100, 0x10, &[], 3_000_000);
        assert_eq!(decision, DiagDecision::Forward);
    }

    #[test]
    fn last_timestamp_us_tracks_monotonic_time() {
        let mut gw = make_gateway();
        assert_eq!(gw.last_timestamp_us(), 0);
        let _ = gw.receive_uds_request(0x0100, 0x10, &[], 5_000_000);
        assert_eq!(gw.last_timestamp_us(), 5_000_000);
    }

    // -----------------------------------------------------------------------
    // V3 - Persistence callback tests
    // -----------------------------------------------------------------------

    use core::sync::atomic::{AtomicU32, Ordering};

    static PERSIST_ENTRY_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    static PERSIST_LOCKOUT_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    static PERSIST_LOCKOUT_LAST_TESTER: AtomicU32 = AtomicU32::new(0);
    static PERSIST_LOCKOUT_LAST_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

    fn reset_persist_counters() {
        PERSIST_ENTRY_CALL_COUNT.store(0, Ordering::SeqCst);
        PERSIST_LOCKOUT_CALL_COUNT.store(0, Ordering::SeqCst);
        PERSIST_LOCKOUT_LAST_TESTER.store(0, Ordering::SeqCst);
        PERSIST_LOCKOUT_LAST_FAIL_COUNT.store(0, Ordering::SeqCst);
    }

    fn test_persist_entry(_entry: &AuditEntry) {
        PERSIST_ENTRY_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    fn test_persist_lockout(tester_addr: u16, fail_count: u8, _locked_until: u64, _gen: u8) {
        PERSIST_LOCKOUT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        PERSIST_LOCKOUT_LAST_TESTER.store(tester_addr as u32, Ordering::SeqCst);
        PERSIST_LOCKOUT_LAST_FAIL_COUNT.store(fail_count as u32, Ordering::SeqCst);
    }

    #[test]
    fn persistence_callbacks_called_on_lockout_state_change() {
        reset_persist_counters();
        let mut gw = make_gateway();
        gw.set_persistence_callbacks(test_persist_entry, test_persist_lockout);

        let tester = 0x0FA1;

        // First bad key creates a new lockout entry (fail_count=1).
        let _ = send_bad_key(&mut gw, tester, 1_000_000);

        assert!(
            PERSIST_LOCKOUT_CALL_COUNT.load(Ordering::SeqCst) >= 1,
            "persist_lockout should be called on first failure"
        );
        assert_eq!(
            PERSIST_LOCKOUT_LAST_TESTER.load(Ordering::SeqCst),
            tester as u32
        );
        assert_eq!(PERSIST_LOCKOUT_LAST_FAIL_COUNT.load(Ordering::SeqCst), 1);

        // Second bad key increments fail_count.
        let _ = send_bad_key(&mut gw, tester, 2_000_000);
        assert_eq!(PERSIST_LOCKOUT_LAST_FAIL_COUNT.load(Ordering::SeqCst), 2);

        // Third bad key triggers lockout.
        let _ = send_bad_key(&mut gw, tester, 3_000_000);
        assert_eq!(PERSIST_LOCKOUT_LAST_FAIL_COUNT.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn persistence_entry_callback_called_on_every_request() {
        // Use a dedicated local counter to avoid races with concurrent
        // tests that share and reset the global static counter.
        static LOCAL_COUNT: AtomicU32 = AtomicU32::new(0);
        LOCAL_COUNT.store(0, Ordering::SeqCst);

        #[allow(clippy::items_after_statements)]
        fn count_persist_entry(_entry: &AuditEntry) {
            LOCAL_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        let mut gw = make_gateway();
        gw.set_persistence_callbacks(count_persist_entry, test_persist_lockout);

        // Send 3 requests.
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 1_000_000);
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 2_000_000);
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 3_000_000);

        assert_eq!(
            LOCAL_COUNT.load(Ordering::SeqCst),
            3,
            "persist_entry should be called once per request"
        );
    }

    #[test]
    fn set_persistence_callbacks_wires_up_correctly() {
        reset_persist_counters();
        let mut gw = make_gateway();

        // Before setting callbacks, no calls should be made.
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 1_000_000);
        assert_eq!(PERSIST_ENTRY_CALL_COUNT.load(Ordering::SeqCst), 0);

        // After setting callbacks, calls should be made.
        gw.set_persistence_callbacks(test_persist_entry, test_persist_lockout);
        let _ = gw.receive_uds_request(0x0F01, 0x10, &[], 2_000_000);
        assert_eq!(PERSIST_ENTRY_CALL_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn persistence_lockout_callback_on_clear() {
        reset_persist_counters();
        let mut gw = make_gateway();
        gw.set_persistence_callbacks(test_persist_entry, test_persist_lockout);

        let tester = 0x0FA2;

        // Fail twice (below threshold).
        let _ = send_bad_key(&mut gw, tester, 1_000_000);
        let _ = send_bad_key(&mut gw, tester, 2_000_000);

        // Authenticate successfully -- clears lockout.
        assert!(authenticate(&mut gw, tester, 3_000_000));

        // The clear_lockout call should have invoked persist_lockout with fail_count=0.
        assert_eq!(
            PERSIST_LOCKOUT_LAST_FAIL_COUNT.load(Ordering::SeqCst),
            0,
            "persist_lockout should be called with fail_count=0 after successful auth"
        );
    }

    // -----------------------------------------------------------------------
    // V3 - restore_lockouts_from tests
    // -----------------------------------------------------------------------

    #[test]
    fn restore_lockouts_from_populates_lockout_table() {
        let mut gw = make_gateway();

        let entries = [
            LockoutEntry {
                tester_address: 0x1000,
                fail_count: 3,
                locked_until_us: 50_000_000,
                lockout_generation: 1,
                active: true,
            },
            LockoutEntry {
                tester_address: 0x1001,
                fail_count: 2,
                locked_until_us: 0,
                lockout_generation: 0,
                active: true,
            },
        ];

        let restored = gw.restore_lockouts_from(&entries);
        assert_eq!(restored, 2);

        // The first tester should be locked out at ts < 50_000_000.
        assert!(gw.is_locked_out(0x1000, 40_000_000));
        // The first tester should not be locked out after expiry.
        assert!(!gw.is_locked_out(0x1000, 60_000_000));
        // The second tester has only 2 failures, not locked out.
        assert!(!gw.is_locked_out(0x1001, 1_000_000));
    }

    #[test]
    fn restore_lockouts_from_skips_inactive_entries() {
        let mut gw = make_gateway();

        let entries = [
            LockoutEntry {
                tester_address: 0x2000,
                fail_count: 3,
                locked_until_us: 50_000_000,
                lockout_generation: 1,
                active: false, // inactive — should be skipped
            },
            LockoutEntry {
                tester_address: 0x2001,
                fail_count: 3,
                locked_until_us: 50_000_000,
                lockout_generation: 1,
                active: true,
            },
        ];

        let restored = gw.restore_lockouts_from(&entries);
        assert_eq!(restored, 1);
        assert!(!gw.is_locked_out(0x2000, 40_000_000));
        assert!(gw.is_locked_out(0x2001, 40_000_000));
    }

    #[test]
    fn restore_lockouts_from_respects_max_capacity() {
        let mut gw = make_gateway();

        // Create more entries than MAX_LOCKOUT_ENTRIES.
        let mut entries = [LockoutEntry::empty(); 20];
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.tester_address = 0x3000 + i as u16;
            entry.fail_count = 3;
            entry.locked_until_us = 50_000_000;
            entry.lockout_generation = 1;
            entry.active = true;
        }

        let restored = gw.restore_lockouts_from(&entries);
        assert_eq!(restored, MAX_LOCKOUT_ENTRIES);
    }

    // -----------------------------------------------------------------------
    // Q3 - Tester address 0x0000 sentinel collision fix
    // -----------------------------------------------------------------------

    #[test]
    fn tester_address_0x0000_works_with_recently_expired() {
        let mut gw = make_gateway();
        let tester_zero = 0x0000u16;

        // Authenticate tester 0x0000 at t=0.
        assert!(authenticate(&mut gw, tester_zero, 0));

        // Confirm the session works.
        let d = gw.receive_uds_request(tester_zero, SID_ROUTINE_CONTROL, &[], 1000);
        assert_eq!(d, DiagDecision::Forward);

        // Jump forward past timeout (> 5_000_000 us from last activity=1000).
        // The session should expire and tester 0x0000 should be in recently_expired.
        let d = gw.receive_uds_request(tester_zero, SID_ROUTINE_CONTROL, &[], 20_000_000);
        assert_eq!(
            d,
            DiagDecision::Block(BlockReason::SessionExpired),
            "tester address 0x0000 should get SessionExpired, not Unauthorized"
        );
    }

    #[test]
    fn tester_address_0x0000_not_falsely_expired_on_init() {
        let mut gw = make_gateway();
        let tester_zero = 0x0000u16;

        // Without any session having been created, tester 0x0000 should NOT
        // appear as recently expired. With the old u16 sentinel approach,
        // the zero-initialized array would falsely match tester 0x0000.
        assert!(
            !gw.was_recently_expired(tester_zero),
            "tester 0x0000 should not be falsely detected as recently expired"
        );

        // An auth-required SID from tester 0x0000 should get Unauthorized,
        // not SessionExpired.
        let d = gw.receive_uds_request(tester_zero, SID_ROUTINE_CONTROL, &[], 1000);
        assert_eq!(
            d,
            DiagDecision::Block(BlockReason::Unauthorized),
            "tester 0x0000 should get Unauthorized when no session ever existed"
        );
    }

    #[test]
    fn exponential_backoff_across_multiple_lockout_cycles() {
        let mut gw = make_gateway();
        let tester = 0x0FD0;
        let base_lockout = gw.lockout_duration_us(); // 10_000_000

        // --- Cycle 1: generation 0 => multiplier 1x ---
        // Trigger lockout with 3 bad keys.
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester, (i + 1) * 1_000_000);
        }
        // Confirm locked out.
        let d = gw.receive_uds_request(tester, SID_SECURITY_ACCESS, &[SA_REQUEST_SEED], 5_000_000);
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // Lockout duration = 1x * base = 10_000_000. Locked at ~3_000_001.
        // Wait well past 1x lockout to ensure expiry.
        let after_cycle1 = 20_000_000u64;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            after_cycle1,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "cycle 1 lockout should have expired by now"
        );

        // --- Cycle 2: generation 1 => multiplier 2x ---
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester, after_cycle1 + (i + 1) * 1_000_000);
        }
        let locked_at_cycle2 = after_cycle1 + 3_000_001;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            locked_at_cycle2,
        );
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // 2x lockout = 20_000_000. Should still be locked at +10_000_000...
        let still_locked = locked_at_cycle2 + base_lockout; // only 1x elapsed
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            still_locked,
        );
        assert_eq!(
            d,
            DiagDecision::Block(BlockReason::LockedOut),
            "cycle 2: should still be locked after 1x duration (needs 2x)"
        );

        // Wait past 2x lockout.
        let after_cycle2 = locked_at_cycle2 + 2 * base_lockout + 1_000_000;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            after_cycle2,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "cycle 2 lockout (2x) should have expired"
        );

        // --- Cycle 3: generation 2 => multiplier 4x ---
        for i in 0..3u64 {
            let _ = send_bad_key(&mut gw, tester, after_cycle2 + (i + 1) * 1_000_000);
        }
        let locked_at_cycle3 = after_cycle2 + 3_000_001;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            locked_at_cycle3,
        );
        assert_eq!(d, DiagDecision::Block(BlockReason::LockedOut));

        // 4x lockout = 40_000_000. Should still be locked at +20_000_000.
        let still_locked3 = locked_at_cycle3 + 2 * base_lockout;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            still_locked3,
        );
        assert_eq!(
            d,
            DiagDecision::Block(BlockReason::LockedOut),
            "cycle 3: should still be locked after 2x duration (needs 4x)"
        );

        // Wait past 4x lockout.
        let after_cycle3 = locked_at_cycle3 + 4 * base_lockout + 1_000_000;
        let d = gw.receive_uds_request(
            tester,
            SID_SECURITY_ACCESS,
            &[SA_REQUEST_SEED],
            after_cycle3,
        );
        assert!(
            matches!(d, DiagDecision::Challenge(_)),
            "cycle 3 lockout (4x) should have expired"
        );
    }

    #[test]
    fn audit_log_wraparound_entries_and_overflow_count() {
        let mut log = DiagAuditLog::new();

        // Fill exactly AUDIT_LOG_CAPACITY entries.
        for i in 0..AUDIT_LOG_CAPACITY as u64 {
            log.record(0x01, 0x10, DECISION_FORWARD, i * 100);
        }
        assert_eq!(log.len(), AUDIT_LOG_CAPACITY);
        assert_eq!(log.overflow_count(), 0, "no overflow yet at exact capacity");

        // Write 10 more entries to force wraparound.
        let extra = 10u64;
        for i in 0..extra {
            let seq_ts = (AUDIT_LOG_CAPACITY as u64 + i) * 100;
            log.record(0x02, 0x22, DECISION_BLOCK, seq_ts);
        }
        assert_eq!(log.len(), AUDIT_LOG_CAPACITY);
        assert_eq!(log.overflow_count(), extra, "should have {extra} overflows");

        // The oldest entry should now be the 11th originally written (index 10),
        // since the first 10 were overwritten.
        let oldest = log.get(0).expect("oldest entry should exist");
        assert_eq!(
            oldest.sequence,
            extra + 1,
            "oldest entry should have sequence = extra + 1 (the first non-overwritten entry)"
        );

        // The newest entry should be the last one recorded.
        let newest = log.get(AUDIT_LOG_CAPACITY - 1).expect("newest entry");
        assert_eq!(
            newest.sequence,
            (AUDIT_LOG_CAPACITY as u64 + extra),
            "newest entry should have the final sequence number"
        );
        assert_eq!(newest.sid, 0x22);
        assert_eq!(newest.decision_code, DECISION_BLOCK);

        // Verify get() returns entries in order from oldest to newest.
        for i in 0..(AUDIT_LOG_CAPACITY - 1) {
            let a = log.get(i).unwrap();
            let b = log.get(i + 1).unwrap();
            assert!(
                b.sequence > a.sequence,
                "entries should be in ascending sequence order: {} vs {}",
                a.sequence,
                b.sequence
            );
        }
    }
}
