#![no_std]
#![deny(missing_docs)]

//! Siemens S7comm / S7comm-plus intrusion detection monitor.
//!
//! Monitors S7comm traffic for security violations:
//!
//! - **Variant awareness** -- classic S7comm (`0x32`) and S7comm-plus (`0x72`)
//!   are parsed as distinct dialects.  A connection is pinned to the first
//!   variant observed; subsequent frames whose variant differs are blocked
//!   as a high-severity MITM indicator.  Rules are evaluated against the
//!   per-rule variant filter.
//! - **PDU-type allowlist** -- restrict allowed PDU types (e.g., allow only
//!   job request/response, block data and system-status PDUs).
//! - **Function-code allowlist** -- per-rule bitmask of allowed function codes.
//! - **Write protection** -- block write operations (`WriteVar`,
//!   `RequestDownload`, `DownloadBlock`, `DownloadEnded`, `PlcControl`,
//!   `Security`) when a rule is read-only.
//! - **SZL filtering** -- block `UserData` PDU type when `block_szl` is
//!   enabled (SZL-Read enumerates device capabilities).
//! - **Rate limiting** -- per-function-code request rate cap with
//!   LRU-evicted token buckets.
//! - **Connection-keyed PDU-reference replay defense** -- full session
//!   tracking keyed by `connection_id`.  Each session keeps a small ring of
//!   recently observed `(pdu_ref, timestamp)` values; a duplicate within
//!   the configurable replay window is blocked at `High` severity.  This
//!   replaces the v0.8 single-ring heuristic, which produced false
//!   positives whenever two real TCP sessions reused PDU references.
//! - **SF 0x29 session-type restriction** -- per-rule allowlist of
//!   session types (PG / HMI / OP) in which `Security (0x29)` may be
//!   issued.  Defaults to "PG only".
//!
//! # References
//!
//! The S7Comm protocol family is proprietary; this crate implements detection
//! against documented protocol behavior gathered from the following sources:
//!
//! - Wireshark s7comm dissector source
//! - ICS-CERT advisory ICSA-12-212-01 (S7comm vulnerabilities)
//! - Claroty Team82 research on S7-1500 authentication (S7comm-plus)

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, InspectResult, RateBucket, SOURCE_S7COMM};

// Re-export the frame types so downstream callers keep importing
// `S7commFrame` from `vs_s7comm_monitor` without churn.
pub use vs_types_ind::{S7CommVariant, S7SessionType, S7commFrame, S7commFunction, S7commPduType};

/// Backward-compatible type alias.
pub type S7commInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum function rules.
const MAX_RULES: usize = 16;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

/// Maximum tracked TCP sessions for replay/variant pinning.
const MAX_SESSIONS: usize = 16;

/// Per-session ring size for `(pdu_ref, timestamp)` replay tracking.
const SESSION_REPLAY_RING: usize = 8;

/// Default replay-detection window (5 s) — duplicate `pdu_ref` values seen
/// within this interval on the same connection are blocked.
pub const DEFAULT_REPLAY_WINDOW_US: u64 = 5_000_000;

// ---------------------------------------------------------------------------
// Function rule
// ---------------------------------------------------------------------------

/// Bit flag in `variant_mask`: rule applies to classic S7comm.
pub const VARIANT_MASK_CLASSIC: u8 = 1 << 0;
/// Bit flag in `variant_mask`: rule applies to S7comm-plus.
pub const VARIANT_MASK_PLUS: u8 = 1 << 1;
/// `variant_mask` value matching both dialects.
pub const VARIANT_MASK_ANY: u8 = VARIANT_MASK_CLASSIC | VARIANT_MASK_PLUS;

/// Default session-type allowlist for `Security (0x29)`: PG only.
pub const SF_SECURITY_DEFAULT_SESSION_MASK: u8 = 1u8 << (S7SessionType::Pg as u8);

/// Convert an [`S7CommVariant`] into its rule-side bit flag.
///
/// `S7CommVariant` is `#[non_exhaustive]`, so a future variant added in
/// `vs-types-ind` would silently land in the "neither" arm here.  That is
/// the conservative behaviour: the unknown variant matches no rule and is
/// only allowed in permissive mode.
fn variant_bit(v: S7CommVariant) -> u8 {
    match v {
        S7CommVariant::Classic => VARIANT_MASK_CLASSIC,
        S7CommVariant::Plus => VARIANT_MASK_PLUS,
        _ => 0,
    }
}

/// Security rule for an S7comm function code.
#[derive(Debug, Clone, Copy)]
struct FunctionRule {
    /// Raw function code to match (0xFF = wildcard, matches any).
    raw_function: u8,
    /// Bitmask of allowed function codes. Bit positions map to
    /// [`S7commFunction::bit_index`] values (bit 0 = `ReadVar`, bit 1 = `WriteVar`,
    /// ..., bit 9 = `Security`). A set bit means the function code is allowed.
    fc_mask: u32,
    /// Variant filter (bitmask of [`VARIANT_MASK_CLASSIC`] / [`VARIANT_MASK_PLUS`]).
    /// A rule only matches frames whose variant bit is set here.
    variant_mask: u8,
    /// Session-type allowlist applied to `Security (0x29)` frames.  Bit `n`
    /// allows session-type with `S7SessionType as u8 == n`.  Other function
    /// codes ignore this field.
    sf_security_session_mask: u8,
    /// Block all write operations.
    read_only: bool,
    /// Block `UserData` PDU type (SZL-Read enumerates device capabilities).
    block_szl: bool,
    /// Maximum requests per second (0 = unlimited).
    max_rate_per_sec: u16,
    active: bool,
}

impl FunctionRule {
    const fn empty() -> Self {
        Self {
            raw_function: 0xFF,
            fc_mask: 0xFFFF_FFFF,
            variant_mask: VARIANT_MASK_ANY,
            sf_security_session_mask: SF_SECURITY_DEFAULT_SESSION_MASK,
            read_only: false,
            block_szl: false,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-session state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ReplaySlot {
    pdu_ref: u16,
    timestamp_us: u64,
    used: bool,
}

impl ReplaySlot {
    const fn empty() -> Self {
        Self {
            pdu_ref: 0,
            timestamp_us: 0,
            used: false,
        }
    }
}

/// Per-TCP-connection state used to enforce variant pinning and
/// connection-keyed replay detection.
#[derive(Debug, Clone, Copy)]
struct Session {
    connection_id: u32,
    /// First observed variant.  Frames whose variant differs from this are
    /// flagged as mixed-variant MITM.
    variant: S7CommVariant,
    /// Ring of recently observed `(pdu_ref, timestamp)` values, oldest-first
    /// eviction.
    ring: [ReplaySlot; SESSION_REPLAY_RING],
    /// Next write position into `ring`.
    ring_head: u8,
    /// LRU generation for slot eviction.
    last_used: u32,
    active: bool,
}

impl Session {
    const fn empty() -> Self {
        Self {
            connection_id: 0,
            variant: S7CommVariant::Classic,
            ring: [ReplaySlot::empty(); SESSION_REPLAY_RING],
            ring_head: 0,
            last_used: 0,
            active: false,
        }
    }

    /// Return `true` if `pdu_ref` was already observed within `window_us`.
    fn is_replay(&self, pdu_ref: u16, now_us: u64, window_us: u64) -> bool {
        for slot in &self.ring {
            if !slot.used {
                continue;
            }
            if slot.pdu_ref != pdu_ref {
                continue;
            }
            // Same pdu_ref; check the time window.  Clock-step-back guard:
            // if now_us < slot.timestamp_us we treat it as "in window".
            let delta = now_us.saturating_sub(slot.timestamp_us);
            if delta <= window_us {
                return true;
            }
        }
        false
    }

    /// Record a new `(pdu_ref, timestamp)` pair, evicting the oldest slot.
    fn record(&mut self, pdu_ref: u16, now_us: u64) {
        // `SESSION_REPLAY_RING` is a small compile-time constant, so the
        // modulo result is bounded well within `u8`.
        const _: () = assert!(SESSION_REPLAY_RING <= u8::MAX as usize);
        let idx = (self.ring_head as usize) % SESSION_REPLAY_RING;
        self.ring[idx] = ReplaySlot {
            pdu_ref,
            timestamp_us: now_us,
            used: true,
        };
        let next = (idx + 1) % SESSION_REPLAY_RING;
        // The modulo above is in 0..SESSION_REPLAY_RING <= u8::MAX, so the
        // truncation here is provably lossless.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.ring_head = next as u8;
        }
    }
}

// ---------------------------------------------------------------------------
// S7comm Monitor
// ---------------------------------------------------------------------------

/// Siemens S7comm intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~3.5 KiB (dominated by 16 sessions × 8 replay
/// slots).
pub struct S7commMonitor {
    rules: [FunctionRule; MAX_RULES],
    rule_count: u8,
    strict_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
    /// Rate-limit token buckets.
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Monotonic generation counter for LRU eviction of rate buckets.
    rate_tick: u32,
    /// Per-TCP-connection session state.
    sessions: [Session; MAX_SESSIONS],
    /// Monotonic generation counter for LRU eviction of sessions.
    session_tick: u32,
    /// Cached count of `sessions[i].active == true` slots, maintained
    /// incrementally so `active_session_count` is O(1).  Invariant:
    /// `active_sessions == sessions.iter().filter(|s| s.active).count()`.
    active_sessions: u8,
    /// Replay-detection time window in microseconds.
    replay_window_us: u64,
}

impl S7commMonitor {
    /// Create a monitor in permissive mode (allow unknown PDU types).
    pub fn new() -> Self {
        Self {
            rules: [FunctionRule::empty(); MAX_RULES],
            rule_count: 0,
            strict_mode: false,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            rate_tick: 0,
            sessions: [Session::empty(); MAX_SESSIONS],
            session_tick: 0,
            active_sessions: 0,
            replay_window_us: DEFAULT_REPLAY_WINDOW_US,
        }
    }

    /// Create a monitor in strict mode (block unknown PDU types).
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Configure the replay-detection window in microseconds.
    ///
    /// Frames with the same `(connection_id, pdu_ref)` observed within this
    /// interval are blocked as duplicates.  A value of `0` disables replay
    /// detection entirely (not recommended).
    pub fn set_replay_window_us(&mut self, window_us: u64) {
        self.replay_window_us = window_us;
    }

    /// Current replay window in microseconds.
    pub fn replay_window_us(&self) -> u64 {
        self.replay_window_us
    }

    /// Add a function rule.
    ///
    /// `raw_function` is the raw byte to match against the frame's
    /// `raw_function` field. Use `0xFF` as a wildcard to match any function.
    ///
    /// `fc_mask` is a bitmask where bit positions map to known function codes.
    /// Set bits allow the corresponding function code; clear bits block it.
    ///
    /// The new rule matches frames of either S7comm variant and restricts
    /// `Security (0x29)` to PG sessions.  Use [`Self::add_rule_full`] to
    /// override these defaults.
    ///
    /// Returns [`VsError::ResourceExhausted`] if the rule table is full,
    /// or [`VsError::InvalidInput`] if a rule for the same `raw_function`
    /// already exists.
    pub fn add_rule(
        &mut self,
        raw_function: u8,
        fc_mask: u32,
        read_only: bool,
        block_szl: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        self.add_rule_full(
            raw_function,
            fc_mask,
            VARIANT_MASK_ANY,
            SF_SECURITY_DEFAULT_SESSION_MASK,
            read_only,
            block_szl,
            max_rate_per_sec,
        )
    }

    /// Add a function rule with full control over the variant filter and the
    /// `Security (0x29)` session-type allowlist.
    ///
    /// `variant_mask` is a bitmask of [`VARIANT_MASK_CLASSIC`] /
    /// [`VARIANT_MASK_PLUS`].  Use [`VARIANT_MASK_ANY`] to match either.
    ///
    /// `sf_security_session_mask` lists the [`S7SessionType`] values in which
    /// SF 0x29 may be issued.  Build it with `S7SessionType::Pg.mask() |
    /// S7SessionType::Op.mask()` for example.  An empty mask blocks all
    /// SF 0x29 calls outright.
    #[allow(clippy::too_many_arguments)] // intentional flat parameter list
    pub fn add_rule_full(
        &mut self,
        raw_function: u8,
        fc_mask: u32,
        variant_mask: u8,
        sf_security_session_mask: u8,
        read_only: bool,
        block_szl: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }
        if variant_mask == 0 || (variant_mask & !VARIANT_MASK_ANY) != 0 {
            return Err(VsError::InvalidInput);
        }
        // Reject duplicate raw_function -- the second rule would be silently
        // shadowed by first-match logic.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && self.rules[i].raw_function == raw_function {
                return Err(VsError::InvalidInput);
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = FunctionRule {
            raw_function,
            fc_mask,
            variant_mask,
            sf_security_session_mask,
            read_only,
            block_szl,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Inspect an S7comm frame.
    pub fn inspect(&mut self, frame: &S7commFrame) -> S7commInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_S7COMM);

        // 1. Unknown PDU type alert.
        if frame.pdu_type == S7commPduType::Unknown {
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_S7COMM,
                frame.raw_pdu_type as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::UnknownFunctionCode,
            );
            // In strict mode, block unknown PDU types outright.
            if self.strict_mode {
                result.allowed = false;
                return result;
            }
        }

        // 2. Variant pinning: look up or create the session for this
        //    connection.  A subsequent frame whose variant differs from
        //    the pinned value is treated as a MITM indicator and blocked
        //    *before* any rule evaluation, so a downgrade attempt cannot
        //    sneak past with a permissive rule.
        let (session_idx, mixed) =
            self.lookup_or_create_session(frame.connection_id, frame.s7_variant);
        if mixed {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_S7COMM,
                frame.connection_id,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PolicyViolation,
            );
            return result;
        }

        // 3. Connection-keyed PDU-ref replay defense.
        //    Only applied to JobRequest frames — AckData and UserData
        //    legitimately echo the master's pdu_ref.
        if frame.pdu_type == S7commPduType::JobRequest && self.replay_window_us > 0 {
            let is_dup = self.sessions[session_idx].is_replay(
                frame.pdu_ref,
                frame.timestamp_us,
                self.replay_window_us,
            );
            if is_dup {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_S7COMM,
                    frame.pdu_ref as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::ReplayDetected,
                );
                return result;
            }
            self.sessions[session_idx].record(frame.pdu_ref, frame.timestamp_us);
        }

        // 4. Find matching rule (first-match by raw_function, restricted to
        //    rules whose variant_mask includes this frame's variant).
        let matched = self.find_matching_rule(frame.raw_function, frame.s7_variant);

        let Some(rule_idx) = matched else {
            // No matching rule. In strict mode, block.
            if self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_S7COMM,
                    frame.raw_function as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::NoMatchingRule,
                );
            }
            return result;
        };

        let rule = &self.rules[rule_idx];

        // 5. Function code policy check (fc_mask).
        //    Only applies to known function codes that have a bit index.
        if let Some(bit) = frame.function.bit_index() {
            if bit < 32 && (rule.fc_mask >> bit) & 1 == 0 {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_S7COMM,
                    frame.raw_function as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::PolicyViolation,
                );
                return result;
            }
        }

        // 6. Write protection.
        if rule.read_only && frame.function.is_write() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_S7COMM,
                frame.raw_function as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::WriteProtection,
            );
            return result;
        }

        // 7. SF 0x29 session-type restriction.  Only the
        //    `Security` function is gated; other function codes ignore the
        //    mask.  A frame whose `session_type` bit is clear in the rule's
        //    mask is rejected.  The default mask (`SF_SECURITY_DEFAULT_
        //    SESSION_MASK`) admits PG only — `Unknown` is NOT included by
        //    design, so operators who haven't wired up session typing must
        //    explicitly opt in via `add_rule_full` to permit untyped
        //    sessions to issue SF 0x29.
        if frame.function == S7commFunction::Security {
            // `S7SessionType` is `#[non_exhaustive]` upstream; a future
            // variant whose discriminant is >= 8 would overflow `1u8 << disc`.
            // Treat such variants as "no bit set" — the SF 0x29 check fails
            // and the frame is blocked, matching the empty-mask semantics.
            let disc = frame.session_type as u8;
            let sess_bit = if disc < 8 { 1u8 << disc } else { 0 };
            if (rule.sf_security_session_mask & sess_bit) == 0 {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_S7COMM,
                    frame.raw_function as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::PolicyViolation,
                );
                return result;
            }
        }

        // 8. SZL filtering: block UserData PDU if block_szl is enabled.
        if rule.block_szl && frame.pdu_type == S7commPduType::UserData {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_S7COMM,
                frame.raw_function as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PolicyViolation,
            );
            return result;
        }

        // 9. Rate limiting.
        let max_rate = self.rules[rule_idx].max_rate_per_sec;
        if max_rate > 0 && !self.rate_check(frame.raw_function as u32, max_rate, frame.timestamp_us)
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_S7COMM,
                frame.raw_function as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::RateExceeded,
            );
        }

        // PDU-reference replay detection is now handled by the per-connection
        // session table earlier in this function (see line ~430). The v0.8
        // global heuristic that lived here has been superseded.

        result
    }

    /// Find the first matching function rule.  A rule matches when both the
    /// `raw_function` matches (0xFF wildcard or exact) and the frame's
    /// variant bit is present in the rule's `variant_mask`.
    ///
    /// Iterates `0..rule_count`; first-match-wins (rules are sorted by
    /// insertion order, which callers use as their priority order).
    fn find_matching_rule(&self, raw_function: u8, variant: S7CommVariant) -> Option<usize> {
        let v_bit = variant_bit(variant);
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            let raw_match = r.active && (r.raw_function == 0xFF || r.raw_function == raw_function);
            let variant_match = (r.variant_mask & v_bit) != 0;
            if raw_match && variant_match {
                return Some(i);
            }
        }
        None
    }

    /// Look up an existing session by `connection_id`, or allocate one.
    ///
    /// Returns the slot index and a `mixed_variant` flag.  When the flag is
    /// set, the caller should reject the frame: the existing session has a
    /// different pinned variant.  On allocation, the new session is pinned
    /// to `variant`.
    fn lookup_or_create_session(
        &mut self,
        connection_id: u32,
        variant: S7CommVariant,
    ) -> (usize, bool) {
        self.session_tick = self.session_tick.wrapping_add(1);
        let now_tick = self.session_tick;

        let mut first_free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_age: u32 = 0;
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.active {
                if s.connection_id == connection_id {
                    s.last_used = now_tick;
                    let mixed = s.variant != variant;
                    return (i, mixed);
                }
                let age = now_tick.wrapping_sub(s.last_used);
                if age >= lru_age {
                    lru_age = age;
                    lru_idx = i;
                }
            } else if first_free.is_none() {
                first_free = Some(i);
            }
        }

        // Allocate.  If we filled a previously-free slot, bump the active
        // counter; if we evicted an LRU victim, the count is unchanged.
        let slot = first_free.unwrap_or(lru_idx);
        let was_active = self.sessions[slot].active;
        self.sessions[slot] = Session {
            connection_id,
            variant,
            ring: [ReplaySlot::empty(); SESSION_REPLAY_RING],
            ring_head: 0,
            last_used: now_tick,
            active: true,
        };
        if !was_active {
            self.active_sessions = self.active_sessions.saturating_add(1);
        }
        (slot, false)
    }

    /// Check and consume a rate-limit token for the given key.
    fn rate_check(&mut self, key: u32, max_rate: u16, now_us: u64) -> bool {
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;

        // Single-pass: find matching bucket, first free slot, and LRU victim.
        let mut first_free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_age: u32 = 0;
        for (i, b) in self.rate_buckets.iter_mut().enumerate() {
            if b.active {
                if b.key == key {
                    b.last_used = now_tick;
                    return b.try_consume(now_us);
                }
                let age = now_tick.wrapping_sub(b.last_used);
                if age >= lru_age {
                    lru_age = age;
                    lru_idx = i;
                }
            } else if first_free.is_none() {
                first_free = Some(i);
            }
        }

        // Allocate in first free slot, or evict LRU.
        let slot = first_free.unwrap_or(lru_idx);
        self.rate_buckets[slot] = RateBucket {
            key,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
            last_used: now_tick,
        };
        true
    }

    /// Total frames inspected since creation or last [`reset`](Self::reset).
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Total alerts raised since creation or last [`reset`](Self::reset).
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Returns `true` if the monitor is in strict mode.
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Number of TCP sessions currently being tracked.
    ///
    /// O(1): returns a counter maintained as sessions are allocated and
    /// evicted.  Bounded by `MAX_SESSIONS`.
    pub fn active_session_count(&self) -> u8 {
        self.active_sessions
    }

    /// Reset all state. Settings (`strict_mode`, replay window) are
    /// preserved; rules, counters, rate buckets, and sessions are cleared.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let window = self.replay_window_us;
        *self = Self::new();
        self.strict_mode = strict;
        self.replay_window_us = window;
    }
}

impl Default for S7commMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// Use Debug derive would require RateBucket: Debug, so implement manually.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for S7commMonitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S7commMonitor")
            .field("rule_count", &self.rule_count)
            .field("strict_mode", &self.strict_mode)
            .field("total_inspected", &self.total_inspected)
            .field("total_alerts", &self.total_alerts)
            .field("active_sessions", &self.active_session_count())
            .field("replay_window_us", &self.replay_window_us)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- PDU type parsing --

    #[test]
    fn s7comm_pdu_type_from_u8() {
        assert_eq!(S7commPduType::from_u8(0x01), S7commPduType::JobRequest);
        assert_eq!(S7commPduType::from_u8(0x03), S7commPduType::AckData);
        assert_eq!(S7commPduType::from_u8(0x07), S7commPduType::UserData);
        assert_eq!(S7commPduType::from_u8(0xFF), S7commPduType::Unknown);
        assert_eq!(S7commPduType::from_u8(0x99), S7commPduType::Unknown);
    }

    // -- Function code parsing --

    #[test]
    fn s7comm_function_from_u8() {
        assert_eq!(S7commFunction::from_u8(0x04), S7commFunction::ReadVar);
        assert_eq!(S7commFunction::from_u8(0x05), S7commFunction::WriteVar);
        assert_eq!(S7commFunction::from_u8(0x28), S7commFunction::PlcControl);
        assert_eq!(S7commFunction::from_u8(0x29), S7commFunction::Security);
        assert_eq!(S7commFunction::from_u8(0xFF), S7commFunction::Unknown);
    }

    // -- is_write --

    #[test]
    fn s7comm_function_is_write() {
        assert!(!S7commFunction::ReadVar.is_write());
        assert!(S7commFunction::WriteVar.is_write());
        assert!(S7commFunction::RequestDownload.is_write());
        assert!(S7commFunction::PlcControl.is_write());
        assert!(S7commFunction::Security.is_write());
        assert!(!S7commFunction::Upload.is_write());
    }

    // -- Permissive mode --

    #[test]
    fn permissive_allows_unknown_pdu_type() {
        let mut mon = S7commMonitor::new();
        let frame = S7commFrame {
            pdu_type: S7commPduType::Unknown,
            raw_pdu_type: 0x99,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            pdu_ref: 1,
            timestamp_us: 1000,
            ..S7commFrame::default()
        };
        let result = mon.inspect(&frame);
        // Permissive: unknown PDU type is allowed (but still generates an alert).
        assert!(result.allowed);
        assert_eq!(result.alert_count, 1);
        assert_eq!(mon.total_inspected(), 1);
    }

    #[test]
    fn permissive_no_rules_allows_all() {
        let mut mon = S7commMonitor::new();
        let frame = S7commFrame::default();
        let result = mon.inspect(&frame);
        assert!(result.allowed);
        assert_eq!(result.alert_count, 0);
    }

    // -- Strict mode --

    #[test]
    fn strict_blocks_unknown_pdu_type() {
        let mut mon = S7commMonitor::new_strict();
        let frame = S7commFrame {
            pdu_type: S7commPduType::Unknown,
            raw_pdu_type: 0x99,
            ..S7commFrame::default()
        };
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        assert!(result.alert_count > 0);
    }

    #[test]
    fn strict_blocks_no_matching_rule() {
        let mut mon = S7commMonitor::new_strict();
        let frame = S7commFrame::default();
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        assert!(result.alert_count > 0);
    }

    #[test]
    fn strict_allows_configured_function() {
        let mut mon = S7commMonitor::new_strict();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();
        let frame = S7commFrame::default();
        let result = mon.inspect(&frame);
        assert!(result.allowed);
    }

    // -- Function code policy (fc_mask) --

    #[test]
    fn fc_mask_blocks_disallowed() {
        let mut mon = S7commMonitor::new();
        // Only allow ReadVar (bit 0).
        mon.add_rule(0xFF, 1 << 0, false, false, 0).unwrap();
        let read = S7commFrame {
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        assert!(mon.inspect(&read).allowed);

        let write = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            connection_id: 99, // distinct conn so the read pdu_ref isn't a replay
            ..Default::default()
        };
        assert!(!mon.inspect(&write).allowed);
    }

    // -- Write protection --

    #[test]
    fn write_protection_blocks_writes() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0).unwrap();

        let write = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            connection_id: 1,
            pdu_ref: 1,
            ..Default::default()
        };
        assert!(!mon.inspect(&write).allowed);
    }

    // -- SZL filtering --

    #[test]
    fn szl_filtering_blocks_userdata() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, true, 0).unwrap();

        let userdata = S7commFrame {
            pdu_type: S7commPduType::UserData,
            raw_pdu_type: 0x07,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        assert!(!mon.inspect(&userdata).allowed);
    }

    // -- Rate limiting --

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 2).unwrap();

        // Use distinct pdu_refs / timestamps to avoid tripping replay first.
        let f1 = S7commFrame {
            pdu_ref: 1,
            timestamp_us: 1_000_000,
            ..Default::default()
        };
        let f2 = S7commFrame {
            pdu_ref: 2,
            timestamp_us: 1_000_001,
            ..Default::default()
        };
        let f3 = S7commFrame {
            pdu_ref: 3,
            timestamp_us: 1_000_002,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        assert!(mon.inspect(&f2).allowed);
        assert!(!mon.inspect(&f3).allowed);
    }

    // -- Reset --

    #[test]
    fn reset_clears_counters_preserves_strict() {
        let mut mon = S7commMonitor::new_strict();
        let frame = S7commFrame::default();
        let _ = mon.inspect(&frame);
        let _ = mon.inspect(&frame);
        assert_eq!(mon.total_inspected(), 2);
        assert!(mon.total_alerts() > 0);
        assert!(mon.strict_mode());

        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
        assert!(mon.strict_mode());
    }

    // -- add_rule error cases --

    #[test]
    fn add_rule_rejects_duplicate() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0x04, 0xFFFF_FFFF, false, false, 0).unwrap();
        let result = mon.add_rule(0x04, 0xFFFF_FFFF, false, false, 0);
        assert!(result.is_err());
    }

    #[test]
    fn add_rule_rejects_when_full() {
        let mut mon = S7commMonitor::new();
        for i in 0..MAX_RULES {
            mon.add_rule(i as u8, 0xFFFF_FFFF, false, false, 0).unwrap();
        }
        let result = mon.add_rule(0xFE, 0xFFFF_FFFF, false, false, 0);
        assert!(result.is_err());
    }

    #[test]
    fn add_rule_full_rejects_empty_variant_mask() {
        let mut mon = S7commMonitor::new();
        let r = mon.add_rule_full(
            0xFF,
            0xFFFF_FFFF,
            0,
            SF_SECURITY_DEFAULT_SESSION_MASK,
            false,
            false,
            0,
        );
        assert!(r.is_err());
    }

    #[test]
    fn add_rule_full_rejects_unknown_variant_bits() {
        let mut mon = S7commMonitor::new();
        let r = mon.add_rule_full(
            0xFF,
            0xFFFF_FFFF,
            0xF0, // bits outside VARIANT_MASK_ANY
            SF_SECURITY_DEFAULT_SESSION_MASK,
            false,
            false,
            0,
        );
        assert!(r.is_err());
    }

    // =======================================================================
    // Regression: S7CommVariant
    // =======================================================================

    #[test]
    fn variant_parses_protocol_id_bytes() {
        assert_eq!(
            S7CommVariant::from_protocol_id(0x32),
            Some(S7CommVariant::Classic)
        );
        assert_eq!(
            S7CommVariant::from_protocol_id(0x72),
            Some(S7CommVariant::Plus)
        );
        assert_eq!(S7CommVariant::from_protocol_id(0x00), None);
        assert_eq!(S7CommVariant::from_protocol_id(0xFF), None);
    }

    #[test]
    fn variant_round_trips_via_protocol_id() {
        assert_eq!(S7CommVariant::Classic.protocol_id(), 0x32);
        assert_eq!(S7CommVariant::Plus.protocol_id(), 0x72);
    }

    #[test]
    fn rule_variant_filter_restricts_to_classic() {
        let mut mon = S7commMonitor::new_strict();
        // Rule applies to classic only.
        mon.add_rule_full(
            0xFF,
            0xFFFF_FFFF,
            VARIANT_MASK_CLASSIC,
            SF_SECURITY_DEFAULT_SESSION_MASK,
            false,
            false,
            0,
        )
        .unwrap();

        // Classic frame on a fresh connection — allowed by the rule.
        let classic = S7commFrame {
            connection_id: 10,
            s7_variant: S7CommVariant::Classic,
            ..Default::default()
        };
        assert!(mon.inspect(&classic).allowed);

        // Plus frame on a different connection — no matching rule in strict
        // mode, must be blocked.
        let plus = S7commFrame {
            connection_id: 11,
            s7_variant: S7CommVariant::Plus,
            ..Default::default()
        };
        let r = mon.inspect(&plus);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn rule_variant_filter_restricts_to_plus() {
        let mut mon = S7commMonitor::new_strict();
        mon.add_rule_full(
            0xFF,
            0xFFFF_FFFF,
            VARIANT_MASK_PLUS,
            SF_SECURITY_DEFAULT_SESSION_MASK,
            false,
            false,
            0,
        )
        .unwrap();

        let plus = S7commFrame {
            connection_id: 20,
            s7_variant: S7CommVariant::Plus,
            ..Default::default()
        };
        assert!(mon.inspect(&plus).allowed);

        let classic = S7commFrame {
            connection_id: 21,
            s7_variant: S7CommVariant::Classic,
            ..Default::default()
        };
        assert!(!mon.inspect(&classic).allowed);
    }

    // =======================================================================
    // Regression: mixed-variant rejection on same connection
    // =======================================================================

    #[test]
    fn mixed_variant_on_same_connection_is_blocked() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        // First frame: classic on connection 7.
        let f1 = S7commFrame {
            connection_id: 7,
            s7_variant: S7CommVariant::Classic,
            pdu_ref: 1,
            timestamp_us: 1_000,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);

        // Second frame: PLUS on the SAME connection — MITM-style mix.
        let f2 = S7commFrame {
            connection_id: 7,
            s7_variant: S7CommVariant::Plus,
            pdu_ref: 2,
            timestamp_us: 2_000,
            ..Default::default()
        };
        let r = mon.inspect(&f2);
        assert!(!r.allowed, "mixed-variant frame must be rejected");
        assert!(r.alert_count > 0);
        assert_eq!(r.alert_codes[0], AlertCode::PolicyViolation);
        // Severity must be High for MITM-grade events.
        assert_eq!(r.alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn same_variant_on_same_connection_is_allowed() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let f1 = S7commFrame {
            connection_id: 8,
            s7_variant: S7CommVariant::Plus,
            pdu_ref: 1,
            timestamp_us: 1_000,
            ..Default::default()
        };
        let f2 = S7commFrame {
            connection_id: 8,
            s7_variant: S7CommVariant::Plus,
            pdu_ref: 2,
            timestamp_us: 2_000,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn distinct_connections_may_use_different_variants() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let classic = S7commFrame {
            connection_id: 1,
            s7_variant: S7CommVariant::Classic,
            pdu_ref: 1,
            timestamp_us: 1_000,
            ..Default::default()
        };
        let plus = S7commFrame {
            connection_id: 2,
            s7_variant: S7CommVariant::Plus,
            pdu_ref: 1, // same pdu_ref, but different conn => OK
            timestamp_us: 2_000,
            ..Default::default()
        };
        assert!(mon.inspect(&classic).allowed);
        assert!(mon.inspect(&plus).allowed);
    }

    // =======================================================================
    // Regression: connection-keyed PDU-reference replay
    // =======================================================================

    #[test]
    fn pdu_ref_replay_on_same_connection_is_blocked() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let f1 = S7commFrame {
            connection_id: 42,
            pdu_ref: 0x1234,
            timestamp_us: 1_000_000,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            ..Default::default()
        };
        let r1 = mon.inspect(&f1);
        assert!(r1.allowed);

        // Same connection, same pdu_ref, well within the 5 s window.
        let f2 = S7commFrame {
            timestamp_us: 1_500_000,
            ..f1
        };
        let r2 = mon.inspect(&f2);
        assert!(!r2.allowed, "duplicate pdu_ref must be blocked");
        assert_eq!(r2.alert_codes[0], AlertCode::ReplayDetected);
        // Upgraded to High severity now that session tracking is real.
        assert_eq!(r2.alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn pdu_ref_replay_outside_window_is_allowed() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();
        mon.set_replay_window_us(1_000_000); // 1 s

        let f1 = S7commFrame {
            connection_id: 5,
            pdu_ref: 7,
            timestamp_us: 1_000_000,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);

        // Outside the 1 s window — legitimate pdu_ref wraparound.
        let f2 = S7commFrame {
            timestamp_us: 3_000_000,
            ..f1
        };
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn pdu_ref_replay_across_distinct_connections_is_not_a_replay() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        // Two distinct connections happen to reuse pdu_ref = 1.  This is
        // normal — pdu_ref is per-session — and must NOT trip replay.
        let f1 = S7commFrame {
            connection_id: 100,
            pdu_ref: 1,
            timestamp_us: 1_000_000,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            ..Default::default()
        };
        let f2 = S7commFrame {
            connection_id: 101,
            ..f1
        };
        assert!(mon.inspect(&f1).allowed);
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn pdu_ref_replay_only_applies_to_job_request() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        // AckData echoes the master's pdu_ref — duplicates are normal.
        let ack = S7commFrame {
            connection_id: 9,
            pdu_ref: 1,
            timestamp_us: 1_000,
            pdu_type: S7commPduType::AckData,
            raw_pdu_type: 0x03,
            ..Default::default()
        };
        assert!(mon.inspect(&ack).allowed);
        assert!(mon.inspect(&ack).allowed);
    }

    #[test]
    fn replay_window_zero_disables_replay_check() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();
        mon.set_replay_window_us(0);
        assert_eq!(mon.replay_window_us(), 0);

        let f1 = S7commFrame {
            connection_id: 1,
            pdu_ref: 7,
            timestamp_us: 0,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        assert!(mon.inspect(&f1).allowed);
    }

    #[test]
    fn reset_clears_replay_state() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let f = S7commFrame {
            connection_id: 1,
            pdu_ref: 1,
            timestamp_us: 1_000,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        mon.reset();
        // The rule was cleared too; re-add a permissive one.  Without the
        // rule add, strict-mode-style "no rule" blocking would shadow the
        // result we're checking for.
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        // After reset, the same (conn, pdu_ref, ts) must not be flagged
        // because the ring was cleared.
        assert!(mon.inspect(&f).allowed);
    }

    // =======================================================================
    // Regression: SF 0x29 session-type restriction
    // =======================================================================

    #[test]
    fn sf_29_default_blocks_hmi_session() {
        let mut mon = S7commMonitor::new();
        // Default add_rule = SF 0x29 PG-only.
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let f = S7commFrame {
            connection_id: 200,
            s7_variant: S7CommVariant::Plus,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::Security,
            raw_function: 0x29,
            pdu_ref: 1,
            session_type: S7SessionType::Hmi,
            timestamp_us: 0,
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "SF 0x29 on HMI must be blocked by default");
        assert!(r.alert_count > 0);
        assert_eq!(r.alert_codes[0], AlertCode::PolicyViolation);
        assert_eq!(r.alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn sf_29_default_allows_pg_session() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let f = S7commFrame {
            connection_id: 201,
            s7_variant: S7CommVariant::Plus,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::Security,
            raw_function: 0x29,
            pdu_ref: 1,
            session_type: S7SessionType::Pg,
            timestamp_us: 0,
        };
        // SF 0x29 is also is_write() — the rule allows writes, fc_mask allows
        // everything, so this PG session should sail through.
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn sf_29_custom_allowlist_admits_op_session() {
        let mut mon = S7commMonitor::new();
        // Allow SF 0x29 from PG *or* OP.
        let mask = S7SessionType::Pg.mask() | S7SessionType::Op.mask();
        mon.add_rule_full(0xFF, 0xFFFF_FFFF, VARIANT_MASK_ANY, mask, false, false, 0)
            .unwrap();

        let f = S7commFrame {
            connection_id: 202,
            function: S7commFunction::Security,
            raw_function: 0x29,
            session_type: S7SessionType::Op,
            pdu_ref: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        // HMI is still excluded.
        let f_hmi = S7commFrame {
            connection_id: 203,
            function: S7commFunction::Security,
            raw_function: 0x29,
            session_type: S7SessionType::Hmi,
            pdu_ref: 1,
            ..Default::default()
        };
        assert!(!mon.inspect(&f_hmi).allowed);
    }

    #[test]
    fn sf_29_empty_allowlist_blocks_every_session() {
        let mut mon = S7commMonitor::new();
        mon.add_rule_full(
            0xFF,
            0xFFFF_FFFF,
            VARIANT_MASK_ANY,
            0, // no session type allowed
            false,
            false,
            0,
        )
        .unwrap();

        for (i, st) in [
            S7SessionType::Pg,
            S7SessionType::Hmi,
            S7SessionType::Op,
            S7SessionType::Unknown,
        ]
        .iter()
        .enumerate()
        {
            let f = S7commFrame {
                connection_id: 300 + i as u32,
                function: S7commFunction::Security,
                raw_function: 0x29,
                session_type: *st,
                pdu_ref: i as u16 + 1,
                ..Default::default()
            };
            assert!(!mon.inspect(&f).allowed, "session {st:?} must be blocked");
        }
    }

    #[test]
    fn sf_29_session_check_does_not_affect_other_function_codes() {
        let mut mon = S7commMonitor::new();
        // Empty mask would block SF 0x29 from every session.  Plain
        // ReadVar must still be allowed because the mask is SF-only.
        mon.add_rule_full(0xFF, 0xFFFF_FFFF, VARIANT_MASK_ANY, 0, false, false, 0)
            .unwrap();

        let f = S7commFrame {
            connection_id: 9999,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            session_type: S7SessionType::Hmi,
            pdu_ref: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    // =======================================================================
    // Misc.
    // =======================================================================

    #[test]
    fn s7_session_type_mask_bits_are_unique() {
        let masks = [
            S7SessionType::Unknown.mask(),
            S7SessionType::Pg.mask(),
            S7SessionType::Hmi.mask(),
            S7SessionType::Op.mask(),
        ];
        for i in 0..masks.len() {
            assert!(masks[i].is_power_of_two());
            for j in (i + 1)..masks.len() {
                assert_eq!(masks[i] & masks[j], 0);
            }
        }
    }

    #[test]
    fn active_session_count_tracks_distinct_connections() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        for i in 0..3u32 {
            let f = S7commFrame {
                connection_id: i,
                pdu_ref: 1,
                timestamp_us: 1_000 * u64::from(i),
                ..Default::default()
            };
            let _ = mon.inspect(&f);
        }
        assert_eq!(mon.active_session_count(), 3);
    }
}
