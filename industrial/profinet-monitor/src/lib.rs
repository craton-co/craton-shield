#![no_std]
#![deny(missing_docs)]

//! PROFINET IO intrusion detection monitor.
//!
//! Monitors PROFINET real-time traffic for anomalies:
//!
//! - **Frame ID allowlist** — restrict which RT frame IDs are permitted.
//! - **Cycle counter validation** — detect missed cycles and reject
//!   backward jumps as replay attempts (`ReplayDetected`).
//! - **IRT timing enforcement** — per-frame-ID `cycle_us ± jitter_us`
//!   window enforced via [`ProfinetMonitor::add_irt_rule`].
//! - **Data status monitoring** — alert on provider run/stop transitions.
//! - **DCP blocking** — block unauthorized Discovery and Configuration
//!   Protocol messages (can be used to rename/reconfigure devices). A
//!   per-service allowlist is available via [`ProfinetMonitor::set_dcp_policy`].
//! - **Alarm monitoring** — track alarm frequency and detect floods over
//!   a configurable timestamp window.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, InspectResult, RateBucket, SOURCE_PROFINET};

/// Backward-compatible type alias.
pub type ProfinetInspectResult = InspectResult;

// Re-export frame types for convenience.
pub use vs_types_ind::{ProfinetFrame, ProfinetFrameType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum frame ID rules.
const MAX_FRAME_RULES: usize = 32;

/// Maximum tracked cyclic connections.
const MAX_CYCLIC_CONNS: usize = 16;

/// Default missed cycle threshold before alert.
const DEFAULT_MISSED_CYCLE_THRESHOLD: u8 = 3;

/// Maximum rate-limiting buckets.
const MAX_RATE_BUCKETS: usize = 16;

/// Maximum alarm events in tracking window.
const MAX_ALARM_WINDOW: usize = 16;

/// Default alarm rate threshold (alarms per window).
const DEFAULT_ALARM_THRESHOLD: u8 = 10;

/// Default alarm window (60 seconds).
const DEFAULT_ALARM_WINDOW_US: u64 = 60_000_000;

/// Maximum configurable IRT (isochronous real-time) timing rules.
const MAX_IRT_RULES: usize = 8;

/// Width of the legitimate cycle-counter wraparound window.
///
/// A cycle counter that has just passed `0xFFFF - WRAP_WINDOW` and is
/// observed below `WRAP_WINDOW` is treated as a legitimate wrap rather
/// than a backward-jump replay attempt.
const WRAP_WINDOW: u16 = 256;

// ---------------------------------------------------------------------------
// PROFINET DCP service IDs
// ---------------------------------------------------------------------------

/// PROFINET DCP service: Get (read parameters from a device).
pub const DCP_SERVICE_GET: u8 = 0x03;
/// PROFINET DCP service: Set (write parameters — rename, re-IP, factory-reset).
pub const DCP_SERVICE_SET: u8 = 0x04;
/// PROFINET DCP service: Identify (discovery broadcast).
pub const DCP_SERVICE_IDENTIFY: u8 = 0x05;
/// PROFINET DCP service: Hello (multicast device announcement).
pub const DCP_SERVICE_HELLO: u8 = 0x06;

// Bit positions in `DcpPolicy::allowed_services`.
const DCP_BIT_GET: u16 = 1 << 0;
const DCP_BIT_SET: u16 = 1 << 1;
const DCP_BIT_IDENTIFY: u16 = 1 << 2;
const DCP_BIT_HELLO: u16 = 1 << 3;
/// Wildcard bit: allow any service id, including ones not enumerated
/// above. Set only by [`DcpPolicy::allow_all`] (and the legacy
/// `set_block_dcp(false)` compatibility shim) so that a hostile caller
/// can't fall through with an unrecognised service id under a policy
/// that meant to enumerate exactly which services are permitted.
const DCP_BIT_WILDCARD: u16 = 1 << 15;

#[inline]
const fn dcp_service_bit(service_id: u8) -> Option<u16> {
    match service_id {
        DCP_SERVICE_GET => Some(DCP_BIT_GET),
        DCP_SERVICE_SET => Some(DCP_BIT_SET),
        DCP_SERVICE_IDENTIFY => Some(DCP_BIT_IDENTIFY),
        DCP_SERVICE_HELLO => Some(DCP_BIT_HELLO),
        _ => None,
    }
}

/// Per-service DCP policy bitmask.
///
/// A `DcpPolicy` stores one bit per recognised DCP service. Unknown
/// service IDs are always rejected. Use the preset constructors below or
/// install one via [`ProfinetMonitor::set_dcp_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcpPolicy {
    allowed_services: u16,
}

impl DcpPolicy {
    /// Allow every DCP service — including unrecognised service IDs.
    /// Equivalent to disabling DCP blocking entirely
    /// (`set_block_dcp(false)`).
    #[must_use]
    pub const fn allow_all() -> Self {
        Self {
            allowed_services: DCP_BIT_GET
                | DCP_BIT_SET
                | DCP_BIT_IDENTIFY
                | DCP_BIT_HELLO
                | DCP_BIT_WILDCARD,
        }
    }

    /// Deny every DCP service — including discovery. This is the default
    /// posture in production and matches the legacy `block_dcp = true`
    /// behaviour.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allowed_services: 0,
        }
    }

    /// Commissioning preset: permit `Get`, `Identify`, and `Hello`
    /// (needed during device discovery / commissioning) while keeping
    /// the dangerous `Set` service (rename, re-IP, factory-reset)
    /// blocked.
    #[must_use]
    pub const fn commissioning() -> Self {
        Self {
            allowed_services: DCP_BIT_GET | DCP_BIT_IDENTIFY | DCP_BIT_HELLO,
        }
    }

    /// Returns `true` when this policy permits the given DCP service ID.
    ///
    /// Recognised service IDs (Get / Set / Identify / Hello) are checked
    /// against the bitmask. Unknown service IDs are permitted only when
    /// the policy is [`Self::allow_all`].
    #[must_use]
    pub const fn allows(&self, service_id: u8) -> bool {
        match dcp_service_bit(service_id) {
            Some(bit) => (self.allowed_services & bit) != 0,
            None => (self.allowed_services & DCP_BIT_WILDCARD) != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PROFINET data status bits
// ---------------------------------------------------------------------------

/// Data status bit: Provider State (0 = Stop, 1 = Run).
pub const DATA_STATUS_PROVIDER_RUN: u8 = 1 << 0;
/// Data status bit: Data Valid (0 = Invalid, 1 = Valid).
pub const DATA_STATUS_DATA_VALID: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// Frame rule
// ---------------------------------------------------------------------------

/// Action for a frame ID match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAction {
    /// Allow the frame to pass.
    Allow,
    /// Block the frame and emit an `EndpointBlocked` alert.
    Block,
}

/// A frame ID filtering rule.
#[derive(Debug, Clone, Copy)]
struct FrameRule {
    /// Frame ID (or start of range).
    frame_id_start: u16,
    /// End of frame ID range (inclusive). Same as start for single ID.
    frame_id_end: u16,
    action: FrameAction,
    active: bool,
    /// Maximum allowed requests per second (0 = unlimited).
    max_rate_per_sec: u16,
}

impl FrameRule {
    const fn empty() -> Self {
        Self {
            frame_id_start: 0,
            frame_id_end: 0,
            action: FrameAction::Allow,
            active: false,
            max_rate_per_sec: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Cyclic connection tracking
// ---------------------------------------------------------------------------

/// Per-connection cycle tracking state.
#[derive(Debug, Clone, Copy)]
struct CyclicConnection {
    frame_id: u16,
    last_cycle_counter: u16,
    missed_cycles: u8,
    /// Last known data status.
    last_data_status: u8,
    /// Provider was previously running.
    provider_was_running: bool,
    last_seen_us: u64,
    active: bool,
}

impl CyclicConnection {
    const fn empty() -> Self {
        Self {
            frame_id: 0,
            last_cycle_counter: 0,
            missed_cycles: 0,
            last_data_status: 0,
            provider_was_running: false,
            last_seen_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IRT (Isochronous Real-Time) timing rule
// ---------------------------------------------------------------------------

/// IRT timing window for a single frame ID.
///
/// Once an IRT rule has been installed for a frame ID, every subsequent
/// `CyclicRT` frame for that ID must arrive within
/// `cycle_us ± jitter_us` of the previously observed frame. Out-of-window
/// frames are denied and emit a `Severity::High` `SequenceAnomaly` alert.
#[derive(Debug, Clone, Copy)]
struct IrtRule {
    frame_id: u16,
    cycle_us: u32,
    jitter_us: u32,
    active: bool,
}

impl IrtRule {
    const fn empty() -> Self {
        Self {
            frame_id: 0,
            cycle_us: 0,
            jitter_us: 0,
            active: false,
        }
    }
}

/// Outcome of a per-frame-id rate-bucket check.
///
/// See [`ProfinetMonitor::rate_check`] for the semantics behind each
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateOutcome {
    /// A token was consumed — the frame is within its rate budget.
    Allowed,
    /// The matching bucket is exhausted (normal rate-limit hit).
    Limited,
    /// No matching bucket exists and the bucket table is full. The
    /// caller must deny the frame and emit a `ResourceExhausted` alert
    /// rather than evicting an existing bucket (VULN-08).
    BucketEvicted,
}

/// Classifies a cycle-counter transition as a replay (backward jump or
/// duplicate) or as a legitimate forward step.
///
/// The legitimate forward-wraparound `0xFFFF → 0` (with `new == last + 1`)
/// is handled by the caller and never reaches this function. A counter
/// that has just passed `0xFFFF - WRAP_WINDOW` and is now observed below
/// `WRAP_WINDOW` is treated as a legitimate wraparound; everything else
/// where `new <= last` is a replay.
#[inline]
fn is_replay(last: u16, new: u16) -> bool {
    if new == last {
        return true;
    }
    if new < last {
        // Possible legitimate wraparound: `last` was deep in the high band
        // and `new` has wrapped into the low band.
        let near_top = last > u16::MAX - WRAP_WINDOW;
        let near_bottom = new < WRAP_WINDOW;
        if near_top && near_bottom {
            return false;
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// PROFINET Monitor
// ---------------------------------------------------------------------------

/// PROFINET IO intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~1.5 KB.
/// - `rules`: 32 × 8 bytes = 256 bytes
/// - `cyclic_conns`: 16 × ~24 bytes = 384 bytes
/// - `alarm_timestamps`: 16 × 8 bytes = 128 bytes
/// - `rate_buckets`: 16 × ~28 bytes = 448 bytes
/// - `irt_rules`: 8 × ~12 bytes = 96 bytes
/// - DCP policy, scalars and counters: ~80 bytes
pub struct ProfinetMonitor {
    rules: [FrameRule; MAX_FRAME_RULES],
    rule_count: u8,
    cyclic_conns: [CyclicConnection; MAX_CYCLIC_CONNS],
    /// Current DCP per-service allowlist. Replaces the old single-bit
    /// `block_dcp` toggle but is kept in sync with it for backward
    /// compatibility via [`ProfinetMonitor::set_block_dcp`].
    dcp_policy: DcpPolicy,
    /// IRT timing-window rules, indexed by `frame_id` lookup.
    irt_rules: [IrtRule; MAX_IRT_RULES],
    /// Number of active IRT rules.
    irt_rule_count: u8,
    /// Cycle miss threshold.
    missed_cycle_threshold: u8,
    /// Alarm tracking — circular buffer of timestamps.
    alarm_timestamps: [u64; MAX_ALARM_WINDOW],
    /// Index of the next write position in the circular buffer.
    alarm_head: u8,
    /// Number of entries currently stored (capped at `MAX_ALARM_WINDOW`).
    alarm_total: u8,
    /// Snapshot of the in-window alarm count from the most recent
    /// [`Self::detect_alarm_flood`] call. Used only for diagnostics — the
    /// flood detector itself does not rely on this field, it recomputes
    /// the count from `alarm_timestamps` on every call.
    alarm_in_window: u8,
    alarm_threshold: u8,
    alarm_window_us: u64,
    /// Default action for unknown frame IDs.
    default_action: FrameAction,
    total_inspected: u64,
    total_alerts: u64,
    /// Monotonically increasing alert ID counter, starting at 1.
    next_alert_id: u64,
    /// Hint for cyclic connection lookup — last matched index.
    last_cyclic_idx: usize,
    /// Rate-limiting token buckets (keyed on full `u16` frame ID).
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Monotonic tick counter for rate-bucket LRU eviction ordering.
    rate_tick: u32,
}

impl ProfinetMonitor {
    /// Create a new PROFINET monitor.
    ///
    /// DCP is blocked by default (`DcpPolicy::deny_all`), unknown frame
    /// IDs are allowed, and no IRT timing rules are installed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: [FrameRule::empty(); MAX_FRAME_RULES],
            rule_count: 0,
            cyclic_conns: [CyclicConnection::empty(); MAX_CYCLIC_CONNS],
            // DCP blocked by default (security best practice).
            dcp_policy: DcpPolicy::deny_all(),
            irt_rules: [IrtRule::empty(); MAX_IRT_RULES],
            irt_rule_count: 0,
            missed_cycle_threshold: DEFAULT_MISSED_CYCLE_THRESHOLD,
            alarm_timestamps: [0u64; MAX_ALARM_WINDOW],
            alarm_head: 0,
            alarm_total: 0,
            alarm_in_window: 0,
            alarm_threshold: DEFAULT_ALARM_THRESHOLD,
            alarm_window_us: DEFAULT_ALARM_WINDOW_US,
            default_action: FrameAction::Allow,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            last_cyclic_idx: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            rate_tick: 0,
        }
    }

    /// Create a PROFINET monitor in strict mode (block unknown frame IDs).
    #[must_use]
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.default_action = FrameAction::Block;
        m
    }

    /// Block or allow *all* DCP messages.
    ///
    /// `true` installs [`DcpPolicy::deny_all`] (the default posture).
    /// `false` installs [`DcpPolicy::allow_all`]. For fine-grained per-
    /// service control use [`Self::set_dcp_policy`].
    pub fn set_block_dcp(&mut self, block: bool) {
        self.dcp_policy = if block {
            DcpPolicy::deny_all()
        } else {
            DcpPolicy::allow_all()
        };
    }

    /// Install a per-service DCP policy.
    ///
    /// Replaces any previous policy (including the default `deny_all`).
    /// Useful presets are [`DcpPolicy::commissioning`],
    /// [`DcpPolicy::allow_all`], and [`DcpPolicy::deny_all`].
    pub fn set_dcp_policy(&mut self, policy: DcpPolicy) {
        self.dcp_policy = policy;
    }

    /// Returns the current DCP policy.
    #[must_use]
    pub fn dcp_policy(&self) -> DcpPolicy {
        self.dcp_policy
    }

    /// Install an IRT (isochronous real-time) timing rule for a frame ID.
    ///
    /// `cycle_us` is the expected inter-arrival period; `jitter_us` is
    /// the tolerated deviation on either side. Frames falling outside the
    /// `cycle_us ± jitter_us` window are denied with a `Severity::High`
    /// `SequenceAnomaly` alert and do not advance the connection's
    /// timing baseline.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidInput`] if `cycle_us == 0` or
    ///   `jitter_us >= cycle_us` (a window that would cover an entire
    ///   sub-cycle is meaningless).
    /// - [`VsError::ResourceExhausted`] if the IRT rule table is full
    ///   (capacity = 8).
    pub fn add_irt_rule(
        &mut self,
        frame_id: u16,
        cycle_us: u32,
        jitter_us: u32,
    ) -> Result<(), VsError> {
        if cycle_us == 0 || jitter_us >= cycle_us {
            return Err(VsError::InvalidInput);
        }
        if self.irt_rule_count as usize >= MAX_IRT_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.irt_rule_count as usize;
        self.irt_rules[idx] = IrtRule {
            frame_id,
            cycle_us,
            jitter_us,
            active: true,
        };
        self.irt_rule_count += 1;
        Ok(())
    }

    /// Set missed cycle threshold.
    pub fn set_missed_cycle_threshold(&mut self, threshold: u8) {
        self.missed_cycle_threshold = threshold;
    }

    /// Set alarm rate detection parameters.
    pub fn set_alarm_params(&mut self, threshold: u8, window_us: u64) {
        self.alarm_threshold = threshold;
        self.alarm_window_us = window_us;
    }

    /// Add a frame ID rule (single ID).
    pub fn add_frame_rule(
        &mut self,
        frame_id: u16,
        action: FrameAction,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        self.add_frame_range_rule(frame_id, frame_id, action, max_rate_per_sec)
    }

    /// Add a frame ID range rule.
    pub fn add_frame_range_rule(
        &mut self,
        start: u16,
        end: u16,
        action: FrameAction,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_FRAME_RULES {
            return Err(VsError::ResourceExhausted);
        }
        if start > end {
            return Err(VsError::InvalidInput);
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = FrameRule {
            frame_id_start: start,
            frame_id_end: end,
            action,
            active: true,
            max_rate_per_sec,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Inspect a PROFINET frame.
    pub fn inspect(&mut self, frame: &vs_types_ind::ProfinetFrame) -> ProfinetInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_PROFINET);

        // Reject frames with payload_len exceeding the buffer size.
        if frame.payload_len_overflow() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_PROFINET,
                frame.frame_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PayloadOverflow,
            );
            return result;
        }

        // DCP per-service allowlist.
        //
        // The DCP service id is carried in `transfer_status` on the inspected
        // frame. Unknown service ids (or any service the policy doesn't
        // explicitly allow) are denied. The alert encodes the service id in
        // the high byte of `source_id` so downstream dedup can distinguish
        // "DCP-Set blocked" from "DCP-Identify blocked".
        if frame.frame_type == vs_types_ind::ProfinetFrameType::Dcp {
            let svc = frame.transfer_status;
            if !self.dcp_policy.allows(svc) {
                let code = if dcp_service_bit(svc).is_none() {
                    AlertCode::DcpBlocked
                } else {
                    AlertCode::PolicyViolation
                };
                let source_id = (u32::from(svc) << 16) | u32::from(frame.frame_id);
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_PROFINET,
                    source_id,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    code,
                );
                return result;
            }
        }

        // Alarm monitoring.
        if frame.frame_type == vs_types_ind::ProfinetFrameType::Alarm {
            self.record_alarm(frame.timestamp_us);
            if self.detect_alarm_flood(frame.timestamp_us) {
                // Alarm flood is a blocking condition: an attacker can use a
                // flood of PROFINET alarms to saturate the controller's alarm
                // queue and mask real process faults. Block the frame so the
                // host can rate-limit or drop it, consistent with DCP blocking
                // and rate-limit enforcement elsewhere in this monitor.
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_PROFINET,
                    frame.frame_id as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::AlarmFlood,
                );
                return result;
            }
        }

        // Frame ID filtering.
        let (action, matched_rule_idx) = self.find_frame_action(frame.frame_id);
        if action == FrameAction::Block {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_PROFINET,
                frame.frame_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::EndpointBlocked,
            );
            return result;
        }

        // Rate limiting (for matched Allow rules).
        if let Some(ri) = matched_rule_idx {
            let rate = self.rules[ri].max_rate_per_sec;
            if rate > 0 {
                match self.rate_check(frame.frame_id, rate, frame.timestamp_us) {
                    RateOutcome::Allowed => {}
                    RateOutcome::Limited => {
                        result.allowed = false;
                        result.push_alert_with_code(
                            AlertSeverity::Medium,
                            SOURCE_PROFINET,
                            frame.frame_id as u32,
                            frame.timestamp_us,
                            &mut self.next_alert_id,
                            &mut self.total_alerts,
                            AlertCode::RateExceeded,
                        );
                        return result;
                    }
                    RateOutcome::BucketEvicted => {
                        // VULN-08: bucket table is full and the frame does
                        // not match any existing bucket. Deny without
                        // evicting a legitimate bucket — otherwise an
                        // attacker cycling fresh frame_ids could reset the
                        // rate state of an already-exhausted id.
                        result.allowed = false;
                        result.push_alert_with_code(
                            AlertSeverity::High,
                            SOURCE_PROFINET,
                            frame.frame_id as u32,
                            frame.timestamp_us,
                            &mut self.next_alert_id,
                            &mut self.total_alerts,
                            AlertCode::ResourceExhausted,
                        );
                        return result;
                    }
                }
            }
        }

        // Cyclic RT frame tracking.
        if frame.frame_type == vs_types_ind::ProfinetFrameType::CyclicRT {
            self.check_cyclic(frame, &mut result);
        }

        result
    }

    /// Total number of frames inspected since creation.
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Total number of alerts generated since creation.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Current value of the next alert ID counter.
    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Find the first matching frame rule.
    ///
    /// Returns the first rule whose `[frame_id_start, frame_id_end]` range
    /// contains `frame_id`, short-circuiting on match. The monitor does
    /// not handle cryptographic secrets, so timing-side-channel resistance
    /// is not a goal here.
    fn find_frame_action(&self, frame_id: u16) -> (FrameAction, Option<usize>) {
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && frame_id >= self.rules[i].frame_id_start
                && frame_id <= self.rules[i].frame_id_end
            {
                return (self.rules[i].action, Some(i));
            }
        }
        (self.default_action, None)
    }

    fn check_cyclic(
        &mut self,
        frame: &vs_types_ind::ProfinetFrame,
        result: &mut ProfinetInspectResult,
    ) {
        let threshold = self.missed_cycle_threshold;

        let ci = self.get_or_create_conn_idx(frame.frame_id);

        // Was this connection already established?
        let first_seen = self.cyclic_conns[ci].last_seen_us == 0;

        // --- VULN-07: IRT timing-window enforcement ----------------------
        //
        // If an IRT rule covers this frame ID, the inter-arrival delta must
        // fall inside `cycle_us ± jitter_us`. Out-of-window frames are
        // denied and do NOT advance the baseline — otherwise an attacker
        // who slipped one bad-cadence frame past us would resync the
        // monitor to their timing.
        let irt_rule = if first_seen {
            None
        } else {
            self.find_irt_rule(frame.frame_id)
        };
        if let Some(rule) = irt_rule {
            let delta = frame
                .timestamp_us
                .saturating_sub(self.cyclic_conns[ci].last_seen_us);
            let cycle = u64::from(rule.cycle_us);
            let jitter = u64::from(rule.jitter_us);
            let min = cycle.saturating_sub(jitter);
            let max = cycle.saturating_add(jitter);
            if delta < min || delta > max {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_PROFINET,
                    frame.frame_id as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::SequenceAnomaly,
                );
                return;
            }
        }

        // --- VULN-05: cycle-counter direction validation -----------------
        //
        // Treat a backward jump (or duplicate) as a replay attempt and
        // emit a High `ReplayDetected`. The legitimate forward-wraparound
        // 0xFFFF → 0 has delta == 1 (matches `expected` below) and never
        // reaches this branch. Outside that, a counter regressing into
        // the past or repeating an already-seen value is unconditionally
        // suspicious. The connection's `last_cycle_counter` is NOT
        // advanced on a detected replay, so the legitimate provider's
        // sequence is not poisoned.
        let provider_running = frame.data_status & DATA_STATUS_PROVIDER_RUN != 0;
        if !first_seen {
            let last = self.cyclic_conns[ci].last_cycle_counter;
            let expected = last.wrapping_add(1);
            if frame.cycle_counter == expected {
                self.cyclic_conns[ci].missed_cycles = 0;
            } else if is_replay(last, frame.cycle_counter) {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_PROFINET,
                    frame.frame_id as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::ReplayDetected,
                );
                return;
            } else {
                // Forward skip — legacy "missed cycle" behaviour.
                self.cyclic_conns[ci].missed_cycles =
                    self.cyclic_conns[ci].missed_cycles.saturating_add(1);
                if self.cyclic_conns[ci].missed_cycles >= threshold {
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_PROFINET,
                        frame.frame_id as u32,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::SequenceAnomaly,
                    );
                    self.cyclic_conns[ci].missed_cycles = 0;
                }
            }
        }

        // Provider state transition monitoring.
        if self.cyclic_conns[ci].provider_was_running && !provider_running {
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_PROFINET,
                frame.frame_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::ProviderStateChange,
            );
        }

        self.cyclic_conns[ci].last_cycle_counter = frame.cycle_counter;
        self.cyclic_conns[ci].last_data_status = frame.data_status;
        self.cyclic_conns[ci].provider_was_running = provider_running;
        self.cyclic_conns[ci].last_seen_us = frame.timestamp_us;
    }

    /// Linear lookup of the IRT rule for a frame ID, if any.
    fn find_irt_rule(&self, frame_id: u16) -> Option<IrtRule> {
        for i in 0..self.irt_rule_count as usize {
            if self.irt_rules[i].active && self.irt_rules[i].frame_id == frame_id {
                return Some(self.irt_rules[i]);
            }
        }
        None
    }

    fn get_or_create_conn_idx(&mut self, frame_id: u16) -> usize {
        // Fast path: temporal locality hint.
        let hint = self.last_cyclic_idx;
        if hint < MAX_CYCLIC_CONNS
            && self.cyclic_conns[hint].active
            && self.cyclic_conns[hint].frame_id == frame_id
        {
            return hint;
        }

        // Single-pass: find matching, first empty, and oldest simultaneously.
        let mut first_empty: Option<usize> = None;
        let mut oldest_idx: usize = 0;
        let mut oldest_ts: u64 = u64::MAX;

        for (i, c) in self.cyclic_conns.iter().enumerate() {
            if c.active {
                if c.frame_id == frame_id {
                    self.last_cyclic_idx = i;
                    return i;
                }
                if c.last_seen_us < oldest_ts {
                    oldest_ts = c.last_seen_us;
                    oldest_idx = i;
                }
            } else if first_empty.is_none() {
                first_empty = Some(i);
            }
        }

        // Use first empty slot, or evict oldest.
        let slot = first_empty.unwrap_or(oldest_idx);
        self.cyclic_conns[slot] = CyclicConnection::empty();
        self.cyclic_conns[slot].frame_id = frame_id;
        self.cyclic_conns[slot].active = true;
        self.last_cyclic_idx = slot;
        slot
    }

    /// Record an alarm timestamp using a circular buffer (O(1)).
    ///
    /// The `alarm_in_window` field is maintained entirely by
    /// [`Self::detect_alarm_flood`] — a single source of truth — so that the
    /// counter can't drift out of sync with the timestamp buffer.
    fn record_alarm(&mut self, ts_us: u64) {
        let idx = self.alarm_head as usize;
        self.alarm_timestamps[idx] = ts_us;
        self.alarm_head = ((self.alarm_head as usize + 1) % MAX_ALARM_WINDOW) as u8;
        if (self.alarm_total as usize) < MAX_ALARM_WINDOW {
            self.alarm_total += 1;
        }
    }

    /// Alarm flood detection — authoritative recount of entries within the
    /// configured window. Runs in O(`MAX_ALARM_WINDOW`) which is a small
    /// constant, and guarantees the returned value reflects the real state
    /// of the circular buffer.
    ///
    /// **Trade-off**: We re-scan the entire circular buffer on every call rather
    /// than maintaining an incrementing counter. The extra work is bounded by
    /// `MAX_ALARM_WINDOW` (a small compile-time constant) and buys correctness:
    /// a single source of truth means the in-window count can never drift out of
    /// sync with the timestamp buffer regardless of clock skew or late arrivals.
    fn detect_alarm_flood(&mut self, now_us: u64) -> bool {
        let mut count: u8 = 0;
        for i in 0..self.alarm_total as usize {
            if now_us.saturating_sub(self.alarm_timestamps[i]) <= self.alarm_window_us {
                count = count.saturating_add(1);
            }
        }
        self.alarm_in_window = count;
        count >= self.alarm_threshold
    }

    /// Per-frame-id rate check.
    ///
    /// Uses the **full** `u16` frame ID as the bucket key — never a truncated
    /// 8-bit value — so an attacker cannot collide buckets by choosing frame
    /// IDs with colliding low bytes.
    ///
    /// Returns:
    /// - [`RateOutcome::Allowed`] — bucket existed or was allocated and a
    ///   token was consumed.
    /// - [`RateOutcome::Limited`] — bucket existed but is exhausted (normal
    ///   rate-limit hit).
    /// - [`RateOutcome::BucketEvicted`] — no matching bucket and the table
    ///   is full. **No bucket is mutated**, preserving rate state for the
    ///   already-tracked frame IDs (see VULN-08).
    fn rate_check(&mut self, frame_id: u16, max_rate: u16, now_us: u64) -> RateOutcome {
        let key = frame_id as u32;
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;

        // Single-pass: find matching bucket and first free slot.
        let mut first_free: Option<usize> = None;
        for (i, b) in self.rate_buckets.iter_mut().enumerate() {
            if b.active {
                if b.key == key {
                    b.last_used = now_tick;
                    return if b.try_consume(now_us) {
                        RateOutcome::Allowed
                    } else {
                        RateOutcome::Limited
                    };
                }
            } else if first_free.is_none() {
                first_free = Some(i);
            }
        }

        // No matching bucket. Allocate only when a free slot is available;
        // refuse to evict a legitimate bucket because doing so would let
        // an attacker cycling fresh frame IDs reset the rate-state of an
        // already-exhausted id (VULN-08).
        let Some(slot) = first_free else {
            return RateOutcome::BucketEvicted;
        };
        self.rate_buckets[slot] = RateBucket {
            key,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
            last_used: now_tick,
        };
        RateOutcome::Allowed
    }

    /// Reset all monitor state — rules, cyclic connections, alarm tracking,
    /// and statistics. Configuration like the DCP policy, `default_action`,
    /// and thresholds is preserved.
    pub fn reset(&mut self) {
        let dcp_policy = self.dcp_policy;
        let missed_cycle_threshold = self.missed_cycle_threshold;
        let alarm_threshold = self.alarm_threshold;
        let alarm_window_us = self.alarm_window_us;
        let default_action = self.default_action;
        *self = Self::new();
        self.dcp_policy = dcp_policy;
        self.missed_cycle_threshold = missed_cycle_threshold;
        self.alarm_threshold = alarm_threshold;
        self.alarm_window_us = alarm_window_us;
        self.default_action = default_action;
    }
}

impl Default for ProfinetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use vs_types_ind::ProfinetFrameType;

    fn make_cyclic(
        frame_id: u16,
        cycle: u16,
        data_status: u8,
        ts_us: u64,
    ) -> vs_types_ind::ProfinetFrame {
        // ProfinetFrame has private payload fields, so construct via
        // Default::default() and mutate only the public scalar fields.
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::CyclicRT;
        f.frame_id = frame_id;
        f.cycle_counter = cycle;
        f.data_status = data_status;
        f.timestamp_us = ts_us;
        f
    }

    fn make_dcp(ts_us: u64) -> vs_types_ind::ProfinetFrame {
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::Dcp;
        f.timestamp_us = ts_us;
        f
    }

    fn make_alarm(ts_us: u64) -> vs_types_ind::ProfinetFrame {
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::Alarm;
        f.timestamp_us = ts_us;
        f
    }

    /// Construct a DCP frame carrying the given service id in
    /// `transfer_status` (the field the inspector reads to apply the
    /// per-service [`DcpPolicy`]).
    fn make_dcp_service(service_id: u8, ts_us: u64) -> vs_types_ind::ProfinetFrame {
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::Dcp;
        f.transfer_status = service_id;
        f.timestamp_us = ts_us;
        f
    }

    #[test]
    fn dcp_blocked_by_default() {
        let mut mon = ProfinetMonitor::new();
        let f = make_dcp(1000);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn dcp_allowed_when_enabled() {
        let mut mon = ProfinetMonitor::new();
        mon.set_block_dcp(false);
        let f = make_dcp(1000);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_mode_blocks_unknown() {
        let mut mon = ProfinetMonitor::new_strict();
        let f = make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn allowed_frame_id() {
        let mut mon = ProfinetMonitor::new_strict();
        mon.add_frame_rule(0x8000, FrameAction::Allow, 0).unwrap();
        let f = make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn frame_id_range() {
        let mut mon = ProfinetMonitor::new_strict();
        mon.add_frame_range_rule(0x8000, 0x800F, FrameAction::Allow, 0)
            .unwrap();

        let f1 = make_cyclic(0x8005, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        assert!(mon.inspect(&f1).allowed);

        let f2 = make_cyclic(0x8010, 1, DATA_STATUS_PROVIDER_RUN, 2000);
        assert!(!mon.inspect(&f2).allowed);
    }

    #[test]
    fn sequential_cycles_ok() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(3);

        for i in 0..5 {
            let f = make_cyclic(
                0x8000,
                i + 1,
                DATA_STATUS_PROVIDER_RUN,
                (i as u64 + 1) * 1000,
            );
            let r = mon.inspect(&f);
            assert_eq!(r.alert_count, 0, "cycle {} should be clean", i + 1);
        }
    }

    #[test]
    fn missed_cycles_alert() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(2);

        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000));

        let r = mon.inspect(&make_cyclic(0x8000, 10, DATA_STATUS_PROVIDER_RUN, 2000));
        assert_eq!(r.alert_count, 0);

        let r = mon.inspect(&make_cyclic(0x8000, 20, DATA_STATUS_PROVIDER_RUN, 3000));
        assert!(r.alert_count > 0);
    }

    #[test]
    fn provider_stop_alert() {
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000));
        let r = mon.inspect(&make_cyclic(0x8000, 2, 0, 2000));
        assert!(r.alert_count > 0);
    }

    #[test]
    fn provider_already_stopped_no_alert() {
        let mut mon = ProfinetMonitor::new();
        let r1 = mon.inspect(&make_cyclic(0x8000, 1, 0, 1000));
        assert_eq!(r1.alert_count, 0);
        let r2 = mon.inspect(&make_cyclic(0x8000, 2, 0, 2000));
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn alarm_flood_detected() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(5, 10_000_000);

        for i in 0..4 {
            let f = make_alarm(1_000_000 * (i + 1));
            let r = mon.inspect(&f);
            assert_eq!(r.alert_count, 0, "alarm {i} within threshold");
        }

        let r = mon.inspect(&make_alarm(5_000_000));
        assert!(r.alert_count > 0);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_dcp(1000));
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 2000));
        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1); // DCP blocked
    }

    #[test]
    fn add_frame_rule_when_full() {
        let mut mon = ProfinetMonitor::new();
        for i in 0..32u16 {
            mon.add_frame_rule(i, FrameAction::Allow, 0).unwrap();
        }
        assert!(mon.add_frame_rule(100, FrameAction::Allow, 0).is_err());
    }

    #[test]
    fn add_frame_range_invalid() {
        let mut mon = ProfinetMonitor::new();
        assert!(mon
            .add_frame_range_rule(100, 50, FrameAction::Allow, 0)
            .is_err());
    }

    #[test]
    fn block_specific_frame_id() {
        let mut mon = ProfinetMonitor::new();
        mon.add_frame_rule(0xBEEF, FrameAction::Block, 0).unwrap();
        let f = make_cyclic(0xBEEF, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn acyclic_frame_passes() {
        let mut mon = ProfinetMonitor::new();
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::AcyclicRT;
        f.frame_id = 0x100;
        f.timestamp_us = 1000;
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cycle_counter_wrapping() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(3);

        let _ = mon.inspect(&make_cyclic(0x8000, 65534, DATA_STATUS_PROVIDER_RUN, 1000));

        let r = mon.inspect(&make_cyclic(0x8000, 65535, DATA_STATUS_PROVIDER_RUN, 2000));
        assert_eq!(r.alert_count, 0);

        let r = mon.inspect(&make_cyclic(0x8000, 0, DATA_STATUS_PROVIDER_RUN, 3000));
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn provider_start_no_alert() {
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, 0, 1000));
        let r = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 2000));
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn data_valid_bit() {
        let mut mon = ProfinetMonitor::new();
        let f = make_cyclic(
            0x8000,
            1,
            DATA_STATUS_PROVIDER_RUN | DATA_STATUS_DATA_VALID,
            1000,
        );
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn alarm_window_overflow() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(50, 100_000_000);
        for i in 0..20 {
            let _ = mon.inspect(&make_alarm(1_000_000 * (i + 1)));
        }
        assert!(mon.total_inspected() >= 20);
    }

    #[test]
    fn default_constructor() {
        let mon = ProfinetMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
    }

    #[test]
    fn multiple_cyclic_connections() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(2);
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000));
        let _ = mon.inspect(&make_cyclic(0x8001, 1, DATA_STATUS_PROVIDER_RUN, 1000));
        let r1 = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 2000));
        let r2 = mon.inspect(&make_cyclic(0x8001, 2, DATA_STATUS_PROVIDER_RUN, 2000));
        assert_eq!(r1.alert_count, 0);
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn first_cycle_no_validation() {
        let mut mon = ProfinetMonitor::new();
        let r = mon.inspect(&make_cyclic(0x8000, 100, DATA_STATUS_PROVIDER_RUN, 1000));
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn cyclic_conn_eviction_when_full() {
        let mut mon = ProfinetMonitor::new();
        for i in 0..16u16 {
            let f = make_cyclic(
                0x8000 + i,
                1,
                DATA_STATUS_PROVIDER_RUN,
                (i as u64 + 1) * 1000,
            );
            let _ = mon.inspect(&f);
        }
        let f = make_cyclic(0x9000, 1, DATA_STATUS_PROVIDER_RUN, 20_000);
        let r = mon.inspect(&f);
        assert!(r.allowed);
        let f2 = make_cyclic(0x8000, 100, DATA_STATUS_PROVIDER_RUN, 21_000);
        let r2 = mon.inspect(&f2);
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn alarm_below_threshold_no_alert() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(5, 10_000_000);
        for i in 0..4 {
            let r = mon.inspect(&make_alarm(1_000_000 * (i + 1)));
            assert_eq!(r.alert_count, 0, "alarm {i} should be within threshold");
        }
    }

    #[test]
    fn payload_len_overflow_rejected() {
        let mut mon = ProfinetMonitor::new();
        // Force payload_len out of range to simulate a malformed FFI
        // frame — the validated set_payload() can no longer produce this,
        // but the monitor must still defend against ABI-level corruption.
        let mut f = vs_types_ind::ProfinetFrame::default();
        f.frame_type = ProfinetFrameType::CyclicRT;
        f.frame_id = 0x8000;
        f.timestamp_us = 1000;
        f.__set_payload_len_unchecked(300);
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn cycle_counter_zero_not_special_cased() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(1);
        let _ = mon.inspect(&make_cyclic(0x8000, 5, DATA_STATUS_PROVIDER_RUN, 1000));
        let r = mon.inspect(&make_cyclic(0x8000, 0, DATA_STATUS_PROVIDER_RUN, 2000));
        assert!(
            r.alert_count > 0,
            "cycle_counter=0 should trigger missed-cycle alert"
        );
    }

    #[test]
    fn reset_clears_state() {
        let mut mon = ProfinetMonitor::new_strict();
        mon.set_alarm_params(5, 10_000_000);
        mon.add_frame_rule(0x8000, FrameAction::Allow, 0).unwrap();
        let f = make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        let _ = mon.inspect(&f);
        assert_eq!(mon.total_inspected(), 1);
        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
        let f = make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 2000);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn alert_id_starts_at_one() {
        let mon = ProfinetMonitor::new();
        assert_eq!(mon.next_alert_id(), 1);
    }

    #[test]
    fn alert_ids_unique_and_incrementing() {
        let mut mon = ProfinetMonitor::new();
        let r1 = mon.inspect(&make_dcp(1000));
        assert_eq!(r1.alert_count, 1);
        assert_eq!(r1.alerts[0].id, 1);
        assert_eq!(mon.next_alert_id(), 2);
        let r2 = mon.inspect(&make_dcp(2000));
        assert_eq!(r2.alert_count, 1);
        assert_eq!(r2.alerts[0].id, 2);
        assert_eq!(mon.next_alert_id(), 3);
        mon.add_frame_rule(0xDEAD, FrameAction::Block, 0).unwrap();
        let r3 = mon.inspect(&make_cyclic(0xDEAD, 1, DATA_STATUS_PROVIDER_RUN, 3000));
        assert_eq!(r3.alert_count, 1);
        assert_eq!(r3.alerts[0].id, 3);
        assert_eq!(mon.next_alert_id(), 4);
    }

    #[test]
    fn alert_ids_across_multiple_alerts_in_single_inspect() {
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(1);
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000));
        let id_before = mon.next_alert_id();
        let r = mon.inspect(&make_cyclic(0x8000, 10, 0, 2000));
        assert_eq!(r.alert_count, 2);
        assert_eq!(r.alerts[0].id, id_before);
        assert_eq!(r.alerts[1].id, id_before + 1);
        assert_eq!(mon.next_alert_id(), id_before + 2);
    }

    #[test]
    fn alert_counting_consistency() {
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_dcp(1000));
        let _ = mon.inspect(&make_dcp(2000));
        assert_eq!(mon.total_alerts(), 2);
    }

    #[test]
    fn circular_buffer_overwrites_oldest() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(100, 10_000_000);
        for i in 0..MAX_ALARM_WINDOW {
            let _ = mon.inspect(&make_alarm((i as u64 + 1) * 1_000));
        }
        assert_eq!(mon.alarm_total as usize, MAX_ALARM_WINDOW);
        for i in 0..4 {
            let _ = mon.inspect(&make_alarm(100_000 + (i as u64 + 1) * 1_000));
        }
        assert_eq!(mon.alarm_total as usize, MAX_ALARM_WINDOW);
    }

    #[test]
    fn circular_buffer_flood_detection_after_overflow() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(5, 10_000_000);
        for i in 0..20u64 {
            let _ = mon.inspect(&make_alarm((i + 1) * 100));
        }
        // Now at time 100_000_000, old entries are outside the window.
        // Flood detection resets because old entries age out.
        // With O(1) detection, the in-window count tracks this.
        // After 20 alarms close together, alarm_in_window may be saturated.
        // Send fresh alarms at widely spaced times.
        let mut mon2 = ProfinetMonitor::new();
        mon2.set_alarm_params(5, 10_000_000);
        // 4 alarms within window.
        for i in 1..5 {
            let r = mon2.inspect(&make_alarm(100_000_000 + i * 1_000));
            assert_eq!(
                r.alert_count, 0,
                "alarm {i} should still be below threshold"
            );
        }
        // 5th alarm triggers flood.
        let r = mon2.inspect(&make_alarm(100_004_000));
        assert!(
            r.alert_count > 0,
            "flood should be detected after 5 alarms in window"
        );
    }

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = ProfinetMonitor::new();
        mon.add_frame_rule(0x8000, FrameAction::Allow, 3).unwrap();
        for i in 0..3u64 {
            let f = make_cyclic(0x8000, (i + 1) as u16, DATA_STATUS_PROVIDER_RUN, i * 100);
            assert!(mon.inspect(&f).allowed, "req {i} should pass");
        }
        let f = make_cyclic(0x8000, 4, DATA_STATUS_PROVIDER_RUN, 300);
        assert!(!mon.inspect(&f).allowed, "4th should be rate limited");
    }

    #[test]
    fn rate_limiting_recovers_after_refill() {
        let mut mon = ProfinetMonitor::new();
        mon.add_frame_rule(0x8000, FrameAction::Allow, 2).unwrap();
        let f1 = make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 0);
        let f2 = make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 0);
        assert!(mon.inspect(&f1).allowed);
        assert!(mon.inspect(&f2).allowed);
        let f3 = make_cyclic(0x8000, 3, DATA_STATUS_PROVIDER_RUN, 0);
        assert!(!mon.inspect(&f3).allowed);
        // After 1 second, tokens refill
        let f4 = make_cyclic(0x8000, 4, DATA_STATUS_PROVIDER_RUN, 1_000_000);
        assert!(mon.inspect(&f4).allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: rate-limit key collision bypass (H3).
    //
    // Previously the rate-limit bucket was keyed on `frame_id as u8`, so
    // frame IDs differing only in their high byte (e.g. 0x0100, 0x0200,
    // 0x0300, …) collapsed into a single shared bucket. An attacker could
    // exhaust a single bucket and then evade the limit by cycling the
    // high byte. The fix uses the full u16 frame id as the key.
    // -----------------------------------------------------------------------
    #[test]
    fn rate_limit_does_not_collide_on_low_byte() {
        let mut mon = ProfinetMonitor::new();
        // Two distinct rules, same low byte.
        mon.add_frame_rule(0x0100, FrameAction::Allow, 1).unwrap();
        mon.add_frame_rule(0x0200, FrameAction::Allow, 1).unwrap();

        // Each frame id should get its own bucket of 1 token.
        let a1 = make_cyclic(0x0100, 1, DATA_STATUS_PROVIDER_RUN, 0);
        let b1 = make_cyclic(0x0200, 1, DATA_STATUS_PROVIDER_RUN, 0);
        assert!(mon.inspect(&a1).allowed);
        assert!(mon.inspect(&b1).allowed);

        // The second frame for each id is rate-limited — independently.
        let a2 = make_cyclic(0x0100, 2, DATA_STATUS_PROVIDER_RUN, 0);
        let b2 = make_cyclic(0x0200, 2, DATA_STATUS_PROVIDER_RUN, 0);
        assert!(!mon.inspect(&a2).allowed);
        assert!(!mon.inspect(&b2).allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: alarm flood counter drift (M1).
    //
    // `detect_alarm_flood` is the single source of truth for the in-window
    // count. Record some alarms, step time past the window, and verify
    // the flood detector correctly returns false.
    // -----------------------------------------------------------------------
    #[test]
    fn alarm_counter_does_not_drift_after_window_expiry() {
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(3, 1_000_000); // 3 alarms / 1s window
        for i in 0..3u64 {
            let f = make_alarm(i * 100);
            let _ = mon.inspect(&f);
        }
        // Exactly at threshold inside window — flood flagged.
        // Now step time beyond the window; the next alarm should NOT be
        // classified as a flood.
        let later = make_alarm(10_000_000);
        let r = mon.inspect(&later);
        // The single alarm outside the window is not itself a flood.
        assert!(
            r.allowed || r.alert_count == 0,
            "single alarm outside window should not flood-alert"
        );
    }

    // -----------------------------------------------------------------------
    // VULN-04: Alarm flood must be a blocking condition.
    //
    // Prior to the fix, `detect_alarm_flood` emitted a medium-severity alert
    // but did NOT set `allowed = false`, meaning a flood of PROFINET alarms
    // would be logged but the frames would continue to the controller.  An
    // attacker could saturate the alarm queue and mask real process faults.
    // After the fix the frame is blocked (allowed = false) and the alert
    // severity is High.
    // -----------------------------------------------------------------------

    #[test]
    fn vuln04_alarm_flood_blocks_frame() {
        let mut mon = ProfinetMonitor::new();
        // Low threshold: 2 alarms / 1 s window.
        mon.set_alarm_params(2, 1_000_000);
        // Send two alarms within the window to reach the threshold.
        let _ = mon.inspect(&make_alarm(100));
        let _ = mon.inspect(&make_alarm(200));
        // Third alarm — flood threshold exceeded, frame must be blocked.
        let r = mon.inspect(&make_alarm(300));
        assert!(
            !r.allowed,
            "alarm flood must block the frame (allowed must be false)"
        );
        assert!(
            r.alert_count >= 1,
            "at least one alert expected for alarm flood"
        );
    }

    #[test]
    fn vuln04_alarm_flood_alert_is_high_severity() {
        use vs_types::AlertSeverity;
        let mut mon = ProfinetMonitor::new();
        mon.set_alarm_params(1, 1_000_000); // threshold = 1: first alarm triggers flood
        let _ = mon.inspect(&make_alarm(100));
        // Second alarm within the window should trigger a High-severity alert.
        let r = mon.inspect(&make_alarm(200));
        assert!(!r.allowed, "alarm flood must block the frame");
        // Check that at least one alert is High severity.
        let has_high =
            (0..r.alert_count as usize).any(|i| r.alerts[i].severity == AlertSeverity::High);
        assert!(has_high, "alarm flood alert must be High severity");
    }

    // -----------------------------------------------------------------------
    // VULN-05: Cycle-counter direction not validated (replay/rewind attack).
    //
    // Previously `check_cyclic` treated any non-`expected` counter as a
    // "missed cycle" and emitted only a Medium non-blocking alert after
    // `threshold` consecutive mismatches.  After threshold it also
    // *unconditionally* advanced `last_cycle_counter` to the attacker's
    // value, poisoning the legitimate provider's sequence.
    //
    // After the fix:
    //   - A backward jump (delta >= 0x8000) or duplicate (delta == 0) emits
    //     an immediate High `ReplayDetected` alert and sets `allowed = false`.
    //   - `last_cycle_counter` and `last_data_status` are NOT advanced on
    //     such events.
    //   - Forward skips (1 < delta < 0x8000) keep the existing
    //     "missed-cycles" Medium-after-threshold behaviour.
    // -----------------------------------------------------------------------
    #[test]
    fn vuln05_cycle_counter_backward_jump_blocked_and_alerted() {
        use vs_types::AlertSeverity;
        let mut mon = ProfinetMonitor::new();
        // Establish baseline: last_cycle_counter = 1000.
        let _ = mon.inspect(&make_cyclic(0x8000, 1000, DATA_STATUS_PROVIDER_RUN, 1000));
        // Attacker injects a frame with cycle_counter = 500 (backward).
        let r = mon.inspect(&make_cyclic(0x8000, 500, DATA_STATUS_PROVIDER_RUN, 2000));
        assert!(!r.allowed, "backward cycle counter must block the frame");
        assert!(r.alert_count >= 1, "backward cycle must emit an alert");
        let has_high =
            (0..r.alert_count as usize).any(|i| r.alerts[i].severity == AlertSeverity::High);
        assert!(has_high, "backward cycle alert must be High severity");
    }

    #[test]
    fn vuln05_cycle_counter_duplicate_blocked_and_alerted() {
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_cyclic(0x8000, 42, DATA_STATUS_PROVIDER_RUN, 1000));
        // Attacker replays the same cycle_counter.
        let r = mon.inspect(&make_cyclic(0x8000, 42, DATA_STATUS_PROVIDER_RUN, 2000));
        assert!(!r.allowed, "duplicate cycle counter must block the frame");
        assert!(r.alert_count >= 1, "duplicate cycle must emit an alert");
    }

    #[test]
    fn vuln05_state_not_poisoned_by_replay() {
        // After a backward-jump replay, the legitimate provider's next frame
        // (which is just `last + 1` from the legitimate sequence) must NOT
        // look like a "missed" frame — i.e. `last_cycle_counter` must not
        // have been advanced to the attacker's value.
        let mut mon = ProfinetMonitor::new();
        // Baseline: provider has emitted cycle 1000.
        let _ = mon.inspect(&make_cyclic(0x8000, 1000, DATA_STATUS_PROVIDER_RUN, 1000));
        // Attacker injects cycle 500 (backward).
        let _ = mon.inspect(&make_cyclic(0x8000, 500, DATA_STATUS_PROVIDER_RUN, 2000));
        // Legitimate next cycle from the real provider: 1001.
        let r = mon.inspect(&make_cyclic(0x8000, 1001, DATA_STATUS_PROVIDER_RUN, 3000));
        assert!(
            r.allowed,
            "legitimate next frame must still be allowed after replay attempt"
        );
        assert_eq!(
            r.alert_count, 0,
            "legitimate next frame must not generate any alert"
        );
    }

    #[test]
    fn vuln05_forward_skip_still_alerts_as_medium() {
        // Forward skips (small, non-wraparound) keep the prior behaviour:
        // Medium SequenceAnomaly after `threshold` consecutive mismatches.
        use vs_types::AlertSeverity;
        let mut mon = ProfinetMonitor::new();
        mon.set_missed_cycle_threshold(1);
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1000));
        // Forward skip: 1 → 5 (delta = 4, missed cycles).
        let r = mon.inspect(&make_cyclic(0x8000, 5, DATA_STATUS_PROVIDER_RUN, 2000));
        assert!(r.alert_count > 0, "forward skip must alert at threshold");
        let has_medium =
            (0..r.alert_count as usize).any(|i| r.alerts[i].severity == AlertSeverity::Medium);
        assert!(has_medium, "forward skip alert must be Medium severity");
    }

    // -----------------------------------------------------------------------
    // VULN-06: DCP per-service allowlist (Set vs. Identify/Hello distinction).
    //
    // Previously `block_dcp` was a single global toggle.  A commissioning
    // deployment that needs DCP-Identify / Hello had to set the toggle to
    // `false`, which also let the dangerous DCP-Set (rename / re-IP /
    // factory-reset) through.  After the fix the policy is per-service and
    // the recommended commissioning preset blocks Set while allowing
    // Identify / Hello / Get.
    // -----------------------------------------------------------------------
    #[test]
    fn vuln06_commissioning_allows_identify_but_blocks_set() {
        let mut mon = ProfinetMonitor::new();
        mon.set_dcp_policy(DcpPolicy::commissioning());
        // Identify (0x05) is benign — allowed.
        let identify = make_dcp_service(DCP_SERVICE_IDENTIFY, 1000);
        assert!(
            mon.inspect(&identify).allowed,
            "DCP-Identify must be allowed"
        );
        // Set (0x04) is dangerous — blocked.
        let set = make_dcp_service(DCP_SERVICE_SET, 2000);
        let r = mon.inspect(&set);
        assert!(
            !r.allowed,
            "DCP-Set must remain blocked under commissioning policy"
        );
        assert!(r.alert_count >= 1, "DCP-Set must emit an alert");
    }

    #[test]
    fn vuln06_commissioning_allows_hello_and_get() {
        let mut mon = ProfinetMonitor::new();
        mon.set_dcp_policy(DcpPolicy::commissioning());
        assert!(
            mon.inspect(&make_dcp_service(DCP_SERVICE_HELLO, 1000))
                .allowed
        );
        assert!(
            mon.inspect(&make_dcp_service(DCP_SERVICE_GET, 2000))
                .allowed
        );
    }

    #[test]
    fn vuln06_commissioning_blocks_unknown_service() {
        // An unrecognised DCP service-id (e.g. 0x7F) must NOT be allowed by
        // the commissioning preset — it's at minimum non-compliant and at
        // worst an exploit attempt.
        let mut mon = ProfinetMonitor::new();
        mon.set_dcp_policy(DcpPolicy::commissioning());
        let weird = make_dcp_service(0x7F, 1000);
        let r = mon.inspect(&weird);
        assert!(!r.allowed, "unknown DCP service must be blocked by default");
    }

    #[test]
    fn vuln06_deny_all_blocks_every_service() {
        // The default (and `set_block_dcp(true)` equivalent) must block all
        // services including Identify / Hello.
        let mut mon = ProfinetMonitor::new(); // default = deny_all
        for sid in [
            DCP_SERVICE_GET,
            DCP_SERVICE_SET,
            DCP_SERVICE_IDENTIFY,
            DCP_SERVICE_HELLO,
        ] {
            let f = make_dcp_service(sid, 1000);
            assert!(
                !mon.inspect(&f).allowed,
                "service-id {sid:#x} must be blocked under deny_all"
            );
        }
    }

    #[test]
    fn vuln06_allow_all_permits_every_service() {
        let mut mon = ProfinetMonitor::new();
        mon.set_dcp_policy(DcpPolicy::allow_all());
        for sid in [
            DCP_SERVICE_GET,
            DCP_SERVICE_SET,
            DCP_SERVICE_IDENTIFY,
            DCP_SERVICE_HELLO,
        ] {
            let f = make_dcp_service(sid, 1000);
            assert!(
                mon.inspect(&f).allowed,
                "service-id {sid:#x} must be allowed under allow_all"
            );
        }
    }

    #[test]
    fn vuln06_set_block_dcp_compat_still_works() {
        // The legacy `set_block_dcp(false)` API must still permit every
        // DCP service (equivalent to allow_all).
        let mut mon = ProfinetMonitor::new();
        mon.set_block_dcp(false);
        let set = make_dcp_service(DCP_SERVICE_SET, 1000);
        assert!(mon.inspect(&set).allowed);

        // And `set_block_dcp(true)` must restore the deny-all behaviour.
        mon.set_block_dcp(true);
        let set2 = make_dcp_service(DCP_SERVICE_SET, 2000);
        assert!(!mon.inspect(&set2).allowed);
    }

    // -----------------------------------------------------------------------
    // VULN-07: IRT (isochronous real-time) timing constraint enforcement.
    //
    // Previously the monitor accepted CyclicRT frames at any inter-arrival
    // rate (subject only to the optional per-rule frames-per-second limit,
    // which is 0/unlimited by default).  An attacker could inject perfectly
    // formed RT frames at the correct frame_id with a valid (incrementing)
    // cycle_counter at any rate, bypassing the IRT timing model that the
    // controller relies on.  After the fix, `add_irt_rule` registers an
    // expected `cycle_us +/- jitter_us` tolerance window per frame_id; a
    // frame arriving outside the window is denied with a High alert and
    // does not advance the connection's timing baseline.
    // -----------------------------------------------------------------------
    #[test]
    fn vuln07_irt_in_window_allowed() {
        let mut mon = ProfinetMonitor::new();
        // 1 ms cycle, +/- 100 µs jitter.
        mon.add_irt_rule(0x8000, 1_000, 100).unwrap();
        // First frame establishes baseline (no timing check yet).
        let r0 = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1_000_000));
        assert!(r0.allowed);
        // Next at exactly 1 ms later — inside window.
        let r1 = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 1_001_000));
        assert!(r1.allowed, "exactly-on-cycle frame must be allowed");
        // Next at 1.05 ms later — still inside window (delta=1050, jitter=100).
        let r2 = mon.inspect(&make_cyclic(0x8000, 3, DATA_STATUS_PROVIDER_RUN, 1_002_050));
        assert!(r2.allowed, "frame within +jitter must be allowed");
        // Next at 0.95 ms later — still inside window.
        let r3 = mon.inspect(&make_cyclic(0x8000, 4, DATA_STATUS_PROVIDER_RUN, 1_003_000));
        assert!(r3.allowed, "frame within -jitter must be allowed");
    }

    #[test]
    fn vuln07_irt_too_fast_blocked() {
        use vs_types::AlertSeverity;
        let mut mon = ProfinetMonitor::new();
        mon.add_irt_rule(0x8000, 1_000, 100).unwrap();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1_000_000));
        // Attacker injects a frame 100 µs after the baseline — well below
        // cycle_us - jitter_us = 900.
        let r = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 1_000_100));
        assert!(!r.allowed, "too-fast frame must be blocked");
        assert!(r.alert_count >= 1);
        let has_high =
            (0..r.alert_count as usize).any(|i| r.alerts[i].severity == AlertSeverity::High);
        assert!(has_high, "IRT timing violation must be High severity");
    }

    #[test]
    fn vuln07_irt_too_slow_blocked() {
        let mut mon = ProfinetMonitor::new();
        mon.add_irt_rule(0x8000, 1_000, 100).unwrap();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1_000_000));
        // Attacker (or fault) delays the frame to 5 ms after baseline —
        // far above cycle_us + jitter_us = 1100.
        let r = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 1_005_000));
        assert!(!r.allowed, "too-slow frame must be blocked");
    }

    #[test]
    fn vuln07_irt_violation_does_not_poison_baseline() {
        // After an IRT timing violation, the rejected frame must NOT become
        // the new timing baseline — otherwise an attacker who injects one
        // bad-timing frame would resync the monitor to their cadence.
        let mut mon = ProfinetMonitor::new();
        mon.add_irt_rule(0x8000, 1_000, 100).unwrap();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1_000_000));
        // Bad frame at 1_100_500 (delta 100_500 — way too slow).
        let _ = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 1_100_500));
        // Legitimate next frame at 1_001_000 µs (1 ms after the ORIGINAL
        // baseline).  Because the baseline was not advanced by the bad
        // frame, this must still be inside the window.
        let r = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 1_001_000));
        assert!(
            r.allowed,
            "legitimate frame after IRT violation must still be allowed"
        );
    }

    #[test]
    fn vuln07_irt_rule_validation_rejects_degenerate() {
        let mut mon = ProfinetMonitor::new();
        // cycle == 0 → degenerate.
        assert!(mon.add_irt_rule(0x8000, 0, 0).is_err());
        // jitter >= cycle → window covers all of time on one side.
        assert!(mon.add_irt_rule(0x8000, 1_000, 1_000).is_err());
        assert!(mon.add_irt_rule(0x8000, 1_000, 2_000).is_err());
        // Valid.
        assert!(mon.add_irt_rule(0x8000, 1_000, 100).is_ok());
    }

    #[test]
    fn vuln07_irt_table_full() {
        let mut mon = ProfinetMonitor::new();
        for i in 0..8u16 {
            mon.add_irt_rule(0x8000 + i, 1_000, 100).unwrap();
        }
        assert!(mon.add_irt_rule(0x9000, 1_000, 100).is_err());
    }

    #[test]
    fn vuln07_no_irt_rule_means_no_timing_check() {
        // Frames without a configured IRT rule must NOT trigger the timing
        // check — preserves backwards-compatible behaviour for callers that
        // don't opt into IRT enforcement.
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_cyclic(0x8000, 1, DATA_STATUS_PROVIDER_RUN, 1_000_000));
        // Wildly different inter-arrival — would fail any IRT check, but
        // none is configured.
        let r = mon.inspect(&make_cyclic(0x8000, 2, DATA_STATUS_PROVIDER_RUN, 9_999_999));
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // VULN-09: README example signature mismatch.
    //
    // The README's "Usage" code example called
    //   `monitor.add_frame_range_rule(0x8000, 0x800F, FrameAction::Allow).unwrap();`
    // with three arguments, but the real signature takes four arguments
    // (`start, end, action, max_rate_per_sec`).  The example would not
    // compile and was misleading to first-time users.  This test exercises
    // the *exact* call shape now documented in the README so a future
    // signature change can't drift from the README example without
    // breaking a regression test.
    // -----------------------------------------------------------------------
    #[test]
    fn vuln09_readme_usage_example_compiles() {
        let mut monitor = ProfinetMonitor::new_strict();
        monitor
            .add_frame_range_rule(0x8000, 0x800F, FrameAction::Allow, 0)
            .unwrap();
        let frame = make_cyclic(0x8005, 1, DATA_STATUS_PROVIDER_RUN, 1000);
        let result = monitor.inspect(&frame);
        assert!(result.allowed);
    }

    #[test]
    fn vuln06_alert_payload_includes_service_id() {
        // Log dedup downstream must be able to distinguish "DCP-Set blocked"
        // from "DCP-Identify blocked" — the alert's source_id encodes the
        // service-id in the high byte.
        let mut mon = ProfinetMonitor::new();
        let set = make_dcp_service(DCP_SERVICE_SET, 1000);
        let r = mon.inspect(&set);
        assert!(!r.allowed);
        assert_eq!(r.alert_count, 1);
        let svc_byte = (r.alerts[0].source_id >> 16) & 0xFF;
        assert_eq!(svc_byte, u32::from(DCP_SERVICE_SET));
    }

    // -----------------------------------------------------------------------
    // VULN-08: Rate-bucket LRU eviction lets attacker reset exhausted bucket.
    //
    // Previously `rate_check` evicted the LRU bucket when all 16 slots were
    // active and seeded the replacement with `max_rate - 1` tokens — so an
    // attacker that cycles >16 frame_ids could repeatedly evict the LRU
    // victim and each eviction handed them a fresh bucket for an id they
    // had already exhausted, bypassing the rate limit.
    //
    // After the fix `rate_check` returns `BucketEvicted` when the table is
    // full and no matching slot exists; `inspect` denies the frame and
    // emits a High `ResourceExhausted` alert.  No bucket is mutated, so the
    // existing rate-limit state for the 16 active frame_ids is preserved.
    // -----------------------------------------------------------------------
    #[test]
    fn vuln08_rate_bucket_table_full_denies_new_frame_id() {
        use vs_types::AlertSeverity;
        let mut mon = ProfinetMonitor::new();
        // 16 distinct frame_ids each with a low rate limit, each used once
        // to populate every bucket slot.
        for i in 0..16u16 {
            let fid = 0x8000 + i;
            mon.add_frame_rule(fid, FrameAction::Allow, 5).unwrap();
            let f = make_cyclic(fid, 1, DATA_STATUS_PROVIDER_RUN, 1_000);
            let r = mon.inspect(&f);
            assert!(
                r.allowed,
                "frame_id {fid:#x} must be allowed (bucket alloc)"
            );
        }
        // 17th distinct frame_id arrives — table is full.  Must be denied
        // with a High ResourceExhausted alert, not silently accepted.
        mon.add_frame_rule(0x9000, FrameAction::Allow, 5).unwrap();
        let f = make_cyclic(0x9000, 1, DATA_STATUS_PROVIDER_RUN, 2_000);
        let r = mon.inspect(&f);
        assert!(
            !r.allowed,
            "17th distinct frame_id must be denied when table is full"
        );
        let has_high =
            (0..r.alert_count as usize).any(|i| r.alerts[i].severity == AlertSeverity::High);
        assert!(has_high, "table-full denial must emit a High alert");
    }

    #[test]
    fn vuln08_cycling_frame_ids_cannot_reset_exhausted_bucket() {
        // Concrete attack from the review:
        //   1. Exhaust the bucket for frame_id A.
        //   2. Send frames for ids B..Q to push A out via LRU eviction.
        //   3. Send A again — *previously* this returned a fresh bucket
        //      with `max_rate - 1` tokens.  After the fix, the cycling
        //      step itself fails on the first id that would require
        //      eviction (no LRU victim is chosen).
        let mut mon = ProfinetMonitor::new();
        // A has a tiny rate limit of 1 frame/sec.
        mon.add_frame_rule(0x0A, FrameAction::Allow, 1).unwrap();
        // First A consumes its token.
        assert!(
            mon.inspect(&make_cyclic(0x0A, 1, DATA_STATUS_PROVIDER_RUN, 0))
                .allowed
        );
        // Second A — over rate, normal Limited path.
        assert!(
            !mon.inspect(&make_cyclic(0x0A, 2, DATA_STATUS_PROVIDER_RUN, 0))
                .allowed
        );

        // Cycle 15 additional ids (total 16 active buckets including A).
        for i in 0..15u16 {
            let fid = 0x10 + i;
            mon.add_frame_rule(fid, FrameAction::Allow, 5).unwrap();
            assert!(
                mon.inspect(&make_cyclic(fid, 1, DATA_STATUS_PROVIDER_RUN, 0))
                    .allowed
            );
        }
        // Add one more id that would have evicted A in the old code.
        mon.add_frame_rule(0xFF, FrameAction::Allow, 5).unwrap();
        let evict = mon.inspect(&make_cyclic(0xFF, 1, DATA_STATUS_PROVIDER_RUN, 0));
        assert!(!evict.allowed, "16th-overflow must be denied (no eviction)");

        // Critically: A's bucket must still be exhausted.  A second A
        // attempt within the same time window must remain denied — the
        // attacker did NOT get a fresh bucket.
        let still_exhausted = mon.inspect(&make_cyclic(0x0A, 3, DATA_STATUS_PROVIDER_RUN, 0));
        assert!(
            !still_exhausted.allowed,
            "attacker must not be able to reset their bucket by cycling ids"
        );
    }

    #[test]
    fn vuln08_active_bucket_keeps_working_when_table_full() {
        // The deny-on-eviction policy must NOT break legitimate traffic
        // for ids that already have an active bucket.
        let mut mon = ProfinetMonitor::new();
        for i in 0..16u16 {
            let fid = 0x8000 + i;
            mon.add_frame_rule(fid, FrameAction::Allow, 100).unwrap();
            assert!(
                mon.inspect(&make_cyclic(fid, 1, DATA_STATUS_PROVIDER_RUN, 0))
                    .allowed
            );
        }
        // A 17th id is denied …
        mon.add_frame_rule(0x9000, FrameAction::Allow, 100).unwrap();
        assert!(
            !mon.inspect(&make_cyclic(0x9000, 1, DATA_STATUS_PROVIDER_RUN, 0))
                .allowed
        );
        // … but the original 16 keep working with their preserved buckets.
        for i in 0..16u16 {
            let fid = 0x8000 + i;
            assert!(
                mon.inspect(&make_cyclic(fid, 2, DATA_STATUS_PROVIDER_RUN, 0))
                    .allowed
            );
        }
    }

    #[test]
    fn vuln05_forward_wraparound_is_not_a_replay() {
        // Cycle counter wrapping from 0xFFFF -> 0 is delta == 1, which is
        // the normal forward step — must not trigger a replay alert.
        let mut mon = ProfinetMonitor::new();
        let _ = mon.inspect(&make_cyclic(0x8000, 0xFFFF, DATA_STATUS_PROVIDER_RUN, 1000));
        let r = mon.inspect(&make_cyclic(0x8000, 0, DATA_STATUS_PROVIDER_RUN, 2000));
        assert!(r.allowed, "0xFFFF -> 0 wrap must be allowed");
        assert_eq!(r.alert_count, 0, "0xFFFF -> 0 wrap must not alert");
    }
}
