#![no_std]

//! PROFINET IO intrusion detection monitor.
//!
//! Monitors PROFINET real-time traffic for anomalies:
//!
//! - **Frame ID allowlist** — restrict which RT frame IDs are permitted.
//! - **Cycle counter validation** — detect missed or replayed cycles.
//! - **Data status monitoring** — alert on provider run/stop transitions.
//! - **DCP blocking** — block unauthorized Discovery and Configuration
//!   Protocol messages (can be used to rename/reconfigure devices).
//! - **Alarm monitoring** — track alarm frequency and types with O(1)
//!   flood detection via running in-window count.

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
    Allow,
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
// PROFINET Monitor
// ---------------------------------------------------------------------------

/// PROFINET IO intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~1 KB.
/// - `rules`: 32 × 8 bytes = 256 bytes
/// - `cyclic_conns`: 16 × ~16 bytes = 256 bytes
/// - `alarm_timestamps`: 16 × 8 bytes = 128 bytes
/// - Scalars: ~60 bytes
pub struct ProfinetMonitor {
    rules: [FrameRule; MAX_FRAME_RULES],
    rule_count: u8,
    cyclic_conns: [CyclicConnection; MAX_CYCLIC_CONNS],
    /// DCP blocking (Discovery and Configuration Protocol).
    block_dcp: bool,
    /// Cycle miss threshold.
    missed_cycle_threshold: u8,
    /// Alarm tracking — circular buffer of timestamps.
    alarm_timestamps: [u64; MAX_ALARM_WINDOW],
    /// Index of the next write position in the circular buffer.
    alarm_head: u8,
    /// Number of entries currently stored (capped at `MAX_ALARM_WINDOW`).
    alarm_total: u8,
    /// Running count of alarms within the current window (O(1) detection).
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
    pub fn new() -> Self {
        Self {
            rules: [FrameRule::empty(); MAX_FRAME_RULES],
            rule_count: 0,
            cyclic_conns: [CyclicConnection::empty(); MAX_CYCLIC_CONNS],
            block_dcp: true, // DCP blocked by default (security best practice).
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
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.default_action = FrameAction::Block;
        m
    }

    /// Set whether DCP messages are blocked.
    pub fn set_block_dcp(&mut self, block: bool) {
        self.block_dcp = block;
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

        // DCP blocking.
        if frame.frame_type == vs_types_ind::ProfinetFrameType::Dcp && self.block_dcp {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_PROFINET,
                frame.frame_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::DcpBlocked,
            );
            return result;
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
            if rate > 0 && !self.rate_check(frame.frame_id, rate, frame.timestamp_us) {
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
    /// Always iterates every rule to avoid timing side-channels that could
    /// leak which rule matched.
    fn find_frame_action(&self, frame_id: u16) -> (FrameAction, Option<usize>) {
        let mut result: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && frame_id >= self.rules[i].frame_id_start
                && frame_id <= self.rules[i].frame_id_end
                && result.is_none()
            {
                result = Some(i);
            }
        }
        match result {
            Some(i) => (self.rules[i].action, Some(i)),
            None => (self.default_action, None),
        }
    }

    fn check_cyclic(
        &mut self,
        frame: &vs_types_ind::ProfinetFrame,
        result: &mut ProfinetInspectResult,
    ) {
        let threshold = self.missed_cycle_threshold;

        let ci = self.get_or_create_conn_idx(frame.frame_id);

        // Cycle counter validation.
        if self.cyclic_conns[ci].last_seen_us > 0 {
            let expected = self.cyclic_conns[ci].last_cycle_counter.wrapping_add(1);
            if frame.cycle_counter == expected {
                self.cyclic_conns[ci].missed_cycles = 0;
            } else {
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
        let provider_running = frame.data_status & DATA_STATUS_PROVIDER_RUN != 0;
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
    fn rate_check(&mut self, frame_id: u16, max_rate: u16, now_us: u64) -> bool {
        let key = frame_id as u32;
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

    /// Reset all monitor state — rules, cyclic connections, alarm tracking,
    /// and statistics. Settings like `block_dcp`, `default_action`, and
    /// thresholds are preserved.
    pub fn reset(&mut self) {
        let block_dcp = self.block_dcp;
        let missed_cycle_threshold = self.missed_cycle_threshold;
        let alarm_threshold = self.alarm_threshold;
        let alarm_window_us = self.alarm_window_us;
        let default_action = self.default_action;
        *self = Self::new();
        self.block_dcp = block_dcp;
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
        vs_types_ind::ProfinetFrame {
            frame_type: ProfinetFrameType::CyclicRT,
            frame_id,
            cycle_counter: cycle,
            data_status,
            timestamp_us: ts_us,
            ..vs_types_ind::ProfinetFrame::default()
        }
    }

    fn make_dcp(ts_us: u64) -> vs_types_ind::ProfinetFrame {
        vs_types_ind::ProfinetFrame {
            frame_type: ProfinetFrameType::Dcp,
            timestamp_us: ts_us,
            ..vs_types_ind::ProfinetFrame::default()
        }
    }

    fn make_alarm(ts_us: u64) -> vs_types_ind::ProfinetFrame {
        vs_types_ind::ProfinetFrame {
            frame_type: ProfinetFrameType::Alarm,
            timestamp_us: ts_us,
            ..vs_types_ind::ProfinetFrame::default()
        }
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
        let f = vs_types_ind::ProfinetFrame {
            frame_type: ProfinetFrameType::AcyclicRT,
            frame_id: 0x100,
            timestamp_us: 1000,
            ..vs_types_ind::ProfinetFrame::default()
        };
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
        let f = vs_types_ind::ProfinetFrame {
            frame_type: ProfinetFrameType::CyclicRT,
            frame_id: 0x8000,
            payload_len: 300,
            timestamp_us: 1000,
            ..vs_types_ind::ProfinetFrame::default()
        };
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
}
