// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `LoRa` / `LoRaWAN` intrusion detection monitor.
//!
//! Detects anomalous `LoRaWAN` traffic:
//!
//! - **Device allowlist/blocklist** -- restrict which device addresses may
//!   communicate.
//! - **Replay detection** -- detects reused frame counters with session
//!   awareness for device rejoins.
//! - **Join flood detection** -- excessive join requests may indicate a `DoS`
//!   or key extraction attempt.
//! - **ADR monitoring** -- detects anomalous adaptive data rate changes.
//! - **Duty cycle tracking** -- detects devices exceeding 1% duty cycle.
//! - **Timestamp validation** -- detects clock manipulation attacks.
//!
//! # Examples
//!
//! ```rust
//! use vs_lora_monitor::{LoraMonitor, DeviceAction};
//! use vs_types_embedded::{LoraMessage, LoraMessageType};
//!
//! let mut monitor = LoraMonitor::new();
//! monitor.add_rule([0x01, 0x02, 0x03, 0x04], DeviceAction::Allow).unwrap();
//!
//! let msg = LoraMessage {
//!     dev_addr: [0x01, 0x02, 0x03, 0x04],
//!     frame_counter: 1,
//!     msg_type: LoraMessageType::UnconfirmedUp,
//!     timestamp_us: 1_000_000,
//!     ..LoraMessage::default()
//! };
//!
//! let result = monitor.inspect(&msg);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_embedded::{
    compute_payload_hash, ct_addr4_eq, LoraAdrState, LoraMessage, LoraSession, MonitorReset,
    TimestampValidator, MAX_LORA_AIRTIME_US, MAX_LORA_DATA_RATE, SOURCE_LORA,
};

pub mod join;
pub use join::{
    FrameDir, JoinGuard, JoinVerdict, LoraWanVersion, MalformedReason, ReplayKind,
    DEV_NONCE_RING_DEPTH, JOIN_NONCE_RING_DEPTH, KEY_LEN, MAX_DEV_NONCE_DEVICES,
    MAX_JOIN_NONCE_SERVERS,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum device address rules.
const MAX_DEVICE_RULES: usize = 32;

/// Maximum tracked devices for replay / session detection.
const MAX_TRACKED_DEVICES: usize = 16;

/// Maximum join timestamps for flood detection.
const MAX_JOIN_TIMESTAMPS: usize = 16;

/// Default join flood threshold (join requests per window).
const DEFAULT_JOIN_FLOOD_THRESHOLD: u8 = 10;

/// Default join flood window (60 seconds).
const DEFAULT_JOIN_FLOOD_WINDOW_US: u64 = 60_000_000;

/// Maximum ADR data rate changes before flagging anomaly.
const MAX_ADR_CHANGES: u8 = 5;

/// ADR monitoring window (60 seconds).
const ADR_WINDOW_US: u64 = 60_000_000;

/// Duty cycle tracking window (1 hour).
const DUTY_CYCLE_WINDOW_US: u64 = 3_600_000_000;

/// Maximum duty cycle (1%) expressed as a fraction of the window.
/// 1% of 1 hour = 36 seconds = `36_000_000` microseconds.
const MAX_DUTY_CYCLE_AIRTIME_US: u64 = 36_000_000;

/// Maximum tracked devices for duty cycle monitoring.
const MAX_DUTY_TRACKERS: usize = 16;

/// Maximum allowed duplicate frames per frame counter value.
/// Confirmed uplink retransmissions reuse the same counter, but real
/// retransmissions are rare and bounded. Exceeding this threshold
/// indicates a replay attack rather than legitimate retransmission.
const MAX_DUP_PER_COUNTER: u8 = 3;

/// Maximum forward jump (in counters) accepted on a single advance.
///
/// LoRaWAN frame counters are 32-bit. A jump beyond this window is treated as
/// a suspicious-jump replay attempt. 2^15 = 32768 leaves generous headroom
/// for legitimate frame loss while bounding what an attacker can pre-empt.
const ACCEPT_FORWARD_WINDOW: u32 = 1 << 15;

/// Top-of-range threshold above which a 0xFFFFFFFF -> 0 rollover is plausible.
const ROLLOVER_TOP_THRESHOLD: u32 = 0xFFFF_0000;

// ---------------------------------------------------------------------------
// Alert source ID constants
// ---------------------------------------------------------------------------

const ALERT_JOIN_FLOOD: u32 = 1;
const ALERT_DEVICE_BLOCKED: u32 = 2;
const ALERT_REPLAY_DETECTED: u32 = 3;
const ALERT_ADR_ANOMALY: u32 = 4;
const ALERT_DUTY_CYCLE_EXCEEDED: u32 = 5;
const ALERT_TIMESTAMP_ANOMALY: u32 = 6;
const ALERT_SESSION_TABLE_EXHAUSTED: u32 = 7;
const ALERT_ADR_TABLE_EXHAUSTED: u32 = 8;
const ALERT_DUTY_TABLE_EXHAUSTED: u32 = 9;

// ---------------------------------------------------------------------------
// Message fingerprint helper
// ---------------------------------------------------------------------------

/// Compute a lightweight fingerprint from core `LoRa` message fields.
#[inline]
fn msg_fingerprint(msg: &LoraMessage) -> vs_types::PayloadHash {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&msg.dev_addr);
    buf[4..8].copy_from_slice(&msg.frame_counter.to_le_bytes());
    buf[8] = msg.frame_port;
    buf[9] = msg.msg_type as u8;
    buf[10..12].copy_from_slice(&msg.payload_len.to_le_bytes());
    compute_payload_hash(&buf)
}

// ---------------------------------------------------------------------------
// Device rule
// ---------------------------------------------------------------------------

/// Action for a device address match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    /// Allow messages from this device.
    Allow,
    /// Block messages from this device.
    Block,
}

#[derive(Debug, Clone, Copy)]
struct DeviceRule {
    dev_addr: [u8; 4],
    action: DeviceAction,
    active: bool,
}

impl DeviceRule {
    const fn empty() -> Self {
        Self {
            dev_addr: [0; 4],
            action: DeviceAction::Allow,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Duty cycle tracker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct DutyCycleTracker {
    dev_addr: [u8; 4],
    /// Accumulated airtime in the current window (microseconds).
    airtime_us: u64,
    /// Window start timestamp.
    window_start_us: u64,
    active: bool,
}

impl DutyCycleTracker {
    const fn empty() -> Self {
        Self {
            dev_addr: [0; 4],
            airtime_us: 0,
            window_start_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Result of inspecting a `LoRa` message.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct LoraInspectResult {
    /// Whether the message was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts that were dropped because the alert array was full.
    pub alerts_dropped: u8,
}

impl LoraInspectResult {
    const fn clean() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: SOURCE_LORA,
                source_id: 0,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: 0,
            }; 4],
            alerts_dropped: 0,
        }
    }

    #[inline]
    fn push_alert(
        &mut self,
        severity: AlertSeverity,
        source_id: u32,
        ts_us: u64,
        alert_id: u64,
        payload_hash: vs_types::PayloadHash,
    ) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type: SOURCE_LORA,
                source_id,
                payload_hash,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// LoRa Monitor
// ---------------------------------------------------------------------------

/// `LoRa` / `LoRaWAN` intrusion detection monitor.
pub struct LoraMonitor {
    rules: [DeviceRule; MAX_DEVICE_RULES],
    rule_count: u8,
    sessions: [LoraSession; MAX_TRACKED_DEVICES],
    adr_states: [LoraAdrState; MAX_TRACKED_DEVICES],
    duty_trackers: [DutyCycleTracker; MAX_DUTY_TRACKERS],
    default_action: DeviceAction,
    /// Join flood detection ring buffer.
    join_timestamps: [u64; MAX_JOIN_TIMESTAMPS],
    join_count: u8,
    join_write_idx: u8,
    join_flood_threshold: u8,
    join_flood_window_us: u64,
    timestamp_validator: TimestampValidator,
    next_alert_id: u64,
    total_inspected: u64,
    total_alerts: u64,
    /// Count of table exhaustion events since last alert delivery.
    /// Increments on each exhaustion; reset to zero when alerts are delivered.
    /// The last source type is tracked separately so the alert identifies the table.
    table_exhaustion_count: u8,
    table_exhaustion_last_source: u32,
    /// Number of session table exhaustion events (LRU evictions).
    session_table_exhaustions: u8,
    /// Number of ADR table exhaustion events (LRU evictions).
    adr_table_exhaustions: u8,
    /// Number of duty cycle table exhaustion events (LRU evictions).
    duty_table_exhaustions: u8,
    /// Per-session duplicate frame counter for uplink replay detection.
    /// Tracks how many times the same uplink frame counter has been seen.
    up_dup_counts: [u8; MAX_TRACKED_DEVICES],
    /// Per-session duplicate frame counter for downlink replay detection.
    /// Tracks how many times the same downlink frame counter has been seen.
    down_dup_counts: [u8; MAX_TRACKED_DEVICES],
    /// Per-session 64-bit replay bitmap for uplink frame counters.
    ///
    /// Bit `b` of `up_recent_bitmap[i]` is set when uplink counter
    /// `sessions[i].up_frame_counter - 1 - b` has been observed, giving each
    /// device an independent 64-counter window. Replaces the old global
    /// `min_frame_counter_floor` so one device's eviction does not lock
    /// out another device.
    up_recent_bitmap: [u64; MAX_TRACKED_DEVICES],
    /// Per-session 64-bit replay bitmap for downlink frame counters.
    down_recent_bitmap: [u64; MAX_TRACKED_DEVICES],
    /// Whether 32-bit counter rollover is allowed for honest devices that
    /// wrap 0xFFFFFFFF -> 0. Rollover is only accepted when the tracked
    /// counter is in the top of the range (`>= ROLLOVER_TOP_THRESHOLD`).
    allow_counter_rollover: bool,
}

impl LoraMonitor {
    /// Create a new `LoRa` monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            rules: [DeviceRule::empty(); MAX_DEVICE_RULES],
            rule_count: 0,
            sessions: [LoraSession::empty(); MAX_TRACKED_DEVICES],
            adr_states: [LoraAdrState::empty(); MAX_TRACKED_DEVICES],
            duty_trackers: [DutyCycleTracker::empty(); MAX_DUTY_TRACKERS],
            default_action: DeviceAction::Allow,
            join_timestamps: [0u64; MAX_JOIN_TIMESTAMPS],
            join_count: 0,
            join_write_idx: 0,
            join_flood_threshold: DEFAULT_JOIN_FLOOD_THRESHOLD,
            join_flood_window_us: DEFAULT_JOIN_FLOOD_WINDOW_US,
            timestamp_validator: TimestampValidator::new(),
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
            table_exhaustion_count: 0,
            table_exhaustion_last_source: 0,
            session_table_exhaustions: 0,
            adr_table_exhaustions: 0,
            duty_table_exhaustions: 0,
            up_dup_counts: [0u8; MAX_TRACKED_DEVICES],
            down_dup_counts: [0u8; MAX_TRACKED_DEVICES],
            up_recent_bitmap: [0u64; MAX_TRACKED_DEVICES],
            down_recent_bitmap: [0u64; MAX_TRACKED_DEVICES],
            allow_counter_rollover: false,
        }
    }

    /// Enable or disable acceptance of 32-bit frame-counter rollover.
    ///
    /// When enabled, a counter that wraps from `0xFFFFFFFF` to `0` (or
    /// thereabouts) is accepted only if the previously seen counter was in
    /// the top of the range (>= `0xFFFF0000`). Disabled by default.
    pub fn set_allow_counter_rollover(&mut self, allow: bool) {
        self.allow_counter_rollover = allow;
    }

    /// Create a new `LoRa` monitor (deny-by-default).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = DeviceAction::Block;
        m
    }

    /// Set join flood detection parameters.
    pub fn set_join_flood_params(&mut self, threshold: u8, window_us: u64) {
        self.join_flood_threshold = threshold.clamp(2, MAX_JOIN_TIMESTAMPS as u8);
        self.join_flood_window_us = window_us.max(1_000_000);
    }

    /// Add a device address rule.
    ///
    /// If a rule for the same `dev_addr` already exists, its action is updated
    /// instead of adding a duplicate entry.
    ///
    /// Note on constant-time comparison: the rule table holds non-secret
    /// device addresses, so `ct_addr4_eq` is used here only for code
    /// consistency with the rest of the monitor. Treating rule-table
    /// addresses as secret-sensitive would not improve any threat model
    /// because the rule list itself is configuration, not key material.
    pub fn add_rule(&mut self, dev_addr: [u8; 4], action: DeviceAction) -> Result<(), VsError> {
        // Check for existing rule with the same dev_addr -- update in place.
        // `ct_addr4_eq` is used for code symmetry; the addresses being
        // compared here are non-secret rule entries.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && ct_addr4_eq(&self.rules[i].dev_addr, &dev_addr) {
                self.rules[i].action = action;
                return Ok(());
            }
        }
        if self.rule_count as usize >= MAX_DEVICE_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = DeviceRule {
            dev_addr,
            action,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Remove all device address rules.
    pub fn clear_rules(&mut self) {
        self.rules = [DeviceRule::empty(); MAX_DEVICE_RULES];
        self.rule_count = 0;
    }

    /// Remove a device address rule by index.
    pub fn remove_rule(&mut self, index: usize) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        let count = self.rule_count as usize;
        for i in index..count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[count - 1] = DeviceRule::empty();
        self.rule_count -= 1;
        Ok(())
    }

    /// Reset the session tracker for a device (e.g. after a rejoin).
    ///
    /// This clears the tracked frame counters so that a frame counter
    /// reset to 0 is not flagged as a replay.
    pub fn reset_device_session(&mut self, dev_addr: [u8; 4]) {
        for i in 0..MAX_TRACKED_DEVICES {
            if self.sessions[i].active && ct_addr4_eq(&self.sessions[i].dev_addr, &dev_addr) {
                self.sessions[i] = LoraSession::empty();
                self.up_recent_bitmap[i] = 0;
                self.down_recent_bitmap[i] = 0;
                self.up_dup_counts[i] = 0;
                self.down_dup_counts[i] = 0;
                return;
            }
        }
    }

    /// Start a new session for a device, incrementing its session ID.
    ///
    /// This resets frame counters while preserving the session lineage.
    /// Used when a device performs a rejoin.
    pub fn start_new_session(&mut self, dev_addr: [u8; 4]) -> Result<(), VsError> {
        // Look for existing session for this device.
        for i in 0..MAX_TRACKED_DEVICES {
            if self.sessions[i].active && ct_addr4_eq(&self.sessions[i].dev_addr, &dev_addr) {
                let new_session_id = self.sessions[i].session_id.wrapping_add(1);
                self.sessions[i].up_frame_counter = u32::MAX;
                self.sessions[i].down_frame_counter = u32::MAX;
                self.sessions[i].session_id = new_session_id;
                self.up_recent_bitmap[i] = 0;
                self.down_recent_bitmap[i] = 0;
                self.up_dup_counts[i] = 0;
                self.down_dup_counts[i] = 0;
                return Ok(());
            }
        }
        // Allocate a new session slot.
        for i in 0..MAX_TRACKED_DEVICES {
            if !self.sessions[i].active {
                self.sessions[i] = LoraSession {
                    dev_addr,
                    up_frame_counter: u32::MAX,
                    down_frame_counter: u32::MAX,
                    session_id: 1,
                    last_activity_us: 0,
                    active: true,
                };
                self.up_recent_bitmap[i] = 0;
                self.down_recent_bitmap[i] = 0;
                self.up_dup_counts[i] = 0;
                self.down_dup_counts[i] = 0;
                return Ok(());
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Inspect a `LoRa` message.
    pub fn inspect(&mut self, msg: &LoraMessage) -> LoraInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = LoraInspectResult::clean();
        let fingerprint = msg_fingerprint(msg);

        // Timestamp validation.
        if !self.timestamp_validator.validate(msg.timestamp_us) {
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_TIMESTAMP_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            // Continue inspection -- timestamp anomaly is informational.
        }

        // Validate data rate is within LoRaWAN range (DR0-DR15).
        if msg.data_rate > MAX_LORA_DATA_RATE {
            result.allowed = false;
            return result;
        }

        // Reject physically implausible airtime values.
        if msg.airtime_us > MAX_LORA_AIRTIME_US {
            result.allowed = false;
            return result;
        }

        // Join flood detection.
        if msg.msg_type == vs_types_embedded::LoraMessageType::JoinRequest {
            self.record_join(msg.timestamp_us);
            if self.detect_join_flood(msg.timestamp_us) {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::High,
                    ALERT_JOIN_FLOOD,
                    msg.timestamp_us,
                    self.next_alert_id(),
                    fingerprint,
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }
        }

        // Device address rule check.
        let mut matched: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && ct_addr4_eq(&self.rules[i].dev_addr, &msg.dev_addr)
                && matched.is_none()
            {
                matched = Some(i);
                break;
            }
        }

        let action = match matched {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };

        if action == DeviceAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_DEVICE_BLOCKED,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Replay detection (for data messages, not joins).
        if !msg.msg_type.is_join()
            && self.check_replay(msg.dev_addr, msg.frame_counter, msg.timestamp_us)
        {
            result.push_alert(
                AlertSeverity::High,
                ALERT_REPLAY_DETECTED,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            result.allowed = false;
        }

        // ADR anomaly detection (for data messages with data rate info).
        if !msg.msg_type.is_join()
            && msg.data_rate > 0
            && self.record_data_rate(msg.dev_addr, msg.data_rate, msg.timestamp_us)
        {
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_ADR_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Duty cycle enforcement (for transmissions with airtime info).
        if msg.airtime_us > 0
            && self.record_transmit(msg.dev_addr, msg.airtime_us, msg.timestamp_us)
        {
            result.push_alert(
                AlertSeverity::High,
                ALERT_DUTY_CYCLE_EXCEEDED,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        if self.table_exhaustion_count > 0 {
            // Deliver a single alert covering all exhaustion events since last
            // delivery.  The source_id identifies the most recent table type;
            // the count (now reset) tells the consumer how many events occurred.
            result.push_alert(
                AlertSeverity::Medium,
                self.table_exhaustion_last_source,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            self.table_exhaustion_count = 0;
        }

        result
    }

    /// Inspect a downlink `LoRa` message.
    ///
    /// Tracks downlink frame counters separately from uplink. Also checks
    /// device address rules and ADR monitoring for downlink traffic.
    pub fn inspect_downlink(&mut self, msg: &LoraMessage) -> LoraInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = LoraInspectResult::clean();
        let fingerprint = msg_fingerprint(msg);

        // Timestamp validation.
        if !self.timestamp_validator.validate(msg.timestamp_us) {
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_TIMESTAMP_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Device address rule check.
        let mut matched: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && ct_addr4_eq(&self.rules[i].dev_addr, &msg.dev_addr)
                && matched.is_none()
            {
                matched = Some(i);
                break;
            }
        }

        let action = match matched {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };

        if action == DeviceAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_DEVICE_BLOCKED,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Downlink replay detection.
        if self.check_downlink_replay(msg.dev_addr, msg.frame_counter, msg.timestamp_us) {
            result.push_alert(
                AlertSeverity::High,
                ALERT_REPLAY_DETECTED,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            result.allowed = false;
        }

        // ADR anomaly detection for downlink.
        if msg.data_rate > 0 && self.record_data_rate(msg.dev_addr, msg.data_rate, msg.timestamp_us)
        {
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_ADR_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Deliver deferred table-exhaustion alerts (same pattern as inspect).
        if self.table_exhaustion_count > 0 {
            result.push_alert(
                AlertSeverity::Medium,
                self.table_exhaustion_last_source,
                msg.timestamp_us,
                self.next_alert_id(),
                fingerprint,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            self.table_exhaustion_count = 0;
        }

        result
    }

    /// Record a data rate observation for ADR monitoring.
    ///
    /// Returns `true` if the rate of data rate changes is anomalous
    /// (more than `MAX_ADR_CHANGES` within `ADR_WINDOW_US`).
    /// # Security
    ///
    /// This method is crate-internal. External callers must not invoke it
    /// directly as it can poison the ADR anomaly detection state.
    pub(crate) fn record_data_rate(
        &mut self,
        dev_addr: [u8; 4],
        data_rate: u8,
        ts_us: u64,
    ) -> bool {
        // Single pass: find existing, free slot, and LRU candidate.
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        for i in 0..MAX_TRACKED_DEVICES {
            if self.adr_states[i].active {
                if ct_addr4_eq(&self.adr_states[i].dev_addr, &dev_addr) {
                    return self.update_adr_state(i, data_rate, ts_us);
                }
                if self.adr_states[i].last_activity_us < lru_ts {
                    lru_ts = self.adr_states[i].last_activity_us;
                    lru_idx = i;
                }
            } else if free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        // Allocate in free slot if available.
        if let Some(idx) = free_slot {
            self.adr_states[idx] = LoraAdrState {
                dev_addr,
                data_rate,
                change_count: 0,
                window_start_us: ts_us,
                last_activity_us: ts_us,
                active: true,
            };
            return false;
        }
        // No free slot — LRU eviction using candidate from single pass.
        // SECURITY: ADR table eviction loses tracking history for the evicted device,
        // which an attacker could exploit to poison ADR state by forcing evictions.
        // The exhaustion alert notifies operators so they can investigate.
        self.table_exhaustion_count = self.table_exhaustion_count.saturating_add(1);
        self.table_exhaustion_last_source = ALERT_ADR_TABLE_EXHAUSTED;
        self.adr_table_exhaustions = self.adr_table_exhaustions.saturating_add(1);
        self.adr_states[lru_idx] = LoraAdrState {
            dev_addr,
            data_rate,
            change_count: 0,
            window_start_us: ts_us,
            last_activity_us: ts_us,
            active: true,
        };
        false
    }

    /// Record a transmit event for duty cycle tracking.
    ///
    /// Returns `true` if the device exceeds 1% duty cycle in a rolling
    /// 1-hour window.
    /// # Security
    ///
    /// This method is crate-internal. External callers must not invoke it
    /// directly as it can poison the duty-cycle detection state.
    pub(crate) fn record_transmit(
        &mut self,
        dev_addr: [u8; 4],
        airtime_us: u64,
        ts_us: u64,
    ) -> bool {
        // Single pass: find existing, free slot, and LRU candidate.
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        for i in 0..MAX_DUTY_TRACKERS {
            if self.duty_trackers[i].active {
                if ct_addr4_eq(&self.duty_trackers[i].dev_addr, &dev_addr) {
                    return self.update_duty_tracker(i, airtime_us, ts_us);
                }
                if self.duty_trackers[i].window_start_us < lru_ts {
                    lru_ts = self.duty_trackers[i].window_start_us;
                    lru_idx = i;
                }
            } else if free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        // Allocate in free slot if available.
        if let Some(idx) = free_slot {
            self.duty_trackers[idx] = DutyCycleTracker {
                dev_addr,
                airtime_us,
                window_start_us: ts_us,
                active: true,
            };
            return airtime_us > MAX_DUTY_CYCLE_AIRTIME_US;
        }
        // No free slot — LRU eviction using candidate from single pass.
        self.table_exhaustion_count = self.table_exhaustion_count.saturating_add(1);
        self.table_exhaustion_last_source = ALERT_DUTY_TABLE_EXHAUSTED;
        self.duty_table_exhaustions = self.duty_table_exhaustions.saturating_add(1);
        self.duty_trackers[lru_idx] = DutyCycleTracker {
            dev_addr,
            airtime_us,
            window_start_us: ts_us,
            active: true,
        };
        airtime_us > MAX_DUTY_CYCLE_AIRTIME_US
    }

    /// Return the total number of messages inspected.
    #[inline]
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Return the total number of alerts raised.
    #[inline]
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Return the number of active rules.
    #[inline]
    pub fn rule_count(&self) -> usize {
        self.rule_count as usize
    }

    /// Return the number of session table exhaustion events.
    #[inline]
    pub fn session_table_exhaustions(&self) -> u8 {
        self.session_table_exhaustions
    }

    /// Return the number of ADR table exhaustion events.
    #[inline]
    pub fn adr_table_exhaustions(&self) -> u8 {
        self.adr_table_exhaustions
    }

    /// Return the number of duty cycle table exhaustion events.
    #[inline]
    pub fn duty_table_exhaustions(&self) -> u8 {
        self.duty_table_exhaustions
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    #[inline]
    fn next_alert_id(&mut self) -> u64 {
        let id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.wrapping_add(1);
        if self.next_alert_id == 0 {
            self.next_alert_id = 1;
        }
        id
    }

    #[inline]
    fn record_join(&mut self, ts_us: u64) {
        let idx = self.join_write_idx as usize % MAX_JOIN_TIMESTAMPS;
        self.join_timestamps[idx] = ts_us;
        self.join_write_idx = ((idx + 1) % MAX_JOIN_TIMESTAMPS) as u8;
        if (self.join_count as usize) < MAX_JOIN_TIMESTAMPS {
            self.join_count += 1;
        }
    }

    #[inline]
    fn detect_join_flood(&self, now_us: u64) -> bool {
        // TODO(perf): the ring is bounded at MAX_JOIN_TIMESTAMPS (16) so the
        // full scan is cheap, but we still re-walk it on every JoinRequest.
        // A nicer formulation would evict expired entries during
        // `record_join` and treat the resulting `join_count` as the answer
        // -- requires reshaping the ring into a true deque keyed by
        // timestamp. Left as a TODO since the win is small at depth 16.
        let start = now_us.saturating_sub(self.join_flood_window_us);
        let mut count: u8 = 0;
        for i in 0..self.join_count as usize {
            if self.join_timestamps[i] >= start {
                count = count.saturating_add(1);
            }
        }
        count >= self.join_flood_threshold
    }

    /// Check for uplink replay attack. Returns `true` if replay detected,
    /// `false` if valid.
    ///
    /// Maintains a per-session sliding window
    /// `(up_frame_counter, up_recent_bitmap)` of size 64 keyed by `dev_addr`.
    /// Each device has independent state, so an evicted device's history
    /// cannot lock out another device.
    fn check_replay(&mut self, dev_addr: [u8; 4], frame_counter: u32, ts_us: u64) -> bool {
        // Single pass: find existing session, free slot, and LRU candidate.
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        for i in 0..MAX_TRACKED_DEVICES {
            if self.sessions[i].active {
                if ct_addr4_eq(&self.sessions[i].dev_addr, &dev_addr) {
                    return Self::accept_uplink(
                        &mut self.sessions[i],
                        &mut self.up_recent_bitmap[i],
                        &mut self.up_dup_counts[i],
                        frame_counter,
                        ts_us,
                        self.allow_counter_rollover,
                    );
                }
                if self.sessions[i].last_activity_us < lru_ts {
                    lru_ts = self.sessions[i].last_activity_us;
                    lru_idx = i;
                }
            } else if free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        // Allocate in free slot if available.
        if let Some(idx) = free_slot {
            self.up_dup_counts[idx] = 0;
            self.down_dup_counts[idx] = 0;
            self.up_recent_bitmap[idx] = 0;
            self.down_recent_bitmap[idx] = 0;
            self.sessions[idx] = LoraSession {
                dev_addr,
                up_frame_counter: frame_counter,
                // Sentinel: accept any first downlink counter for this session.
                down_frame_counter: u32::MAX,
                session_id: 1,
                last_activity_us: ts_us,
                active: true,
            };
            return false;
        }
        // No free slot -- LRU eviction. Per-device windows are independent
        // so the evicted session's counter is NOT carried forward as a
        // global floor; the new device starts fresh.
        self.table_exhaustion_count = self.table_exhaustion_count.saturating_add(1);
        self.table_exhaustion_last_source = ALERT_SESSION_TABLE_EXHAUSTED;
        self.session_table_exhaustions = self.session_table_exhaustions.saturating_add(1);
        self.up_dup_counts[lru_idx] = 0;
        self.down_dup_counts[lru_idx] = 0;
        self.up_recent_bitmap[lru_idx] = 0;
        self.down_recent_bitmap[lru_idx] = 0;
        self.sessions[lru_idx] = LoraSession {
            dev_addr,
            up_frame_counter: frame_counter,
            // Fresh slot: downlink starts fresh too (sentinel u32::MAX).
            down_frame_counter: u32::MAX,
            session_id: 1,
            last_activity_us: ts_us,
            active: true,
        };
        false
    }

    /// Apply per-device uplink window rules.
    ///
    /// Returns `true` if the frame is a replay (and must be rejected),
    /// `false` if it should be accepted (and the session state has been
    /// updated in place).
    fn accept_uplink(
        session: &mut LoraSession,
        bitmap: &mut u64,
        dup_count: &mut u8,
        frame_counter: u32,
        ts_us: u64,
        allow_rollover: bool,
    ) -> bool {
        // Sentinel: u32::MAX means fresh session, accept any counter.
        if session.up_frame_counter == u32::MAX {
            session.up_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *bitmap = 0;
            *dup_count = 0;
            return false; // not a replay
        }

        let highest = session.up_frame_counter;

        if frame_counter > highest {
            let advance = frame_counter - highest;
            if advance > ACCEPT_FORWARD_WINDOW {
                return true; // suspicious forward jump
            }
            let shift = advance.min(64);
            // Asymmetry: when `advance > 64` the whole window slides past the
            // previous highest, so we zero the bitmap and do NOT set a bit
            // for the new highest. That is safe because the new highest is
            // tracked in `session.up_frame_counter`, and any subsequent
            // frame at that counter takes the `frame_counter == highest`
            // path (which the dup-count machinery already handles). The
            // `advance <= 64` branch shifts the old bitmap and sets the bit
            // at `advance - 1` representing the gap to the new highest.
            let new_bitmap = if shift >= 64 {
                0u64
            } else {
                (*bitmap << shift) | (1u64 << (advance - 1))
            };
            *bitmap = new_bitmap;
            session.up_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *dup_count = 0;
            return false;
        }

        if frame_counter == highest {
            // LoRaWAN confirmed uplinks legitimately reuse the same counter
            // for retransmissions, so allow a bounded number before flagging.
            *dup_count = dup_count.saturating_add(1);
            if *dup_count > MAX_DUP_PER_COUNTER {
                return true;
            }
            session.last_activity_us = ts_us;
            return false;
        }

        // frame_counter < highest
        let diff = highest - frame_counter;

        // Detect plausible 32-bit rollover.
        if allow_rollover
            && highest >= ROLLOVER_TOP_THRESHOLD
            && frame_counter < ACCEPT_FORWARD_WINDOW
        {
            session.up_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *bitmap = 0;
            *dup_count = 0;
            return false;
        }

        if diff > 64 {
            return true; // out-of-window stale frame
        }
        let bit = diff - 1;
        let mask = 1u64 << bit;
        if *bitmap & mask != 0 {
            return true; // already-seen replay
        }
        *bitmap |= mask;
        session.last_activity_us = ts_us;
        false
    }

    /// Check for downlink replay attack.
    fn check_downlink_replay(&mut self, dev_addr: [u8; 4], frame_counter: u32, ts_us: u64) -> bool {
        // Single pass: find existing session, free slot, and LRU candidate.
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        for i in 0..MAX_TRACKED_DEVICES {
            if self.sessions[i].active {
                if ct_addr4_eq(&self.sessions[i].dev_addr, &dev_addr) {
                    return Self::accept_downlink(
                        &mut self.sessions[i],
                        &mut self.down_recent_bitmap[i],
                        &mut self.down_dup_counts[i],
                        frame_counter,
                        ts_us,
                        self.allow_counter_rollover,
                    );
                }
                if self.sessions[i].last_activity_us < lru_ts {
                    lru_ts = self.sessions[i].last_activity_us;
                    lru_idx = i;
                }
            } else if free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        // Allocate in free slot if available.
        if let Some(idx) = free_slot {
            self.up_dup_counts[idx] = 0;
            self.down_dup_counts[idx] = 0;
            self.up_recent_bitmap[idx] = 0;
            self.down_recent_bitmap[idx] = 0;
            self.sessions[idx] = LoraSession {
                dev_addr,
                // Sentinel: accept any first uplink counter for this session.
                up_frame_counter: u32::MAX,
                down_frame_counter: frame_counter,
                session_id: 1,
                last_activity_us: ts_us,
                active: true,
            };
            return false;
        }
        // No free slot -- LRU eviction. Per-device windows are independent;
        // no global floor is propagated.
        self.table_exhaustion_count = self.table_exhaustion_count.saturating_add(1);
        self.table_exhaustion_last_source = ALERT_SESSION_TABLE_EXHAUSTED;
        self.session_table_exhaustions = self.session_table_exhaustions.saturating_add(1);
        self.up_dup_counts[lru_idx] = 0;
        self.down_dup_counts[lru_idx] = 0;
        self.up_recent_bitmap[lru_idx] = 0;
        self.down_recent_bitmap[lru_idx] = 0;
        self.sessions[lru_idx] = LoraSession {
            dev_addr,
            // Fresh slot: uplink starts fresh too (sentinel u32::MAX).
            up_frame_counter: u32::MAX,
            down_frame_counter: frame_counter,
            session_id: 1,
            last_activity_us: ts_us,
            active: true,
        };
        false
    }

    /// Apply per-device downlink window rules. Symmetrical to
    /// [`accept_uplink`](Self::accept_uplink).
    fn accept_downlink(
        session: &mut LoraSession,
        bitmap: &mut u64,
        dup_count: &mut u8,
        frame_counter: u32,
        ts_us: u64,
        allow_rollover: bool,
    ) -> bool {
        if session.down_frame_counter == u32::MAX {
            session.down_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *bitmap = 0;
            *dup_count = 0;
            return false;
        }

        let highest = session.down_frame_counter;

        if frame_counter > highest {
            let advance = frame_counter - highest;
            if advance > ACCEPT_FORWARD_WINDOW {
                return true;
            }
            let shift = advance.min(64);
            let new_bitmap = if shift >= 64 {
                0u64
            } else {
                (*bitmap << shift) | (1u64 << (advance - 1))
            };
            *bitmap = new_bitmap;
            session.down_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *dup_count = 0;
            return false;
        }

        if frame_counter == highest {
            *dup_count = dup_count.saturating_add(1);
            if *dup_count > MAX_DUP_PER_COUNTER {
                return true;
            }
            session.last_activity_us = ts_us;
            return false;
        }

        let diff = highest - frame_counter;

        if allow_rollover
            && highest >= ROLLOVER_TOP_THRESHOLD
            && frame_counter < ACCEPT_FORWARD_WINDOW
        {
            session.down_frame_counter = frame_counter;
            session.last_activity_us = ts_us;
            *bitmap = 0;
            *dup_count = 0;
            return false;
        }

        if diff > 64 {
            return true;
        }
        let bit = diff - 1;
        let mask = 1u64 << bit;
        if *bitmap & mask != 0 {
            return true;
        }
        *bitmap |= mask;
        session.last_activity_us = ts_us;
        false
    }

    /// Update ADR state for a tracked device. Returns `true` if anomalous.
    fn update_adr_state(&mut self, idx: usize, data_rate: u8, ts_us: u64) -> bool {
        let state = &mut self.adr_states[idx];

        // If the window has elapsed, decay the counter.
        if ts_us.saturating_sub(state.window_start_us) > ADR_WINDOW_US {
            // Decay rather than reset: halving preserves memory of recent changes
            // and prevents evasion by spacing changes just outside the window.
            state.change_count = state.change_count / 2;
            state.window_start_us = ts_us;
        }

        // Update last activity timestamp for LRU eviction.
        state.last_activity_us = ts_us;

        // Only count actual changes.
        if data_rate != state.data_rate {
            state.data_rate = data_rate;
            state.change_count = state.change_count.saturating_add(1);
        }

        state.change_count > MAX_ADR_CHANGES
    }

    /// Update duty cycle tracker. Returns `true` if duty cycle exceeded.
    fn update_duty_tracker(&mut self, idx: usize, airtime_us: u64, ts_us: u64) -> bool {
        let tracker = &mut self.duty_trackers[idx];

        // Proportional decay: reduce airtime linearly based on elapsed time,
        // not in discrete window-sized steps. This prevents boundary exploits
        // where a device could transmit 2x the duty cycle across 2 windows.
        // NOTE: window_start_us must advance on every message because the decay
        // formula computes incremental decay since the last update. Freezing it
        // would cause repeated over-decay of already-decayed airtime.
        let elapsed = ts_us.saturating_sub(tracker.window_start_us);
        if elapsed > 0 {
            let decay_fraction = elapsed.min(DUTY_CYCLE_WINDOW_US);
            let decay = (tracker.airtime_us as u128).saturating_mul(decay_fraction as u128)
                / (DUTY_CYCLE_WINDOW_US as u128);
            tracker.airtime_us = tracker.airtime_us.saturating_sub(decay as u64);
            tracker.window_start_us = ts_us;
        }

        tracker.airtime_us = tracker.airtime_us.saturating_add(airtime_us);
        tracker.airtime_us > MAX_DUTY_CYCLE_AIRTIME_US
    }
}

impl Default for LoraMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for LoraMonitor {
    /// Reset all runtime state while preserving rules and thresholds.
    fn reset_state(&mut self) {
        // Clear sessions.
        self.sessions = [LoraSession::empty(); MAX_TRACKED_DEVICES];
        // Clear ADR states.
        self.adr_states = [LoraAdrState::empty(); MAX_TRACKED_DEVICES];
        // Clear duty cycle trackers.
        self.duty_trackers = [DutyCycleTracker::empty(); MAX_DUTY_TRACKERS];
        // Clear join flood state.
        self.join_timestamps = [0u64; MAX_JOIN_TIMESTAMPS];
        self.join_count = 0;
        self.join_write_idx = 0;
        // Reset timestamp validator.
        self.timestamp_validator.reset();
        // Reset counters.
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
        self.table_exhaustion_count = 0;
        self.table_exhaustion_last_source = 0;
        self.session_table_exhaustions = 0;
        self.adr_table_exhaustions = 0;
        self.duty_table_exhaustions = 0;
        // Reset duplicate counters.
        self.up_dup_counts = [0u8; MAX_TRACKED_DEVICES];
        self.down_dup_counts = [0u8; MAX_TRACKED_DEVICES];
        // Reset per-session replay bitmaps.
        self.up_recent_bitmap = [0u64; MAX_TRACKED_DEVICES];
        self.down_recent_bitmap = [0u64; MAX_TRACKED_DEVICES];
        // NOTE: rules, rule_count, default_action, join_flood_threshold,
        // and join_flood_window_us are preserved.
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use vs_types_embedded::LoraMessageType;

    fn make_msg(addr: [u8; 4], mt: LoraMessageType, fc: u32, ts: u64) -> LoraMessage {
        LoraMessage {
            dev_addr: addr,
            frame_counter: fc,
            frame_port: 1,
            msg_type: mt,
            payload_len: 20,
            rssi: -80,
            snr: 10,
            data_rate: 0,
            airtime_us: 0,
            timestamp_us: ts,
        }
    }

    #[test]
    fn default_allows() {
        let mut mon = LoraMonitor::new();
        let msg = make_msg(
            [0x01, 0x02, 0x03, 0x04],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        );
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn deny_default_blocks() {
        let mut mon = LoraMonitor::new_deny_default();
        let msg = make_msg(
            [0x01, 0x02, 0x03, 0x04],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        );
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn allow_overrides_deny() {
        let mut mon = LoraMonitor::new_deny_default();
        mon.add_rule([0x01, 0x02, 0x03, 0x04], DeviceAction::Allow)
            .unwrap();
        let msg = make_msg(
            [0x01, 0x02, 0x03, 0x04],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        );
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn block_rule() {
        let mut mon = LoraMonitor::new();
        mon.add_rule([0x01, 0x02, 0x03, 0x04], DeviceAction::Block)
            .unwrap();
        let msg = make_msg(
            [0x01, 0x02, 0x03, 0x04],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn replay_detection() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];
        // First message with counter 10.
        let msg1 = make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 1000);
        assert!(mon.inspect(&msg1).allowed);
        // Counter 11 — valid.
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedUp, 11, 2000);
        assert!(mon.inspect(&msg2).allowed);
        // Counter 10 again — replay.
        let msg3 = make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 3000);
        let r = mon.inspect(&msg3);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn join_flood_detection() {
        let mut mon = LoraMonitor::new();
        mon.set_join_flood_params(4, 10_000_000);

        for i in 0..3 {
            let msg = make_msg([0; 4], LoraMessageType::JoinRequest, 0, (i + 1) * 1_000_000);
            assert!(mon.inspect(&msg).allowed);
        }
        // 4th join triggers flood.
        let msg = make_msg([0; 4], LoraMessageType::JoinRequest, 0, 4_000_000);
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = LoraMonitor::new();
        mon.add_rule([0x01; 4], DeviceAction::Block).unwrap();
        let _ = mon.inspect(&make_msg(
            [0x02; 4],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        ));
        let _ = mon.inspect(&make_msg(
            [0x01; 4],
            LoraMessageType::UnconfirmedUp,
            1,
            2000,
        ));
        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
    }

    #[test]
    fn default_constructor() {
        let mon = LoraMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn alert_ids_nonzero() {
        let mut mon = LoraMonitor::new();
        mon.add_rule([0x01; 4], DeviceAction::Block).unwrap();
        let r = mon.inspect(&make_msg(
            [0x01; 4],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        ));
        assert!(r.alerts[0].id > 0);
    }

    #[test]
    fn join_accept_does_not_trigger_flood_check() {
        let mut mon = LoraMonitor::new();
        mon.set_join_flood_params(2, 10_000_000);
        // JoinAccept is a downlink response — it should NOT count toward
        // join flood detection (only JoinRequest does).
        let _ = mon.inspect(&make_msg([0; 4], LoraMessageType::JoinAccept, 0, 1_000_000));
        let r = mon.inspect(&make_msg([0; 4], LoraMessageType::JoinAccept, 0, 2_000_000));
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Session-aware replay detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn reset_device_session_allows_counter_restart() {
        let mut mon = LoraMonitor::new();
        let addr = [0x10, 0x20, 0x30, 0x40];

        // Send messages with increasing counters.
        let msg1 = make_msg(addr, LoraMessageType::UnconfirmedUp, 100, 1000);
        assert!(mon.inspect(&msg1).allowed);

        // Reset the session (simulating a device rejoin).
        mon.reset_device_session(addr);

        // Counter 0 should now be accepted (not flagged as replay).
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedUp, 0, 2000);
        assert!(mon.inspect(&msg2).allowed);
    }

    #[test]
    fn start_new_session_resets_counters() {
        let mut mon = LoraMonitor::new();
        let addr = [0x10, 0x20, 0x30, 0x40];

        // Establish a session with high counters.
        let msg = make_msg(addr, LoraMessageType::UnconfirmedUp, 500, 1000);
        assert!(mon.inspect(&msg).allowed);

        // Start a new session.
        mon.start_new_session(addr).unwrap();

        // Counter 1 should be accepted after session reset.
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedUp, 1, 2000);
        assert!(mon.inspect(&msg2).allowed);
    }

    #[test]
    fn start_new_session_increments_session_id() {
        let mut mon = LoraMonitor::new();
        let addr = [0x10, 0x20, 0x30, 0x40];

        // First inspection creates session with id 1.
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 1, 1000));

        // Start new session bumps to 2.
        mon.start_new_session(addr).unwrap();

        // Verify session_id by checking internal state.
        let session = mon
            .sessions
            .iter()
            .find(|s| s.active && ct_addr4_eq(&s.dev_addr, &addr))
            .unwrap();
        assert_eq!(session.session_id, 2);
    }

    #[test]
    fn start_new_session_for_unknown_device() {
        let mut mon = LoraMonitor::new();
        let addr = [0xAA, 0xBB, 0xCC, 0xDD];
        mon.start_new_session(addr).unwrap();

        // Should accept counter 1.
        let msg = make_msg(addr, LoraMessageType::UnconfirmedUp, 1, 1000);
        assert!(mon.inspect(&msg).allowed);
    }

    // -----------------------------------------------------------------------
    // Downlink frame counter tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn downlink_replay_detected() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];

        // First downlink.
        let msg1 = make_msg(addr, LoraMessageType::UnconfirmedDown, 10, 1000);
        let r1 = mon.inspect_downlink(&msg1);
        assert!(r1.allowed);

        // Valid next downlink.
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedDown, 11, 2000);
        let r2 = mon.inspect_downlink(&msg2);
        assert!(r2.allowed);

        // Replay downlink.
        let msg3 = make_msg(addr, LoraMessageType::UnconfirmedDown, 10, 3000);
        let r3 = mon.inspect_downlink(&msg3);
        assert!(!r3.allowed);
        assert!(r3.alert_count > 0);
    }

    #[test]
    fn uplink_and_downlink_counters_independent() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];

        // Send uplink with counter 10.
        let up = make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 1000);
        assert!(mon.inspect(&up).allowed);

        // Send downlink with counter 5 -- should be fine (separate counter).
        let down = make_msg(addr, LoraMessageType::UnconfirmedDown, 5, 2000);
        let r = mon.inspect_downlink(&down);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // ADR monitoring tests
    // -----------------------------------------------------------------------

    #[test]
    fn adr_normal_changes_not_anomalous() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];
        // A few data rate changes within window are fine.
        assert!(!mon.record_data_rate(addr, 0, 1_000_000));
        assert!(!mon.record_data_rate(addr, 1, 2_000_000));
        assert!(!mon.record_data_rate(addr, 2, 3_000_000));
    }

    #[test]
    fn adr_excessive_changes_flagged() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Create initial state.
        assert!(!mon.record_data_rate(addr, 0, 1_000_000));

        // Rapidly change data rates (more than MAX_ADR_CHANGES = 5).
        let mut anomalous = false;
        for i in 1..=8 {
            let dr = (i % 6) as u8; // cycle through rates to ensure changes
            let result = mon.record_data_rate(addr, dr, 1_000_000 + i * 100_000);
            if result {
                anomalous = true;
            }
        }
        assert!(
            anomalous,
            "should have flagged ADR anomaly after >5 changes"
        );
    }

    #[test]
    fn adr_window_reset() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Fill up changes within one window.
        assert!(!mon.record_data_rate(addr, 0, 1_000_000));
        for i in 1..=5 {
            mon.record_data_rate(addr, i as u8, 1_000_000 + i * 100_000);
        }

        // Jump past the ADR window (60 seconds later).
        let after_window = 1_000_000 + ADR_WINDOW_US + 1_000_000;
        // Should not be anomalous because window resets.
        assert!(!mon.record_data_rate(addr, 10, after_window));
    }

    #[test]
    fn adr_same_rate_not_counted() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Same data rate repeated many times should not trigger.
        for i in 0..20 {
            let result = mon.record_data_rate(addr, 5, 1_000_000 + i * 100_000);
            assert!(!result, "same data rate should not trigger anomaly");
        }
    }

    // -----------------------------------------------------------------------
    // Duty cycle tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn duty_cycle_normal_usage() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];
        // 100ms airtime is well within 1% of 1 hour.
        assert!(!mon.record_transmit(addr, 100_000, 1_000_000));
    }

    #[test]
    fn duty_cycle_exceeded() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Accumulate more than 36 seconds of airtime.
        // With proportional decay, use short intervals so decay is minimal.
        let mut exceeded = false;
        let mut ts = 1_000_000u64;
        for _ in 0..40 {
            // Each transmit: 1 second of airtime, spaced 1 second apart
            // so proportional decay is negligible (~0.03% per step).
            let result = mon.record_transmit(addr, 1_000_000, ts);
            if result {
                exceeded = true;
            }
            ts += 1_000_000; // 1 second apart, minimal decay
        }
        assert!(exceeded, "should have exceeded duty cycle limit");
    }

    #[test]
    fn duty_cycle_window_reset() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Use a lot of airtime.
        mon.record_transmit(addr, 30_000_000, 1_000_000);

        // Jump past the 1-hour window.
        let after_window = 1_000_000 + DUTY_CYCLE_WINDOW_US + 1_000_000;
        // Small transmit after window reset should be fine.
        assert!(!mon.record_transmit(addr, 100_000, after_window));
    }

    // -----------------------------------------------------------------------
    // Timestamp validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_anomaly_generates_alert() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // First message establishes baseline.
        let msg1 = make_msg(addr, LoraMessageType::UnconfirmedUp, 1, 1_000_000);
        let r1 = mon.inspect(&msg1);
        assert_eq!(r1.alert_count, 0);

        // Massive forward jump triggers timestamp anomaly.
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedUp, 2, 1_000_000_000_000);
        let r2 = mon.inspect(&msg2);
        // Should have a timestamp anomaly alert but still allow the message.
        assert!(r2.alert_count > 0);
        assert!(r2.allowed);
    }

    #[test]
    fn normal_timestamps_no_alert() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        let msg1 = make_msg(addr, LoraMessageType::UnconfirmedUp, 1, 1_000_000);
        let r1 = mon.inspect(&msg1);
        assert_eq!(r1.alert_count, 0);

        // Normal increment.
        let msg2 = make_msg(addr, LoraMessageType::UnconfirmedUp, 2, 2_000_000);
        let r2 = mon.inspect(&msg2);
        assert_eq!(r2.alert_count, 0);
    }

    // -----------------------------------------------------------------------
    // MonitorReset tests
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_reset_clears_runtime_state() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];

        // Accumulate state.
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 1000));
        mon.record_data_rate(addr, 5, 1000);
        mon.record_transmit(addr, 100_000, 1000);
        assert_eq!(mon.total_inspected(), 1);

        // Reset.
        mon.reset_state();

        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);

        // After reset, counter 0 should be accepted (session was cleared).
        let msg = make_msg(addr, LoraMessageType::UnconfirmedUp, 0, 2000);
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn monitor_reset_preserves_rules() {
        let mut mon = LoraMonitor::new();
        mon.add_rule([0x01; 4], DeviceAction::Block).unwrap();
        mon.set_join_flood_params(5, 5_000_000);

        // Reset runtime state.
        mon.reset_state();

        // Rules should still be in effect.
        assert_eq!(mon.rule_count(), 1);
        let msg = make_msg([0x01; 4], LoraMessageType::UnconfirmedUp, 1, 1000);
        let r = mon.inspect(&msg);
        assert!(!r.allowed, "block rule should survive reset");
    }

    #[test]
    fn monitor_reset_preserves_thresholds() {
        let mut mon = LoraMonitor::new();
        mon.set_join_flood_params(3, 5_000_000);

        mon.reset_state();

        // Flood threshold should still be 3.
        for i in 0..2 {
            let msg = make_msg([0; 4], LoraMessageType::JoinRequest, 0, (i + 1) * 1_000_000);
            assert!(mon.inspect(&msg).allowed);
        }
        let msg = make_msg([0; 4], LoraMessageType::JoinRequest, 0, 3_000_000);
        let r = mon.inspect(&msg);
        assert!(!r.allowed, "join flood threshold should survive reset");
    }

    // -----------------------------------------------------------------------
    // Alert source ID tests
    // -----------------------------------------------------------------------

    #[test]
    fn block_alert_has_correct_source_id() {
        let mut mon = LoraMonitor::new();
        mon.add_rule([0x01; 4], DeviceAction::Block).unwrap();
        let r = mon.inspect(&make_msg(
            [0x01; 4],
            LoraMessageType::UnconfirmedUp,
            1,
            1000,
        ));
        assert_eq!(r.alerts[0].source_id, ALERT_DEVICE_BLOCKED);
    }

    #[test]
    fn join_flood_alert_has_correct_source_id() {
        let mut mon = LoraMonitor::new();
        mon.set_join_flood_params(2, 10_000_000);
        let _ = mon.inspect(&make_msg(
            [0; 4],
            LoraMessageType::JoinRequest,
            0,
            1_000_000,
        ));
        let r = mon.inspect(&make_msg(
            [0; 4],
            LoraMessageType::JoinRequest,
            0,
            2_000_000,
        ));
        assert_eq!(r.alerts[0].source_id, ALERT_JOIN_FLOOD);
    }

    #[test]
    fn replay_alert_has_correct_source_id() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01; 4];
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 1000));
        // Counter 9 < 10 within the 64-counter window is now an out-of-order
        // delivery (acceptable, marks the bit). Replaying it is a replay.
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 9, 1500));
        let r = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 9, 2000));
        assert_eq!(r.alerts[0].source_id, ALERT_REPLAY_DETECTED);
    }

    #[test]
    fn start_new_session_then_counter_zero_allowed() {
        let mut monitor = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];
        // Establish session with counter 10
        let msg1 = LoraMessage {
            dev_addr: addr,
            frame_counter: 10,
            msg_type: LoraMessageType::UnconfirmedUp,
            timestamp_us: 1_000_000,
            ..LoraMessage::default()
        };
        assert!(monitor.inspect(&msg1).allowed);

        // Reset session
        monitor.start_new_session(addr).unwrap();

        // Counter 0 should now be allowed (not a false positive replay)
        let msg2 = LoraMessage {
            dev_addr: addr,
            frame_counter: 0,
            msg_type: LoraMessageType::UnconfirmedUp,
            timestamp_us: 2_000_000,
            ..LoraMessage::default()
        };
        let r = monitor.inspect(&msg2);
        assert!(r.allowed, "counter 0 after session reset should be allowed");
    }

    #[test]
    fn session_table_exhaustion_emits_alert() {
        let mut monitor = LoraMonitor::new();
        // Fill all MAX_TRACKED_DEVICES (16) session slots
        for i in 0..17u32 {
            let addr = [(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8];
            let msg = LoraMessage {
                dev_addr: addr,
                frame_counter: 1,
                msg_type: LoraMessageType::UnconfirmedUp,
                timestamp_us: (i as u64 + 1) * 1_000_000,
                ..LoraMessage::default()
            };
            let r = monitor.inspect(&msg);
            if i >= 16 {
                // 17th device should trigger exhaustion alert
                let has_exhaustion =
                    (0..r.alert_count as usize).any(|j| r.alerts[j].source_id == 7);
                assert!(has_exhaustion, "session table exhaustion alert expected");
            }
        }
    }

    #[test]
    fn remove_rule_works() {
        let mut monitor = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];
        monitor.add_rule(addr, DeviceAction::Block).unwrap();

        let msg = LoraMessage {
            dev_addr: addr,
            frame_counter: 1,
            msg_type: LoraMessageType::UnconfirmedUp,
            timestamp_us: 1_000_000,
            ..LoraMessage::default()
        };
        assert!(!monitor.inspect(&msg).allowed, "should be blocked");

        monitor.remove_rule(0).unwrap();

        let msg2 = LoraMessage {
            dev_addr: addr,
            frame_counter: 2,
            msg_type: LoraMessageType::UnconfirmedUp,
            timestamp_us: 2_000_000,
            ..LoraMessage::default()
        };
        assert!(
            monitor.inspect(&msg2).allowed,
            "should be allowed after rule removal"
        );
    }

    // -----------------------------------------------------------------------
    // Cross-direction sentinel regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn uplink_first_then_downlink_counter_zero_not_replay() {
        let mut mon = LoraMonitor::new();
        let addr = [0x01, 0x02, 0x03, 0x04];

        // Uplink creates session with up_frame_counter=10, down_frame_counter=u32::MAX.
        let up = make_msg(addr, LoraMessageType::UnconfirmedUp, 10, 1_000_000);
        assert!(mon.inspect(&up).allowed);

        // First downlink with counter 0 must be accepted (sentinel u32::MAX means "fresh").
        let down = make_msg(addr, LoraMessageType::UnconfirmedDown, 0, 2_000_000);
        let r = mon.inspect_downlink(&down);
        assert!(
            r.allowed,
            "first downlink counter 0 must NOT be flagged as replay"
        );
        assert_eq!(
            r.alert_count, 0,
            "no alerts expected for valid first downlink"
        );
    }

    #[test]
    fn downlink_first_then_uplink_counter_zero_not_replay() {
        let mut mon = LoraMonitor::new();
        let addr = [0x05, 0x06, 0x07, 0x08];

        // Downlink creates session with down_frame_counter=5, up_frame_counter=u32::MAX.
        let down = make_msg(addr, LoraMessageType::UnconfirmedDown, 5, 1_000_000);
        assert!(mon.inspect_downlink(&down).allowed);

        // First uplink with counter 0 must be accepted.
        let up = make_msg(addr, LoraMessageType::UnconfirmedUp, 0, 2_000_000);
        let r = mon.inspect(&up);
        assert!(
            r.allowed,
            "first uplink counter 0 must NOT be flagged as replay"
        );
    }

    #[test]
    fn lru_eviction_preserves_cross_direction_sentinels() {
        let mut mon = LoraMonitor::new();

        // Fill all session slots with uplink-only sessions.
        for i in 0..MAX_TRACKED_DEVICES as u32 {
            let addr = [0, 0, (i >> 8) as u8, i as u8];
            let msg = make_msg(
                addr,
                LoraMessageType::UnconfirmedUp,
                1,
                (i as u64 + 1) * 1_000_000,
            );
            let _ = mon.inspect(&msg);
        }

        // 17th device forces LRU eviction.
        let new_addr = [0xFF, 0xFF, 0xFF, 0xFF];
        let msg = make_msg(new_addr, LoraMessageType::UnconfirmedUp, 10, 100_000_000);
        let _ = mon.inspect(&msg);

        // With per-device windows the new session starts fresh: the first
        // downlink counter (sentinel u32::MAX -> any value) is accepted.
        // This is correct because per-device windows are independent of
        // any evicted device's history.
        let down = make_msg(new_addr, LoraMessageType::UnconfirmedDown, 1, 200_000_000);
        let r = mon.inspect_downlink(&down);
        assert!(
            r.allowed,
            "downlink counter 1 after LRU eviction must be accepted"
        );

        // Counter 0 < 1 with diff=1 is in-window and unseen, so accepted.
        let down0 = make_msg(new_addr, LoraMessageType::UnconfirmedDown, 0, 300_000_000);
        let r0 = mon.inspect_downlink(&down0);
        assert!(
            r0.allowed,
            "downlink counter 0 in-window after LRU eviction is acceptable out-of-order"
        );
        // Replaying counter 0 (whose bit is now set) must be rejected as a
        // replay; this exercises the per-device bitmap.
        let down0_again = make_msg(new_addr, LoraMessageType::UnconfirmedDown, 0, 400_000_000);
        let r0_again = mon.inspect_downlink(&down0_again);
        assert!(
            !r0_again.allowed,
            "second downlink counter 0 must be rejected as replay"
        );
    }

    #[test]
    fn join_request_triggers_flood_but_accept_does_not() {
        let mut mon = LoraMonitor::new();
        mon.set_join_flood_params(2, 10_000_000);

        // 2 JoinRequest messages should trigger flood.
        let _ = mon.inspect(&make_msg(
            [0; 4],
            LoraMessageType::JoinRequest,
            0,
            1_000_000,
        ));
        let r = mon.inspect(&make_msg(
            [0; 4],
            LoraMessageType::JoinRequest,
            0,
            2_000_000,
        ));
        assert!(!r.allowed, "2nd JoinRequest should trigger flood");

        // Reset the monitor to clear flood state.
        mon.reset_state();

        // 2 JoinAccept messages should NOT trigger flood.
        let _ = mon.inspect(&make_msg([0; 4], LoraMessageType::JoinAccept, 0, 3_000_000));
        let r = mon.inspect(&make_msg([0; 4], LoraMessageType::JoinAccept, 0, 4_000_000));
        assert!(r.allowed, "JoinAccept should not trigger flood detection");
    }

    #[test]
    fn alerts_dropped_counter_accessible() {
        let r = LoraInspectResult::clean();
        assert_eq!(r.alerts_dropped, 0);
    }

    #[test]
    fn table_exhaustion_granularity_tracked() {
        // Verify per-table exhaustion counters exist and are initialized to 0.
        let monitor = LoraMonitor::new();
        assert_eq!(monitor.session_table_exhaustions(), 0);
        assert_eq!(monitor.adr_table_exhaustions(), 0);
        assert_eq!(monitor.duty_table_exhaustions(), 0);
    }

    // -----------------------------------------------------------------------
    // Per-device frame-counter window tests
    // -----------------------------------------------------------------------

    #[test]
    fn per_device_window_in_order_accept() {
        let mut mon = LoraMonitor::new();
        let addr = [0xA0; 4];
        for c in [1u32, 2, 3, 100, 1000] {
            let m = make_msg(addr, LoraMessageType::UnconfirmedUp, c, 1000 + c as u64);
            assert!(
                mon.inspect(&m).allowed,
                "in-order counter {} should accept",
                c
            );
        }
    }

    #[test]
    fn per_device_window_replay_within_window_rejected() {
        let mut mon = LoraMonitor::new();
        let addr = [0xA1; 4];
        // Establish counter 100 then advance to 110.
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 100, 1000));
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 110, 2000));
        // Out-of-order delivery of 105 (in-window, unseen) is accepted.
        assert!(
            mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 105, 3000))
                .allowed
        );
        // Replay of 105 must be rejected.
        let r = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 105, 4000));
        assert!(!r.allowed, "replay within window must be rejected");
    }

    #[test]
    fn per_device_window_old_frame_below_window_rejected() {
        let mut mon = LoraMonitor::new();
        let addr = [0xA2; 4];
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 200, 1000));
        // diff=64 boundary still in window.
        assert!(
            mon.inspect(&make_msg(
                addr,
                LoraMessageType::UnconfirmedUp,
                200 - 64,
                2000
            ))
            .allowed
        );
        // diff=65 is below the window.
        let r = mon.inspect(&make_msg(
            addr,
            LoraMessageType::UnconfirmedUp,
            200 - 65,
            3000,
        ));
        assert!(!r.allowed, "frame below 64-counter window must be rejected");
    }

    #[test]
    fn per_device_window_forward_jump_within_window_accepts() {
        let mut mon = LoraMonitor::new();
        let addr = [0xA3; 4];
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 100, 1000));
        let r = mon.inspect(&make_msg(
            addr,
            LoraMessageType::UnconfirmedUp,
            100 + ACCEPT_FORWARD_WINDOW,
            2000,
        ));
        assert!(r.allowed, "forward jump within accept window must accept");
    }

    #[test]
    fn per_device_window_forward_jump_beyond_window_rejected() {
        let mut mon = LoraMonitor::new();
        let addr = [0xA4; 4];
        let _ = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 100, 1000));
        let r = mon.inspect(&make_msg(
            addr,
            LoraMessageType::UnconfirmedUp,
            100 + ACCEPT_FORWARD_WINDOW + 1,
            2000,
        ));
        assert!(!r.allowed, "forward jump beyond window must be rejected");
    }

    #[test]
    fn per_device_window_rollover_when_enabled_accepts() {
        let mut mon = LoraMonitor::new();
        mon.set_allow_counter_rollover(true);
        let addr = [0xA5; 4];
        // Seed at top of u32 range so rollover is plausible.
        let _ = mon.inspect(&make_msg(
            addr,
            LoraMessageType::UnconfirmedUp,
            0xFFFF_FFF0,
            1000,
        ));
        let r = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 0, 2000));
        assert!(r.allowed, "honest rollover must be accepted when enabled");
    }

    #[test]
    fn per_device_window_rollover_when_disabled_rejects() {
        let mut mon = LoraMonitor::new();
        // Default: rollover disabled.
        let addr = [0xA6; 4];
        let _ = mon.inspect(&make_msg(
            addr,
            LoraMessageType::UnconfirmedUp,
            0xFFFF_FFF0,
            1000,
        ));
        let r = mon.inspect(&make_msg(addr, LoraMessageType::UnconfirmedUp, 0, 2000));
        assert!(!r.allowed, "rollover with disabled config must be rejected");
    }

    #[test]
    fn per_device_window_lru_eviction_works() {
        // Verify LRU eviction does not propagate the evicted device's counter
        // as a global floor: a freshly admitted device must accept any
        // starting counter independently of evicted state.
        let mut mon = LoraMonitor::new();
        // Fill all session slots, all with high counters.
        for i in 0..MAX_TRACKED_DEVICES as u32 {
            let addr = [0x11, 0x22, (i >> 8) as u8, i as u8];
            let m = make_msg(
                addr,
                LoraMessageType::UnconfirmedUp,
                1_000_000,
                (i as u64 + 1) * 1_000_000,
            );
            let _ = mon.inspect(&m);
        }
        // Admit a 17th device which forces LRU eviction.
        let new_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let m_evict = make_msg(new_addr, LoraMessageType::UnconfirmedUp, 5, 100_000_000);
        let r_evict = mon.inspect(&m_evict);
        assert!(
            r_evict.allowed,
            "new device after eviction must accept its own counter (no global floor)"
        );
        // Continue from the new device's counter.
        assert!(
            mon.inspect(&make_msg(
                new_addr,
                LoraMessageType::UnconfirmedUp,
                6,
                200_000_000
            ))
            .allowed
        );
        // Replay of 5 on the new device is rejected.
        assert!(
            !mon.inspect(&make_msg(
                new_addr,
                LoraMessageType::UnconfirmedUp,
                5,
                300_000_000
            ))
            .allowed
        );
    }

    #[test]
    fn per_device_window_isolated_across_devices() {
        // Ensure two devices' windows are independent.
        let mut mon = LoraMonitor::new();
        let a = [0xB0; 4];
        let b = [0xB1; 4];
        // Device A advances to a high counter.
        assert!(
            mon.inspect(&make_msg(
                a,
                LoraMessageType::UnconfirmedUp,
                1_000_000,
                1000
            ))
            .allowed
        );
        // Device B can still legitimately start at 1.
        assert!(
            mon.inspect(&make_msg(b, LoraMessageType::UnconfirmedUp, 1, 2000))
                .allowed
        );
        assert!(
            mon.inspect(&make_msg(b, LoraMessageType::UnconfirmedUp, 2, 3000))
                .allowed
        );
        // Device A still rejects its own old counter (out of window).
        assert!(
            !mon.inspect(&make_msg(a, LoraMessageType::UnconfirmedUp, 1, 4000))
                .allowed
        );
    }
}
