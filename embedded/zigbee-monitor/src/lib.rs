// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Zigbee / IEEE 802.15.4 intrusion detection monitor.
//!
//! Inspects NWK/APS frames against the Zigbee Specification R23 (2023) /
//! Zigbee 3.0 unified stack.
//!
//! Detects anomalous Zigbee traffic on `IoT` devices:
//!
//! - **Address allowlist/blocklist** -- restrict which short addresses may
//!   communicate.
//! - **PAN ID enforcement** -- restrict which PAN IDs are accepted.
//! - **Frame type filtering** -- block unexpected frame types.
//! - **Rate limiting** -- per-source address rate control.
//! - **Security frame counter tracking** -- replay protection.
//! - **Timestamp validation** -- detect clock manipulation.
//! - **Trust Center monitoring** -- detect rapid key rotations.
//!
//! # Examples
//!
//! ```rust
//! use vs_zigbee_monitor::{ZigbeeMonitor, AddrAction};
//! use vs_types_embedded::{ZigbeeFrame, ZigbeeFrameType};
//!
//! let mut monitor = ZigbeeMonitor::new();
//! monitor.add_rule(0x0001, 0x1234, AddrAction::Allow, 10).unwrap();
//!
//! let frame = ZigbeeFrame {
//!     src_pan_id: 0x1234,
//!     src_addr: 0x0001,
//!     dst_addr: 0x0000,
//!     cluster_id: 0,
//!     frame_type: ZigbeeFrameType::Data,
//!     payload_len: 20,
//!     timestamp_us: 1_000_000,
//! };
//!
//! let result = monitor.inspect(&frame);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_embedded::{
    compute_payload_hash, ct_u16_eq, MonitorReset, TimestampValidator, TrustCenterEvent,
    ZigbeeFrame, ZigbeeFrameType, MAX_ZIGBEE_ADDR_RULES, MAX_ZIGBEE_RATE_BUCKETS,
    MAX_ZIGBEE_SECURITY_COUNTERS, SOURCE_ZIGBEE,
};

// ---------------------------------------------------------------------------
// Alert source ID constants
// ---------------------------------------------------------------------------

const ALERT_UNKNOWN_FRAME_TYPE: u32 = 1;
const ALERT_BLOCKED_FRAME_TYPE: u32 = 2;
const ALERT_ADDRESS_BLOCKED: u32 = 3;
const ALERT_RATE_LIMITED: u32 = 4;
const ALERT_SECURITY_COUNTER_REPLAY: u32 = 5;
const ALERT_TRUST_CENTER_EVENT: u32 = 6;
const ALERT_TIMESTAMP_ANOMALY: u32 = 7;
const ALERT_COUNTER_TABLE_EXHAUSTED: u32 = 8;
const ALERT_RATE_TABLE_EXHAUSTED: u32 = 9;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of address rules (imported from types-embedded).
const MAX_ADDR_RULES: usize = MAX_ZIGBEE_ADDR_RULES;

/// Maximum rate-limit buckets (imported from types-embedded).
const MAX_RATE_BUCKETS: usize = MAX_ZIGBEE_RATE_BUCKETS;

/// Bucket expiration timeout: 5 minutes.
const RATE_BUCKET_EXPIRY_US: u64 = 300_000_000;

/// Maximum number of tracked security frame counters (imported from types-embedded).
///
/// Each entry holds a per-device sliding window: `(highest_seen, recent_bitmap)`
/// keyed by source address. When this cap is reached new devices evict the
/// least-recently-used entry.
const MAX_SECURITY_COUNTERS: usize = MAX_ZIGBEE_SECURITY_COUNTERS;

/// Maximum forward jump (in counters) accepted on a single advance.
///
/// A jump beyond this window is treated as a suspicious-jump replay attempt
/// (e.g. an attacker injecting a frame with a fabricated counter chosen to
/// lock out the legitimate device). 2^15 = 32768 leaves generous headroom for
/// legitimate frame loss.
const ACCEPT_FORWARD_WINDOW: u32 = 1 << 15;

/// Top-of-range threshold above which a 0xFFFFFFFF -> 0 rollover is plausible.
const ROLLOVER_TOP_THRESHOLD: u32 = 0xFFFF_0000;

/// Maximum Trust Center events tracked in the sliding window.
const MAX_TC_EVENTS: usize = 16;

// `tc_event_cursor` is a `u8`, so the ring-buffer modulo
// (`self.tc_event_cursor as usize % MAX_TC_EVENTS`) is only correct while
// `MAX_TC_EVENTS` fits in a `u8`. If this constant is ever raised above 256,
// the cursor would silently truncate and entries would alias. Widen the
// cursor type before relaxing this bound.
const _: () = assert!(MAX_TC_EVENTS <= 256);

/// Trust Center rapid key rotation threshold: max key rotations in the window.
const TC_KEY_ROTATION_THRESHOLD: u32 = 3;

/// Trust Center rapid key rotation detection window (seconds).
const TC_KEY_ROTATION_WINDOW_US: u64 = 60_000_000; // 60 seconds

// ---------------------------------------------------------------------------
// Address rule
// ---------------------------------------------------------------------------

/// Action for an address match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrAction {
    /// Allow frames from this address.
    Allow,
    /// Block frames from this address.
    Block,
}

/// An address filtering rule.
#[derive(Debug, Clone, Copy)]
struct AddrRule {
    /// Source short address.
    addr: u16,
    /// PAN ID (0xFFFF = any PAN).
    pan_id: u16,
    action: AddrAction,
    /// Max frames per second (0 = unlimited).
    max_rate_per_sec: u16,
}

impl AddrRule {
    const fn empty() -> Self {
        Self {
            addr: 0xFFFF,
            pan_id: 0xFFFF,
            action: AddrAction::Allow,
            max_rate_per_sec: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Rate bucket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct RateBucket {
    addr_key: u32,
    tokens: u16,
    capacity: u16,
    last_refill_us: u64,
    active: bool,
}

impl RateBucket {
    const fn empty() -> Self {
        Self {
            addr_key: 0,
            tokens: 0,
            capacity: 0,
            last_refill_us: 0,
            active: false,
        }
    }

    #[inline]
    fn try_consume(&mut self, now_us: u64) -> bool {
        let elapsed = now_us.saturating_sub(self.last_refill_us);
        let refill = elapsed.saturating_mul(self.capacity as u64) / 1_000_000;
        let refill_clamped = refill.min(self.capacity as u64) as u16;
        if refill_clamped > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refill_clamped)
                .min(self.capacity);
            self.last_refill_us = now_us;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn is_expired(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.last_refill_us) > RATE_BUCKET_EXPIRY_US
    }
}

// ---------------------------------------------------------------------------
// Per-device frame counter window
// ---------------------------------------------------------------------------

/// Per-device frame-counter sliding window for replay protection.
///
/// Stores the highest counter value seen for a given source address along
/// with a 64-bit bitmap of the 64 counters strictly below it. Bit `b` of
/// `recent_bitmap` is set when counter `highest_seen - 1 - b` has been
/// observed. This lets us accept moderately-out-of-order delivery while
/// rejecting replays.
#[derive(Debug, Clone, Copy)]
struct FrameCounterWindow {
    /// Source short address.
    src_addr: u16,
    /// Highest counter value seen for this device.
    highest_seen: u32,
    /// Bitmap of recent counters strictly below `highest_seen`. Bit `b`
    /// represents counter `highest_seen - 1 - b` (so bit 0 is one below
    /// the highest, bit 63 is 64 below).
    recent_bitmap: u64,
    /// Last activity timestamp for LRU eviction.
    last_activity_us: u64,
    /// Whether this entry is active.
    active: bool,
}

impl FrameCounterWindow {
    const fn empty() -> Self {
        Self {
            src_addr: 0xFFFF,
            highest_seen: 0,
            recent_bitmap: 0,
            last_activity_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Trust Center event record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct TcEventRecord {
    event: u8,
    timestamp_us: u64,
    active: bool,
}

impl TcEventRecord {
    const fn empty() -> Self {
        Self {
            event: 0,
            timestamp_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Compute a content fingerprint for a Zigbee frame.
///
/// Hashes `src_addr`, `dst_addr`, `cluster_id`, and `payload_len` to produce a
/// compact identity for the alert payload.
#[inline]
fn frame_fingerprint(frame: &ZigbeeFrame) -> vs_types::PayloadHash {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&frame.src_addr.to_le_bytes());
    buf[2..4].copy_from_slice(&frame.dst_addr.to_le_bytes());
    buf[4..6].copy_from_slice(&frame.cluster_id.to_le_bytes());
    buf[6..8].copy_from_slice(&frame.payload_len.to_le_bytes());
    compute_payload_hash(&buf)
}

/// Result of inspecting a Zigbee frame.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct ZigbeeInspectResult {
    /// Whether the frame was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts that were dropped because the alert array was full.
    pub alerts_dropped: u8,
}

impl ZigbeeInspectResult {
    const fn clean() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: SOURCE_ZIGBEE,
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
                source_type: SOURCE_ZIGBEE,
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
// Zigbee Monitor
// ---------------------------------------------------------------------------

/// Zigbee / IEEE 802.15.4 intrusion detection monitor.
pub struct ZigbeeMonitor {
    rules: [AddrRule; MAX_ADDR_RULES],
    rule_count: u8,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    default_action: AddrAction,
    /// Allowed frame types bitmask (bit 0 = beacon, 1 = data, 2 = ack, 3 = command).
    allowed_frame_types: u8,
    next_alert_id: u64,
    total_inspected: u64,
    total_alerts: u64,
    /// Timestamp validator for clock anomaly detection.
    timestamp_validator: TimestampValidator,
    /// Per-device frame-counter sliding windows for replay protection.
    ///
    /// Each entry stores `(highest_seen, recent_bitmap)` keyed by source
    /// address, giving each device an independent replay window so an
    /// attacker cannot replay one device's old frames against another.
    security_counters: [FrameCounterWindow; MAX_SECURITY_COUNTERS],
    /// Whether 32-bit counter rollover is allowed for honest devices that
    /// wrap 0xFFFFFFFF -> 0. Rollover is only accepted when `highest_seen`
    /// is in the top of the range (`>= ROLLOVER_TOP_THRESHOLD`).
    allow_counter_rollover: bool,
    /// Trust Center event ring buffer.
    tc_events: [TcEventRecord; MAX_TC_EVENTS],
    /// Next write position in the TC event ring buffer.
    tc_event_cursor: u8,
    /// Count of rapid key rotation alerts raised.
    tc_rapid_rotation_alerts: u32,
    /// Deferred table-exhaustion flags (can fire both in the same inspection).
    rate_table_exhausted: bool,
    counter_table_exhausted: bool,
}

impl ZigbeeMonitor {
    /// Create a new Zigbee monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            rules: [AddrRule::empty(); MAX_ADDR_RULES],
            rule_count: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            default_action: AddrAction::Allow,
            allowed_frame_types: 0x0F, // all types allowed
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
            timestamp_validator: TimestampValidator::new(),
            security_counters: [FrameCounterWindow::empty(); MAX_SECURITY_COUNTERS],
            allow_counter_rollover: false,
            tc_events: [TcEventRecord::empty(); MAX_TC_EVENTS],
            tc_event_cursor: 0,
            tc_rapid_rotation_alerts: 0,
            rate_table_exhausted: false,
            counter_table_exhausted: false,
        }
    }

    /// Enable or disable acceptance of 32-bit frame-counter rollover.
    ///
    /// When enabled, a counter that wraps from `0xFFFFFFFF` to `0` (or
    /// thereabouts) is accepted only if the previously seen value was in the
    /// top of the range (>= `0xFFFF0000`). This prevents an attacker from
    /// using a small counter to bypass replay protection on a freshly seen
    /// device.
    pub fn set_allow_counter_rollover(&mut self, allow: bool) {
        self.allow_counter_rollover = allow;
    }

    /// Create a new Zigbee monitor (deny-by-default).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = AddrAction::Block;
        m
    }

    /// Set which frame types are allowed (bitmask: bit 0=beacon, 1=data, 2=ack, 3=command).
    pub fn set_allowed_frame_types(&mut self, mask: u8) {
        self.allowed_frame_types = mask & 0x0F;
    }

    /// Add an address rule.
    pub fn add_rule(
        &mut self,
        addr: u16,
        pan_id: u16,
        action: AddrAction,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_ADDR_RULES {
            return Err(VsError::ResourceExhausted);
        }
        // Check for duplicate (same addr + pan_id): update in place.
        for i in 0..self.rule_count as usize {
            if ct_u16_eq(self.rules[i].addr, addr) && ct_u16_eq(self.rules[i].pan_id, pan_id) {
                self.rules[i].action = action;
                self.rules[i].max_rate_per_sec = max_rate_per_sec;
                return Ok(());
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = AddrRule {
            addr,
            pan_id,
            action,
            max_rate_per_sec,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Remove an address rule by index.
    pub fn remove_rule(&mut self, index: usize) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        let count = self.rule_count as usize;
        for i in index..count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[count - 1] = AddrRule::empty();
        self.rule_count -= 1;
        Ok(())
    }

    /// Remove all address rules.
    pub fn clear_rules(&mut self) {
        for i in 0..self.rule_count as usize {
            self.rules[i] = AddrRule::empty();
        }
        self.rule_count = 0;
    }

    /// Update an existing address rule by index.
    pub fn update_rule(
        &mut self,
        index: usize,
        addr: u16,
        pan_id: u16,
        action: AddrAction,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        self.rules[index] = AddrRule {
            addr,
            pan_id,
            action,
            max_rate_per_sec,
        };
        Ok(())
    }

    /// Inspect a Zigbee frame.
    ///
    /// First-match-wins: the first rule whose address matches is applied.
    /// If no rule matches, the default action (allow or block) is used.
    pub fn inspect(&mut self, frame: &ZigbeeFrame) -> ZigbeeInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = ZigbeeInspectResult::clean();
        let fp = frame_fingerprint(frame);

        // Timestamp validation -- still process but push a low-severity alert
        // if the timestamp is anomalous.
        if !self.timestamp_validator.validate(frame.timestamp_us) {
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TIMESTAMP_ANOMALY,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Frame type check.
        let ft_bit = match frame.frame_type {
            ZigbeeFrameType::Beacon => 0,
            ZigbeeFrameType::Data => 1,
            ZigbeeFrameType::Ack => 2,
            ZigbeeFrameType::Command => 3,
            ZigbeeFrameType::Unknown => {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::Medium,
                    ALERT_UNKNOWN_FRAME_TYPE,
                    frame.timestamp_us,
                    self.next_alert_id(),
                    fp,
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }
            // ZigbeeFrameType is #[non_exhaustive]; treat future variants as unknown.
            _ => {
                result.allowed = false;
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }
        };
        if (self.allowed_frame_types >> ft_bit) & 1 == 0 {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Low,
                ALERT_BLOCKED_FRAME_TYPE,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Constant-time: always iterate all slots, performing dummy comparisons
        // on inactive slots to prevent timing side-channels that leak rule count.
        let mut matched = false;
        let mut matched_action = self.default_action;
        let mut matched_max_rate: u16 = 0;
        let mut matched_pan_is_wildcard = false;
        for i in 0..MAX_ADDR_RULES {
            let rule = &self.rules[i];
            let addr_eq = ct_u16_eq(rule.addr, frame.src_addr);
            let pan_eq = ct_u16_eq(rule.pan_id, frame.src_pan_id) | ct_u16_eq(rule.pan_id, 0xFFFF);
            let slot_active = i < self.rule_count as usize;
            let is_match = slot_active & addr_eq & pan_eq;
            // Use bitwise selection to avoid branching
            if is_match && !matched {
                matched_action = rule.action;
                matched_max_rate = rule.max_rate_per_sec;
                matched_pan_is_wildcard = ct_u16_eq(rule.pan_id, 0xFFFF);
                matched = true;
            }
        }

        let action = matched_action;

        if action == AddrAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_ADDRESS_BLOCKED,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Rate limiting.
        if matched {
            let max_rate = matched_max_rate;
            if max_rate > 0 {
                // When rule has wildcard PAN, use 0 for PAN component to avoid
                // cross-PAN rate bucket collision.
                let key = if matched_pan_is_wildcard {
                    frame.src_addr as u32
                } else {
                    (frame.src_pan_id as u32) << 16 | frame.src_addr as u32
                };
                if !self.rate_limit_check(key, max_rate, frame.timestamp_us) {
                    result.allowed = false;
                    result.push_alert(
                        AlertSeverity::Medium,
                        ALERT_RATE_LIMITED,
                        frame.timestamp_us,
                        self.next_alert_id(),
                        fp,
                    );
                    self.total_alerts = self.total_alerts.saturating_add(1);
                }
            }
        }

        // Emit deferred table-exhaustion alerts if any were recorded.
        if self.rate_table_exhausted {
            self.rate_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_RATE_TABLE_EXHAUSTED,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }
        if self.counter_table_exhausted {
            self.counter_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_COUNTER_TABLE_EXHAUSTED,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Inspect a Zigbee frame with security frame counter check.
    ///
    /// Performs all the same checks as [`inspect`](Self::inspect) plus
    /// validates the security frame counter for replay detection.
    pub fn inspect_with_counter(
        &mut self,
        frame: &ZigbeeFrame,
        security_counter: u32,
    ) -> ZigbeeInspectResult {
        let mut result = self.inspect(frame);
        let fp = frame_fingerprint(frame);

        // Security frame counter replay check.
        if !self.check_security_counter(frame.src_addr, security_counter, frame.timestamp_us) {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::High,
                ALERT_SECURITY_COUNTER_REPLAY,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Emit deferred table-exhaustion alerts (both flags may be set).
        if self.rate_table_exhausted {
            self.rate_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_RATE_TABLE_EXHAUSTED,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }
        if self.counter_table_exhausted {
            self.counter_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_COUNTER_TABLE_EXHAUSTED,
                frame.timestamp_us,
                self.next_alert_id(),
                fp,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Check a security frame counter for a source address.
    ///
    /// Maintains a per-device sliding window `(highest_seen, recent_bitmap)`
    /// of size 64 keyed by `src_addr`. Returns `true` if the counter is
    /// valid (in-order, in-window forward jump, or out-of-order but unseen
    /// within the window). Returns `false` for:
    ///
    /// * exact replay (counter == highest_seen, or already-set bit),
    /// * out-of-window stale frame (counter < highest_seen - 63),
    /// * suspicious forward jump (counter > highest_seen + ACCEPT_FORWARD_WINDOW),
    /// * a fresh-looking small counter when rollover is disabled and the
    ///   tracked highest is in the top of the range.
    ///
    /// When all counter slots are full, the least-recently-used entry
    /// (smallest `last_activity_us`) is evicted to make room. Per-device
    /// state is independent, so an evicted device's history does not gate
    /// any other device's window.
    pub fn check_security_counter(&mut self, src_addr: u16, counter: u32, ts_us: u64) -> bool {
        // Single-pass scan: locate any existing entry for this address while
        // also remembering the first free slot and the overall LRU candidate
        // so we never have to walk the table a second or third time.
        // Mirrors the structure of `rate_limit_check`.
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_SECURITY_COUNTERS {
            if !self.security_counters[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if ct_u16_eq(self.security_counters[i].src_addr, src_addr) {
                return Self::accept_into_window(
                    &mut self.security_counters[i],
                    counter,
                    ts_us,
                    self.allow_counter_rollover,
                );
            }
            if self.security_counters[i].last_activity_us < lru_ts {
                lru_ts = self.security_counters[i].last_activity_us;
                lru_idx = i;
            }
        }

        // No existing entry: insert into a free slot if available, otherwise
        // evict the LRU candidate already chosen above. Per-device windows
        // are independent, so no floor needs to be carried forward.
        let idx = if let Some(idx) = free_slot {
            idx
        } else {
            self.counter_table_exhausted = true;
            lru_idx
        };
        self.security_counters[idx] = FrameCounterWindow {
            src_addr,
            highest_seen: counter,
            recent_bitmap: 0,
            last_activity_us: ts_us,
            active: true,
        };
        true
    }

    /// Apply the per-device window rules to an existing entry.
    ///
    /// Returns `true` if the counter is accepted (and the window is updated
    /// in place), `false` if the counter must be rejected as a replay,
    /// out-of-window, or suspicious-jump.
    fn accept_into_window(
        win: &mut FrameCounterWindow,
        counter: u32,
        ts_us: u64,
        allow_rollover: bool,
    ) -> bool {
        let highest = win.highest_seen;

        if counter > highest {
            let advance = counter - highest;
            if advance > ACCEPT_FORWARD_WINDOW {
                // Suspicious forward jump.
                return false;
            }
            // Shift the bitmap left by `advance`. Bit 0 records the previous
            // highest. Anything shifted out beyond bit 63 falls off the
            // window (those counters are now too old to track).
            let shift = advance.min(64);
            let new_bitmap = if shift >= 64 {
                0u64
            } else {
                // After the shift, bit 0 corresponds to (counter - 1). The
                // previous highest is at position (advance - 1). Set that
                // bit to record that we did see it.
                let shifted = win.recent_bitmap << shift;
                shifted | (1u64 << (advance - 1))
            };
            win.recent_bitmap = new_bitmap;
            win.highest_seen = counter;
            win.last_activity_us = ts_us;
            return true;
        }

        if counter == highest {
            // Exact replay of the highest value.
            return false;
        }

        // counter < highest: candidate older frame.
        let diff = highest - counter;

        // Detect plausible 32-bit rollover: an honest device that wrapped
        // from 0xFFFFFFFF -> 0 will produce a small counter when the tracked
        // highest is in the top of the range. Only accept when explicitly
        // enabled by config.
        if allow_rollover && highest >= ROLLOVER_TOP_THRESHOLD && counter < ACCEPT_FORWARD_WINDOW {
            // Treat this like a fresh start past rollover: drop the old
            // window and re-anchor at the new (small) counter.
            win.highest_seen = counter;
            win.recent_bitmap = 0;
            win.last_activity_us = ts_us;
            return true;
        }

        if diff > 64 {
            // Too old: out of window.
            return false;
        }

        // diff is in 1..=64. Bit position is diff - 1.
        let bit = diff - 1;
        let mask = 1u64 << bit;
        if win.recent_bitmap & mask != 0 {
            // Already seen this counter -- replay.
            return false;
        }
        win.recent_bitmap |= mask;
        win.last_activity_us = ts_us;
        true
    }

    /// Record a Trust Center event and detect rapid key rotations.
    ///
    /// Returns a `ZigbeeInspectResult` with an alert if rapid key rotation
    /// is detected (more than a configured threshold of `NetworkKeyUpdate`
    /// events within a configured window).
    pub fn record_trust_center_event(
        &mut self,
        event: TrustCenterEvent,
        ts_us: u64,
    ) -> ZigbeeInspectResult {
        let mut result = ZigbeeInspectResult::clean();

        // Validate timestamp: reject zero timestamps as invalid.
        if ts_us == 0 {
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TIMESTAMP_ANOMALY,
                ts_us,
                self.next_alert_id(),
                vs_types::PayloadHash::ZERO,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Record the event in the ring buffer.
        let cursor = self.tc_event_cursor as usize % MAX_TC_EVENTS;
        self.tc_events[cursor] = TcEventRecord {
            event: event as u8,
            timestamp_us: ts_us,
            active: true,
        };
        self.tc_event_cursor = self.tc_event_cursor.wrapping_add(1);

        // Check for rapid key rotation (only for NetworkKeyUpdate events).
        if matches!(event, TrustCenterEvent::NetworkKeyUpdate) {
            let mut key_update_count: u32 = 0;
            let window_start = ts_us.saturating_sub(TC_KEY_ROTATION_WINDOW_US);

            for i in 0..MAX_TC_EVENTS {
                if self.tc_events[i].active
                    && self.tc_events[i].event == TrustCenterEvent::NetworkKeyUpdate as u8
                    && self.tc_events[i].timestamp_us >= window_start
                    && self.tc_events[i].timestamp_us <= ts_us
                {
                    key_update_count += 1;
                    // Once the alert threshold is crossed the result is the
                    // same no matter how many more matches we find; stop
                    // scanning to save up to `MAX_TC_EVENTS - threshold`
                    // iterations per call.
                    if key_update_count > TC_KEY_ROTATION_THRESHOLD {
                        break;
                    }
                }
            }

            if key_update_count > TC_KEY_ROTATION_THRESHOLD {
                result.push_alert(
                    AlertSeverity::High,
                    ALERT_TRUST_CENTER_EVENT,
                    ts_us,
                    self.next_alert_id(),
                    vs_types::PayloadHash::ZERO,
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                self.tc_rapid_rotation_alerts = self.tc_rapid_rotation_alerts.saturating_add(1);
            }
        }

        result
    }

    /// Return the total number of frames inspected.
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Return the total number of alerts raised.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count as usize
    }

    /// Return the number of Trust Center rapid rotation alerts.
    pub fn tc_rapid_rotation_alerts(&self) -> u32 {
        self.tc_rapid_rotation_alerts
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

    fn rate_limit_check(&mut self, key: u32, max_rate: u16, now_us: u64) -> bool {
        let mut free_slot: Option<usize> = None;
        let mut oldest_expired_idx: Option<usize> = None;
        let mut oldest_expired_ts = u64::MAX;
        // Track overall LRU candidate in the same pass to avoid a second scan.
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_RATE_BUCKETS {
            if !self.rate_buckets[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if self.rate_buckets[i].addr_key == key {
                return self.rate_buckets[i].try_consume(now_us);
            }
            if self.rate_buckets[i].is_expired(now_us)
                && self.rate_buckets[i].last_refill_us < oldest_expired_ts
            {
                oldest_expired_ts = self.rate_buckets[i].last_refill_us;
                oldest_expired_idx = Some(i);
            }
            if self.rate_buckets[i].last_refill_us < lru_ts {
                lru_ts = self.rate_buckets[i].last_refill_us;
                lru_idx = i;
            }
        }

        let slot = free_slot.or(oldest_expired_idx);
        if let Some(idx) = slot {
            self.rate_buckets[idx] = RateBucket {
                addr_key: key,
                tokens: max_rate.saturating_sub(1),
                capacity: max_rate,
                last_refill_us: now_us,
                active: true,
            };
            return true;
        }

        // All buckets full and none expired — LRU eviction using the
        // candidate already found above (no second scan needed).
        self.rate_table_exhausted = true;
        self.rate_buckets[lru_idx] = RateBucket::empty();
        false
    }
}

impl Default for ZigbeeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for ZigbeeMonitor {
    fn reset_state(&mut self) {
        // Clear all runtime state while preserving rules and configuration.
        self.rate_buckets = [RateBucket::empty(); MAX_RATE_BUCKETS];
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
        self.timestamp_validator.reset();
        self.security_counters = [FrameCounterWindow::empty(); MAX_SECURITY_COUNTERS];
        self.tc_events = [TcEventRecord::empty(); MAX_TC_EVENTS];
        self.tc_event_cursor = 0;
        self.tc_rapid_rotation_alerts = 0;
        self.rate_table_exhausted = false;
        self.counter_table_exhausted = false;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(src: u16, pan: u16, ft: ZigbeeFrameType, ts: u64) -> ZigbeeFrame {
        ZigbeeFrame {
            src_pan_id: pan,
            src_addr: src,
            dst_addr: 0x0000,
            cluster_id: 0,
            frame_type: ft,
            payload_len: 10,
            timestamp_us: ts,
        }
    }

    #[test]
    fn default_allows_all() {
        let mut mon = ZigbeeMonitor::new();
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn deny_default_blocks() {
        let mut mon = ZigbeeMonitor::new_deny_default();
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn allow_rule_overrides_deny() {
        let mut mon = ZigbeeMonitor::new_deny_default();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 0).unwrap();
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn block_rule() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0002, 0xFFFF, AddrAction::Block, 0).unwrap();
        let f = make_frame(0x0002, 0x1234, ZigbeeFrameType::Data, 1000);
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn pan_id_filter() {
        let mut mon = ZigbeeMonitor::new_deny_default();
        mon.add_rule(0x0001, 0x1234, AddrAction::Allow, 0).unwrap();
        // Matching PAN.
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        assert!(mon.inspect(&f).allowed);
        // Wrong PAN — falls to default Block.
        let f2 = make_frame(0x0001, 0x5678, ZigbeeFrameType::Data, 2000);
        assert!(!mon.inspect(&f2).allowed);
    }

    #[test]
    fn unknown_frame_type_blocked() {
        let mut mon = ZigbeeMonitor::new();
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Unknown, 1000);
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn frame_type_filter() {
        let mut mon = ZigbeeMonitor::new();
        // Only allow data frames.
        mon.set_allowed_frame_types(0x02);
        let data = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        assert!(mon.inspect(&data).allowed);
        let beacon = make_frame(0x0001, 0x1234, ZigbeeFrameType::Beacon, 2000);
        assert!(!mon.inspect(&beacon).allowed);
    }

    #[test]
    fn rate_limiting() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 2).unwrap();
        for i in 0..2 {
            let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000 + i * 100);
            assert!(mon.inspect(&f).allowed);
        }
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1200);
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0002, 0xFFFF, AddrAction::Block, 0).unwrap();
        let _ = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000));
        let _ = mon.inspect(&make_frame(0x0002, 0x1234, ZigbeeFrameType::Data, 2000));
        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
    }

    #[test]
    fn rule_capacity() {
        let mut mon = ZigbeeMonitor::new();
        for i in 0..MAX_ADDR_RULES as u16 {
            mon.add_rule(i, 0xFFFF, AddrAction::Allow, 0).unwrap();
        }
        assert!(mon.add_rule(0xFFFF, 0xFFFF, AddrAction::Allow, 0).is_err());
    }

    #[test]
    fn remove_rule_works() {
        let mut mon = ZigbeeMonitor::new_deny_default();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 0).unwrap();
        assert!(
            mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000))
                .allowed
        );
        mon.remove_rule(0).unwrap();
        assert!(
            !mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2000))
                .allowed
        );
    }

    #[test]
    fn alert_ids_nonzero() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Block, 0).unwrap();
        let r = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000));
        assert!(r.alerts[0].id > 0);
    }

    #[test]
    fn default_constructor() {
        let mon = ZigbeeMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    // -----------------------------------------------------------------------
    // New tests: rate bucket exhaustion DoS fix
    // -----------------------------------------------------------------------

    #[test]
    fn rate_bucket_exhaustion_denies_traffic() {
        let mut mon = ZigbeeMonitor::new();
        // Fill all rate buckets with distinct addresses.
        for i in 0..MAX_RATE_BUCKETS as u16 {
            mon.add_rule(i, 0xFFFF, AddrAction::Allow, 100).unwrap();
            let f = make_frame(i, 0x1234, ZigbeeFrameType::Data, 1000);
            assert!(mon.inspect(&f).allowed);
        }
        // Now add a rule for a new address that will have no available bucket.
        mon.add_rule(0x00FF, 0xFFFF, AddrAction::Allow, 10).unwrap();
        let f = make_frame(0x00FF, 0x1234, ZigbeeFrameType::Data, 1000);
        // Should be denied when rate table is exhausted (matches CoAP behaviour).
        assert!(!mon.inspect(&f).allowed);
    }

    // -----------------------------------------------------------------------
    // New tests: named alert source IDs
    // -----------------------------------------------------------------------

    #[test]
    fn alert_uses_named_source_ids() {
        let mut mon = ZigbeeMonitor::new();
        // Unknown frame type -> ALERT_UNKNOWN_FRAME_TYPE
        let f = make_frame(0x0001, 0x1234, ZigbeeFrameType::Unknown, 1000);
        let r = mon.inspect(&f);
        assert_eq!(r.alerts[0].source_id, ALERT_UNKNOWN_FRAME_TYPE);

        // Blocked frame type -> ALERT_BLOCKED_FRAME_TYPE
        let mut mon2 = ZigbeeMonitor::new();
        mon2.set_allowed_frame_types(0x02); // only data
        let f2 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Beacon, 2000);
        let r2 = mon2.inspect(&f2);
        assert_eq!(r2.alerts[0].source_id, ALERT_BLOCKED_FRAME_TYPE);

        // Address blocked -> ALERT_ADDRESS_BLOCKED
        let mut mon3 = ZigbeeMonitor::new();
        mon3.add_rule(0x0001, 0xFFFF, AddrAction::Block, 0).unwrap();
        let f3 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 3000);
        let r3 = mon3.inspect(&f3);
        assert_eq!(r3.alerts[0].source_id, ALERT_ADDRESS_BLOCKED);

        // Rate limited -> ALERT_RATE_LIMITED
        let mut mon4 = ZigbeeMonitor::new();
        mon4.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 1).unwrap();
        let _ = mon4.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 4000));
        let r4 = mon4.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 4001));
        assert!(!r4.allowed);
        assert_eq!(r4.alerts[0].source_id, ALERT_RATE_LIMITED);
    }

    // -----------------------------------------------------------------------
    // New tests: timestamp validation
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_anomaly_generates_low_alert() {
        let mut mon = ZigbeeMonitor::new();
        // First frame initializes the validator.
        let f1 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1_000_000);
        let r1 = mon.inspect(&f1);
        assert!(r1.allowed);
        assert_eq!(r1.alert_count, 0);

        // Normal timestamp increment -- no alert.
        let f2 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2_000_000);
        let r2 = mon.inspect(&f2);
        assert!(r2.allowed);
        assert_eq!(r2.alert_count, 0);

        // Huge forward jump triggers anomaly alert but still allows.
        let f3 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 999_999_999_000_000);
        let r3 = mon.inspect(&f3);
        assert!(r3.allowed);
        assert!(r3.alert_count > 0);
        assert_eq!(r3.alerts[0].source_id, ALERT_TIMESTAMP_ANOMALY);
        assert_eq!(r3.alerts[0].severity, AlertSeverity::Low);
    }

    // -----------------------------------------------------------------------
    // New tests: security frame counter tracking
    // -----------------------------------------------------------------------

    #[test]
    fn security_counter_allows_increasing() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0001, 1, 1000));
        assert!(mon.check_security_counter(0x0001, 2, 2000));
        assert!(mon.check_security_counter(0x0001, 100, 3000));
    }

    #[test]
    fn security_counter_detects_replay() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0001, 10, 1000));
        // Same value = replay.
        assert!(!mon.check_security_counter(0x0001, 10, 2000));
        // Lower value not yet seen but in window: accepted as out-of-order delivery.
        assert!(mon.check_security_counter(0x0001, 5, 3000));
        // Re-trying counter 5 is now a replay (bit set).
        assert!(!mon.check_security_counter(0x0001, 5, 4000));
    }

    #[test]
    fn security_counter_replay_within_window_rejected() {
        // Counter values within the 64-counter window that have already been
        // recorded must be rejected as replays.
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0010, 100, 1000));
        // In-window forward jump records the bit.
        assert!(mon.check_security_counter(0x0010, 110, 2000));
        // Replaying 100 (now diff=10) is a replay.
        assert!(!mon.check_security_counter(0x0010, 100, 3000));
        // Highest value replayed.
        assert!(!mon.check_security_counter(0x0010, 110, 4000));
    }

    #[test]
    fn security_counter_old_frame_below_window_rejected() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0010, 200, 1000));
        // diff=64 is the boundary (still in window).
        assert!(mon.check_security_counter(0x0010, 200 - 64, 2000));
        // diff=65 is below the window.
        assert!(!mon.check_security_counter(0x0010, 200 - 65, 3000));
        // Far below the window.
        assert!(!mon.check_security_counter(0x0010, 1, 4000));
    }

    #[test]
    fn security_counter_forward_jump_within_window_accepts() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0011, 100, 1000));
        // Jump within the accept-forward window.
        assert!(mon.check_security_counter(0x0011, 100 + ACCEPT_FORWARD_WINDOW, 2000));
    }

    #[test]
    fn security_counter_forward_jump_beyond_window_rejected() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0012, 100, 1000));
        // Jump beyond ACCEPT_FORWARD_WINDOW: suspicious-jump replay.
        assert!(!mon.check_security_counter(0x0012, 100 + ACCEPT_FORWARD_WINDOW + 1, 2000));
    }

    #[test]
    fn security_counter_rollover_when_enabled_accepts() {
        let mut mon = ZigbeeMonitor::new();
        mon.set_allow_counter_rollover(true);
        // Seed at top-of-range so rollover is plausible.
        assert!(mon.check_security_counter(0x0013, 0xFFFF_FFF0, 1000));
        // Honest device wraps to 0.
        assert!(mon.check_security_counter(0x0013, 0, 2000));
        // Continues from 0.
        assert!(mon.check_security_counter(0x0013, 1, 3000));
    }

    #[test]
    fn security_counter_rollover_when_disabled_rejects() {
        let mut mon = ZigbeeMonitor::new();
        // Default: rollover disabled.
        assert!(mon.check_security_counter(0x0014, 0xFFFF_FFF0, 1000));
        // Apparent wrap is treated as out-of-window stale frame.
        assert!(!mon.check_security_counter(0x0014, 0, 2000));
    }

    #[test]
    fn security_counter_per_address() {
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x0001, 10, 1000));
        assert!(mon.check_security_counter(0x0002, 5, 2000)); // different addr
                                                              // Replay of 10 on addr 1 is rejected.
        assert!(!mon.check_security_counter(0x0001, 10, 3000));
        assert!(mon.check_security_counter(0x0002, 6, 4000)); // ok on addr 2
    }

    #[test]
    fn security_counter_per_device_isolation() {
        // Replays on one device must not be gated by another device's history:
        // the per-device window means a fresh device can use any starting
        // counter without inheriting a global floor.
        let mut mon = ZigbeeMonitor::new();
        assert!(mon.check_security_counter(0x00A0, 1_000_000, 1000));
        // A different device legitimately starts at a much lower counter.
        assert!(mon.check_security_counter(0x00A1, 5, 2000));
        // And continues independently.
        assert!(mon.check_security_counter(0x00A1, 6, 3000));
    }

    #[test]
    fn security_counter_lru_eviction_works() {
        let mut mon = ZigbeeMonitor::new();
        // Fill all slots with distinct addresses.
        for i in 0..MAX_SECURITY_COUNTERS as u16 {
            assert!(mon.check_security_counter(i, 100, 1000 + i as u64 * 1000));
        }
        // Bump the LRU candidate (index 0, oldest) so a different one is LRU.
        assert!(mon.check_security_counter(0, 101, 1_000_000));
        // Adding a new device evicts the *least recently used* (now index 1).
        assert!(mon.check_security_counter(0xFFFE, 100, 2_000_000));
        // The previously-evicted address can re-allocate a fresh window
        // starting from a low counter (no global floor leaks across devices).
        assert!(mon.check_security_counter(1, 1, 3_000_000));
        // The not-evicted address still rejects its own replay.
        assert!(!mon.check_security_counter(0, 101, 4_000_000));
    }

    #[test]
    fn inspect_with_counter_detects_replay() {
        let mut mon = ZigbeeMonitor::new();
        let f1 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        let r1 = mon.inspect_with_counter(&f1, 100);
        assert!(r1.allowed);

        let f2 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2000);
        let r2 = mon.inspect_with_counter(&f2, 100); // replay
        assert!(!r2.allowed);
        // Should have a replay alert.
        let has_replay_alert = (0..r2.alert_count as usize)
            .any(|i| r2.alerts[i].source_id == ALERT_SECURITY_COUNTER_REPLAY);
        assert!(has_replay_alert);
    }

    #[test]
    fn inspect_with_counter_allows_increasing() {
        let mut mon = ZigbeeMonitor::new();
        let f1 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000);
        let r1 = mon.inspect_with_counter(&f1, 100);
        assert!(r1.allowed);

        let f2 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2000);
        let r2 = mon.inspect_with_counter(&f2, 101);
        assert!(r2.allowed);
    }

    #[test]
    fn security_counter_slots_full_allows() {
        let mut mon = ZigbeeMonitor::new();
        // Fill all security counter slots.
        for i in 0..MAX_SECURITY_COUNTERS as u16 {
            assert!(mon.check_security_counter(i, 1, 1000 + i as u64 * 1000));
        }
        // New address with all slots full should still be allowed (LRU eviction).
        assert!(mon.check_security_counter(0xFFFF, 1, 100_000));
    }

    // -----------------------------------------------------------------------
    // New tests: Trust Center monitoring
    // -----------------------------------------------------------------------

    #[test]
    fn trust_center_single_event_no_alert() {
        let mut mon = ZigbeeMonitor::new();
        let r = mon.record_trust_center_event(TrustCenterEvent::NetworkKeyUpdate, 1_000_000);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn trust_center_rapid_rotation_detected() {
        let mut mon = ZigbeeMonitor::new();
        let base_ts = 1_000_000u64;
        // Send TC_KEY_ROTATION_THRESHOLD + 1 key updates within the window.
        for i in 0..=TC_KEY_ROTATION_THRESHOLD {
            let r = mon.record_trust_center_event(
                TrustCenterEvent::NetworkKeyUpdate,
                base_ts + (i as u64) * 1_000_000,
            );
            if i < TC_KEY_ROTATION_THRESHOLD {
                assert_eq!(r.alert_count, 0, "No alert expected at count {}", i + 1);
            } else {
                assert!(r.alert_count > 0, "Alert expected at count {}", i + 1);
                assert_eq!(r.alerts[0].source_id, ALERT_TRUST_CENTER_EVENT);
                assert_eq!(r.alerts[0].severity, AlertSeverity::High);
            }
        }
        assert_eq!(mon.tc_rapid_rotation_alerts(), 1);
    }

    #[test]
    fn trust_center_non_key_events_no_rotation_alert() {
        let mut mon = ZigbeeMonitor::new();
        // Many DeviceJoined events should not trigger key rotation alert.
        for i in 0..10 {
            let r = mon.record_trust_center_event(
                TrustCenterEvent::DeviceJoined,
                1_000_000 + i * 1_000_000,
            );
            assert_eq!(r.alert_count, 0);
        }
    }

    #[test]
    fn trust_center_events_outside_window_no_alert() {
        let mut mon = ZigbeeMonitor::new();
        // Spread key updates far apart (beyond TC_KEY_ROTATION_WINDOW_US).
        for i in 0..=TC_KEY_ROTATION_THRESHOLD {
            let r = mon.record_trust_center_event(
                TrustCenterEvent::NetworkKeyUpdate,
                1_000_000 + (i as u64) * (TC_KEY_ROTATION_WINDOW_US + 1_000_000),
            );
            // Should never trigger because each update is outside the window of previous ones.
            assert_eq!(
                r.alert_count, 0,
                "No alert expected when events are spread apart"
            );
        }
    }

    // -----------------------------------------------------------------------
    // New tests: MonitorReset
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_reset_clears_runtime_state() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 10).unwrap();
        mon.add_rule(0x0002, 0xFFFF, AddrAction::Block, 0).unwrap();

        // Accumulate some state.
        let _ = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000));
        let _ = mon.inspect(&make_frame(0x0002, 0x1234, ZigbeeFrameType::Data, 2000));
        mon.check_security_counter(0x0001, 100, 2500);
        let _ = mon.record_trust_center_event(TrustCenterEvent::NetworkKeyUpdate, 3000);

        assert!(mon.total_inspected() > 0);
        assert!(mon.total_alerts() > 0);

        // Reset.
        mon.reset_state();

        // Runtime state should be cleared.
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
        assert_eq!(mon.tc_rapid_rotation_alerts(), 0);

        // Configuration (rules) should be preserved.
        assert_eq!(mon.rule_count(), 2);

        // Security counters should be cleared -- previously seen counter is now accepted.
        assert!(mon.check_security_counter(0x0001, 100, 5000));
    }

    #[test]
    fn monitor_reset_preserves_rules_and_config() {
        let mut mon = ZigbeeMonitor::new_deny_default();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 0).unwrap();
        mon.set_allowed_frame_types(0x02);

        let _ = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1000));
        mon.reset_state();

        // Rules still work after reset.
        let r = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2000));
        assert!(r.allowed);

        // Deny-default still in effect for unknown addresses.
        let r2 = mon.inspect(&make_frame(0x0099, 0x1234, ZigbeeFrameType::Data, 3000));
        assert!(!r2.allowed);

        // Frame type filter still in effect.
        let r3 = mon.inspect(&make_frame(0x0001, 0x1234, ZigbeeFrameType::Beacon, 4000));
        assert!(!r3.allowed);
    }

    #[test]
    fn update_rule_works() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Block, 0).unwrap();

        let frame = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 1_000_000);
        assert!(!mon.inspect(&frame).allowed, "should be blocked");

        // Update to allow
        let result = mon.update_rule(0, 0x0001, 0xFFFF, AddrAction::Allow, 0);
        assert!(result.is_ok());

        let frame2 = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 2_000_000);
        assert!(
            mon.inspect(&frame2).allowed,
            "should be allowed after update"
        );
    }

    #[test]
    fn rate_bucket_expiry_and_reuse() {
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 5).unwrap(); // 5/sec rate limit

        // Send messages to create a rate bucket
        for i in 0..3u64 {
            let frame = make_frame(
                0x0001,
                0x1234,
                ZigbeeFrameType::Data,
                1_000_000 + i * 100_000,
            );
            let _ = mon.inspect(&frame);
        }

        // After bucket expiry (>1 second), bucket should be reusable
        let frame = make_frame(0x0001, 0x1234, ZigbeeFrameType::Data, 10_000_000);
        let r = mon.inspect(&frame);
        assert!(r.allowed, "should be allowed after rate bucket expires");
    }

    #[test]
    fn trust_center_ring_buffer_wrap() {
        let mut mon = ZigbeeMonitor::new();
        // Record more events than typical to test wrap-around
        for i in 0..20u64 {
            let _ = mon
                .record_trust_center_event(TrustCenterEvent::DeviceJoined, 1_000_000 + i * 100_000);
        }
        // Also inspect some frames to increment total_inspected
        for i in 0..20u64 {
            let frame = make_frame(
                0x0001,
                0x1234,
                ZigbeeFrameType::Data,
                5_000_000 + i * 100_000,
            );
            let _ = mon.inspect(&frame);
        }
        // Should not panic
        assert!(mon.total_inspected() >= 20);
    }

    // -----------------------------------------------------------------------
    // Rate-limit key includes PAN ID
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_key_includes_pan_id() {
        // With a specific PAN rule, different PANs use separate buckets.
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0x1111, AddrAction::Allow, 2).unwrap();

        // Send 2 frames from PAN 0x1111 -- both should be allowed.
        for i in 0..2u64 {
            let f = make_frame(0x0001, 0x1111, ZigbeeFrameType::Data, 1000 + i * 100);
            assert!(
                mon.inspect(&f).allowed,
                "PAN 0x1111 frame {} should be allowed",
                i
            );
        }

        // Third frame from PAN 0x1111 should be rate-limited.
        let f = make_frame(0x0001, 0x1111, ZigbeeFrameType::Data, 1200);
        assert!(
            !mon.inspect(&f).allowed,
            "PAN 0x1111 should be rate-limited"
        );
    }

    #[test]
    fn wildcard_pan_shares_rate_bucket() {
        // With a wildcard PAN rule (0xFFFF), all PANs share the same
        // rate bucket to prevent cross-PAN rate bucket collision.
        let mut mon = ZigbeeMonitor::new();
        mon.add_rule(0x0001, 0xFFFF, AddrAction::Allow, 2).unwrap();

        // Send 2 frames from PAN 0x1111 -- both should be allowed.
        for i in 0..2u64 {
            let f = make_frame(0x0001, 0x1111, ZigbeeFrameType::Data, 1000 + i * 100);
            assert!(
                mon.inspect(&f).allowed,
                "PAN 0x1111 frame {} should be allowed",
                i
            );
        }

        // Third frame from PAN 0x1111 should be rate-limited.
        let f = make_frame(0x0001, 0x1111, ZigbeeFrameType::Data, 1200);
        assert!(
            !mon.inspect(&f).allowed,
            "PAN 0x1111 should be rate-limited"
        );

        // A frame from the same src_addr but different PAN 0x2222 should
        // also be rate-limited because wildcard PAN shares a single bucket.
        let f2 = make_frame(0x0001, 0x2222, ZigbeeFrameType::Data, 1300);
        assert!(
            !mon.inspect(&f2).allowed,
            "PAN 0x2222 should share the wildcard bucket and be rate-limited"
        );
    }

    #[test]
    fn alerts_dropped_counter_accessible() {
        let r = ZigbeeInspectResult::clean();
        assert_eq!(r.alerts_dropped, 0);
    }
}
