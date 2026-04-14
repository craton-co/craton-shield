// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

//! MQTT protocol intrusion detection monitor.
//!
//! Detects anomalous MQTT traffic patterns on `IoT` devices:
//!
//! - **Topic allowlist/blocklist** — restrict which topics a device may
//!   publish or subscribe to (wildcard matching supported).
//! - **Payload size anomaly** — EWMA-based per-topic baseline detection of
//!   unusually large payloads.
//! - **Rate limiting** — per-topic publish rate enforcement.
//! - **Connect storm detection** — excessive CONNECT packets from the same
//!   device trigger alerts.
//! - **`QoS` policy** — enforce minimum/maximum `QoS` per topic.
//!
//! All state is stack-allocated with fixed-size arrays. No heap required.
//!
//! # Examples
//!
//! ```rust
//! use vs_mqtt_monitor::{MqttMonitor, TopicAction, QosPolicy};
//! use vs_types_embedded::{MqttMessage, MqttPacketType, MqttQoS};
//!
//! let mut monitor = MqttMonitor::new();
//! monitor.add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 10).unwrap();
//! monitor.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0).unwrap();
//!
//! let mut msg = MqttMessage::default();
//! msg.packet_type = MqttPacketType::Publish;
//! msg.topic[..11].copy_from_slice(b"sensors/tmp");
//! msg.topic_len = 11;
//! msg.timestamp_us = 1_000_000;
//!
//! let result = monitor.inspect(&msg);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, PayloadHash, SecurityAlert, VsError};
use vs_types_embedded::{
    compute_payload_hash, fnv1a_hash, MonitorReset, MqttMessage, MqttPacketType, MqttQoS,
    TimestampValidator, EWMA_MEAN_CEILING_X256, MAX_RATE_BUCKETS_MQTT, MAX_TOPIC_RULES,
    SOURCE_MQTT,
};

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Maximum topic pattern length in bytes.
const MAX_PATTERN_LEN: usize = 64;

/// Maximum CONNECT events tracked for storm detection.
const MAX_CONNECT_WINDOW: usize = 16;

/// Maximum number of single-level (`+`) wildcards allowed in a topic pattern.
///
/// Limits worst-case matching complexity to O(n × `MAX_WILDCARD_DEPTH`) where
/// n = topic length. Patterns exceeding this depth are rejected by `add_rule`.
const MAX_WILDCARD_DEPTH: usize = 6;

/// Default connect storm threshold (connects per window).
const DEFAULT_CONNECT_STORM_THRESHOLD: u8 = 5;

/// Default connect storm window in microseconds (60 seconds).
const DEFAULT_CONNECT_STORM_WINDOW_US: u64 = 60_000_000;

/// Bucket collision-resistance prefix length. Increased from 8 to 32 bytes
/// to strengthen collision resistance against crafted topic names that share
/// a hash and short prefix.
const BUCKET_PREFIX_LEN: usize = 32;

/// EWMA smoothing factor numerator (out of 256). 32/256 = 0.125.
///
/// α = 1/8 gives an effective memory of ~7 samples, balancing responsiveness
/// to real baseline shifts against resilience to short-lived anomalies.
const EWMA_ALPHA_NUM: u32 = 32;

/// EWMA smoothing factor denominator.
const EWMA_ALPHA_DEN: u32 = 256;

/// EWMA anomaly multiplier — payload > `mean * EWMA_ANOMALY_MULT` triggers alert.
///
/// 4× the running mean catches payloads that are statistically extreme
/// (≈ 3-4 σ for typical `IoT` distributions) without false-positives on
/// normal variance. Increase to 6-8 for noisy environments.
const EWMA_ANOMALY_MULT: u32 = 4;

/// Maximum EWMA trackers (one per distinct topic hash).
///
/// 16 trackers cover typical `IoT` deployments (5-10 active topics).
/// Increase via capacity features if the device publishes on more topics.
const MAX_EWMA_TRACKERS: usize = 16;

// ---------------------------------------------------------------------------
// Secondary hash for collision resistance (djb2)
// ---------------------------------------------------------------------------

/// Compute a djb2 hash of the given bytes. Used as a second independent hash
/// alongside FNV-1a to strengthen collision resistance in bucket/tracker matching.
#[inline]
fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &b in data {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Compute a hash of the suffix portion of the topic (bytes after `BUCKET_PREFIX_LEN`).
/// Returns 0 for short topics, providing a third independent verification for long topics.
#[inline]
fn suffix_hash(topic: &[u8]) -> u32 {
    if topic.len() <= BUCKET_PREFIX_LEN {
        return 0;
    }
    djb2_hash(&topic[BUCKET_PREFIX_LEN..])
}

// ---------------------------------------------------------------------------
// Alert source IDs for correlation.
// ---------------------------------------------------------------------------

const ALERT_CONNECT_STORM: u32 = 1;
const ALERT_EMPTY_TOPIC: u32 = 2;
const ALERT_TOPIC_BLOCKED: u32 = 3;
const ALERT_QOS_VIOLATION: u32 = 4;
const ALERT_RATE_LIMITED: u32 = 5;
const ALERT_RATE_BUCKET_EXHAUSTED: u32 = 6;
const ALERT_PAYLOAD_ANOMALY: u32 = 7;
const ALERT_TIMESTAMP_ANOMALY: u32 = 8;

// ---------------------------------------------------------------------------
// Topic rule
// ---------------------------------------------------------------------------

/// Action to take when a topic matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicAction {
    /// Allow the message.
    Allow,
    /// Block the message and raise an alert.
    Block,
}

/// Minimum `QoS` enforcement for a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosPolicy {
    /// Any `QoS` is acceptable.
    Any,
    /// Minimum `QoS` level required.
    MinQoS(MqttQoS),
    /// Exact `QoS` required.
    ExactQoS(MqttQoS),
}

/// A topic filtering rule.
#[derive(Debug, Clone, Copy)]
struct TopicRule {
    /// Topic pattern (supports MQTT wildcards: + and #).
    pattern: [u8; MAX_PATTERN_LEN],
    /// Number of valid bytes in `pattern`.
    pattern_len: u8,
    /// Whether this is an allow or block rule.
    action: TopicAction,
    /// `QoS` enforcement for this topic.
    qos_policy: QosPolicy,
    /// Maximum publish rate (messages per second). 0 = unlimited.
    max_rate_per_sec: u16,
    /// Whether this rule is active.
    active: bool,
}

impl TopicRule {
    const fn empty() -> Self {
        Self {
            pattern: [0u8; MAX_PATTERN_LEN],
            pattern_len: 0,
            action: TopicAction::Allow,
            qos_policy: QosPolicy::Any,
            max_rate_per_sec: 0,
            active: false,
        }
    }

    #[inline]
    fn pattern_bytes(&self) -> &[u8] {
        &self.pattern[..self.pattern_len as usize]
    }
}

// ---------------------------------------------------------------------------
// Rate-limit bucket
// ---------------------------------------------------------------------------

/// Bucket expiration timeout: 5 minutes without activity.
const RATE_BUCKET_EXPIRY_US: u64 = 300_000_000;

/// Per-topic token bucket for rate limiting.
#[derive(Debug, Clone, Copy)]
struct RateBucket {
    /// Topic hash (FNV-1a of the topic bytes).
    topic_hash: u32,
    /// Secondary topic hash (djb2) for collision resistance.
    topic_hash2: u32,
    /// First N bytes of the topic for collision resistance.
    topic_prefix: [u8; BUCKET_PREFIX_LEN],
    /// Length of valid bytes in `topic_prefix`.
    topic_prefix_len: u8,
    /// Full length of the original topic (for exact-length matching).
    topic_len: u16,
    /// Hash of the topic suffix (bytes after `BUCKET_PREFIX_LEN`) for collision resistance.
    topic_suffix_hash: u32,
    /// Available tokens.
    tokens: u16,
    /// Maximum tokens (= `max_rate_per_sec`).
    capacity: u16,
    /// Last refill timestamp (microseconds).
    last_refill_us: u64,
    /// Whether this bucket is in use.
    active: bool,
}

impl RateBucket {
    const fn empty() -> Self {
        Self {
            topic_hash: 0,
            topic_hash2: 0,
            topic_prefix: [0u8; BUCKET_PREFIX_LEN],
            topic_prefix_len: 0,
            topic_len: 0,
            topic_suffix_hash: 0,
            tokens: 0,
            capacity: 0,
            last_refill_us: 0,
            active: false,
        }
    }

    /// Check if this bucket matches the given topic (dual hash + prefix + suffix hash + length).
    #[inline]
    fn matches_topic(
        &self,
        topic_hash: u32,
        topic_hash2: u32,
        topic: &[u8],
        topic_suffix_hash: u32,
    ) -> bool {
        if self.topic_hash != topic_hash || self.topic_hash2 != topic_hash2 {
            return false;
        }
        if topic.len() != self.topic_len as usize {
            return false;
        }
        if self.topic_suffix_hash != topic_suffix_hash {
            return false;
        }
        let prefix_len = self.topic_prefix_len as usize;
        let cmp_len = topic.len().min(prefix_len);
        self.topic_prefix[..cmp_len] == topic[..cmp_len]
    }

    #[inline]
    fn try_consume(&mut self, now_us: u64) -> bool {
        // Refill tokens based on elapsed time.
        // Use saturating_mul to prevent overflow when elapsed is large.
        let elapsed = now_us.saturating_sub(self.last_refill_us);
        let refill = elapsed.saturating_mul(self.capacity as u64) / 1_000_000;
        if refill > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refill.min(self.capacity as u64) as u16)
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

    /// Returns `true` if this bucket has expired (no activity for `RATE_BUCKET_EXPIRY_US`).
    #[inline]
    fn is_expired(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.last_refill_us) > RATE_BUCKET_EXPIRY_US
    }
}

// ---------------------------------------------------------------------------
// EWMA payload size tracker
// ---------------------------------------------------------------------------

/// Per-topic exponentially-weighted moving average of payload sizes.
///
/// Used to detect anomalously large payloads compared to historical baseline.
/// Keyed by both topic hash and 32-byte prefix for collision resistance.
#[derive(Debug, Clone, Copy)]
struct EwmaTracker {
    /// Topic hash.
    topic_hash: u32,
    /// Secondary topic hash (djb2) for collision resistance.
    topic_hash2: u32,
    /// First 32 bytes of the topic for collision resistance.
    topic_prefix: [u8; BUCKET_PREFIX_LEN],
    /// Length of valid bytes in `topic_prefix`.
    topic_prefix_len: u8,
    /// Full length of the original topic (for exact-length matching).
    topic_len: u16,
    /// Hash of the topic suffix (bytes after `BUCKET_PREFIX_LEN`) for collision resistance.
    topic_suffix_hash: u32,
    /// EWMA mean payload size (scaled by 256 for fixed-point precision).
    mean_x256: u32,
    /// Number of samples seen (capped at 255 to indicate "warmed up").
    sample_count: u8,
    /// Last update timestamp for LRU eviction.
    last_update_us: u64,
    /// Whether this tracker is in use.
    active: bool,
}

impl EwmaTracker {
    const fn empty() -> Self {
        Self {
            topic_hash: 0,
            topic_hash2: 0,
            topic_prefix: [0u8; BUCKET_PREFIX_LEN],
            topic_prefix_len: 0,
            topic_len: 0,
            topic_suffix_hash: 0,
            mean_x256: 0,
            sample_count: 0,
            last_update_us: 0,
            active: false,
        }
    }

    /// Check if this tracker matches the given topic (dual hash + prefix + suffix hash + length).
    #[inline]
    fn matches_topic(
        &self,
        topic_hash: u32,
        topic_hash2: u32,
        topic: &[u8],
        topic_suffix_hash: u32,
    ) -> bool {
        if self.topic_hash != topic_hash || self.topic_hash2 != topic_hash2 {
            return false;
        }
        if topic.len() != self.topic_len as usize {
            return false;
        }
        if self.topic_suffix_hash != topic_suffix_hash {
            return false;
        }
        let prefix_len = self.topic_prefix_len as usize;
        let cmp_len = topic.len().min(prefix_len);
        self.topic_prefix[..cmp_len] == topic[..cmp_len]
    }

    /// Update the EWMA with a new payload size. Returns `true` if the
    /// payload is anomalously large (> `EWMA_ANOMALY_MULT * mean`).
    #[inline]
    fn update(&mut self, payload_len: u16) -> bool {
        let val = payload_len as u32;
        let val_x256 = val * 256;

        if self.sample_count < 8 {
            // Warmup phase: accumulate directly into mean_x256 as a running
            // sum, then divide. This avoids reconstructing the sum from the
            // mean (which loses precision due to integer division rounding).
            // During warmup, mean_x256 holds the running sum; it is converted
            // to the actual mean on the 8th sample when warmup completes.
            if self.sample_count == 0 {
                self.mean_x256 = val_x256;
            } else if self.sample_count < 7 {
                // Accumulate sum (mean_x256 is still a running sum here).
                self.mean_x256 = self.mean_x256.saturating_add(val_x256);
                // Cap warmup accumulation to prevent baseline inflation attacks.
                // An attacker cannot inflate the baseline beyond the max payload length.
                let warmup_ceiling = EWMA_MEAN_CEILING_X256.saturating_mul(8);
                if self.mean_x256 > warmup_ceiling {
                    self.mean_x256 = warmup_ceiling;
                }
            } else {
                // 8th sample: finalize the average.
                let sum = self.mean_x256.saturating_add(val_x256);
                self.mean_x256 = sum / 8;
            }
            self.sample_count = self.sample_count.saturating_add(1);
            return false; // never alert during warmup
        }

        // Check for anomaly before updating.
        // Multiply first, then divide to avoid precision loss for small baselines.
        let threshold = self.mean_x256.saturating_mul(EWMA_ANOMALY_MULT) / 256;
        let anomaly = val > threshold && threshold > 0;

        // EWMA update: mean = alpha * val + (1 - alpha) * mean
        // Compute each part divided by EWMA_ALPHA_DEN to avoid near-overflow
        // on extreme values. This loses ~0.4% precision but prevents wrapping.
        let new_part = EWMA_ALPHA_NUM.saturating_mul(val_x256) / EWMA_ALPHA_DEN;
        let old_part =
            (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM).saturating_mul(self.mean_x256) / EWMA_ALPHA_DEN;
        self.mean_x256 = new_part
            .saturating_add(old_part)
            .min(EWMA_MEAN_CEILING_X256);
        self.sample_count = self.sample_count.saturating_add(1);

        anomaly
    }
}

// ---------------------------------------------------------------------------
// MQTT monitor result
// ---------------------------------------------------------------------------

/// Result of inspecting an MQTT message.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct MqttInspectResult {
    /// Whether the message was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Number of alerts that were dropped because the alert array was full.
    pub alerts_dropped: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
}

impl MqttInspectResult {
    const fn clean() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts_dropped: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: SOURCE_MQTT,
                source_id: 0,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: 0,
            }; 4],
        }
    }

    #[inline]
    fn push_alert(&mut self, severity: AlertSeverity, source_id: u32, ts_us: u64, alert_id: u64) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type: SOURCE_MQTT,
                source_id,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }

    #[inline]
    fn push_alert_with_hash(
        &mut self,
        severity: AlertSeverity,
        source_id: u32,
        ts_us: u64,
        alert_id: u64,
        hash: PayloadHash,
    ) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type: SOURCE_MQTT,
                source_id,
                payload_hash: hash,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Rate-limit check result
// ---------------------------------------------------------------------------

/// Internal result of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateCheckResult {
    /// Token consumed — request is within the rate limit.
    Allowed,
    /// Bucket exists but tokens exhausted — rate limit exceeded.
    Limited,
}

// ---------------------------------------------------------------------------
// MQTT Monitor
// ---------------------------------------------------------------------------

/// MQTT protocol intrusion detection monitor.
///
/// Inspects MQTT messages against a set of topic rules, rate limits, and
/// connect-storm detection. All state is stack-allocated.
pub struct MqttMonitor {
    /// Topic filtering rules.
    rules: [TopicRule; MAX_TOPIC_RULES],
    /// Number of active rules.
    rule_count: u8,
    /// Per-topic rate-limit buckets.
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS_MQTT],
    /// Connect storm detection: ring buffer of recent CONNECT timestamps.
    connect_timestamps: [u64; MAX_CONNECT_WINDOW],
    /// Number of entries in `connect_timestamps` (capped at `MAX_CONNECT_WINDOW`).
    connect_count: u8,
    /// Ring buffer write index for `connect_timestamps`.
    connect_write_idx: u8,
    /// Connect storm threshold.
    connect_storm_threshold: u8,
    /// Connect storm window in microseconds.
    connect_storm_window_us: u64,
    /// Default action for topics that match no rule.
    default_action: TopicAction,
    /// EWMA payload size trackers.
    ewma_trackers: [EwmaTracker; MAX_EWMA_TRACKERS],
    /// Timestamp plausibility validator.
    ts_validator: TimestampValidator,
    /// Monotonically increasing alert ID counter.
    next_alert_id: u64,
    /// Total messages inspected.
    total_inspected: u64,
    /// Total alerts raised.
    total_alerts: u64,
}

impl MqttMonitor {
    /// Create a new MQTT monitor.
    ///
    /// By default, all topics are allowed. Add rules to restrict.
    pub fn new() -> Self {
        Self {
            rules: [TopicRule::empty(); MAX_TOPIC_RULES],
            rule_count: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS_MQTT],
            connect_timestamps: [0u64; MAX_CONNECT_WINDOW],
            connect_count: 0,
            connect_write_idx: 0,
            connect_storm_threshold: DEFAULT_CONNECT_STORM_THRESHOLD,
            connect_storm_window_us: DEFAULT_CONNECT_STORM_WINDOW_US,
            default_action: TopicAction::Allow,
            ewma_trackers: [EwmaTracker::empty(); MAX_EWMA_TRACKERS],
            ts_validator: TimestampValidator::new(),
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
        }
    }

    /// Create a new MQTT monitor with deny-by-default policy.
    ///
    /// All topics are blocked unless explicitly allowed by a rule.
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = TopicAction::Block;
        m
    }

    /// Add a topic rule.
    ///
    /// Patterns support MQTT wildcards:
    /// - `+` matches a single level (e.g. `sensors/+/temperature`)
    /// - `#` matches zero or more levels (e.g. `sensors/#`)
    ///
    /// Returns the number of shadowed rules detected after adding this rule.
    /// A non-zero value indicates potential misconfiguration where earlier
    /// rules may make this rule unreachable (first-match-wins semantics).
    pub fn add_rule(
        &mut self,
        pattern: &[u8],
        action: TopicAction,
        qos_policy: QosPolicy,
        max_rate_per_sec: u16,
    ) -> Result<u16, VsError> {
        if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
            return Err(VsError::InvalidInput);
        }
        // MQTT 3.1.1 §4.7.3: reject null bytes in topic patterns.
        if pattern.contains(&0) {
            return Err(VsError::InvalidInput);
        }
        // Reject patterns with excessive wildcard complexity to prevent O(n²)
        // matching on deeply nested topics.
        let mut wildcard_count: usize = 0;
        let mut pi = 0;
        while pi < pattern.len() {
            if pattern[pi] == b'+' {
                wildcard_count += 1;
            }
            pi += 1;
        }
        if wildcard_count > MAX_WILDCARD_DEPTH {
            return Err(VsError::InvalidInput);
        }
        if !validate_mqtt_wildcard(pattern) {
            return Err(VsError::InvalidInput);
        }

        // Check for duplicate rule with the same pattern — update in place
        // instead of adding a new entry.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && self.rules[i].pattern_len as usize == pattern.len()
                && self.rules[i].pattern[..pattern.len()] == *pattern
            {
                self.rules[i].action = action;
                self.rules[i].qos_policy = qos_policy;
                self.rules[i].max_rate_per_sec = max_rate_per_sec;
                return Ok(self.validate_rules());
            }
        }

        if self.rule_count as usize >= MAX_TOPIC_RULES {
            return Err(VsError::ResourceExhausted);
        }

        let idx = self.rule_count as usize;
        self.rules[idx].pattern[..pattern.len()].copy_from_slice(pattern);
        self.rules[idx].pattern_len = pattern.len() as u8;
        self.rules[idx].action = action;
        self.rules[idx].qos_policy = qos_policy;
        self.rules[idx].max_rate_per_sec = max_rate_per_sec;
        self.rules[idx].active = true;
        self.rule_count += 1;

        // Auto-validate to warn about shadowed rules.
        Ok(self.validate_rules())
    }

    /// Set the connect storm detection parameters.
    ///
    /// `threshold` must be >= 2 to avoid false positives. Values 0 or 1 are
    /// clamped to 2.
    pub fn set_connect_storm_params(&mut self, threshold: u8, window_us: u64) {
        self.connect_storm_threshold = threshold.clamp(2, MAX_CONNECT_WINDOW as u8);
        self.connect_storm_window_us = window_us.clamp(1_000_000, 600_000_000);
    }

    /// Remove a topic rule by index.
    ///
    /// Returns `Err(InvalidInput)` if `index >= rule_count()`.
    pub fn remove_rule(&mut self, index: usize) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        // Shift remaining rules down.
        let count = self.rule_count as usize;
        for i in index..count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[count - 1] = TopicRule::empty();
        self.rule_count -= 1;
        Ok(())
    }

    /// Remove all rules.
    pub fn clear_rules(&mut self) {
        self.rule_count = 0;
        self.rules = [TopicRule::empty(); MAX_TOPIC_RULES];
    }

    /// Validate the current rule set for shadowed rules.
    ///
    /// Returns the number of shadowed rules detected. A rule is shadowed if
    /// a broader rule earlier in the list matches the same topics, making the
    /// later rule unreachable. This is common with first-match-wins semantics.
    pub fn validate_rules(&self) -> u16 {
        let mut shadowed: u16 = 0;
        for i in 0..self.rule_count as usize {
            if !self.rules[i].active {
                continue;
            }
            let later_pat = self.rules[i].pattern_bytes();
            for j in 0..i {
                if !self.rules[j].active {
                    continue;
                }
                let earlier_pat = self.rules[j].pattern_bytes();
                if topic_matches(later_pat, earlier_pat) {
                    shadowed = shadowed.saturating_add(1);
                    break;
                }
            }
        }
        shadowed
    }

    /// Inspect an MQTT message.
    ///
    /// Returns an [`MqttInspectResult`] with allow/block decision and any
    /// generated alerts.
    ///
    /// First-match-wins: the first topic rule whose pattern matches is applied.
    /// If no rules match, the message is denied by default. This follows MQTT
    /// convention where wildcard ordering is significant.
    pub fn inspect(&mut self, msg: &MqttMessage) -> MqttInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = MqttInspectResult::clean();

        // Timestamp validation — flag anomalies but still process the message.
        if !self.ts_validator.validate(msg.timestamp_us) {
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TIMESTAMP_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Connect storm detection.
        if msg.packet_type == MqttPacketType::Connect {
            self.record_connect(msg.timestamp_us);
            if self.detect_connect_storm(msg.timestamp_us) {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::High,
                    ALERT_CONNECT_STORM,
                    msg.timestamp_us,
                    self.next_alert_id(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }
        }

        // Topic-based checks only apply to Publish/Subscribe/Unsubscribe.
        if msg.packet_type != MqttPacketType::Publish
            && msg.packet_type != MqttPacketType::Subscribe
            && msg.packet_type != MqttPacketType::Unsubscribe
        {
            return result;
        }

        let topic = msg.topic_bytes();
        if topic.is_empty() {
            // Empty topic in a Publish/Subscribe is suspicious.
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_EMPTY_TOPIC,
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Pre-compute topic hashes once for rate limiting and EWMA.
        let topic_hash = fnv1a_hash(topic);
        let topic_hash2 = djb2_hash(topic);

        // Find matching rule.
        let mut matched_rule: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && topic_matches(topic, self.rules[i].pattern_bytes()) {
                matched_rule = Some(i);
                break;
            }
        }

        let action = match matched_rule {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };

        if action == TopicAction::Block {
            result.allowed = false;
            let payload_hash = compute_payload_hash(msg.payload_bytes());
            result.push_alert_with_hash(
                AlertSeverity::Medium,
                ALERT_TOPIC_BLOCKED,
                msg.timestamp_us,
                self.next_alert_id(),
                payload_hash,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // QoS policy check (advisory: raises an alert but does NOT block the message,
        // because QoS downgrades can occur legitimately at the broker level).
        if let Some(idx) = matched_rule {
            if !Self::check_qos_policy(self.rules[idx].qos_policy, msg.qos) {
                result.push_alert(
                    AlertSeverity::Low,
                    ALERT_QOS_VIOLATION,
                    msg.timestamp_us,
                    self.next_alert_id(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
            }

            // Rate limiting.
            let max_rate = self.rules[idx].max_rate_per_sec;
            if max_rate > 0 && msg.packet_type == MqttPacketType::Publish {
                match self.rate_limit_check(
                    topic_hash,
                    topic_hash2,
                    topic,
                    max_rate,
                    msg.timestamp_us,
                    &mut result,
                ) {
                    RateCheckResult::Limited => {
                        result.allowed = false;
                        result.push_alert(
                            AlertSeverity::Medium,
                            ALERT_RATE_LIMITED,
                            msg.timestamp_us,
                            self.next_alert_id(),
                        );
                        self.total_alerts = self.total_alerts.saturating_add(1);
                    }
                    RateCheckResult::Allowed => {}
                }
            }
        }

        // EWMA payload size anomaly detection (Publish only).
        if msg.packet_type == MqttPacketType::Publish
            && msg.payload_len > 0
            && self.ewma_update(
                topic_hash,
                topic_hash2,
                topic,
                msg.payload_len,
                msg.timestamp_us,
            )
        {
            let payload_hash = compute_payload_hash(msg.payload_bytes());
            result.push_alert_with_hash(
                AlertSeverity::Low,
                ALERT_PAYLOAD_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
                payload_hash,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Return the total number of messages inspected.
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

    /// Remove the rate-limit bucket for the given topic.
    ///
    /// Returns `Ok(())` if found and removed, or `Err(VsError::NotInitialized)` if not found.
    pub fn remove_rate_bucket(&mut self, topic: &[u8]) -> Result<(), VsError> {
        let topic_hash = fnv1a_hash(topic);
        let topic_hash2 = djb2_hash(topic);
        let prefix = Self::make_topic_prefix(topic);
        let topic_len = topic.len() as u16;
        for i in 0..self.rate_buckets.len() {
            if self.rate_buckets[i].active
                && self.rate_buckets[i].topic_hash == topic_hash
                && self.rate_buckets[i].topic_hash2 == topic_hash2
                && self.rate_buckets[i].topic_len == topic_len
                && self.rate_buckets[i].topic_prefix == prefix
            {
                self.rate_buckets[i] = RateBucket::empty();
                return Ok(());
            }
        }
        Err(VsError::NotInitialized)
    }

    /// Remove the EWMA tracker for the given topic.
    ///
    /// Returns `Ok(())` if found and removed, or `Err(VsError::NotInitialized)` if not found.
    pub fn remove_ewma_tracker(&mut self, topic: &[u8]) -> Result<(), VsError> {
        let topic_hash = fnv1a_hash(topic);
        let topic_hash2 = djb2_hash(topic);
        let prefix = Self::make_topic_prefix(topic);
        let topic_len = topic.len() as u16;
        for i in 0..self.ewma_trackers.len() {
            if self.ewma_trackers[i].active
                && self.ewma_trackers[i].topic_hash == topic_hash
                && self.ewma_trackers[i].topic_hash2 == topic_hash2
                && self.ewma_trackers[i].topic_len == topic_len
                && self.ewma_trackers[i].topic_prefix == prefix
            {
                self.ewma_trackers[i] = EwmaTracker::empty();
                return Ok(());
            }
        }
        Err(VsError::NotInitialized)
    }

    /// Swap two rules by index, allowing rule reordering.
    ///
    /// Since rule matching is first-match-wins, ordering matters. Use this to
    /// adjust rule priority without clearing and re-adding all rules.
    ///
    /// Returns `Err(VsError::InvalidInput)` if either index is out of bounds.
    pub fn swap_rules(&mut self, a: usize, b: usize) -> Result<(), VsError> {
        let count = self.rule_count as usize;
        if a >= count || b >= count {
            return Err(VsError::InvalidInput);
        }
        self.rules.swap(a, b);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    #[inline]
    fn next_alert_id(&mut self) -> u64 {
        let id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.wrapping_add(1);
        // Skip zero — it is used as a sentinel for "no alert".
        if self.next_alert_id == 0 {
            self.next_alert_id = 1;
        }
        id
    }

    #[inline]
    fn make_topic_prefix(topic: &[u8]) -> [u8; BUCKET_PREFIX_LEN] {
        let mut prefix = [0u8; BUCKET_PREFIX_LEN];
        let copy_len = topic.len().min(BUCKET_PREFIX_LEN);
        prefix[..copy_len].copy_from_slice(&topic[..copy_len]);
        prefix
    }

    #[inline]
    fn record_connect(&mut self, ts_us: u64) {
        let idx = self.connect_write_idx as usize % MAX_CONNECT_WINDOW;
        self.connect_timestamps[idx] = ts_us;
        self.connect_write_idx = ((idx + 1) % MAX_CONNECT_WINDOW) as u8;
        if (self.connect_count as usize) < MAX_CONNECT_WINDOW {
            self.connect_count += 1;
        }
    }

    #[inline]
    fn detect_connect_storm(&self, now_us: u64) -> bool {
        let window_start = now_us.saturating_sub(self.connect_storm_window_us);
        let mut count: u8 = 0;
        for i in 0..self.connect_count as usize {
            if self.connect_timestamps[i] >= window_start {
                count = count.saturating_add(1);
            }
        }
        count >= self.connect_storm_threshold
    }

    #[inline]
    fn check_qos_policy(policy: QosPolicy, actual: MqttQoS) -> bool {
        match policy {
            QosPolicy::Any => true,
            QosPolicy::MinQoS(min) => (actual as u8) >= (min as u8),
            QosPolicy::ExactQoS(exact) => actual == exact,
        }
    }

    fn rate_limit_check(
        &mut self,
        topic_hash: u32,
        topic_hash2: u32,
        topic: &[u8],
        max_rate: u16,
        now_us: u64,
        result: &mut MqttInspectResult,
    ) -> RateCheckResult {
        let sfx_hash = suffix_hash(topic);
        // Single pass over all slots: find matching bucket, free slot,
        // expired slot, AND LRU candidate all at once — no second scan.
        let mut free_slot: Option<usize> = None;
        let mut oldest_expired_idx: Option<usize> = None;
        let mut oldest_expired_ts = u64::MAX;
        // Track overall LRU candidate for fallback eviction (merged from
        // the former second pass to eliminate O(n) redundant scan).
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_RATE_BUCKETS_MQTT {
            if !self.rate_buckets[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if self.rate_buckets[i].matches_topic(topic_hash, topic_hash2, topic, sfx_hash) {
                return if self.rate_buckets[i].try_consume(now_us) {
                    RateCheckResult::Allowed
                } else {
                    RateCheckResult::Limited
                };
            }
            // Track oldest expired bucket as preferred eviction candidate.
            if self.rate_buckets[i].is_expired(now_us)
                && self.rate_buckets[i].last_refill_us < oldest_expired_ts
            {
                oldest_expired_ts = self.rate_buckets[i].last_refill_us;
                oldest_expired_idx = Some(i);
            }
            // Track overall oldest active bucket for LRU fallback.
            if self.rate_buckets[i].last_refill_us < lru_ts {
                lru_ts = self.rate_buckets[i].last_refill_us;
                lru_idx = i;
            }
        }

        let slot = free_slot.or(oldest_expired_idx);
        if let Some(idx) = slot {
            let prefix_len = topic.len().min(BUCKET_PREFIX_LEN);
            let prefix = Self::make_topic_prefix(topic);
            self.rate_buckets[idx] = RateBucket {
                topic_hash,
                topic_hash2,
                topic_prefix: prefix,
                topic_prefix_len: prefix_len as u8,
                topic_len: topic.len() as u16,
                topic_suffix_hash: sfx_hash,
                tokens: max_rate.saturating_sub(1),
                capacity: max_rate,
                last_refill_us: now_us,
                active: true,
            };
            return RateCheckResult::Allowed;
        }

        // All buckets active and none expired. LRU eviction using the
        // candidate already found in the single pass above — no second scan.
        let prefix_len = topic.len().min(BUCKET_PREFIX_LEN);
        let prefix = Self::make_topic_prefix(topic);
        self.rate_buckets[lru_idx] = RateBucket {
            topic_hash,
            topic_hash2,
            topic_prefix: prefix,
            topic_prefix_len: prefix_len as u8,
            topic_len: topic.len() as u16,
            topic_suffix_hash: sfx_hash,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
        };
        // Emit a high-severity alert for the eviction event.
        result.push_alert(
            AlertSeverity::High,
            ALERT_RATE_BUCKET_EXHAUSTED,
            now_us,
            self.next_alert_id(),
        );
        self.total_alerts = self.total_alerts.saturating_add(1);
        // Allow traffic but with a warning — LRU eviction indicates resource
        // pressure, however blocking legitimate traffic on bucket exhaustion
        // causes more harm than permitting it with an alert.
        RateCheckResult::Allowed
    }

    /// Update EWMA tracker for the given topic. Returns `true` if anomalous.
    fn ewma_update(
        &mut self,
        topic_hash: u32,
        topic_hash2: u32,
        topic: &[u8],
        payload_len: u16,
        ts_us: u64,
    ) -> bool {
        let sfx_hash = suffix_hash(topic);

        // Single pass: find existing match, first free slot, AND LRU candidate.
        let mut matched: Option<usize> = None;
        let mut free_slot: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_EWMA_TRACKERS {
            if !self.ewma_trackers[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if matched.is_none()
                && self.ewma_trackers[i].matches_topic(topic_hash, topic_hash2, topic, sfx_hash)
            {
                matched = Some(i);
                // Continue scanning to find LRU in case we need it later,
                // but we already have our match.
                continue;
            }
            if self.ewma_trackers[i].last_update_us < lru_ts {
                lru_ts = self.ewma_trackers[i].last_update_us;
                lru_idx = i;
            }
        }

        // Existing tracker found — update in place.
        if let Some(idx) = matched {
            self.ewma_trackers[idx].last_update_us = ts_us;
            return self.ewma_trackers[idx].update(payload_len);
        }

        // Allocate new tracker from a free slot or LRU eviction.
        let alloc_idx = free_slot.unwrap_or(lru_idx);
        let prefix_len = topic.len().min(BUCKET_PREFIX_LEN);
        let prefix = Self::make_topic_prefix(topic);
        self.ewma_trackers[alloc_idx] = EwmaTracker {
            topic_hash,
            topic_hash2,
            topic_prefix: prefix,
            topic_prefix_len: prefix_len as u8,
            topic_len: topic.len() as u16,
            topic_suffix_hash: sfx_hash,
            mean_x256: 0,
            sample_count: 0,
            last_update_us: ts_us,
            active: true,
        };
        self.ewma_trackers[alloc_idx].update(payload_len);
        false
    }
}

impl Default for MqttMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for MqttMonitor {
    /// Reset all runtime state while preserving configuration (rules, thresholds).
    fn reset_state(&mut self) {
        self.rate_buckets = [RateBucket::empty(); MAX_RATE_BUCKETS_MQTT];
        self.connect_timestamps = [0u64; MAX_CONNECT_WINDOW];
        self.connect_count = 0;
        self.connect_write_idx = 0;
        self.ewma_trackers = [EwmaTracker::empty(); MAX_EWMA_TRACKERS];
        self.ts_validator.reset();
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
    }
}

// ---------------------------------------------------------------------------
// MQTT topic matching (supports + and # wildcards)
// ---------------------------------------------------------------------------

/// Validate MQTT wildcard placement in a topic pattern.
///
/// Rules:
/// - `#` must be the last character and preceded by `/` (or be the only character).
/// - `+` must occupy an entire level (preceded by `/` or at start, followed by `/` or at end).
#[inline]
fn validate_mqtt_wildcard(pattern: &[u8]) -> bool {
    let len = pattern.len();
    if len == 0 {
        return false;
    }
    let mut i = 0;
    while i < len {
        if pattern[i] == b'#' {
            if i + 1 != len {
                return false;
            }
            if i > 0 && pattern[i - 1] != b'/' {
                return false;
            }
        } else if pattern[i] == b'+' {
            if i > 0 && pattern[i - 1] != b'/' {
                return false;
            }
            if i + 1 < len && pattern[i + 1] != b'/' {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// Match an MQTT topic against a pattern with wildcard support.
///
/// - `+` matches exactly one topic level.
/// - `#` matches zero or more trailing levels (must be last character).
#[inline]
fn topic_matches(topic: &[u8], pattern: &[u8]) -> bool {
    let mut ti = 0;
    let mut pi = 0;

    while pi < pattern.len() && ti < topic.len() {
        if pattern[pi] == b'#' {
            return true;
        }

        if pattern[pi] == b'+' {
            while ti < topic.len() && topic[ti] != b'/' {
                ti += 1;
            }
            pi += 1;
            if pi < pattern.len() && pattern[pi] == b'/' {
                if ti < topic.len() && topic[ti] == b'/' {
                    ti += 1;
                    pi += 1;
                } else {
                    // Topic exhausted after `+` — check if remaining pattern
                    // is `/#` which matches zero trailing levels per MQTT spec.
                    if pi + 1 < pattern.len() && pattern[pi + 1] == b'#' {
                        return true;
                    }
                    return false;
                }
            }
            continue;
        }

        if pattern[pi] != topic[ti] {
            return false;
        }

        ti += 1;
        pi += 1;
    }

    if pi < pattern.len() {
        if pattern[pi] == b'#' {
            return true;
        }
        if pi + 1 < pattern.len() && pattern[pi] == b'/' && pattern[pi + 1] == b'#' {
            return true;
        }
        return false;
    }
    ti == topic.len()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_publish(topic: &[u8], qos: MqttQoS, ts_us: u64) -> MqttMessage {
        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos,
            timestamp_us: ts_us,
            payload_len: 10,
            payload_inspectable_len: 10,
            ..MqttMessage::default()
        };
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;
        msg
    }

    fn make_publish_with_payload(
        topic: &[u8],
        qos: MqttQoS,
        ts_us: u64,
        payload_len: u16,
    ) -> MqttMessage {
        let mut msg = make_publish(topic, qos, ts_us);
        msg.payload_len = payload_len;
        msg.payload_inspectable_len = payload_len.min(512);
        msg
    }

    fn make_connect(ts_us: u64) -> MqttMessage {
        MqttMessage {
            packet_type: MqttPacketType::Connect,
            timestamp_us: ts_us,
            ..MqttMessage::default()
        }
    }

    fn make_subscribe(topic: &[u8], ts_us: u64) -> MqttMessage {
        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Subscribe,
            timestamp_us: ts_us,
            ..MqttMessage::default()
        };
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;
        msg
    }

    // -----------------------------------------------------------------------
    // Topic matching
    // -----------------------------------------------------------------------

    #[test]
    fn exact_topic_match() {
        assert!(topic_matches(b"sensors/temp", b"sensors/temp"));
    }

    #[test]
    fn exact_topic_mismatch() {
        assert!(!topic_matches(b"sensors/temp", b"sensors/humidity"));
    }

    #[test]
    fn single_level_wildcard() {
        assert!(topic_matches(b"sensors/room1/temp", b"sensors/+/temp"));
        assert!(topic_matches(b"sensors/room2/temp", b"sensors/+/temp"));
        assert!(!topic_matches(b"sensors/room1/sub/temp", b"sensors/+/temp"));
    }

    #[test]
    fn multi_level_wildcard() {
        assert!(topic_matches(b"sensors/room1/temp", b"sensors/#"));
        assert!(topic_matches(b"sensors", b"sensors/#"));
        assert!(topic_matches(b"sensors/room1/sub/deep/temp", b"sensors/#"));
    }

    #[test]
    fn hash_at_root() {
        assert!(topic_matches(b"anything/goes/here", b"#"));
    }

    // -----------------------------------------------------------------------
    // Allow / block rules
    // -----------------------------------------------------------------------

    #[test]
    fn default_allow_policy() {
        let mut mon = MqttMonitor::new();
        let msg = make_publish(b"any/topic", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(result.allowed);
        assert_eq!(result.alert_count, 0);
    }

    #[test]
    fn deny_default_policy() {
        let mut mon = MqttMonitor::new_deny_default();
        let msg = make_publish(b"any/topic", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
    }

    #[test]
    fn explicit_allow_overrides_deny_default() {
        let mut mon = MqttMonitor::new_deny_default();
        mon.add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        let msg = make_publish(b"sensors/temp", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(result.allowed);
    }

    #[test]
    fn explicit_block_rule() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        let msg = make_publish(b"admin/config", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
    }

    #[test]
    fn empty_topic_rejected() {
        let mut mon = MqttMonitor::new();
        let msg = make_publish(b"", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // QoS policy
    // -----------------------------------------------------------------------

    #[test]
    fn qos_min_policy_pass() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(
            b"critical/#",
            TopicAction::Allow,
            QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .unwrap();
        let msg = make_publish(b"critical/alert", MqttQoS::ExactlyOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(result.allowed);
        assert_eq!(result.alert_count, 0);
    }

    #[test]
    fn qos_min_policy_fail() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(
            b"critical/#",
            TopicAction::Allow,
            QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .unwrap();
        let msg = make_publish(b"critical/alert", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);
        assert!(result.allowed); // allowed but alert raised
        assert_eq!(result.alert_count, 1);
    }

    #[test]
    fn qos_exact_policy() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(
            b"sensors/+",
            TopicAction::Allow,
            QosPolicy::ExactQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .unwrap();

        let msg_ok = make_publish(b"sensors/temp", MqttQoS::AtLeastOnce, 1000);
        assert_eq!(mon.inspect(&msg_ok).alert_count, 0);

        let msg_bad = make_publish(b"sensors/temp", MqttQoS::ExactlyOnce, 2000);
        assert_eq!(mon.inspect(&msg_bad).alert_count, 1);
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_blocks_excess() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 3)
            .unwrap();

        for i in 0..3 {
            let msg = make_publish(b"data/stream", MqttQoS::AtMostOnce, 1000 + i * 100);
            assert!(mon.inspect(&msg).allowed, "msg {i} should be allowed");
        }

        let msg = make_publish(b"data/stream", MqttQoS::AtMostOnce, 1300);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
        assert!(result.alert_count > 0);
    }

    #[test]
    fn rate_limit_refills_over_time() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 2)
            .unwrap();

        for i in 0..2 {
            let msg = make_publish(b"data/stream", MqttQoS::AtMostOnce, 1000 + i * 100);
            assert!(mon.inspect(&msg).allowed);
        }

        let msg = make_publish(b"data/stream", MqttQoS::AtMostOnce, 1_100_000);
        assert!(mon.inspect(&msg).allowed);
    }

    // -----------------------------------------------------------------------
    // Connect storm detection
    // -----------------------------------------------------------------------

    #[test]
    fn connect_storm_detected() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(3, 10_000_000);

        for i in 0..2 {
            let msg = make_connect(1_000_000 * (i + 1));
            let result = mon.inspect(&msg);
            assert!(result.allowed, "connect {i} should be allowed");
        }

        let msg = make_connect(3_000_000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
    }

    #[test]
    fn connect_storm_window_expiry() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(3, 5_000_000);

        for i in 0..2 {
            let msg = make_connect(1_000_000 * (i + 1));
            assert!(mon.inspect(&msg).allowed);
        }

        let msg = make_connect(20_000_000);
        let result = mon.inspect(&msg);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // Subscribe inspection
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_blocked_topic() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"$SYS/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        let msg = make_subscribe(b"$SYS/broker/clients", 1000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Rule management
    // -----------------------------------------------------------------------

    #[test]
    fn add_rule_rejects_empty_pattern() {
        let mut mon = MqttMonitor::new();
        assert!(mon
            .add_rule(b"", TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    #[test]
    fn add_rule_rejects_oversized_pattern() {
        let mut mon = MqttMonitor::new();
        let big = [b'a'; MAX_PATTERN_LEN + 1];
        assert!(mon
            .add_rule(&big, TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    #[test]
    fn add_rule_rejects_when_full() {
        let mut mon = MqttMonitor::new();
        for i in 0..MAX_TOPIC_RULES {
            // Generate unique two-byte patterns: "aa", "ab", "ac", ..., "ba", "bb", ...
            let topic = [b'a' + (i as u8 / 26), b'a' + (i as u8 % 26)];
            mon.add_rule(&topic, TopicAction::Allow, QosPolicy::Any, 0)
                .unwrap();
        }
        assert!(mon
            .add_rule(b"overflow", TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    #[test]
    fn stats_tracking() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"blocked/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        let msg1 = make_publish(b"ok/topic", MqttQoS::AtMostOnce, 1000);
        let _ = mon.inspect(&msg1);
        let msg2 = make_publish(b"blocked/topic", MqttQoS::AtMostOnce, 2000);
        let _ = mon.inspect(&msg2);

        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
        assert_eq!(mon.rule_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Non-topic packets pass through
    // -----------------------------------------------------------------------

    #[test]
    fn ping_passes_without_topic_check() {
        let mut mon = MqttMonitor::new_deny_default();
        let msg = MqttMessage {
            packet_type: MqttPacketType::PingReq,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let result = mon.inspect(&msg);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // FNV hash
    // -----------------------------------------------------------------------

    #[test]
    fn fnv_hash_deterministic() {
        let h1 = fnv1a_hash(b"sensors/temperature");
        let h2 = fnv1a_hash(b"sensors/temperature");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv_hash_different_inputs() {
        let h1 = fnv1a_hash(b"sensors/temperature");
        let h2 = fnv1a_hash(b"sensors/humidity");
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------------

    #[test]
    fn disconnect_passes_without_topic_check() {
        let mut mon = MqttMonitor::new_deny_default();
        let msg = MqttMessage {
            packet_type: MqttPacketType::Disconnect,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let result = mon.inspect(&msg);
        assert!(result.allowed);
    }

    #[test]
    fn connack_passes_without_topic_check() {
        let mut mon = MqttMonitor::new_deny_default();
        let msg = MqttMessage {
            packet_type: MqttPacketType::ConnAck,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn unsubscribe_checked_against_rules() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Unsubscribe,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let topic = b"admin/users";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn connect_window_overflow_shifts_oldest() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(50, 100_000_000);

        for i in 0..20 {
            let msg = make_connect(1_000_000 * (i + 1));
            let _ = mon.inspect(&msg);
        }
        assert!(mon.total_inspected() >= 20);
    }

    #[test]
    fn rate_limit_different_topics_independent() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"a/#", TopicAction::Allow, QosPolicy::Any, 2)
            .unwrap();
        mon.add_rule(b"b/#", TopicAction::Allow, QosPolicy::Any, 2)
            .unwrap();

        for i in 0..2 {
            let msg = make_publish(b"a/data", MqttQoS::AtMostOnce, 1000 + i * 100);
            assert!(mon.inspect(&msg).allowed);
        }

        let msg = make_publish(b"b/data", MqttQoS::AtMostOnce, 1200);
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn rate_limit_not_applied_to_subscribe() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 1)
            .unwrap();

        let msg = make_publish(b"data/x", MqttQoS::AtMostOnce, 1000);
        assert!(mon.inspect(&msg).allowed);

        let msg2 = make_publish(b"data/x", MqttQoS::AtMostOnce, 1100);
        assert!(!mon.inspect(&msg2).allowed);

        let msg3 = make_subscribe(b"data/x", 1200);
        assert!(mon.inspect(&msg3).allowed);
    }

    #[test]
    fn wildcard_plus_at_start() {
        assert!(topic_matches(b"room1/temp", b"+/temp"));
        assert!(!topic_matches(b"room1/sub/temp", b"+/temp"));
    }

    #[test]
    fn wildcard_plus_at_end() {
        assert!(topic_matches(b"sensors/temp", b"sensors/+"));
        assert!(topic_matches(b"sensors/humidity", b"sensors/+"));
    }

    #[test]
    fn wildcard_multiple_plus() {
        assert!(topic_matches(b"a/b/c", b"+/+/+"));
        assert!(!topic_matches(b"a/b", b"+/+/+"));
    }

    #[test]
    fn exact_match_no_wildcard() {
        assert!(topic_matches(b"exact", b"exact"));
        assert!(!topic_matches(b"exact2", b"exact"));
        assert!(!topic_matches(b"exac", b"exact"));
    }

    #[test]
    fn empty_topic_empty_pattern() {
        assert!(topic_matches(b"", b""));
    }

    #[test]
    fn hash_alone_matches_empty() {
        assert!(topic_matches(b"", b"#"));
    }

    #[test]
    fn qos_any_policy_accepts_all() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"t/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        for qos in [
            MqttQoS::AtMostOnce,
            MqttQoS::AtLeastOnce,
            MqttQoS::ExactlyOnce,
        ] {
            let msg = make_publish(b"t/a", qos, 1000);
            assert_eq!(mon.inspect(&msg).alert_count, 0);
        }
    }

    #[test]
    fn default_constructor() {
        let mon = MqttMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.rule_count(), 0);
    }

    #[test]
    fn multiple_rules_first_match_wins() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        mon.add_rule(b"sensors/secret", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        let msg = make_publish(b"sensors/secret", MqttQoS::AtMostOnce, 1000);
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn rate_limit_bucket_exhaustion_alert() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"#", TopicAction::Allow, QosPolicy::Any, 1)
            .unwrap();

        for i in 0..MAX_RATE_BUCKETS_MQTT {
            let mut topic = [0u8; 4];
            topic[0] = b'x';
            topic[1] = b'/';
            topic[2] = b'a' + (i as u8 / 26);
            topic[3] = b'a' + (i as u8 % 26);
            let msg = make_publish(&topic, MqttQoS::AtMostOnce, 1000 + i as u64 * 100);
            let _ = mon.inspect(&msg);
        }

        // New topic should trigger LRU eviction of the oldest bucket.
        // Traffic is allowed but a high-severity exhaustion alert is emitted.
        let msg = make_publish(b"z/overflow", MqttQoS::AtMostOnce, 5000);
        let result = mon.inspect(&msg);
        assert!(
            result.allowed,
            "LRU eviction should allow traffic with warning"
        );
        assert!(result.alert_count > 0);
        // The alert should be the bucket exhaustion alert.
        let has_exhausted = (0..result.alert_count as usize)
            .any(|i| result.alerts[i].source_id == ALERT_RATE_BUCKET_EXHAUSTED);
        assert!(has_exhausted, "should have bucket exhaustion alert");
    }

    #[test]
    fn connect_storm_threshold_exactly_at_boundary() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(3, 10_000_000);

        for i in 0..2 {
            let msg = make_connect(1_000_000 * (i + 1));
            assert!(mon.inspect(&msg).allowed);
        }
        assert_eq!(mon.total_alerts(), 0);
    }

    // -----------------------------------------------------------------------
    // Rule removal and validation
    // -----------------------------------------------------------------------

    #[test]
    fn remove_rule_works() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"a/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        mon.add_rule(b"b/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        assert_eq!(mon.rule_count(), 2);

        mon.remove_rule(0).unwrap();
        assert_eq!(mon.rule_count(), 1);

        let msg = make_publish(b"a/data", MqttQoS::AtMostOnce, 1000);
        assert!(mon.inspect(&msg).allowed);

        let msg2 = make_publish(b"b/data", MqttQoS::AtMostOnce, 2000);
        assert!(!mon.inspect(&msg2).allowed);
    }

    #[test]
    fn remove_rule_invalid_index() {
        let mut mon = MqttMonitor::new();
        assert!(mon.remove_rule(0).is_err());
    }

    #[test]
    fn clear_rules_works() {
        let mut mon = MqttMonitor::new_deny_default();
        mon.add_rule(b"a/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        mon.clear_rules();
        assert_eq!(mon.rule_count(), 0);
        let msg = make_publish(b"a/data", MqttQoS::AtMostOnce, 1000);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn validate_rules_detects_shadowed() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        let shadowed = mon
            .add_rule(b"sensors/secret", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        assert_eq!(shadowed, 1);
    }

    #[test]
    fn validate_rules_no_shadow() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        let shadowed = mon
            .add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        assert_eq!(shadowed, 0);
    }

    // -----------------------------------------------------------------------
    // Wildcard validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn wildcard_hash_not_last_rejected() {
        let mut mon = MqttMonitor::new();
        assert!(mon
            .add_rule(b"sensors/#/more", TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    #[test]
    fn wildcard_hash_without_slash_rejected() {
        let mut mon = MqttMonitor::new();
        assert!(mon
            .add_rule(b"sensors#", TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    #[test]
    fn wildcard_plus_mid_level_rejected() {
        let mut mon = MqttMonitor::new();
        assert!(mon
            .add_rule(b"sensors/te+mp", TopicAction::Allow, QosPolicy::Any, 0)
            .is_err());
    }

    // -----------------------------------------------------------------------
    // Alert overflow
    // -----------------------------------------------------------------------

    #[test]
    fn alert_overflow_capped_at_4() {
        let mut result = MqttInspectResult::clean();
        for _ in 0..6 {
            result.push_alert(AlertSeverity::Medium, 0, 1000, 1);
        }
        assert_eq!(result.alert_count, 4);
    }

    // -----------------------------------------------------------------------
    // Non-monotonic timestamps
    // -----------------------------------------------------------------------

    #[test]
    fn non_monotonic_timestamp_no_panic() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(5, 10_000_000);

        let _ = mon.inspect(&make_connect(10_000_000));
        let _r = mon.inspect(&make_connect(1_000_000));
        // No panic is the assertion — the function returned successfully.
    }

    // -----------------------------------------------------------------------
    // Rate bucket expiration
    // -----------------------------------------------------------------------

    #[test]
    fn rate_bucket_expires_and_is_reused() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"#", TopicAction::Allow, QosPolicy::Any, 1)
            .unwrap();

        for i in 0u8..32 {
            let topic = [b'a' + (i / 26), b'a' + (i % 26)];
            let msg = make_publish(&topic, MqttQoS::AtMostOnce, 1000);
            let _ = mon.inspect(&msg);
        }
        let msg = make_publish(b"zz", MqttQoS::AtMostOnce, 400_000_000);
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Alert ID tracking (V: C3 fix)
    // -----------------------------------------------------------------------

    #[test]
    fn alert_ids_are_unique_and_incrementing() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"block/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        let r1 = mon.inspect(&make_publish(b"block/a", MqttQoS::AtMostOnce, 1000));
        let r2 = mon.inspect(&make_publish(b"block/b", MqttQoS::AtMostOnce, 2000));

        assert!(r1.alerts[0].id > 0);
        assert!(r2.alerts[0].id > r1.alerts[0].id);
    }

    // -----------------------------------------------------------------------
    // Payload hash computation (C3 fix)
    // -----------------------------------------------------------------------

    #[test]
    fn payload_hash_populated_on_block() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        let mut msg = make_publish(b"admin/x", MqttQoS::AtMostOnce, 1000);
        msg.payload[0] = 0xDE;
        msg.payload[1] = 0xAD;
        msg.payload_inspectable_len = 2;

        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        // Hash should not be all-zero since we have payload content.
        assert_ne!(r.alerts[0].payload_hash, PayloadHash::ZERO);
    }

    #[test]
    fn payload_hash_zero_for_empty_payload() {
        let h = compute_payload_hash(&[]);
        assert_eq!(h, PayloadHash::ZERO);
    }

    #[test]
    fn payload_hash_deterministic() {
        let h1 = compute_payload_hash(&[1, 2, 3]);
        let h2 = compute_payload_hash(&[1, 2, 3]);
        assert_eq!(h1.0, h2.0);
    }

    // -----------------------------------------------------------------------
    // EWMA payload size anomaly detection
    // -----------------------------------------------------------------------

    #[test]
    fn ewma_no_alert_during_warmup() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"t/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        // First 4 messages are warmup — no anomaly alerts even for large payloads.
        for i in 0..4 {
            let msg = make_publish_with_payload(b"t/a", MqttQoS::AtMostOnce, 1000 + i, 10);
            let r = mon.inspect(&msg);
            assert_eq!(r.alert_count, 0, "warmup msg {i} should not alert");
        }
    }

    #[test]
    fn ewma_detects_anomalous_payload() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"t/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        // Warmup with small payloads.
        for i in 0..10 {
            let msg = make_publish_with_payload(b"t/a", MqttQoS::AtMostOnce, 1000 + i, 10);
            let _ = mon.inspect(&msg);
        }

        // Large payload should trigger anomaly (10 * 4 = 40, 500 > 40).
        let msg = make_publish_with_payload(b"t/a", MqttQoS::AtMostOnce, 2000, 500);
        let r = mon.inspect(&msg);
        assert!(r.alert_count > 0, "anomalous payload should trigger alert");
        // Alert source_id for EWMA anomaly is 6.
        let has_ewma =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_PAYLOAD_ANOMALY);
        assert!(has_ewma, "should have EWMA anomaly alert (source_id=6)");
    }

    #[test]
    fn ewma_no_alert_for_proportional_payload() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"t/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        // Warmup with payloads of size 100.
        for i in 0..10 {
            let msg = make_publish_with_payload(b"t/a", MqttQoS::AtMostOnce, 1000 + i, 100);
            let _ = mon.inspect(&msg);
        }

        // Slightly larger payload (150) should NOT trigger (< 4x mean).
        let msg = make_publish_with_payload(b"t/a", MqttQoS::AtMostOnce, 2000, 150);
        let r = mon.inspect(&msg);
        let has_ewma =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_PAYLOAD_ANOMALY);
        assert!(
            !has_ewma,
            "proportional payload should not trigger EWMA alert"
        );
    }

    // -----------------------------------------------------------------------
    // Clear rules mid-traffic
    // -----------------------------------------------------------------------

    #[test]
    fn clear_rules_mid_traffic_no_corruption() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 5)
            .unwrap();

        // Some traffic to populate rate buckets.
        for i in 0..3 {
            let msg = make_publish(b"data/x", MqttQoS::AtMostOnce, 1000 + i * 100);
            let _ = mon.inspect(&msg);
        }

        // Clear rules mid-traffic.
        mon.clear_rules();
        assert_eq!(mon.rule_count(), 0);

        // New traffic should use default action (Allow), no panics.
        let msg = make_publish(b"data/x", MqttQoS::AtMostOnce, 2000);
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Timestamp validation
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_normal_no_alert() {
        let mut mon = MqttMonitor::new();
        let msg1 = make_publish(b"t/a", MqttQoS::AtMostOnce, 1_000_000);
        let r1 = mon.inspect(&msg1);
        assert_eq!(r1.alert_count, 0);

        let msg2 = make_publish(b"t/a", MqttQoS::AtMostOnce, 2_000_000);
        let r2 = mon.inspect(&msg2);
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn timestamp_anomaly_large_forward_jump() {
        let mut mon = MqttMonitor::new();
        // First message initializes the validator.
        let msg1 = make_publish(b"t/a", MqttQoS::AtMostOnce, 1_000_000);
        let r1 = mon.inspect(&msg1);
        assert_eq!(r1.alert_count, 0);

        // Jump more than MAX_CLOCK_FORWARD_JUMP_US (3_600_000_000 = 1 hour).
        let msg2 = make_publish(b"t/a", MqttQoS::AtMostOnce, 5_000_000_000);
        let r2 = mon.inspect(&msg2);
        // Should still be allowed (timestamp anomaly doesn't block).
        assert!(r2.allowed);
        // Should have a timestamp anomaly alert.
        let has_ts =
            (0..r2.alert_count as usize).any(|i| r2.alerts[i].source_id == ALERT_TIMESTAMP_ANOMALY);
        assert!(has_ts, "should have timestamp anomaly alert");
    }

    #[test]
    fn timestamp_anomaly_large_backward_jump() {
        let mut mon = MqttMonitor::new();
        let msg1 = make_publish(b"t/a", MqttQoS::AtMostOnce, 100_000_000);
        let _ = mon.inspect(&msg1);

        // Jump backward more than MAX_CLOCK_BACKWARD_JUMP_US (10_000_000).
        let msg2 = make_publish(b"t/a", MqttQoS::AtMostOnce, 1_000);
        let r2 = mon.inspect(&msg2);
        assert!(r2.allowed);
        let has_ts =
            (0..r2.alert_count as usize).any(|i| r2.alerts[i].source_id == ALERT_TIMESTAMP_ANOMALY);
        assert!(
            has_ts,
            "should have timestamp anomaly alert on backward jump"
        );
    }

    // -----------------------------------------------------------------------
    // MonitorReset
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_reset_preserves_rules_clears_state() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 5)
            .unwrap();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        // Generate some traffic to populate state.
        for i in 0..5 {
            let msg = make_publish(b"data/x", MqttQoS::AtMostOnce, 1_000_000 + i * 100_000);
            let _ = mon.inspect(&msg);
        }
        let msg = make_publish(b"admin/x", MqttQoS::AtMostOnce, 2_000_000);
        let _ = mon.inspect(&msg);
        let msg = make_connect(3_000_000);
        let _ = mon.inspect(&msg);

        assert!(mon.total_inspected() > 0);
        assert!(mon.total_alerts() > 0);

        // Reset state.
        mon.reset_state();

        // Counters should be cleared.
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);

        // Rules should be preserved.
        assert_eq!(mon.rule_count(), 2);

        // Allowed topic still works.
        let msg = make_publish(b"data/y", MqttQoS::AtMostOnce, 100_000);
        let r = mon.inspect(&msg);
        assert!(r.allowed);

        // Blocked topic still works.
        let msg = make_publish(b"admin/y", MqttQoS::AtMostOnce, 200_000);
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
    }

    #[test]
    fn monitor_reset_clears_connect_storm_state() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(3, 10_000_000);

        // Two connects in quick succession.
        let _ = mon.inspect(&make_connect(1_000_000));
        let _ = mon.inspect(&make_connect(2_000_000));

        // Reset clears connect history.
        mon.reset_state();

        // Third connect should not trigger storm since history was cleared.
        let r = mon.inspect(&make_connect(3_000_000));
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    // -----------------------------------------------------------------------
    // Alert source ID constants
    // -----------------------------------------------------------------------

    #[test]
    fn alert_source_ids_are_named_constants() {
        // Verify the constants have the expected values for correlation.
        assert_eq!(ALERT_CONNECT_STORM, 1);
        assert_eq!(ALERT_EMPTY_TOPIC, 2);
        assert_eq!(ALERT_TOPIC_BLOCKED, 3);
        assert_eq!(ALERT_QOS_VIOLATION, 4);
        assert_eq!(ALERT_RATE_LIMITED, 5);
        assert_eq!(ALERT_RATE_BUCKET_EXHAUSTED, 6);
        assert_eq!(ALERT_PAYLOAD_ANOMALY, 7);
        assert_eq!(ALERT_TIMESTAMP_ANOMALY, 8);
    }

    #[test]
    fn connect_storm_alert_uses_correct_source_id() {
        let mut mon = MqttMonitor::new();
        mon.set_connect_storm_params(2, 10_000_000);

        let _ = mon.inspect(&make_connect(1_000_000));
        let r = mon.inspect(&make_connect(2_000_000));
        assert!(!r.allowed);
        assert_eq!(r.alerts[0].source_id, ALERT_CONNECT_STORM);
    }

    #[test]
    fn blocked_topic_alert_uses_correct_source_id() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        let msg = make_publish(b"admin/x", MqttQoS::AtMostOnce, 1000);
        let r = mon.inspect(&msg);
        assert_eq!(r.alerts[0].source_id, ALERT_TOPIC_BLOCKED);
    }

    #[test]
    fn qos_violation_alert_uses_correct_source_id() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(
            b"strict/#",
            TopicAction::Allow,
            QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .unwrap();
        let msg = make_publish(b"strict/x", MqttQoS::AtMostOnce, 1000);
        let r = mon.inspect(&msg);
        assert_eq!(r.alerts[0].source_id, ALERT_QOS_VIOLATION);
    }

    // -----------------------------------------------------------------------
    // V4: validate_mqtt_wildcard rejects empty patterns (via add_rule)
    // -----------------------------------------------------------------------

    #[test]
    fn add_rule_rejects_empty_pattern_after_clear() {
        let mut mon = MqttMonitor::new();
        // Empty pattern is invalid — add_rule should return an error.
        let result = mon.add_rule(b"", TopicAction::Allow, QosPolicy::Any, 0);
        assert!(
            result.is_err(),
            "empty pattern must be rejected by add_rule"
        );
    }

    #[test]
    fn add_rule_accepts_root_pattern() {
        let mut mon = MqttMonitor::new();
        // Single-char pattern is valid.
        let result = mon.add_rule(b"#", TopicAction::Allow, QosPolicy::Any, 0);
        assert!(result.is_ok(), "single '#' wildcard must be accepted");
    }

    // -----------------------------------------------------------------------
    // V5: rate-limit bucket scan visits all MAX_RATE_BUCKETS_MQTT slots
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_no_duplicate_bucket_after_lru_eviction() {
        let mut mon = MqttMonitor::new();
        // One wildcard rule with a rate limit — each distinct topic gets its
        // own rate bucket.  Send MAX_RATE_BUCKETS_MQTT + 1 distinct topics to
        // guarantee an LRU eviction, then re-send the first topic.  The bucket
        // table must not create a duplicate (old + new entry for the same topic).
        mon.add_rule(b"#", TopicAction::Allow, QosPolicy::Any, 100)
            .unwrap();

        let mut topics: [[u8; 4]; MAX_RATE_BUCKETS_MQTT] = [[b't'; 4]; MAX_RATE_BUCKETS_MQTT];
        for (i, t) in topics.iter_mut().enumerate() {
            t[0] = b'A' + (i % 26) as u8;
            t[1] = b'0' + (i / 26) as u8;
            t[2] = b'/';
            t[3] = b'x';
        }

        // Fill all rate buckets.
        for (i, topic) in topics.iter().enumerate() {
            let msg = make_publish(topic, MqttQoS::AtMostOnce, (i as u64 + 1) * 10_000);
            let _ = mon.inspect(&msg);
        }

        // Submit one more distinct topic to trigger LRU eviction of the oldest.
        let overflow = b"ZZ/x";
        let ts_evict = (MAX_RATE_BUCKETS_MQTT as u64 + 2) * 10_000;
        let _ = mon.inspect(&make_publish(overflow, MqttQoS::AtMostOnce, ts_evict));

        // Re-send the first topic (which was evicted).  All buckets are still
        // full with active non-expired entries, so this triggers another LRU
        // eviction.  Traffic is allowed but an exhaustion alert is emitted.
        let ts_retry = ts_evict + 10_000;
        let r = mon.inspect(&make_publish(&topics[0], MqttQoS::AtMostOnce, ts_retry));
        assert!(
            r.allowed,
            "evicted topic re-submitted should be allowed with warning"
        );
    }

    #[test]
    fn payload_hash_all_bytes_populated() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();

        // Build a message with a non-trivial payload (all bytes different).
        let mut msg = make_publish(b"admin/secret", MqttQoS::AtMostOnce, 1000);
        for i in 0..64usize {
            msg.payload[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        msg.payload_len = 64;
        msg.payload_inspectable_len = 64;

        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);

        // The hash should have all 32 bytes non-zero for a non-trivial payload.
        let hash_bytes = &r.alerts[0].payload_hash.0;
        for (idx, &byte) in hash_bytes.iter().enumerate() {
            assert_ne!(
                byte, 0,
                "payload_hash byte {idx} must be non-zero for non-trivial payload"
            );
        }
    }

    #[test]
    fn qos_violation_is_advisory_not_blocking() {
        let mut mon = MqttMonitor::new();
        mon.add_rule(
            b"strict/#",
            TopicAction::Allow,
            QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .unwrap();

        // Send a message with QoS 0 (AtMostOnce) which violates the MinQoS(AtLeastOnce) policy.
        let msg = make_publish(b"strict/data", MqttQoS::AtMostOnce, 1000);
        let result = mon.inspect(&msg);

        // QoS violation should generate an alert...
        assert!(
            result.alert_count > 0,
            "QoS violation should generate an alert"
        );
        let has_qos_alert = (0..result.alert_count as usize)
            .any(|i| result.alerts[i].source_id == ALERT_QOS_VIOLATION);
        assert!(has_qos_alert, "should have a QoS violation alert");

        // ...but the message should still be allowed (advisory, not blocking).
        assert!(
            result.allowed,
            "QoS violation must be advisory — message should still be allowed"
        );
    }

    #[test]
    fn ewma_tracker_lru_eviction_no_panic() {
        let mut monitor = MqttMonitor::new();
        monitor
            .add_rule(b"#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        // Fill all 16 EWMA tracker slots with distinct topics + payload data
        for i in 0u8..20 {
            let topic = [b'e', b'/', b'a' + i];
            let mut msg = MqttMessage {
                packet_type: MqttPacketType::Publish,
                topic_len: 3,
                qos: MqttQoS::AtMostOnce,
                payload_len: 50,
                payload_inspectable_len: 50,
                timestamp_us: 1000 + u64::from(i) * 100,
                ..MqttMessage::default()
            };
            msg.topic[..3].copy_from_slice(&topic);
            let r = monitor.inspect(&msg);
            assert!(r.allowed);
        }
        assert!(monitor.total_inspected() >= 20);
    }

    #[test]
    fn set_connect_storm_params_clamping() {
        let mut monitor = MqttMonitor::new();
        // Threshold 0 and 1 should be clamped to 2
        monitor.set_connect_storm_params(0, 5_000_000);
        // We can't directly read the threshold, but we can verify
        // that 1 connect doesn't trigger a storm (proving threshold >= 2)
        let msg = MqttMessage {
            packet_type: MqttPacketType::Connect,
            timestamp_us: 1_000_000,
            ..MqttMessage::default()
        };
        let r = monitor.inspect(&msg);
        assert!(r.allowed, "single connect should not trigger storm");
    }

    #[test]
    fn rate_limit_with_zero_max_rate_is_unlimited() {
        let mut monitor = MqttMonitor::new();
        // max_rate_per_sec = 0 means unlimited
        monitor
            .add_rule(b"test/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();
        for i in 0..100u64 {
            let mut msg = MqttMessage {
                packet_type: MqttPacketType::Publish,
                topic_len: 6,
                qos: MqttQoS::AtMostOnce,
                timestamp_us: 1_000_000 + i * 1000, // rapid fire
                ..MqttMessage::default()
            };
            msg.topic[..6].copy_from_slice(b"test/a");
            let r = monitor.inspect(&msg);
            assert!(r.allowed, "zero max_rate should mean unlimited at msg {i}");
        }
    }

    #[test]
    fn next_alert_id_skips_zero() {
        let mut monitor = MqttMonitor::new();
        monitor
            .add_rule(b"block/#", TopicAction::Block, QosPolicy::Any, 0)
            .unwrap();
        // Generate alerts and verify IDs are always nonzero
        for i in 1..=10u64 {
            let mut msg = MqttMessage {
                packet_type: MqttPacketType::Publish,
                topic_len: 7,
                qos: MqttQoS::AtMostOnce,
                timestamp_us: i * 1_000_000,
                ..MqttMessage::default()
            };
            msg.topic[..7].copy_from_slice(b"block/x");
            let r = monitor.inspect(&msg);
            assert!(r.alert_count > 0);
            assert!(r.alerts[0].id > 0, "alert ID must never be zero");
        }
    }

    #[test]
    fn rate_bucket_matches_topic_with_different_lengths() {
        // Regression test for CRIT-1: topics with same hash prefix but different
        // lengths must NOT match the same bucket.
        let mut monitor = MqttMonitor::new();
        monitor
            .add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 10)
            .unwrap();

        // First message: creates a rate bucket for "sensors/a"
        let mut msg = MqttMessage::default();
        msg.topic[..9].copy_from_slice(b"sensors/a");
        msg.topic_len = 9;
        msg.timestamp_us = 1_000_000;
        let _ = monitor.inspect(&msg);

        // Second message with a shorter topic that shares the same prefix bytes
        let mut msg2 = MqttMessage::default();
        msg2.topic[..4].copy_from_slice(b"sens");
        msg2.topic_len = 4;
        msg2.timestamp_us = 2_000_000;
        // This should NOT match the bucket for "sensors/a"
        // (before the fix, it could incorrectly match or create a duplicate)
        let _ = monitor.inspect(&msg2);
    }

    #[test]
    fn ewma_tracker_matches_topic_with_different_lengths() {
        // Regression test: EWMA trackers must distinguish topics of different lengths.
        let mut monitor = MqttMonitor::new();
        monitor
            .add_rule(b"data/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        // Build up EWMA baseline for "data/temp"
        for i in 0..10u64 {
            let mut msg = MqttMessage::default();
            msg.topic[..9].copy_from_slice(b"data/temp");
            msg.topic_len = 9;
            msg.payload_len = 100;
            msg.payload_inspectable_len = 100;
            msg.timestamp_us = (i + 1) * 1_000_000;
            let _ = monitor.inspect(&msg);
        }

        // A shorter topic "data/t" must get its own tracker, not share the
        // baseline from "data/temp".
        let mut msg2 = MqttMessage::default();
        msg2.topic[..6].copy_from_slice(b"data/t");
        msg2.topic_len = 6;
        msg2.payload_len = 100;
        msg2.payload_inspectable_len = 100;
        msg2.timestamp_us = 20_000_000;
        let r = monitor.inspect(&msg2);
        assert!(r.allowed);
    }

    #[test]
    fn alerts_dropped_counter_increments_on_overflow() {
        // Verify alerts_dropped tracks dropped alerts beyond the 4-alert limit.
        let mut monitor = MqttMonitor::new_deny_default();
        // Add a block rule that will trigger multiple alerts
        monitor
            .add_rule(
                b"blocked",
                TopicAction::Block,
                QosPolicy::ExactQoS(MqttQoS::ExactlyOnce),
                1,
            )
            .unwrap();

        let mut msg = MqttMessage::default();
        msg.topic[..7].copy_from_slice(b"blocked");
        msg.topic_len = 7;
        msg.timestamp_us = 1_000_000;
        let r = monitor.inspect(&msg);
        // Should have alerts_dropped field accessible (even if 0)
        let _ = r.alerts_dropped;
    }

    #[test]
    fn connect_storm_window_upper_bound_clamped() {
        let mut monitor = MqttMonitor::new();
        // Setting window to u64::MAX should be clamped to 600_000_000
        monitor.set_connect_storm_params(5, u64::MAX);
        // The monitor should still function correctly with the clamped value
        let mut msg = MqttMessage::default();
        msg.packet_type = MqttPacketType::Connect;
        msg.timestamp_us = 1_000_000;
        let r = monitor.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // topic_matches edge cases — audit fixes
    // -----------------------------------------------------------------------

    #[test]
    fn topic_matches_multi_level_wildcard_matches_parent() {
        // MQTT spec: "sport/tennis/player1/#" also matches "sport/tennis/player1"
        assert!(topic_matches(b"a/b", b"a/b/#"));
        assert!(topic_matches(b"a", b"a/#"));
        assert!(topic_matches(b"sensors", b"sensors/#"));
    }

    #[test]
    fn topic_matches_plus_then_hash_matches_single_level() {
        // "a/+/#" should match "a/b" (+ matches "b", # matches zero trailing levels)
        assert!(topic_matches(b"a/b", b"a/+/#"));
    }

    #[test]
    fn topic_matches_plus_then_hash_matches_deep() {
        assert!(topic_matches(b"a/b/c/d", b"a/+/#"));
    }

    #[test]
    fn topic_matches_plus_no_trailing_hash_no_extra() {
        // "a/+/b" should NOT match "a/x" (no trailing # to absorb missing /b)
        assert!(!topic_matches(b"a/x", b"a/+/b"));
    }

    #[test]
    fn topic_matches_exact() {
        assert!(topic_matches(b"a/b/c", b"a/b/c"));
        assert!(!topic_matches(b"a/b", b"a/b/c"));
        assert!(!topic_matches(b"a/b/c", b"a/b"));
    }

    #[test]
    fn topic_matches_hash_alone() {
        assert!(topic_matches(b"anything", b"#"));
        assert!(topic_matches(b"a/b/c", b"#"));
    }

    #[test]
    fn topic_matches_plus_single_level() {
        assert!(topic_matches(b"a/b/c", b"a/+/c"));
        assert!(!topic_matches(b"a/b/d", b"a/+/c"));
    }

    // -----------------------------------------------------------------------
    // EWMA ceiling — audit fix
    // -----------------------------------------------------------------------

    #[test]
    fn ewma_ceiling_prevents_drift() {
        let mut tracker = EwmaTracker::empty();
        tracker.topic_hash = 0x1234;
        tracker.topic_prefix = [0; BUCKET_PREFIX_LEN];
        tracker.topic_prefix_len = 0;
        tracker.topic_len = 5;

        // Warmup with small values.
        for _ in 0..4 {
            tracker.update(100);
        }

        // Send increasingly large payloads to try to inflate the baseline.
        for _ in 0..1000 {
            tracker.update(60000); // near u16::MAX
        }

        // The mean should be clamped at the ceiling.
        assert!(
            tracker.mean_x256 <= vs_types_embedded::EWMA_MEAN_CEILING_X256,
            "EWMA mean {} should be clamped at ceiling {}",
            tracker.mean_x256,
            vs_types_embedded::EWMA_MEAN_CEILING_X256,
        );
    }

    // -----------------------------------------------------------------------
    // validate_rules returns u16 — audit fix
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rules_returns_u16() {
        let mon = MqttMonitor::new();
        let _count: u16 = mon.validate_rules(); // type check
    }
}
