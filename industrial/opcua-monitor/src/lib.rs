#![no_std]

//! OPC UA security monitor for industrial control systems.
//!
//! Monitors OPC UA traffic for security violations:
//!
//! - **Security mode enforcement** — require `SignAndEncrypt` for all channels,
//!   with configurable blocking (not just alerting).
//! - **Session management** — track active sessions, detect session hijacking.
//! - **Write authorization** — restrict which nodes/endpoints allow writes.
//! - **Method call filtering** — block dangerous method invocations.
//! - **Endpoint allowlist** — restrict which OPC UA endpoints are reachable.
//!   Rules are sorted by pattern length for fastest longest-prefix matching.
//! - **Rate limiting** — per-channel request rate enforcement.
//! - **Sequence number validation** — detect replay attacks with
//!   wraparound-safe window comparison.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{
    AlertCode, InspectResult, OpcUaMessage, OpcUaMessageType, OpcUaSecurityMode, RateBucket,
    SOURCE_OPCUA,
};

/// Backward-compatible type alias.
pub type OpcUaInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum endpoint rules.
const MAX_ENDPOINT_RULES: usize = 16;

/// Maximum endpoint pattern length.
const MAX_PATTERN_LEN: usize = 64;

/// Maximum tracked sessions/channels.
const MAX_SESSIONS: usize = 16;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

/// Default session timeout in microseconds (600 seconds).
const DEFAULT_SESSION_TIMEOUT_US: u64 = 600_000_000;

/// Sequence number replay detection window.
/// A difference greater than this (via wrapping subtraction) is considered
/// a replay or out-of-order packet.
const SEQUENCE_WINDOW: u32 = 65536;

// ---------------------------------------------------------------------------
// Endpoint rule
// ---------------------------------------------------------------------------

/// Action for an endpoint match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAction {
    Allow,
    Block,
}

/// Message type permissions bitmask.
#[derive(Debug, Clone, Copy)]
pub struct MessagePermissions(u16);

impl MessagePermissions {
    /// All message types allowed.
    pub const ALL: Self = Self(0xFFFF);
    /// Read-only: Browse + Read + `CreateSubscription` + Publish.
    pub const READ_ONLY: Self = Self(
        (1 << OpcUaMessageType::Browse as u16)
            | (1 << OpcUaMessageType::Read as u16)
            | (1 << OpcUaMessageType::CreateSubscription as u16)
            | (1 << OpcUaMessageType::Publish as u16),
    );
    /// No operations allowed (session management only).
    pub const NONE: Self = Self(0);

    /// Check if a message type is allowed.
    pub fn is_allowed(self, msg_type: OpcUaMessageType) -> bool {
        let bit = msg_type as u16;
        if bit > 15 {
            return false;
        }
        (self.0 >> bit) & 1 == 1
    }
}

/// Endpoint filtering rule.
#[derive(Debug, Clone, Copy)]
struct EndpointRule {
    pattern: [u8; MAX_PATTERN_LEN],
    pattern_len: u8,
    action: EndpointAction,
    permissions: MessagePermissions,
    /// Minimum required security mode.
    min_security_mode: OpcUaSecurityMode,
    /// Max requests per second.
    max_rate_per_sec: u16,
    active: bool,
}

impl EndpointRule {
    const fn empty() -> Self {
        Self {
            pattern: [0u8; MAX_PATTERN_LEN],
            pattern_len: 0,
            action: EndpointAction::Allow,
            permissions: MessagePermissions::ALL,
            min_security_mode: OpcUaSecurityMode::None,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Session tracking
// ---------------------------------------------------------------------------

/// Tracked OPC UA channel/session.
#[derive(Debug, Clone, Copy)]
struct SessionState {
    channel_id: u32,
    /// Last seen sequence number for replay detection.
    last_sequence: u32,
    /// Whether at least one message has been seen (for seq=0 handling).
    has_seen_message: bool,
    /// Security mode negotiated for this channel.
    security_mode: OpcUaSecurityMode,
    /// Last activity timestamp.
    last_activity_us: u64,
    active: bool,
}

impl SessionState {
    const fn empty() -> Self {
        Self {
            channel_id: 0,
            last_sequence: 0,
            has_seen_message: false,
            security_mode: OpcUaSecurityMode::None,
            last_activity_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// OPC UA Monitor
// ---------------------------------------------------------------------------

/// OPC UA security monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~2.5 KB.
/// - `rules`: 16 × ~74 bytes = 1184 bytes
/// - `sessions`: 16 × ~24 bytes = 384 bytes
/// - `rate_buckets`: 16 × 24 bytes = 384 bytes
/// - Scalars: ~80 bytes
pub struct OpcUaMonitor {
    /// Rules sorted by `pattern_len` descending for fastest longest-prefix match.
    rules: [EndpointRule; MAX_ENDPOINT_RULES],
    rule_count: u8,
    sessions: [SessionState; MAX_SESSIONS],
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Global minimum security mode (applied to all channels).
    global_min_security: OpcUaSecurityMode,
    /// Block all Write and Call operations globally.
    global_read_only: bool,
    /// Default action for unmatched endpoints.
    default_action: EndpointAction,
    /// When `true`, security mode violations block traffic (not just alert).
    enforce_security_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    /// Monotonic alert ID counter.
    next_alert_id: u64,
    /// Session timeout in microseconds.
    session_timeout_us: u64,
    /// Last rate bucket index used (temporal locality optimization).
    last_rate_idx: usize,
    /// Number of active sessions (O(1) tracking).
    active_session_count: u8,
    /// Earliest `last_activity_us` across active sessions for fast expiry skip.
    earliest_activity_us: u64,
    /// When `true`, replay detection blocks traffic (not just alerts).
    enforce_replay: bool,
    /// Maximum allowed message size (0 = no limit).
    max_message_size: u32,
    /// Monotonic tick counter for rate-bucket LRU eviction ordering.
    rate_tick: u32,
    /// Rate limiter for new session creation to prevent session flood attacks
    /// that could evict legitimate sessions from the tracking table.
    session_create_bucket: RateBucket,
    /// Maximum new sessions per second (0 = unlimited).
    max_session_create_rate: u16,
}

impl OpcUaMonitor {
    /// Create a new OPC UA monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            rules: [EndpointRule::empty(); MAX_ENDPOINT_RULES],
            rule_count: 0,
            sessions: [SessionState::empty(); MAX_SESSIONS],
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            global_min_security: OpcUaSecurityMode::None,
            global_read_only: false,
            default_action: EndpointAction::Allow,
            enforce_security_mode: true,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            session_timeout_us: DEFAULT_SESSION_TIMEOUT_US,
            last_rate_idx: 0,
            active_session_count: 0,
            earliest_activity_us: u64::MAX,
            enforce_replay: true,
            max_message_size: 0,
            rate_tick: 0,
            session_create_bucket: RateBucket::empty(),
            max_session_create_rate: 0,
        }
    }

    /// Create a new OPC UA monitor (deny-by-default).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = EndpointAction::Block;
        m
    }

    /// Set global minimum security mode.
    ///
    /// Channels using a weaker security mode will trigger alerts.
    /// If [`set_enforce_security_mode`](Self::set_enforce_security_mode) is
    /// `true`, violating traffic is also blocked.
    pub fn set_min_security_mode(&mut self, mode: OpcUaSecurityMode) {
        self.global_min_security = mode;
    }

    /// Set whether security mode violations block traffic (default: `true`).
    ///
    /// When `true`, messages with a security mode below the global or
    /// per-endpoint minimum are denied, not just alerted.
    pub fn set_enforce_security_mode(&mut self, enforce: bool) {
        self.enforce_security_mode = enforce;
    }

    /// Set global read-only mode (block all Write and Call operations).
    pub fn set_read_only(&mut self, read_only: bool) {
        self.global_read_only = read_only;
    }

    /// Set the session timeout in microseconds.
    pub fn set_session_timeout(&mut self, timeout_us: u64) {
        self.session_timeout_us = timeout_us;
    }

    /// Set whether replay detection blocks traffic (default: `true`).
    pub fn set_enforce_replay(&mut self, enforce: bool) {
        self.enforce_replay = enforce;
    }

    /// Set maximum allowed message size (0 = no limit).
    pub fn set_max_message_size(&mut self, max_size: u32) {
        self.max_message_size = max_size;
    }

    /// Set maximum rate of new session creation per second.
    ///
    /// When set, new sessions that exceed this rate are rejected rather than
    /// evicting existing tracked sessions. This prevents an attacker from
    /// flooding the session table and evicting legitimate sessions whose
    /// replay detection state would then be lost.
    ///
    /// A value of `0` disables the limit (default).
    pub fn set_max_session_create_rate(&mut self, rate: u16) {
        self.max_session_create_rate = rate;
        if rate > 0 {
            self.session_create_bucket = RateBucket {
                key: 0,
                tokens: rate,
                capacity: rate,
                last_refill_us: 0,
                active: true,
                last_used: 0,
            };
        } else {
            self.session_create_bucket = RateBucket::empty();
        }
    }

    /// Add an endpoint rule.
    ///
    /// The pattern is matched as a prefix of the endpoint URL.
    /// Rules are kept sorted by pattern length (longest first) for
    /// early-exit longest-prefix matching.
    pub fn add_rule(
        &mut self,
        endpoint_prefix: &[u8],
        action: EndpointAction,
        permissions: MessagePermissions,
        min_security: OpcUaSecurityMode,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if endpoint_prefix.is_empty() || endpoint_prefix.len() > MAX_PATTERN_LEN {
            return Err(VsError::InvalidInput);
        }
        if self.rule_count as usize >= MAX_ENDPOINT_RULES {
            return Err(VsError::ResourceExhausted);
        }

        let new_len = endpoint_prefix.len() as u8;

        // Find insertion point to maintain descending sort by pattern_len.
        let count = self.rule_count as usize;
        let mut insert_at = count;
        for i in 0..count {
            if self.rules[i].pattern_len < new_len {
                insert_at = i;
                break;
            }
        }

        // Shift rules right to make room.
        let mut i = count;
        while i > insert_at {
            self.rules[i] = self.rules[i - 1];
            i -= 1;
        }

        self.rules[insert_at].pattern[..endpoint_prefix.len()].copy_from_slice(endpoint_prefix);
        // Normalise stored pattern to lowercase for case-insensitive prefix matching.
        for b in &mut self.rules[insert_at].pattern[..endpoint_prefix.len()] {
            *b = b.to_ascii_lowercase();
        }
        self.rules[insert_at].pattern_len = new_len;
        self.rules[insert_at].action = action;
        self.rules[insert_at].permissions = permissions;
        self.rules[insert_at].min_security_mode = min_security;
        self.rules[insert_at].max_rate_per_sec = max_rate_per_sec;
        self.rules[insert_at].active = true;
        self.rule_count += 1;
        Ok(())
    }

    /// Inspect an OPC UA message.
    #[allow(clippy::too_many_lines)]
    pub fn inspect(&mut self, msg: &OpcUaMessage) -> OpcUaInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_OPCUA);

        // Reject messages with endpoint_len exceeding the buffer size.
        if msg.endpoint_len_overflow() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PayloadOverflow,
            );
            return result;
        }

        // Message size enforcement.
        if self.max_message_size > 0 && msg.message_size > self.max_message_size {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::MessageSizeExceeded,
            );
            return result;
        }

        // Security mode enforcement (global).
        if (msg.security_mode as u8) < (self.global_min_security as u8) {
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::SecurityModeViolation,
            );
            if self.enforce_security_mode {
                result.allowed = false;
                return result;
            }
        }

        // Global read-only enforcement.
        if self.global_read_only
            && (msg.msg_type == OpcUaMessageType::Write || msg.msg_type == OpcUaMessageType::Call)
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::WriteProtection,
            );
            return result;
        }

        // Sequence number replay detection + session tracking.
        let (replay_result, session_hint) =
            self.check_replay(msg.channel_id, msg.sequence_number, msg.msg_type);
        if let Some(true) = replay_result {
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::ReplayDetected,
            );
            if self.enforce_replay {
                result.allowed = false;
                return result;
            }
        }

        self.track_session(msg, session_hint);

        // Apply default_action even when endpoint is empty.
        // Use `valid_endpoint_len()` to defensively cap the slice length —
        // never trust a raw `endpoint_len` field against the buffer size.
        let endpoint_len = msg.valid_endpoint_len();
        if endpoint_len > 0 {
            let endpoint = &msg.endpoint[..endpoint_len];
            let matched = self.find_matching_rule(endpoint);

            let action = match matched {
                Some(idx) => self.rules[idx].action,
                None => self.default_action,
            };

            if action == EndpointAction::Block {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_OPCUA,
                    msg.channel_id,
                    msg.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::EndpointBlocked,
                );
                return result;
            }

            // Per-endpoint security mode.
            if let Some(idx) = matched {
                let min_sec = self.rules[idx].min_security_mode;
                if (msg.security_mode as u8) < (min_sec as u8) {
                    result.push_alert_with_code(
                        AlertSeverity::High,
                        SOURCE_OPCUA,
                        msg.channel_id,
                        msg.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::SecurityModeViolation,
                    );
                    if self.enforce_security_mode {
                        result.allowed = false;
                        return result;
                    }
                }

                // Message type permissions.
                if !self.rules[idx].permissions.is_allowed(msg.msg_type) {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_OPCUA,
                        msg.channel_id,
                        msg.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::MessageTypeBlocked,
                    );
                    return result;
                }

                // Rate limiting.
                let max_rate = self.rules[idx].max_rate_per_sec;
                if max_rate > 0 && !self.rate_check(msg.channel_id, max_rate, msg.timestamp_us) {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_OPCUA,
                        msg.channel_id,
                        msg.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::RateExceeded,
                    );
                }
            }
        } else {
            // No endpoint present — apply default_action.
            if self.default_action == EndpointAction::Block {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_OPCUA,
                    msg.channel_id,
                    msg.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::EndpointBlocked,
                );
                return result;
            }
        }

        result
    }

    /// Total number of messages inspected since creation.
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Total number of alerts generated since creation.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Number of currently active sessions/channels.
    pub fn active_sessions(&self) -> usize {
        self.active_session_count as usize
    }

    /// Return the next alert ID that will be assigned.
    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    /// Expire sessions that have been inactive longer than `session_timeout_us`.
    ///
    /// Uses `earliest_activity_us` to skip the scan when no session can
    /// possibly be expired (O(1) fast path).
    pub fn expire_sessions(&mut self, now_us: u64) {
        // Fast path: no session is old enough to expire.
        if self.active_session_count == 0
            || now_us.saturating_sub(self.earliest_activity_us) <= self.session_timeout_us
        {
            return;
        }

        let mut new_earliest = u64::MAX;
        for s in &mut self.sessions {
            if s.active {
                if now_us.saturating_sub(s.last_activity_us) > self.session_timeout_us {
                    s.active = false;
                    self.active_session_count = self.active_session_count.saturating_sub(1);
                } else if s.last_activity_us < new_earliest {
                    new_earliest = s.last_activity_us;
                }
            }
        }
        self.earliest_activity_us = new_earliest;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Single-pass session tracking: handles close, update, creation, and
    /// eviction in one scan.
    fn track_session(&mut self, msg: &OpcUaMessage, session_hint: Option<usize>) {
        if msg.channel_id == 0 {
            return;
        }

        let is_close = msg.msg_type == OpcUaMessageType::CloseSession
            || msg.msg_type == OpcUaMessageType::CloseSecureChannel;

        // Fast path: reuse hint from check_replay.
        if let Some(hi) = session_hint {
            let s = &mut self.sessions[hi];
            if s.active && s.channel_id == msg.channel_id {
                if is_close {
                    s.active = false;
                    self.active_session_count = self.active_session_count.saturating_sub(1);
                    self.recompute_earliest();
                } else {
                    s.last_activity_us = msg.timestamp_us;
                    if msg.msg_type == OpcUaMessageType::OpenSecureChannel {
                        s.security_mode = msg.security_mode;
                    }
                    if msg.timestamp_us < self.earliest_activity_us {
                        self.earliest_activity_us = msg.timestamp_us;
                    }
                }
                return;
            }
        }

        // Single-pass: find matching, first empty, and oldest simultaneously.
        let mut matched: Option<usize> = None;
        let mut first_empty: Option<usize> = None;
        let mut oldest: Option<(usize, u64)> = None;

        for (i, s) in self.sessions.iter().enumerate() {
            if s.active {
                if s.channel_id == msg.channel_id {
                    matched = Some(i);
                    break;
                }
                match oldest {
                    Some((_, ts)) if s.last_activity_us >= ts => {}
                    _ => oldest = Some((i, s.last_activity_us)),
                }
            } else if first_empty.is_none() {
                first_empty = Some(i);
            }
        }

        if let Some(mi) = matched {
            if is_close {
                self.sessions[mi].active = false;
                self.active_session_count = self.active_session_count.saturating_sub(1);
                self.recompute_earliest();
            } else {
                self.sessions[mi].last_activity_us = msg.timestamp_us;
                if msg.msg_type == OpcUaMessageType::OpenSecureChannel {
                    self.sessions[mi].security_mode = msg.security_mode;
                }
                self.update_earliest(msg.timestamp_us);
            }
            return;
        }

        // Close on unknown channel — nothing to do.
        if is_close {
            return;
        }

        // Rate-limit new session creation to prevent session table flooding.
        if self.max_session_create_rate > 0
            && !self.session_create_bucket.try_consume(msg.timestamp_us)
        {
            return;
        }

        // Create new session in first empty slot, or evict oldest.
        // If both are None (no slots exist at all — impossible with
        // MAX_SESSIONS > 0), drop the message rather than index garbage.
        let Some(slot) = first_empty.or(oldest.map(|(i, _)| i)) else {
            return;
        };
        let evicting = self.sessions[slot].active;
        self.sessions[slot] = SessionState {
            channel_id: msg.channel_id,
            security_mode: msg.security_mode,
            last_sequence: msg.sequence_number,
            has_seen_message: true,
            last_activity_us: msg.timestamp_us,
            active: true,
        };
        if !evicting {
            self.active_session_count = self.active_session_count.saturating_add(1);
        }
        self.update_earliest(msg.timestamp_us);
    }

    /// Check for sequence number replay using wraparound-safe window comparison.
    ///
    /// Returns `(Option<bool>, Option<usize>)` where the second element is
    /// the session index found, reusable as a hint for `track_session`.
    ///
    /// `OpenSecureChannel` messages reset the sequence counter for the channel,
    /// matching the OPC UA spec which allows re-keying to restart the counter.
    fn check_replay(
        &mut self,
        channel_id: u32,
        seq: u32,
        msg_type: OpcUaMessageType,
    ) -> (Option<bool>, Option<usize>) {
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.active && s.channel_id == channel_id {
                // OpenSecureChannel resets the sequence counter (re-keying).
                if msg_type == OpcUaMessageType::OpenSecureChannel {
                    s.last_sequence = seq;
                    s.has_seen_message = true;
                    return (Some(false), Some(i));
                }
                if !s.has_seen_message {
                    s.last_sequence = seq;
                    s.has_seen_message = true;
                    return (Some(false), Some(i));
                }
                // Wraparound-safe replay detection:
                // diff = seq - last_sequence (wrapping). Valid forward progress
                // means diff is in 1..=SEQUENCE_WINDOW. Anything else (0 for
                // duplicate, or too far ahead/behind) is treated as a replay.
                let diff = seq.wrapping_sub(s.last_sequence);
                if diff == 0 || diff > SEQUENCE_WINDOW {
                    return (Some(true), Some(i));
                }
                s.last_sequence = seq;
                return (Some(false), Some(i));
            }
        }
        (None, None)
    }

    /// Find the longest-prefix matching rule. Rules are pre-sorted by
    /// `pattern_len` descending, so the first match is the longest.
    ///
    /// Always iterates every rule to avoid timing side-channels that could
    /// leak which rule matched.
    fn find_matching_rule(&self, endpoint: &[u8]) -> Option<usize> {
        let mut result: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if !self.rules[i].active {
                continue;
            }
            let pat = &self.rules[i].pattern[..self.rules[i].pattern_len as usize];
            if endpoint.len() >= pat.len()
                && ascii_eq_ignore_case(&endpoint[..pat.len()], pat)
                && result.is_none()
            {
                result = Some(i);
            }
        }
        result
    }

    fn rate_check(&mut self, channel_id: u32, max_rate: u16, now_us: u64) -> bool {
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;

        // Fast path: temporal locality check.
        if self.last_rate_idx < MAX_RATE_BUCKETS {
            let b = &mut self.rate_buckets[self.last_rate_idx];
            if b.active && b.key == channel_id {
                b.last_used = now_tick;
                return b.try_consume(now_us);
            }
        }

        // Single-pass: find matching bucket, first free slot, and LRU victim.
        let mut first_free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_age: u32 = 0;
        for (i, b) in self.rate_buckets.iter_mut().enumerate() {
            if b.active {
                if b.key == channel_id {
                    b.last_used = now_tick;
                    self.last_rate_idx = i;
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

        // Allocate a new bucket in the first free slot, or evict LRU.
        let slot = first_free.unwrap_or(lru_idx);
        self.rate_buckets[slot] = RateBucket {
            key: channel_id,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
            last_used: now_tick,
        };
        self.last_rate_idx = slot;
        true
    }

    /// Recompute `earliest_activity_us` from all active sessions.
    fn recompute_earliest(&mut self) {
        let mut earliest = u64::MAX;
        for s in &self.sessions {
            if s.active && s.last_activity_us < earliest {
                earliest = s.last_activity_us;
            }
        }
        self.earliest_activity_us = earliest;
    }

    /// Update `earliest_activity_us` if the new timestamp is earlier.
    fn update_earliest(&mut self, ts: u64) {
        if ts < self.earliest_activity_us {
            self.earliest_activity_us = ts;
        }
    }

    /// Reset all monitor state — rules, sessions, rate buckets, and statistics.
    /// Settings (`default_action`, `global_min_security`, `global_read_only`,
    /// `session_timeout_us`, `enforce_security_mode`) are preserved.
    pub fn reset(&mut self) {
        let default_action = self.default_action;
        let global_min_security = self.global_min_security;
        let global_read_only = self.global_read_only;
        let session_timeout_us = self.session_timeout_us;
        let enforce_security_mode = self.enforce_security_mode;
        let enforce_replay = self.enforce_replay;
        let max_message_size = self.max_message_size;
        let max_session_create_rate = self.max_session_create_rate;
        *self = Self::new();
        self.default_action = default_action;
        self.global_min_security = global_min_security;
        self.global_read_only = global_read_only;
        self.session_timeout_us = session_timeout_us;
        self.enforce_security_mode = enforce_security_mode;
        self.enforce_replay = enforce_replay;
        self.max_message_size = max_message_size;
        self.set_max_session_create_rate(max_session_create_rate);
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let la = if a[i].is_ascii_uppercase() {
            a[i] + 32
        } else {
            a[i]
        };
        let lb = if b[i].is_ascii_uppercase() {
            b[i] + 32
        } else {
            b[i]
        };
        if la != lb {
            return false;
        }
    }
    true
}

impl Default for OpcUaMonitor {
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

    #[allow(clippy::field_reassign_with_default)]
    fn make_msg(
        msg_type: OpcUaMessageType,
        security: OpcUaSecurityMode,
        channel: u32,
        seq: u32,
        endpoint: &[u8],
        ts_us: u64,
    ) -> OpcUaMessage {
        let mut m = OpcUaMessage::default();
        m.msg_type = msg_type;
        m.security_mode = security;
        m.channel_id = channel;
        m.sequence_number = seq;
        if !endpoint.is_empty() {
            m.endpoint[..endpoint.len()].copy_from_slice(endpoint);
            m.endpoint_len = endpoint.len() as u8;
        }
        m.timestamp_us = ts_us;
        m
    }

    #[test]
    fn default_allow() {
        let mut mon = OpcUaMonitor::new();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            1000,
        );
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn deny_default() {
        let mut mon = OpcUaMonitor::new_deny_default();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn allow_overrides_deny() {
        let mut mon = OpcUaMonitor::new_deny_default();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn enforce_security_mode_on_by_default() {
        // enforce_security_mode defaults to true — violations block traffic.
        let mut mon = OpcUaMonitor::new();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::None,
            1,
            1,
            b"",
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn security_mode_enforcement_alert_only_when_disabled() {
        // Explicitly disable enforcement — violations alert but allow.
        let mut mon = OpcUaMonitor::new();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);
        mon.set_enforce_security_mode(false);

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::None,
            1,
            1,
            b"",
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn security_mode_enforcement_blocks_when_enforced() {
        let mut mon = OpcUaMonitor::new();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);
        mon.set_enforce_security_mode(true);

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::None,
            1,
            1,
            b"",
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn security_mode_enforcement_allows_compliant() {
        let mut mon = OpcUaMonitor::new();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);
        mon.set_enforce_security_mode(true);

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn global_read_only_blocks_write() {
        let mut mon = OpcUaMonitor::new();
        mon.set_read_only(true);

        let read = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            1000,
        );
        assert!(mon.inspect(&read).allowed);

        let write = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            2,
            b"",
            2000,
        );
        assert!(!mon.inspect(&write).allowed);

        let call = make_msg(
            OpcUaMessageType::Call,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            3,
            b"",
            3000,
        );
        assert!(!mon.inspect(&call).allowed);
    }

    #[test]
    fn read_only_permissions() {
        let mut mon = OpcUaMonitor::new();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::READ_ONLY,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();

        let read = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        assert!(mon.inspect(&read).allowed);

        let write = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            2,
            b"opc.tcp://plc1:4840",
            2000,
        );
        assert!(!mon.inspect(&write).allowed);
    }

    // -----------------------------------------------------------------------
    // Sequence number replay detection
    // -----------------------------------------------------------------------

    #[test]
    fn replay_detected() {
        let mut mon = OpcUaMonitor::new();
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            1000,
        );
        let r = mon.inspect(&msg1);
        assert_eq!(r.alert_count, 0);

        let msg2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            2000,
        );
        let r = mon.inspect(&msg2);
        assert!(r.alert_count > 0); // Duplicate seq detected
    }

    #[test]
    fn sequence_forward_progress_ok() {
        let mut mon = OpcUaMonitor::new();
        for seq in 1..=5 {
            let msg = make_msg(
                OpcUaMessageType::Read,
                OpcUaSecurityMode::SignAndEncrypt,
                1,
                seq,
                b"",
                seq as u64 * 1000,
            );
            let r = mon.inspect(&msg);
            assert_eq!(r.alert_count, 0, "seq {seq} should be clean");
        }
    }

    #[test]
    fn sequence_wraparound_accepted() {
        let mut mon = OpcUaMonitor::new();
        // Establish session at near-max sequence.
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            u32::MAX - 2,
            b"",
            1000,
        );
        assert_eq!(mon.inspect(&msg1).alert_count, 0);

        // Next sequence wraps around.
        let msg2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            u32::MAX - 1,
            b"",
            2000,
        );
        assert_eq!(mon.inspect(&msg2).alert_count, 0);

        let msg3 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            u32::MAX,
            b"",
            3000,
        );
        assert_eq!(mon.inspect(&msg3).alert_count, 0);

        // Wrap to 1 — should be accepted (forward progress).
        let msg4 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            4000,
        );
        assert_eq!(mon.inspect(&msg4).alert_count, 0);
    }

    #[test]
    fn sequence_far_backward_rejected() {
        let mut mon = OpcUaMonitor::new();
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            50000,
            b"",
            1000,
        );
        assert_eq!(mon.inspect(&msg1).alert_count, 0);

        // Sequence 100 is far behind 50000 — replay.
        let msg2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            100,
            b"",
            2000,
        );
        assert!(mon.inspect(&msg2).alert_count > 0);
    }

    #[test]
    fn open_secure_channel_resets_sequence() {
        let mut mon = OpcUaMonitor::new();
        // Establish at seq 100.
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            100,
            b"",
            1000,
        );
        let _ = mon.inspect(&msg1);

        // Re-key resets counter.
        let msg2 = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            2000,
        );
        assert_eq!(mon.inspect(&msg2).alert_count, 0);

        // Seq 2 after reset — ok.
        let msg3 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            2,
            b"",
            3000,
        );
        assert_eq!(mon.inspect(&msg3).alert_count, 0);
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    #[test]
    fn session_tracking() {
        let mut mon = OpcUaMonitor::new();
        let msg = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            1,
            b"",
            1000,
        );
        let _ = mon.inspect(&msg);
        assert_eq!(mon.active_sessions(), 1);

        let close = make_msg(
            OpcUaMessageType::CloseSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            2,
            b"",
            2000,
        );
        let _ = mon.inspect(&close);
        assert_eq!(mon.active_sessions(), 0);
    }

    #[test]
    fn session_expiry() {
        let mut mon = OpcUaMonitor::new();
        mon.set_session_timeout(5_000);

        let msg = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            1,
            b"",
            1000,
        );
        let _ = mon.inspect(&msg);
        assert_eq!(mon.active_sessions(), 1);

        // Not expired yet.
        mon.expire_sessions(4000);
        assert_eq!(mon.active_sessions(), 1);

        // Expired.
        mon.expire_sessions(1_000_000);
        assert_eq!(mon.active_sessions(), 0);
    }

    #[test]
    fn session_expiry_skips_when_none_near_timeout() {
        let mut mon = OpcUaMonitor::new();
        mon.set_session_timeout(1_000_000);

        let msg = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            1,
            b"",
            500_000,
        );
        let _ = mon.inspect(&msg);

        // Well within timeout — fast path should skip scan.
        mon.expire_sessions(600_000);
        assert_eq!(mon.active_sessions(), 1);
    }

    // -----------------------------------------------------------------------
    // Endpoint rule sorting
    // -----------------------------------------------------------------------

    #[test]
    fn longest_prefix_match_with_sorted_rules() {
        let mut mon = OpcUaMonitor::new_deny_default();
        // Add short rule first, long rule second — should still match longest.
        mon.add_rule(
            b"opc.tcp://",
            EndpointAction::Allow,
            MessagePermissions::READ_ONLY,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();

        // Should match the longer "opc.tcp://plc1" rule (ALL permissions).
        let write = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        assert!(mon.inspect(&write).allowed);

        // "opc.tcp://other" matches shorter rule with READ_ONLY.
        let write2 = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt,
            2,
            1,
            b"opc.tcp://other:4840",
            2000,
        );
        assert!(!mon.inspect(&write2).allowed);
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiting() {
        let mut mon = OpcUaMonitor::new();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            3,
        )
        .unwrap();

        for i in 0..3 {
            let msg = make_msg(
                OpcUaMessageType::Read,
                OpcUaSecurityMode::SignAndEncrypt,
                1,
                i + 1,
                b"opc.tcp://plc1:4840",
                (i as u64 + 1) * 100,
            );
            assert!(mon.inspect(&msg).allowed, "req {i} should pass");
        }

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            4,
            b"opc.tcp://plc1:4840",
            400,
        );
        assert!(!mon.inspect(&msg).allowed);
    }

    // -----------------------------------------------------------------------
    // Deny-default blocks empty endpoint
    // -----------------------------------------------------------------------

    #[test]
    fn deny_default_blocks_empty_endpoint() {
        let mut mon = OpcUaMonitor::new_deny_default();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            1000,
        );
        assert!(!mon.inspect(&msg).allowed);
    }

    // -----------------------------------------------------------------------
    // Reset preserves settings
    // -----------------------------------------------------------------------

    #[test]
    fn reset_preserves_all_settings() {
        let mut mon = OpcUaMonitor::new_deny_default();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);
        mon.set_read_only(true);
        mon.set_session_timeout(42);
        mon.set_enforce_security_mode(true);

        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        let _ = mon.inspect(&msg);

        mon.reset();

        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.active_sessions(), 0);
        // Rules cleared — deny-default should block.
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            2000,
        );
        assert!(!mon.inspect(&msg).allowed);
    }

    // -----------------------------------------------------------------------
    // Alert counting consistency
    // -----------------------------------------------------------------------

    #[test]
    fn alert_counting_consistent() {
        let mut mon = OpcUaMonitor::new_deny_default();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        let r = mon.inspect(&msg);
        assert_eq!(r.alert_count as u64, mon.total_alerts());
    }

    // -----------------------------------------------------------------------
    // Endpoint overflow
    // -----------------------------------------------------------------------

    #[test]
    fn endpoint_len_overflow_rejected() {
        let mut mon = OpcUaMonitor::new();
        let msg = OpcUaMessage {
            endpoint_len: 255,
            msg_type: OpcUaMessageType::Read,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            channel_id: 1,
            sequence_number: 1,
            timestamp_us: 1000,
            ..OpcUaMessage::default()
        };
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    // -----------------------------------------------------------------------
    // Resource exhaustion
    // -----------------------------------------------------------------------

    #[test]
    fn add_rule_when_full() {
        let mut mon = OpcUaMonitor::new();
        for i in 0..16u8 {
            let pat = [b'a' + i];
            mon.add_rule(
                &pat,
                EndpointAction::Allow,
                MessagePermissions::ALL,
                OpcUaSecurityMode::None,
                0,
            )
            .unwrap();
        }
        assert!(mon
            .add_rule(
                b"z",
                EndpointAction::Allow,
                MessagePermissions::ALL,
                OpcUaSecurityMode::None,
                0,
            )
            .is_err());
    }

    #[test]
    fn empty_pattern_rejected() {
        let mut mon = OpcUaMonitor::new();
        assert!(mon
            .add_rule(
                b"",
                EndpointAction::Allow,
                MessagePermissions::ALL,
                OpcUaSecurityMode::None,
                0,
            )
            .is_err());
    }

    #[test]
    fn default_constructor() {
        let mon = OpcUaMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
    }

    #[test]
    fn replay_blocks_by_default() {
        let mut mon = OpcUaMonitor::new();
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            1000,
        );
        let _ = mon.inspect(&msg1);
        let msg2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            2000,
        );
        let r = mon.inspect(&msg2);
        assert!(!r.allowed, "replay should be blocked by default");
    }

    #[test]
    fn replay_alert_only_when_enforce_disabled() {
        let mut mon = OpcUaMonitor::new();
        mon.set_enforce_replay(false);
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            1000,
        );
        let _ = mon.inspect(&msg1);
        let msg2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            2000,
        );
        let r = mon.inspect(&msg2);
        assert!(
            r.allowed,
            "replay should be allowed when enforcement disabled"
        );
        assert!(r.alert_count > 0, "but should still generate alert");
    }

    #[test]
    fn case_insensitive_endpoint_matching() {
        let mut mon = OpcUaMonitor::new_deny_default();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();
        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"OPC.TCP://PLC1:4840",
            1000,
        );
        assert!(mon.inspect(&msg).allowed, "should match case-insensitively");
    }

    #[test]
    fn message_size_enforcement() {
        let mut mon = OpcUaMonitor::new();
        mon.set_max_message_size(1000);
        let msg = OpcUaMessage {
            msg_type: OpcUaMessageType::Read,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            channel_id: 1,
            sequence_number: 1,
            message_size: 2000,
            timestamp_us: 1000,
            ..OpcUaMessage::default()
        };
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn message_size_zero_means_no_limit() {
        let mut mon = OpcUaMonitor::new();
        // max_message_size defaults to 0 = no limit
        let msg = OpcUaMessage {
            msg_type: OpcUaMessageType::Read,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            channel_id: 1,
            sequence_number: 1,
            message_size: 999_999,
            timestamp_us: 1000,
            ..OpcUaMessage::default()
        };
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: endpoint length must be bounds-checked (H4).
    // -----------------------------------------------------------------------
    #[test]
    fn oversized_endpoint_len_does_not_panic() {
        let mut mon = OpcUaMonitor::new();
        let msg = OpcUaMessage {
            msg_type: OpcUaMessageType::Read,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            channel_id: 1,
            sequence_number: 1,
            timestamp_us: 1000,
            endpoint_len: u8::MAX, // Larger than the backing array.
            ..OpcUaMessage::default()
        };
        // The sole guarantee we need is "no panic". Whether the frame is
        // allowed depends on how the clamped (all-zero) endpoint matches
        // against configured rules, which is irrelevant here.
        let _ = mon.inspect(&msg);
    }

    // -----------------------------------------------------------------------
    // Regression: session eviction with many distinct channels (C3).
    // -----------------------------------------------------------------------
    #[test]
    fn session_eviction_many_channels() {
        let mut mon = OpcUaMonitor::new();
        for i in 1u32..=100 {
            let msg = OpcUaMessage {
                msg_type: OpcUaMessageType::Read,
                security_mode: OpcUaSecurityMode::SignAndEncrypt,
                channel_id: i,
                sequence_number: 1,
                timestamp_us: i as u64 * 1000,
                ..OpcUaMessage::default()
            };
            let r = mon.inspect(&msg);
            assert!(r.allowed);
        }
        assert!(mon.active_sessions() <= 16);
    }

    // -----------------------------------------------------------------------
    // Session creation rate limiting (V5).
    // -----------------------------------------------------------------------
    #[test]
    fn session_flood_rate_limited() {
        let mut mon = OpcUaMonitor::new();
        mon.set_max_session_create_rate(2); // 2 new sessions/sec

        // First two sessions should be created
        for ch in 1..=2u32 {
            let msg = OpcUaMessage {
                channel_id: ch,
                msg_type: OpcUaMessageType::OpenSecureChannel,
                security_mode: OpcUaSecurityMode::SignAndEncrypt,
                sequence_number: 1,
                timestamp_us: 1_000_000,
                ..OpcUaMessage::default()
            };
            let _ = mon.inspect(&msg);
        }
        assert_eq!(mon.active_sessions(), 2);

        // Third session within same second should be rate-limited
        let msg = OpcUaMessage {
            channel_id: 100,
            msg_type: OpcUaMessageType::OpenSecureChannel,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            sequence_number: 1,
            timestamp_us: 1_000_000,
            ..OpcUaMessage::default()
        };
        let _ = mon.inspect(&msg);
        // Session should not be created (still 2)
        assert_eq!(mon.active_sessions(), 2);

        // After enough time, bucket refills
        let msg = OpcUaMessage {
            channel_id: 100,
            msg_type: OpcUaMessageType::OpenSecureChannel,
            security_mode: OpcUaSecurityMode::SignAndEncrypt,
            sequence_number: 1,
            timestamp_us: 2_500_000,
            ..OpcUaMessage::default()
        };
        let _ = mon.inspect(&msg);
        assert_eq!(mon.active_sessions(), 3);
    }
}
