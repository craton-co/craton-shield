#![no_std]
#![deny(missing_docs)]

//! OPC UA security monitor for industrial control systems.
//!
//! Validates SecureChannel and Session traffic against IEC 62541 (OPC UA)
//! parts 1-8.
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

/// Width of the per-channel sliding replay-detection bitmap.
///
/// The window covers the 64 sequence numbers immediately below
/// `last_seq` (inclusive). A forward jump greater than this width is
/// considered suspicious and rejected without advancing state — see
/// [`OpcUaMonitor::window_accept`].
const REPLAY_WINDOW_WIDTH: u32 = 64;

// ---------------------------------------------------------------------------
// Endpoint rule
// ---------------------------------------------------------------------------

/// Action for an endpoint match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAction {
    /// Allow traffic that matches this rule.
    Allow,
    /// Block traffic that matches this rule.
    Block,
}

/// Index into the monitor's endpoint-rule table.
///
/// Uses `usize` to match Rust's indexing convention. Internal-only; we
/// re-export `Option<RuleIndex>` semantically via the public `inspect()`
/// API rather than this alias.
type RuleIndex = usize;

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
///
/// Carries the per-channel sliding-window replay state, the rule
/// (and security mode) cached from the channel's `OpenSecureChannel`,
/// and the LRU bookkeeping that backs cache eviction.
#[derive(Debug, Clone, Copy)]
struct SessionState {
    /// Channel identifier — primary lookup key.
    channel_id: u32,
    /// Highest sequence number accepted on this channel. The replay
    /// bitmap tracks the 64 sequence numbers immediately below it.
    last_seq: u32,
    /// Sliding-window replay bitmap. Bit `n` (LSB-indexed) represents
    /// whether `last_seq - n` has been seen. Bit 0 is therefore always
    /// set once `has_seen_message` is true.
    window_bitmap: u64,
    /// Whether at least one message has been seen (for first-frame
    /// initialisation, regardless of sequence value).
    has_seen_message: bool,
    /// Security mode negotiated for this channel via `OpenSecureChannel`.
    security_mode: OpcUaSecurityMode,
    /// Cached rule index from the channel's `OpenSecureChannel` (if any).
    /// `None` means no endpoint rule was matched at OSC time, so in-band
    /// frames fall through to `default_action`.
    cached_rule: Option<u8>,
    /// Last activity timestamp (microseconds) for expiry.
    last_activity_us: u64,
    /// Last access timestamp (microseconds) for LRU eviction of the
    /// session-rule cache. Updated on every match.
    last_seen_us: u64,
    /// Slot in-use flag.
    active: bool,
}

impl SessionState {
    const fn empty() -> Self {
        Self {
            channel_id: 0,
            last_seq: 0,
            window_bitmap: 0,
            has_seen_message: false,
            security_mode: OpcUaSecurityMode::None,
            cached_rule: None,
            last_activity_us: 0,
            last_seen_us: 0,
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
/// Approximate stack usage: ~2.5 KB worst case.
/// - `rules`: 16 × ~74 bytes ≈ 1.2 KB
/// - `sessions`: 16 × ~40 bytes ≈ 0.6 KB (sliding replay bitmap + session-rule cache)
/// - `rate_buckets`: 16 × 28 bytes ≈ 0.5 KB
/// - Scalars and session-create bucket: ~80 bytes
pub struct OpcUaMonitor {
    /// Rules sorted by `pattern_len` descending for fastest longest-prefix match.
    rules: [EndpointRule; MAX_ENDPOINT_RULES],
    rule_count: u8,
    sessions: [SessionState; MAX_SESSIONS],
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Global minimum security mode (applied to all channels).
    global_min_security: OpcUaSecurityMode,
    /// When `true`, only read-like and session-lifecycle messages are
    /// allowed globally; Write, Call, and Unknown are blocked. Implements
    /// allow-list semantics — see `is_read_only_safe`.
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

    /// Set global read-only mode.
    ///
    /// When enabled, only read-like operations (`Read`, `Browse`,
    /// `CreateSubscription`, `Publish`) and session-lifecycle messages
    /// (`Hello`, `Acknowledge`, the OSC / session open / close flow) are
    /// allowed. Everything else — including `Write`, `Call`, and the
    /// `Unknown` type — is blocked with a `WriteProtection` alert.
    ///
    /// Read-only mode is an allow-list, not a deny-list: this guarantees
    /// that any future write-capable message type cannot slip through
    /// without being explicitly added to `is_read_only_safe`.
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
    ///
    /// Evaluates, in order:
    /// 1. Framing sanity (`endpoint_len` overflow, message size).
    /// 2. Global security-mode minimum.
    /// 3. Global read-only allowlist (Read / Browse / lifecycle).
    /// 4. Rule resolution from frame endpoint or session-cached rule.
    /// 5. Endpoint allow/block action.
    /// 6. Per-rule security-mode minimum (effective = min of frame and
    ///    session's cached mode, so a forged per-frame claim cannot
    ///    escape a weakly-negotiated session).
    /// 7. Per-rule message-type permissions.
    /// 8. Per-rule rate limit.
    /// 9. Replay detection (sliding 64-counter bitmap per channel).
    /// 10. Session tracking (create / update / close).
    ///
    /// Permissions and rate-limit are **always** evaluated against the
    /// matched rule even when security is compliant. The earlier control
    /// flow that nested them inside the security-violation branch
    /// silently bypassed both checks on compliant traffic.
    #[allow(clippy::too_many_lines)]
    pub fn inspect(&mut self, msg: &OpcUaMessage) -> OpcUaInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_OPCUA);

        // -------------------------------------------------------------------
        // 1. Framing sanity.
        // -------------------------------------------------------------------
        if msg.endpoint_len_overflow() {
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
        if self.max_message_size > 0 && msg.message_size > self.max_message_size {
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

        // -------------------------------------------------------------------
        // 2. Global security-mode enforcement.
        //
        // The global alert always fires when the frame's mode is below
        // the global minimum. Under enforce mode we additionally set
        // `allowed = false`; we do NOT early-return so permissions,
        // rate-limit, and replay still run for telemetry consistency.
        // -------------------------------------------------------------------
        let mut sec_alerted = false;
        if (msg.security_mode as u8) < (self.global_min_security as u8) {
            let severity = if self.enforce_security_mode {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };
            result.push_alert_with_code(
                severity,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::SecurityModeViolation,
            );
            sec_alerted = true;
            if self.enforce_security_mode {
                result.allowed = false;
            }
        }

        // -------------------------------------------------------------------
        // 3. Global read-only allowlist.
        //
        // Only read-like operations (Read, Browse, CreateSubscription,
        // Publish) and session-lifecycle messages (Hello, Acknowledge,
        // OSC / CSC / session open / activate / close) pass through.
        // Everything else (Write, Call, Unknown, future write-capable
        // variants) is blocked.
        // -------------------------------------------------------------------
        if self.global_read_only && !is_read_only_safe(msg.msg_type) {
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

        // -------------------------------------------------------------------
        // 4. Rule resolution.
        //
        // Frame endpoint wins when present; otherwise fall back to the
        // rule cached on the session at OpenSecureChannel time. This is
        // how in-band Writes / Calls inherit READ_ONLY permissions and
        // rate-limit from the channel rule even though the frame itself
        // carries no endpoint.
        // -------------------------------------------------------------------
        let endpoint_len = msg.valid_endpoint_len();
        let (matched, has_endpoint) = if endpoint_len > 0 {
            (self.find_matching_rule(msg.endpoint()), true)
        } else {
            (self.session_cached_rule(msg.channel_id), false)
        };

        // Note: caching the rule onto the session is deferred until
        // after `track_session` runs at the end of `inspect`, so the
        // session slot is guaranteed to exist before we write to it.

        // -------------------------------------------------------------------
        // 5. Endpoint allow/block.
        // -------------------------------------------------------------------
        let action = match matched {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };
        if action == EndpointAction::Block {
            // No matched rule + deny-default produces a hard block;
            // matched-block also blocks. Either way emit an EndpointBlocked
            // and stop further policy evaluation.
            result.push_alert_blocking(
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

        // -------------------------------------------------------------------
        // 6/7/8. Per-rule policy: security mode, permissions, rate limit.
        //
        // These run unconditionally when a rule matched, regardless of
        // whether the security mode is compliant. The previous control
        // flow accidentally nested permissions + rate-limit inside the
        // security-violation branch, silently bypassing them on
        // compliant traffic.
        // -------------------------------------------------------------------
        if let Some(idx) = matched {
            let rule = self.rules[idx];

            // 6. Effective security mode = strongest of (a) frame's
            //    per-message claim and (b) session's cached mode (the
            //    value negotiated at OSC time). Use the minimum so a
            //    forged per-frame claim cannot escape a weakly
            //    negotiated channel.
            let session_mode = self
                .session_security_mode(msg.channel_id)
                .unwrap_or(msg.security_mode);
            let effective = if (session_mode as u8) < (msg.security_mode as u8) {
                session_mode
            } else {
                msg.security_mode
            };
            if (effective as u8) < (rule.min_security_mode as u8) {
                if !sec_alerted {
                    let severity = if self.enforce_security_mode {
                        AlertSeverity::High
                    } else {
                        AlertSeverity::Medium
                    };
                    result.push_alert_with_code(
                        severity,
                        SOURCE_OPCUA,
                        msg.channel_id,
                        msg.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::SecurityModeViolation,
                    );
                }
                if self.enforce_security_mode {
                    result.allowed = false;
                }
            }

            // 7. Message-type permissions.
            //
            // Permissions govern *data-plane* operations only:
            // Read, Write, Call, Browse, CreateSubscription, Publish.
            // Session-lifecycle messages (Hello, Acknowledge,
            // OpenSecureChannel, CloseSecureChannel, CreateSession,
            // ActivateSession, CloseSession) bypass the permission
            // mask — they are required to negotiate the channel that
            // any data-plane permission decision is anchored on.
            //
            // Deny is High-severity for Write / Call (write-protection
            // class); other denied operations are Medium.
            if is_data_plane(msg.msg_type) && !rule.permissions.is_allowed(msg.msg_type) {
                let is_write_class = matches!(
                    msg.msg_type,
                    OpcUaMessageType::Write | OpcUaMessageType::Call
                );
                let severity = if is_write_class {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                };
                result.push_alert_blocking(
                    severity,
                    SOURCE_OPCUA,
                    msg.channel_id,
                    msg.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::MessageTypeBlocked,
                );
            }

            // 8. Rate limit.
            if rule.max_rate_per_sec > 0
                && !self.rate_check(msg.channel_id, rule.max_rate_per_sec, msg.timestamp_us)
            {
                result.push_alert_blocking(
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

        // -------------------------------------------------------------------
        // 9. Replay detection.
        //
        // Always run replay + session bookkeeping, even when policy
        // already rejected the frame above: the bookkeeping has to stay
        // in sync with what actually arrived on the wire so a future
        // legitimate frame is not falsely flagged.
        //
        // Severity follows `enforce_replay`: High denies (per the
        // InspectResult auto-deny policy), Medium is alert-only. We
        // also explicitly set `allowed = false` on enforce mode so the
        // deny is unambiguous regardless of severity-mapped behaviour.
        // -------------------------------------------------------------------
        let (replay, session_hint, downgrade) = self.check_replay_and_downgrade(msg);
        if downgrade {
            // Forged OpenSecureChannel attempting to downgrade an
            // already-negotiated channel to a weaker security mode.
            result.push_alert_blocking(
                AlertSeverity::High,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::SecurityModeViolation,
            );
        }
        if replay {
            let severity = if self.enforce_replay {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };
            result.push_alert_with_code(
                severity,
                SOURCE_OPCUA,
                msg.channel_id,
                msg.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::ReplayDetected,
            );
            if self.enforce_replay {
                result.allowed = false;
            }
        }

        // 10. Session tracking. Skip mode-update when this frame was
        //     rejected as an OSC downgrade, so the session's cached
        //     mode is not silently weakened by a rejected re-key.
        self.track_session(msg, session_hint, downgrade);

        // Cache the matched rule onto the (now-guaranteed-to-exist)
        // session when this is an OpenSecureChannel that carried an
        // endpoint. Skip when this OSC was rejected as a downgrade —
        // we must not let a forged re-key replace the existing
        // cached rule on the session.
        if msg.msg_type == OpcUaMessageType::OpenSecureChannel && has_endpoint && !downgrade {
            self.cache_session_rule(msg.channel_id, matched, msg.security_mode);
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
    // Internal: session-rule cache
    // -----------------------------------------------------------------------

    /// Look up the index in `self.sessions` whose `channel_id` matches.
    fn find_session_slot(&self, channel_id: u32) -> Option<usize> {
        for (i, s) in self.sessions.iter().enumerate() {
            if s.active && s.channel_id == channel_id {
                return Some(i);
            }
        }
        None
    }

    /// Return the cached endpoint-rule index for this channel's session,
    /// if any.
    ///
    /// Used to inherit policy onto in-band frames that carry no endpoint
    /// (e.g. an in-band `Write` after the `OpenSecureChannel` that did
    /// carry the endpoint).
    fn session_cached_rule(&self, session_id: u32) -> Option<RuleIndex> {
        let slot = self.find_session_slot(session_id)?;
        self.sessions[slot].cached_rule.map(|v| v as RuleIndex)
    }

    /// Cache the matched rule index (and the security mode negotiated
    /// at OSC time) on the channel's session.
    ///
    /// LRU eviction (by `last_seen_us`) is handled by `track_session`
    /// when the table is full and a new entry must be created — that
    /// helper already updates `last_seen_us` for the current frame
    /// before this is called, so we only need to write the cached
    /// rule + mode here.
    fn cache_session_rule(
        &mut self,
        session_id: u32,
        rule_idx: Option<RuleIndex>,
        mode: OpcUaSecurityMode,
    ) {
        if let Some(slot) = self.find_session_slot(session_id) {
            self.sessions[slot].cached_rule = rule_idx.map(|i| i as u8);
            self.sessions[slot].security_mode = mode;
        }
        // If no slot exists (e.g. session-create rate limited), nothing
        // to cache — the frame's policy decision has already been made
        // and a future frame will recreate the session if appropriate.
    }

    /// Return the security mode negotiated for this channel (the cached
    /// `OpenSecureChannel` mode), if the session is currently tracked.
    fn session_security_mode(&self, session_id: u32) -> Option<OpcUaSecurityMode> {
        let slot = self.find_session_slot(session_id)?;
        Some(self.sessions[slot].security_mode)
    }

    // -----------------------------------------------------------------------
    // Internal: session tracking
    // -----------------------------------------------------------------------

    /// Single-pass session tracking: handles close, update, creation, and
    /// eviction in one scan.
    ///
    /// `skip_mode_update` is set when this frame is an `OpenSecureChannel`
    /// that was rejected as a downgrade; the session's cached security
    /// mode must NOT be silently weakened by a rejected re-key.
    fn track_session(
        &mut self,
        msg: &OpcUaMessage,
        session_hint: Option<usize>,
        skip_mode_update: bool,
    ) {
        if msg.channel_id == 0 {
            return;
        }

        let is_close = msg.msg_type == OpcUaMessageType::CloseSession
            || msg.msg_type == OpcUaMessageType::CloseSecureChannel;

        // Fast path: reuse hint from the replay check.
        if let Some(hi) = session_hint {
            let s = &mut self.sessions[hi];
            if s.active && s.channel_id == msg.channel_id {
                if is_close {
                    s.active = false;
                    self.active_session_count = self.active_session_count.saturating_sub(1);
                    self.recompute_earliest();
                } else {
                    s.last_activity_us = msg.timestamp_us;
                    s.last_seen_us = msg.timestamp_us;
                    if msg.msg_type == OpcUaMessageType::OpenSecureChannel && !skip_mode_update {
                        s.security_mode = msg.security_mode;
                    }
                    if msg.timestamp_us < self.earliest_activity_us {
                        self.earliest_activity_us = msg.timestamp_us;
                    }
                }
                return;
            }
        }

        // Slow path: scan for matching slot, first empty slot, and LRU victim.
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
                    Some((_, ts)) if s.last_seen_us >= ts => {}
                    _ => oldest = Some((i, s.last_seen_us)),
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
                self.sessions[mi].last_seen_us = msg.timestamp_us;
                if msg.msg_type == OpcUaMessageType::OpenSecureChannel && !skip_mode_update {
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

        // Create a new session in the first empty slot, or evict the LRU
        // entry. If both are None (impossible with MAX_SESSIONS > 0),
        // drop the message rather than index out of bounds.
        let Some(slot) = first_empty.or(oldest.map(|(i, _)| i)) else {
            return;
        };
        let evicting = self.sessions[slot].active;
        self.sessions[slot] = SessionState {
            channel_id: msg.channel_id,
            last_seq: msg.sequence_number,
            window_bitmap: 1, // bit 0 = last_seq itself has been seen
            has_seen_message: true,
            security_mode: msg.security_mode,
            cached_rule: None,
            last_activity_us: msg.timestamp_us,
            last_seen_us: msg.timestamp_us,
            active: true,
        };
        if !evicting {
            self.active_session_count = self.active_session_count.saturating_add(1);
        }
        self.update_earliest(msg.timestamp_us);
    }

    // -----------------------------------------------------------------------
    // Internal: replay window
    // -----------------------------------------------------------------------

    /// Run replay detection + downgrade check for `msg`.
    ///
    /// Returns `(replay, session_hint, downgrade)`:
    /// - `replay`: `true` when the frame's sequence is a replay (duplicate
    ///   within the 64-counter sliding window, or out of window entirely).
    /// - `session_hint`: index in `self.sessions` of the matched session
    ///   so `track_session` can fast-path back to it.
    /// - `downgrade`: `true` when this is an `OpenSecureChannel` whose
    ///   `security_mode` is strictly weaker than the session's already
    ///   negotiated mode.
    fn check_replay_and_downgrade(&mut self, msg: &OpcUaMessage) -> (bool, Option<usize>, bool) {
        let seq = msg.sequence_number;
        let msg_type = msg.msg_type;
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.active && s.channel_id == msg.channel_id {
                // OpenSecureChannel: detect downgrade BEFORE resetting
                // the sliding window. A downgrade is a forged re-key
                // attempting to weaken the channel's negotiated mode.
                if msg_type == OpcUaMessageType::OpenSecureChannel {
                    let downgrade = (msg.security_mode as u8) < (s.security_mode as u8);
                    if !downgrade {
                        // Legitimate re-key: reset the replay window.
                        s.last_seq = seq;
                        s.window_bitmap = 1;
                        s.has_seen_message = true;
                    }
                    // On downgrade, leave the replay state untouched so
                    // a subsequent legitimate frame still validates
                    // against the pre-downgrade sequence space.
                    return (false, Some(i), downgrade);
                }
                if !s.has_seen_message {
                    s.last_seq = seq;
                    s.window_bitmap = 1;
                    s.has_seen_message = true;
                    return (false, Some(i), false);
                }
                // Sliding 64-counter replay window.
                let replay = !Self::window_accept(&mut s.last_seq, &mut s.window_bitmap, seq);
                return (replay, Some(i), false);
            }
        }
        (false, None, false)
    }

    /// Sliding-window accept/reject for a single sequence number.
    ///
    /// `last_seq` is the highest accepted sequence; bit 0 of `bitmap`
    /// corresponds to `last_seq`, bit `n` to `last_seq - n` for
    /// `1 <= n <= 63`.
    ///
    /// Returns `true` if the frame is fresh and the window was updated;
    /// `false` if the frame is a duplicate (bit already set), exactly
    /// equal to `last_seq`, outside the 64-counter window, or a
    /// suspicious forward jump greater than the window width.
    ///
    /// A forward jump greater than 63 is intentionally rejected
    /// **without advancing state** — accepting a forged jump would
    /// otherwise lock out the next 64 legitimate frames as "behind
    /// the window".
    fn window_accept(last_seq: &mut u32, bitmap: &mut u64, seq: u32) -> bool {
        if seq == *last_seq {
            // Exact duplicate of the current head.
            return false;
        }
        // Wrapping diff. The side with the smaller value is the
        // intended direction (forward if ahead, backward otherwise).
        let forward = seq.wrapping_sub(*last_seq);
        let backward = last_seq.wrapping_sub(seq);
        if forward < backward {
            // Forward progress.
            if forward >= REPLAY_WINDOW_WIDTH {
                // Too far ahead — suspicious. Do not advance.
                return false;
            }
            *bitmap = (*bitmap << forward) | 1;
            *last_seq = seq;
            true
        } else if backward < REPLAY_WINDOW_WIDTH {
            // Backward within the 64-counter window — check whether
            // we already saw this exact sequence.
            let bit = 1u64 << backward;
            if (*bitmap & bit) != 0 {
                false // already seen — replay
            } else {
                *bitmap |= bit;
                true
            }
        } else {
            // Too far behind the window: stale or forged.
            false
        }
    }

    // -----------------------------------------------------------------------
    // Internal: rule matching
    // -----------------------------------------------------------------------

    /// Find the longest-prefix matching rule. Rules are pre-sorted by
    /// `pattern_len` descending, so the first match is the longest
    /// — early-return on the first hit.
    fn find_matching_rule(&self, endpoint: &[u8]) -> Option<RuleIndex> {
        for i in 0..self.rule_count as usize {
            if !self.rules[i].active {
                continue;
            }
            let pat = &self.rules[i].pattern[..self.rules[i].pattern_len as usize];
            if endpoint.len() >= pat.len() && endpoint[..pat.len()].eq_ignore_ascii_case(pat) {
                return Some(i);
            }
        }
        None
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

/// Returns `true` for data-plane operations subject to per-rule
/// `MessagePermissions` checks: Read, Write, Call, Browse,
/// CreateSubscription, Publish, and Unknown.
///
/// Session-lifecycle messages (Hello, Acknowledge, OSC, CSC,
/// CreateSession, ActivateSession, CloseSession) are not data-plane —
/// they negotiate the channel on which data-plane permissions are
/// anchored, and would otherwise be blocked by `READ_ONLY` rules even
/// though no data was transferred.
const fn is_data_plane(msg_type: OpcUaMessageType) -> bool {
    matches!(
        msg_type,
        OpcUaMessageType::Browse
            | OpcUaMessageType::Read
            | OpcUaMessageType::Write
            | OpcUaMessageType::Call
            | OpcUaMessageType::CreateSubscription
            | OpcUaMessageType::Publish
            | OpcUaMessageType::Unknown
    )
}

/// Allow-list test for global read-only mode.
///
/// Returns `true` for the read-like operations and session-management
/// types that must remain available even when the gateway is locked
/// down: `Hello`, `Acknowledge`, the secure-channel and session
/// open/activate/close flow, `Browse`, `Read`, `CreateSubscription`,
/// and `Publish`. Everything else — including `Write`, `Call`, and
/// `Unknown` — is denied.
const fn is_read_only_safe(msg_type: OpcUaMessageType) -> bool {
    matches!(
        msg_type,
        OpcUaMessageType::Hello
            | OpcUaMessageType::Acknowledge
            | OpcUaMessageType::OpenSecureChannel
            | OpcUaMessageType::CloseSecureChannel
            | OpcUaMessageType::CreateSession
            | OpcUaMessageType::ActivateSession
            | OpcUaMessageType::CloseSession
            | OpcUaMessageType::Browse
            | OpcUaMessageType::Read
            | OpcUaMessageType::CreateSubscription
            | OpcUaMessageType::Publish
    )
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
            m.set_endpoint(endpoint);
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
    // Regression: a single security-mode violation must not produce
    // duplicate alerts when both the global and per-rule checks fire.
    // -----------------------------------------------------------------------

    #[test]
    fn security_mode_violation_dedup() {
        let mut mon = OpcUaMonitor::new();
        mon.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);
        // Alert-only so both global and per-rule paths execute on a
        // single inspect (rather than the global path short-circuiting
        // with a return).
        mon.set_enforce_security_mode(false);
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::SignAndEncrypt,
            0,
        )
        .unwrap();

        let msg = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::None,
            1,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        let r = mon.inspect(&msg);

        // Exactly one SecurityModeViolation alert — not two.
        assert_eq!(
            r.alert_count, 1,
            "global + per-rule mode-violation must dedup to a single alert"
        );
        assert_eq!(mon.total_alerts(), 1);
    }

    // -----------------------------------------------------------------------
    // Regression: OpenSecureChannel downgrade attack.
    // An attacker that opens a channel with strong security and then
    // injects a forged OpenSecureChannel with weaker security must be
    // rejected and must not silently overwrite the cached mode.
    // -----------------------------------------------------------------------

    #[test]
    fn osc_downgrade_rejected() {
        let mut mon = OpcUaMonitor::new();

        // Open with SignAndEncrypt.
        let osc_strong = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            7,
            1,
            b"",
            1000,
        );
        assert!(mon.inspect(&osc_strong).allowed);

        // Forged downgrade OSC with None: must be rejected.
        let osc_weak = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::None,
            7,
            2,
            b"",
            2000,
        );
        let r = mon.inspect(&osc_weak);
        assert!(!r.allowed, "downgrade OSC must be rejected");
        assert!(r.alert_count > 0);

        // The cached mode must remain SignAndEncrypt — a subsequent
        // Read with a forged-strong claim but referencing a rule that
        // requires SignAndEncrypt must still be allowed (mode wasn't
        // silently downgraded by the rejected OSC).
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::SignAndEncrypt,
            0,
        )
        .unwrap();
        let read = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            7,
            3,
            b"opc.tcp://plc1:4840",
            3000,
        );
        let r = mon.inspect(&read);
        assert!(r.allowed, "cached mode must not have been downgraded");
    }

    #[test]
    fn osc_lateral_mode_allowed() {
        // OSC with same mode is not a downgrade — must be allowed.
        let mut mon = OpcUaMonitor::new();
        let osc1 = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::Sign,
            8,
            1,
            b"",
            1000,
        );
        assert!(mon.inspect(&osc1).allowed);
        let osc2 = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::Sign,
            8,
            2,
            b"",
            2000,
        );
        let r = mon.inspect(&osc2);
        assert!(r.allowed, "same-mode OSC re-key must be allowed");
    }

    #[test]
    fn osc_upgrade_allowed() {
        // OSC strengthening the mode is allowed.
        let mut mon = OpcUaMonitor::new();
        let osc1 = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::None,
            9,
            1,
            b"",
            1000,
        );
        assert!(mon.inspect(&osc1).allowed);
        let osc2 = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            9,
            2,
            b"",
            2000,
        );
        let r = mon.inspect(&osc2);
        assert!(r.allowed, "OSC strengthening mode must be allowed");
    }

    #[test]
    fn min_security_uses_session_mode_for_inband_traffic() {
        // A channel negotiated with None must NOT be able to slip
        // writes past a rule that requires SignAndEncrypt by claiming
        // a high per-frame security_mode on the in-band Write.
        let mut mon = OpcUaMonitor::new();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::SignAndEncrypt,
            0,
        )
        .unwrap();

        // Open channel with None (weak) — must trip min-security on the
        // OSC itself (rule requires SignAndEncrypt). Disable enforcement
        // so the OSC passes and establishes the (weak) session mode for
        // the test that follows.
        mon.set_enforce_security_mode(false);
        let osc = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::None,
            55,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        let _ = mon.inspect(&osc);

        // Re-enable enforcement, then send in-band Write with a forged
        // strong per-frame mode. The session's cached mode is still
        // None, so min-security must reject this.
        mon.set_enforce_security_mode(true);
        let write = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt, // forged claim
            55,
            2,
            b"",
            2000,
        );
        let r = mon.inspect(&write);
        assert!(
            !r.allowed,
            "in-band frame must be checked against session's cached mode"
        );
        assert!(r.alert_count > 0);
    }

    // -----------------------------------------------------------------------
    // Regression: in-band messages without endpoint inherit the rule
    // that the channel's OpenSecureChannel matched. Without this, a
    // Write or Call on a tracked channel with empty endpoint slipped
    // through default-allow even when the channel's rule was READ_ONLY.
    // -----------------------------------------------------------------------

    #[test]
    fn write_without_endpoint_inherits_channel_rule() {
        let mut mon = OpcUaMonitor::new();
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::READ_ONLY,
            OpcUaSecurityMode::None,
            0,
        )
        .unwrap();

        // OpenSecureChannel carries the endpoint and is matched against
        // the READ_ONLY rule.
        let osc = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        let r = mon.inspect(&osc);
        assert!(r.allowed);

        // In-band Write on the same channel with NO endpoint must
        // inherit the channel's rule (READ_ONLY) and be blocked.
        let write = make_msg(
            OpcUaMessageType::Write,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            2,
            b"",
            2000,
        );
        let r = mon.inspect(&write);
        assert!(
            !r.allowed,
            "in-band Write must inherit READ_ONLY perms from channel rule"
        );
        assert!(r.alert_count > 0);

        // A Read on the same channel must still be allowed.
        let read = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            42,
            3,
            b"",
            3000,
        );
        assert!(mon.inspect(&read).allowed);
    }

    #[test]
    fn in_band_inherits_rate_limit_from_channel_rule() {
        let mut mon = OpcUaMonitor::new();
        // Rate = 3: enough for OpenSecureChannel + 2 in-band reads, then
        // the 3rd in-band read must trip the inherited limit.
        mon.add_rule(
            b"opc.tcp://plc1",
            EndpointAction::Allow,
            MessagePermissions::ALL,
            OpcUaSecurityMode::None,
            3,
        )
        .unwrap();

        // OpenSecureChannel binds the channel to the rate-limited rule.
        let osc = make_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            77,
            1,
            b"opc.tcp://plc1:4840",
            1000,
        );
        assert!(mon.inspect(&osc).allowed);

        // Two in-band reads consume the remaining rate-limit tokens.
        for seq in 2..=3 {
            let m = make_msg(
                OpcUaMessageType::Read,
                OpcUaSecurityMode::SignAndEncrypt,
                77,
                seq,
                b"",
                1000 + seq as u64,
            );
            assert!(mon.inspect(&m).allowed, "seq {seq} should pass");
        }
        // Third in-band read (4th frame total) must trip the inherited
        // rate-limit even though the frame carries no endpoint.
        let m = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            77,
            4,
            b"",
            1004,
        );
        let r = mon.inspect(&m);
        assert!(!r.allowed, "rate-limit must be inherited from channel rule");
    }

    // -----------------------------------------------------------------------
    // Regression: global read-only is an allow-list, not a deny-list.
    // Unknown (and any future write-capable variant) must be blocked.
    // -----------------------------------------------------------------------

    #[test]
    fn global_read_only_blocks_unknown_message_type() {
        // The legacy deny-list only checked Write|Call; an attacker that
        // classified a write/method-call payload as `Unknown` slipped
        // past read-only. Allow-list must block it.
        let mut mon = OpcUaMonitor::new();
        mon.set_read_only(true);
        let msg = make_msg(
            OpcUaMessageType::Unknown,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            b"",
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(!r.allowed, "Unknown must be blocked under read-only");
        assert!(r.alert_count > 0);
    }

    #[test]
    fn global_read_only_allows_management_and_read_types() {
        let mut mon = OpcUaMonitor::new();
        mon.set_read_only(true);
        // Each safe type must pass under read-only.
        let safe = [
            OpcUaMessageType::Hello,
            OpcUaMessageType::Acknowledge,
            OpcUaMessageType::OpenSecureChannel,
            OpcUaMessageType::CloseSecureChannel,
            OpcUaMessageType::CreateSession,
            OpcUaMessageType::ActivateSession,
            OpcUaMessageType::CloseSession,
            OpcUaMessageType::Browse,
            OpcUaMessageType::Read,
            OpcUaMessageType::CreateSubscription,
            OpcUaMessageType::Publish,
        ];
        for (i, t) in safe.iter().enumerate() {
            // Distinct channel_id per type so replay bitmap state for one
            // type does not affect another.
            let msg = make_msg(
                *t,
                OpcUaSecurityMode::SignAndEncrypt,
                (i as u32) + 100,
                1,
                b"",
                1000 + i as u64,
            );
            let r = mon.inspect(&msg);
            assert!(r.allowed, "{t:?} must be allowed under read-only");
        }
    }

    // -----------------------------------------------------------------------
    // Regression: per-channel sliding 64-counter replay bitmap.
    // A single forged forward jump must not lock out subsequent legitimate
    // frames; small reorders within the 64-counter window must be accepted.
    // -----------------------------------------------------------------------

    #[test]
    fn forged_forward_jump_does_not_lock_out_legit_frames() {
        // With the old single-counter window, a forged frame with
        // seq = last + 65000 would advance `last_sequence` to that value
        // and cause the next 65000 legitimate frames to be flagged as
        // replays. With the per-channel sliding bitmap, that forged jump
        // is now suspicious and rejected, so the next legitimate frame is
        // still accepted.
        let mut mon = OpcUaMonitor::new();
        let msg1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10,
            b"",
            1000,
        );
        assert_eq!(mon.inspect(&msg1).alert_count, 0);

        // Forged big-forward jump — must not advance the window.
        let forged = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            10 + 65_000,
            b"",
            2000,
        );
        let r = mon.inspect(&forged);
        assert!(!r.allowed, "forged big jump must be rejected");
        assert!(r.alert_count > 0);

        // Subsequent legitimate frame (seq = 11) must still be accepted.
        let legit = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            11,
            b"",
            3000,
        );
        let r = mon.inspect(&legit);
        assert!(r.allowed, "legitimate seq=11 must not be locked out");
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn in_window_reorder_accepted() {
        // Two-frame reorder within the 64-counter window must NOT be
        // flagged as replay. Old single-counter window would have
        // falsely flagged this.
        let mut mon = OpcUaMonitor::new();
        // Establish sequence at 100.
        let m1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            100,
            b"",
            1000,
        );
        assert_eq!(mon.inspect(&m1).alert_count, 0);

        // Frame seq=102 arrives before seq=101 — both must be accepted.
        let m2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            102,
            b"",
            2000,
        );
        assert_eq!(mon.inspect(&m2).alert_count, 0, "seq 102 forward jump");

        let m3 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            101,
            b"",
            3000,
        );
        let r = mon.inspect(&m3);
        assert_eq!(r.alert_count, 0, "seq 101 in-window reorder must pass");
        assert!(r.allowed);
    }

    #[test]
    fn duplicate_within_window_rejected() {
        // After accepting an in-window out-of-order frame, a duplicate
        // of the same frame must be flagged as replay (bit already set).
        let mut mon = OpcUaMonitor::new();
        let m1 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            100,
            b"",
            1000,
        );
        assert_eq!(mon.inspect(&m1).alert_count, 0);
        let m2 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            105,
            b"",
            2000,
        );
        assert_eq!(mon.inspect(&m2).alert_count, 0);
        // 103 is within window of 105 (diff = 2) — accept.
        let m3 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            103,
            b"",
            3000,
        );
        assert_eq!(mon.inspect(&m3).alert_count, 0);
        // Replay 103 — must be flagged.
        let m4 = make_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            103,
            b"",
            4000,
        );
        let r = mon.inspect(&m4);
        assert!(r.alert_count > 0, "duplicate within window must be replay");
        assert!(!r.allowed);
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
        // Force endpoint_len out of range to simulate a malformed FFI
        // frame — the validated set_endpoint() can no longer produce this,
        // but the monitor must still defend against ABI-level corruption.
        let mut msg = OpcUaMessage::default();
        msg.msg_type = OpcUaMessageType::Read;
        msg.security_mode = OpcUaSecurityMode::SignAndEncrypt;
        msg.channel_id = 1;
        msg.sequence_number = 1;
        msg.timestamp_us = 1000;
        msg.__set_endpoint_len_unchecked(255);
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

    // Helper to build a basic OPC UA message with only public scalar
    // fields populated. `endpoint` is encapsulated and stays empty unless
    // the test explicitly sets it via `set_endpoint`.
    fn opcua_msg(
        msg_type: OpcUaMessageType,
        security_mode: OpcUaSecurityMode,
        channel_id: u32,
        sequence_number: u32,
        message_size: u32,
        timestamp_us: u64,
    ) -> OpcUaMessage {
        let mut m = OpcUaMessage::default();
        m.msg_type = msg_type;
        m.security_mode = security_mode;
        m.channel_id = channel_id;
        m.sequence_number = sequence_number;
        m.message_size = message_size;
        m.timestamp_us = timestamp_us;
        m
    }

    #[test]
    fn message_size_enforcement() {
        let mut mon = OpcUaMonitor::new();
        mon.set_max_message_size(1000);
        let msg = opcua_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            2000,
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn message_size_zero_means_no_limit() {
        let mut mon = OpcUaMonitor::new();
        // max_message_size defaults to 0 = no limit
        let msg = opcua_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            999_999,
            1000,
        );
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: endpoint length must be bounds-checked (H4).
    // -----------------------------------------------------------------------
    #[test]
    fn oversized_endpoint_len_does_not_panic() {
        let mut mon = OpcUaMonitor::new();
        let mut msg = opcua_msg(
            OpcUaMessageType::Read,
            OpcUaSecurityMode::SignAndEncrypt,
            1,
            1,
            0,
            1000,
        );
        // Simulate ABI-level corruption — set endpoint_len larger than the
        // backing array through the test-only unchecked setter.
        msg.__set_endpoint_len_unchecked(u8::MAX);
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
            let msg = opcua_msg(
                OpcUaMessageType::Read,
                OpcUaSecurityMode::SignAndEncrypt,
                i,
                1,
                0,
                i as u64 * 1000,
            );
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
            let msg = opcua_msg(
                OpcUaMessageType::OpenSecureChannel,
                OpcUaSecurityMode::SignAndEncrypt,
                ch,
                1,
                0,
                1_000_000,
            );
            let _ = mon.inspect(&msg);
        }
        assert_eq!(mon.active_sessions(), 2);

        // Third session within same second should be rate-limited
        let msg = opcua_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            100,
            1,
            0,
            1_000_000,
        );
        let _ = mon.inspect(&msg);
        // Session should not be created (still 2)
        assert_eq!(mon.active_sessions(), 2);

        // After enough time, bucket refills
        let msg = opcua_msg(
            OpcUaMessageType::OpenSecureChannel,
            OpcUaSecurityMode::SignAndEncrypt,
            100,
            1,
            0,
            2_500_000,
        );
        let _ = mon.inspect(&msg);
        assert_eq!(mon.active_sessions(), 3);
    }
}
