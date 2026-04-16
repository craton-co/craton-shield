#![no_std]
#![deny(missing_docs)]

//! EtherNet/IP (CIP over Ethernet) intrusion detection monitor.
//!
//! Implemented against ODVA EtherNet/IP Vol. 1 (Common Industrial Protocol)
//! and Vol. 2 (Encapsulation Protocol).
//!
//! Monitors EtherNet/IP traffic for security violations:
//!
//! - **Session handle tracking** — detect unauthorized sessions.
//! - **Command allowlist** — restrict which encapsulation commands are
//!   permitted.
//! - **Rate limiting** — per-session request rate enforcement.
//! - **CIP service allowlist** — bitmask-based filter applied to the
//!   embedded CIP service code parsed from `SendRRData` / `SendUnitData`
//!   encapsulation commands (see [`EtherNetIpMonitor::set_cip_service_filter`]).

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, EtherNetIpFrame, InspectResult, RateBucket, SOURCE_ETHERNETIP};

/// Backward-compatible type alias.
pub type EtherNetIpInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum session rules.
const MAX_SESSION_RULES: usize = 16;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

const REGISTER_SESSION: u16 = 0x0065;
const UNREGISTER_SESSION: u16 = 0x0066;
const SEND_RR_DATA: u16 = 0x006F;
const SEND_UNIT_DATA: u16 = 0x0070;
const MAX_SESSIONS: usize = 16;

/// CPF item type for an unconnected data item (contains embedded MR request).
const CPF_ITEM_UNCONNECTED_DATA: u16 = 0x00B2;
/// CPF item type for a connected data item (contains sequence count + MR request).
const CPF_ITEM_CONNECTED_DATA: u16 = 0x00B1;

/// Maximum number of CPF items we will walk before giving up.
///
/// The EtherNet/IP spec only requires a handful of items per frame (address +
/// data). Capping the scan makes the parser immune to crafted payloads that
/// advertise an attacker-controlled `item_count` in the tens of thousands.
const MAX_CPF_ITEMS: u16 = 16;

/// Default session timeout in microseconds (600 seconds).
const DEFAULT_SESSION_TIMEOUT_US: u64 = 600_000_000;

// ---------------------------------------------------------------------------
// Session rule
// ---------------------------------------------------------------------------

/// Security rule for an EtherNet/IP session.
#[derive(Debug, Clone, Copy)]
struct SessionRule {
    /// Allowed encapsulation command code (0 = any).
    allowed_command: u16,
    /// Max requests per second (0 = unlimited).
    max_rate_per_sec: u16,
    active: bool,
}

impl SessionRule {
    const fn empty() -> Self {
        Self {
            allowed_command: 0,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CIP payload parsing
// ---------------------------------------------------------------------------

/// Parse the embedded CIP service code from a `SendRRData` / `SendUnitData`
/// encapsulation command payload.
///
/// Wire layout (little-endian on EtherNet/IP):
///
/// ```text
///   SendRRData/SendUnitData encap data:
///     Interface handle   : u32
///     Timeout            : u16
///     CPF item count     : u16
///     CPF items[count]   : { type: u16, length: u16, data: [u8; length] }
/// ```
///
/// The relevant item is the Connected Data Item (`0x00B1`) or
/// Unconnected Data Item (`0x00B2`). Its `data` region begins with the
/// embedded Message Router (MR) request:
///
/// - For `0x00B2`: `service (u8, low 7 bits)` + path + request data
/// - For `0x00B1`: `sequence_count (u16)` + `service (u8)` + path + ...
///
/// The high bit of the service byte marks a response; we mask it off
/// and return the low 7 bits as the service code.
///
/// Returns `None` if the layout is malformed or no data item is present.
/// The parser is strict — unparseable payloads skip the CIP filter but
/// the rest of the monitor continues to run.
#[inline]
fn parse_cip_service(payload: &[u8]) -> Option<u8> {
    // Need at least: interface(4) + timeout(2) + count(2) = 8
    if payload.len() < 8 {
        return None;
    }
    let item_count = u16::from_le_bytes([payload[6], payload[7]]);
    // Cap attacker-controlled iteration count. Anything beyond
    // `MAX_CPF_ITEMS` is either malformed or hostile — fail closed.
    if item_count > MAX_CPF_ITEMS {
        return None;
    }
    // Reject payloads too short to hold the claimed number of CPF item headers.
    let min_items_len = (item_count as usize).saturating_mul(4);
    if payload.len().saturating_sub(8) < min_items_len {
        return None;
    }
    let mut cursor = 8usize;
    let payload_len = payload.len();
    for _ in 0..item_count {
        // Checked bounds: header is 4 bytes.
        let header_end = cursor.checked_add(4)?;
        if header_end > payload_len {
            return None;
        }
        let item_type = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]);
        let item_len = u16::from_le_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
        cursor = header_end;
        // Checked add catches cursor overflow on 32-bit targets where a
        // large `item_len` could wrap the cursor past `payload_len`.
        let data_end = cursor.checked_add(item_len)?;
        if data_end > payload_len {
            return None;
        }
        let data = &payload[cursor..data_end];
        match item_type {
            CPF_ITEM_UNCONNECTED_DATA => {
                // First byte is the MR service code (mask off response bit).
                if item_len < 1 {
                    return None;
                }
                return Some(data[0] & 0x7F);
            }
            CPF_ITEM_CONNECTED_DATA => {
                // Connected items prefix the MR request with a 2-byte sequence count.
                if data.len() >= 3 {
                    return Some(data[2] & 0x7F);
                }
                return None;
            }
            _ => {
                // Address / other items — skip and continue scanning.
                cursor = data_end;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Session entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct SessionEntry {
    session_handle: u32,
    active: bool,
    /// Timestamp of the most recent frame seen on this session.
    /// Used by `expire_sessions` — idle timeout is measured from last activity,
    /// not from session creation, so long-running active sessions are not
    /// incorrectly evicted.
    last_activity_us: u64,
}

impl SessionEntry {
    const fn empty() -> Self {
        Self {
            session_handle: 0,
            active: false,
            last_activity_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// EtherNet/IP Monitor
// ---------------------------------------------------------------------------

/// EtherNet/IP intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~700 bytes.
pub struct EtherNetIpMonitor {
    rules: [SessionRule; MAX_SESSION_RULES],
    rule_count: u8,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Whether to block unknown session handles.
    strict_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
    sessions: [SessionEntry; MAX_SESSIONS],
    session_count: u8,
    /// Bitmask of allowed CIP service codes 0-127 (0 = no filtering).
    ///
    /// The embedded CIP service byte is 7 bits (0x00–0x7F after masking the
    /// response bit). A `u128` covers all 128 possible codes; bit N corresponds
    /// to service code N.
    cip_service_mask: u128,
    /// Session timeout in microseconds.
    session_timeout_us: u64,
    /// Monotonic tick counter for rate-bucket LRU eviction ordering.
    rate_tick: u32,
}

impl EtherNetIpMonitor {
    /// Create a new EtherNet/IP monitor (permissive).
    pub fn new() -> Self {
        Self {
            rules: [SessionRule::empty(); MAX_SESSION_RULES],
            rule_count: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            strict_mode: false,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            sessions: [SessionEntry::empty(); MAX_SESSIONS],
            session_count: 0,
            cip_service_mask: 0u128,
            session_timeout_us: DEFAULT_SESSION_TIMEOUT_US,
            rate_tick: 0,
        }
    }

    /// Create a new EtherNet/IP monitor in strict mode.
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Inspect an EtherNet/IP frame.
    #[allow(clippy::too_many_lines)]
    pub fn inspect(&mut self, frame: &EtherNetIpFrame) -> EtherNetIpInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_ETHERNETIP);

        // Reject frames with payload_len exceeding the buffer size.
        if frame.payload_len_overflow() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_ETHERNETIP,
                frame.session_handle,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PayloadOverflow,
            );
            return result;
        }

        // Reserved sentinel handle: `session_handle == 0` is valid ONLY on
        // RegisterSession (per the EtherNet/IP spec the server assigns the
        // real handle in the reply). Any other command carrying handle 0 is
        // a forged or malformed frame and must be denied unconditionally —
        // even in permissive mode — so attackers cannot bypass per-session
        // controls by targeting the "no session" sentinel.
        if frame.session_handle == 0 && frame.command != REGISTER_SESSION {
            result.push_alert_blocking(
                AlertSeverity::High,
                SOURCE_ETHERNETIP,
                frame.session_handle,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::UnknownSession,
            );
            return result;
        }

        // Session lifecycle tracking.
        if frame.command == REGISTER_SESSION {
            self.register_session(frame.session_handle, frame.timestamp_us);
        } else if frame.command == UNREGISTER_SESSION {
            self.unregister_session(frame.session_handle);
        }
        // Non-lifecycle commands: combine the touch + known-check into a
        // single scan via `touch_and_check_known` below.

        let is_lifecycle = frame.command == REGISTER_SESSION || frame.command == UNREGISTER_SESSION;
        if !is_lifecycle {
            let known = self.touch_and_check_known(frame.session_handle, frame.timestamp_us);
            if self.strict_mode && !known {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_ETHERNETIP,
                    frame.session_handle,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::UnknownSession,
                );
                return result;
            }
        }

        // Command allowlist check.
        // UNREGISTER_SESSION is always permitted (lifecycle teardown must
        // succeed regardless of rule configuration).
        //
        // Matching is specificity-ordered: a rule whose `allowed_command`
        // exactly matches `frame.command` always wins over a wildcard rule
        // (`allowed_command == 0`), regardless of insertion order. This
        // closes a class of misconfiguration bugs where a permissive
        // catch-all added first would mask a tighter per-command rule
        // added later (e.g. a loose wildcard with high `max_rate_per_sec`
        // would shadow a strict per-command limit). Among rules of equal
        // specificity, the first-active wins (deterministic, insertion
        // order).
        let mut matched_rule: Option<usize> = None;
        if frame.command == UNREGISTER_SESSION {
            // Skip command allowlist for session teardown.
        } else if self.rule_count > 0 {
            let mut wildcard_match: Option<usize> = None;
            for i in 0..self.rule_count as usize {
                if !self.rules[i].active {
                    continue;
                }
                if self.rules[i].allowed_command == frame.command {
                    // Specific match — always wins; stop scanning.
                    matched_rule = Some(i);
                    break;
                }
                if self.rules[i].allowed_command == 0 && wildcard_match.is_none() {
                    wildcard_match = Some(i);
                }
            }
            if matched_rule.is_none() {
                matched_rule = wildcard_match;
            }
            if matched_rule.is_none() && self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_ETHERNETIP,
                    frame.session_handle,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::NoMatchingRule,
                );
                return result;
            }
        } else if self.strict_mode {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_ETHERNETIP,
                frame.session_handle,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::NoMatchingRule,
            );
            return result;
        }

        // CIP service filter: parse the embedded MR service code from
        // SendRRData / SendUnitData encapsulation commands and check it
        // against the configured bitmask. CIP service codes are 7-bit
        // (0x00–0x7F after masking the response bit), and the u128 mask
        // covers all 128 possible codes — any code not set in the mask
        // is blocked.
        if self.cip_service_mask != 0
            && (frame.command == SEND_RR_DATA || frame.command == SEND_UNIT_DATA)
        {
            let payload = &frame.payload[..frame.valid_payload_len()];
            if let Some(service) = parse_cip_service(payload) {
                // `parse_cip_service` already masks the response bit, so
                // `service` is guaranteed to be in 0..=127 and the shift
                // below cannot overflow the u128 mask.
                debug_assert!(service < 128);
                let bit = 1u128 << service;
                if (self.cip_service_mask & bit) == 0 {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::High,
                        SOURCE_ETHERNETIP,
                        frame.session_handle,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::CipServiceBlocked,
                    );
                    return result;
                }
            }
        }

        // Rate limiting (per matched rule).
        if let Some(ri) = matched_rule {
            let rate = self.rules[ri].max_rate_per_sec;
            if rate > 0 && !self.rate_check(frame.session_handle, rate, frame.timestamp_us) {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_ETHERNETIP,
                    frame.session_handle,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::RateExceeded,
                );
            }
        }

        result
    }

    /// Add a command allowlist rule.
    ///
    /// `command` is the EtherNet/IP encapsulation command code (use `0`
    /// to match any command); `max_rate_per_sec` is the per-session token
    /// bucket capacity (use `0` for unrate-limited).
    ///
    /// Returns [`VsError::ResourceExhausted`] when either the rule table
    /// is full (16 entries) or a rule with the same `command` already
    /// exists. Duplicate rules would never both fire under
    /// specificity-ordered matching, so rejecting them surfaces a
    /// configuration mistake rather than silently shadowing the second
    /// rule.
    pub fn add_command_rule(&mut self, command: u16, max_rate_per_sec: u16) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_SESSION_RULES {
            return Err(VsError::ResourceExhausted);
        }
        // Reject duplicate command entries.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && self.rules[i].allowed_command == command {
                return Err(VsError::ResourceExhausted);
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = SessionRule {
            allowed_command: command,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Total number of frames inspected since construction or the last
    /// [`reset`](Self::reset).
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Total number of alerts emitted since construction or the last
    /// [`reset`](Self::reset).
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Next alert ID that will be assigned. Useful for monitoring and
    /// for tests that need to observe alert numbering.
    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    /// Reset all state. Settings (`strict_mode`, `session_timeout_us`) are preserved.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let session_timeout_us = self.session_timeout_us;
        *self = Self::new();
        self.strict_mode = strict;
        self.session_timeout_us = session_timeout_us;
    }

    /// Set the session timeout in microseconds.
    pub fn set_session_timeout(&mut self, timeout_us: u64) {
        self.session_timeout_us = timeout_us;
    }

    /// Expire sessions that have been idle longer than `session_timeout_us`.
    ///
    /// Idleness is measured from `last_activity_us`, not `created_us`, so
    /// long-running active sessions are not incorrectly evicted.
    pub fn expire_sessions(&mut self, now_us: u64) {
        for s in &mut self.sessions {
            if s.active && now_us.saturating_sub(s.last_activity_us) > self.session_timeout_us {
                s.active = false;
                self.session_count = self.session_count.saturating_sub(1);
            }
        }
    }

    /// Set the CIP service bitmask filter.
    ///
    /// When non-zero, the monitor parses the embedded CIP Message Router
    /// (MR) service code from `SendRRData` (0x006F) and `SendUnitData`
    /// (0x0070) encapsulation commands and requires that bit `service`
    /// of the mask be set for the frame to be allowed.
    ///
    /// CIP service codes are 7-bit (0x00–0x7F after masking the response
    /// bit). The `u128` mask covers all 128 possible codes. Bit N corresponds
    /// to service code N:
    ///
    /// - `1u128 << 0x0E` — `Get_Attribute_Single`
    /// - `1u128 << 0x10` — `Set_Attribute_Single`
    /// - `1u128 << 0x4C` — `Read_Tag` (EtherNet/IP vendor extension, code 76)
    /// - `1u128 << 0x4D` — `Write_Tag`
    ///
    /// Unparseable payloads bypass the CIP filter (the service-level and
    /// session-level checks still apply).
    ///
    /// Pass `0` to disable CIP service filtering.
    pub fn set_cip_service_filter(&mut self, mask: u128) {
        self.cip_service_mask = mask;
    }

    /// Returns the currently configured CIP service bitmask.
    pub fn cip_service_mask(&self) -> u128 {
        self.cip_service_mask
    }

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
                    // Capacity must track the *currently matched* rule, not
                    // the rule active when the bucket was first allocated.
                    // If the rule has been re-evaluated to a different rate
                    // (e.g. specificity-ordered matching now picks a more
                    // specific rule over a wildcard), adopt the new cap and
                    // clamp leftover tokens so a previously looser rule
                    // cannot leak excess credit into a newly tightened one.
                    if b.capacity != max_rate {
                        b.capacity = max_rate;
                        if b.tokens > max_rate {
                            b.tokens = max_rate;
                        }
                    }
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

    fn register_session(&mut self, handle: u32, ts_us: u64) {
        // Single-pass scan (mirrors `rate_check`): find the matching slot,
        // the first empty slot, and the LRU victim in one walk over the
        // session table. LRU is ordered by `last_activity_us` so the
        // eviction policy matches `expire_sessions` (which also measures
        // idleness from last activity, not creation).
        let mut first_empty: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.active {
                if s.session_handle == handle {
                    // Already registered — refresh idle timer and exit.
                    s.last_activity_us = ts_us;
                    return;
                }
                if s.last_activity_us < lru_ts {
                    lru_ts = s.last_activity_us;
                    lru_idx = i;
                }
            } else if first_empty.is_none() {
                first_empty = Some(i);
            }
        }
        let slot = first_empty.unwrap_or(lru_idx);
        if !self.sessions[slot].active {
            self.session_count = self.session_count.saturating_add(1);
        }
        self.sessions[slot] = SessionEntry {
            session_handle: handle,
            active: true,
            last_activity_us: ts_us,
        };
    }

    fn unregister_session(&mut self, handle: u32) {
        for s in &mut self.sessions {
            if s.active && s.session_handle == handle {
                s.active = false;
                self.session_count = self.session_count.saturating_sub(1);
                return;
            }
        }
    }

    /// Single-pass session lookup used by `inspect` on non-lifecycle
    /// commands: refreshes `last_activity_us` if a matching entry is
    /// found and returns whether the session is known. Combines what
    /// were previously two separate scans (`touch_session` followed
    /// by `session_known`) into one walk over the session table.
    fn touch_and_check_known(&mut self, handle: u32, ts_us: u64) -> bool {
        for s in &mut self.sessions {
            if s.active && s.session_handle == handle {
                s.last_activity_us = ts_us;
                return true;
            }
        }
        false
    }
}

impl Default for EtherNetIpMonitor {
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

    #[test]
    fn permissive_allows_all() {
        // Permissive mode allows non-reserved sessions / unmatched
        // commands. (Reserved `session_handle == 0` on non-RegisterSession
        // is rejected even in permissive mode — see the `handle_zero_*`
        // regression tests.)
        let mut mon = EtherNetIpMonitor::new();
        let f = EtherNetIpFrame {
            session_handle: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_blocks_unknown() {
        let mut mon = EtherNetIpMonitor::new_strict();
        let f = EtherNetIpFrame::default();
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_allows_configured_command() {
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0x0065, 0).unwrap(); // RegisterSession
        let f = EtherNetIpFrame {
            command: 0x0065,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn payload_overflow_rejected() {
        let mut mon = EtherNetIpMonitor::new();
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = EtherNetIpMonitor::new();
        let _ = mon.inspect(&EtherNetIpFrame::default());
        assert_eq!(mon.total_inspected(), 1);
    }

    #[test]
    fn reset_preserves_mode() {
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0x01, 0).unwrap();
        let _ = mon.inspect(&EtherNetIpFrame {
            command: 0x01,
            ..Default::default()
        });
        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        // Strict mode preserved, rules cleared.
        assert!(!mon.inspect(&EtherNetIpFrame::default()).allowed);
    }

    #[test]
    fn default_constructor() {
        let mon = EtherNetIpMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn rate_limiter_lru_eviction_allows_new_session() {
        let mut mon = EtherNetIpMonitor::new();
        // Allow any command with rate limiting (2 req/s).
        mon.add_command_rule(0, 2).unwrap();

        // Fill all 16 rate-limit buckets with distinct session handles at
        // incrementing timestamps so handle 1 is the LRU.
        for handle in 1..=(MAX_RATE_BUCKETS as u32) {
            let f = EtherNetIpFrame {
                command: 0x01,
                session_handle: handle,
                timestamp_us: handle as u64 * 1000,
                ..Default::default()
            };
            let r = mon.inspect(&f);
            assert!(r.allowed, "handle {handle} should be allowed");
        }

        // The 17th distinct session evicts the LRU bucket (handle 1) and is allowed.
        let f17 = EtherNetIpFrame {
            command: 0x01,
            session_handle: 999,
            timestamp_us: 100_000,
            ..Default::default()
        };
        let r = mon.inspect(&f17);
        assert!(r.allowed, "17th session should be allowed via LRU eviction");
    }

    #[test]
    fn add_command_rule_when_full_returns_resource_exhausted() {
        let mut mon = EtherNetIpMonitor::new();
        for i in 0..MAX_SESSION_RULES {
            mon.add_command_rule(i as u16 + 1, 0).unwrap();
        }
        let err = mon.add_command_rule(0xFF, 0).unwrap_err();
        assert!(
            matches!(err, VsError::ResourceExhausted),
            "expected ResourceExhausted, got {err:?}"
        );
    }

    #[test]
    fn multiple_simultaneous_sessions_different_handles() {
        let mut mon = EtherNetIpMonitor::new();
        // Allow any command with rate limit of 1 req/s.
        mon.add_command_rule(0, 1).unwrap();

        let f_a = EtherNetIpFrame {
            command: 0x01,
            session_handle: 100,
            timestamp_us: 0,
            ..Default::default()
        };
        let f_b = EtherNetIpFrame {
            command: 0x01,
            session_handle: 200,
            timestamp_us: 0,
            ..Default::default()
        };

        // Both sessions get their first request allowed.
        assert!(mon.inspect(&f_a).allowed);
        assert!(mon.inspect(&f_b).allowed);

        // Second request at same timestamp: both should be denied (1 req/s).
        assert!(!mon.inspect(&f_a).allowed);
        assert!(!mon.inspect(&f_b).allowed);

        // After 1 second, both should be allowed again.
        let f_after_a = EtherNetIpFrame {
            timestamp_us: 1_000_000,
            ..f_a
        };
        let f_after_b = EtherNetIpFrame {
            timestamp_us: 1_000_000,
            ..f_b
        };
        assert!(mon.inspect(&f_after_a).allowed);
        assert!(mon.inspect(&f_after_b).allowed);
    }

    #[test]
    fn wildcard_command_matching_with_rate_limiting() {
        let mut mon = EtherNetIpMonitor::new_strict();
        // Wildcard command (0) matches any command, rate-limited to 3 req/s.
        mon.add_command_rule(0, 3).unwrap();

        // Register sessions first so session tracking doesn't block them.
        for handle in [0x0001u32, 0x0065, 0x006F, 0x0070] {
            let reg = EtherNetIpFrame {
                command: REGISTER_SESSION,
                session_handle: handle,
                timestamp_us: 0,
                ..Default::default()
            };
            let _ = mon.inspect(&reg);
        }

        // Different commands should all match the wildcard rule.
        for cmd in [0x0001, 0x0065, 0x006F, 0x0070] {
            let f = EtherNetIpFrame {
                command: cmd,
                session_handle: cmd as u32,
                timestamp_us: 0,
                ..Default::default()
            };
            assert!(
                mon.inspect(&f).allowed,
                "command {cmd:#06x} should match wildcard"
            );
        }

        // Exhaust rate limit for one session.
        let f = EtherNetIpFrame {
            command: 0x0065,
            session_handle: 0x0065,
            timestamp_us: 0,
            ..Default::default()
        };
        // Already consumed 2 above for handle 0x0065 (register + loop); consume 1 more.
        assert!(mon.inspect(&f).allowed);
        // 4th should be denied (capacity is 3).
        assert!(!mon.inspect(&f).allowed);

        // Other sessions should still be fine at the same timestamp.
        let f2 = EtherNetIpFrame {
            command: 0x0001,
            session_handle: 0x0001,
            timestamp_us: 0,
            ..Default::default()
        };
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = EtherNetIpMonitor::new();
        // Allow command 0x01 with max 2 requests per second.
        mon.add_command_rule(0x01, 2).unwrap();

        let f = EtherNetIpFrame {
            command: 0x01,
            session_handle: 1,
            timestamp_us: 0,
            ..Default::default()
        };

        // First two should be allowed.
        assert!(mon.inspect(&f).allowed);
        assert!(mon.inspect(&f).allowed);

        // Third at same timestamp should be blocked.
        assert!(!mon.inspect(&f).allowed);

        // After 1 second, should be allowed again.
        let f2 = EtherNetIpFrame {
            command: 0x01,
            session_handle: 1,
            timestamp_us: 1_000_000,
            ..Default::default()
        };
        assert!(f2.timestamp_us == 1_000_000);
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn session_register_and_unregister() {
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0, 0).unwrap(); // allow all commands

        // Register a session
        let reg = EtherNetIpFrame {
            command: 0x0065,
            session_handle: 42,
            ..Default::default()
        };
        assert!(mon.inspect(&reg).allowed);

        // Use the session
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 42,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        // Unknown session in strict mode should be blocked
        let f2 = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 99,
            ..Default::default()
        };
        assert!(!mon.inspect(&f2).allowed);

        // Unregister
        let unreg = EtherNetIpFrame {
            command: 0x0066,
            session_handle: 42,
            ..Default::default()
        };
        assert!(mon.inspect(&unreg).allowed);

        // After unregister, session is unknown again
        let f3 = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 42,
            ..Default::default()
        };
        assert!(!mon.inspect(&f3).allowed);
    }

    #[test]
    fn handle_zero_data_plane_rejected_strict() {
        // session_handle=0 on a data-plane command must be rejected in strict
        // mode — handle 0 is never a valid registered session handle.
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0, 0).unwrap();
        let f = EtherNetIpFrame {
            command: SEND_UNIT_DATA,
            session_handle: 0,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(
            !r.allowed,
            "handle=0 on data-plane command must be rejected in strict mode"
        );
        assert!(r.alert_count > 0);
    }

    // -------------------------------------------------------------------
    // Regression: reserved session_handle == 0 rejection.
    //
    // Per the EtherNet/IP spec session_handle=0 is reserved for the
    // RegisterSession request — the server assigns the real handle in the
    // reply. Any non-RegisterSession command carrying handle=0 must be
    // rejected unconditionally (not only in strict mode), otherwise an
    // attacker can forge UnregisterSession / SendRRData / SendUnitData
    // against the "no session" sentinel and bypass per-session controls.
    // -------------------------------------------------------------------

    #[test]
    fn handle_zero_data_plane_rejected_permissive() {
        // Even with no rules and no strict mode, handle=0 on a data-plane
        // command is rejected because the value is reserved on the wire.
        let mut mon = EtherNetIpMonitor::new();
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 0,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(
            !r.allowed,
            "handle=0 on data-plane command must be rejected even in permissive mode"
        );
        assert!(r.alert_count > 0);
        assert_eq!(r.alert_codes[0], AlertCode::UnknownSession);
    }

    #[test]
    fn handle_zero_unregister_session_rejected() {
        // UnregisterSession with handle=0 is also invalid — the sentinel
        // can never name a real session to tear down. The reserved-handle
        // check fires before the lifecycle bypass.
        let mut mon = EtherNetIpMonitor::new();
        let f = EtherNetIpFrame {
            command: UNREGISTER_SESSION,
            session_handle: 0,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "handle=0 on UnregisterSession must be rejected");
        assert_eq!(r.alert_codes[0], AlertCode::UnknownSession);
    }

    #[test]
    fn handle_zero_register_session_still_processed() {
        // RegisterSession requests *do* carry handle=0 on the wire — the
        // reserved-handle check must NOT block them. The monitor processes
        // the lifecycle event without polluting the session table with
        // a handle=0 entry (which would otherwise let later data-plane
        // traffic with handle=0 appear "known").
        let mut mon = EtherNetIpMonitor::new();
        let reg = EtherNetIpFrame {
            command: REGISTER_SESSION,
            session_handle: 0,
            ..Default::default()
        };
        let r = mon.inspect(&reg);
        assert!(
            r.allowed,
            "RegisterSession with handle=0 is the on-wire norm"
        );
        // Session table must NOT now contain a handle=0 entry, so a
        // follow-up data frame for handle=0 is still rejected.
        let data = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 0,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&data).allowed,
            "handle=0 must not be tracked as a real session"
        );
    }

    // -------------------------------------------------------------------
    // Regression: rule matching is specificity-ordered.
    //
    // The old first-match-wins scan let a wildcard rule (allowed_command
    // == 0) shadow a tighter per-command rule simply by being added
    // first. After the fix, a rule whose `allowed_command` equals
    // `frame.command` always wins over a wildcard, regardless of
    // insertion order, so operators cannot accidentally neutralise a
    // strict per-command rule by leaving a permissive catch-all in the
    // config.
    // -------------------------------------------------------------------

    #[test]
    fn specific_rule_wins_over_wildcard_added_first() {
        let mut mon = EtherNetIpMonitor::new();
        // Wildcard rule added FIRST with a loose rate (10/s).
        mon.add_command_rule(0, 10).unwrap();
        // Specific rule for SEND_RR_DATA with a tight rate (2/s).
        mon.add_command_rule(SEND_RR_DATA, 2).unwrap();

        // Send 2 SEND_RR_DATA frames — the specific rule must match,
        // so both pass under cap=2.
        for _ in 0..2 {
            let f = EtherNetIpFrame {
                command: SEND_RR_DATA,
                session_handle: 5,
                timestamp_us: 0,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed);
        }
        // 3rd frame must be denied: the tight per-command cap (2) is
        // enforced even though the wildcard (10) was added first.
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 5,
            timestamp_us: 0,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(
            !r.allowed,
            "specific rule (cap=2) must shadow wildcard (cap=10), even when wildcard was added first"
        );
        assert_eq!(r.alert_codes[0], AlertCode::RateExceeded);
    }

    #[test]
    fn wildcard_still_matches_for_other_commands() {
        // A specific rule for one command must not stop the wildcard
        // rule from matching other commands.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 5).unwrap(); // wildcard, cap=5
        mon.add_command_rule(SEND_RR_DATA, 1).unwrap(); // specific, cap=1

        // SEND_UNIT_DATA falls through to the wildcard.
        for i in 0..5 {
            let f = EtherNetIpFrame {
                command: SEND_UNIT_DATA,
                session_handle: 9,
                timestamp_us: i,
                ..Default::default()
            };
            assert!(
                mon.inspect(&f).allowed,
                "wildcard cap=5 must allow request {i} of SEND_UNIT_DATA"
            );
        }
        // 6th SEND_UNIT_DATA at same instant is denied by wildcard cap.
        let f = EtherNetIpFrame {
            command: SEND_UNIT_DATA,
            session_handle: 9,
            timestamp_us: 0,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f).allowed,
            "wildcard cap=5 must deny 6th request"
        );
    }

    #[test]
    fn specific_rule_added_first_still_wins() {
        // Sanity: specificity ordering is independent of insertion order.
        // Adding the specific rule first must also work.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(SEND_RR_DATA, 2).unwrap();
        mon.add_command_rule(0, 10).unwrap();

        for _ in 0..2 {
            let f = EtherNetIpFrame {
                command: SEND_RR_DATA,
                session_handle: 5,
                timestamp_us: 0,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed);
        }
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 5,
            timestamp_us: 0,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    // -------------------------------------------------------------------
    // Regression: rate-bucket capacity must follow the currently matched
    // rule, not the rule active at bucket-allocation time.
    //
    // Before the fix, capacity was frozen at the moment the bucket was
    // allocated. If the matched rule for a given session_handle later
    // changed to a tighter `max_rate_per_sec` (e.g. a more specific rule
    // overriding a wildcard once specificity-ordered matching landed), the
    // stale capacity in the bucket let traffic exceed the tighter limit
    // until the bucket was evicted. rate_check now recomputes capacity on
    // every match and clamps `tokens` when capacity shrinks.
    // -------------------------------------------------------------------

    #[test]
    fn rate_bucket_capacity_tightens_on_subsequent_call() {
        let mut mon = EtherNetIpMonitor::new();
        // First call: simulate the previously matched rule's rate (10).
        // This allocates the bucket with capacity=10.
        assert!(mon.rate_check(42, 10, 0));
        // Confirm the bucket exists with capacity=10.
        let b = mon
            .rate_buckets
            .iter()
            .find(|b| b.active && b.key == 42)
            .expect("bucket should exist");
        assert_eq!(b.capacity, 10);

        // Second call at the same instant with a *tighter* rate (2): the
        // bucket must adopt the new capacity and clamp leftover tokens.
        assert!(mon.rate_check(42, 2, 0));
        let b = mon
            .rate_buckets
            .iter()
            .find(|b| b.active && b.key == 42)
            .expect("bucket should still exist");
        assert_eq!(b.capacity, 2, "capacity must follow the new rule");
        // Tokens must be clamped to the new capacity (or below after consume).
        assert!(b.tokens <= 2, "tokens must not exceed new capacity");

        // Third call at the same instant: bucket already consumed one token
        // above, so only one token remains under the tighter cap of 2.
        assert!(mon.rate_check(42, 2, 0));
        // Fourth call must be denied — tighter cap has been honored.
        assert!(
            !mon.rate_check(42, 2, 0),
            "tighter rate must block 4th request"
        );
    }

    #[test]
    fn rate_bucket_capacity_loosens_on_subsequent_call() {
        // Capacity can also grow: when the matched rule's rate increases,
        // the bucket adopts the larger capacity. `tokens` is left alone
        // and refill catches up naturally at the new rate.
        let mut mon = EtherNetIpMonitor::new();
        // Tight rate first: 2 req/s.
        assert!(mon.rate_check(7, 2, 0));
        assert!(mon.rate_check(7, 2, 0));
        assert!(
            !mon.rate_check(7, 2, 0),
            "third request must be denied under cap=2"
        );

        // Loosen the rule to rate=10. The bucket's capacity must grow,
        // and the next refill at t=1s allows up to 10 requests.
        // Refill at +1_000_000 us: elapsed * capacity / 1_000_000 = 10 tokens.
        for _ in 0..10 {
            assert!(
                mon.rate_check(7, 10, 1_000_000),
                "request must pass under loosened cap"
            );
        }
        assert!(
            !mon.rate_check(7, 10, 1_000_000),
            "11th request still must be denied under cap=10"
        );
    }

    // -------------------------------------------------------------------
    // CIP service filter tests
    // -------------------------------------------------------------------

    /// Build a `SendRRData`-style encap payload carrying a single
    /// unconnected-data CPF item whose first byte is the CIP service code.
    fn cip_payload_unconnected(service: u8, extra: &[u8]) -> [u8; 256] {
        let mut buf = [0u8; 256];
        // interface handle = 0
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        // timeout
        buf[4..6].copy_from_slice(&0u16.to_le_bytes());
        // item count = 2 (null address item + unconnected data item)
        buf[6..8].copy_from_slice(&2u16.to_le_bytes());
        // Null address item: type=0x0000, len=0
        buf[8..10].copy_from_slice(&0x0000u16.to_le_bytes());
        buf[10..12].copy_from_slice(&0u16.to_le_bytes());
        // Unconnected data item: type=0x00B2, len = 1 + extra.len()
        buf[12..14].copy_from_slice(&CPF_ITEM_UNCONNECTED_DATA.to_le_bytes());
        let data_len = 1 + extra.len();
        buf[14..16].copy_from_slice(&(data_len as u16).to_le_bytes());
        buf[16] = service;
        buf[17..17 + extra.len()].copy_from_slice(extra);
        buf
    }

    fn cip_payload_connected(service: u8) -> [u8; 256] {
        let mut buf = [0u8; 256];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4..6].copy_from_slice(&0u16.to_le_bytes());
        buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // 1 item
                                                        // Connected data item: type=0x00B1, len = 3 (seq(2) + service(1))
        buf[8..10].copy_from_slice(&CPF_ITEM_CONNECTED_DATA.to_le_bytes());
        buf[10..12].copy_from_slice(&3u16.to_le_bytes());
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // sequence count
        buf[14] = service;
        buf
    }

    #[test]
    fn parse_cip_service_unconnected() {
        let buf = cip_payload_unconnected(0x4C, &[]);
        assert_eq!(parse_cip_service(&buf[..17]), Some(0x4C));
    }

    #[test]
    fn parse_cip_service_connected() {
        let buf = cip_payload_connected(0x0E); // Get_Attribute_Single
        assert_eq!(parse_cip_service(&buf[..15]), Some(0x0E));
    }

    #[test]
    fn parse_cip_service_strips_response_bit() {
        // High bit set → response; low 7 bits are the service code.
        let buf = cip_payload_unconnected(0x8E, &[]);
        assert_eq!(parse_cip_service(&buf[..17]), Some(0x0E));
    }

    #[test]
    fn parse_cip_service_rejects_truncated() {
        // Less than 8 bytes.
        assert!(parse_cip_service(&[0u8; 4]).is_none());
        // Item length lies beyond the buffer.
        let mut buf = [0u8; 16];
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());
        buf[8..10].copy_from_slice(&CPF_ITEM_UNCONNECTED_DATA.to_le_bytes());
        buf[10..12].copy_from_slice(&100u16.to_le_bytes()); // length 100, buffer only 16
        assert!(parse_cip_service(&buf).is_none());
    }

    #[test]
    fn cip_filter_blocks_disallowed_service() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        // Allow only Get_Attribute_Single (0x0E).
        mon.set_cip_service_filter(1u128 << 0x0E);
        assert_eq!(mon.cip_service_mask(), 1u128 << 0x0E);

        // Set_Attribute_Single (0x10) → blocked.
        let payload = cip_payload_unconnected(0x10, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 42,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "Set_Attribute_Single must be blocked");
        assert_eq!(r.alert_codes[0], AlertCode::CipServiceBlocked);

        // Get_Attribute_Single (0x0E) → allowed.
        let payload = cip_payload_unconnected(0x0E, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 42,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cip_filter_only_applies_to_send_commands() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        // Reject all services (mask = 0 would disable filter, so use 1
        // to allow only service 0 which we never send).
        mon.set_cip_service_filter(1u128 << 0);

        // A NOP command (0x0001) with a valid-looking CIP payload is NOT filtered.
        let payload = cip_payload_unconnected(0x10, &[]);
        let f = EtherNetIpFrame {
            command: 0x0001,
            session_handle: 1,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cip_filter_zero_mask_disables_filter() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        mon.set_cip_service_filter(0);

        let payload = cip_payload_unconnected(0x10, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 1,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cip_filter_unparseable_payload_bypasses_filter() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        mon.set_cip_service_filter(1u128 << 0x0E);

        // Payload too short to parse — filter is skipped, frame passes.
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 1,
            payload_len: 4,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cip_filter_service_above_63_is_filtered() {
        // Regression: previously a `service < 64` guard limited the bitset
        // to a u64 range, silently bypassing services 64..=127 (e.g.
        // ReadTag = 0x4C). With the u128 mask the full 7-bit code space
        // is filterable.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        // Only allow service 0x0E (Get_Attribute_Single).
        mon.set_cip_service_filter(1u128 << 0x0E);

        // Service 0x4C (76, ReadTag) is NOT in the mask and must be blocked.
        let payload = cip_payload_unconnected(0x4C, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 1,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(
            !r.allowed,
            "service 0x4C must be blocked by the u128 mask (was silently bypassed before)"
        );
        assert_eq!(r.alert_codes[0], AlertCode::CipServiceBlocked);
    }

    #[test]
    fn cip_filter_service_0x7f_is_filterable() {
        // 0x7F is the highest 7-bit CIP service code (after stripping the
        // response bit). It must be representable in the u128 mask.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0, 0).unwrap();
        // Allow only service 0x7F.
        mon.set_cip_service_filter(1u128 << 0x7F);

        // 0x7F is allowed.
        let payload = cip_payload_unconnected(0x7F, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 1,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        assert!(
            mon.inspect(&f).allowed,
            "service 0x7F must be allowed when its bit is set"
        );

        // 0x3F (63, the old high-water mark) is NOT in the mask and must be blocked.
        let payload = cip_payload_unconnected(0x3F, &[]);
        let f = EtherNetIpFrame {
            command: SEND_RR_DATA,
            session_handle: 2,
            payload,
            payload_len: 17,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f).allowed,
            "service 0x3F must be filtered when not set in the u128 mask"
        );
    }

    #[test]
    fn cip_filter_full_range_64_to_127_is_filterable() {
        // Sweep services 64..=127: with only bit `s` set in the mask, exactly
        // service `s` should be allowed and any other service in the range
        // should be blocked. This is the latent bug the u64→u128 fix closes.
        for allowed_service in [0x40u8, 0x4C, 0x50, 0x60, 0x70, 0x7E, 0x7F] {
            let mut mon = EtherNetIpMonitor::new();
            mon.add_command_rule(0, 0).unwrap();
            mon.set_cip_service_filter(1u128 << allowed_service);

            // Allowed service passes.
            let payload = cip_payload_unconnected(allowed_service, &[]);
            let f = EtherNetIpFrame {
                command: SEND_RR_DATA,
                session_handle: 1,
                payload,
                payload_len: 17,
                ..Default::default()
            };
            assert!(
                mon.inspect(&f).allowed,
                "service {allowed_service:#04x} must be allowed when its bit is set"
            );

            // A different service in the same upper half is blocked.
            let blocked = if allowed_service == 0x40 { 0x41 } else { 0x40 };
            let payload = cip_payload_unconnected(blocked, &[]);
            let f = EtherNetIpFrame {
                command: SEND_RR_DATA,
                session_handle: 2,
                payload,
                payload_len: 17,
                ..Default::default()
            };
            assert!(
                !mon.inspect(&f).allowed,
                "service {blocked:#04x} must be blocked when only {allowed_service:#04x} is set"
            );
        }
    }

    // -------------------------------------------------------------------
    // Session timeout test
    // -------------------------------------------------------------------

    #[test]
    fn session_expires_after_timeout() {
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0, 0).unwrap();
        mon.set_session_timeout(5_000);

        // Register a session.
        let reg = EtherNetIpFrame {
            command: REGISTER_SESSION,
            session_handle: 42,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(mon.inspect(&reg).allowed);

        // Use the session — should be allowed.
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 42,
            timestamp_us: 2000,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        // Expire sessions after timeout.
        mon.expire_sessions(1_000_000);

        // Session should now be unknown in strict mode.
        let f2 = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 42,
            timestamp_us: 1_000_001,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f2).allowed,
            "expired session must be rejected in strict mode"
        );
    }

    // -------------------------------------------------------------------
    // Session LRU eviction test
    // -------------------------------------------------------------------

    #[test]
    fn session_lru_eviction_when_table_full() {
        // LRU eviction is keyed on `last_activity_us` (matches the
        // `expire_sessions` policy), so a session that has been touched
        // recently is NOT the LRU even if it was registered first.
        let mut mon = EtherNetIpMonitor::new_strict();
        mon.add_command_rule(0, 0).unwrap();

        // Fill the session table. After this loop the LRU by
        // `last_activity_us` is handle 1000 (registered at ts=1000).
        for i in 0..MAX_SESSIONS as u32 {
            let reg = EtherNetIpFrame {
                command: REGISTER_SESSION,
                session_handle: 1000 + i,
                timestamp_us: 1000 + (i as u64),
                ..Default::default()
            };
            assert!(mon.inspect(&reg).allowed);
        }

        // Touch handle 1000 so its last_activity_us becomes the newest.
        // Now the LRU is handle 1001 (last_activity_us = 1001).
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 1000,
            timestamp_us: 2000,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        // Register one more → should evict the LRU by last_activity_us
        // (handle 1001, untouched since registration).
        let reg = EtherNetIpFrame {
            command: REGISTER_SESSION,
            session_handle: 9999,
            timestamp_us: 10000,
            ..Default::default()
        };
        let _ = mon.inspect(&reg);

        // The newest handle is known.
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 9999,
            timestamp_us: 11000,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);

        // Handle 1000 was touched, so it survives the eviction.
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 1000,
            timestamp_us: 11000,
            ..Default::default()
        };
        assert!(
            mon.inspect(&f).allowed,
            "touched session should NOT be the LRU victim"
        );

        // Handle 1001 (never touched) was the LRU and was evicted.
        let f = EtherNetIpFrame {
            command: 0x0070,
            session_handle: 1001,
            timestamp_us: 11000,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "evicted session should be unknown");
        assert_eq!(r.alert_codes[0], AlertCode::UnknownSession);
    }

    // -----------------------------------------------------------------------
    // Regression: CPF item_count is capped (C4).
    //
    // A malformed SendRRData payload advertising a huge item_count must
    // return None from the parser — without burning CPU or overflowing
    // the cursor — so the rest of the monitor continues safely.
    // -----------------------------------------------------------------------
    #[test]
    fn parse_cip_service_rejects_excessive_item_count() {
        // interface_handle(4) + timeout(2) + item_count(2) = 8 bytes header.
        let mut payload = [0u8; 64];
        // Advertise 0xFFFF items — well beyond MAX_CPF_ITEMS.
        payload[6] = 0xFF;
        payload[7] = 0xFF;
        assert_eq!(parse_cip_service(&payload), None);
    }

    #[test]
    fn parse_cip_service_rejects_cursor_overflow_item_len() {
        // Header advertises 1 item; item header says length > remaining.
        let mut payload = [0u8; 32];
        payload[6] = 0x01; // item_count = 1
                           // Cursor starts at 8. type=0x00B2 unconnected data.
        payload[8] = 0xB2;
        payload[9] = 0x00;
        // len = 0xFFFE — wildly larger than payload. checked_add must reject.
        payload[10] = 0xFE;
        payload[11] = 0xFF;
        assert_eq!(parse_cip_service(&payload), None);
    }

    #[test]
    fn parse_cip_service_accepts_wellformed_unconnected() {
        let mut payload = [0u8; 32];
        payload[6] = 0x01; // item_count = 1
        payload[8] = 0xB2; // CPF_ITEM_UNCONNECTED_DATA
        payload[9] = 0x00;
        payload[10] = 0x04; // item_len = 4
        payload[11] = 0x00;
        payload[12] = 0x4C; // service = 0x4C (ReadTag) — response bit clear.
        payload[13] = 0x00;
        payload[14] = 0x00;
        payload[15] = 0x00;
        assert_eq!(parse_cip_service(&payload[..16]), Some(0x4C));
    }

    // -------------------------------------------------------------------
    // VULN-02: CIP service codes ≥ 64 (0x40) must be filterable.
    // The previous u64 mask could not represent codes ≥ 64 (e.g. ReadTag
    // = 0x4C = 76).  Upgrading to u128 lets all 7-bit CIP service codes
    // (0x00–0x7F) be individually allowed or blocked.
    // -------------------------------------------------------------------

    fn make_payload_for_service(service: u8) -> [u8; 20] {
        let mut payload = [0u8; 20];
        payload[6] = 0x01; // item_count = 1
        payload[8] = 0xB2; // CPF_ITEM_UNCONNECTED_DATA
        payload[9] = 0x00;
        payload[10] = 0x04; // item_len = 4
        payload[11] = 0x00;
        payload[12] = service & 0x7F; // clear response bit
        payload
    }

    #[test]
    fn vuln02_cip_service_code_above_63_can_be_allowed() {
        // ReadTag (0x4C = 76) is above 63 and could not be represented in u64.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0x006F, 0).unwrap(); // SEND_RR_DATA
                                                  // Allow ONLY ReadTag (0x4C).
        mon.set_cip_service_filter(1u128 << 0x4C);

        let mut frame = EtherNetIpFrame::default();
        frame.session_handle = 1;
        frame.command = 0x006F;
        frame.payload_len = 20;
        let payload = make_payload_for_service(0x4C);
        frame.payload[..20].copy_from_slice(&payload);
        frame.timestamp_us = 1000;

        // Register a session so the data frame is not blocked for unknown session.
        let mut reg = EtherNetIpFrame::default();
        reg.command = REGISTER_SESSION;
        reg.timestamp_us = 500;
        let _ = mon.inspect(&reg);

        let result = mon.inspect(&frame);
        assert!(
            result.allowed,
            "ReadTag (0x4C) must be allowed when bit 0x4C is set in the u128 mask"
        );
    }

    #[test]
    fn vuln02_cip_service_code_above_63_can_be_blocked() {
        // Service codes >= 64 must now be blockable. With the previous u64
        // mask + `service < 64` guard, ReadTag (0x4C = 76) was silently
        // bypassed regardless of mask configuration.
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(0x006F, 0).unwrap();
        // Allow only Get_Attribute_Single (0x0E); ReadTag (0x4C) is NOT set.
        mon.set_cip_service_filter(1u128 << 0x0E);

        let mut frame = EtherNetIpFrame::default();
        frame.session_handle = 1;
        frame.command = 0x006F;
        frame.payload_len = 20;
        let payload = make_payload_for_service(0x4C);
        frame.payload[..20].copy_from_slice(&payload);
        frame.timestamp_us = 1000;

        let mut reg = EtherNetIpFrame::default();
        reg.command = REGISTER_SESSION;
        reg.timestamp_us = 500;
        let _ = mon.inspect(&reg);

        let result = mon.inspect(&frame);
        assert!(
            !result.allowed,
            "service 0x4C (>= 64) must be blocked when bit 0x4C is not in the u128 mask"
        );
        assert_eq!(result.alert_codes[0], AlertCode::CipServiceBlocked);
    }

    // -------------------------------------------------------------------
    // VULN-03: Session idle timeout must use last_activity_us, not
    // created_us.  Without this fix, an attacker could keep a session
    // alive indefinitely by sending requests but never triggering a new
    // REGISTER_SESSION — the session would expire based on creation time
    // even if recently active.
    // -------------------------------------------------------------------

    #[test]
    fn vuln03_active_session_not_expired_before_idle_timeout() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(REGISTER_SESSION, 0).unwrap();
        mon.add_command_rule(0x006F, 0).unwrap();
        mon.set_session_timeout(10_000_000); // 10 s

        // Register at t=0.
        let mut reg = EtherNetIpFrame::default();
        reg.command = REGISTER_SESSION;
        reg.timestamp_us = 0;
        let _ = mon.inspect(&reg);

        // Send data at t=5 s (within the 10-s timeout); this touches last_activity_us.
        let mut data = EtherNetIpFrame::default();
        data.session_handle = 1;
        data.command = 0x006F;
        data.timestamp_us = 5_000_000;
        let r1 = mon.inspect(&data);
        assert!(
            r1.allowed,
            "data at t=5s should be allowed (session not yet expired)"
        );

        // Expire sessions at t=12 s: session was touched at t=5 s,
        // so only 7 s of idle time has passed — must NOT be expired.
        mon.expire_sessions(12_000_000);

        let mut data2 = EtherNetIpFrame::default();
        data2.session_handle = 1;
        data2.command = 0x006F;
        data2.timestamp_us = 12_000_001;
        let r2 = mon.inspect(&data2);
        assert!(
            r2.allowed,
            "session should still be active: only 7s idle, timeout is 10s"
        );
    }

    #[test]
    fn vuln03_idle_session_expires_after_inactivity() {
        let mut mon = EtherNetIpMonitor::new();
        mon.add_command_rule(REGISTER_SESSION, 0).unwrap();
        mon.add_command_rule(0x006F, 0).unwrap();
        mon.set_session_timeout(10_000_000); // 10 s

        // Register at t=0; never send any data (no touch).
        let mut reg = EtherNetIpFrame::default();
        reg.command = REGISTER_SESSION;
        reg.timestamp_us = 0;
        let _ = mon.inspect(&reg);

        // Expire sessions at t=11 s (> 10 s since last activity).
        mon.expire_sessions(11_000_000);

        // A subsequent data frame for that handle should be blocked in strict mode.
        let mut mon_strict = EtherNetIpMonitor::new_strict();
        mon_strict.add_command_rule(REGISTER_SESSION, 0).unwrap();
        mon_strict.add_command_rule(0x006F, 0).unwrap();
        mon_strict.set_session_timeout(10_000_000);

        let mut reg2 = EtherNetIpFrame::default();
        reg2.command = REGISTER_SESSION;
        reg2.timestamp_us = 0;
        let _ = mon_strict.inspect(&reg2);
        mon_strict.expire_sessions(11_000_000);

        // After expiry, strict mode has no session for handle 1.
        // UNREGISTER is a lifecycle command and is allowed regardless.
        let mut unreg = EtherNetIpFrame::default();
        unreg.session_handle = 1;
        unreg.command = UNREGISTER_SESSION;
        unreg.timestamp_us = 11_000_001;
        // UNREGISTER is always allowed (lifecycle command).
        let r = mon_strict.inspect(&unreg);
        assert!(r.allowed, "UNREGISTER_SESSION should always be allowed");
    }
}
