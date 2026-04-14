#![no_std]

//! Siemens S7comm / S7comm-plus intrusion detection monitor.
//!
//! Monitors S7comm traffic for security violations:
//!
//! - **PDU-type allowlist** -- restrict allowed PDU types (e.g., allow only
//!   job request/response, block data and system-status PDUs).
//! - **Function-code allowlist** -- per-rule bitmask of allowed function codes.
//! - **Write protection** -- block write operations (`WriteVar`,
//!   `RequestDownload`, `DownloadBlock`, `DownloadEnded`, `PlcControl`,
//!   `PlcStop`) when a rule is read-only.
//! - **SZL filtering** -- block `UserData` PDU type when `block_szl` is
//!   enabled (SZL-Read enumerates device capabilities).
//! - **Rate limiting** -- per-function-code request rate cap with
//!   LRU-evicted token buckets.
//!
//! # References
//!
//! - Wireshark s7comm dissector source
//! - ICS-CERT advisory ICSA-12-212-01 (S7comm vulnerabilities)

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, InspectResult, RateBucket, SOURCE_S7COMM};

/// Backward-compatible type alias.
pub type S7commInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum function rules.
const MAX_RULES: usize = 16;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------

/// S7comm PDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7commPduType {
    /// Job request (master -> PLC).
    JobRequest = 0x01,
    /// Ack data (PLC -> master, with data).
    AckData = 0x03,
    /// User data (for SZL reads, cyclic services, etc.).
    UserData = 0x07,
    /// Unknown / unparseable PDU type.
    Unknown = 0xFF,
}

impl S7commPduType {
    /// Parse from a raw byte.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::JobRequest,
            0x03 => Self::AckData,
            0x07 => Self::UserData,
            _ => Self::Unknown,
        }
    }
}

/// S7comm function codes (job-layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7commFunction {
    /// Read variable.
    ReadVar = 0x04,
    /// Write variable.
    WriteVar = 0x05,
    /// Request download (begin).
    RequestDownload = 0x1A,
    /// Download block.
    DownloadBlock = 0x1B,
    /// Download ended.
    DownloadEnded = 0x1C,
    /// Start upload.
    StartUpload = 0x1D,
    /// Upload.
    Upload = 0x1E,
    /// End upload.
    EndUpload = 0x1F,
    /// PLC control (run, stop, etc.).
    PlcControl = 0x28,
    /// PLC stop.
    PlcStop = 0x29,
    /// Unknown function code.
    Unknown = 0xFF,
}

impl S7commFunction {
    /// Parse from a raw byte.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x04 => Self::ReadVar,
            0x05 => Self::WriteVar,
            0x1A => Self::RequestDownload,
            0x1B => Self::DownloadBlock,
            0x1C => Self::DownloadEnded,
            0x1D => Self::StartUpload,
            0x1E => Self::Upload,
            0x1F => Self::EndUpload,
            0x28 => Self::PlcControl,
            0x29 => Self::PlcStop,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this function code modifies PLC state.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::WriteVar
                | Self::RequestDownload
                | Self::DownloadBlock
                | Self::DownloadEnded
                | Self::PlcControl
                | Self::PlcStop
        )
    }

    /// Map known function codes to bit positions 0..=9 for `fc_mask` checking.
    ///
    /// Returns `None` for `Unknown` (0xFF) since it has no assigned bit.
    fn bit_index(self) -> Option<u8> {
        match self {
            Self::ReadVar => Some(0),
            Self::WriteVar => Some(1),
            Self::RequestDownload => Some(2),
            Self::DownloadBlock => Some(3),
            Self::DownloadEnded => Some(4),
            Self::StartUpload => Some(5),
            Self::Upload => Some(6),
            Self::EndUpload => Some(7),
            Self::PlcControl => Some(8),
            Self::PlcStop => Some(9),
            Self::Unknown => None,
        }
    }
}

/// An S7comm frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct S7commFrame {
    /// PDU type.
    pub pdu_type: S7commPduType,
    /// Raw PDU type byte (for detecting unknown types).
    pub raw_pdu_type: u8,
    /// Function code.
    pub function: S7commFunction,
    /// Raw function code byte.
    pub raw_function: u8,
    /// PDU reference (sequence number).
    pub pdu_ref: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl Default for S7commFrame {
    fn default() -> Self {
        Self {
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            pdu_ref: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Function rule
// ---------------------------------------------------------------------------

/// Security rule for an S7comm function code.
#[derive(Debug, Clone, Copy)]
struct FunctionRule {
    /// Raw function code to match (0xFF = wildcard, matches any).
    raw_function: u8,
    /// Bitmask of allowed function codes. Bit positions map to
    /// [`S7commFunction::bit_index`] values (bit 0 = `ReadVar`, bit 1 = `WriteVar`,
    /// ..., bit 9 = `PlcStop`). A set bit means the function code is allowed.
    fc_mask: u32,
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
            read_only: false,
            block_szl: false,
            max_rate_per_sec: 0,
            active: false,
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
/// Approximate stack usage: ~500 bytes.
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
        }
    }

    /// Create a monitor in strict mode (block unknown PDU types).
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Add a function rule.
    ///
    /// `raw_function` is the raw byte to match against the frame's
    /// `raw_function` field. Use `0xFF` as a wildcard to match any function.
    ///
    /// `fc_mask` is a bitmask where bit positions map to known function codes.
    /// Set bits allow the corresponding function code; clear bits block it.
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
        if self.rule_count as usize >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
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

        // 2. Find matching rule (fast path: check last matched index first).
        let matched = self.find_matching_rule(frame.raw_function);

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

        // 3. Function code policy check (fc_mask).
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

        // 4. Write protection.
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

        // 5. SZL filtering: block UserData PDU if block_szl is enabled.
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

        // 6. Rate limiting.
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

        result
    }

    /// Find the first matching function rule.
    ///
    /// Always iterates every rule to avoid timing side-channels that could
    /// leak which rule matched.
    fn find_matching_rule(&self, raw_function: u8) -> Option<usize> {
        let mut result: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            if r.active
                && (r.raw_function == 0xFF || r.raw_function == raw_function)
                && result.is_none()
            {
                result = Some(i);
            }
        }
        result
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

    /// Reset all state. Settings (`strict_mode`) are preserved; rules, counters,
    /// and rate buckets are cleared.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        *self = Self::new();
        self.strict_mode = strict;
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
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- PDU type parsing (existing tests) --

    #[test]
    fn s7comm_pdu_type_from_u8() {
        assert_eq!(S7commPduType::from_u8(0x01), S7commPduType::JobRequest);
        assert_eq!(S7commPduType::from_u8(0x03), S7commPduType::AckData);
        assert_eq!(S7commPduType::from_u8(0x07), S7commPduType::UserData);
        assert_eq!(S7commPduType::from_u8(0xFF), S7commPduType::Unknown);
        assert_eq!(S7commPduType::from_u8(0x99), S7commPduType::Unknown);
    }

    // -- Function code parsing (existing tests) --

    #[test]
    fn s7comm_function_from_u8() {
        assert_eq!(S7commFunction::from_u8(0x04), S7commFunction::ReadVar);
        assert_eq!(S7commFunction::from_u8(0x05), S7commFunction::WriteVar);
        assert_eq!(S7commFunction::from_u8(0x28), S7commFunction::PlcControl);
        assert_eq!(S7commFunction::from_u8(0xFF), S7commFunction::Unknown);
    }

    // -- is_write (existing tests) --

    #[test]
    fn s7comm_function_is_write() {
        assert!(!S7commFunction::ReadVar.is_write());
        assert!(S7commFunction::WriteVar.is_write());
        assert!(S7commFunction::RequestDownload.is_write());
        assert!(S7commFunction::PlcControl.is_write());
        assert!(S7commFunction::PlcStop.is_write());
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
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            pdu_ref: 1,
            timestamp_us: 1000,
        };
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        assert!(result.alert_count > 0);
    }

    #[test]
    fn strict_blocks_no_matching_rule() {
        let mut mon = S7commMonitor::new_strict();
        // No rules added. Any known frame should be blocked.
        let frame = S7commFrame {
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            pdu_ref: 1,
            timestamp_us: 1000,
        };
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        assert!(result.alert_count > 0);
    }

    #[test]
    fn strict_allows_configured_function() {
        let mut mon = S7commMonitor::new_strict();
        // Wildcard rule matching any function, all FCs allowed.
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();
        let frame = S7commFrame::default();
        let result = mon.inspect(&frame);
        assert!(result.allowed);
    }

    #[test]
    fn strict_allows_specific_function_match() {
        let mut mon = S7commMonitor::new_strict();
        // Rule specifically for ReadVar (0x04), all FCs allowed.
        mon.add_rule(0x04, 0xFFFF_FFFF, false, false, 0).unwrap();
        let frame = S7commFrame {
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        let result = mon.inspect(&frame);
        assert!(result.allowed);

        // WriteVar (0x05) has no matching rule => blocked.
        let frame2 = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            ..Default::default()
        };
        let result2 = mon.inspect(&frame2);
        assert!(!result2.allowed);
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
            ..Default::default()
        };
        assert!(!mon.inspect(&write).allowed);
    }

    #[test]
    fn fc_mask_allows_multiple() {
        let mut mon = S7commMonitor::new();
        // Allow ReadVar (bit 0) and Upload (bit 6).
        mon.add_rule(0xFF, (1 << 0) | (1 << 6), false, false, 0)
            .unwrap();

        let read = S7commFrame {
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        assert!(mon.inspect(&read).allowed);

        let upload = S7commFrame {
            function: S7commFunction::Upload,
            raw_function: 0x1E,
            ..Default::default()
        };
        assert!(mon.inspect(&upload).allowed);

        let download = S7commFrame {
            function: S7commFunction::DownloadBlock,
            raw_function: 0x1B,
            ..Default::default()
        };
        assert!(!mon.inspect(&download).allowed);
    }

    // -- Write protection --

    #[test]
    fn write_protection_blocks_writes() {
        let mut mon = S7commMonitor::new();
        // Wildcard rule, all FCs allowed, read-only.
        mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0).unwrap();

        let write = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            ..Default::default()
        };
        assert!(!mon.inspect(&write).allowed);

        let plc_control = S7commFrame {
            function: S7commFunction::PlcControl,
            raw_function: 0x28,
            ..Default::default()
        };
        assert!(!mon.inspect(&plc_control).allowed);

        let plc_stop = S7commFrame {
            function: S7commFunction::PlcStop,
            raw_function: 0x29,
            ..Default::default()
        };
        assert!(!mon.inspect(&plc_stop).allowed);

        let download = S7commFrame {
            function: S7commFunction::RequestDownload,
            raw_function: 0x1A,
            ..Default::default()
        };
        assert!(!mon.inspect(&download).allowed);
    }

    #[test]
    fn write_protection_allows_reads() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0).unwrap();

        let read = S7commFrame {
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        assert!(mon.inspect(&read).allowed);

        let upload = S7commFrame {
            function: S7commFunction::Upload,
            raw_function: 0x1E,
            ..Default::default()
        };
        assert!(mon.inspect(&upload).allowed);
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

    #[test]
    fn szl_filtering_allows_non_userdata() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, true, 0).unwrap();

        let job = S7commFrame {
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            ..Default::default()
        };
        assert!(mon.inspect(&job).allowed);
    }

    // -- Rate limiting --

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = S7commMonitor::new();
        // Allow 2 requests per second.
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 2).unwrap();

        let frame = S7commFrame {
            timestamp_us: 1_000_000,
            ..Default::default()
        };
        // First two should pass.
        assert!(mon.inspect(&frame).allowed);
        assert!(mon.inspect(&frame).allowed);
        // Third should be blocked (same timestamp, no refill).
        assert!(!mon.inspect(&frame).allowed);
    }

    #[test]
    fn rate_limiting_refills_over_time() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 1).unwrap();

        let frame1 = S7commFrame {
            timestamp_us: 1_000_000,
            ..Default::default()
        };
        assert!(mon.inspect(&frame1).allowed);

        // Should be blocked at same time.
        assert!(!mon.inspect(&frame1).allowed);

        // After 1 second, should refill.
        let frame2 = S7commFrame {
            timestamp_us: 2_000_001,
            ..Default::default()
        };
        assert!(mon.inspect(&frame2).allowed);
    }

    #[test]
    fn rate_limiting_zero_means_unlimited() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();

        let frame = S7commFrame::default();
        for _ in 0..100 {
            assert!(mon.inspect(&frame).allowed);
        }
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
        // Strict mode should be preserved.
        assert!(mon.strict_mode());
    }

    #[test]
    fn reset_clears_rules() {
        let mut mon = S7commMonitor::new_strict();
        mon.add_rule(0xFF, 0xFFFF_FFFF, false, false, 0).unwrap();
        let frame = S7commFrame::default();
        assert!(mon.inspect(&frame).allowed);

        mon.reset();
        // After reset, no rules remain, so strict mode blocks.
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
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

    // -- Counter checks --

    #[test]
    fn total_inspected_increments() {
        let mut mon = S7commMonitor::new();
        let frame = S7commFrame::default();
        assert_eq!(mon.total_inspected(), 0);
        let _ = mon.inspect(&frame);
        assert_eq!(mon.total_inspected(), 1);
        let _ = mon.inspect(&frame);
        assert_eq!(mon.total_inspected(), 2);
    }

    #[test]
    fn total_alerts_increments_on_block() {
        let mut mon = S7commMonitor::new_strict();
        let frame = S7commFrame::default(); // no rule => blocked
        let _ = mon.inspect(&frame);
        assert!(mon.total_alerts() > 0);
    }

    // -- Write protection alert has High severity --

    #[test]
    fn write_protection_alert_severity() {
        let mut mon = S7commMonitor::new();
        mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0).unwrap();
        let frame = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            ..Default::default()
        };
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
        assert_eq!(result.alerts[0].severity, AlertSeverity::High);
    }

    // -- Combination: fc_mask takes precedence over write protection --

    #[test]
    fn fc_mask_checked_before_write_protection() {
        let mut mon = S7commMonitor::new();
        // Only allow ReadVar (bit 0), read-only mode.
        // WriteVar should be blocked by fc_mask (PolicyViolation) not write protection.
        mon.add_rule(0xFF, 1 << 0, true, false, 0).unwrap();
        let frame = S7commFrame {
            function: S7commFunction::WriteVar,
            raw_function: 0x05,
            ..Default::default()
        };
        let result = mon.inspect(&frame);
        assert!(!result.allowed);
        // Should be PolicyViolation from fc_mask, not WriteProtection.
        assert_eq!(result.alert_codes[0], AlertCode::PolicyViolation);
    }
}
