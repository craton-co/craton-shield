#![no_std]

//! IEC 60870-5-104 telecontrol intrusion detection monitor.
//!
//! Monitors IEC 60870-5-104 traffic for security violations:
//!
//! - **`TypeID` allowlist** — restrict allowed `ASDU` type identifiers using a
//!   256-bit bitmask; block command `TypeIDs` (45–51, 58–64) unless explicitly
//!   permitted.
//! - **COT filtering** — Cause of Transmission filtering rejects frames with
//!   unexpected COT values.
//! - **Write protection** — block command `TypeIDs` when the matched rule is
//!   read-only and the COT indicates activation/deactivation.
//! - **I-frame sequence tracking** — detect sequence number gaps or replays
//!   using a forward-progress window.
//! - **Rate limiting** — per-TypeID request rate cap.
//!
//! # References
//!
//! - IEC 60870-5-104:2006 (TCP/IP-based telecontrol)
//! - NIST SP 800-82 Rev.3 §4.6 (SCADA security)

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, InspectResult, RateBucket, SOURCE_IEC60870};

/// Backward-compatible type alias.
pub type Iec60870InspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_RULES: usize = 16;
const MAX_RATE_BUCKETS: usize = 16;
const MAX_SEQ_ENTRIES: usize = 16;

/// Forward-progress window for I-frame 15-bit sequence numbers (0–32767).
const SEQ_WINDOW: u16 = 1024;

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------

/// IEC 60870-5-104 frame format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Iec60870FrameFormat {
    /// I-format — numbered information transfer.
    I = 0,
    /// S-format — supervisory (acknowledgement).
    S = 1,
    /// U-format — unnumbered (STARTDT, STOPDT, TESTFR).
    U = 2,
    /// Unknown frame format.
    Unknown = 0xFF,
}

/// Cause of Transmission (COT) — 6-bit field from the ASDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Iec60870Cot {
    Periodic = 1,
    Background = 2,
    Spontaneous = 3,
    Initialized = 4,
    Interrogation = 5,
    Activation = 6,
    ActivationConfirmation = 7,
    Deactivation = 8,
    DeactivationConfirmation = 9,
    ActivationTermination = 10,
    Unknown = 0xFF,
}

impl Iec60870Cot {
    /// Parse from a raw byte (6-bit value, bits 0-5).
    pub fn from_u8(v: u8) -> Self {
        match v & 0x3F {
            1 => Self::Periodic,
            2 => Self::Background,
            3 => Self::Spontaneous,
            4 => Self::Initialized,
            5 => Self::Interrogation,
            6 => Self::Activation,
            7 => Self::ActivationConfirmation,
            8 => Self::Deactivation,
            9 => Self::DeactivationConfirmation,
            10 => Self::ActivationTermination,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this COT indicates a command (activation or
    /// deactivation) — used for write-protection decisions.
    pub fn is_command(self) -> bool {
        matches!(self, Self::Activation | Self::Deactivation)
    }
}

/// An IEC 60870-5-104 frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct Iec60870Frame {
    pub frame_format: Iec60870FrameFormat,
    pub type_id: u8,
    pub cot: Iec60870Cot,
    pub raw_cot: u8,
    pub asdu_address: u16,
    pub send_seq: u16,
    pub recv_seq: u16,
    pub timestamp_us: u64,
}

impl Default for Iec60870Frame {
    fn default() -> Self {
        Self {
            frame_format: Iec60870FrameFormat::I,
            type_id: 0,
            cot: Iec60870Cot::Spontaneous,
            raw_cot: 3,
            asdu_address: 1,
            send_seq: 0,
            recv_seq: 0,
            timestamp_us: 0,
        }
    }
}

impl Iec60870Frame {
    /// Returns `true` if the `TypeID` represents a command (write) operation.
    pub fn is_command_type_id(type_id: u8) -> bool {
        matches!(type_id, 45..=51 | 58..=64)
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct SeqEntry {
    key: u16,
    last_seq: u16,
    has_seen: bool,
    active: bool,
    last_used: u32,
}

impl SeqEntry {
    const fn empty() -> Self {
        Self {
            key: 0,
            last_seq: 0,
            has_seen: false,
            active: false,
            last_used: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AsduRule {
    asdu_address: u16,
    read_only: bool,
    max_rate_per_sec: u16,
    active: bool,
}

impl AsduRule {
    const fn empty() -> Self {
        Self {
            asdu_address: 0xFFFF,
            read_only: false,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// IEC 60870-5-104 intrusion detection monitor.
pub struct Iec60870Monitor {
    rules: [AsduRule; MAX_RULES],
    rule_count: u8,
    strict_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
    type_id_low: u128,
    type_id_high: u128,
    cot_filter: u16,
    seq_table: [SeqEntry; MAX_SEQ_ENTRIES],
    seq_tick: u32,
    seq_validation: bool,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    rate_tick: u32,
}

impl Iec60870Monitor {
    pub fn new() -> Self {
        Self {
            rules: [AsduRule::empty(); MAX_RULES],
            rule_count: 0,
            strict_mode: false,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            type_id_low: 0,
            type_id_high: 0,
            cot_filter: 0,
            seq_table: [SeqEntry::empty(); MAX_SEQ_ENTRIES],
            seq_tick: 0,
            seq_validation: true,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            rate_tick: 0,
        }
    }

    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Set the `TypeID` allowlist. `low` covers 0–127, `high` covers 128–255.
    /// Pass `(0, 0)` to disable filtering.
    pub fn set_type_id_allowlist(&mut self, low: u128, high: u128) {
        self.type_id_low = low;
        self.type_id_high = high;
    }

    /// Set COT filter bitmask. Bit N = COT N allowed. 0 = disabled.
    pub fn set_cot_filter(&mut self, mask: u16) {
        self.cot_filter = mask;
    }

    pub fn set_seq_validation(&mut self, enabled: bool) {
        self.seq_validation = enabled;
    }

    pub fn add_rule(
        &mut self,
        asdu_address: u16,
        read_only: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && self.rules[i].asdu_address == asdu_address {
                return Err(VsError::InvalidInput);
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = AsduRule {
            asdu_address,
            read_only,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn inspect(&mut self, frame: &Iec60870Frame) -> Iec60870InspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);

        if frame.frame_format != Iec60870FrameFormat::I {
            return InspectResult::clean(SOURCE_IEC60870);
        }

        let mut result = InspectResult::clean(SOURCE_IEC60870);

        // TypeID allowlist.
        if self.type_id_low != 0 || self.type_id_high != 0 {
            let tid = frame.type_id;
            let allowed = if tid < 128 {
                (self.type_id_low >> tid) & 1 == 1
            } else {
                (self.type_id_high >> (tid - 128)) & 1 == 1
            };
            if !allowed {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC60870,
                    frame.asdu_address as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::UnknownFunctionCode,
                );
                return result;
            }
        }

        // COT filtering.
        if self.cot_filter != 0 {
            let cot_val = frame.raw_cot & 0x3F;
            let allowed = cot_val < 16 && (self.cot_filter >> cot_val) & 1 == 1;
            if !allowed {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC60870,
                    frame.asdu_address as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::PolicyViolation,
                );
                return result;
            }
        }

        // Sequence tracking.
        if self.seq_validation {
            if let Some(replay) = self.check_seq(frame.asdu_address, frame.send_seq) {
                if replay {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::High,
                        SOURCE_IEC60870,
                        frame.asdu_address as u32,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::ReplayDetected,
                    );
                    return result;
                }
            }
        }

        // Rule matching.
        let matched = self.find_matching_rule(frame.asdu_address);

        // Write protection.
        if let Some(rule_idx) = matched {
            if self.rules[rule_idx].read_only
                && Iec60870Frame::is_command_type_id(frame.type_id)
                && frame.cot.is_command()
            {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC60870,
                    frame.asdu_address as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::WriteProtection,
                );
                return result;
            }
        }

        let Some(rule_idx) = matched else {
            if self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC60870,
                    frame.asdu_address as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::NoMatchingRule,
                );
            }
            return result;
        };

        // Rate limiting.
        let max_rate = self.rules[rule_idx].max_rate_per_sec;
        if max_rate > 0 && !self.rate_check(frame.type_id as u32, max_rate, frame.timestamp_us) {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_IEC60870,
                frame.asdu_address as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::RateExceeded,
            );
        }

        result
    }

    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let tid_low = self.type_id_low;
        let tid_high = self.type_id_high;
        let cot = self.cot_filter;
        let seq_val = self.seq_validation;
        *self = Self::new();
        self.strict_mode = strict;
        self.type_id_low = tid_low;
        self.type_id_high = tid_high;
        self.cot_filter = cot;
        self.seq_validation = seq_val;
    }

    /// Find the first matching ASDU address rule.
    ///
    /// Always iterates every rule to avoid timing side-channels that could
    /// leak which rule matched.
    fn find_matching_rule(&self, asdu_address: u16) -> Option<usize> {
        let mut result: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            if r.active
                && (r.asdu_address == 0xFFFF || r.asdu_address == asdu_address)
                && result.is_none()
            {
                result = Some(i);
            }
        }
        result
    }

    fn check_seq(&mut self, key: u16, seq: u16) -> Option<bool> {
        let seq = seq & 0x7FFF;
        self.seq_tick = self.seq_tick.wrapping_add(1);
        let now = self.seq_tick;

        for entry in &mut self.seq_table {
            if entry.active && entry.key == key {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_seq = seq;
                    entry.has_seen = true;
                    return Some(false);
                }
                let diff = seq.wrapping_sub(entry.last_seq) & 0x7FFF;
                if diff == 0 {
                    return Some(true);
                }
                if diff > SEQ_WINDOW {
                    entry.last_seq = seq;
                    return Some(true);
                }
                entry.last_seq = seq;
                return Some(false);
            }
        }

        for entry in &mut self.seq_table {
            if !entry.active {
                *entry = SeqEntry {
                    key,
                    last_seq: seq,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                return None;
            }
        }

        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.seq_table.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        self.seq_table[victim] = SeqEntry {
            key,
            last_seq: seq,
            has_seen: true,
            active: true,
            last_used: now,
        };
        None
    }

    fn rate_check(&mut self, key: u32, max_rate: u16, now_us: u64) -> bool {
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;
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
}

impl Default for Iec60870Monitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cot_from_u8() {
        assert_eq!(Iec60870Cot::from_u8(1), Iec60870Cot::Periodic);
        assert_eq!(Iec60870Cot::from_u8(6), Iec60870Cot::Activation);
        assert_eq!(Iec60870Cot::from_u8(0xFF), Iec60870Cot::Unknown);
        assert_eq!(Iec60870Cot::from_u8(0b1100_0110), Iec60870Cot::Activation);
    }

    #[test]
    fn cot_is_command() {
        assert!(Iec60870Cot::Activation.is_command());
        assert!(Iec60870Cot::Deactivation.is_command());
        assert!(!Iec60870Cot::Spontaneous.is_command());
    }

    #[test]
    fn frame_is_command_type_id() {
        assert!(Iec60870Frame::is_command_type_id(45));
        assert!(Iec60870Frame::is_command_type_id(51));
        assert!(Iec60870Frame::is_command_type_id(58));
        assert!(Iec60870Frame::is_command_type_id(64));
        assert!(!Iec60870Frame::is_command_type_id(1));
        assert!(!Iec60870Frame::is_command_type_id(44));
        assert!(!Iec60870Frame::is_command_type_id(65));
    }

    #[test]
    fn permissive_allows_unknown() {
        let mut mon = Iec60870Monitor::new();
        let f = Iec60870Frame {
            asdu_address: 99,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_blocks_unknown() {
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            asdu_address: 99,
            send_seq: 0,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_allows_configured() {
        let mut mon = Iec60870Monitor::new_strict();
        mon.add_rule(1, false, 0).unwrap();
        let f = Iec60870Frame {
            asdu_address: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn type_id_allowlist_blocks() {
        let mut mon = Iec60870Monitor::new();
        mon.set_type_id_allowlist(1u128 << 1, 0);
        let f = Iec60870Frame {
            type_id: 45,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn type_id_allowlist_allows() {
        let mut mon = Iec60870Monitor::new();
        mon.set_type_id_allowlist(1u128 << 1 | 1u128 << 45, 0);
        let f = Iec60870Frame {
            type_id: 45,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn cot_filter_blocks() {
        let mut mon = Iec60870Monitor::new();
        mon.set_cot_filter(1u16 << 3);
        let f = Iec60870Frame {
            raw_cot: 6,
            cot: Iec60870Cot::Activation,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn cot_filter_allows() {
        let mut mon = Iec60870Monitor::new();
        mon.set_cot_filter(1u16 << 3);
        let f = Iec60870Frame {
            raw_cot: 3,
            cot: Iec60870Cot::Spontaneous,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn write_protection_blocks_command() {
        let mut mon = Iec60870Monitor::new();
        mon.add_rule(1, true, 0).unwrap();
        let f = Iec60870Frame {
            type_id: 45,
            cot: Iec60870Cot::Activation,
            raw_cot: 6,
            asdu_address: 1,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn write_protection_allows_read() {
        let mut mon = Iec60870Monitor::new();
        mon.add_rule(1, true, 0).unwrap();
        let f = Iec60870Frame {
            type_id: 1,
            asdu_address: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn seq_replay_detected() {
        let mut mon = Iec60870Monitor::new();
        let f = Iec60870Frame {
            send_seq: 5,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
        assert!(!mon.inspect(&f).allowed); // duplicate
    }

    #[test]
    fn seq_forward_ok() {
        let mut mon = Iec60870Monitor::new();
        let f1 = Iec60870Frame {
            send_seq: 5,
            ..Default::default()
        };
        let _ = mon.inspect(&f1);
        let f2 = Iec60870Frame {
            send_seq: 6,
            ..Default::default()
        };
        assert!(mon.inspect(&f2).allowed);
    }

    #[test]
    fn s_frame_passes() {
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::S,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn u_frame_passes() {
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::U,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn rate_limiting() {
        let mut mon = Iec60870Monitor::new();
        mon.add_rule(1, false, 2).unwrap();
        let mk = |seq, ts| Iec60870Frame {
            type_id: 1,
            asdu_address: 1,
            send_seq: seq,
            timestamp_us: ts,
            cot: Iec60870Cot::Spontaneous,
            raw_cot: 3,
            ..Default::default()
        };
        assert!(mon.inspect(&mk(1, 1000)).allowed);
        assert!(mon.inspect(&mk(2, 1000)).allowed);
        assert!(!mon.inspect(&mk(3, 1000)).allowed);
        assert!(mon.inspect(&mk(4, 1_001_000)).allowed);
    }

    #[test]
    fn wildcard_rule() {
        let mut mon = Iec60870Monitor::new_strict();
        mon.add_rule(0xFFFF, false, 0).unwrap();
        let f = Iec60870Frame {
            asdu_address: 42,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn duplicate_rule_rejected() {
        let mut mon = Iec60870Monitor::new();
        mon.add_rule(1, false, 0).unwrap();
        assert_eq!(mon.add_rule(1, true, 0), Err(VsError::InvalidInput));
    }

    #[test]
    fn reset_preserves_settings() {
        let mut mon = Iec60870Monitor::new_strict();
        mon.set_type_id_allowlist(42, 0);
        mon.add_rule(1, false, 0).unwrap();
        let f = Iec60870Frame {
            asdu_address: 1,
            ..Default::default()
        };
        let _ = mon.inspect(&f);
        assert_eq!(mon.total_inspected(), 1);
        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        assert!(mon.strict_mode());
    }
}
