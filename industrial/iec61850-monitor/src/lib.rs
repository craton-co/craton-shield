#![no_std]

//! IEC 61850 MMS / GOOSE intrusion detection monitor.
//!
//! Monitors IEC 61850 traffic for security violations:
//!
//! ## MMS (Manufacturing Message Specification)
//!
//! - **Service-type allowlist** — bitmask filter for MMS service types.
//! - **Write protection** — block Write, Define/Delete operations.
//! - **Rate limiting** — per-invoke-ID token buckets.
//!
//! ## GOOSE (Generic Object Oriented Substation Event)
//!
//! - **Publisher allowlist** — restrict allowed (`src_mac`, `GoCBRef`) pairs.
//! - **Replay detection** — stNum/sqNum tracking.
//! - **Test-flag blocking** — optionally block test frames.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{
    AlertCode, InspectResult, RateBucket, SOURCE_IEC61850_GOOSE, SOURCE_IEC61850_MMS,
};

/// Backward-compatible type aliases.
pub type Iec61850MmsInspectResult = InspectResult;
pub type Iec61850GooseInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_MMS_RULES: usize = 16;
const MAX_RATE_BUCKETS: usize = 16;
const MAX_GOOSE_PUBLISHERS: usize = 16;
const MAX_GOOSE_SEQ_ENTRIES: usize = 16;

// ---------------------------------------------------------------------------
// MMS frame types
// ---------------------------------------------------------------------------

/// MMS confirmed service types relevant for IDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MmsServiceType {
    Read = 1,
    Write = 2,
    GetNameList = 3,
    GetVariableAccessAttributes = 4,
    DefineNamedVariable = 5,
    DeleteNamedVariable = 6,
    GetDataValues = 7,
    SetDataValues = 8,
    Initiate = 9,
    Conclude = 10,
    Unknown = 0xFF,
}

impl MmsServiceType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::GetNameList,
            4 => Self::GetVariableAccessAttributes,
            5 => Self::DefineNamedVariable,
            6 => Self::DeleteNamedVariable,
            7 => Self::GetDataValues,
            8 => Self::SetDataValues,
            9 => Self::Initiate,
            10 => Self::Conclude,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this service modifies substation state.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::Write
                | Self::DefineNamedVariable
                | Self::DeleteNamedVariable
                | Self::SetDataValues
        )
    }
}

/// Maximum MMS domain/item identifier length.
pub const MAX_MMS_DOMAIN_LEN: usize = 64;

/// An IEC 61850 MMS frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct MmsFrame {
    pub service_type: MmsServiceType,
    pub raw_service_type: u8,
    pub domain: [u8; MAX_MMS_DOMAIN_LEN],
    pub domain_len: u8,
    pub invoke_id: u32,
    pub timestamp_us: u64,
}

impl Default for MmsFrame {
    fn default() -> Self {
        Self {
            service_type: MmsServiceType::Read,
            raw_service_type: 1,
            domain: [0u8; MAX_MMS_DOMAIN_LEN],
            domain_len: 0,
            invoke_id: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// GOOSE frame types
// ---------------------------------------------------------------------------

/// Maximum GOOSE control block reference length.
pub const MAX_GOOSE_GOCBREF_LEN: usize = 64;

/// An IEC 61850 GOOSE frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct GooseFrame {
    pub src_mac: [u8; 6],
    pub go_cb_ref: [u8; MAX_GOOSE_GOCBREF_LEN],
    pub go_cb_ref_len: u8,
    pub st_num: u32,
    pub sq_num: u32,
    pub test: bool,
    pub timestamp_us: u64,
}

impl Default for GooseFrame {
    fn default() -> Self {
        Self {
            src_mac: [0u8; 6],
            go_cb_ref: [0u8; MAX_GOOSE_GOCBREF_LEN],
            go_cb_ref_len: 0,
            st_num: 0,
            sq_num: 0,
            test: false,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct MmsRule {
    service_mask: u16,
    read_only: bool,
    max_rate_per_sec: u16,
    active: bool,
}

impl MmsRule {
    const fn empty() -> Self {
        Self {
            service_mask: 0xFFFF,
            read_only: false,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
struct GoosePublisherRule {
    src_mac: [u8; 6],
    go_cb_ref: [u8; MAX_GOOSE_GOCBREF_LEN],
    go_cb_ref_len: u8,
    active: bool,
}

impl GoosePublisherRule {
    const fn empty() -> Self {
        Self {
            src_mac: [0u8; 6],
            go_cb_ref: [0u8; MAX_GOOSE_GOCBREF_LEN],
            go_cb_ref_len: 0,
            active: false,
        }
    }

    fn matches(&self, src_mac: [u8; 6], go_cb_ref: &[u8], go_cb_ref_len: u8) -> bool {
        if !self.active {
            return false;
        }
        if self.src_mac != src_mac {
            return false;
        }
        if self.go_cb_ref_len == 0 {
            return true;
        } // MAC-only match
        if self.go_cb_ref_len != go_cb_ref_len {
            return false;
        }
        let len = self.go_cb_ref_len as usize;
        self.go_cb_ref[..len] == go_cb_ref[..len]
    }
}

#[derive(Clone, Copy)]
struct GooseSeqEntry {
    src_mac: [u8; 6],
    last_st_num: u32,
    last_sq_num: u32,
    has_seen: bool,
    active: bool,
    last_used: u32,
}

impl GooseSeqEntry {
    const fn empty() -> Self {
        Self {
            src_mac: [0u8; 6],
            last_st_num: 0,
            last_sq_num: 0,
            has_seen: false,
            active: false,
            last_used: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// IEC 61850 MMS / GOOSE intrusion detection monitor.
pub struct Iec61850Monitor {
    // MMS state
    mms_rules: [MmsRule; MAX_MMS_RULES],
    mms_rule_count: u8,
    mms_service_mask: u16,
    mms_read_only: bool,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    rate_tick: u32,
    // GOOSE state
    goose_publishers: [GoosePublisherRule; MAX_GOOSE_PUBLISHERS],
    goose_publisher_count: u8,
    goose_seq_table: [GooseSeqEntry; MAX_GOOSE_SEQ_ENTRIES],
    goose_seq_tick: u32,
    block_test_frames: bool,
    // Shared
    strict_mode: bool,
    mms_total_inspected: u64,
    goose_total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
}

impl Iec61850Monitor {
    pub fn new() -> Self {
        Self {
            mms_rules: [MmsRule::empty(); MAX_MMS_RULES],
            mms_rule_count: 0,
            mms_service_mask: 0,
            mms_read_only: false,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            rate_tick: 0,
            goose_publishers: [GoosePublisherRule::empty(); MAX_GOOSE_PUBLISHERS],
            goose_publisher_count: 0,
            goose_seq_table: [GooseSeqEntry::empty(); MAX_GOOSE_SEQ_ENTRIES],
            goose_seq_tick: 0,
            block_test_frames: false,
            strict_mode: false,
            mms_total_inspected: 0,
            goose_total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
        }
    }

    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Set global MMS service bitmask. Bit N = service with enum value N allowed.
    /// 0 = no filtering.
    pub fn set_mms_service_mask(&mut self, mask: u16) {
        self.mms_service_mask = mask;
    }

    /// Set global MMS read-only mode.
    pub fn set_mms_read_only(&mut self, read_only: bool) {
        self.mms_read_only = read_only;
    }

    /// Add an MMS rule with per-rule service mask, write protection, and rate limit.
    pub fn add_mms_rule(
        &mut self,
        service_mask: u16,
        read_only: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.mms_rule_count as usize >= MAX_MMS_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.mms_rule_count as usize;
        self.mms_rules[idx] = MmsRule {
            service_mask,
            read_only,
            max_rate_per_sec,
            active: true,
        };
        self.mms_rule_count += 1;
        Ok(())
    }

    /// Add a GOOSE publisher allowlist entry.
    pub fn add_goose_publisher(
        &mut self,
        src_mac: [u8; 6],
        go_cb_ref: &[u8],
    ) -> Result<(), VsError> {
        if self.goose_publisher_count as usize >= MAX_GOOSE_PUBLISHERS {
            return Err(VsError::ResourceExhausted);
        }
        if go_cb_ref.len() > MAX_GOOSE_GOCBREF_LEN {
            return Err(VsError::InvalidInput);
        }
        let idx = self.goose_publisher_count as usize;
        let mut rule = GoosePublisherRule::empty();
        rule.src_mac = src_mac;
        let len = go_cb_ref.len();
        rule.go_cb_ref[..len].copy_from_slice(go_cb_ref);
        rule.go_cb_ref_len = len as u8;
        rule.active = true;
        self.goose_publishers[idx] = rule;
        self.goose_publisher_count += 1;
        Ok(())
    }

    /// Set whether test-flagged GOOSE frames are blocked.
    pub fn set_block_test_frames(&mut self, block: bool) {
        self.block_test_frames = block;
    }

    /// Inspect an MMS frame.
    pub fn inspect_mms(&mut self, frame: &MmsFrame) -> Iec61850MmsInspectResult {
        self.mms_total_inspected = self.mms_total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_IEC61850_MMS);

        // Global service mask check.
        if self.mms_service_mask != 0 {
            let svc = frame.raw_service_type;
            let allowed = svc < 16 && (self.mms_service_mask >> svc) & 1 == 1;
            if !allowed {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC61850_MMS,
                    frame.invoke_id,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::UnknownFunctionCode,
                );
                return result;
            }
        }

        // Global write protection.
        if self.mms_read_only && frame.service_type.is_write() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_IEC61850_MMS,
                frame.invoke_id,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::WriteProtection,
            );
            return result;
        }

        // Per-rule matching.
        // Always iterate all rules to avoid timing side-channels.
        let mut matched: Option<usize> = None;
        for i in 0..self.mms_rule_count as usize {
            let r = &self.mms_rules[i];
            if !r.active {
                continue;
            }
            let svc = frame.raw_service_type;
            if (r.service_mask == 0xFFFF || (svc < 16 && (r.service_mask >> svc) & 1 == 1))
                && matched.is_none()
            {
                matched = Some(i);
            }
        }

        if let Some(rule_idx) = matched {
            let rule = &self.mms_rules[rule_idx];

            // Per-rule write protection.
            if rule.read_only && frame.service_type.is_write() {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC61850_MMS,
                    frame.invoke_id,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::WriteProtection,
                );
                return result;
            }

            // Rate limiting.
            let max_rate = rule.max_rate_per_sec;
            if max_rate > 0 && !self.rate_check(frame.invoke_id, max_rate, frame.timestamp_us) {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC61850_MMS,
                    frame.invoke_id,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::RateExceeded,
                );
            }
        } else if self.strict_mode && self.mms_rule_count > 0 {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_IEC61850_MMS,
                frame.invoke_id,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::NoMatchingRule,
            );
        }

        result
    }

    /// Inspect a GOOSE frame.
    pub fn inspect_goose(&mut self, frame: &GooseFrame) -> Iec61850GooseInspectResult {
        self.goose_total_inspected = self.goose_total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_IEC61850_GOOSE);

        // Test flag blocking.
        if self.block_test_frames && frame.test {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_IEC61850_GOOSE,
                frame.st_num,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PolicyViolation,
            );
            return result;
        }

        // Publisher allowlist.
        if self.goose_publisher_count > 0 {
            let ref_len = if (frame.go_cb_ref_len as usize) <= MAX_GOOSE_GOCBREF_LEN {
                frame.go_cb_ref_len
            } else {
                MAX_GOOSE_GOCBREF_LEN as u8
            };
            // Always iterate all publishers to avoid timing side-channels.
            let mut found = false;
            for i in 0..self.goose_publisher_count as usize {
                if self.goose_publishers[i].matches(
                    frame.src_mac,
                    &frame.go_cb_ref[..ref_len as usize],
                    ref_len,
                ) && !found
                {
                    found = true;
                }
            }
            if !found {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC61850_GOOSE,
                    frame.st_num,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::PolicyViolation,
                );
                return result;
            }
        }

        // Replay detection.
        if let Some(replay) = self.check_goose_seq(frame.src_mac, frame.st_num, frame.sq_num) {
            if replay {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC61850_GOOSE,
                    frame.st_num,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::ReplayDetected,
                );
                return result;
            }
        }

        result
    }

    pub fn mms_total_inspected(&self) -> u64 {
        self.mms_total_inspected
    }
    pub fn goose_total_inspected(&self) -> u64 {
        self.goose_total_inspected
    }
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let block_test = self.block_test_frames;
        let svc_mask = self.mms_service_mask;
        let read_only = self.mms_read_only;
        *self = Self::new();
        self.strict_mode = strict;
        self.block_test_frames = block_test;
        self.mms_service_mask = svc_mask;
        self.mms_read_only = read_only;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

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

    fn check_goose_seq(&mut self, src_mac: [u8; 6], st_num: u32, seq_num: u32) -> Option<bool> {
        self.goose_seq_tick = self.goose_seq_tick.wrapping_add(1);
        let now = self.goose_seq_tick;

        for entry in &mut self.goose_seq_table {
            if entry.active && entry.src_mac == src_mac {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_st_num = st_num;
                    entry.last_sq_num = seq_num;
                    entry.has_seen = true;
                    return Some(false);
                }
                // State number went backwards → replay.
                if st_num < entry.last_st_num {
                    entry.last_st_num = st_num;
                    entry.last_sq_num = seq_num;
                    return Some(true);
                }
                // New state → valid.
                if st_num > entry.last_st_num {
                    entry.last_st_num = st_num;
                    entry.last_sq_num = seq_num;
                    return Some(false);
                }
                // Same state: check seq_num.
                if seq_num == entry.last_sq_num {
                    return Some(true); // exact duplicate
                }
                if seq_num < entry.last_sq_num {
                    return Some(true); // sq backwards within same state
                }
                entry.last_sq_num = seq_num;
                return Some(false);
            }
        }

        // New entry.
        for entry in &mut self.goose_seq_table {
            if !entry.active {
                *entry = GooseSeqEntry {
                    src_mac,
                    last_st_num: st_num,
                    last_sq_num: seq_num,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                return None;
            }
        }

        // LRU eviction.
        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.goose_seq_table.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        self.goose_seq_table[victim] = GooseSeqEntry {
            src_mac,
            last_st_num: st_num,
            last_sq_num: seq_num,
            has_seen: true,
            active: true,
            last_used: now,
        };
        None
    }
}

impl Default for Iec61850Monitor {
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
    fn mms_service_type_from_u8() {
        assert_eq!(MmsServiceType::from_u8(1), MmsServiceType::Read);
        assert_eq!(MmsServiceType::from_u8(2), MmsServiceType::Write);
        assert_eq!(MmsServiceType::from_u8(8), MmsServiceType::SetDataValues);
        assert_eq!(MmsServiceType::from_u8(0xAB), MmsServiceType::Unknown);
    }

    #[test]
    fn mms_service_is_write() {
        assert!(!MmsServiceType::Read.is_write());
        assert!(MmsServiceType::Write.is_write());
        assert!(MmsServiceType::SetDataValues.is_write());
        assert!(MmsServiceType::DefineNamedVariable.is_write());
        assert!(!MmsServiceType::GetNameList.is_write());
    }

    #[test]
    fn mms_service_mask_blocks_disallowed() {
        let mut mon = Iec61850Monitor::new();
        // Allow only Read (1) and GetNameList (3).
        mon.set_mms_service_mask((1u16 << 1) | (1u16 << 3));
        let write_frame = MmsFrame {
            service_type: MmsServiceType::Write,
            raw_service_type: 2,
            ..Default::default()
        };
        assert!(!mon.inspect_mms(&write_frame).allowed);
    }

    #[test]
    fn mms_service_mask_allows() {
        let mut mon = Iec61850Monitor::new();
        mon.set_mms_service_mask((1u16 << 1) | (1u16 << 3));
        let read_frame = MmsFrame {
            service_type: MmsServiceType::Read,
            raw_service_type: 1,
            ..Default::default()
        };
        assert!(mon.inspect_mms(&read_frame).allowed);
    }

    #[test]
    fn mms_global_write_protection() {
        let mut mon = Iec61850Monitor::new();
        mon.set_mms_read_only(true);
        let frame = MmsFrame {
            service_type: MmsServiceType::Write,
            raw_service_type: 2,
            ..Default::default()
        };
        assert!(!mon.inspect_mms(&frame).allowed);
    }

    #[test]
    fn mms_global_write_allows_read() {
        let mut mon = Iec61850Monitor::new();
        mon.set_mms_read_only(true);
        let frame = MmsFrame {
            service_type: MmsServiceType::Read,
            raw_service_type: 1,
            ..Default::default()
        };
        assert!(mon.inspect_mms(&frame).allowed);
    }

    #[test]
    fn mms_per_rule_write_protection() {
        let mut mon = Iec61850Monitor::new();
        mon.add_mms_rule(0xFFFF, true, 0).unwrap(); // wildcard, read-only
        let frame = MmsFrame {
            service_type: MmsServiceType::SetDataValues,
            raw_service_type: 8,
            ..Default::default()
        };
        assert!(!mon.inspect_mms(&frame).allowed);
    }

    #[test]
    fn mms_rate_limiting() {
        let mut mon = Iec61850Monitor::new();
        mon.add_mms_rule(0xFFFF, false, 2).unwrap();
        let mk = |id, ts| MmsFrame {
            invoke_id: id,
            timestamp_us: ts,
            ..Default::default()
        };
        assert!(mon.inspect_mms(&mk(1, 1000)).allowed);
        assert!(mon.inspect_mms(&mk(1, 1000)).allowed);
        assert!(!mon.inspect_mms(&mk(1, 1000)).allowed);
        assert!(mon.inspect_mms(&mk(1, 1_001_000)).allowed);
    }

    #[test]
    fn mms_strict_no_rule_match() {
        let mut mon = Iec61850Monitor::new_strict();
        // Add a rule for service 1 only.
        mon.add_mms_rule(1u16 << 1, false, 0).unwrap();
        let frame = MmsFrame {
            service_type: MmsServiceType::Write,
            raw_service_type: 2,
            ..Default::default()
        };
        assert!(!mon.inspect_mms(&frame).allowed);
    }

    #[test]
    fn goose_test_flag_blocked() {
        let mut mon = Iec61850Monitor::new();
        mon.set_block_test_frames(true);
        let frame = GooseFrame {
            test: true,
            ..Default::default()
        };
        assert!(!mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_test_flag_allowed_when_disabled() {
        let mut mon = Iec61850Monitor::new();
        let frame = GooseFrame {
            test: true,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_publisher_allowlist_blocks_unknown() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        mon.add_goose_publisher(mac, b"").unwrap();
        let frame = GooseFrame {
            src_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        assert!(!mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_publisher_allowlist_allows_known() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        mon.add_goose_publisher(mac, b"").unwrap();
        let frame = GooseFrame {
            src_mac: mac,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_replay_exact_duplicate() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let frame = GooseFrame {
            src_mac: mac,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&frame).allowed);
        assert!(!mon.inspect_goose(&frame).allowed); // duplicate
    }

    #[test]
    fn goose_replay_st_num_backwards() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let f1 = GooseFrame {
            src_mac: mac,
            st_num: 5,
            sq_num: 0,
            ..Default::default()
        };
        let _ = mon.inspect_goose(&f1);
        let f2 = GooseFrame {
            src_mac: mac,
            st_num: 3,
            sq_num: 0,
            ..Default::default()
        };
        assert!(!mon.inspect_goose(&f2).allowed);
    }

    #[test]
    fn goose_forward_progress_ok() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let f1 = GooseFrame {
            src_mac: mac,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        let _ = mon.inspect_goose(&f1);
        let f2 = GooseFrame {
            src_mac: mac,
            st_num: 2,
            sq_num: 0,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&f2).allowed);
    }

    #[test]
    fn goose_retransmission_sq_increase() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let f1 = GooseFrame {
            src_mac: mac,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        let _ = mon.inspect_goose(&f1);
        let f2 = GooseFrame {
            src_mac: mac,
            st_num: 1,
            sq_num: 1,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&f2).allowed); // retransmission ok
    }

    #[test]
    fn monitor_reset_clears_counters() {
        let mut mon = Iec61850Monitor::new();
        let mms = MmsFrame::default();
        let goose = GooseFrame::default();
        let _ = mon.inspect_mms(&mms);
        let _ = mon.inspect_goose(&goose);
        assert_eq!(mon.mms_total_inspected(), 1);
        assert_eq!(mon.goose_total_inspected(), 1);
        mon.reset();
        assert_eq!(mon.mms_total_inspected(), 0);
        assert_eq!(mon.goose_total_inspected(), 0);
    }

    #[test]
    fn add_goose_publisher_resource_exhaustion() {
        let mut mon = Iec61850Monitor::new();
        for i in 0..MAX_GOOSE_PUBLISHERS {
            let mac = [0, 0, 0, 0, 0, i as u8];
            mon.add_goose_publisher(mac, b"").unwrap();
        }
        let mac = [0xFF; 6];
        assert_eq!(
            mon.add_goose_publisher(mac, b""),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn add_mms_rule_resource_exhaustion() {
        let mut mon = Iec61850Monitor::new();
        for _ in 0..MAX_MMS_RULES {
            mon.add_mms_rule(0xFFFF, false, 0).unwrap();
        }
        assert_eq!(
            mon.add_mms_rule(0xFFFF, false, 0),
            Err(VsError::ResourceExhausted)
        );
    }
}
