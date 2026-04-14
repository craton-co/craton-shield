#![no_std]

//! DNP3 (Distributed Network Protocol) intrusion detection monitor.
//!
//! Monitors DNP3 traffic for security violations:
//!
//! - **Function code allowlist** — restrict which DNP3 application-layer
//!   function codes are permitted.
//! - **Address validation** — enforce source/destination address policies.
//! - **Write protection** — block write operations to protected points.
//! - **Rate limiting** — cap the number of requests per second per address pair.
//! - **Sequence validation** — detect replayed DNP3 frames.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, Dnp3Frame, InspectResult, RateBucket, SOURCE_DNP3};

/// Backward-compatible type alias.
pub type Dnp3InspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum address rules.
const MAX_ADDRESS_RULES: usize = 16;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

/// Forward-progress window for DNP3 4-bit application-layer sequence numbers.
///
/// A received sequence `seq` is considered valid (not replayed) if the
/// wrapping distance `(seq - last_seq) mod 16` is in the range `1..=SEQ_WINDOW`.
/// Setting the window to half the sequence space (8) lets the monitor tolerate
/// up to 7 retransmissions or missed acknowledgements before raising an alert,
/// while still detecting actual replays (distance 0 = duplicate) and large
/// backwards jumps (distance > 8 = likely replay or desync).
const SEQ_WINDOW: u8 = 8;

// ---------------------------------------------------------------------------
// Sequence entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct SeqEntry {
    key: u32,
    last_seq: u8,
    has_seen: bool,
    active: bool,
    /// Monotonically increasing "last used" counter for LRU eviction.
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

// ---------------------------------------------------------------------------
// Address rule
// ---------------------------------------------------------------------------

/// Security rule for a DNP3 address pair.
#[derive(Debug, Clone, Copy)]
struct AddressRule {
    /// Source address (0xFFFF = any).
    source_addr: u16,
    /// Destination address (0xFFFF = any).
    dest_addr: u16,
    /// Bitmask of allowed function codes (bit N = FC N allowed, up to 31).
    fc_mask: u32,
    /// Block all write operations.
    read_only: bool,
    /// Maximum requests per second (0 = unlimited).
    max_rate_per_sec: u16,
    active: bool,
}

impl AddressRule {
    const fn empty() -> Self {
        Self {
            source_addr: 0xFFFF,
            dest_addr: 0xFFFF,
            fc_mask: 0xFFFF_FFFF,
            read_only: false,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

/// DNP3 function codes that perform writes.
const DNP3_WRITE_FCS: u32 = (1 << 2) // Write
    | (1 << 3)  // Select
    | (1 << 4)  // Operate
    | (1 << 5)  // Direct Operate
    | (1 << 6); // Direct Operate No Ack

// ---------------------------------------------------------------------------
// DNP3 Monitor
// ---------------------------------------------------------------------------

/// DNP3 intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~500 bytes.
pub struct Dnp3Monitor {
    rules: [AddressRule; MAX_ADDRESS_RULES],
    rule_count: u8,
    strict_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
    /// Rate-limit token buckets.
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    next_free_bucket: u8,
    /// Monotonic generation counter for LRU eviction of rate buckets.
    rate_tick: u32,
    /// Sequence validation enabled.
    seq_validation: bool,
    /// Last seen sequence per address pair (key = (src << 16 | dst), stored in a small table).
    seq_table: [SeqEntry; 16],
    seq_count: u8,
    /// Monotonic tick driving LRU ordering of `seq_table`.
    seq_tick: u32,
}

impl Dnp3Monitor {
    /// Create a new DNP3 monitor (permissive).
    pub fn new() -> Self {
        Self {
            rules: [AddressRule::empty(); MAX_ADDRESS_RULES],
            rule_count: 0,
            strict_mode: false,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            next_free_bucket: 0,
            rate_tick: 0,
            seq_validation: true,
            seq_table: [SeqEntry::empty(); 16],
            seq_count: 0,
            seq_tick: 0,
        }
    }

    /// Create a DNP3 monitor in strict mode.
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Add an address rule.
    ///
    /// Returns `VsError::InvalidInput` if a rule with the same
    /// `(source_addr, dest_addr)` pair already exists. Duplicate rules would
    /// be silently shadowed by the first match, leading to unexpected policy
    /// behaviour.
    pub fn add_address_rule(
        &mut self,
        source_addr: u16,
        dest_addr: u16,
        fc_mask: u32,
        read_only: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_ADDRESS_RULES {
            return Err(VsError::ResourceExhausted);
        }
        // Reject duplicate (source_addr, dest_addr) pairs — a second rule for
        // the same pair would never be reached.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && self.rules[i].source_addr == source_addr
                && self.rules[i].dest_addr == dest_addr
            {
                return Err(VsError::InvalidInput);
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = AddressRule {
            source_addr,
            dest_addr,
            fc_mask,
            read_only,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Enable or disable sequence number validation.
    ///
    /// Enabled by default. Disable only if the network uses non-sequential
    /// application-layer sequences (rare; not recommended for
    /// security-sensitive deployments).
    pub fn set_seq_validation(&mut self, enabled: bool) {
        self.seq_validation = enabled;
    }

    /// Inspect a DNP3 frame.
    pub fn inspect(&mut self, frame: &Dnp3Frame) -> Dnp3InspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_DNP3);

        if frame.payload_len_overflow() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PayloadOverflow,
            );
            return result;
        }

        // Sequence number validation (DNP3 uses 4-bit seq, 0-15).
        if self.seq_validation {
            let seq = frame.sequence_number & 0x0F; // mask to 4 bits
            let key = ((frame.source_addr as u32) << 16) | frame.dest_addr as u32;
            if let Some(replay) = self.check_seq(key, seq) {
                if replay {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::High,
                        SOURCE_DNP3,
                        frame.dest_addr as u32,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::ReplayDetected,
                    );
                    return result;
                }
            }
        }

        // Find matching address rule (fast path: check last matched first).
        let matched = self.find_matching_rule(frame.source_addr, frame.dest_addr);

        let Some(rule_idx) = matched else {
            if self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_DNP3,
                    frame.dest_addr as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::AddressViolation,
                );
            }
            return result;
        };

        let rule = &self.rules[rule_idx];

        // Function code check.
        // The fc_mask only covers FCs 0-31; any FC >= 32 is not
        // representable in the mask and must be blocked.
        let fc = frame.function_code;
        let fc_allowed = fc < 32 && (rule.fc_mask >> fc) & 1 == 1;
        if !fc_allowed {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::UnknownFunctionCode,
            );
            return result;
        }

        // Write protection (only reachable for fc < 32 since fc_allowed
        // already gates us above).
        if rule.read_only && (DNP3_WRITE_FCS >> fc) & 1 == 1 {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::WriteProtection,
            );
            return result;
        }

        // Rate limiting.
        let max_rate = self.rules[rule_idx].max_rate_per_sec;
        if max_rate > 0
            && !self.rate_check(
                frame.source_addr,
                frame.dest_addr,
                max_rate,
                frame.timestamp_us,
            )
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::RateExceeded,
            );
        }

        result
    }

    /// Check and consume a rate-limit token for the given address pair.
    fn rate_check(&mut self, source: u16, dest: u16, max_rate: u16, now_us: u64) -> bool {
        let key = ((source as u32) << 16) | dest as u32;
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;

        // Search existing bucket.
        for b in &mut self.rate_buckets {
            if b.active && b.key == key {
                b.last_used = now_tick;
                return b.try_consume(now_us);
            }
        }

        // Allocate new bucket.
        if (self.next_free_bucket as usize) < MAX_RATE_BUCKETS {
            let i = self.next_free_bucket as usize;
            self.rate_buckets[i] = RateBucket {
                key,
                tokens: max_rate.saturating_sub(1),
                capacity: max_rate,
                last_refill_us: now_us,
                last_used: now_tick,
                active: true,
            };
            self.next_free_bucket += 1;
            return true;
        }

        // LRU eviction: replace least-recently-used bucket.
        let mut lru_idx = 0usize;
        let mut lru_age: u32 = 0;
        for (i, b) in self.rate_buckets.iter().enumerate() {
            let age = now_tick.wrapping_sub(b.last_used);
            if i == 0 || age > lru_age {
                lru_age = age;
                lru_idx = i;
            }
        }
        self.rate_buckets[lru_idx] = RateBucket {
            key,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            last_used: now_tick,
            active: true,
        };
        true
    }

    /// Check sequence number for replay / out-of-order detection.
    ///
    /// DNP3 application-layer sequences are 4 bits (0..=15). We use a
    /// forward-progress window of [`SEQ_WINDOW`] (8) to distinguish normal
    /// operation from replays:
    ///
    /// - `diff = (seq − last_seq) mod 16`
    /// - `diff == 0` → exact duplicate → **replay**
    /// - `1 ≤ diff ≤ SEQ_WINDOW` → valid forward progress (allows gaps /
    ///   retransmissions up to 7 steps ahead)
    /// - `diff > SEQ_WINDOW` → large backwards jump → **replay**
    ///
    /// The previous strict `diff != 1` check would fire on every retransmission
    /// or legitimate application-layer gap, generating false-positive blocks.
    ///
    /// Returns:
    /// - `Some(true)`  — replay detected,
    /// - `Some(false)` — valid forward progress,
    /// - `None`        — first observation for this address pair (no baseline).
    fn check_seq(&mut self, key: u32, seq: u8) -> Option<bool> {
        let seq = seq & 0x0F;
        // Bump the logical clock for LRU bookkeeping.
        self.seq_tick = self.seq_tick.wrapping_add(1);
        let now = self.seq_tick;

        // Find existing entry.
        for entry in &mut self.seq_table {
            if entry.active && entry.key == key {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_seq = seq;
                    entry.has_seen = true;
                    return Some(false);
                }
                // Wraparound-safe forward distance in the 4-bit sequence space.
                let diff = seq.wrapping_sub(entry.last_seq) & 0x0F;
                if diff == 0 {
                    // Exact duplicate → replay (do NOT advance last_seq).
                    return Some(true);
                }
                if diff > SEQ_WINDOW {
                    // Large backwards jump or replay: still advance last_seq
                    // to the observed value so the monitor re-syncs rather than
                    // permanently blocking all future traffic.
                    entry.last_seq = seq;
                    return Some(true);
                }
                entry.last_seq = seq;
                return Some(false);
            }
        }

        // Create new entry in a free slot.
        for entry in &mut self.seq_table {
            if !entry.active {
                *entry = SeqEntry {
                    key,
                    last_seq: seq,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                self.seq_count = self.seq_count.saturating_add(1);
                return None;
            }
        }

        // Table full — evict the least-recently-used entry. The "oldest"
        // entry is the one with the largest age relative to `now`, measured
        // via wrapping subtraction so a wrapped `seq_tick` still yields the
        // correct ordering.
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
        // `seq_count` unchanged: one entry replaced another.
        None
    }

    /// Find the first matching address rule.
    ///
    /// Always iterates every rule to avoid timing side-channels that could
    /// leak which rule matched.
    fn find_matching_rule(&self, source: u16, dest: u16) -> Option<usize> {
        let mut result: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            if !r.active {
                continue;
            }
            let src_ok = r.source_addr == 0xFFFF || r.source_addr == source;
            let dst_ok = r.dest_addr == 0xFFFF || r.dest_addr == dest;
            if src_ok && dst_ok && result.is_none() {
                result = Some(i);
            }
        }
        result
    }

    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    /// Reset all state. Settings (`strict_mode`, `seq_validation`) are preserved.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let seq_validation = self.seq_validation;
        *self = Self::new();
        self.strict_mode = strict;
        self.seq_validation = seq_validation;
    }
}

impl Default for Dnp3Monitor {
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
        let mut mon = Dnp3Monitor::new();
        let f = Dnp3Frame::default();
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_blocks_unknown() {
        let mut mon = Dnp3Monitor::new_strict();
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_allows_configured_address() {
        let mut mon = Dnp3Monitor::new_strict();
        mon.add_address_rule(1, 2, 0xFFFF_FFFF, false, 0).unwrap();
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1, // Read
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn write_protection() {
        let mut mon = Dnp3Monitor::new();
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, true, 0)
            .unwrap();
        // FC 2 = Write → blocked.
        let f = Dnp3Frame {
            function_code: 2,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn fc_mask_blocks_disallowed() {
        let mut mon = Dnp3Monitor::new();
        // Only allow FC 1 (Read).
        mon.add_address_rule(0xFFFF, 0xFFFF, 1 << 1, false, 0)
            .unwrap();
        let read = Dnp3Frame {
            function_code: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&read).allowed);

        let write = Dnp3Frame {
            function_code: 2,
            ..Default::default()
        };
        assert!(!mon.inspect(&write).allowed);
    }

    #[test]
    fn payload_overflow_rejected() {
        let mut mon = Dnp3Monitor::new();
        let f = Dnp3Frame {
            payload_len: 500,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn reset_preserves_mode() {
        let mut mon = Dnp3Monitor::new_strict();
        mon.add_address_rule(1, 2, 0xFFFF_FFFF, false, 0).unwrap();
        let _ = mon.inspect(&Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        });
        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        assert!(!mon.inspect(&Dnp3Frame::default()).allowed);
    }

    #[test]
    fn default_constructor() {
        let mon = Dnp3Monitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn fc_ge_32_blocked_when_rule_exists() {
        let mut mon = Dnp3Monitor::new();
        // Allow all representable FCs (0-31).
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();

        // FC 31 (max representable) should be allowed.
        let f31 = Dnp3Frame {
            function_code: 31,
            ..Default::default()
        };
        assert!(mon.inspect(&f31).allowed);

        // FC 32 is outside the mask range and must be blocked.
        let f32 = Dnp3Frame {
            function_code: 32,
            ..Default::default()
        };
        assert!(!mon.inspect(&f32).allowed);

        // FC 129 (common response code) must also be blocked.
        let f129 = Dnp3Frame {
            function_code: 129,
            ..Default::default()
        };
        assert!(!mon.inspect(&f129).allowed);

        // FC 255 (max u8) must be blocked.
        let f255 = Dnp3Frame {
            function_code: 255,
            ..Default::default()
        };
        assert!(!mon.inspect(&f255).allowed);
    }

    #[test]
    fn add_address_rule_at_capacity_returns_error() {
        let mut mon = Dnp3Monitor::new();
        for i in 0..MAX_ADDRESS_RULES {
            mon.add_address_rule(i as u16, 0, 0xFFFF_FFFF, false, 0)
                .unwrap();
        }
        // Next add must fail with ResourceExhausted.
        let err = mon
            .add_address_rule(99, 99, 0xFFFF_FFFF, false, 0)
            .unwrap_err();
        assert!(matches!(err, VsError::ResourceExhausted));
    }

    #[test]
    fn overlapping_wildcard_and_specific_rules() {
        let mut mon = Dnp3Monitor::new();
        // Rule 0: wildcard — allow only FC 1 (Read).
        mon.add_address_rule(0xFFFF, 0xFFFF, 1 << 1, false, 0)
            .unwrap();
        // Rule 1: specific pair — allow FC 1 and FC 2.
        mon.add_address_rule(10, 20, (1 << 1) | (1 << 2), false, 0)
            .unwrap();

        // The wildcard rule (idx 0) matches first for address pair (10, 20).
        // FC 2 is not allowed by the wildcard rule.
        let f = Dnp3Frame {
            source_addr: 10,
            dest_addr: 20,
            function_code: 2,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);

        // FC 1 should be allowed for any pair (matched by wildcard).
        // Use a different sequence number so replay detection doesn't block it.
        let f_read = Dnp3Frame {
            source_addr: 10,
            dest_addr: 20,
            function_code: 1,
            sequence_number: 1,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(mon.inspect(&f_read).allowed);

        // Unknown pair also matches wildcard; FC 2 blocked.
        let f_other = Dnp3Frame {
            source_addr: 50,
            dest_addr: 60,
            function_code: 2,
            ..Default::default()
        };
        assert!(!mon.inspect(&f_other).allowed);
    }

    #[test]
    fn wildcard_source_specific_dest() {
        let mut mon = Dnp3Monitor::new_strict();
        // Allow any source talking to dest 5, FC 0 and FC 1 only.
        mon.add_address_rule(0xFFFF, 5, (1 << 0) | (1 << 1), false, 0)
            .unwrap();

        // Any source to dest 5 with FC 1 → allowed.
        let f1 = Dnp3Frame {
            source_addr: 100,
            dest_addr: 5,
            function_code: 1,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);

        // Different source, same dest → still allowed.
        let f2 = Dnp3Frame {
            source_addr: 200,
            dest_addr: 5,
            function_code: 0,
            ..Default::default()
        };
        assert!(mon.inspect(&f2).allowed);

        // Dest mismatch → strict mode blocks.
        let f3 = Dnp3Frame {
            source_addr: 100,
            dest_addr: 6,
            function_code: 1,
            ..Default::default()
        };
        assert!(!mon.inspect(&f3).allowed);

        // Correct dest but disallowed FC → blocked.
        let f4 = Dnp3Frame {
            source_addr: 100,
            dest_addr: 5,
            function_code: 3,
            ..Default::default()
        };
        assert!(!mon.inspect(&f4).allowed);
    }

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = Dnp3Monitor::new();
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 3)
            .unwrap();
        for i in 0..3u64 {
            // Use incrementing sequence numbers to avoid replay detection.
            let f = Dnp3Frame {
                function_code: 1,
                sequence_number: i as u8,
                timestamp_us: i * 100,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed, "req {i} should pass");
        }
        let f = Dnp3Frame {
            function_code: 1,
            sequence_number: 3,
            timestamp_us: 300,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn seq_validation_detects_duplicate() {
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();
        let f1 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        let f2 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(!mon.inspect(&f2).allowed, "duplicate seq should be blocked");
    }

    #[test]
    fn seq_validation_on_by_default() {
        let mut mon = Dnp3Monitor::new();
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();
        let f1 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        let f2 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f2).allowed,
            "seq validation on by default — duplicate must be blocked"
        );
    }

    #[test]
    fn seq_validation_can_be_disabled() {
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(false);
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();
        let f1 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);
        let f2 = Dnp3Frame {
            function_code: 1,
            sequence_number: 5,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(
            mon.inspect(&f2).allowed,
            "seq validation disabled — duplicate must be allowed"
        );
    }

    #[test]
    fn duplicate_address_rule_rejected() {
        let mut mon = Dnp3Monitor::new();
        mon.add_address_rule(0x0001, 0x0002, 0xFFFF_FFFF, false, 0)
            .unwrap();
        let result = mon.add_address_rule(0x0001, 0x0002, 0xFFFF_FFFF, true, 100);
        assert!(result.is_err(), "duplicate address rule must be rejected");
    }

    #[test]
    fn strict_mode_emits_address_violation() {
        let mut mon = Dnp3Monitor::new_strict();
        // No rules added — any frame should be blocked with AddressViolation.
        let f = Dnp3Frame {
            function_code: 1,
            sequence_number: 0,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        let result = mon.inspect(&f);
        assert!(!result.allowed);
        assert!(
            result.alert_codes[..result.alert_count as usize]
                .contains(&AlertCode::AddressViolation),
            "strict mode no-match must emit AddressViolation"
        );
    }

    #[test]
    fn seq_validation_4bit_wraparound_accepts_distinct_values() {
        // DNP3 uses a 4-bit sequence counter (0..=15). Exercise the full
        // range and wrap back to 0 — the monitor must NOT flag the wrap
        // itself as a replay; only literal duplicates of the last seq.
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();
        for i in 0u8..=15 {
            let f = Dnp3Frame {
                function_code: 1,
                sequence_number: i,
                source_addr: 1,
                dest_addr: 2,
                timestamp_us: i as u64 * 1_000,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed, "seq {i} should pass");
        }
        // Wrap back to 0 — distinct from the last (15), should pass.
        let f = Dnp3Frame {
            function_code: 1,
            sequence_number: 0,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 16_000,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed, "wrap 15 → 0 must pass");
    }

    #[test]
    fn seq_validation_masks_upper_bits() {
        // Upper bits of `sequence_number` must be ignored (DNP3 is 4-bit).
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();

        let f1 = Dnp3Frame {
            function_code: 1,
            sequence_number: 0x05,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        assert!(mon.inspect(&f1).allowed);

        // Same low nibble (5) with upper bits set — should still be a duplicate.
        let f2 = Dnp3Frame {
            function_code: 1,
            sequence_number: 0xF5,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 1_000,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f2).allowed,
            "0xF5 masks to 0x05 and must be flagged"
        );
    }

    #[test]
    fn seq_validation_is_per_address_pair() {
        // Duplicate seq on one pair must not affect a different pair.
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();

        let a = Dnp3Frame {
            function_code: 1,
            sequence_number: 7,
            source_addr: 1,
            dest_addr: 2,
            ..Default::default()
        };
        assert!(mon.inspect(&a).allowed);

        // Same seq, different destination → different pair → allowed.
        let b = Dnp3Frame {
            function_code: 1,
            sequence_number: 7,
            source_addr: 1,
            dest_addr: 3,
            timestamp_us: 100,
            ..Default::default()
        };
        assert!(mon.inspect(&b).allowed);

        // Replay on the original pair → blocked.
        let c = Dnp3Frame {
            function_code: 1,
            sequence_number: 7,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: 200,
            ..Default::default()
        };
        assert!(!mon.inspect(&c).allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: out-of-order sequence detection (H1).
    // -----------------------------------------------------------------------
    #[test]
    fn out_of_order_sequence_is_flagged() {
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        let mk = |seq: u8, ts: u64| Dnp3Frame {
            function_code: 1,
            sequence_number: seq,
            source_addr: 1,
            dest_addr: 2,
            timestamp_us: ts,
            ..Default::default()
        };
        // First frame — establishes baseline.
        assert!(mon.inspect(&mk(0, 10)).allowed);
        // In-order next.
        assert!(mon.inspect(&mk(1, 20)).allowed);
        // Small gap within SEQ_WINDOW (diff=4, window=8) → allowed.
        assert!(mon.inspect(&mk(5, 30)).allowed);
        // Jump beyond SEQ_WINDOW (diff=9 > 8) → flagged as replay/out-of-order.
        assert!(!mon.inspect(&mk(14, 40)).allowed);
        // Back in sync from the new baseline.
        assert!(mon.inspect(&mk(15, 50)).allowed);
    }

    // -----------------------------------------------------------------------
    // Regression: LRU eviction when seq_table is full (H2).
    // -----------------------------------------------------------------------
    #[test]
    fn seq_table_lru_eviction_preserves_recent_entries() {
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(true);
        // Fill the 16-entry seq_table with distinct address pairs.
        for i in 0..16u16 {
            let f = Dnp3Frame {
                function_code: 1,
                sequence_number: 0,
                source_addr: 100 + i,
                dest_addr: 200 + i,
                timestamp_us: i as u64,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed);
        }
        // Touch pair #0 so it is freshly LRU-young.
        let touch = Dnp3Frame {
            function_code: 1,
            sequence_number: 1,
            source_addr: 100,
            dest_addr: 200,
            timestamp_us: 1000,
            ..Default::default()
        };
        assert!(mon.inspect(&touch).allowed);
        // Insert a 17th pair — must evict the oldest, not pair #0.
        let new_pair = Dnp3Frame {
            function_code: 1,
            sequence_number: 0,
            source_addr: 999,
            dest_addr: 999,
            timestamp_us: 2000,
            ..Default::default()
        };
        assert!(mon.inspect(&new_pair).allowed);
        // Pair #0 should still exist and recognize an in-sequence frame.
        let follow = Dnp3Frame {
            function_code: 1,
            sequence_number: 2,
            source_addr: 100,
            dest_addr: 200,
            timestamp_us: 3000,
            ..Default::default()
        };
        assert!(mon.inspect(&follow).allowed);
        // And should detect a duplicate of the last seen seq on pair #0.
        let dup = Dnp3Frame {
            function_code: 1,
            sequence_number: 2,
            source_addr: 100,
            dest_addr: 200,
            timestamp_us: 4000,
            ..Default::default()
        };
        assert!(!mon.inspect(&dup).allowed);
    }

    // -----------------------------------------------------------------------
    // VULN-07: DNP3 sequence number replay detection uses a forward-progress
    // window (diff 1..=SEQ_WINDOW) rather than strict equality.
    //
    // The prior implementation fired a replay alert whenever
    // `seq != expected_next`, which caused false positives on legitimate
    // retransmissions (diff == 0) and on large gaps after a device restart
    // (diff > window). After the fix:
    //   diff == 0          → replay (same seq retransmitted)
    //   1 <= diff <= 8     → valid forward progress
    //   diff > 8 / < 0     → replay or resync
    // -----------------------------------------------------------------------

    fn make_rule_monitor() -> Dnp3Monitor {
        let mut mon = Dnp3Monitor::new_strict();
        mon.add_address_rule(1, 10, 0xFFFF_FFFF, true, 0).unwrap();
        mon
    }

    fn make_frame(src: u16, dst: u16, seq: u8, ts: u64) -> Dnp3Frame {
        Dnp3Frame {
            source_addr: src,
            dest_addr: dst,
            function_code: 1, // Read
            sequence_number: seq & 0x0F,
            timestamp_us: ts,
            ..Default::default()
        }
    }

    #[test]
    fn vuln07_same_seq_detected_as_replay() {
        let mut mon = make_rule_monitor();
        // First frame: seq=0 (seeds last_seq).
        let r1 = mon.inspect(&make_frame(1, 10, 0, 1000));
        assert!(r1.allowed, "first frame (seq=0) must be allowed");
        // Exact same seq: replay.
        let r2 = mon.inspect(&make_frame(1, 10, 0, 2000));
        assert!(!r2.allowed, "duplicate seq=0 must be detected as replay");
    }

    #[test]
    fn vuln07_seq_within_window_is_allowed() {
        let mut mon = make_rule_monitor();
        // Seed with seq=0.
        let _ = mon.inspect(&make_frame(1, 10, 0, 1000));
        // Forward progress of 1 through SEQ_WINDOW (8) must all be allowed.
        for step in 1u8..=8 {
            let seq = step & 0x0F;
            let r = mon.inspect(&make_frame(1, 10, seq, (step as u64) * 1000 + 1000));
            assert!(
                r.allowed,
                "seq diff={step} (seq={seq}) must be within the forward-progress window"
            );
        }
    }

    #[test]
    fn vuln07_seq_beyond_window_not_false_positive() {
        // A sequence jump beyond SEQ_WINDOW (e.g. after device restart)
        // should not cause a missed packet every cycle — the monitor should
        // resync rather than permanently blocking the device.
        let mut mon = make_rule_monitor();
        // Seed with seq=0, then jump to seq=9 (diff=9 > SEQ_WINDOW=8).
        let _ = mon.inspect(&make_frame(1, 10, 0, 1000));
        let r_jump = mon.inspect(&make_frame(1, 10, 9, 2000));
        // After the jump, the next in-sequence frame must be accepted.
        let r_next = mon.inspect(&make_frame(1, 10, 10, 3000));
        assert!(
            r_next.allowed,
            "frame after a resync must be allowed (seq=10 is +1 from resynced last_seq=9)"
        );
        // (r_jump may or may not be allowed depending on resync policy — we
        // only assert that the monitor resyncs and does not permanently block.)
        let _ = r_jump;
    }

    #[test]
    fn vuln07_retransmit_within_window_is_treated_as_replay() {
        // diff == 0 means the same seq was sent again — replay.
        let mut mon = make_rule_monitor();
        let _ = mon.inspect(&make_frame(1, 10, 5, 1000));
        let r = mon.inspect(&make_frame(1, 10, 5, 2000));
        assert!(!r.allowed, "retransmit of seq=5 must be detected as replay");
    }
}
