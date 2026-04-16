#![no_std]
#![deny(missing_docs)]

//! DNP3 (Distributed Network Protocol) intrusion detection monitor.
//!
//! Monitors DNP3 traffic for security violations:
//!
//! - **Function code allowlist** — restrict which DNP3 application-layer
//!   function codes are permitted.
//! - **Address validation** — enforce source/destination address policies.
//! - **Write protection** — block write operations to protected points.
//! - **Rate limiting** — cap the number of requests per second per address pair.
//! - **Application-layer sequence validation** — detect replayed DNP3 frames
//!   using the 4-bit application-layer sequence.
//! - **Link-layer CRC** (IEEE 1815 §9.2.2.4) — validate the per-block
//!   CRC-16/DNP3 over the link header.
//! - **Transport-layer sequence** (IEEE 1815 §8.2) — track the 6-bit
//!   transport sequence and reject out-of-order frames.
//! - **DNP3-SA downgrade detection** — reject Secure Authentication
//!   negotiations that propose HMAC algorithm = None or key-wrap
//!   algorithm = None (FC 32 / FC 33).
//! - **IIN flag spoofing** — track response IIN1 bits and alert on sudden
//!   `LOCAL_CONTROL = 1` (outstation bypasses master) or `DEVICE_TROUBLE`
//!   flapping.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{
    AlertCode, Dnp3Frame, InspectResult, RateBucket, DNP3_FC_AUTH_REQUEST, DNP3_FC_AUTH_RESPONSE,
    DNP3_IIN1_DEVICE_TROUBLE, DNP3_IIN1_LOCAL_CONTROL, SOURCE_DNP3,
};

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

/// Forward-progress window for DNP3 6-bit transport-layer sequence numbers.
///
/// Mirrors [`SEQ_WINDOW`] semantics but in a 64-step space. Half the space
/// (32) lets the monitor tolerate normal retransmission gaps while still
/// detecting replays and large backwards jumps.
const TRANSPORT_SEQ_WINDOW: u8 = 32;

/// Number of consecutive `DEVICE_TROUBLE` transitions within a session
/// before the monitor classifies the behaviour as "flapping".
const DEVICE_TROUBLE_FLAP_THRESHOLD: u8 = 3;

// ---------------------------------------------------------------------------
// CRC-16 / DNP3 (polynomial 0x3D65, init 0x0000, final XOR 0xFFFF, reflected)
// ---------------------------------------------------------------------------

/// Precomputed CRC-16/DNP3 table (reflected polynomial `0xA6BC`).
///
/// Built once at compile time so [`crc16_dnp3`] can run a byte-at-a-time
/// table lookup instead of the eight-shift bit-serial loop used by
/// [`crc16_dnp3_slow`]. The two functions return identical values for any
/// input; the table is kept private to this crate.
const CRC16_TABLE: [u16; 256] = build_crc16_table();

/// Build the CRC-16/DNP3 lookup table at compile time.
const fn build_crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u16;
        let mut j = 0;
        while j < 8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Compute the CRC-16/DNP3 used by IEEE 1815 link-layer blocks (§9.2.2.4).
///
/// Polynomial `0xA6BC` (reversed `0x3D65`), init `0x0000`, final XOR
/// `0xFFFF`, reflected input/output. Uses a 256-entry byte-at-a-time
/// lookup table for performance (~8x faster than the bit-serial form);
/// see [`crc16_dnp3_slow`] for the reference bit-serial implementation.
pub fn crc16_dnp3(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let idx = ((crc ^ u16::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC16_TABLE[idx];
    }
    crc ^ 0xFFFF
}

/// Reference bit-serial CRC-16/DNP3 implementation.
///
/// Retained for cross-checking the table-driven [`crc16_dnp3`] and for
/// situations where the 512-byte table is undesirable (it is not used
/// internally). Behaviour is byte-for-byte identical to [`crc16_dnp3`].
pub fn crc16_dnp3_slow(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF
}

/// Verify the link-layer CRC of a DNP3 frame.
///
/// # WARNING — lossy CRC reconstruction
///
/// `Dnp3Frame` (defined in `vs-types-ind`) does **not** retain the raw
/// `length` (byte 2) and `control` (byte 3) bytes of the link header.
/// Per IEEE 1815-2012 §9.2.2.4 those bytes are part of the CRC input, so
/// reconstructing the header from `Dnp3Frame` alone is lossy: bytes 2
/// and 3 are substituted with `0x00`, so the computed CRC will not
/// match a real wire CRC unless the parser also feeds in a CRC computed
/// over the same lossy header.
///
/// Per-frame opt-in: the check is performed only when
/// [`Dnp3Frame::link_crc_provided`] is `true`. Parsers that cannot
/// satisfy the lossy-header contract MUST leave this flag `false` so
/// the check is skipped on a per-frame basis. The monitor-level
/// [`Dnp3Monitor::set_link_crc_validation`] /
/// [`Dnp3Monitor::set_crc_validation_enabled`] toggles disable the
/// detector entirely.
///
/// Returns `true` if the frame's `link_crc` matches the computed value, or
/// if [`Dnp3Frame::link_crc_provided`] is `false` (caller signals the lower
/// layer already validated and stripped the CRC).
///
/// Per IEEE 1815-2012 §9.2.2.4 the link header is:
///
/// | byte | field           | width |
/// |------|-----------------|-------|
/// | 0–1  | start (0x0564)  | 2     |
/// | 2    | length          | 1     |
/// | 3    | control         | 1     |
/// | 4–5  | destination     | 2 LE  |
/// | 6–7  | source          | 2 LE  |
///
/// The monitor reconstructs this header from the parsed `Dnp3Frame`
/// fields. `length` and `control` are not stored separately on the frame
/// (architectural limitation — see WARNING above); they are treated as
/// zero when reconstructing the CRC input.
#[must_use]
pub fn verify_crc(frame: &Dnp3Frame) -> bool {
    if !frame.link_crc_provided {
        return true;
    }
    let header: [u8; 8] = [
        0x05,
        0x64,
        // length (placeholder — see WARNING in doc comment)
        0x00,
        // control (placeholder — see WARNING in doc comment)
        0x00,
        (frame.dest_addr & 0xFF) as u8,
        (frame.dest_addr >> 8) as u8,
        (frame.source_addr & 0xFF) as u8,
        (frame.source_addr >> 8) as u8,
    ];
    crc16_dnp3(&header) == frame.link_crc
}

// ---------------------------------------------------------------------------
// Transport-layer sequence tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct TransportEntry {
    key: u32,
    last_seq: u8,
    has_seen: bool,
    active: bool,
    last_used: u32,
}

impl TransportEntry {
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
// IIN flag state tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct IinEntry {
    key: u32,
    /// Last observed IIN1 bits for this address pair.
    last_iin: u16,
    /// Counter of `DEVICE_TROUBLE` transitions since baseline.
    trouble_transitions: u8,
    active: bool,
    last_used: u32,
}

impl IinEntry {
    const fn empty() -> Self {
        Self {
            key: 0,
            last_iin: 0,
            trouble_transitions: 0,
            active: false,
            last_used: 0,
        }
    }
}

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

/// DNP3 application-layer **response** function code: RESPONSE.
///
/// Outstation-to-master traffic carries FC 129 in reply to every read,
/// write, and operate request. Unconditionally blocking every FC ≥ 32
/// would drop the entire reply direction of any real DNP3 session.
const DNP3_FC_RESPONSE: u8 = 129;

/// DNP3 application-layer **response** function code: UNSOLICITED_RESPONSE.
///
/// Outstations send FC 130 to push event data without a matching poll
/// (the IIN bit "unsolicited" flow). This is required by the protocol and
/// must not be globally blocked.
const DNP3_FC_UNSOLICITED_RESPONSE: u8 = 130;

// ---------------------------------------------------------------------------
// DNP3 Monitor
// ---------------------------------------------------------------------------

/// DNP3 intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~500 bytes.
#[allow(clippy::struct_excessive_bools)]
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
    /// Application-layer sequence validation enabled.
    seq_validation: bool,
    /// Last seen sequence per address pair (key = (src << 16 | dst), stored in a small table).
    seq_table: [SeqEntry; 16],
    seq_count: u8,
    /// Monotonic tick driving LRU ordering of `seq_table`.
    seq_tick: u32,
    /// Link-layer CRC validation enabled.
    link_crc_validation: bool,
    /// Transport-layer sequence validation enabled.
    transport_seq_validation: bool,
    /// Per-link 6-bit transport sequence tracking.
    transport_table: [TransportEntry; 16],
    transport_tick: u32,
    /// DNP3-SA downgrade detection enabled.
    sa_downgrade_detection: bool,
    /// IIN spoofing detection enabled.
    iin_detection: bool,
    /// Per-link IIN tracking state.
    iin_table: [IinEntry; 16],
    iin_tick: u32,
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
            // Enabled by default — the security invariant is that a frame
            // marked `link_crc_provided = true` must carry a matching CRC.
            // The false-positive concern noted on [`verify_crc`] (that
            // `Dnp3Frame` does not retain `length` / `control`) is gated
            // per-frame: parsers that cannot fully reconstruct the CRC
            // input must set `link_crc_provided = false`, which skips the
            // check. The monitor-level toggle remains for callers that
            // want to disable the detector entirely.
            link_crc_validation: true,
            transport_seq_validation: true,
            transport_table: [TransportEntry::empty(); 16],
            transport_tick: 0,
            sa_downgrade_detection: true,
            iin_detection: true,
            iin_table: [IinEntry::empty(); 16],
            iin_tick: 0,
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
    ///
    /// Address rules are append-only in 0.7.0; remove support deferred to
    /// 0.8.0. There is no `remove_address_rule` — the rule table cannot
    /// reclaim a slot once allocated, and the only way to clear rules is
    /// to call [`Self::reset`] (which drops *all* rules and resets
    /// counters). Plan rule allocations accordingly within the
    /// `MAX_ADDRESS_RULES` (16) budget.
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

    /// Enable or disable application-layer sequence number validation.
    ///
    /// Enabled by default. Disable only if the network uses non-sequential
    /// application-layer sequences (rare; not recommended for
    /// security-sensitive deployments).
    pub fn set_seq_validation(&mut self, enabled: bool) {
        self.seq_validation = enabled;
    }

    /// Enable or disable link-layer CRC verification (IEEE 1815 §9.2.2.4).
    ///
    /// Enabled by default. When enabled, frames whose `link_crc_provided`
    /// flag is set are checked against [`verify_crc`]; mismatches emit
    /// [`AlertCode::BadLinkCrc`] (High).
    ///
    /// See the WARNING on [`verify_crc`]: `Dnp3Frame` does not retain the
    /// link-header `length` and `control` bytes, so the reconstructed CRC
    /// input is lossy. Parsers that cannot supply a CRC computed over the
    /// same lossy header (start || 0 || 0 || dest || src) MUST leave
    /// `link_crc_provided = false` to skip the check per-frame; this
    /// monitor-level toggle exists to disable the detector entirely.
    pub fn set_link_crc_validation(&mut self, enabled: bool) {
        self.link_crc_validation = enabled;
    }

    /// Alias for [`Self::set_link_crc_validation`].
    ///
    /// Provided to match the naming requested by the integration spec —
    /// behaves identically. See [`verify_crc`] for the WARNING about why
    /// CRC validation is disabled by default.
    pub fn set_crc_validation_enabled(&mut self, enabled: bool) {
        self.set_link_crc_validation(enabled);
    }

    /// Enable or disable transport-layer sequence validation (IEEE 1815 §8.2).
    ///
    /// Enabled by default. Tracks the 6-bit transport SEQ per address pair
    /// and emits [`AlertCode::TransportSeqAnomaly`] on out-of-order frames.
    pub fn set_transport_seq_validation(&mut self, enabled: bool) {
        self.transport_seq_validation = enabled;
    }

    /// Enable or disable DNP3-SA downgrade detection.
    ///
    /// Enabled by default. Inspects FC 32 / FC 33 (Authenticate
    /// Request/Response) payloads for HMAC algorithm = None or
    /// key-wrap algorithm = None and emits [`AlertCode::SaDowngrade`] (High).
    pub fn set_sa_downgrade_detection(&mut self, enabled: bool) {
        self.sa_downgrade_detection = enabled;
    }

    /// Enable or disable IIN flag spoofing detection.
    ///
    /// Enabled by default. Tracks response IIN1 bits and alerts on
    /// unexpected `LOCAL_CONTROL = 1` or `DEVICE_TROUBLE` flapping.
    pub fn set_iin_detection(&mut self, enabled: bool) {
        self.iin_detection = enabled;
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

        // Link-layer CRC validation (IEEE 1815 §9.2.2.4).
        if self.link_crc_validation && frame.link_crc_provided && !verify_crc(frame) {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::BadLinkCrc,
            );
            return result;
        }

        // Transport-layer sequence validation (IEEE 1815 §8.2).
        //
        // The check is skipped when the caller did not populate
        // `transport_byte` — a wire-valid transport header *usually* has at
        // least one of FIN or FIR set, so `transport_byte == 0` is treated
        // as "header not provided by the parser" rather than a real value.
        //
        // Edge case (false negative): a legitimate transport byte of
        // exactly `0x00` (FIN=0, FIR=0, SEQ=0) is rare but legal — it
        // identifies an interior segmentation continuation with SEQ 0
        // (e.g. the 64th segment of a long fragmented APDU). On such
        // frames this gate suppresses the seq check. Callers that need
        // strict transport-seq enforcement on segmentation continuations
        // should ensure the parser sets a sentinel bit before passing
        // the frame in.
        if self.transport_seq_validation && frame.transport_byte != 0 {
            let tkey = ((frame.source_addr as u32) << 16) | frame.dest_addr as u32;
            if let Some(anomaly) = self.check_transport_seq(tkey, frame.transport_seq()) {
                if anomaly {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_DNP3,
                        frame.dest_addr as u32,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::TransportSeqAnomaly,
                    );
                    return result;
                }
            }
        }

        // DNP3-SA downgrade detection (FC 32 / 33).
        if self.sa_downgrade_detection
            && (frame.function_code == DNP3_FC_AUTH_REQUEST
                || frame.function_code == DNP3_FC_AUTH_RESPONSE)
            && Self::sa_proposes_weak_algorithm(frame)
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_DNP3,
                frame.dest_addr as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::SaDowngrade,
            );
            return result;
        }

        // IIN flag spoofing detection (response frames only).
        if self.iin_detection && frame.is_response() {
            let ikey = ((frame.source_addr as u32) << 16) | frame.dest_addr as u32;
            if self.check_iin_flags(ikey, frame.iin) {
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_DNP3,
                    frame.dest_addr as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::IinFlagSpoofing,
                );
                // Note: IIN spoofing alerts are advisory — the response itself
                // is still delivered, but the alert is raised for operator
                // review. Continue with downstream checks.
            }
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
        //
        // Two legal FC ranges exist in DNP3:
        //
        // - **Requests (0–33)**: filtered by the rule's `fc_mask` (covers 0–31).
        //   FCs 32 (AUTHENTICATE_REQ) and 33 (AUTH_REQ_NO_ACK) are not
        //   representable in the 32-bit mask and are conservatively blocked
        //   here — DNP3-SA support is out of scope for this release.
        //
        // - **Responses (129, 130)**: RESPONSE and UNSOLICITED_RESPONSE.
        //   These are the primary outstation-to-master traffic the IDS
        //   sees and must never be blocked merely because the request
        //   mask cannot represent them. They are allowed unconditionally
        //   when a matching rule exists; per-FC response filtering would
        //   require a separate response mask, which is a v0.9 honesty
        //   pass item.
        //
        // Any other FC value (32, 33, 34..=128, 131..=255) is treated as
        // illegal / unknown and blocked with `UnknownFunctionCode`.
        let fc = frame.function_code;
        let is_response_fc = fc == DNP3_FC_RESPONSE || fc == DNP3_FC_UNSOLICITED_RESPONSE;
        let fc_allowed = is_response_fc || (fc < 32 && (rule.fc_mask >> fc) & 1 == 1);
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

        // Write protection.
        //
        // Only request FCs (0..32) can be write operations — response FCs
        // never appear in `DNP3_WRITE_FCS`. Guarding on `fc < 32` keeps the
        // `(DNP3_WRITE_FCS >> fc) & 1` shift well-defined for `u8` FCs.
        if fc < 32 && rule.read_only && (DNP3_WRITE_FCS >> fc) & 1 == 1 {
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

        // Search existing bucket. Only bump `rate_tick` after we have
        // committed to actually using/creating a bucket — bumping on every
        // miss would skew LRU ages on lookups that never produced any
        // state change.
        for b in &mut self.rate_buckets {
            if b.active && b.key == key {
                self.rate_tick = self.rate_tick.wrapping_add(1);
                b.last_used = self.rate_tick;
                return b.try_consume(now_us);
            }
        }

        // Allocate new bucket.
        if (self.next_free_bucket as usize) < MAX_RATE_BUCKETS {
            self.rate_tick = self.rate_tick.wrapping_add(1);
            let now_tick = self.rate_tick;
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
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;
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

    /// Inspect a DNP3-SA frame payload for downgrade attempts.
    ///
    /// # ⚠️ WARNING — this is a heuristic, not a full DNP3-SA parser
    ///
    /// Without a full DNP3-SA object decoder this monitor cannot
    /// authoritatively locate the HMAC / key-wrap algorithm bytes within a
    /// `g120v1` / `g120v2` / `g120v5` payload. Instead it scans the fixed
    /// candidate offsets `[4, 5, 6]` for any zero byte. This produces
    /// **false positives** in cases such as:
    ///
    /// - `g120v1` frames with a non-zero HMAC at offset 4 but zero padding
    ///   (e.g. unused MAC reserved bytes) at offset 6,
    /// - any g120 variation whose first MAC byte happens to be `0x00`,
    /// - any payload that legitimately carries a zero byte in `[4..7]`
    ///   that is not an algorithm-code field.
    ///
    /// It will also miss downgrades where the algorithm-code byte sits
    /// outside `[4, 5, 6]` (e.g. behind a variable-length challenge
    /// preceding the algorithm field).
    ///
    /// Treat alerts from this detector as **advisory** — pair them with
    /// out-of-band confirmation before taking blocking action in
    /// production. A full DNP3-SA decoder is planned for 0.8.0.
    ///
    /// # Background
    ///
    /// DNP3-SA `gAuthChallenge` / `gAuthReply` objects (group 120, variation 1
    /// and 2) carry a 1-byte HMAC algorithm code at payload offset 4 (after
    /// the object header) and, for key-status responses (variation 5), a
    /// 1-byte key-wrap algorithm code at offset 5. Algorithm code `0` means
    /// "no algorithm" — accepting it allows an attacker to negotiate
    /// authentication with no integrity protection.
    ///
    /// Per IEEE 1815-2-2012 §7.6 the only permitted HMAC algorithms are
    /// `1..=4` (HMAC-SHA-1 truncated to {4, 8, 10} octets and HMAC-SHA-256
    /// truncated to 16 octets). Anything outside that range — including
    /// `0` — is a downgrade.
    fn sa_proposes_weak_algorithm(frame: &Dnp3Frame) -> bool {
        let len = frame.valid_payload_len();
        if len == 0 {
            // FC 32/33 with empty payload cannot carry a valid algorithm
            // negotiation — treat as a downgrade attempt.
            return true;
        }
        // Window of interest: object-header + first few fields. The
        // algorithm code byte must lie within this window in any well-formed
        // DNP3-SA frame.
        let window = len.min(16);
        // Scan candidate offsets where the algorithm code may appear.
        // Per IEEE 1815-2 the HMAC algorithm code follows the 4-byte object
        // header in g120v1/v2 and the 5-byte header+ksq in g120v5. Both fall
        // within the first 16 bytes. A zero at any algorithm-byte position
        // signals "no algorithm".
        for &offset in &[4usize, 5, 6] {
            if offset < window && frame.payload[offset] == 0 {
                return true;
            }
        }
        false
    }

    /// Check the transport-layer 6-bit sequence for replay / out-of-order.
    ///
    /// Mirrors [`Self::check_seq`] but in a 6-bit (0..=63) sequence space.
    /// Returns `Some(true)` on anomaly, `Some(false)` on valid forward
    /// progress, and `None` on the first observation (no baseline).
    fn check_transport_seq(&mut self, key: u32, seq: u8) -> Option<bool> {
        let seq = seq & 0x3F;
        self.transport_tick = self.transport_tick.wrapping_add(1);
        let now = self.transport_tick;

        for entry in &mut self.transport_table {
            if entry.active && entry.key == key {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_seq = seq;
                    entry.has_seen = true;
                    return Some(false);
                }
                // Wraparound-safe forward distance in the 6-bit sequence space.
                let diff = seq.wrapping_sub(entry.last_seq) & 0x3F;
                if diff == 0 {
                    // Exact duplicate — anomaly, do not advance.
                    return Some(true);
                }
                if diff > TRANSPORT_SEQ_WINDOW {
                    // Large backwards jump → anomaly, but resync the entry
                    // so the monitor does not permanently block the link.
                    entry.last_seq = seq;
                    return Some(true);
                }
                entry.last_seq = seq;
                return Some(false);
            }
        }

        // Allocate a new entry in a free slot.
        for entry in &mut self.transport_table {
            if !entry.active {
                *entry = TransportEntry {
                    key,
                    last_seq: seq,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                return None;
            }
        }

        // Table full — evict the LRU entry.
        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.transport_table.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        self.transport_table[victim] = TransportEntry {
            key,
            last_seq: seq,
            has_seen: true,
            active: true,
            last_used: now,
        };
        None
    }

    /// Update the IIN tracking state for an outstation response.
    ///
    /// Returns `true` if a spoofing-suspicious transition was detected:
    ///
    /// - `LOCAL_CONTROL` newly set to `1` (outstation reports it is in
    ///   local mode — control bypasses the master). One observation is
    ///   enough to alert.
    /// - `DEVICE_TROUBLE` toggling rapidly — `≥ DEVICE_TROUBLE_FLAP_THRESHOLD`
    ///   transitions since the entry was first seen suggests the flag is
    ///   being manipulated (or the device is genuinely unstable; either
    ///   warrants operator attention).
    fn check_iin_flags(&mut self, key: u32, iin: u16) -> bool {
        self.iin_tick = self.iin_tick.wrapping_add(1);
        let now = self.iin_tick;

        // Find or insert entry.
        for entry in &mut self.iin_table {
            if entry.active && entry.key == key {
                entry.last_used = now;
                let alert = Self::iin_transition_alert(entry, iin);
                entry.last_iin = iin;
                return alert;
            }
        }

        // First observation for this pair — baseline. Alert immediately if
        // the very first response already claims LOCAL_CONTROL, since that
        // is unexpected for a freshly connected outstation.
        let initial_alert = (iin & DNP3_IIN1_LOCAL_CONTROL) != 0;
        for entry in &mut self.iin_table {
            if !entry.active {
                *entry = IinEntry {
                    key,
                    last_iin: iin,
                    trouble_transitions: 0,
                    active: true,
                    last_used: now,
                };
                return initial_alert;
            }
        }
        // LRU eviction.
        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.iin_table.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        self.iin_table[victim] = IinEntry {
            key,
            last_iin: iin,
            trouble_transitions: 0,
            active: true,
            last_used: now,
        };
        initial_alert
    }

    /// Compute whether a transition from `entry.last_iin` to `new_iin`
    /// constitutes an IIN spoofing alert. Updates `entry.trouble_transitions`
    /// as a side effect.
    fn iin_transition_alert(entry: &mut IinEntry, new_iin: u16) -> bool {
        let was_local = (entry.last_iin & DNP3_IIN1_LOCAL_CONTROL) != 0;
        let is_local = (new_iin & DNP3_IIN1_LOCAL_CONTROL) != 0;
        let was_trouble = (entry.last_iin & DNP3_IIN1_DEVICE_TROUBLE) != 0;
        let is_trouble = (new_iin & DNP3_IIN1_DEVICE_TROUBLE) != 0;

        // Track DEVICE_TROUBLE transitions for flap detection.
        if was_trouble != is_trouble {
            entry.trouble_transitions = entry.trouble_transitions.saturating_add(1);
        }

        // Alert: LOCAL_CONTROL rising edge (outstation entered local mode).
        if !was_local && is_local {
            return true;
        }
        // Alert: DEVICE_TROUBLE flapping above threshold.
        if entry.trouble_transitions >= DEVICE_TROUBLE_FLAP_THRESHOLD {
            // Reset so we re-alert only on further flapping bursts.
            entry.trouble_transitions = 0;
            return true;
        }
        false
    }

    /// Find the first matching address rule.
    ///
    /// Short-circuits on the first match. This is industrial-monitoring
    /// traffic policy, not a cryptographic comparison — leaking "which
    /// rule index matched" via timing is not in the threat model, and the
    /// short-circuit roughly halves the average rule-table scan cost on
    /// hot paths.
    fn find_matching_rule(&self, source: u16, dest: u16) -> Option<usize> {
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            if !r.active {
                continue;
            }
            let src_ok = r.source_addr == 0xFFFF || r.source_addr == source;
            let dst_ok = r.dest_addr == 0xFFFF || r.dest_addr == dest;
            if src_ok && dst_ok {
                return Some(i);
            }
        }
        None
    }

    /// Total number of frames passed to [`Self::inspect`] since
    /// construction (or the last [`Self::reset`]).
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Total number of alerts emitted since construction (or the last
    /// [`Self::reset`]). A single inspection may emit multiple alerts.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// The next alert ID that will be assigned. IDs are monotonically
    /// increasing within a monitor instance; they are not reset by
    /// [`Self::reset`].
    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    /// Reset all state. Settings (`strict_mode`, sequence and v0.9 detector
    /// toggles) are preserved.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let seq_validation = self.seq_validation;
        let link_crc_validation = self.link_crc_validation;
        let transport_seq_validation = self.transport_seq_validation;
        let sa_downgrade_detection = self.sa_downgrade_detection;
        let iin_detection = self.iin_detection;
        *self = Self::new();
        self.strict_mode = strict;
        self.seq_validation = seq_validation;
        self.link_crc_validation = link_crc_validation;
        self.transport_seq_validation = transport_seq_validation;
        self.sa_downgrade_detection = sa_downgrade_detection;
        self.iin_detection = iin_detection;
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
    use vs_types_ind::MAX_DNP3_PAYLOAD_LEN;

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
    fn illegal_fcs_above_31_are_blocked_but_responses_pass() {
        let mut mon = Dnp3Monitor::new();
        // Allow all representable FCs (0-31).
        mon.add_address_rule(0xFFFF, 0xFFFF, 0xFFFF_FFFF, false, 0)
            .unwrap();

        let mk = |fc: u8, seq: u8| Dnp3Frame {
            function_code: fc,
            sequence_number: seq,
            ..Default::default()
        };

        // FC 31 (max representable in the request mask) is allowed.
        assert!(mon.inspect(&mk(31, 0)).allowed);

        // FC 32 (AUTHENTICATE_REQ) is not representable in the mask and is
        // blocked by this release (DNP3-SA support is out of scope).
        assert!(!mon.inspect(&mk(32, 1)).allowed);

        // FC 128 is not a legal DNP3 application-layer FC — blocked.
        assert!(!mon.inspect(&mk(128, 2)).allowed);

        // FC 131 (AUTHENTICATE_RESP) is out of scope for this release —
        // blocked rather than silently passed.
        assert!(!mon.inspect(&mk(131, 3)).allowed);

        // FC 255 (max u8) is illegal — blocked.
        assert!(!mon.inspect(&mk(255, 4)).allowed);
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

    // =======================================================================
    // v0.9 honesty-pass: link CRC, transport seq, DNP3-SA, IIN spoofing.
    // =======================================================================

    // -----------------------------------------------------------------------
    // 1) Link-layer CRC validation (IEEE 1815 §9.2.2.4).
    // -----------------------------------------------------------------------

    /// Helper: compute the link-CRC the monitor expects for a given pair.
    fn expected_link_crc(src: u16, dst: u16) -> u16 {
        // Returns the raw CRC (not the boolean comparison). The monitor's
        // [`verify_crc`] applies the same computation internally.
        let header: [u8; 8] = [
            0x05,
            0x64,
            0x00,
            0x00,
            (dst & 0xFF) as u8,
            (dst >> 8) as u8,
            (src & 0xFF) as u8,
            (src >> 8) as u8,
        ];
        crc16_dnp3(&header)
    }

    #[test]
    fn crc16_dnp3_empty_input_matches_init_xor_final() {
        // CRC of empty input is init (0x0000) XOR final (0xFFFF) = 0xFFFF.
        assert_eq!(crc16_dnp3(&[]), 0xFFFF);
    }

    #[test]
    fn link_crc_good_passes() {
        let mut mon = Dnp3Monitor::new();
        // Disable transport-seq validation here to focus on link CRC.
        mon.set_transport_seq_validation(false);
        let crc = expected_link_crc(1, 2);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            link_crc: crc,
            link_crc_provided: true,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(r.allowed, "matching link CRC must pass");
    }

    #[test]
    fn link_crc_bad_emits_alert() {
        let mut mon = Dnp3Monitor::new();
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            // Deliberately wrong CRC.
            link_crc: 0xDEAD,
            link_crc_provided: true,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "bad link CRC must block frame");
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::BadLinkCrc),
            "bad link CRC must emit BadLinkCrc"
        );
        assert_eq!(
            r.alerts[0].severity,
            AlertSeverity::High,
            "BadLinkCrc must be High severity"
        );
    }

    #[test]
    fn link_crc_not_provided_skips_check() {
        let mut mon = Dnp3Monitor::new();
        // No `link_crc_provided` → check skipped even with garbage value.
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            link_crc: 0xDEAD,
            link_crc_provided: false,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(r.allowed, "missing CRC field must not block frame");
    }

    #[test]
    fn link_crc_validation_can_be_disabled() {
        let mut mon = Dnp3Monitor::new();
        mon.set_link_crc_validation(false);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            link_crc: 0xDEAD,
            link_crc_provided: true,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(r.allowed, "disabling link-CRC validation must allow frame");
    }

    #[test]
    fn verify_crc_function_works_standalone() {
        let crc = expected_link_crc(0xABCD, 0x1234);
        let f = Dnp3Frame {
            source_addr: 0xABCD,
            dest_addr: 0x1234,
            link_crc: crc,
            link_crc_provided: true,
            ..Default::default()
        };
        assert!(verify_crc(&f));
        let mut bad = f;
        bad.link_crc = crc.wrapping_add(1);
        assert!(!verify_crc(&bad));
    }

    // -----------------------------------------------------------------------
    // 2) Transport-layer sequence validation (IEEE 1815 §8.2).
    // -----------------------------------------------------------------------

    fn transport_byte(is_final: bool, is_first: bool, seq: u8) -> u8 {
        let mut b = seq & 0x3F;
        if is_final {
            b |= 0x80;
        }
        if is_first {
            b |= 0x40;
        }
        b
    }

    #[test]
    fn transport_seq_in_order_is_allowed() {
        let mut mon = Dnp3Monitor::new();
        let mk = |seq: u8, ts: u64| Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            transport_byte: transport_byte(true, true, seq),
            sequence_number: seq & 0x0F,
            timestamp_us: ts,
            ..Default::default()
        };
        // First frame seeds the baseline.
        assert!(mon.inspect(&mk(0, 10)).allowed);
        // Forward progress within the 6-bit window.
        for step in 1u8..=10 {
            assert!(
                mon.inspect(&mk(step, 100 + u64::from(step))).allowed,
                "in-order transport seq={step} should pass"
            );
        }
    }

    #[test]
    fn transport_seq_duplicate_is_flagged() {
        let mut mon = Dnp3Monitor::new();
        // Disable app-layer seq validation so the transport-seq alert is the one we see.
        mon.set_seq_validation(false);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            transport_byte: transport_byte(true, true, 5),
            timestamp_us: 1_000,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
        let dup = Dnp3Frame {
            timestamp_us: 2_000,
            ..f
        };
        let r = mon.inspect(&dup);
        assert!(!r.allowed, "duplicate transport seq must be blocked");
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::TransportSeqAnomaly),
            "must emit TransportSeqAnomaly"
        );
    }

    #[test]
    fn transport_seq_large_backwards_jump_is_flagged() {
        let mut mon = Dnp3Monitor::new();
        mon.set_seq_validation(false);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            transport_byte: transport_byte(true, true, 1),
            timestamp_us: 100,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
        // Jump backwards by 40 (diff in 6-bit space = 64-40 = 24? no — diff = (seq - last) mod 64).
        // last=1, seq=40 → diff=39 > TRANSPORT_SEQ_WINDOW (32) → anomaly.
        let jump = Dnp3Frame {
            transport_byte: transport_byte(true, true, 40),
            timestamp_us: 200,
            ..f
        };
        let r = mon.inspect(&jump);
        assert!(!r.allowed, "jump beyond transport window must be flagged");
    }

    #[test]
    fn transport_seq_validation_can_be_disabled() {
        let mut mon = Dnp3Monitor::new();
        mon.set_transport_seq_validation(false);
        mon.set_seq_validation(false);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            transport_byte: transport_byte(true, true, 7),
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
        let dup = Dnp3Frame {
            timestamp_us: 1_000,
            ..f
        };
        assert!(
            mon.inspect(&dup).allowed,
            "transport-seq validation disabled must allow duplicate transport seq"
        );
    }

    // -----------------------------------------------------------------------
    // 3) DNP3-SA downgrade detection (FC 32 / 33).
    // -----------------------------------------------------------------------

    #[test]
    fn sa_request_with_hmac_none_is_flagged() {
        let mut mon = Dnp3Monitor::new();
        // Build a DNP3-SA payload with zero in the HMAC algorithm slot
        // (offset 4 — the first byte after a 4-byte object header).
        let mut payload = [0u8; MAX_DNP3_PAYLOAD_LEN];
        // Object header (4 bytes), then HMAC algorithm = 0 at offset 4.
        payload[0] = 120; // group
        payload[1] = 1; // variation
        payload[2] = 0x07; // qualifier (arbitrary)
        payload[3] = 0x01; // count
        payload[4] = 0x00; // HMAC algorithm = None → downgrade
        payload[5] = 0x02; // key-wrap = arbitrary non-zero
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_REQUEST,
            payload,
            payload_len: 16,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "HMAC=None DNP3-SA request must be blocked");
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::SaDowngrade),
            "must emit SaDowngrade"
        );
        assert_eq!(
            r.alerts[0].severity,
            AlertSeverity::High,
            "SaDowngrade must be High severity"
        );
    }

    #[test]
    fn sa_response_with_key_wrap_none_is_flagged() {
        let mut mon = Dnp3Monitor::new();
        let mut payload = [0u8; MAX_DNP3_PAYLOAD_LEN];
        payload[0] = 120;
        payload[1] = 5; // key-status variation
        payload[2] = 0x07;
        payload[3] = 0x01;
        payload[4] = 0x02; // HMAC = HMAC-SHA1-4 (non-zero)
        payload[5] = 0x00; // key-wrap = None → downgrade
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_RESPONSE,
            payload,
            payload_len: 16,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "key-wrap=None DNP3-SA response must be blocked");
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::SaDowngrade),
            "must emit SaDowngrade"
        );
    }

    #[test]
    fn sa_with_valid_algorithms_passes() {
        let mut mon = Dnp3Monitor::new();
        let mut payload = [0u8; MAX_DNP3_PAYLOAD_LEN];
        payload[0] = 120;
        payload[1] = 1;
        payload[2] = 0x07;
        payload[3] = 0x01;
        payload[4] = 0x04; // HMAC-SHA-256
        payload[5] = 0x02; // valid key-wrap
        payload[6] = 0x01; // padding non-zero
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_REQUEST,
            payload,
            payload_len: 16,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(r.allowed, "valid DNP3-SA negotiation must pass");
    }

    #[test]
    fn sa_empty_payload_is_treated_as_downgrade() {
        // An Authenticate Request with no payload cannot carry a valid
        // algorithm negotiation and must be rejected.
        let mut mon = Dnp3Monitor::new();
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_REQUEST,
            payload_len: 0,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed, "empty DNP3-SA payload must be blocked");
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::SaDowngrade),
            "must emit SaDowngrade"
        );
    }

    #[test]
    fn sa_downgrade_detection_can_be_disabled() {
        let mut mon = Dnp3Monitor::new();
        mon.set_sa_downgrade_detection(false);
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_REQUEST,
            payload_len: 0,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn sa_non_auth_fc_is_not_scanned() {
        // FC != 32 / 33 should be unaffected by SA checks.
        let mut mon = Dnp3Monitor::new();
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1, // Read — not an auth FC.
            payload_len: 0,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    // -----------------------------------------------------------------------
    // 4) IIN flag spoofing detection.
    // -----------------------------------------------------------------------

    fn response_frame(src: u16, dst: u16, iin: u16, ts: u64, seq: u8) -> Dnp3Frame {
        Dnp3Frame {
            source_addr: src,
            dest_addr: dst,
            function_code: 129, // Response
            sequence_number: seq & 0x0F,
            iin,
            timestamp_us: ts,
            ..Default::default()
        }
    }

    #[test]
    fn iin_local_control_rising_edge_alerts() {
        let mut mon = Dnp3Monitor::new();
        // Baseline: no LOCAL_CONTROL.
        let r1 = mon.inspect(&response_frame(1, 2, 0, 100, 0));
        assert_eq!(r1.alert_count, 0, "clean baseline must not alert");
        // Outstation now reports LOCAL_CONTROL = 1.
        let r2 = mon.inspect(&response_frame(1, 2, DNP3_IIN1_LOCAL_CONTROL, 200, 1));
        assert!(
            r2.alert_codes[..r2.alert_count as usize].contains(&AlertCode::IinFlagSpoofing),
            "LOCAL_CONTROL rising edge must emit IinFlagSpoofing"
        );
    }

    #[test]
    fn iin_initial_local_control_alerts_immediately() {
        // Very first observation already shows LOCAL_CONTROL — alert.
        let mut mon = Dnp3Monitor::new();
        let r = mon.inspect(&response_frame(1, 2, DNP3_IIN1_LOCAL_CONTROL, 100, 0));
        assert!(
            r.alert_codes[..r.alert_count as usize].contains(&AlertCode::IinFlagSpoofing),
            "initial LOCAL_CONTROL must alert"
        );
    }

    #[test]
    fn iin_device_trouble_flapping_alerts() {
        let mut mon = Dnp3Monitor::new();
        // Baseline: trouble = 0.
        let _ = mon.inspect(&response_frame(1, 2, 0, 100, 0));
        // Three transitions: 0→1, 1→0, 0→1 → threshold reached.
        let r1 = mon.inspect(&response_frame(1, 2, DNP3_IIN1_DEVICE_TROUBLE, 200, 1));
        let r2 = mon.inspect(&response_frame(1, 2, 0, 300, 2));
        let r3 = mon.inspect(&response_frame(1, 2, DNP3_IIN1_DEVICE_TROUBLE, 400, 3));
        // The 3rd transition crosses the flap threshold.
        let alerted = r1
            .alert_codes
            .iter()
            .chain(r2.alert_codes.iter())
            .chain(r3.alert_codes.iter())
            .any(|c| *c == AlertCode::IinFlagSpoofing);
        assert!(
            alerted,
            "DEVICE_TROUBLE flapping must eventually emit IinFlagSpoofing"
        );
    }

    #[test]
    fn iin_stable_state_does_not_alert() {
        let mut mon = Dnp3Monitor::new();
        // Two responses with identical clean IIN — no transitions.
        let r1 = mon.inspect(&response_frame(1, 2, 0, 100, 0));
        let r2 = mon.inspect(&response_frame(1, 2, 0, 200, 1));
        assert_eq!(r1.alert_count, 0);
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn iin_check_only_runs_on_responses() {
        let mut mon = Dnp3Monitor::new();
        // FC=1 (Read request) carries IIN bits in the frame struct, but the
        // monitor should ignore them — IIN is only meaningful in responses.
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: 1,
            iin: DNP3_IIN1_LOCAL_CONTROL,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(
            !r.alert_codes[..r.alert_count as usize].contains(&AlertCode::IinFlagSpoofing),
            "non-response frames must not trigger IIN checks"
        );
    }

    #[test]
    fn iin_detection_can_be_disabled() {
        let mut mon = Dnp3Monitor::new();
        mon.set_iin_detection(false);
        let r = mon.inspect(&response_frame(1, 2, DNP3_IIN1_LOCAL_CONTROL, 100, 0));
        assert!(
            !r.alert_codes[..r.alert_count as usize].contains(&AlertCode::IinFlagSpoofing),
            "IIN detection disabled must not emit IinFlagSpoofing"
        );
    }

    // -----------------------------------------------------------------------
    // Reset preserves the new toggles.
    // -----------------------------------------------------------------------

    #[test]
    fn reset_preserves_new_detector_toggles() {
        let mut mon = Dnp3Monitor::new();
        mon.set_link_crc_validation(false);
        mon.set_transport_seq_validation(false);
        mon.set_sa_downgrade_detection(false);
        mon.set_iin_detection(false);
        mon.reset();
        // All new detectors should remain disabled after reset.
        // Verify via an SA frame that would otherwise be blocked:
        let f = Dnp3Frame {
            source_addr: 1,
            dest_addr: 2,
            function_code: DNP3_FC_AUTH_REQUEST,
            payload_len: 0,
            ..Default::default()
        };
        assert!(
            mon.inspect(&f).allowed,
            "reset must preserve sa_downgrade_detection=false"
        );
    }
}
