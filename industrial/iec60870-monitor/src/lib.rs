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

/// IEC 60870-5-104 APDU start byte (§5.1).
pub const IEC60870_START_BYTE: u8 = 0x68;

/// Length of the APCI for S- and U-format frames (4 bytes after start).
pub const APCI_FIXED_LEN: u8 = 4;

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

/// U-format unnumbered control function (IEC 60870-5-104 §5.1, table).
///
/// The control field of a U-format APDU has bits 0..1 = `11` and exactly
/// one of the six function bits set in octet 1.  Any other bit pattern is
/// illegal and must be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Iec60870UFunction {
    /// STARTDT activation — request to start data transfer (octet 1 = `0x07`).
    StartDtAct = 0x07,
    /// STARTDT confirmation — STARTDT acknowledged (octet 1 = `0x0B`).
    StartDtCon = 0x0B,
    /// STOPDT activation — request to stop data transfer (octet 1 = `0x13`).
    StopDtAct = 0x13,
    /// STOPDT confirmation — STOPDT acknowledged (octet 1 = `0x23`).
    StopDtCon = 0x23,
    /// TESTFR activation — connection liveness probe (octet 1 = `0x43`).
    TestFrAct = 0x43,
    /// TESTFR confirmation — TESTFR probe acknowledged (octet 1 = `0x83`).
    TestFrCon = 0x83,
}

impl Iec60870UFunction {
    /// Decode a U-format control octet (byte 1 of the APCI, after the
    /// start/length pair). Returns `None` for any bit pattern other than
    /// the six legal U-format functions.
    pub fn from_control_octet(octet: u8) -> Option<Self> {
        match octet {
            0x07 => Some(Self::StartDtAct),
            0x0B => Some(Self::StartDtCon),
            0x13 => Some(Self::StopDtAct),
            0x23 => Some(Self::StopDtCon),
            0x43 => Some(Self::TestFrAct),
            0x83 => Some(Self::TestFrCon),
            _ => None,
        }
    }
}

/// Errors returned by [`parse_apdu`] when an IEC 60870-5-104 APDU fails
/// structural validation per §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iec60870ParseError {
    /// Buffer too short to contain a start byte + length field.
    TooShort,
    /// First byte is not the IEC 60870-5-104 start sentinel `0x68`.
    BadStartByte,
    /// APDU length field disagrees with the buffer length, or is outside
    /// the legal range (4..=253 octets).
    BadLength,
    /// S- or U-format frame whose APCI length is not exactly 4 octets.
    BadApciLength,
    /// S- or U-format frame carrying ASDU bytes (must have no payload).
    UnexpectedAsdu,
    /// U-format control octet does not match any of the six legal STARTDT
    /// / STOPDT / TESTFR act/con patterns.
    IllegalUControl,
    /// I-format APCI is too short to contain send/receive sequence numbers.
    BadIControl,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iec60870Frame {
    pub frame_format: Iec60870FrameFormat,
    pub type_id: u8,
    pub cot: Iec60870Cot,
    pub raw_cot: u8,
    pub asdu_address: u16,
    pub send_seq: u16,
    pub recv_seq: u16,
    pub timestamp_us: u64,
    /// Decoded U-format function. Only meaningful when
    /// `frame_format == Iec60870FrameFormat::U`; `None` otherwise.
    pub u_function: Option<Iec60870UFunction>,
    /// APCI length field (byte after the start sentinel). For S/U frames
    /// this must equal `APCI_FIXED_LEN` (4). For I frames it includes the
    /// ASDU payload length.
    pub apci_len: u8,
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
            u_function: None,
            apci_len: 4,
        }
    }
}

impl Iec60870Frame {
    /// Returns `true` if the `TypeID` represents a command (write) operation.
    pub fn is_command_type_id(type_id: u8) -> bool {
        matches!(type_id, 45..=51 | 58..=64)
    }
}

/// Parse an IEC 60870-5-104 APDU starting with the `0x68` start byte.
///
/// Detects the frame format from the control field per §5.1:
///
/// - I-format (bit 0 of control octet 1 = 0): numbered information
///   transfer with send/receive sequence numbers and an ASDU payload.
/// - S-format (bits 0..1 = `01`): supervisory acknowledgement carrying
///   only the receive sequence number; APCI length must be exactly 4 and
///   the APDU must carry no ASDU bytes.
/// - U-format (bits 0..1 = `11`): unnumbered control whose octet 1 must
///   match one of the six STARTDT/STOPDT/TESTFR act/con patterns; APCI
///   length must be exactly 4 and the APDU must carry no ASDU bytes.
///
/// Any other shape — bad start byte, mismatched length, illegal U
/// pattern, or S/U with ASDU bytes — is rejected with a specific
/// [`Iec60870ParseError`] variant.
#[allow(clippy::missing_errors_doc)]
pub fn parse_apdu(bytes: &[u8]) -> Result<Iec60870Frame, Iec60870ParseError> {
    // Need at least start + length.
    if bytes.len() < 2 {
        return Err(Iec60870ParseError::TooShort);
    }
    if bytes[0] != IEC60870_START_BYTE {
        return Err(Iec60870ParseError::BadStartByte);
    }
    let apci_len = bytes[1];
    // APDU length field counts the four control octets + any ASDU.
    // Legal range per §5.1 is 4..=253.
    if !(4..=253).contains(&apci_len) {
        return Err(Iec60870ParseError::BadLength);
    }
    // Total wire size = 2 (start+len) + apci_len.
    let needed = 2usize + apci_len as usize;
    if bytes.len() < needed {
        return Err(Iec60870ParseError::BadLength);
    }
    // Control field: 4 octets at bytes[2..6].
    if bytes.len() < 6 {
        return Err(Iec60870ParseError::TooShort);
    }
    let c0 = bytes[2];
    let c1 = bytes[3];
    let c2 = bytes[4];
    let c3 = bytes[5];

    // Format dispatch on the low two bits of c0 per §5.1.
    let mut frame = Iec60870Frame {
        apci_len,
        timestamp_us: 0,
        ..Iec60870Frame::default()
    };
    match c0 & 0b11 {
        // I-format: bit 0 = 0.
        0b00 | 0b10 => {
            frame.frame_format = Iec60870FrameFormat::I;
            // I-format requires an ASDU body — APCI alone (len=4) is illegal.
            if apci_len < 4 {
                return Err(Iec60870ParseError::BadIControl);
            }
            // 15-bit send seq = c0..c1 >> 1; 15-bit recv seq = c2..c3 >> 1.
            let send = (u16::from(c1) << 8) | u16::from(c0);
            frame.send_seq = (send >> 1) & 0x7FFF;
            let recv = (u16::from(c3) << 8) | u16::from(c2);
            frame.recv_seq = (recv >> 1) & 0x7FFF;
            // ASDU header (best effort): TypeID, VSQ, COT, COT-orig, ASDU addr.
            let asdu = &bytes[6..needed];
            if asdu.len() >= 6 {
                frame.type_id = asdu[0];
                frame.raw_cot = asdu[2] & 0x3F;
                frame.cot = Iec60870Cot::from_u8(asdu[2]);
                frame.asdu_address = u16::from(asdu[4]) | (u16::from(asdu[5]) << 8);
            }
        }
        // S-format: bits 0..1 = 01.
        0b01 => {
            frame.frame_format = Iec60870FrameFormat::S;
            // S-frame APCI length must be exactly 4 (control only, no ASDU).
            // `apci_len < 4` was rejected as `BadLength` above, so the only
            // remaining failure mode is `apci_len > 4`, i.e. an unexpected
            // ASDU body riding on what claims to be a supervisory frame.
            if apci_len > APCI_FIXED_LEN {
                return Err(Iec60870ParseError::UnexpectedAsdu);
            }
            // The first octet of an S-frame must be exactly 0x01: bits 2..7
            // are reserved zero. Anything else is malformed.
            if c0 != 0x01 || c1 != 0x00 {
                return Err(Iec60870ParseError::BadApciLength);
            }
            let recv = (u16::from(c3) << 8) | u16::from(c2);
            frame.recv_seq = (recv >> 1) & 0x7FFF;
        }
        // U-format: bits 0..1 = 11.
        0b11 => {
            frame.frame_format = Iec60870FrameFormat::U;
            if apci_len > APCI_FIXED_LEN {
                return Err(Iec60870ParseError::UnexpectedAsdu);
            }
            // U-format reserves c1..c3 = 0; only c0 carries function bits.
            if c1 != 0 || c2 != 0 || c3 != 0 {
                return Err(Iec60870ParseError::IllegalUControl);
            }
            let Some(func) = Iec60870UFunction::from_control_octet(c0) else {
                return Err(Iec60870ParseError::IllegalUControl);
            };
            frame.u_function = Some(func);
        }
        _ => unreachable!("control & 0b11 has only 4 values"),
    }
    Ok(frame)
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

        // S- and U-format frames carry no ASDU; rule/COT/sequence checks
        // only apply to I-format. Validate structural well-formedness here
        // so that hand-constructed frames cannot smuggle illegal U patterns
        // or S-frames-with-ASDU past the monitor.
        match frame.frame_format {
            Iec60870FrameFormat::I => { /* fall through to full inspection */ }
            Iec60870FrameFormat::S => {
                let mut r = InspectResult::clean(SOURCE_IEC60870);
                // S-frame must declare APCI length 4 (no ASDU).
                if frame.apci_len != APCI_FIXED_LEN {
                    r.allowed = false;
                    r.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_IEC60870,
                        u32::from(frame.asdu_address),
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::PayloadOverflow,
                    );
                }
                return r;
            }
            Iec60870FrameFormat::U => {
                let mut r = InspectResult::clean(SOURCE_IEC60870);
                if frame.apci_len != APCI_FIXED_LEN {
                    r.allowed = false;
                    r.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_IEC60870,
                        u32::from(frame.asdu_address),
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::PayloadOverflow,
                    );
                    return r;
                }
                // U-frame must carry a recognised STARTDT/STOPDT/TESTFR
                // act/con function. Anything else is a malformed control
                // octet — reject with `UnknownFunctionCode`.
                if frame.u_function.is_none() {
                    r.allowed = false;
                    r.push_alert_with_code(
                        AlertSeverity::High,
                        SOURCE_IEC60870,
                        u32::from(frame.asdu_address),
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::UnknownFunctionCode,
                    );
                }
                return r;
            }
            Iec60870FrameFormat::Unknown => {
                let mut r = InspectResult::clean(SOURCE_IEC60870);
                r.allowed = false;
                r.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC60870,
                    u32::from(frame.asdu_address),
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::InvalidProtocol,
                );
                return r;
            }
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
        // A well-formed S-frame: APCI len 4, no ASDU, no U-function.
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::S,
            apci_len: APCI_FIXED_LEN,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn s_frame_with_asdu_rejected_by_inspect() {
        // S-frame APCI claims length > 4 → indicates an ASDU is riding on
        // a supervisory frame, which violates §5.1.
        let mut mon = Iec60870Monitor::new();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::S,
            apci_len: 10,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::PayloadOverflow);
    }

    #[test]
    fn u_frame_with_valid_function_passes() {
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::U,
            u_function: Some(Iec60870UFunction::StartDtAct),
            apci_len: APCI_FIXED_LEN,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn u_frame_without_function_rejected_by_inspect() {
        // A U-format frame whose u_function field is None → no recognised
        // STARTDT/STOPDT/TESTFR pattern.
        let mut mon = Iec60870Monitor::new();
        let f = Iec60870Frame {
            frame_format: Iec60870FrameFormat::U,
            u_function: None,
            apci_len: APCI_FIXED_LEN,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::UnknownFunctionCode);
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

    // -- Parser tests (IEC 60870-5-104 §5.1 frame format dispatch) -----------

    /// Helper: build a U-format APDU with the given control octet.
    fn u_apdu(control: u8) -> [u8; 6] {
        [IEC60870_START_BYTE, 4, control, 0, 0, 0]
    }

    /// Helper: build a well-formed S-format APDU acknowledging `recv_seq`.
    fn s_apdu(recv_seq: u16) -> [u8; 6] {
        let recv = (recv_seq & 0x7FFF) << 1;
        [
            IEC60870_START_BYTE,
            4,
            0x01,
            0x00,
            (recv & 0xFF) as u8,
            ((recv >> 8) & 0xFF) as u8,
        ]
    }

    #[test]
    fn parse_all_six_valid_u_functions() {
        for &(octet, expect) in &[
            (0x07u8, Iec60870UFunction::StartDtAct),
            (0x0B, Iec60870UFunction::StartDtCon),
            (0x13, Iec60870UFunction::StopDtAct),
            (0x23, Iec60870UFunction::StopDtCon),
            (0x43, Iec60870UFunction::TestFrAct),
            (0x83, Iec60870UFunction::TestFrCon),
        ] {
            let bytes = u_apdu(octet);
            let f = parse_apdu(&bytes).expect("valid U-format APDU should parse");
            assert_eq!(f.frame_format, Iec60870FrameFormat::U);
            assert_eq!(f.u_function, Some(expect));
        }
    }

    #[test]
    fn parse_invalid_u_pattern_rejected() {
        // c0 has bits 0..1 = 11 → claims to be U-format, but the function
        // bits don't match any of the six legal patterns (0x33 has both
        // STOPDT_act and STARTDT_act bits set, which is illegal).
        let bytes = u_apdu(0x33);
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::IllegalUControl));

        // Reserved bit pattern: c0 = 0xFF.
        let bytes = u_apdu(0xFF);
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::IllegalUControl));

        // c0 = 0x03 — bits 0..1 = 11 but no function bit set.
        let bytes = u_apdu(0x03);
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::IllegalUControl));
    }

    #[test]
    fn parse_u_with_nonzero_reserved_bytes_rejected() {
        // c1..c3 must be zero in U-format.
        let bytes = [IEC60870_START_BYTE, 4, 0x07, 0x01, 0x00, 0x00];
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::IllegalUControl));
    }

    #[test]
    fn parse_valid_s_frame_accepted() {
        let bytes = s_apdu(42);
        let f = parse_apdu(&bytes).expect("valid S-format APDU should parse");
        assert_eq!(f.frame_format, Iec60870FrameFormat::S);
        assert_eq!(f.recv_seq, 42);
        assert_eq!(f.apci_len, APCI_FIXED_LEN);
        assert!(f.u_function.is_none());
    }

    #[test]
    fn parse_s_frame_with_asdu_rejected() {
        // APCI length 10 → 6 ASDU bytes appended after a c0=0x01 marker.
        // S-frames MUST carry no ASDU.
        let mut bytes = [0u8; 12];
        bytes[0] = IEC60870_START_BYTE;
        bytes[1] = 10;
        bytes[2] = 0x01; // S-format marker
        bytes[3] = 0x00;
        // bytes[4..6] = recv seq, bytes[6..12] = forbidden ASDU body
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::UnexpectedAsdu),);
    }

    #[test]
    fn parse_i_frame_still_works() {
        // I-format APDU: c0 bit 0 = 0; APCI len = 4 (control) + 6 (ASDU
        // header) = 10. ASDU header: TypeID=1, VSQ=1, COT=3 (Spontaneous),
        // origin=0, ASDU addr = 0x0001.
        let mut bytes = [0u8; 12];
        bytes[0] = IEC60870_START_BYTE;
        bytes[1] = 10;
        // send seq = 5 → c0/c1 = (5 << 1) = 0x000A → c0 = 0x0A, c1 = 0x00.
        bytes[2] = 0x0A;
        bytes[3] = 0x00;
        // recv seq = 7 → c2/c3 = 0x000E → c2 = 0x0E, c3 = 0x00.
        bytes[4] = 0x0E;
        bytes[5] = 0x00;
        // ASDU header.
        bytes[6] = 1; // TypeID
        bytes[7] = 1; // VSQ
        bytes[8] = 3; // COT raw = Spontaneous
        bytes[9] = 0; // COT origin
        bytes[10] = 0x01; // ASDU addr lo
        bytes[11] = 0x00; // ASDU addr hi

        let f = parse_apdu(&bytes).expect("valid I-format APDU should parse");
        assert_eq!(f.frame_format, Iec60870FrameFormat::I);
        assert_eq!(f.send_seq, 5);
        assert_eq!(f.recv_seq, 7);
        assert_eq!(f.type_id, 1);
        assert_eq!(f.cot, Iec60870Cot::Spontaneous);
        assert_eq!(f.asdu_address, 1);
    }

    #[test]
    fn parse_bad_start_byte_rejected() {
        let bytes = [0x69u8, 4, 0x07, 0, 0, 0];
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::BadStartByte));
    }

    #[test]
    fn parse_bad_length_rejected() {
        // length field claims 4 but buffer is shorter than declared.
        let bytes = [IEC60870_START_BYTE, 4, 0x07];
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::BadLength));

        // length 3 is below the minimum (4).
        let bytes = [IEC60870_START_BYTE, 3, 0x07, 0, 0, 0];
        assert_eq!(parse_apdu(&bytes), Err(Iec60870ParseError::BadLength));
    }

    #[test]
    fn parse_too_short_rejected() {
        assert_eq!(parse_apdu(&[]), Err(Iec60870ParseError::TooShort));
        assert_eq!(parse_apdu(&[0x68]), Err(Iec60870ParseError::TooShort));
    }
}
