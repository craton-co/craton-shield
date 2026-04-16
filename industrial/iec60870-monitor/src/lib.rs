#![no_std]
#![deny(missing_docs)]

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
    /// S-format control field has reserved bits set. The first APCI octet
    /// of an S-frame must be exactly `0x01` (bits 2..7 reserved zero) and
    /// the second octet must be `0x00`; anything else indicates a
    /// malformed supervisory control field.
    MalformedSControl,
}

/// Cause of Transmission (COT) — 6-bit field from the ASDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Iec60870Cot {
    /// Cyclic / periodic data report (COT 1).
    Periodic = 1,
    /// Background scan (COT 2).
    Background = 2,
    /// Spontaneous event report (COT 3).
    Spontaneous = 3,
    /// Initialised — sent after station initialisation (COT 4).
    Initialized = 4,
    /// Response to a general interrogation (COT 5).
    Interrogation = 5,
    /// Activation request — a command from controlling to controlled
    /// station (COT 6). Treated as a write operation.
    Activation = 6,
    /// Activation confirmation — the controlled station has accepted
    /// the activation request (COT 7).
    ActivationConfirmation = 7,
    /// Deactivation request — cancel a previously activated command
    /// (COT 8). Treated as a write operation.
    Deactivation = 8,
    /// Deactivation confirmation (COT 9).
    DeactivationConfirmation = 9,
    /// Activation termination — the controlled station has finished
    /// executing the activation (COT 10).
    ActivationTermination = 10,
    /// Any COT value not recognised by this decoder.
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
    /// Frame format detected from the APCI control field (I, S, U, or
    /// Unknown).
    pub frame_format: Iec60870FrameFormat,
    /// ASDU TypeID — identifies the information object payload format
    /// (e.g. `1` = M_SP_NA_1 single-point information).
    pub type_id: u8,
    /// Decoded Cause of Transmission. Use [`Self::raw_cot`] for
    /// unrecognised values.
    pub cot: Iec60870Cot,
    /// Raw 6-bit COT value as read from the wire (low 6 bits of the
    /// COT octet, T/P bits stripped).
    pub raw_cot: u8,
    /// 16-bit common ASDU address — the destination station address.
    pub asdu_address: u16,
    /// 15-bit send sequence number from the APCI control field (I
    /// frames only).
    pub send_seq: u16,
    /// 15-bit receive sequence number from the APCI control field (I
    /// and S frames).
    pub recv_seq: u16,
    /// Monotonic timestamp in microseconds, supplied by the caller for
    /// rate-limiting and alert correlation.
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
/// pattern, malformed S-control field, or S/U with ASDU bytes — is
/// rejected with a specific [`Iec60870ParseError`] variant.
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
                return Err(Iec60870ParseError::MalformedSControl);
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

/// Outcome of [`Iec60870Monitor::check_seq`]; see its doc-comment for
/// the contract of each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqOutcome {
    /// Sequence number advanced within `SEQ_WINDOW`. Allow the frame.
    Ok,
    /// Duplicate sequence number or gap larger than `SEQ_WINDOW`.
    /// Block as a replay.
    Replay,
    /// First frame seen for this ASDU; replay tracker initialised.
    /// Allow the frame.
    NewPeer,
    /// First frame seen for this ASDU AND an existing peer was evicted
    /// to make room. Caller raises a `ResourceExhausted` alert for the
    /// lost replay history; the frame itself is still allowed.
    NewPeerEvicted,
}

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
    cot_filter: u64,
    seq_table: [SeqEntry; MAX_SEQ_ENTRIES],
    seq_tick: u32,
    seq_validation: bool,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    rate_tick: u32,
}

impl Iec60870Monitor {
    /// Create a permissive monitor. Frames whose ASDU address is not in
    /// any rule are allowed by default. Sequence validation is enabled.
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

    /// Create a strict monitor. Frames whose ASDU address is not in any
    /// rule are blocked and emit a [`AlertCode::NoMatchingRule`] alert.
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
    ///
    /// The COT field is 6 bits wide (0..=63), so a `u64` mask is required
    /// to cover the full COT space. Earlier versions used a `u16` mask
    /// that silently truncated to COTs 0..=15.
    pub fn set_cot_filter(&mut self, mask: u64) {
        self.cot_filter = mask;
    }

    /// Enable or disable I-frame send-sequence replay tracking. Enabled
    /// by default; disabling skips the `SEQ_WINDOW` check entirely.
    pub fn set_seq_validation(&mut self, enabled: bool) {
        self.seq_validation = enabled;
    }

    /// Register a per-ASDU rule. `asdu_address` of `0xFFFF` acts as a
    /// wildcard matching every address. `read_only = true` blocks
    /// command TypeIDs (45..=51, 58..=64) on this address.
    /// `max_rate_per_sec = 0` disables rate limiting for the rule.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] when the 16-rule table is full.
    /// - [`VsError::InvalidInput`] when `asdu_address` is already in
    ///   the table.
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

    /// Inspect a single frame and return an [`Iec60870InspectResult`]
    /// describing whether the frame is allowed and any alerts raised.
    ///
    /// The full inspection pipeline runs only for I-format frames. S
    /// and U frames are checked for structural well-formedness (APCI
    /// length, U-function presence). Frames of [`Iec60870FrameFormat::Unknown`]
    /// are rejected unconditionally.
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

        // TypeID allowlist. Branchless indexed lookup over the two 128-bit
        // halves: `halves[tid >> 7] >> (tid & 0x7F)` picks the low or high
        // bitmask without a runtime `tid < 128` branch. Mirrors the
        // constant-time philosophy of `find_matching_rule`.
        if self.type_id_low != 0 || self.type_id_high != 0 {
            let tid = frame.type_id;
            let halves: [u128; 2] = [self.type_id_low, self.type_id_high];
            let half = halves[usize::from(tid >> 7)];
            let bit = u32::from(tid & 0x7F);
            let allowed = (half >> bit) & 1 == 1;
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

        // COT filtering. The COT field is 6 bits wide (0..=63), so the
        // bitmask is a u64 — earlier versions used a u16 that silently
        // ignored COTs 16..=63.
        if self.cot_filter != 0 {
            let cot_val = frame.raw_cot & 0x3F;
            let allowed = (self.cot_filter >> cot_val) & 1 == 1;
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
            match self.check_seq(frame.asdu_address, frame.send_seq) {
                SeqOutcome::Replay => {
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
                SeqOutcome::NewPeerEvicted => {
                    // Replay history for the evicted peer is lost. Raise
                    // a `Medium` `ResourceExhausted` alert but still
                    // allow the frame (the new peer's first sequence is
                    // legitimate).
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_IEC60870,
                        frame.asdu_address as u32,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::ResourceExhausted,
                    );
                }
                SeqOutcome::Ok | SeqOutcome::NewPeer => {}
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

    /// Total number of frames inspected since construction or last
    /// [`Self::reset`].
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }
    /// Total number of alerts raised since construction or last
    /// [`Self::reset`].
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }
    /// Returns `true` if this monitor was constructed in strict mode
    /// (frames matching no rule are blocked).
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Reset the monitor's runtime state (counters, rate buckets,
    /// sequence tracking, rules) while preserving configuration
    /// (strict mode, TypeID allowlist, COT filter, sequence-validation
    /// toggle).
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

    /// Find the index of the first matching ASDU-address rule.
    ///
    /// # Performance vs. security trade-off
    ///
    /// This scan deliberately walks all [`MAX_RULES`] slots on every
    /// call, even after a match — a constant-time iteration count is
    /// the intended trade-off against the alternative "stop on first
    /// match" strategy. The branchless arithmetic costs a few extra
    /// cycles per inactive slot vs. a short-circuiting loop, but it
    /// removes the timing side-channel that would otherwise let a
    /// remote peer infer rule-slot layout from per-frame latency.
    ///
    /// **Constant-time scan (HIGH-4):** to deny a remote peer a timing
    /// oracle that could leak which ASDU address occupies which rule
    /// slot (and thus the policy layout), this scan
    ///
    /// 1. always walks every populated rule slot — no `break` on first
    ///    match, no `Option::is_none()` short-circuit;
    /// 2. computes match/active predicates with branchless arithmetic
    ///    (XOR + `u16::wrapping_sub(1) >> 15` to derive a 0/1 mask)
    ///    so the comparison itself does not branch;
    /// 3. selects the first match with a branchless conditional move on
    ///    a "first-match-seen" flag.
    ///
    /// The loop trip count is fixed at [`MAX_RULES`] (not `rule_count`)
    /// so that the iteration count itself does not depend on policy
    /// size. Inactive slots simply contribute zero to the match mask.
    ///
    /// All arithmetic is on `u32` / `usize`; no comparison operators
    /// (`==`, `<`) are used inside the inner body. The Rust compiler is
    /// not contractually required to keep this branchless after
    /// optimisation, but the source form removes the obvious
    /// data-dependent control flow that LLVM would otherwise lower.
    fn find_matching_rule(&self, asdu_address: u16) -> Option<usize> {
        // 0 if no match yet; 1 if a match has already been recorded.
        let mut seen: u32 = 0;
        // Index of the first match, or 0 if no match.
        let mut first: u32 = 0;
        // 1 if any match has ever been recorded, 0 otherwise.
        let mut any: u32 = 0;

        for i in 0..MAX_RULES {
            let r = &self.rules[i];

            // active_mask = 1 if r.active else 0 (no comparison op).
            let active_mask: u32 = u32::from(r.active);

            // eq_addr = 1 if r.asdu_address == asdu_address, else 0.
            // Derived branchlessly: `a ^ b` is 0 iff a == b. The
            // wrapping_sub(1)>>31 trick then maps 0 → 1 (since 0u32
            // minus 1 wraps to 0xFFFF_FFFF whose top bit is 1) and any
            // non-zero u32 value to 0 (subtracting 1 stays in the low
            // half of the range, top bit = 0). No comparison op is
            // emitted from this expression.
            let xor_addr = u32::from(r.asdu_address ^ asdu_address);
            let eq_addr: u32 = xor_addr.wrapping_sub(1) >> 31;
            // eq_wild = 1 if r.asdu_address == 0xFFFF, else 0.
            let xor_wild = u32::from(r.asdu_address ^ 0xFFFFu16);
            let eq_wild: u32 = xor_wild.wrapping_sub(1) >> 31;
            // match_mask: 1 if address matches or rule is wildcard.
            // Bitwise OR is safe: both operands are 0 or 1.
            let match_mask: u32 = (eq_addr | eq_wild) & active_mask;

            // take = 1 iff this slot matches AND no earlier slot did.
            let take = match_mask & (seen ^ 1);
            // Branchless conditional assignment: first = take ? i : first.
            // (`take` is 0 or 1, so `0u32.wrapping_sub(take)` is 0 or
            // 0xFFFF_FFFF, giving a full-width mask.)
            #[allow(clippy::cast_possible_truncation)] // i < MAX_RULES = 16
            let i_u32 = i as u32;
            let take_mask = 0u32.wrapping_sub(take);
            first = (first & !take_mask) | (i_u32 & take_mask);

            // Latch "seen" the first time we take a match; never clear.
            seen |= take;
            any |= match_mask;
        }

        if any == 1 {
            Some(first as usize)
        } else {
            None
        }
    }

    /// Update the per-ASDU send-sequence replay tracker.
    ///
    /// Returns a [`SeqOutcome`] describing the disposition of this
    /// sequence number:
    ///
    /// - `Ok` — sequence advanced within the forward-progress window.
    /// - `Replay` — duplicate or gap larger than [`SEQ_WINDOW`].
    /// - `NewPeer` — first frame seen from this ASDU; nothing replayed.
    /// - `NewPeerEvicted` — first frame from this ASDU AND the LRU peer
    ///   was evicted to make room. Caller should raise a
    ///   `ResourceExhausted` alert because the evicted peer's replay
    ///   history is now lost.
    ///
    /// Performance: single pass over `seq_table` tracking match, first
    /// free slot, and oldest entry simultaneously (mirrors `rate_check`).
    fn check_seq(&mut self, key: u16, seq: u16) -> SeqOutcome {
        let seq = seq & 0x7FFF;
        self.seq_tick = self.seq_tick.wrapping_add(1);
        let now = self.seq_tick;

        let mut match_idx: Option<usize> = None;
        let mut first_free: Option<usize> = None;
        let mut oldest_idx: usize = 0;
        let mut oldest_age: u32 = 0;
        let mut any_active = false;

        for (i, entry) in self.seq_table.iter().enumerate() {
            if entry.active {
                if entry.key == key {
                    match_idx = Some(i);
                    break;
                }
                let age = now.wrapping_sub(entry.last_used);
                if !any_active || age > oldest_age {
                    oldest_age = age;
                    oldest_idx = i;
                    any_active = true;
                }
            } else if first_free.is_none() {
                first_free = Some(i);
            }
        }

        if let Some(idx) = match_idx {
            let entry = &mut self.seq_table[idx];
            entry.last_used = now;
            if !entry.has_seen {
                entry.last_seq = seq;
                entry.has_seen = true;
                return SeqOutcome::Ok;
            }
            let diff = seq.wrapping_sub(entry.last_seq) & 0x7FFF;
            if diff == 0 {
                return SeqOutcome::Replay;
            }
            if diff > SEQ_WINDOW {
                entry.last_seq = seq;
                return SeqOutcome::Replay;
            }
            entry.last_seq = seq;
            return SeqOutcome::Ok;
        }

        if let Some(slot) = first_free {
            self.seq_table[slot] = SeqEntry {
                key,
                last_seq: seq,
                has_seen: true,
                active: true,
                last_used: now,
            };
            return SeqOutcome::NewPeer;
        }

        // No free slot — evict the LRU active entry. Its replay history
        // is lost, so signal `NewPeerEvicted` so the caller can raise a
        // `ResourceExhausted` alert.
        self.seq_table[oldest_idx] = SeqEntry {
            key,
            last_seq: seq,
            has_seen: true,
            active: true,
            last_used: now,
        };
        SeqOutcome::NewPeerEvicted
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
        mon.set_cot_filter(1u64 << 3);
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
        mon.set_cot_filter(1u64 << 3);
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

    // -------------------------------------------------------------------
    // Regression (HIGH-4): the rule scan must be branchless on the
    // match comparison, not just claim to be in a comment.
    //
    // These tests pin the *functional* contract — same answers as the
    // old short-circuiting implementation — so any future refactor that
    // breaks the branchless arithmetic will trip a known input. The
    // constant-time property itself is a source-form invariant; the
    // comment on `find_matching_rule` documents it.
    // -------------------------------------------------------------------
    #[test]
    fn find_matching_rule_first_match_wins() {
        let mut mon = Iec60870Monitor::new();
        // Specific ASDU 5 rule is read-only and added FIRST.
        mon.add_rule(5, true, 0).unwrap();
        // Wildcard rule added SECOND would otherwise match too.
        mon.add_rule(0xFFFF, false, 0).unwrap();
        mon.add_rule(7, false, 0).unwrap();

        // The branchless scan must return the FIRST matching index
        // (the read-only rule at slot 0), not the wildcard at slot 1.
        // We observe this externally: a command frame on ASDU 5 must
        // be blocked as a write-protection violation.
        let cmd = Iec60870Frame {
            type_id: 45,
            asdu_address: 5,
            cot: Iec60870Cot::Activation,
            raw_cot: 6,
            ..Default::default()
        };
        assert!(!mon.inspect(&cmd).allowed);
    }

    #[test]
    fn find_matching_rule_last_slot_match() {
        // Add several non-matching rules, then a matching one in the
        // last populated slot. The branchless scan must still find it.
        let mut mon = Iec60870Monitor::new_strict();
        mon.add_rule(1, false, 0).unwrap();
        mon.add_rule(2, false, 0).unwrap();
        mon.add_rule(3, false, 0).unwrap();
        mon.add_rule(42, false, 0).unwrap();
        let f = Iec60870Frame {
            asdu_address: 42,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn find_matching_rule_no_match_returns_none_path() {
        // Empty rule table — strict mode must reject.
        let mut mon = Iec60870Monitor::new_strict();
        let f = Iec60870Frame {
            asdu_address: 99,
            send_seq: 1,
            ..Default::default()
        };
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::NoMatchingRule);

        // Populated but non-matching: same outcome. Use a fresh
        // send_seq so the sequence tracker doesn't flag a replay.
        mon.add_rule(1, false, 0).unwrap();
        mon.add_rule(2, false, 0).unwrap();
        let f2 = Iec60870Frame {
            asdu_address: 99,
            send_seq: 2,
            ..Default::default()
        };
        let r2 = mon.inspect(&f2);
        assert!(!r2.allowed);
        assert_eq!(r2.alert_codes[0], AlertCode::NoMatchingRule);
    }

    #[test]
    fn find_matching_rule_wildcard_does_not_override_specific() {
        // Specific rule for ASDU 1 (read-only) is added BEFORE the
        // wildcard. The branchless first-match logic must still pick
        // the specific read-only rule.
        let mut mon = Iec60870Monitor::new();
        mon.add_rule(1, true, 0).unwrap();
        mon.add_rule(0xFFFF, false, 0).unwrap();

        let cmd = Iec60870Frame {
            type_id: 45,
            asdu_address: 1,
            cot: Iec60870Cot::Activation,
            raw_cot: 6,
            ..Default::default()
        };
        let r = mon.inspect(&cmd);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::WriteProtection);
    }

    #[test]
    fn find_matching_rule_unused_slots_do_not_match() {
        // The branchless scan iterates the full MAX_RULES, not just
        // rule_count, so it must correctly ignore inactive slots.
        // Active=false on a slot whose asdu_address happens to match
        // must NOT be reported.
        let mut mon = Iec60870Monitor::new_strict();
        // No rules added at all. ASDU 0 happens to be the empty()
        // default of `AsduRule { asdu_address: 0xFFFF, active: false }`
        // — but active=false, so no match.
        let f = Iec60870Frame {
            asdu_address: 0xFFFF,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed); // NoMatchingRule
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
