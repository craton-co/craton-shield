#![no_std]
#![deny(missing_docs)]

//! IEC 61850 MMS / GOOSE / SV anomaly-detection monitor.
//!
//! Monitors IEC 61850 substation traffic for behavioural anomalies across
//! the three protocol layers carried inside a substation automation system.
//!
//! # Security model
//!
//! **This crate does NOT implement IEC 62351-6 GOOSE/SV authentication.
//! There is no HMAC verification, no signing, and no cryptographic trust
//! root.** Frames are accepted on the wire as-is; the monitor only inspects
//! their plaintext fields.
//!
//! Detection is **heuristic**, based on:
//!
//! - `src_mac` of the publishing Ethernet frame,
//! - `stNum` / `sqNum` counters and baseline-no-downgrade rules,
//! - timing windows (retransmission decay, `t`-field monotonicity),
//! - per-publisher bindings learned from configuration or observation.
//!
//! An attacker who can replicate a legitimate publisher's `src_mac` and
//! increment the `stNum` / `sqNum` counters correctly **cannot be detected
//! by this crate**. Layer-2 MAC spoofing on a shared substation LAN is
//! trivial for any attacker with bus access. Treat all alerts emitted by
//! this monitor as **forensic / anomaly signals**, not as authenticated
//! rejection of a cryptographically untrusted peer.
//!
//! For production-grade authentication, consult **IEC 62351-6:2020**
//! (cyber security for IEC 61850 GOOSE and Sampled Values) and provide a
//! HMAC / signature-verifying layer below or alongside this monitor.
//!
//! ## MMS (Manufacturing Message Specification, ISO 9506)
//!
//! - **Service-type allowlist** — bitmask filter for MMS service types.
//! - **Write protection** — block Write, Define/Delete operations.
//! - **Rate limiting** — per-invoke-ID token buckets.
//! - **Control-block reservation tracking** — observe `SelectControl` /
//!   `Select` operations and remember which client (`invoke_id` namespace)
//!   owns each GoCB / SvCB. Subsequent GOOSE / SV traffic addressing that
//!   control block from a different publisher MAC is flagged as
//!   [`AlertCode::CbHijack`]. This is a heuristic hijack indicator, not an
//!   authenticated rejection.
//!
//! ## GOOSE (Generic Object Oriented Substation Event, IEC 61850-8-1)
//!
//! - **Publisher allowlist** — restrict allowed (`src_mac`, `GoCBRef`) pairs
//!   (note: `src_mac` is trivially forgeable; see security model above).
//! - **Replay detection** — `stNum` / `sqNum` tracking with baseline
//!   no-downgrade.
//! - **Test-flag blocking** — optionally block test frames.
//! - **Retransmission interval validation** — IEC 61850-8-1 §B.3.2 mandates
//!   a published retransmission decay (T0, T1=T0*2, T2=T1*2, ..., T_max).
//!   Frames arriving with intervals that materially deviate from the
//!   published schedule are flagged as [`AlertCode::RetransmissionAnomaly`].
//! - **Heuristic time-sync spoofing indicators** — backwards `t` field or
//!   implausibly large forward jumps are flagged as
//!   [`AlertCode::TimeSyncSpoofing`].
//!
//! ## SV (Sampled Values, IEC 61850-9-2)
//!
//! - **smpCnt monotonicity** — backwards step or duplicate flagged as
//!   [`AlertCode::SvReplay`].
//! - **Rate anomaly** — implausibly large smpCnt gaps relative to the
//!   declared `smpRate` flagged as [`AlertCode::SvRateAnomaly`].
//! - **IED binding** — `svID` registered to a fixed publisher MAC; mismatch
//!   flagged as [`AlertCode::IedMismatch`] (heuristic; defeated by MAC
//!   spoofing).
//! - **Heuristic time-sync spoofing indicators** — shared per-IED tracker
//!   with GOOSE.
//! - **Raw-frame parsing** — [`Iec61850Monitor::parse_sv`] decodes a wire
//!   buffer starting at the Ethernet payload (post-VLAN-strip) for
//!   EtherType `0x88BA`.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{
    AlertCode, InspectResult, RateBucket, SvFrame, MAX_SV_DATASET_REF_LEN, MAX_SV_SVID_LEN,
    SOURCE_IEC61850_GOOSE, SOURCE_IEC61850_MMS, SOURCE_IEC61850_SV,
};

/// Inspection result for an IEC 61850 MMS frame (backward-compatible alias).
pub type Iec61850MmsInspectResult = InspectResult;
/// Inspection result for an IEC 61850 GOOSE frame (backward-compatible alias).
pub type Iec61850GooseInspectResult = InspectResult;
/// Inspection result for an IEC 61850-9-2 Sampled Values frame.
pub type Iec61850SvInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_MMS_RULES: usize = 16;
const MAX_RATE_BUCKETS: usize = 16;
const MAX_GOOSE_PUBLISHERS: usize = 16;
const MAX_GOOSE_SEQ_ENTRIES: usize = 16;
const MAX_SV_PUBLISHERS: usize = 16;
const MAX_SV_SEQ_ENTRIES: usize = 16;
const MAX_CB_RESERVATIONS: usize = 16;
const MAX_TIME_TRACKERS: usize = 16;

/// IEC 61850 SV / GOOSE EtherType (used by raw-frame parsers).
pub const ETHERTYPE_SV: u16 = 0x88BA;
/// IEC 61850 GOOSE EtherType.
pub const ETHERTYPE_GOOSE: u16 = 0x88B8;
/// 802.1Q VLAN tag EtherType.
pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;

/// Heuristic distance threshold for distinguishing a legitimate smpCnt
/// cycle wrap from a suspicious near-wrap forward gap.
///
/// `smpCnt` is a `u16` that wraps every nominal cycle. A naive
/// signed-style comparison would map any transition where `cur < prev`
/// to a clean wrap — but a near-wrap forward gap (e.g. `prev = 65_530`,
/// `cur = 10`, an actual forward jump of 16 samples) is then silently
/// classified as a wrap. We treat any wrap-like transition whose
/// implied forward distance is greater than this threshold as a
/// legitimate wrap; smaller distances are suspicious and alerted as
/// [`AlertCode::SvRateAnomaly`] (semantic close-relative of the
/// requested `SuspiciousSmpGap`).
pub const MAX_SMP_GAP_WINDOW: u16 = 256;

// ---------------------------------------------------------------------------
// MMS frame types
// ---------------------------------------------------------------------------

/// MMS confirmed service types relevant for IDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MmsServiceType {
    /// `Read` — read variable values (no state change).
    Read = 1,
    /// `Write` — write variable values (state-modifying).
    Write = 2,
    /// `GetNameList` — enumerate domain / variable names.
    GetNameList = 3,
    /// `GetVariableAccessAttributes` — query variable metadata.
    GetVariableAccessAttributes = 4,
    /// `DefineNamedVariable` — create a new named variable (state-modifying).
    DefineNamedVariable = 5,
    /// `DeleteNamedVariable` — remove a named variable (state-modifying).
    DeleteNamedVariable = 6,
    /// `GetDataValues` — read data attribute values.
    GetDataValues = 7,
    /// `SetDataValues` — write data attribute values (state-modifying).
    SetDataValues = 8,
    /// `Initiate` — open the MMS association.
    Initiate = 9,
    /// `Conclude` — close the MMS association.
    Conclude = 10,
    /// `SelectControl` / `Select` on a control block (GoCB / SvCB).
    /// Used to reserve a control block to one client before issuing
    /// `Operate` / `SetGoCBValues`. Tracked by the monitor for hijack
    /// detection.
    SelectControl = 11,
    /// Cancel a previous `SelectControl` reservation (release).
    CancelControl = 12,
    /// Unknown / unsupported service type.
    Unknown = 0xFF,
}

impl MmsServiceType {
    /// Decode an MMS service-type byte from the wire.
    ///
    /// Values outside the recognised range are mapped to
    /// [`MmsServiceType::Unknown`].
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
            11 => Self::SelectControl,
            12 => Self::CancelControl,
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

/// Identifier of an MMS client (e.g., association / TCP-connection ID).
///
/// The monitor uses this opaque `u32` to scope control-block reservations.
/// Two frames with the same `client_id` are treated as the same MMS client.
pub type MmsClientId = u32;

/// An IEC 61850 MMS frame as seen by the IDS.
///
/// When `service_type == SelectControl` or `CancelControl`, the
/// `domain` / `domain_len` field carries the GoCB / SvCB object reference
/// being (de)reserved — the field is re-used to keep the frame size stable.
/// Callers wanting to reserve a specific GoCB/SvCB should place its
/// object-reference into `domain`.
#[derive(Debug, Clone, Copy)]
pub struct MmsFrame {
    /// Decoded MMS service type for this frame.
    pub service_type: MmsServiceType,
    /// Raw service-type byte as observed on the wire.
    pub raw_service_type: u8,
    /// MMS domain / item / control-block reference bytes.
    pub domain: [u8; MAX_MMS_DOMAIN_LEN],
    /// Valid length of [`MmsFrame::domain`].
    pub domain_len: u8,
    /// MMS `invokeID` for this confirmed service.
    pub invoke_id: u32,
    /// Local capture timestamp in microseconds.
    pub timestamp_us: u64,
    /// Identifier of the MMS client / association that sent this frame.
    /// Used to scope control-block reservations for hijack detection.
    pub client_id: MmsClientId,
    /// `true` when the control block referenced by `domain` is a GoCB
    /// (GOOSE control block); `false` for an SvCB (SV control block).
    /// Only meaningful for `SelectControl` / `CancelControl` frames.
    pub control_block_is_goose: bool,
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
            client_id: 0,
            control_block_is_goose: true,
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
    /// Ethernet source MAC of the publisher.
    pub src_mac: [u8; 6],
    /// GOOSE control-block reference bytes (e.g. `IED1/LLN0$GO$GoCB01`).
    pub go_cb_ref: [u8; MAX_GOOSE_GOCBREF_LEN],
    /// Valid length of [`GooseFrame::go_cb_ref`].
    pub go_cb_ref_len: u8,
    /// `stNum` — incremented on every state change of the dataset.
    pub st_num: u32,
    /// `sqNum` — retransmission counter within the current state.
    pub sq_num: u32,
    /// `test` flag — set by simulation tools to mark non-operational frames.
    pub test: bool,
    /// Local capture timestamp (microseconds).
    pub timestamp_us: u64,
    /// IEC 61850 `t` (UTC timestamp) — seconds since Unix epoch. 0 if absent.
    pub t_seconds_since_epoch: u32,
    /// IEC 61850 `t` (UTC timestamp) — fractional seconds (24-bit). 0 if absent.
    pub t_fraction_of_second: u32,
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
            t_seconds_since_epoch: 0,
            t_fraction_of_second: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Retransmission schedule
// ---------------------------------------------------------------------------

/// GOOSE retransmission decay schedule (IEC 61850-8-1 §B.3.2 / §A.3).
///
/// After a state change (`stNum` increment) the publisher emits the new
/// state with `sqNum = 0`, then retransmits at exponentially increasing
/// intervals capped at `t_max_us`:
///
/// ```text
/// T0 = initial_us, T1 = T0 * 2, T2 = T1 * 2, ... clamped to t_max_us.
/// ```
///
/// When no state change occurs the publisher continues to emit at
/// `t_max_us` (heartbeat). The monitor verifies that observed
/// retransmission intervals are within a tolerance band of the expected
/// schedule.
#[derive(Debug, Clone, Copy)]
pub struct RetxSchedule {
    /// Initial retransmission interval `T0` in microseconds.
    pub initial_us: u32,
    /// Maximum (steady-state heartbeat) interval in microseconds.
    pub t_max_us: u32,
    /// Allowed tolerance as a fraction (e.g. 25 = ±25 %).
    pub tolerance_pct: u8,
}

impl RetxSchedule {
    /// Default schedule per IEC 61850-8-1 informative annex:
    /// `T0 = 4 ms`, `T_max = 1 s`, tolerance ±25 %.
    pub const fn default_8_1() -> Self {
        Self {
            initial_us: 4_000,
            t_max_us: 1_000_000,
            tolerance_pct: 25,
        }
    }

    /// Compute the expected interval for the `n`-th retransmission within
    /// a state (sqNum). `n = 0` is the state-change frame itself (no
    /// predecessor — caller should skip the check for it).
    ///
    /// Saturates at `t_max_us`. `n` is clamped to 31 to avoid overflow.
    pub fn expected_interval_us(self, n: u32) -> u32 {
        let n = n.min(31);
        let scaled = (self.initial_us as u64).saturating_mul(1u64 << n);
        let clamped = scaled.min(self.t_max_us as u64);
        clamped as u32
    }

    /// Returns `true` if `observed_us` is within `±tolerance_pct` of
    /// `expected_us`.
    pub fn within_tolerance(self, observed_us: u32, expected_us: u32) -> bool {
        let tol = (expected_us as u64 * self.tolerance_pct as u64) / 100;
        let lo = (expected_us as u64).saturating_sub(tol);
        let hi = (expected_us as u64).saturating_add(tol);
        let obs = observed_us as u64;
        obs >= lo && obs <= hi
    }
}

impl Default for RetxSchedule {
    fn default() -> Self {
        Self::default_8_1()
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
    /// FNV-1a 32-bit hash of the GoCBRef bytes for the publisher this entry
    /// tracks. Combined with `src_mac` to form the per-publisher /
    /// per-control-block tracker key — see security regression test
    /// `goose_replay_tracker_keyed_on_gocb_ref` (two GoCBs from the same IED
    /// MUST NOT share a tracker, or one can downgrade the other's baseline).
    go_cb_ref_hash: u32,
    last_st_num: u32,
    last_sq_num: u32,
    has_seen: bool,
    active: bool,
    last_used: u32,
    /// Timestamp of the most recently observed frame in this state, for
    /// retransmission-interval enforcement.
    last_seen_us: u64,
}

impl GooseSeqEntry {
    const fn empty() -> Self {
        Self {
            src_mac: [0u8; 6],
            go_cb_ref_hash: 0,
            last_st_num: 0,
            last_sq_num: 0,
            has_seen: false,
            active: false,
            last_used: 0,
            last_seen_us: 0,
        }
    }
}

/// FNV-1a 32-bit hash of the input bytes.
///
/// Used to compress a variable-length GoCBRef (up to
/// [`MAX_GOOSE_GOCBREF_LEN`] bytes) into a fixed 32-bit key so the GOOSE
/// replay tracker can index by `(src_mac, gocb_ref)` without storing the
/// full reference in every entry. Collision risk is negligible for typical
/// substation deployments (< 1000 GoCBs).
fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[derive(Clone, Copy)]
struct SvPublisherRule {
    src_mac: [u8; 6],
    svid: [u8; MAX_SV_SVID_LEN],
    svid_len: u8,
    /// Declared sample rate per nominal cycle (used as the expected
    /// per-second extrapolation baseline). 0 = unspecified, skip rate
    /// anomaly checks for this publisher.
    expected_smp_rate: u16,
    active: bool,
}

impl SvPublisherRule {
    const fn empty() -> Self {
        Self {
            src_mac: [0u8; 6],
            svid: [0u8; MAX_SV_SVID_LEN],
            svid_len: 0,
            expected_smp_rate: 0,
            active: false,
        }
    }

    fn matches_svid(&self, svid: &[u8], svid_len: u8) -> bool {
        if !self.active {
            return false;
        }
        if self.svid_len != svid_len {
            return false;
        }
        let len = self.svid_len as usize;
        self.svid[..len] == svid[..len]
    }
}

#[derive(Clone, Copy)]
struct SvSeqEntry {
    svid: [u8; MAX_SV_SVID_LEN],
    svid_len: u8,
    last_smp_cnt: u16,
    last_seen_us: u64,
    has_seen: bool,
    active: bool,
    last_used: u32,
}

impl SvSeqEntry {
    const fn empty() -> Self {
        Self {
            svid: [0u8; MAX_SV_SVID_LEN],
            svid_len: 0,
            last_smp_cnt: 0,
            last_seen_us: 0,
            has_seen: false,
            active: false,
            last_used: 0,
        }
    }

    fn matches(&self, svid: &[u8], svid_len: u8) -> bool {
        if !self.active {
            return false;
        }
        if self.svid_len != svid_len {
            return false;
        }
        let len = self.svid_len as usize;
        self.svid[..len] == svid[..len]
    }
}

/// A GoCB / SvCB reservation owned by an MMS client.
#[derive(Clone, Copy)]
struct CbReservation {
    /// Object reference (e.g. `IED1/LLN0$GO$GoCB01`).
    cb_ref: [u8; MAX_GOOSE_GOCBREF_LEN],
    cb_ref_len: u8,
    /// Owning MMS client id (association handle).
    owner_client_id: MmsClientId,
    /// Publisher MAC that owns the control block on the wire. Set the
    /// first time we observe a matching GOOSE/SV frame from the
    /// allowlisted publisher. Used to detect a *different* MAC trying to
    /// publish the same GoCB.
    bound_src_mac: [u8; 6],
    bound: bool,
    /// `true` when reservation targets a GoCB, `false` for SvCB.
    is_goose: bool,
    active: bool,
    last_used: u32,
}

impl CbReservation {
    const fn empty() -> Self {
        Self {
            cb_ref: [0u8; MAX_GOOSE_GOCBREF_LEN],
            cb_ref_len: 0,
            owner_client_id: 0,
            bound_src_mac: [0u8; 6],
            bound: false,
            is_goose: true,
            active: false,
            last_used: 0,
        }
    }

    fn matches_ref(&self, cb_ref: &[u8], cb_ref_len: u8, is_goose: bool) -> bool {
        if !self.active {
            return false;
        }
        if self.is_goose != is_goose {
            return false;
        }
        if self.cb_ref_len != cb_ref_len {
            return false;
        }
        let len = self.cb_ref_len as usize;
        self.cb_ref[..len] == cb_ref[..len]
    }
}

/// Per-IED `t`-field tracker for time-sync spoofing detection.
#[derive(Clone, Copy)]
struct TimeTracker {
    src_mac: [u8; 6],
    last_t_seconds: u32,
    last_t_fraction: u32,
    has_seen: bool,
    active: bool,
    last_used: u32,
}

impl TimeTracker {
    const fn empty() -> Self {
        Self {
            src_mac: [0u8; 6],
            last_t_seconds: 0,
            last_t_fraction: 0,
            has_seen: false,
            active: false,
            last_used: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// IEC 61850 MMS / GOOSE / SV intrusion detection monitor.
#[allow(clippy::struct_excessive_bools)]
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
    // SV state
    sv_publishers: [SvPublisherRule; MAX_SV_PUBLISHERS],
    sv_publisher_count: u8,
    sv_seq_table: [SvSeqEntry; MAX_SV_SEQ_ENTRIES],
    sv_seq_tick: u32,
    sv_total_inspected: u64,
    /// Maximum smpCnt forward gap accepted in a single frame transition.
    /// 0 disables the check.
    sv_max_smp_cnt_gap: u16,
    // Control-block reservations
    cb_reservations: [CbReservation; MAX_CB_RESERVATIONS],
    cb_reservation_tick: u32,
    // Retransmission schedule
    retx_schedule: RetxSchedule,
    retx_enforce: bool,
    // Time-sync trackers (per IED MAC, shared between GOOSE / SV)
    time_trackers: [TimeTracker; MAX_TIME_TRACKERS],
    time_tracker_tick: u32,
    /// Maximum forward `t`-field jump (seconds) accepted between two
    /// consecutive frames from the same IED. 0 disables the forward check.
    time_max_forward_jump_s: u32,
    // Shared
    strict_mode: bool,
    mms_total_inspected: u64,
    goose_total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
}

impl Iec61850Monitor {
    /// Construct a new monitor with permissive defaults — no rules, no
    /// allowlists, no enforcement. Configure via the `set_*` and `add_*`
    /// helpers.
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
            sv_publishers: [SvPublisherRule::empty(); MAX_SV_PUBLISHERS],
            sv_publisher_count: 0,
            sv_seq_table: [SvSeqEntry::empty(); MAX_SV_SEQ_ENTRIES],
            sv_seq_tick: 0,
            sv_total_inspected: 0,
            sv_max_smp_cnt_gap: 0,
            cb_reservations: [CbReservation::empty(); MAX_CB_RESERVATIONS],
            cb_reservation_tick: 0,
            retx_schedule: RetxSchedule::default_8_1(),
            retx_enforce: false,
            time_trackers: [TimeTracker::empty(); MAX_TIME_TRACKERS],
            time_tracker_tick: 0,
            time_max_forward_jump_s: 0,
            strict_mode: false,
            mms_total_inspected: 0,
            goose_total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
        }
    }

    /// Construct a new monitor in *strict* mode — frames that do not match
    /// any rule are denied (`AlertCode::NoMatchingRule`).
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

    /// Bind an `svID` to a fixed publisher MAC. Frames advertising the same
    /// `svID` from a different MAC will be flagged as
    /// [`AlertCode::IedMismatch`]. Pass `expected_smp_rate = 0` to skip
    /// rate anomaly checks for this publisher.
    pub fn add_sv_publisher(
        &mut self,
        src_mac: [u8; 6],
        svid: &[u8],
        expected_smp_rate: u16,
    ) -> Result<(), VsError> {
        if self.sv_publisher_count as usize >= MAX_SV_PUBLISHERS {
            return Err(VsError::ResourceExhausted);
        }
        if svid.len() > MAX_SV_SVID_LEN {
            return Err(VsError::InvalidInput);
        }
        let idx = self.sv_publisher_count as usize;
        let mut rule = SvPublisherRule::empty();
        rule.src_mac = src_mac;
        rule.svid[..svid.len()].copy_from_slice(svid);
        rule.svid_len = svid.len() as u8;
        rule.expected_smp_rate = expected_smp_rate;
        rule.active = true;
        self.sv_publishers[idx] = rule;
        self.sv_publisher_count += 1;
        Ok(())
    }

    /// Set whether test-flagged GOOSE frames are blocked.
    pub fn set_block_test_frames(&mut self, block: bool) {
        self.block_test_frames = block;
    }

    /// Set the maximum smpCnt forward gap accepted in a single frame
    /// transition. 0 disables the check.
    pub fn set_sv_max_smp_cnt_gap(&mut self, gap: u16) {
        self.sv_max_smp_cnt_gap = gap;
    }

    /// Configure GOOSE retransmission schedule enforcement.
    pub fn set_retx_schedule(&mut self, schedule: RetxSchedule, enforce: bool) {
        self.retx_schedule = schedule;
        self.retx_enforce = enforce;
    }

    /// Set the maximum forward `t`-field jump (seconds) accepted between
    /// two consecutive frames from the same IED. 0 disables the forward
    /// check. Backwards jumps are always flagged.
    pub fn set_time_max_forward_jump_s(&mut self, seconds: u32) {
        self.time_max_forward_jump_s = seconds;
    }

    // -----------------------------------------------------------------------
    // MMS inspection
    // -----------------------------------------------------------------------

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

        // Per-rule matching. First-match-wins — callers are expected to
        // have inserted rules in descending priority order. We break on
        // the first match rather than scanning to the end of the rule
        // table.
        let mut matched: Option<usize> = None;
        for i in 0..self.mms_rule_count as usize {
            let r = &self.mms_rules[i];
            if !r.active {
                continue;
            }
            let svc = frame.raw_service_type;
            if r.service_mask == 0xFFFF || (svc < 16 && (r.service_mask >> svc) & 1 == 1) {
                matched = Some(i);
                break;
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
                return result;
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
            return result;
        }

        // Control-block reservation side-effects.
        // SelectControl reserves; CancelControl / Conclude releases.
        match frame.service_type {
            MmsServiceType::SelectControl => {
                let len = (frame.domain_len as usize).min(MAX_MMS_DOMAIN_LEN);
                let r = self.reserve_cb(
                    &frame.domain[..len],
                    len as u8,
                    frame.client_id,
                    frame.control_block_is_goose,
                );
                if r.is_err() {
                    // Out of slots — alert, but allow frame.
                    result.push_alert_with_code(
                        AlertSeverity::Low,
                        SOURCE_IEC61850_MMS,
                        frame.invoke_id,
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::ResourceExhausted,
                    );
                }
            }
            MmsServiceType::CancelControl | MmsServiceType::Conclude => {
                let len = (frame.domain_len as usize).min(MAX_MMS_DOMAIN_LEN);
                self.release_cb(
                    &frame.domain[..len],
                    len as u8,
                    frame.client_id,
                    frame.control_block_is_goose,
                );
            }
            _ => {}
        }

        result
    }

    // -----------------------------------------------------------------------
    // GOOSE inspection
    // -----------------------------------------------------------------------

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

        // Control-block hijack: any reservation for this GoCB must accept
        // this src_mac, or bind it on first observation.
        let cb_len = (frame.go_cb_ref_len as usize).min(MAX_GOOSE_GOCBREF_LEN);
        if self.cb_hijack_check(
            &frame.go_cb_ref[..cb_len],
            cb_len as u8,
            true,
            frame.src_mac,
        ) {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_IEC61850_GOOSE,
                frame.st_num,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::CbHijack,
            );
            return result;
        }

        // Time-sync spoofing check (before mutating seq state).
        if self.check_time_field(
            frame.src_mac,
            frame.t_seconds_since_epoch,
            frame.t_fraction_of_second,
        ) {
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_IEC61850_GOOSE,
                frame.st_num,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::TimeSyncSpoofing,
            );
            result.allowed = false;
            // Continue to also record the seq update — do NOT return early
            // so a single malicious frame with both spoofing + replay
            // still produces the strongest alert and updates state.
        }

        // GoCBRef hash for per-(MAC, GoCBRef) tracker keying (security:
        // the replay tracker must be keyed on both publisher MAC AND
        // GoCBRef — one IED can host multiple GoCBs, and their stNum
        // counters are independent).
        let go_cb_ref_hash =
            fnv1a_32(&frame.go_cb_ref[..(frame.go_cb_ref_len as usize).min(MAX_GOOSE_GOCBREF_LEN)]);

        // Retransmission interval enforcement (must run before seq update so
        // we have the predecessor timestamp + sqNum).
        //
        // We deliberately scope this check to `entry.last_st_num ==
        // frame.st_num`: per IEC 61850-8-1 §B.3.2, a `stNum` increment
        // (state change) resets `sqNum` back to 0 and restarts the
        // retransmission decay (T0, T1, ...). Comparing a post-state-
        // change frame's inter-arrival against the *previous* state's
        // sqNum would mis-classify normal IED behaviour as anomalous —
        // hence we only enforce within an unchanged state.
        let mut retx_anomaly = false;
        if self.retx_enforce {
            if let Some(prev) = self.find_goose_seq(frame.src_mac, go_cb_ref_hash) {
                let entry = self.goose_seq_table[prev];
                if entry.has_seen
                    && entry.last_st_num == frame.st_num
                    && frame.sq_num > entry.last_sq_num
                    && frame.timestamp_us >= entry.last_seen_us
                {
                    let observed = (frame.timestamp_us - entry.last_seen_us).min(u32::MAX as u64);
                    let expected = self.retx_schedule.expected_interval_us(frame.sq_num);
                    if !self
                        .retx_schedule
                        .within_tolerance(observed as u32, expected)
                    {
                        retx_anomaly = true;
                    }
                }
            }
        }

        // Replay detection (mutates seq state and last_seen_us).
        let replay = self.check_goose_seq(
            frame.src_mac,
            go_cb_ref_hash,
            frame.st_num,
            frame.sq_num,
            frame.timestamp_us,
        );
        if matches!(replay, Some(true)) {
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

        if retx_anomaly {
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_IEC61850_GOOSE,
                frame.st_num,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::RetransmissionAnomaly,
            );
            // Retx anomaly is not by itself a deny — but flagged. Keep
            // `allowed = true` so downstream policies can choose.
        }

        result
    }

    // -----------------------------------------------------------------------
    // SV inspection
    // -----------------------------------------------------------------------

    /// Inspect an IEC 61850-9-2 Sampled Values frame.
    pub fn inspect_sv(&mut self, frame: &SvFrame) -> Iec61850SvInspectResult {
        self.sv_total_inspected = self.sv_total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_IEC61850_SV);

        let svid_len = if (frame.svid_len as usize) <= MAX_SV_SVID_LEN {
            frame.svid_len
        } else {
            MAX_SV_SVID_LEN as u8
        };
        let svid_bytes = &frame.svid[..svid_len as usize];

        // Publisher binding: if an svID is registered, the src_mac MUST
        // match. Unknown svIDs are allowed when no publishers are registered;
        // in strict mode an unknown svID denies.
        let mut bound_publisher_smp_rate: u16 = 0;
        if self.sv_publisher_count > 0 {
            let mut matched_svid = false;
            let mut mac_ok = false;
            for i in 0..self.sv_publisher_count as usize {
                let p = &self.sv_publishers[i];
                if p.matches_svid(svid_bytes, svid_len) {
                    matched_svid = true;
                    if p.src_mac == frame.src_mac {
                        mac_ok = true;
                        bound_publisher_smp_rate = p.expected_smp_rate;
                    }
                }
            }
            if matched_svid && !mac_ok {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC61850_SV,
                    u32::from(frame.smp_cnt),
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::IedMismatch,
                );
                return result;
            }
            if !matched_svid && self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC61850_SV,
                    u32::from(frame.smp_cnt),
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::PolicyViolation,
                );
                return result;
            }
        }

        // Control-block hijack on SvCB (datSet ref carries the SvCB
        // reference for IEC 61850 multi-cast SV).
        let cb_len = (frame.dataset_ref_len as usize).min(MAX_SV_DATASET_REF_LEN);
        if cb_len > 0
            && self.cb_hijack_check(
                &frame.dataset_ref[..cb_len],
                cb_len as u8,
                false,
                frame.src_mac,
            )
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_IEC61850_SV,
                u32::from(frame.smp_cnt),
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::CbHijack,
            );
            return result;
        }

        // Time-sync spoofing (shared per-IED tracker).
        if self.check_time_field(
            frame.src_mac,
            frame.t_seconds_since_epoch,
            frame.t_fraction_of_second,
        ) {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_IEC61850_SV,
                u32::from(frame.smp_cnt),
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::TimeSyncSpoofing,
            );
            // Continue — also update smpCnt state.
        }

        // smpCnt replay / gap anomaly.
        let smp_outcome =
            self.check_sv_seq(svid_bytes, svid_len, frame.smp_cnt, frame.timestamp_us);
        match smp_outcome {
            SvSeqOutcome::Replay => {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_IEC61850_SV,
                    u32::from(frame.smp_cnt),
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::SvReplay,
                );
                return result;
            }
            SvSeqOutcome::ForwardGap(gap) => {
                if self.sv_max_smp_cnt_gap > 0 && gap > self.sv_max_smp_cnt_gap {
                    result.allowed = false;
                    result.push_alert_with_code(
                        AlertSeverity::Medium,
                        SOURCE_IEC61850_SV,
                        u32::from(frame.smp_cnt),
                        frame.timestamp_us,
                        &mut self.next_alert_id,
                        &mut self.total_alerts,
                        AlertCode::SvRateAnomaly,
                    );
                }
            }
            SvSeqOutcome::SuspiciousSmpGap(_) => {
                // Near-wrap forward gap exceeds the heuristic window —
                // alert at Medium severity. Not denied by default: this
                // is informative; downstream policies may escalate.
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_IEC61850_SV,
                    u32::from(frame.smp_cnt),
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::SvRateAnomaly,
                );
            }
            SvSeqOutcome::FirstSeen | SvSeqOutcome::CycleWrap => {}
        }

        // Sample-rate anomaly relative to declared rate. We compare the
        // frame's `smp_rate` field against the registered publisher
        // expectation. If both are set and differ, alert.
        if bound_publisher_smp_rate != 0
            && frame.smp_rate != 0
            && frame.smp_rate != bound_publisher_smp_rate
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_IEC61850_SV,
                u32::from(frame.smp_cnt),
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::SvRateAnomaly,
            );
        }

        result
    }

    // -----------------------------------------------------------------------
    // Raw-frame parsing (SV)
    // -----------------------------------------------------------------------

    /// Parse an IEC 61850-9-2 Sampled Values frame starting at the Ethernet
    /// frame (including dst+src MAC and EtherType, optionally with one
    /// 802.1Q VLAN tag).
    ///
    /// Validates EtherType `0x88BA`, peels a single VLAN tag if present,
    /// then decodes the minimum SV ASN.1 fields needed for IDS analysis:
    /// `svID`, `smpCnt`, `smpRate`, `datSet`, and `refrTm` (when present).
    /// Returns [`VsError::InvalidInput`] on any malformed input.
    ///
    /// `refrTm` is decoded into [`SvFrame::t_seconds_since_epoch`] and
    /// [`SvFrame::t_fraction_of_second`]; both remain zero when the
    /// publisher omits the field. The 1-byte `timeQuality` tail is
    /// intentionally not surfaced.
    ///
    /// This is a defensive parser; it does NOT attempt to decode the
    /// `seqOfData` payload. Bounds are strictly checked.
    pub fn parse_sv(bytes: &[u8], timestamp_us: u64) -> Result<SvFrame, VsError> {
        // Ethernet header: 6 dst + 6 src + 2 ethertype = 14 bytes minimum.
        if bytes.len() < 14 {
            return Err(VsError::InvalidInput);
        }
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&bytes[6..12]);

        let mut offset = 12usize;
        let mut ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        offset += 2;

        // Single optional 802.1Q VLAN tag.
        if ethertype == ETHERTYPE_VLAN_8021Q {
            if bytes.len() < offset + 4 {
                return Err(VsError::InvalidInput);
            }
            // Skip TCI (2 bytes), then read inner ethertype.
            ethertype = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            offset += 4;
        }

        if ethertype != ETHERTYPE_SV {
            return Err(VsError::InvalidInput);
        }

        // SV header per IEC 61850-9-2:
        //   APPID (2) | Length (2) | Reserved1 (2) | Reserved2 (2) | APDU...
        if bytes.len() < offset + 8 {
            return Err(VsError::InvalidInput);
        }
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        if (length as usize) < 8 || offset + (length as usize) > bytes.len() {
            return Err(VsError::InvalidInput);
        }
        let apdu_start = offset + 8;
        let apdu_end = offset + length as usize;
        let apdu = &bytes[apdu_start..apdu_end];

        // APDU is `savPdu ::= SEQUENCE { noASDU INTEGER, seqASDU SEQUENCE OF ASDU }`.
        // We BER-decode it loosely: find the first ASDU and pull its svID,
        // smpCnt, smpRate, datSet fields by their context tags.
        let frame = decode_sv_apdu(apdu, src_mac, timestamp_us)?;
        Ok(frame)
    }

    // -----------------------------------------------------------------------
    // Counters / accessors
    // -----------------------------------------------------------------------

    /// Total MMS frames inspected since construction / last [`reset`](Self::reset).
    pub fn mms_total_inspected(&self) -> u64 {
        self.mms_total_inspected
    }
    /// Total GOOSE frames inspected since construction / last [`reset`](Self::reset).
    pub fn goose_total_inspected(&self) -> u64 {
        self.goose_total_inspected
    }
    /// Total SV frames inspected since construction / last [`reset`](Self::reset).
    pub fn sv_total_inspected(&self) -> u64 {
        self.sv_total_inspected
    }
    /// Total alerts generated since construction / last [`reset`](Self::reset).
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }
    /// Returns `true` if the monitor was constructed via [`new_strict`](Self::new_strict).
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Reset all dynamic state (counters, replay trackers, reservations,
    /// rate buckets) while preserving configuration (rules, allowlists,
    /// thresholds, retransmission schedule).
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        let block_test = self.block_test_frames;
        let svc_mask = self.mms_service_mask;
        let read_only = self.mms_read_only;
        let retx_schedule = self.retx_schedule;
        let retx_enforce = self.retx_enforce;
        let time_jump = self.time_max_forward_jump_s;
        let sv_gap = self.sv_max_smp_cnt_gap;
        *self = Self::new();
        self.strict_mode = strict;
        self.block_test_frames = block_test;
        self.mms_service_mask = svc_mask;
        self.mms_read_only = read_only;
        self.retx_schedule = retx_schedule;
        self.retx_enforce = retx_enforce;
        self.time_max_forward_jump_s = time_jump;
        self.sv_max_smp_cnt_gap = sv_gap;
    }

    // -----------------------------------------------------------------------
    // Internal: rate / replay
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

    /// Lookup a GOOSE seq-table entry by `(src_mac, go_cb_ref_hash)`.
    /// Returns the index if found and active.
    ///
    /// The tracker is keyed on the GoCBRef hash in addition to the
    /// source MAC so that two control blocks published by the same IED
    /// (a normal IEC 61850-8-1 deployment pattern) get independent
    /// replay state — one CB advancing past the other must not produce
    /// false replay alerts on legitimate traffic, nor downgrade the
    /// baseline.
    fn find_goose_seq(&self, src_mac: [u8; 6], go_cb_ref_hash: u32) -> Option<usize> {
        for (i, entry) in self.goose_seq_table.iter().enumerate() {
            if entry.active && entry.src_mac == src_mac && entry.go_cb_ref_hash == go_cb_ref_hash {
                return Some(i);
            }
        }
        None
    }

    /// Update / consult the GOOSE replay tracker for this `(src_mac,
    /// go_cb_ref_hash)` key.
    ///
    /// Per IEC 61850-8-1: when `stNum` increments (state change), the
    /// publisher SHOULD reset `sqNum` to 0 and begin a fresh
    /// retransmission decay sequence. Within a single state, `sqNum`
    /// monotonically increases. This function therefore treats:
    ///
    /// * `stNum` decreasing → replay (legitimate publishers never
    ///   regress `stNum`; resync is an operator action via [`Self::reset`]).
    /// * `stNum` increasing → forward progress; the new `sqNum` is
    ///   adopted as-is (it MAY be non-zero if the state-change frame
    ///   was lost and we caught a retransmission first).
    /// * `stNum` unchanged, `sqNum` equal or smaller → replay.
    /// * `stNum` unchanged, `sqNum` larger → retransmission.
    ///
    /// A detected replay does NOT update the tracker baseline (security:
    /// prevent attacker-controlled baseline downgrade).
    fn check_goose_seq(
        &mut self,
        src_mac: [u8; 6],
        go_cb_ref_hash: u32,
        st_num: u32,
        seq_num: u32,
        now_us: u64,
    ) -> Option<bool> {
        self.goose_seq_tick = self.goose_seq_tick.wrapping_add(1);
        let now = self.goose_seq_tick;

        for entry in &mut self.goose_seq_table {
            if entry.active && entry.src_mac == src_mac && entry.go_cb_ref_hash == go_cb_ref_hash {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_st_num = st_num;
                    entry.last_sq_num = seq_num;
                    entry.has_seen = true;
                    entry.last_seen_us = now_us;
                    return Some(false);
                }
                if st_num < entry.last_st_num {
                    // SECURITY: do NOT update the baseline on a detected
                    // replay. Overwriting `last_st_num` / `last_sq_num` /
                    // `last_seen_us` with attacker-controlled values would
                    // permanently downgrade the tracker, after which every
                    // attacker frame in `[attacker_st, legit_st)` would
                    // look like forward progress. Resync is an explicit
                    // operator action via `reset()`.
                    return Some(true);
                }
                if st_num > entry.last_st_num {
                    entry.last_st_num = st_num;
                    entry.last_sq_num = seq_num;
                    entry.last_seen_us = now_us;
                    return Some(false);
                }
                if seq_num == entry.last_sq_num {
                    return Some(true);
                }
                if seq_num < entry.last_sq_num {
                    return Some(true);
                }
                entry.last_sq_num = seq_num;
                entry.last_seen_us = now_us;
                return Some(false);
            }
        }

        for entry in &mut self.goose_seq_table {
            if !entry.active {
                *entry = GooseSeqEntry {
                    src_mac,
                    go_cb_ref_hash,
                    last_st_num: st_num,
                    last_sq_num: seq_num,
                    has_seen: true,
                    active: true,
                    last_used: now,
                    last_seen_us: now_us,
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
            go_cb_ref_hash,
            last_st_num: st_num,
            last_sq_num: seq_num,
            has_seen: true,
            active: true,
            last_used: now,
            last_seen_us: now_us,
        };
        None
    }

    fn check_sv_seq(
        &mut self,
        svid: &[u8],
        svid_len: u8,
        smp_cnt: u16,
        now_us: u64,
    ) -> SvSeqOutcome {
        self.sv_seq_tick = self.sv_seq_tick.wrapping_add(1);
        let now = self.sv_seq_tick;

        for entry in &mut self.sv_seq_table {
            if entry.matches(svid, svid_len) {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_smp_cnt = smp_cnt;
                    entry.last_seen_us = now_us;
                    entry.has_seen = true;
                    return SvSeqOutcome::FirstSeen;
                }
                let prev = entry.last_smp_cnt;
                if smp_cnt == prev {
                    return SvSeqOutcome::Replay;
                }
                // smpCnt is a 16-bit counter that wraps every nominal
                // cycle. Treat decreases > half-range as legitimate
                // wrap-around, everything else as replay.
                //
                // Heuristic refinement (security): the apparent
                // forward distance across a wrap is
                // `u16::MAX as u32 + 1 - backward`. If that distance
                // exceeds [`MAX_SMP_GAP_WINDOW`] AND the transition
                // looks like a near-wrap (small `cur`, large `prev`),
                // we suspect a hidden forward gap (e.g. prev=65530,
                // cur=10 → 16-frame gap silently classified as wrap).
                // In that case emit a SvRateAnomaly (semantic of the
                // requested `SuspiciousSmpGap`) rather than treating
                // it as a clean wrap.
                if smp_cnt < prev {
                    let backward = prev - smp_cnt;
                    if backward < u16::MAX / 2 {
                        return SvSeqOutcome::Replay;
                    }
                    let forward_across_wrap: u32 = (u16::MAX as u32 + 1) - backward as u32;
                    entry.last_smp_cnt = smp_cnt;
                    entry.last_seen_us = now_us;
                    if forward_across_wrap > MAX_SMP_GAP_WINDOW as u32 {
                        // Suspicious near-wrap forward gap — surface it
                        // so the rate-anomaly check at the call site
                        // can alert.
                        let capped = forward_across_wrap.min(u16::MAX as u32) as u16;
                        return SvSeqOutcome::SuspiciousSmpGap(capped);
                    }
                    return SvSeqOutcome::CycleWrap;
                }
                let gap = smp_cnt - prev;
                entry.last_smp_cnt = smp_cnt;
                entry.last_seen_us = now_us;
                return SvSeqOutcome::ForwardGap(gap);
            }
        }

        // Insert.
        for entry in &mut self.sv_seq_table {
            if !entry.active {
                let mut svid_buf = [0u8; MAX_SV_SVID_LEN];
                svid_buf[..svid_len as usize].copy_from_slice(svid);
                *entry = SvSeqEntry {
                    svid: svid_buf,
                    svid_len,
                    last_smp_cnt: smp_cnt,
                    last_seen_us: now_us,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                return SvSeqOutcome::FirstSeen;
            }
        }
        // LRU evict.
        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.sv_seq_table.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        let mut svid_buf = [0u8; MAX_SV_SVID_LEN];
        svid_buf[..svid_len as usize].copy_from_slice(svid);
        self.sv_seq_table[victim] = SvSeqEntry {
            svid: svid_buf,
            svid_len,
            last_smp_cnt: smp_cnt,
            last_seen_us: now_us,
            has_seen: true,
            active: true,
            last_used: now,
        };
        SvSeqOutcome::FirstSeen
    }

    // -----------------------------------------------------------------------
    // Internal: control-block reservations
    // -----------------------------------------------------------------------

    fn reserve_cb(
        &mut self,
        cb_ref: &[u8],
        cb_ref_len: u8,
        client_id: MmsClientId,
        is_goose: bool,
    ) -> Result<(), VsError> {
        self.cb_reservation_tick = self.cb_reservation_tick.wrapping_add(1);
        let now = self.cb_reservation_tick;

        // If an active reservation already exists for this CB, overwrite
        // its owner (re-selection is allowed by the same or new client).
        for entry in &mut self.cb_reservations {
            if entry.matches_ref(cb_ref, cb_ref_len, is_goose) {
                entry.owner_client_id = client_id;
                entry.last_used = now;
                // Reset binding — the new owner may bind a different MAC.
                entry.bound = false;
                entry.bound_src_mac = [0u8; 6];
                return Ok(());
            }
        }
        // Find a free slot.
        for entry in &mut self.cb_reservations {
            if !entry.active {
                let mut buf = [0u8; MAX_GOOSE_GOCBREF_LEN];
                buf[..cb_ref_len as usize].copy_from_slice(cb_ref);
                *entry = CbReservation {
                    cb_ref: buf,
                    cb_ref_len,
                    owner_client_id: client_id,
                    bound_src_mac: [0u8; 6],
                    bound: false,
                    is_goose,
                    active: true,
                    last_used: now,
                };
                return Ok(());
            }
        }
        Err(VsError::ResourceExhausted)
    }

    fn release_cb(
        &mut self,
        cb_ref: &[u8],
        cb_ref_len: u8,
        client_id: MmsClientId,
        is_goose: bool,
    ) {
        if cb_ref_len == 0 || cb_ref.is_empty() {
            // Bulk-release every reservation owned by this client (used by
            // Conclude / disconnect).
            for entry in &mut self.cb_reservations {
                if entry.active && entry.owner_client_id == client_id {
                    *entry = CbReservation::empty();
                }
            }
            return;
        }
        for entry in &mut self.cb_reservations {
            if entry.matches_ref(cb_ref, cb_ref_len, is_goose) && entry.owner_client_id == client_id
            {
                *entry = CbReservation::empty();
                return;
            }
        }
    }

    /// Returns `true` if the given control-block / `src_mac` pair would
    /// constitute a hijack (CB is reserved and currently bound to a
    /// different MAC). Binds the MAC on first observation; bumps LRU.
    fn cb_hijack_check(
        &mut self,
        cb_ref: &[u8],
        cb_ref_len: u8,
        is_goose: bool,
        src_mac: [u8; 6],
    ) -> bool {
        if cb_ref_len == 0 {
            return false;
        }
        self.cb_reservation_tick = self.cb_reservation_tick.wrapping_add(1);
        let now = self.cb_reservation_tick;
        for entry in &mut self.cb_reservations {
            if entry.matches_ref(cb_ref, cb_ref_len, is_goose) {
                entry.last_used = now;
                if !entry.bound {
                    entry.bound_src_mac = src_mac;
                    entry.bound = true;
                    return false;
                }
                return entry.bound_src_mac != src_mac;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Internal: time-sync tracker
    // -----------------------------------------------------------------------

    /// Returns `true` if the observed `t` field indicates time-sync
    /// spoofing (monotonic regression, or implausibly large forward jump).
    /// `t_secs == 0 && t_frac == 0` means "no `t` present" and is skipped.
    fn check_time_field(&mut self, src_mac: [u8; 6], t_secs: u32, t_frac: u32) -> bool {
        if t_secs == 0 && t_frac == 0 {
            return false;
        }
        self.time_tracker_tick = self.time_tracker_tick.wrapping_add(1);
        let now = self.time_tracker_tick;

        for entry in &mut self.time_trackers {
            if entry.active && entry.src_mac == src_mac {
                entry.last_used = now;
                if !entry.has_seen {
                    entry.last_t_seconds = t_secs;
                    entry.last_t_fraction = t_frac;
                    entry.has_seen = true;
                    return false;
                }
                // Backwards regression — always spoofing.
                if t_secs < entry.last_t_seconds
                    || (t_secs == entry.last_t_seconds && t_frac < entry.last_t_fraction)
                {
                    // Update so subsequent legit traffic does not keep
                    // flagging.
                    entry.last_t_seconds = t_secs;
                    entry.last_t_fraction = t_frac;
                    return true;
                }
                // Forward jump beyond configured threshold.
                if self.time_max_forward_jump_s > 0 {
                    let delta = t_secs.saturating_sub(entry.last_t_seconds);
                    if delta > self.time_max_forward_jump_s {
                        entry.last_t_seconds = t_secs;
                        entry.last_t_fraction = t_frac;
                        return true;
                    }
                }
                entry.last_t_seconds = t_secs;
                entry.last_t_fraction = t_frac;
                return false;
            }
        }

        for entry in &mut self.time_trackers {
            if !entry.active {
                *entry = TimeTracker {
                    src_mac,
                    last_t_seconds: t_secs,
                    last_t_fraction: t_frac,
                    has_seen: true,
                    active: true,
                    last_used: now,
                };
                return false;
            }
        }
        // LRU evict.
        let mut victim = 0usize;
        let mut oldest_age: u32 = 0;
        for (i, entry) in self.time_trackers.iter().enumerate() {
            let age = now.wrapping_sub(entry.last_used);
            if i == 0 || age > oldest_age {
                oldest_age = age;
                victim = i;
            }
        }
        self.time_trackers[victim] = TimeTracker {
            src_mac,
            last_t_seconds: t_secs,
            last_t_fraction: t_frac,
            has_seen: true,
            active: true,
            last_used: now,
        };
        false
    }
}

impl Default for Iec61850Monitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SV ASN.1 / BER decoding (defensive, bounds-checked)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SvSeqOutcome {
    FirstSeen,
    Replay,
    /// smpCnt advanced — payload is the forward gap (samples).
    ForwardGap(u16),
    /// smpCnt wrapped around the modulo-65536 nominal cycle (clean wrap,
    /// implied forward distance ≤ [`MAX_SMP_GAP_WINDOW`]).
    CycleWrap,
    /// smpCnt transition LOOKS like a wrap (backward > half-range) but
    /// the implied forward distance is suspiciously large (> [`MAX_SMP_GAP_WINDOW`]),
    /// suggesting an attacker is hiding a forward gap behind the wrap
    /// boundary. Payload is the implied forward-gap samples (clamped to
    /// `u16::MAX`).
    SuspiciousSmpGap(u16),
}

/// Decode an SV APDU into an [`SvFrame`], extracting the fields the IDS
/// needs. The full ASN.1 grammar is `savPdu ::= [APPLICATION 0] IMPLICIT
/// SEQUENCE { noASDU [0] IMPLICIT INTEGER, seqASDU [2] IMPLICIT SEQUENCE OF
/// ASDU }`. Each ASDU contains context-tagged fields:
///   `[0] svID`, `[1] datSet`, `[2] smpCnt`, `[3] confRev`, `[4] refrTm`,
///   `[5] smpSynch`, `[6] smpRate`, `[7] sample`, `[8] smpMod`.
///
/// This decoder is deliberately permissive: it accepts both the BER
/// outer `[APPLICATION 0]` wrapper and a raw `seqASDU`, and walks the
/// first ASDU's TLVs to extract the fields it cares about. Anything
/// malformed -> `Err(VsError::InvalidInput)`.
fn decode_sv_apdu(apdu: &[u8], src_mac: [u8; 6], timestamp_us: u64) -> Result<SvFrame, VsError> {
    // Strip a single `[APPLICATION 0]` wrapper (tag 0x60) if present.
    let body = if let Some(first) = apdu.first() {
        if *first == 0x60 {
            let (_tag, content, _rest) = parse_tlv(apdu)?;
            content
        } else {
            apdu
        }
    } else {
        return Err(VsError::InvalidInput);
    };

    // Walk top-level TLVs to find `seqASDU` ([2] IMPLICIT SEQUENCE OF
    // ASDU). The context-2 constructed tag is 0xA2.
    let mut cursor = body;
    let mut seq_asdu: Option<&[u8]> = None;
    while !cursor.is_empty() {
        let (tag, content, rest) = parse_tlv(cursor)?;
        if tag == 0xA2 {
            seq_asdu = Some(content);
            break;
        }
        cursor = rest;
    }
    let seq_asdu = seq_asdu.ok_or(VsError::InvalidInput)?;

    // First ASDU. Each ASDU is a SEQUENCE (tag 0x30) of context-tagged
    // fields. Some merging units emit constructed SEQUENCE; some flatten
    // — accept either by stripping a single leading SEQUENCE tag if
    // present.
    let asdu_content = if let Some(first) = seq_asdu.first() {
        if *first == 0x30 {
            let (_tag, content, _rest) = parse_tlv(seq_asdu)?;
            content
        } else {
            seq_asdu
        }
    } else {
        return Err(VsError::InvalidInput);
    };

    let mut svid = [0u8; MAX_SV_SVID_LEN];
    let mut svid_len = 0u8;
    let mut dataset_ref = [0u8; MAX_SV_DATASET_REF_LEN];
    let mut dataset_ref_len = 0u8;
    let mut smp_cnt: u16 = 0;
    let mut smp_rate: u16 = 0;
    let mut t_seconds_since_epoch: u32 = 0;
    let mut t_fraction_of_second: u32 = 0;
    let mut found_smp_cnt = false;

    let mut walk = asdu_content;
    while !walk.is_empty() {
        let (tag, content, rest) = parse_tlv(walk)?;
        match tag {
            0x80 => {
                // [0] IMPLICIT VisibleString svID
                if content.len() > MAX_SV_SVID_LEN {
                    return Err(VsError::InvalidInput);
                }
                svid[..content.len()].copy_from_slice(content);
                svid_len = content.len() as u8;
            }
            0x81 => {
                // [1] IMPLICIT VisibleString datSet
                if content.len() > MAX_SV_DATASET_REF_LEN {
                    return Err(VsError::InvalidInput);
                }
                dataset_ref[..content.len()].copy_from_slice(content);
                dataset_ref_len = content.len() as u8;
            }
            0x82 => {
                // [2] IMPLICIT INTEGER smpCnt — IEC 61850-9-2 specifies
                // OCTET STRING SIZE(2) on the wire (always 2 bytes BE).
                if content.len() != 2 {
                    return Err(VsError::InvalidInput);
                }
                smp_cnt = u16::from_be_bytes([content[0], content[1]]);
                found_smp_cnt = true;
            }
            0x84 => {
                // [4] IMPLICIT UtcTime refrTm — IEC 61850 encodes UtcTime
                // as OCTET STRING SIZE(8): 4 bytes secondsSinceEpoch
                // (big-endian u32) | 3 bytes fractionOfSecond
                // (big-endian, MSB-justified) | 1 byte timeQuality.
                // Some merging units omit the field entirely; we accept
                // both 8-byte (canonical) and shorter encodings by
                // simply zero-filling missing low-order bytes.
                if content.len() >= 4 {
                    t_seconds_since_epoch =
                        u32::from_be_bytes([content[0], content[1], content[2], content[3]]);
                }
                if content.len() >= 7 {
                    // Pack 3 fraction bytes into the high 24 bits of u32.
                    t_fraction_of_second =
                        (content[4] as u32) << 16 | (content[5] as u32) << 8 | (content[6] as u32);
                }
                // content[7] (timeQuality) intentionally ignored — it
                // does not feed the time-sync spoofing check.
            }
            0x86 => {
                // [6] IMPLICIT INTEGER smpRate
                smp_rate = decode_unsigned_int(content)?;
            }
            _ => {
                // Skip unknown / uninteresting fields.
            }
        }
        walk = rest;
    }

    if !found_smp_cnt {
        return Err(VsError::InvalidInput);
    }

    Ok(SvFrame {
        src_mac,
        svid_len,
        svid,
        smp_cnt,
        smp_rate,
        dataset_ref_len,
        dataset_ref,
        timestamp_us,
        t_seconds_since_epoch,
        t_fraction_of_second,
    })
}

/// Parse a single ASN.1 / BER TLV. Returns `(tag, content, remainder)`.
///
/// Supports short-form lengths and definite long-form (1–4 length bytes).
/// Indefinite lengths and high-tag-number form are rejected — they do not
/// appear in valid IEC 61850-9-2 frames and admitting them would expand
/// the parser surface for fuzz attacks.
fn parse_tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), VsError> {
    if bytes.is_empty() {
        return Err(VsError::InvalidInput);
    }
    let tag = bytes[0];
    if tag & 0x1F == 0x1F {
        // High-tag-number form — rejected.
        return Err(VsError::InvalidInput);
    }
    if bytes.len() < 2 {
        return Err(VsError::InvalidInput);
    }
    let first_len = bytes[1];
    let (length, len_octets) = if first_len < 0x80 {
        (first_len as usize, 1usize)
    } else {
        let n = (first_len & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(VsError::InvalidInput);
        }
        if bytes.len() < 2 + n {
            return Err(VsError::InvalidInput);
        }
        let mut acc: u32 = 0;
        for i in 0..n {
            acc = (acc << 8) | (bytes[2 + i] as u32);
        }
        if acc > u16::MAX as u32 {
            return Err(VsError::InvalidInput);
        }
        (acc as usize, 1 + n)
    };
    let content_start = 1 + len_octets;
    let content_end = content_start
        .checked_add(length)
        .ok_or(VsError::InvalidInput)?;
    if content_end > bytes.len() {
        return Err(VsError::InvalidInput);
    }
    Ok((
        tag,
        &bytes[content_start..content_end],
        &bytes[content_end..],
    ))
}

/// Decode an unsigned BER INTEGER (1–4 byte content) into a `u16`.
fn decode_unsigned_int(content: &[u8]) -> Result<u16, VsError> {
    if content.is_empty() || content.len() > 4 {
        return Err(VsError::InvalidInput);
    }
    let mut acc: u32 = 0;
    for b in content {
        acc = (acc << 8) | (*b as u32);
    }
    if acc > u16::MAX as u32 {
        return Err(VsError::InvalidInput);
    }
    Ok(acc as u16)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(b: u8) -> [u8; 6] {
        [0xAA, 0xBB, 0xCC, 0x00, 0x00, b]
    }

    #[test]
    fn mms_service_type_from_u8() {
        assert_eq!(MmsServiceType::from_u8(1), MmsServiceType::Read);
        assert_eq!(MmsServiceType::from_u8(2), MmsServiceType::Write);
        assert_eq!(MmsServiceType::from_u8(8), MmsServiceType::SetDataValues);
        assert_eq!(MmsServiceType::from_u8(11), MmsServiceType::SelectControl);
        assert_eq!(MmsServiceType::from_u8(12), MmsServiceType::CancelControl);
        assert_eq!(MmsServiceType::from_u8(0xAB), MmsServiceType::Unknown);
    }

    #[test]
    fn mms_service_is_write() {
        assert!(!MmsServiceType::Read.is_write());
        assert!(MmsServiceType::Write.is_write());
        assert!(MmsServiceType::SetDataValues.is_write());
        assert!(MmsServiceType::DefineNamedVariable.is_write());
        assert!(!MmsServiceType::GetNameList.is_write());
        assert!(!MmsServiceType::SelectControl.is_write());
    }

    #[test]
    fn mms_service_mask_blocks_disallowed() {
        let mut mon = Iec61850Monitor::new();
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
        mon.add_mms_rule(0xFFFF, true, 0).unwrap();
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
        let mac = mac(1);
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
        let m = mac(1);
        mon.add_goose_publisher(m, b"").unwrap();
        let frame = GooseFrame {
            src_mac: m,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_replay_exact_duplicate() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let frame = GooseFrame {
            src_mac: m,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        };
        assert!(mon.inspect_goose(&frame).allowed);
        assert!(!mon.inspect_goose(&frame).allowed);
    }

    #[test]
    fn goose_replay_st_num_backwards() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let _ = mon.inspect_goose(&GooseFrame {
            src_mac: m,
            st_num: 5,
            sq_num: 0,
            ..Default::default()
        });
        let f2 = GooseFrame {
            src_mac: m,
            st_num: 3,
            sq_num: 0,
            ..Default::default()
        };
        assert!(!mon.inspect_goose(&f2).allowed);
    }

    #[test]
    fn goose_forward_progress_ok() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let _ = mon.inspect_goose(&GooseFrame {
            src_mac: m,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        });
        assert!(
            mon.inspect_goose(&GooseFrame {
                src_mac: m,
                st_num: 2,
                sq_num: 0,
                ..Default::default()
            })
            .allowed
        );
    }

    #[test]
    fn goose_retransmission_sq_increase() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let _ = mon.inspect_goose(&GooseFrame {
            src_mac: m,
            st_num: 1,
            sq_num: 0,
            ..Default::default()
        });
        assert!(
            mon.inspect_goose(&GooseFrame {
                src_mac: m,
                st_num: 1,
                sq_num: 1,
                ..Default::default()
            })
            .allowed
        );
    }

    /// Regression test (security): a detected GOOSE replay must NOT update
    /// the tracker baseline. Previously, when `st_num < entry.last_st_num`,
    /// the function first overwrote `last_st_num` / `last_sq_num` with the
    /// attacker's value and only then returned `Some(true)`. That meant a
    /// single spoofed low-numbered frame permanently downgraded the baseline,
    /// after which every legitimate publisher frame looked like forward
    /// progress and every attacker frame in `[attacker_st, legit_st)` was
    /// accepted as valid. Resync is now an operator action via `reset()`.
    #[test]
    fn goose_replay_does_not_auto_resync_st_num() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let mk = |st_num, sq_num| GooseFrame {
            src_mac: mac,
            st_num,
            sq_num,
            ..Default::default()
        };

        // Legitimate publisher reaches st_num=100.
        assert!(mon.inspect_goose(&mk(100, 0)).allowed);

        // Attacker spoofs a low frame (st_num=5). Must be flagged as replay.
        assert!(!mon.inspect_goose(&mk(5, 0)).allowed);

        // Critical: subsequent attacker frames between 5 and 100 must STILL
        // be flagged as replay. Before the fix, the baseline was downgraded
        // to 5, so 50 would have looked like forward progress.
        assert!(!mon.inspect_goose(&mk(50, 0)).allowed);
        assert!(!mon.inspect_goose(&mk(99, 0)).allowed);

        // Legitimate publisher's next frame (st_num=101) is forward progress
        // from the preserved baseline of 100 — accepted.
        assert!(mon.inspect_goose(&mk(101, 0)).allowed);

        // And a replay of 100 is still caught (because baseline is now 101).
        assert!(!mon.inspect_goose(&mk(100, 0)).allowed);
    }

    /// Regression test (security): a backwards-sqNum spoof within the same
    /// state must NOT update `last_sq_num` either. The same auto-resync
    /// pattern applied to the sqNum branch.
    #[test]
    fn goose_replay_does_not_auto_resync_sq_num() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
        let mk = |st_num, sq_num| GooseFrame {
            src_mac: mac,
            st_num,
            sq_num,
            ..Default::default()
        };

        // Legitimate retransmission stream: st=1, sq=0,1,2,...10.
        assert!(mon.inspect_goose(&mk(1, 0)).allowed);
        assert!(mon.inspect_goose(&mk(1, 10)).allowed);

        // Attacker injects backwards sq_num=2 → flagged as replay.
        assert!(!mon.inspect_goose(&mk(1, 2)).allowed);

        // Critical: subsequent attacker frames sq=3..9 must STILL be flagged
        // (baseline must remain at 10, not have been downgraded to 2).
        assert!(!mon.inspect_goose(&mk(1, 3)).allowed);
        assert!(!mon.inspect_goose(&mk(1, 9)).allowed);

        // Legitimate sq=11 still accepted as forward progress.
        assert!(mon.inspect_goose(&mk(1, 11)).allowed);
    }

    /// Regression test (security): the GOOSE replay tracker must be keyed on
    /// `(src_mac, go_cb_ref)`, not on `src_mac` alone. Previously, two GoCBs
    /// publishing from the same source MAC (a normal IEC 61850-8-1 deployment
    /// pattern) shared a single tracker — so one GoCB's stNum advancing past
    /// another GoCB's counter caused either false replay alerts on legitimate
    /// traffic OR (worse) baseline downgrade letting a replay slip through.
    #[test]
    fn goose_replay_tracker_keyed_on_gocb_ref() {
        let mut mon = Iec61850Monitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];

        // Build a frame on GoCB "GoCB_A" with st_num=10.
        let mut gocb_a = GooseFrame {
            src_mac: mac,
            st_num: 10,
            sq_num: 0,
            ..Default::default()
        };
        let ref_a = b"IEDA/LLN0$GO$GoCB_A";
        gocb_a.go_cb_ref[..ref_a.len()].copy_from_slice(ref_a);
        gocb_a.go_cb_ref_len = ref_a.len() as u8;
        assert!(mon.inspect_goose(&gocb_a).allowed);

        // A different GoCB ("GoCB_B") on the same MAC with st_num=3 must NOT
        // be flagged as replay — its tracker is independent of GoCB_A.
        let mut gocb_b = GooseFrame {
            src_mac: mac,
            st_num: 3,
            sq_num: 0,
            ..Default::default()
        };
        let ref_b = b"IEDA/LLN0$GO$GoCB_B";
        gocb_b.go_cb_ref[..ref_b.len()].copy_from_slice(ref_b);
        gocb_b.go_cb_ref_len = ref_b.len() as u8;
        assert!(
            mon.inspect_goose(&gocb_b).allowed,
            "GoCB_B's first frame must not be flagged as replay just because \
             GoCB_A on the same MAC has a higher stNum"
        );

        // GoCB_A continues with st_num=11 — must still be accepted as forward
        // progress (its own tracker was not overwritten by GoCB_B).
        gocb_a.st_num = 11;
        assert!(
            mon.inspect_goose(&gocb_a).allowed,
            "GoCB_A's tracker must not be trampled by GoCB_B"
        );

        // Real replay on GoCB_A (re-send st_num=11) must still fire.
        assert!(!mon.inspect_goose(&gocb_a).allowed);

        // Real replay on GoCB_B (re-send st_num=3 after advancing) must also
        // fire independently.
        gocb_b.st_num = 5;
        assert!(mon.inspect_goose(&gocb_b).allowed);
        gocb_b.st_num = 4; // backwards
        assert!(!mon.inspect_goose(&gocb_b).allowed);
    }

    #[test]
    fn monitor_reset_clears_counters() {
        let mut mon = Iec61850Monitor::new();
        let _ = mon.inspect_mms(&MmsFrame::default());
        let _ = mon.inspect_goose(&GooseFrame::default());
        let _ = mon.inspect_sv(&SvFrame::default());
        assert_eq!(mon.mms_total_inspected(), 1);
        assert_eq!(mon.goose_total_inspected(), 1);
        assert_eq!(mon.sv_total_inspected(), 1);
        mon.reset();
        assert_eq!(mon.mms_total_inspected(), 0);
        assert_eq!(mon.goose_total_inspected(), 0);
        assert_eq!(mon.sv_total_inspected(), 0);
    }

    #[test]
    fn add_goose_publisher_resource_exhaustion() {
        let mut mon = Iec61850Monitor::new();
        for i in 0..MAX_GOOSE_PUBLISHERS {
            let m = [0, 0, 0, 0, 0, i as u8];
            mon.add_goose_publisher(m, b"").unwrap();
        }
        assert_eq!(
            mon.add_goose_publisher([0xFF; 6], b""),
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

    // -----------------------------------------------------------------------
    // SV — Sampled Values
    // -----------------------------------------------------------------------

    fn sv_frame_with(mac: [u8; 6], svid: &[u8], smp_cnt: u16, ts: u64) -> SvFrame {
        let mut s = SvFrame::default();
        s.src_mac = mac;
        s.svid[..svid.len()].copy_from_slice(svid);
        s.svid_len = svid.len() as u8;
        s.smp_cnt = smp_cnt;
        s.timestamp_us = ts;
        s
    }

    #[test]
    fn sv_clean_first_sighting_allowed() {
        let mut mon = Iec61850Monitor::new();
        let f = sv_frame_with(mac(1), b"MU1", 0, 1_000);
        assert!(mon.inspect_sv(&f).allowed);
        assert_eq!(mon.sv_total_inspected(), 1);
    }

    #[test]
    fn sv_smp_cnt_replay_duplicate_alerts() {
        let mut mon = Iec61850Monitor::new();
        let f = sv_frame_with(mac(1), b"MU1", 100, 1_000);
        assert!(mon.inspect_sv(&f).allowed);
        let r2 = mon.inspect_sv(&f);
        assert!(!r2.allowed);
        assert_eq!(r2.alert_codes[0], AlertCode::SvReplay);
    }

    #[test]
    fn sv_smp_cnt_backwards_step_alerts() {
        let mut mon = Iec61850Monitor::new();
        let f1 = sv_frame_with(mac(1), b"MU1", 500, 1_000);
        let f2 = sv_frame_with(mac(1), b"MU1", 100, 2_000);
        let _ = mon.inspect_sv(&f1);
        let r = mon.inspect_sv(&f2);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::SvReplay);
    }

    #[test]
    fn sv_smp_cnt_wrap_around_is_clean() {
        let mut mon = Iec61850Monitor::new();
        let f1 = sv_frame_with(mac(1), b"MU1", u16::MAX - 1, 1_000);
        let f2 = sv_frame_with(mac(1), b"MU1", 5, 2_000);
        let _ = mon.inspect_sv(&f1);
        // smpCnt wraps modulo 65536 — backwards from 65534 to 5 is a wrap.
        let r = mon.inspect_sv(&f2);
        assert!(r.allowed, "wrap-around must be accepted");
    }

    #[test]
    fn sv_rate_anomaly_excess_gap() {
        let mut mon = Iec61850Monitor::new();
        mon.set_sv_max_smp_cnt_gap(10);
        let f1 = sv_frame_with(mac(1), b"MU1", 0, 0);
        let f2 = sv_frame_with(mac(1), b"MU1", 5000, 1_000);
        let _ = mon.inspect_sv(&f1);
        let r = mon.inspect_sv(&f2);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::SvRateAnomaly);
    }

    #[test]
    fn sv_ied_mismatch_blocked() {
        let mut mon = Iec61850Monitor::new();
        mon.add_sv_publisher(mac(1), b"MU1", 0).unwrap();
        // Same svID but a different src_mac → spoof.
        let f = sv_frame_with(mac(2), b"MU1", 0, 1_000);
        let r = mon.inspect_sv(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::IedMismatch);
    }

    #[test]
    fn sv_ied_match_allowed() {
        let mut mon = Iec61850Monitor::new();
        mon.add_sv_publisher(mac(1), b"MU1", 80).unwrap();
        let f = sv_frame_with(mac(1), b"MU1", 0, 1_000);
        assert!(mon.inspect_sv(&f).allowed);
    }

    #[test]
    fn sv_strict_blocks_unregistered_svid() {
        let mut mon = Iec61850Monitor::new_strict();
        mon.add_sv_publisher(mac(1), b"MU1", 0).unwrap();
        let f = sv_frame_with(mac(1), b"OTHER", 0, 1_000);
        assert!(!mon.inspect_sv(&f).allowed);
    }

    #[test]
    fn sv_smp_rate_mismatch_alerts() {
        let mut mon = Iec61850Monitor::new();
        mon.add_sv_publisher(mac(1), b"MU1", 80).unwrap();
        let mut f = sv_frame_with(mac(1), b"MU1", 0, 1_000);
        f.smp_rate = 256;
        let r = mon.inspect_sv(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::SvRateAnomaly);
    }

    // -----------------------------------------------------------------------
    // Control-block reservation / hijack
    // -----------------------------------------------------------------------

    fn select_cb_frame(cb_ref: &[u8], client_id: u32, is_goose: bool) -> MmsFrame {
        let mut domain = [0u8; MAX_MMS_DOMAIN_LEN];
        domain[..cb_ref.len()].copy_from_slice(cb_ref);
        MmsFrame {
            service_type: MmsServiceType::SelectControl,
            raw_service_type: 11,
            domain,
            domain_len: cb_ref.len() as u8,
            invoke_id: client_id,
            client_id,
            timestamp_us: 0,
            control_block_is_goose: is_goose,
        }
    }

    fn cancel_cb_frame(cb_ref: &[u8], client_id: u32, is_goose: bool) -> MmsFrame {
        let mut domain = [0u8; MAX_MMS_DOMAIN_LEN];
        domain[..cb_ref.len()].copy_from_slice(cb_ref);
        MmsFrame {
            service_type: MmsServiceType::CancelControl,
            raw_service_type: 12,
            domain,
            domain_len: cb_ref.len() as u8,
            invoke_id: client_id,
            client_id,
            timestamp_us: 0,
            control_block_is_goose: is_goose,
        }
    }

    fn goose_with_ref(src_mac: [u8; 6], cb_ref: &[u8]) -> GooseFrame {
        let mut g = GooseFrame::default();
        g.src_mac = src_mac;
        g.go_cb_ref[..cb_ref.len()].copy_from_slice(cb_ref);
        g.go_cb_ref_len = cb_ref.len() as u8;
        g.st_num = 1;
        g.sq_num = 0;
        g
    }

    #[test]
    fn cb_hijack_alerts_when_different_mac_publishes_reserved_block() {
        let mut mon = Iec61850Monitor::new();
        let cb = b"IED1/LLN0$GO$GoCB01";
        // Client A reserves the GoCB.
        let _ = mon.inspect_mms(&select_cb_frame(cb, 7, true));
        // Publisher MAC mac(1) successfully publishes — binds the CB.
        let g_owner = goose_with_ref(mac(1), cb);
        assert!(mon.inspect_goose(&g_owner).allowed);
        // Now a different publisher MAC tries the same GoCB → hijack.
        let g_attacker = goose_with_ref(mac(2), cb);
        let r = mon.inspect_goose(&g_attacker);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::CbHijack);
    }

    #[test]
    fn cb_hijack_clears_after_cancel_control() {
        let mut mon = Iec61850Monitor::new();
        let cb = b"IED1/LLN0$GO$GoCB01";
        let _ = mon.inspect_mms(&select_cb_frame(cb, 7, true));
        let g_owner = goose_with_ref(mac(1), cb);
        let _ = mon.inspect_goose(&g_owner);
        // Cancel the reservation, then a different publisher arrives →
        // no reservation, so no hijack alert.
        let _ = mon.inspect_mms(&cancel_cb_frame(cb, 7, true));
        let g_other = goose_with_ref(mac(2), cb);
        let r = mon.inspect_goose(&g_other);
        assert!(r.allowed, "no reservation → no hijack");
    }

    #[test]
    fn cb_hijack_unreserved_block_is_unaffected() {
        let mut mon = Iec61850Monitor::new();
        let cb = b"IED1/LLN0$GO$GoCB01";
        // No reservation at all — any MAC can publish.
        let g1 = goose_with_ref(mac(1), cb);
        let g2 = goose_with_ref(mac(2), cb);
        assert!(mon.inspect_goose(&g1).allowed);
        // g2 has the same go_cb_ref but different mac — allowed because
        // there is no reservation to protect it.
        let r = mon.inspect_goose(&g2);
        // Replay tracker is per src_mac, so g2 is a fresh sighting.
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Retransmission interval enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn retx_interval_within_tolerance_is_clean() {
        let mut mon = Iec61850Monitor::new();
        mon.set_retx_schedule(RetxSchedule::default_8_1(), true);
        let m = mac(1);
        // First frame establishes state.
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 5;
        f1.sq_num = 0;
        f1.timestamp_us = 1_000_000;
        assert!(mon.inspect_goose(&f1).allowed);
        // Expected T1 = T0 * 2 = 8 ms. Provide a 7 ms gap (well within
        // ±25 %).
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 5;
        f2.sq_num = 1;
        f2.timestamp_us = 1_007_000;
        let r = mon.inspect_goose(&f2);
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn retx_interval_out_of_tolerance_alerts() {
        let mut mon = Iec61850Monitor::new();
        mon.set_retx_schedule(RetxSchedule::default_8_1(), true);
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 5;
        f1.sq_num = 0;
        f1.timestamp_us = 1_000_000;
        assert!(mon.inspect_goose(&f1).allowed);
        // Expected T1 = 8 ms. Send at 500 ms — far outside ±25 %.
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 5;
        f2.sq_num = 1;
        f2.timestamp_us = 1_500_000;
        let r = mon.inspect_goose(&f2);
        // Retx anomaly is informative (alerts but allows).
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alert_codes[0], AlertCode::RetransmissionAnomaly);
    }

    #[test]
    fn retx_schedule_expected_intervals_double() {
        let s = RetxSchedule::default_8_1();
        assert_eq!(s.expected_interval_us(0), 4_000);
        assert_eq!(s.expected_interval_us(1), 8_000);
        assert_eq!(s.expected_interval_us(2), 16_000);
        // Doubling saturates at t_max_us.
        assert_eq!(s.expected_interval_us(20), 1_000_000);
    }

    #[test]
    fn retx_schedule_disabled_does_not_alert() {
        let mut mon = Iec61850Monitor::new();
        // enforce = false → no retx alert even for wild deltas.
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 5;
        f1.sq_num = 0;
        f1.timestamp_us = 0;
        let _ = mon.inspect_goose(&f1);
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 5;
        f2.sq_num = 1;
        f2.timestamp_us = 10_000_000_000;
        let r = mon.inspect_goose(&f2);
        assert_eq!(r.alert_count, 0);
    }

    // -----------------------------------------------------------------------
    // Time-sync spoofing
    // -----------------------------------------------------------------------

    #[test]
    fn time_sync_monotonic_regression_alerts() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 1;
        f1.t_seconds_since_epoch = 1_700_000_000;
        let _ = mon.inspect_goose(&f1);
        // Second frame regresses by 10 seconds.
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 2;
        f2.t_seconds_since_epoch = 1_699_999_990;
        let r = mon.inspect_goose(&f2);
        assert!(!r.allowed);
        // First alert slot may be the time-sync; assert presence.
        let mut found = false;
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            if *code == AlertCode::TimeSyncSpoofing {
                found = true;
            }
        }
        assert!(found, "expected TimeSyncSpoofing alert");
    }

    #[test]
    fn time_sync_fraction_backwards_alerts() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 1;
        f1.t_seconds_since_epoch = 1_700_000_000;
        f1.t_fraction_of_second = 0x80_0000;
        let _ = mon.inspect_goose(&f1);
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 2;
        f2.t_seconds_since_epoch = 1_700_000_000;
        f2.t_fraction_of_second = 0x10_0000;
        let r = mon.inspect_goose(&f2);
        let mut found = false;
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            if *code == AlertCode::TimeSyncSpoofing {
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn time_sync_large_forward_jump_alerts() {
        let mut mon = Iec61850Monitor::new();
        mon.set_time_max_forward_jump_s(60);
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 1;
        f1.t_seconds_since_epoch = 1_700_000_000;
        let _ = mon.inspect_goose(&f1);
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 2;
        f2.t_seconds_since_epoch = 1_700_000_000 + 3600; // 1 hour jump
        let r = mon.inspect_goose(&f2);
        let mut found = false;
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            if *code == AlertCode::TimeSyncSpoofing {
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn time_sync_small_forward_step_is_clean() {
        let mut mon = Iec61850Monitor::new();
        mon.set_time_max_forward_jump_s(60);
        let m = mac(1);
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 1;
        f1.t_seconds_since_epoch = 1_700_000_000;
        let _ = mon.inspect_goose(&f1);
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 2;
        f2.t_seconds_since_epoch = 1_700_000_010;
        let r = mon.inspect_goose(&f2);
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            assert_ne!(*code, AlertCode::TimeSyncSpoofing);
        }
    }

    #[test]
    fn time_sync_applies_to_sv_too() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        let mut s1 = sv_frame_with(m, b"MU1", 0, 0);
        s1.t_seconds_since_epoch = 1_700_000_000;
        let _ = mon.inspect_sv(&s1);
        let mut s2 = sv_frame_with(m, b"MU1", 1, 1_000);
        s2.t_seconds_since_epoch = 1_699_999_990;
        let r = mon.inspect_sv(&s2);
        let mut found = false;
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            if *code == AlertCode::TimeSyncSpoofing {
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn time_sync_absent_t_field_is_skipped() {
        let mut mon = Iec61850Monitor::new();
        let m = mac(1);
        // Both frames have t_seconds=0 (no `t` field) → never alerts.
        let mut f1 = GooseFrame::default();
        f1.src_mac = m;
        f1.st_num = 1;
        let _ = mon.inspect_goose(&f1);
        let mut f2 = GooseFrame::default();
        f2.src_mac = m;
        f2.st_num = 2;
        let r = mon.inspect_goose(&f2);
        for code in r.alert_codes.iter().take(r.alert_count as usize) {
            assert_ne!(*code, AlertCode::TimeSyncSpoofing);
        }
    }

    // -----------------------------------------------------------------------
    // SV raw parsing
    // -----------------------------------------------------------------------

    fn build_sv_frame_bytes(svid: &[u8], smp_cnt: u16) -> heapless_vec_like::Buffer {
        // Hand-roll a minimal SV Ethernet frame:
        //   dst_mac(6) | src_mac(6) | 0x88BA | APPID(2) | Length(2)
        //   | Reserved1(2) | Reserved2(2) | APDU
        let mut buf = heapless_vec_like::Buffer::new();
        // dst+src MAC (12 bytes)
        for _ in 0..6 {
            buf.push(0x01);
        }
        // src_mac
        buf.push(0xAA);
        buf.push(0xBB);
        buf.push(0xCC);
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x01);
        // EtherType 0x88BA
        buf.push(0x88);
        buf.push(0xBA);

        // Build APDU = [APPLICATION 0] IMPLICIT seqASDU = [2] IMPLICIT
        //   { SEQUENCE { [0] svID, [2] smpCnt(2) } }
        let mut asdu_body = heapless_vec_like::Buffer::new();
        // [0] svID
        asdu_body.push(0x80);
        asdu_body.push(svid.len() as u8);
        for b in svid {
            asdu_body.push(*b);
        }
        // [2] smpCnt
        asdu_body.push(0x82);
        asdu_body.push(0x02);
        asdu_body.push((smp_cnt >> 8) as u8);
        asdu_body.push((smp_cnt & 0xFF) as u8);

        // Wrap asdu_body in SEQUENCE 0x30.
        let mut asdu_wrapped = heapless_vec_like::Buffer::new();
        asdu_wrapped.push(0x30);
        asdu_wrapped.push(asdu_body.len() as u8);
        for b in asdu_body.as_slice() {
            asdu_wrapped.push(*b);
        }

        // Wrap in [2] IMPLICIT (seqASDU) -> 0xA2.
        let mut seq_asdu = heapless_vec_like::Buffer::new();
        seq_asdu.push(0xA2);
        seq_asdu.push(asdu_wrapped.len() as u8);
        for b in asdu_wrapped.as_slice() {
            seq_asdu.push(*b);
        }

        // APDU = [APPLICATION 0] (tag 0x60) — wrap seq_asdu.
        let mut apdu = heapless_vec_like::Buffer::new();
        apdu.push(0x60);
        apdu.push(seq_asdu.len() as u8);
        for b in seq_asdu.as_slice() {
            apdu.push(*b);
        }

        // SV header: APPID(2) | Length(2) | Reserved1(2) | Reserved2(2)
        let total_len = 8 + apdu.len() as u16;
        // APPID
        buf.push(0x00);
        buf.push(0x01);
        // Length (incl. header)
        buf.push((total_len >> 8) as u8);
        buf.push((total_len & 0xFF) as u8);
        // Reserved1 + Reserved2
        for _ in 0..4 {
            buf.push(0x00);
        }
        // APDU
        for b in apdu.as_slice() {
            buf.push(*b);
        }
        buf
    }

    #[test]
    fn parse_sv_basic() {
        let buf = build_sv_frame_bytes(b"MU1", 1234);
        let frame = Iec61850Monitor::parse_sv(buf.as_slice(), 42).expect("parse");
        assert_eq!(&frame.svid[..frame.valid_svid_len()], b"MU1");
        assert_eq!(frame.smp_cnt, 1234);
        assert_eq!(frame.src_mac, [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);
        assert_eq!(frame.timestamp_us, 42);
    }

    #[test]
    fn parse_sv_too_short_rejected() {
        let bytes = [0u8; 10];
        // `SvFrame` does not derive `PartialEq`, so we cannot
        // `assert_eq!` a `Result<SvFrame, _>` directly. Use `matches!`.
        assert!(matches!(
            Iec61850Monitor::parse_sv(&bytes, 0),
            Err(VsError::InvalidInput)
        ));
    }

    #[test]
    fn parse_sv_wrong_ethertype_rejected() {
        let mut bytes = [0u8; 30];
        // Wrong EtherType 0x0800 (IPv4)
        bytes[12] = 0x08;
        bytes[13] = 0x00;
        assert!(matches!(
            Iec61850Monitor::parse_sv(&bytes, 0),
            Err(VsError::InvalidInput)
        ));
    }

    #[test]
    fn parse_sv_with_vlan_tag() {
        // Build the regular frame, then splice a VLAN tag in front of the
        // EtherType.
        let base = build_sv_frame_bytes(b"MU2", 7);
        let mut tagged = heapless_vec_like::Buffer::new();
        // dst+src mac
        for b in &base.as_slice()[..12] {
            tagged.push(*b);
        }
        // 802.1Q EtherType
        tagged.push(0x81);
        tagged.push(0x00);
        // TCI (priority/VLAN ID) — arbitrary
        tagged.push(0x00);
        tagged.push(0x64);
        // Inner EtherType + rest of frame
        for b in &base.as_slice()[12..] {
            tagged.push(*b);
        }
        let frame = Iec61850Monitor::parse_sv(tagged.as_slice(), 0).expect("vlan parse");
        assert_eq!(frame.smp_cnt, 7);
        assert_eq!(&frame.svid[..frame.valid_svid_len()], b"MU2");
    }

    #[test]
    fn parse_sv_truncated_apdu_rejected() {
        let mut buf = build_sv_frame_bytes(b"MU1", 1);
        // Truncate the buffer mid-APDU.
        buf.truncate(buf.len() - 3);
        assert!(matches!(
            Iec61850Monitor::parse_sv(buf.as_slice(), 0),
            Err(VsError::InvalidInput)
        ));
    }

    #[test]
    fn parse_sv_missing_smp_cnt_rejected() {
        // Hand-build an APDU with svID but no smpCnt → must reject.
        let mut buf = heapless_vec_like::Buffer::new();
        for _ in 0..6 {
            buf.push(0x01);
        }
        for _ in 0..6 {
            buf.push(0x02);
        }
        buf.push(0x88);
        buf.push(0xBA);

        // ASDU body: [0] svID only.
        let svid = b"MU1";
        let mut asdu_body = heapless_vec_like::Buffer::new();
        asdu_body.push(0x80);
        asdu_body.push(svid.len() as u8);
        for b in svid {
            asdu_body.push(*b);
        }
        let mut asdu_wrapped = heapless_vec_like::Buffer::new();
        asdu_wrapped.push(0x30);
        asdu_wrapped.push(asdu_body.len() as u8);
        for b in asdu_body.as_slice() {
            asdu_wrapped.push(*b);
        }
        let mut seq_asdu = heapless_vec_like::Buffer::new();
        seq_asdu.push(0xA2);
        seq_asdu.push(asdu_wrapped.len() as u8);
        for b in asdu_wrapped.as_slice() {
            seq_asdu.push(*b);
        }
        let mut apdu = heapless_vec_like::Buffer::new();
        apdu.push(0x60);
        apdu.push(seq_asdu.len() as u8);
        for b in seq_asdu.as_slice() {
            apdu.push(*b);
        }
        let total_len = 8 + apdu.len() as u16;
        buf.push(0x00);
        buf.push(0x01);
        buf.push((total_len >> 8) as u8);
        buf.push((total_len & 0xFF) as u8);
        for _ in 0..4 {
            buf.push(0x00);
        }
        for b in apdu.as_slice() {
            buf.push(*b);
        }
        assert!(matches!(
            Iec61850Monitor::parse_sv(buf.as_slice(), 0),
            Err(VsError::InvalidInput)
        ));
    }

    // Small fixed-capacity helper for tests so we avoid std::Vec.
    mod heapless_vec_like {
        pub struct Buffer {
            data: [u8; 512],
            len: usize,
        }
        impl Buffer {
            pub fn new() -> Self {
                Self {
                    data: [0u8; 512],
                    len: 0,
                }
            }
            pub fn push(&mut self, b: u8) {
                assert!(self.len < self.data.len());
                self.data[self.len] = b;
                self.len += 1;
            }
            pub fn truncate(&mut self, new_len: usize) {
                if new_len < self.len {
                    self.len = new_len;
                }
            }
            pub fn len(&self) -> usize {
                self.len
            }
            pub fn as_slice(&self) -> &[u8] {
                &self.data[..self.len]
            }
        }
        impl Default for Buffer {
            fn default() -> Self {
                Self::new()
            }
        }
    }
}
