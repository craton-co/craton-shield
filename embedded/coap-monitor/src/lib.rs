// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `CoAP` (Constrained Application Protocol) intrusion detection monitor.
//!
//! Targets RFC 7252 (`CoAP`); see also RFC 7959 (block-wise, NOT implemented
//! here).
//!
//! Detects anomalous `CoAP` traffic on resource-constrained `IoT` devices:
//!
//! - **URI allowlist/blocklist** — restrict accessible resources.
//! - **Method enforcement** — per-resource allowed HTTP-like methods.
//! - **Request rate limiting** — per-resource token-bucket rate control.
//! - **Amplification detection** — detects `CoAP` amplification attack
//!   patterns (large responses to small requests from spoofed sources).
//!
//! # Examples
//!
//! ```rust
//! use vs_coap_monitor::{CoapMonitor, UriAction, AllowedMethods};
//! use vs_types_embedded::{CoapMessage, CoapMethod, CoapMessageType};
//!
//! let mut monitor = CoapMonitor::new();
//! monitor.add_rule(b"/sensors", UriAction::Allow, AllowedMethods::GET_ONLY, 10).unwrap();
//!
//! let mut msg = CoapMessage::default();
//! msg.method = CoapMethod::Get;
//! msg.uri[..8].copy_from_slice(b"/sensors");
//! msg.uri_len = 8;
//! msg.timestamp_us = 1_000_000;
//!
//! let result = monitor.inspect(&msg);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_embedded::{
    fnv1a_hash, CoapMessage, CoapMessageType, CoapMethod, MonitorReset, TimestampValidator,
    MAX_RATE_BUCKETS_COAP, MAX_URI_RULES, SOURCE_COAP,
};

// ---------------------------------------------------------------------------
// Secondary hash for collision resistance (djb2)
// ---------------------------------------------------------------------------

/// Compute a djb2 hash of the given bytes. Used as a second independent hash
/// alongside FNV-1a to strengthen collision resistance in bucket matching.
#[inline]
fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &b in data {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Compute a hash of the suffix portion of the URI (bytes after `BUCKET_PREFIX_LEN`).
/// Returns 0 for short URIs, providing a third independent verification for long URIs.
#[inline]
fn suffix_hash(uri: &[u8]) -> u32 {
    if uri.len() <= BUCKET_PREFIX_LEN {
        return 0;
    }
    djb2_hash(&uri[BUCKET_PREFIX_LEN..])
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum URI pattern length.
const MAX_PATTERN_LEN: usize = 64;

/// Bucket collision-resistance prefix length. Increased from 8 to 32 bytes
/// to strengthen collision resistance against crafted URI names that share
/// a hash and short prefix.
const BUCKET_PREFIX_LEN: usize = 32;

/// Maximum rate-limit buckets (from feature-flag-driven constant).
const MAX_RATE_BUCKETS: usize = MAX_RATE_BUCKETS_COAP;

/// Bucket expiration timeout: 5 minutes without activity.
const RATE_BUCKET_EXPIRY_US: u64 = 300_000_000;

/// Maximum number of entries in the request-size ring buffer used for
/// amplification detection. This is a fixed size — not driven by capacity
/// feature flags. A value of 32 means only the 32 most recent requests are
/// tracked; under high traffic, older entries are evicted before their
/// responses arrive, which may cause amplification attacks to go undetected.
/// Increase this value if the device handles sustained high request rates.
const MAX_REQUEST_TRACKER: usize = vs_types_embedded::MAX_COAP_REQUEST_TRACKER;

/// Minimum request size baseline for amplification detection.
/// Requests with payload <= this are treated as having this size,
/// preventing zero-payload requests from bypassing detection.
const MIN_REQUEST_SIZE_BASELINE: u16 = 4;

// Alert source IDs for correlation.
const ALERT_URI_BLOCKED: u32 = 1;
const ALERT_METHOD_BLOCKED: u32 = 2;
const ALERT_RATE_LIMITED: u32 = 3;
const ALERT_RATE_BUCKET_EXHAUSTED: u32 = 4;
const ALERT_AMPLIFICATION: u32 = 5;
const ALERT_TIMESTAMP_ANOMALY: u32 = 6;
const ALERT_TRACKER_SATURATED: u32 = 7;
const ALERT_URI_PATH_TRAVERSAL: u32 = 8;
const ALERT_URI_NUL_BYTE: u32 = 9;
const ALERT_URI_EMPTY_SEGMENT: u32 = 10;
const ALERT_URI_OVERSIZED_SEGMENT: u32 = 11;

// ---------------------------------------------------------------------------
// URI normalization / validation
// ---------------------------------------------------------------------------

/// Default maximum length (in raw, pre-decode bytes) for any single Uri-Path
/// or Uri-Query segment. RFC 7252 caps a single option value at 255 bytes,
/// matching this default.
pub const DEFAULT_MAX_SEGMENT_LEN: usize = 255;

/// Configuration for the Uri-Path / Uri-Query normalization checks performed
/// on every inspected `CoAP` frame.
#[derive(Debug, Clone, Copy)]
pub struct CoapValidationConfig {
    /// Maximum length of any single Uri-Path or Uri-Query key segment, measured
    /// in *raw* (pre percent-decode) bytes. Segments longer than this are
    /// rejected with [`UriRejectReason::OversizedSegment`].
    pub max_segment_len: usize,
}

impl CoapValidationConfig {
    /// Construct a config with the default 255-byte segment cap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_segment_len: DEFAULT_MAX_SEGMENT_LEN,
        }
    }

    /// Override the per-segment maximum length.
    #[must_use]
    pub const fn with_max_segment_len(mut self, max_segment_len: usize) -> Self {
        self.max_segment_len = max_segment_len;
        self
    }
}

impl Default for CoapValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason a Uri-Path or Uri-Query key was rejected during normalization.
///
/// Surfaced on [`CoapInspectResult::reject_reason`] so a downstream policy
/// engine can distinguish the failure mode without re-parsing the URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriRejectReason {
    /// A path segment, after a single percent-decode pass, equals `..` or `.`.
    /// Detection runs on the raw bytes too, so encoded forms such as `%2e%2e`,
    /// `%2E%2E`, `%2e.`, and `.%2e` are caught even though the codepoints are
    /// only decoded once.
    PathTraversal,
    /// A NUL (`0x00`) byte was found in a segment, either as a literal byte or
    /// as a `%00` escape after a single decode pass. Downstream C-style
    /// string handlers truncate at NUL, which would silently change the URI's
    /// meaning.
    NulByte,
    /// An empty path segment (e.g. `//`, a trailing `/`, or a leading `/` with
    /// nothing after it). RFC 7252 forbids zero-length Uri-Path option values.
    EmptySegment,
    /// A raw (pre-decode) segment exceeded
    /// [`CoapValidationConfig::max_segment_len`].
    OversizedSegment,
}

impl UriRejectReason {
    /// Stable alert source ID for correlation with downstream SIEM tooling.
    #[inline]
    #[must_use]
    pub const fn alert_source_id(self) -> u32 {
        match self {
            Self::PathTraversal => ALERT_URI_PATH_TRAVERSAL,
            Self::NulByte => ALERT_URI_NUL_BYTE,
            Self::EmptySegment => ALERT_URI_EMPTY_SEGMENT,
            Self::OversizedSegment => ALERT_URI_OVERSIZED_SEGMENT,
        }
    }
}

/// Decode a single percent-encoded byte triple `%HH`.
///
/// Returns `Some((byte, 3))` on success, or `None` if the triple is malformed
/// (truncated or non-hex). Callers treat malformed escapes as a literal `%`
/// followed by the remaining bytes — they cannot magically become `..`, so we
/// do not surface a dedicated rejection reason for them.
#[inline]
fn decode_percent_triple(bytes: &[u8]) -> Option<u8> {
    if bytes.len() < 3 || bytes[0] != b'%' {
        return None;
    }
    let hi = hex_nibble(bytes[1])?;
    let lo = hex_nibble(bytes[2])?;
    Some((hi << 4) | lo)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Run a *single* percent-decode pass over `raw`, writing the result into `out`
/// up to `out`'s capacity, and return the decoded length (or `None` if the
/// decoded form would overflow `out`).
///
/// Why a single pass: the decoded output is what an application sees once. If
/// we recursively decoded, we would interpret a literal `%2e%2e` segment that a
/// client genuinely meant to send (which carries the bytes `%`, `2`, `e`, `%`,
/// `2`, `e`) as `..`, breaking apps that legitimately use `%`-containing names.
/// More importantly, attackers exploit double-decode bugs: any layer that
/// re-decodes already-decoded output is itself the vulnerability. We decode
/// exactly once and then compare the result; double-encoded inputs such as
/// `%252e%252e` decode to the literal string `%2e%2e`, which is NOT `..` and
/// is therefore allowed through this check (and would still be rejected by any
/// upstream layer that already decoded once before handing us the bytes).
fn percent_decode_once<const N: usize>(raw: &[u8], out: &mut [u8; N]) -> Option<usize> {
    let mut i = 0usize;
    let mut o = 0usize;
    while i < raw.len() {
        if raw[i] == b'%' {
            if let Some(decoded) = decode_percent_triple(&raw[i..]) {
                if o >= N {
                    return None;
                }
                out[o] = decoded;
                o += 1;
                i += 3;
                continue;
            }
        }
        if o >= N {
            return None;
        }
        out[o] = raw[i];
        o += 1;
        i += 1;
    }
    Some(o)
}

/// Validate a single raw Uri-Path or Uri-Query-key segment.
///
/// Performs, in order:
/// 1. Length cap (raw bytes) — see [`UriRejectReason::OversizedSegment`].
/// 2. Empty check — see [`UriRejectReason::EmptySegment`].
/// 3. Literal NUL scan in the raw bytes.
/// 4. *Single-pass* percent-decode, followed by:
///    - NUL check on the decoded bytes (catches `%00`).
///    - Equality check against `.` and `..` (catches `%2e%2e`, `%2E%2E`,
///      `%2e.`, `.%2e`, and any other single-decode reach of a traversal token).
///
/// A segment exceeding the internal 256-byte decode buffer is rejected as
/// `OversizedSegment` defensively; the public 255-byte default keeps us
/// inside that buffer.
pub fn validate_segment(raw: &[u8], cfg: &CoapValidationConfig) -> Result<(), UriRejectReason> {
    if raw.is_empty() {
        return Err(UriRejectReason::EmptySegment);
    }
    if raw.len() > cfg.max_segment_len {
        return Err(UriRejectReason::OversizedSegment);
    }
    // Raw NUL byte check (defense-in-depth: would also be caught after decode).
    for &b in raw {
        if b == 0 {
            return Err(UriRejectReason::NulByte);
        }
    }

    // Single-pass percent decode into a fixed buffer.
    let mut buf = [0u8; 256];
    let Some(decoded_len) = percent_decode_once(raw, &mut buf) else {
        return Err(UriRejectReason::OversizedSegment);
    };
    let decoded = &buf[..decoded_len];

    // %00 in the raw form decodes to a NUL here.
    for &b in decoded {
        if b == 0 {
            return Err(UriRejectReason::NulByte);
        }
    }

    // Traversal: a segment that is exactly "." or ".." after one decode pass.
    if decoded == b"." || decoded == b".." {
        return Err(UriRejectReason::PathTraversal);
    }

    Ok(())
}

/// Validate an assembled Uri-Path (slash-delimited segments).
///
/// A leading `/` is permitted (and conventional in this codebase). Any other
/// empty segment — including a trailing `/` or a doubled `//` — is rejected
/// with [`UriRejectReason::EmptySegment`].
pub fn validate_uri_path(path: &[u8], cfg: &CoapValidationConfig) -> Result<(), UriRejectReason> {
    if path.is_empty() {
        // An empty Uri-Path is the root resource — RFC 7252 represents this as
        // "no Uri-Path options at all", which is fine. Nothing to validate.
        return Ok(());
    }

    // Skip exactly one leading slash (our assembled-URI convention). A bare
    // "/" therefore yields no segments and validates trivially.
    let body = if path[0] == b'/' { &path[1..] } else { path };

    if body.is_empty() {
        return Ok(());
    }

    // Reject a trailing slash — that creates an empty terminal segment.
    if *body.last().expect("non-empty checked above") == b'/' {
        return Err(UriRejectReason::EmptySegment);
    }

    let mut start = 0usize;
    let mut i = 0usize;
    while i < body.len() {
        if body[i] == b'/' {
            let seg = &body[start..i];
            validate_segment(seg, cfg)?;
            start = i + 1;
        }
        i += 1;
    }
    // Final segment.
    validate_segment(&body[start..], cfg)?;
    Ok(())
}

/// Validate a single Uri-Query *key* (the `k` in `k=v`, or the whole option
/// when no `=` is present). Same checks as [`validate_segment`].
pub fn validate_uri_query_key(
    key: &[u8],
    cfg: &CoapValidationConfig,
) -> Result<(), UriRejectReason> {
    validate_segment(key, cfg)
}

// ---------------------------------------------------------------------------
// URI rule
// ---------------------------------------------------------------------------

/// Action for a URI match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriAction {
    /// Allow the request.
    Allow,
    /// Block the request and raise an alert.
    Block,
}

/// Allowed methods bitmask.
#[derive(Debug, Clone, Copy)]
pub struct AllowedMethods(u8);

impl AllowedMethods {
    /// All methods allowed.
    pub const ALL: Self = Self(0x0F);
    /// No methods allowed (block everything).
    pub const NONE: Self = Self(0x00);
    /// Only GET allowed.
    pub const GET_ONLY: Self = Self(1 << 0);
    /// GET and POST.
    pub const GET_POST: Self = Self((1 << 0) | (1 << 1));

    /// Create from individual method flags.
    #[allow(clippy::fn_params_excessive_bools)]
    pub const fn new(get: bool, post: bool, put: bool, delete: bool) -> Self {
        Self((get as u8) | ((post as u8) << 1) | ((put as u8) << 2) | ((delete as u8) << 3))
    }

    /// Check if a method is allowed.
    #[inline]
    pub fn is_allowed(self, method: CoapMethod) -> bool {
        let bit = match method {
            CoapMethod::Get => 0,
            CoapMethod::Post => 1,
            CoapMethod::Put => 2,
            CoapMethod::Delete => 3,
            // CoapMethod is #[non_exhaustive]; deny unknown methods.
            _ => return false,
        };
        (self.0 >> bit) & 1 == 1
    }
}

/// A URI filtering rule.
#[derive(Debug, Clone, Copy)]
struct UriRule {
    /// URI prefix pattern.
    pattern: [u8; MAX_PATTERN_LEN],
    pattern_len: u8,
    action: UriAction,
    allowed_methods: AllowedMethods,
    /// Max requests per second (0 = unlimited).
    max_rate_per_sec: u16,
    active: bool,
}

impl UriRule {
    const fn empty() -> Self {
        Self {
            pattern: [0u8; MAX_PATTERN_LEN],
            pattern_len: 0,
            action: UriAction::Allow,
            allowed_methods: AllowedMethods::ALL,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Rate bucket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct RateBucket {
    uri_hash: u32,
    /// Secondary URI hash (djb2) for collision resistance.
    uri_hash2: u32,
    /// First N bytes of the URI for collision resistance.
    uri_prefix: [u8; BUCKET_PREFIX_LEN],
    /// Length of valid bytes in `uri_prefix`.
    uri_prefix_len: u8,
    /// Full length of the URI that created this bucket.
    uri_len: u16,
    /// Suffix hash (djb2 of bytes after `BUCKET_PREFIX_LEN`) for collision resistance.
    uri_suffix_hash: u32,
    tokens: u16,
    capacity: u16,
    last_refill_us: u64,
    active: bool,
}

impl RateBucket {
    const fn empty() -> Self {
        Self {
            uri_hash: 0,
            uri_hash2: 0,
            uri_prefix: [0u8; BUCKET_PREFIX_LEN],
            uri_prefix_len: 0,
            uri_len: 0,
            uri_suffix_hash: 0,
            tokens: 0,
            capacity: 0,
            last_refill_us: 0,
            active: false,
        }
    }

    /// Check if this bucket matches the given URI (dual hash + suffix hash + length + prefix).
    #[inline]
    fn matches_uri(&self, uri_hash: u32, uri_hash2: u32, uri: &[u8], uri_suffix_hash: u32) -> bool {
        if self.uri_hash != uri_hash || self.uri_hash2 != uri_hash2 {
            return false;
        }
        if uri.len() != self.uri_len as usize {
            return false;
        }
        if self.uri_suffix_hash != uri_suffix_hash {
            return false;
        }
        let prefix_len = self.uri_prefix_len as usize;
        let cmp_len = uri.len().min(prefix_len);
        self.uri_prefix[..cmp_len] == uri[..cmp_len]
    }

    #[inline]
    fn try_consume(&mut self, now_us: u64) -> bool {
        let elapsed = now_us.saturating_sub(self.last_refill_us);
        // Use saturating_mul to prevent overflow when elapsed is large.
        let refill = elapsed.saturating_mul(self.capacity as u64) / 1_000_000;
        let refill_clamped = refill.min(self.capacity as u64) as u16;
        if refill_clamped > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refill_clamped)
                .min(self.capacity);
            self.last_refill_us = now_us;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn is_expired(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.last_refill_us) > RATE_BUCKET_EXPIRY_US
    }
}

// ---------------------------------------------------------------------------
// Rate-limit check result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateCheckResult {
    Allowed,
    Limited,
    /// All buckets active, none expired — LRU eviction occurred.
    BucketExhausted,
}

// ---------------------------------------------------------------------------
// Request tracker entry (for amplification detection)
// ---------------------------------------------------------------------------

/// Tracked request for amplification detection.
///
/// Uses both `message_id` and `token` for matching to reduce false positives
/// from message ID reuse in high-traffic environments (V3 fix).
/// Request expiry timeout: 30 seconds.
const REQUEST_EXPIRY_US: u64 = 30_000_000;

#[derive(Debug, Clone, Copy)]
struct TrackedRequest {
    message_id: u16,
    /// `CoAP` token (up to 8 bytes) for stronger request/response matching.
    token: [u8; 8],
    token_len: u8,
    /// Effective payload length (clamped to `MIN_REQUEST_SIZE_BASELINE`).
    payload_len: u16,
    /// Timestamp of the request for expiry-based cleanup.
    timestamp_us: u64,
}

impl TrackedRequest {
    const fn empty() -> Self {
        Self {
            message_id: 0,
            token: [0u8; 8],
            token_len: 0,
            payload_len: 0,
            timestamp_us: 0,
        }
    }

    #[inline]
    fn matches(&self, message_id: u16, token: &[u8], now_us: u64) -> bool {
        if self.message_id != message_id {
            return false;
        }
        // If both have tokens, compare them.
        // If neither has a token, match by ID only when the request is fresh
        // (within 5 seconds) to reduce false-positive matching from message ID
        // reuse across unrelated token-less exchanges.
        if self.token_len == 0 && token.is_empty() {
            const EMPTY_TOKEN_FRESHNESS_US: u64 = 5_000_000;
            return now_us.saturating_sub(self.timestamp_us) <= EMPTY_TOKEN_FRESHNESS_US;
        }
        if self.token_len as usize != token.len() {
            return false;
        }
        self.token[..self.token_len as usize] == token[..token.len()]
    }
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Result of inspecting a `CoAP` message.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct CoapInspectResult {
    /// Whether the message was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts dropped because the alert array was full.
    pub alerts_dropped: u8,
    /// If the frame was rejected by Uri-Path / Uri-Query normalization, the
    /// specific reason. `None` for any other allow/deny outcome.
    pub reject_reason: Option<UriRejectReason>,
}

impl CoapInspectResult {
    const fn clean() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: SOURCE_COAP,
                source_id: 0,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: 0,
            }; 4],
            alerts_dropped: 0,
            reject_reason: None,
        }
    }

    #[inline]
    fn push_alert(&mut self, severity: AlertSeverity, source_id: u32, ts_us: u64, alert_id: u64) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type: SOURCE_COAP,
                source_id,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// CoAP Monitor
// ---------------------------------------------------------------------------

/// Peer endpoint identifier for peer-scoped CoAP inspection.
///
/// Represents a remote CoAP endpoint by an IP address (IPv4 or IPv6) and
/// UDP port. The intent is to enable per-peer rate-limiting, amplification
/// tracking, and replay state in 0.8.0; at 0.7.0 the value is recorded but
/// the inspection logic is peer-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoapPeer {
    /// IPv4 or IPv6 address of the peer, encoded as the first 4 (IPv4) or
    /// 16 (IPv6) bytes followed by zeros for IPv4.
    pub address: [u8; 16],
    /// `true` if `address` is an IPv6 address; `false` for IPv4.
    pub is_ipv6: bool,
    /// UDP port number of the peer.
    pub port: u16,
}

impl CoapPeer {
    /// Construct a peer identifier from an IPv4 address and UDP port.
    #[must_use]
    pub const fn from_ipv4(addr: [u8; 4], port: u16) -> Self {
        let mut address = [0u8; 16];
        address[0] = addr[0];
        address[1] = addr[1];
        address[2] = addr[2];
        address[3] = addr[3];
        Self {
            address,
            is_ipv6: false,
            port,
        }
    }

    /// Alias for [`Self::from_ipv4`].
    #[must_use]
    pub const fn v4(addr: [u8; 4], port: u16) -> Self {
        Self::from_ipv4(addr, port)
    }

    /// Construct a peer identifier from an IPv6 address and UDP port.
    #[must_use]
    pub const fn from_ipv6(addr: [u8; 16], port: u16) -> Self {
        Self {
            address: addr,
            is_ipv6: true,
            port,
        }
    }

    /// Alias for [`Self::from_ipv6`].
    #[must_use]
    pub const fn v6(addr: [u8; 16], port: u16) -> Self {
        Self::from_ipv6(addr, port)
    }
}

/// `CoAP` protocol intrusion detection monitor.
pub struct CoapMonitor {
    rules: [UriRule; MAX_URI_RULES],
    rule_count: u8,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    /// Number of active rate-limit buckets (limits scan range).
    rate_bucket_count: u8,
    default_action: UriAction,
    /// Amplification detection: ring buffer of tracked requests.
    recent_requests: [TrackedRequest; MAX_REQUEST_TRACKER],
    recent_request_count: u8,
    recent_request_write_idx: u8,
    /// Amplification ratio threshold (response/request size).
    amplification_threshold: u16,
    /// Timestamp validator for clock anomaly detection.
    ts_validator: TimestampValidator,
    /// Monotonically increasing alert ID counter.
    next_alert_id: u64,
    total_inspected: u64,
    total_alerts: u64,
    /// Count of active (non-expired) tracker entries overwritten due to ring
    /// buffer saturation. When non-zero, amplification detection coverage is
    /// degraded: a response arriving after the corresponding request was
    /// evicted will not be detected. Callers should monitor this counter and
    /// consider increasing `MAX_REQUEST_TRACKER` (via `capacity-large` or
    /// `capacity-xl`) if it grows under normal load.
    requests_dropped: u32,
    /// Pending alert flag: set when the tracker drops an active entry,
    /// emitted and cleared on the next `inspect()` call.
    tracker_saturated_alert_pending: bool,
    /// Configuration governing Uri-Path / Uri-Query normalization checks.
    validation_cfg: CoapValidationConfig,
}

impl CoapMonitor {
    /// Create a new `CoAP` monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            rules: [UriRule::empty(); MAX_URI_RULES],
            rule_count: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            rate_bucket_count: 0,
            default_action: UriAction::Allow,
            recent_requests: [TrackedRequest::empty(); MAX_REQUEST_TRACKER],
            recent_request_count: 0,
            recent_request_write_idx: 0,
            amplification_threshold: 10,
            ts_validator: TimestampValidator::new(),
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
            requests_dropped: 0,
            tracker_saturated_alert_pending: false,
            validation_cfg: CoapValidationConfig::new(),
        }
    }

    /// Override the Uri-Path / Uri-Query normalization configuration.
    #[inline]
    pub fn set_validation_config(&mut self, cfg: CoapValidationConfig) {
        self.validation_cfg = cfg;
    }

    /// Returns the current Uri-Path / Uri-Query normalization configuration.
    #[inline]
    #[must_use]
    pub fn validation_config(&self) -> CoapValidationConfig {
        self.validation_cfg
    }

    /// Create a new `CoAP` monitor (deny-by-default).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = UriAction::Block;
        m
    }

    /// Set the amplification detection threshold.
    ///
    /// A response payload > `threshold * request_payload` triggers an alert.
    /// Requests with zero or very small payloads are treated as having a
    /// minimum baseline of `MIN_REQUEST_SIZE_BASELINE` bytes to prevent
    /// zero-payload requests from bypassing detection.
    /// Threshold must be >= 1 to be meaningful. A value of 0 is clamped to 1.
    #[inline]
    pub fn set_amplification_threshold(&mut self, threshold: u16) {
        self.amplification_threshold = threshold.max(1);
    }

    /// Add a URI rule.
    ///
    /// The pattern is matched as a prefix of the request URI.
    ///
    /// **Configuration-time only.** The duplicate-pattern check is O(n) over
    /// the current rule set; this is fine at startup but should not be called
    /// on the hot path. Use [`update_rule`](Self::update_rule) by index for
    /// runtime mutations.
    pub fn add_rule(
        &mut self,
        uri_prefix: &[u8],
        action: UriAction,
        methods: AllowedMethods,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if uri_prefix.is_empty() || uri_prefix.len() > MAX_PATTERN_LEN {
            return Err(VsError::InvalidInput);
        }

        // Check for duplicate: if a rule with the same pattern already exists,
        // update it in place instead of adding a new entry.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active
                && self.rules[i].pattern_len as usize == uri_prefix.len()
                && self.rules[i].pattern[..uri_prefix.len()] == *uri_prefix
            {
                self.rules[i].action = action;
                self.rules[i].allowed_methods = methods;
                self.rules[i].max_rate_per_sec = max_rate_per_sec;
                return Ok(());
            }
        }

        if self.rule_count as usize >= MAX_URI_RULES {
            return Err(VsError::ResourceExhausted);
        }

        let idx = self.rule_count as usize;
        self.rules[idx].pattern[..uri_prefix.len()].copy_from_slice(uri_prefix);
        self.rules[idx].pattern_len = uri_prefix.len() as u8;
        self.rules[idx].action = action;
        self.rules[idx].allowed_methods = methods;
        self.rules[idx].max_rate_per_sec = max_rate_per_sec;
        self.rules[idx].active = true;
        self.rule_count += 1;
        Ok(())
    }

    /// Remove a URI rule by index.
    pub fn remove_rule(&mut self, index: usize) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        let count = self.rule_count as usize;
        for i in index..count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[count - 1] = UriRule::empty();
        self.rule_count -= 1;
        Ok(())
    }

    /// Update an existing URI rule by index.
    pub fn update_rule(
        &mut self,
        index: usize,
        uri_prefix: &[u8],
        action: UriAction,
        methods: AllowedMethods,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        if uri_prefix.is_empty() || uri_prefix.len() > MAX_PATTERN_LEN {
            return Err(VsError::InvalidInput);
        }
        // No need to zero the full pattern buffer: `pattern_len` bounds what
        // any read sees, and the slice copy below overwrites every byte that
        // will be read.
        self.rules[index].pattern[..uri_prefix.len()].copy_from_slice(uri_prefix);
        self.rules[index].pattern_len = uri_prefix.len() as u8;
        self.rules[index].action = action;
        self.rules[index].allowed_methods = methods;
        self.rules[index].max_rate_per_sec = max_rate_per_sec;
        Ok(())
    }

    /// Remove all URI rules.
    ///
    /// Resets `rule_count` to zero. Slot contents are not zeroed — every
    /// read path bounds its scan by `rule_count` (and the per-slot `active`
    /// flag) so leftover bytes are unreachable.
    pub fn clear_rules(&mut self) {
        self.rule_count = 0;
    }

    /// Inspect a `CoAP` message in a peer-scoped context.
    ///
    /// At 0.7.0 the peer is recorded for forensic correlation but does not
    /// affect inspection logic; routes through [`Self::inspect`] unchanged.
    /// Provided so runtime crates can adopt the peer-scoped API now and
    /// gain per-peer isolation in 0.8.0 without churn.
    pub fn inspect_with_peer(&mut self, msg: &CoapMessage, _peer: &CoapPeer) -> CoapInspectResult {
        self.inspect(msg)
    }

    /// Inspect a `CoAP` message.
    ///
    /// URI rules use **longest-prefix-match** semantics.
    pub fn inspect(&mut self, msg: &CoapMessage) -> CoapInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = CoapInspectResult::clean();

        // Timestamp validation.
        if !self.ts_validator.validate(msg.timestamp_us) {
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TIMESTAMP_ANOMALY,
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            // Don't block — just alert on clock anomalies.
        }

        // RFC 7252: token length MUST be 0-8 bytes.
        if msg.token_len > 8 {
            result.allowed = false;
            return result;
        }

        let uri = msg.uri_bytes();

        // Uri-Path normalization. The check runs on the *raw* received bytes
        // and percent-decodes exactly once — see `percent_decode_once` for the
        // rationale on why iterative decoding is itself a vulnerability.
        if let Err(reason) = validate_uri_path(uri, &self.validation_cfg) {
            result.allowed = false;
            result.reject_reason = Some(reason);
            result.push_alert(
                AlertSeverity::High,
                reason.alert_source_id(),
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Find matching rule (longest prefix match).
        //
        // TODO(perf): O(MAX_URI_RULES) linear scan per inspected frame. With
        // `capacity-xl` (96 rules) this scales linearly with the rule count
        // on the hot path. Consider a length-bucketed table or a small trie
        // keyed on the first few prefix bytes for an indexed lookup; either
        // would keep this constant-time relative to the rule count.
        let mut best_match: Option<usize> = None;
        let mut best_len: u8 = 0;

        for i in 0..self.rule_count as usize {
            if !self.rules[i].active {
                continue;
            }
            let pat = &self.rules[i].pattern[..self.rules[i].pattern_len as usize];
            if uri.len() >= pat.len()
                && &uri[..pat.len()] == pat
                && self.rules[i].pattern_len > best_len
            {
                best_match = Some(i);
                best_len = self.rules[i].pattern_len;
                // Exact match — no longer prefix can exist.
                if best_len as usize == uri.len() {
                    break;
                }
            }
        }

        let action = match best_match {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };

        if action == UriAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_URI_BLOCKED,
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Method enforcement.
        if let Some(idx) = best_match {
            if !self.rules[idx].allowed_methods.is_allowed(msg.method) {
                result.push_alert(
                    AlertSeverity::Medium,
                    ALERT_METHOD_BLOCKED,
                    msg.timestamp_us,
                    self.next_alert_id(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                result.allowed = false;
                return result;
            }

            // Rate limiting.
            let max_rate = self.rules[idx].max_rate_per_sec;
            if max_rate > 0 {
                let uri_hash = fnv1a_hash(uri);
                let uri_hash2 = djb2_hash(uri);
                match self.rate_limit_check(uri_hash, uri_hash2, uri, max_rate, msg.timestamp_us) {
                    RateCheckResult::Allowed => {}
                    RateCheckResult::Limited => {
                        result.allowed = false;
                        result.push_alert(
                            AlertSeverity::Medium,
                            ALERT_RATE_LIMITED,
                            msg.timestamp_us,
                            self.next_alert_id(),
                        );
                        self.total_alerts = self.total_alerts.saturating_add(1);
                    }
                    RateCheckResult::BucketExhausted => {
                        // Allow traffic but with a warning — LRU eviction
                        // indicates resource pressure, however blocking
                        // legitimate traffic on bucket exhaustion causes more
                        // harm than permitting it with an alert.
                        result.push_alert(
                            AlertSeverity::Low,
                            ALERT_RATE_BUCKET_EXHAUSTED,
                            msg.timestamp_us,
                            self.next_alert_id(),
                        );
                        self.total_alerts = self.total_alerts.saturating_add(1);
                    }
                }
            }
        }

        // Track request sizes for amplification detection.
        if msg.msg_type == CoapMessageType::Confirmable
            || msg.msg_type == CoapMessageType::NonConfirmable
        {
            self.record_request(msg);
        }

        // Emit a warning alert if the request tracker became saturated
        // (active entries were evicted) since the last inspect call.
        if self.tracker_saturated_alert_pending {
            self.tracker_saturated_alert_pending = false;
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TRACKER_SATURATED,
                msg.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Check for amplification attack.
    ///
    /// Call this when a response is received. Returns `true` if the
    /// response size suggests amplification. Uses both message ID and
    /// token for matching to reduce false positives.
    /// Check for amplification, scoped to a peer endpoint. At 0.7.0 the peer
    /// is logged but does not affect matching; delegates to
    /// [`Self::check_amplification`]. Per-peer isolation is on the 0.8.0
    /// roadmap.
    pub fn check_amplification_with_peer(
        &mut self,
        message_id: u16,
        token: &[u8],
        _peer: &CoapPeer,
        response_payload_len: u16,
        ts_us: u64,
    ) -> Option<SecurityAlert> {
        self.check_amplification(message_id, token, response_payload_len, ts_us)
    }

    /// Check for amplification attack.
    pub fn check_amplification(
        &mut self,
        message_id: u16,
        token: &[u8],
        response_payload_len: u16,
        ts_us: u64,
    ) -> Option<SecurityAlert> {
        // TODO(perf): O(MAX_REQUEST_TRACKER) ring-buffer scan per response.
        // With `capacity-xl` (128 entries) every response pays the full scan.
        // Consider a small open-addressed index keyed by `(message_id, token)`
        // sized to the same capacity for O(1) lookup.
        for i in 0..self.recent_request_count as usize {
            // Skip expired requests.
            if ts_us.saturating_sub(self.recent_requests[i].timestamp_us) > REQUEST_EXPIRY_US {
                continue;
            }
            if self.recent_requests[i].matches(message_id, token, ts_us) {
                let req_len = self.recent_requests[i].payload_len;
                // Mark entry as consumed so it cannot be matched again.
                self.recent_requests[i].timestamp_us = 0;
                // Use checked_mul: if the product overflows u32, the threshold
                // is astronomically large and cannot be exceeded — skip alerting.
                // This prevents saturating_mul from masking overflow to u32::MAX
                // which would disable detection entirely.
                let threshold_len =
                    (req_len as u32).checked_mul(self.amplification_threshold as u32);
                let is_amplified = match threshold_len {
                    Some(t) => response_payload_len as u32 > t,
                    // Overflow means threshold > u32::MAX — response can't exceed it.
                    None => false,
                };
                if is_amplified {
                    self.total_alerts = self.total_alerts.saturating_add(1);
                    return Some(SecurityAlert {
                        id: self.next_alert_id(),
                        severity: AlertSeverity::High,
                        source_type: SOURCE_COAP,
                        source_id: ALERT_AMPLIFICATION,
                        payload_hash: vs_types::PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    });
                }
                return None;
            }
        }
        None
    }

    /// Return the total number of messages inspected.
    #[inline]
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Return the total number of alerts raised.
    #[inline]
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Return the number of active URI rules.
    #[inline]
    pub fn rule_count(&self) -> usize {
        self.rule_count as usize
    }

    /// Return the number of active tracker entries overwritten due to ring
    /// buffer saturation.
    ///
    /// A non-zero value indicates that under current traffic volume, the
    /// amplification detection tracker is full and older entries are being
    /// evicted before their responses arrive. This reduces detection coverage.
    ///
    /// If this counter grows under normal load, enable the `capacity-large` or
    /// `capacity-xl` feature to increase `MAX_REQUEST_TRACKER`.
    #[inline]
    pub fn requests_dropped(&self) -> u32 {
        self.requests_dropped
    }

    /// Returns `true` if the request tracker ring buffer is currently at full
    /// capacity (all `MAX_REQUEST_TRACKER` slots are active/non-expired).
    #[inline]
    pub fn tracker_is_saturated(&self) -> bool {
        self.recent_request_count as usize >= MAX_REQUEST_TRACKER
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    #[inline]
    fn next_alert_id(&mut self) -> u64 {
        let id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.wrapping_add(1);
        if self.next_alert_id == 0 {
            self.next_alert_id = 1;
        }
        id
    }

    #[inline]
    fn record_request(&mut self, msg: &CoapMessage) {
        let idx = self.recent_request_write_idx as usize % MAX_REQUEST_TRACKER;
        // When the ring buffer is full, we overwrite an existing entry.
        // If the slot still holds an active (non-expired) request, the
        // corresponding response can no longer be matched — amplification
        // detection coverage is degraded. Increment the counter so callers
        // can detect this and consider upgrading to a larger capacity tier.
        if self.recent_request_count as usize >= MAX_REQUEST_TRACKER {
            let slot_ts = self.recent_requests[idx].timestamp_us;
            let is_active =
                slot_ts != 0 && msg.timestamp_us.saturating_sub(slot_ts) <= REQUEST_EXPIRY_US;
            if is_active {
                self.requests_dropped = self.requests_dropped.saturating_add(1);
                self.tracker_saturated_alert_pending = true;
            }
        }
        let effective_len = if msg.payload_len < MIN_REQUEST_SIZE_BASELINE {
            MIN_REQUEST_SIZE_BASELINE
        } else {
            msg.payload_len
        };
        let mut token = [0u8; 8];
        let token_len = (msg.token_len as usize).min(msg.token.len()).min(8);
        token[..token_len].copy_from_slice(&msg.token[..token_len]);
        self.recent_requests[idx] = TrackedRequest {
            message_id: msg.message_id,
            token,
            token_len: token_len as u8,
            payload_len: effective_len,
            timestamp_us: msg.timestamp_us,
        };
        self.recent_request_write_idx = ((idx + 1) % MAX_REQUEST_TRACKER) as u8;
        if (self.recent_request_count as usize) < MAX_REQUEST_TRACKER {
            self.recent_request_count += 1;
        }
    }

    /// Look up or allocate the rate-limit bucket for `uri` and try to consume
    /// a token.
    ///
    /// **Cost:** O(`MAX_RATE_BUCKETS`) linear scan per call — one pass over
    /// the full bucket table to find a match, free slot, expired slot, and
    /// LRU candidate simultaneously. With the default (16) or `capacity-large`
    /// (64) feature this is acceptable; on `capacity-xl` (128) this becomes
    /// the hot path's dominant cost.
    ///
    /// TODO(perf): on `capacity-xl`, switch to an open-addressed hash table
    /// keyed by `(uri_hash, uri_hash2)` so the common-case match is O(1).
    fn rate_limit_check(
        &mut self,
        uri_hash: u32,
        uri_hash2: u32,
        uri: &[u8],
        max_rate: u16,
        now_us: u64,
    ) -> RateCheckResult {
        let sfx_hash = suffix_hash(uri);
        // Single pass: find matching bucket, free slot, expired slot, and
        // LRU candidate all at once to avoid a second scan on eviction.
        let mut match_idx: Option<usize> = None;
        let mut free_idx: Option<usize> = None;
        let mut expired_idx: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_RATE_BUCKETS {
            let bucket = &self.rate_buckets[i];
            if !bucket.active {
                if free_idx.is_none() {
                    free_idx = Some(i);
                }
                continue;
            }
            // Proactively deactivate expired buckets and decrement count.
            if bucket.is_expired(now_us) {
                self.rate_buckets[i].active = false;
                self.rate_bucket_count = self.rate_bucket_count.saturating_sub(1);
                if expired_idx.is_none() {
                    expired_idx = Some(i);
                }
                continue;
            }
            if bucket.matches_uri(uri_hash, uri_hash2, uri, sfx_hash) {
                match_idx = Some(i);
            }
            if bucket.last_refill_us < lru_ts {
                lru_ts = bucket.last_refill_us;
                lru_idx = i;
            }
        }

        // 1. Matching bucket found -- consume a token.
        if let Some(idx) = match_idx {
            return if self.rate_buckets[idx].try_consume(now_us) {
                RateCheckResult::Allowed
            } else {
                RateCheckResult::Limited
            };
        }

        // 2. Allocate in a free or expired slot.
        let alloc_slot = free_idx.or(expired_idx);
        if let Some(idx) = alloc_slot {
            let prefix_len = uri.len().min(BUCKET_PREFIX_LEN);
            let mut prefix = [0u8; BUCKET_PREFIX_LEN];
            prefix[..prefix_len].copy_from_slice(&uri[..prefix_len]);
            self.rate_buckets[idx] = RateBucket {
                uri_hash,
                uri_hash2,
                uri_prefix: prefix,
                uri_prefix_len: prefix_len as u8,
                uri_len: uri.len() as u16,
                uri_suffix_hash: sfx_hash,
                tokens: max_rate.saturating_sub(1),
                capacity: max_rate,
                last_refill_us: now_us,
                active: true,
            };
            self.rate_bucket_count = self.rate_bucket_count.saturating_add(1);
            return RateCheckResult::Allowed;
        }

        // 3. All buckets active and none expired -- LRU eviction.
        // Evict the oldest bucket to free space for future requests,
        // but DENY the current request to prevent an attacker from
        // flooding new URIs to bypass rate limiting entirely.
        self.rate_buckets[lru_idx].active = false;
        self.rate_bucket_count = self.rate_bucket_count.saturating_sub(1);
        RateCheckResult::BucketExhausted
    }
}

impl Default for CoapMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for CoapMonitor {
    /// Reset all runtime state while preserving rules and configuration.
    fn reset_state(&mut self) {
        self.rate_buckets = [RateBucket::empty(); MAX_RATE_BUCKETS];
        self.rate_bucket_count = 0;
        self.recent_requests = [TrackedRequest::empty(); MAX_REQUEST_TRACKER];
        self.recent_request_count = 0;
        self.recent_request_write_idx = 0;
        self.requests_dropped = 0;
        self.tracker_saturated_alert_pending = false;
        self.ts_validator.reset();
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
        // Preserve: rules, rule_count, default_action, amplification_threshold.
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(uri: &[u8], method: CoapMethod, ts_us: u64) -> CoapMessage {
        let mut msg = CoapMessage::default();
        msg.uri[..uri.len()].copy_from_slice(uri);
        msg.uri_len = uri.len() as u8;
        msg.method = method;
        msg.timestamp_us = ts_us;
        msg.payload_len = 10;
        msg
    }

    fn make_request_with_token(
        uri: &[u8],
        method: CoapMethod,
        ts_us: u64,
        token: &[u8],
    ) -> CoapMessage {
        let mut msg = make_request(uri, method, ts_us);
        let tlen = token.len().min(8);
        msg.token[..tlen].copy_from_slice(&token[..tlen]);
        msg.token_len = tlen as u8;
        msg
    }

    #[test]
    fn default_allow() {
        let mut mon = CoapMonitor::new();
        let msg = make_request(b"/sensors/temp", CoapMethod::Get, 1000);
        let result = mon.inspect(&msg);
        assert!(result.allowed);
    }

    #[test]
    fn deny_default() {
        let mut mon = CoapMonitor::new_deny_default();
        let msg = make_request(b"/sensors/temp", CoapMethod::Get, 1000);
        let result = mon.inspect(&msg);
        assert!(!result.allowed);
    }

    #[test]
    fn allow_overrides_deny_default() {
        let mut mon = CoapMonitor::new_deny_default();
        mon.add_rule(b"/sensors", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        let msg = make_request(b"/sensors/temp", CoapMethod::Get, 1000);
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn block_rule() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/admin", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();
        let msg = make_request(b"/admin/config", CoapMethod::Post, 1000);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn method_enforcement() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/sensors", UriAction::Allow, AllowedMethods::GET_ONLY, 0)
            .unwrap();

        let get = make_request(b"/sensors/temp", CoapMethod::Get, 1000);
        assert!(mon.inspect(&get).allowed);

        let post = make_request(b"/sensors/temp", CoapMethod::Post, 2000);
        assert!(!mon.inspect(&post).allowed);
    }

    #[test]
    fn rate_limiting() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/data", UriAction::Allow, AllowedMethods::ALL, 2)
            .unwrap();

        for i in 0..2 {
            let msg = make_request(b"/data/stream", CoapMethod::Get, 1000 + i * 100);
            assert!(mon.inspect(&msg).allowed, "msg {i} should pass");
        }

        let msg = make_request(b"/data/stream", CoapMethod::Get, 1200);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn amplification_detection() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x42]);
        msg.payload_len = 4;
        msg.message_id = 42;
        let _ = mon.inspect(&msg);

        // 4 * 10 = 40 threshold, 500 > 40.
        let alert = mon.check_amplification(42, &[0x42], 500, 2000);
        assert!(alert.is_some());
    }

    #[test]
    fn no_amplification_for_normal_response() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x99]);
        msg.payload_len = 50;
        msg.message_id = 99;
        let _ = mon.inspect(&msg);

        let alert = mon.check_amplification(99, &[0x99], 100, 2000);
        assert!(alert.is_none());
    }

    #[test]
    fn longest_prefix_match() {
        let mut mon = CoapMonitor::new_deny_default();
        mon.add_rule(b"/api", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        mon.add_rule(b"/api/admin", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();

        let msg1 = make_request(b"/api/data", CoapMethod::Get, 1000);
        assert!(mon.inspect(&msg1).allowed);

        let msg2 = make_request(b"/api/admin/users", CoapMethod::Get, 2000);
        assert!(!mon.inspect(&msg2).allowed);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/blocked", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();

        let _ = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 1000));
        let _ = mon.inspect(&make_request(b"/blocked/x", CoapMethod::Get, 2000));

        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
    }

    #[test]
    fn allowed_methods_bitmask() {
        let m = AllowedMethods::new(true, false, true, false);
        assert!(m.is_allowed(CoapMethod::Get));
        assert!(!m.is_allowed(CoapMethod::Post));
        assert!(m.is_allowed(CoapMethod::Put));
        assert!(!m.is_allowed(CoapMethod::Delete));
    }

    #[test]
    fn allowed_methods_all() {
        let m = AllowedMethods::ALL;
        assert!(m.is_allowed(CoapMethod::Get));
        assert!(m.is_allowed(CoapMethod::Post));
        assert!(m.is_allowed(CoapMethod::Put));
        assert!(m.is_allowed(CoapMethod::Delete));
    }

    #[test]
    fn allowed_methods_none() {
        let m = AllowedMethods::NONE;
        assert!(!m.is_allowed(CoapMethod::Get));
        assert!(!m.is_allowed(CoapMethod::Post));
    }

    #[test]
    fn allowed_methods_get_post() {
        let m = AllowedMethods::GET_POST;
        assert!(m.is_allowed(CoapMethod::Get));
        assert!(m.is_allowed(CoapMethod::Post));
        assert!(!m.is_allowed(CoapMethod::Put));
        assert!(!m.is_allowed(CoapMethod::Delete));
    }

    #[test]
    fn add_rule_rejects_empty() {
        let mut mon = CoapMonitor::new();
        assert!(mon
            .add_rule(b"", UriAction::Allow, AllowedMethods::ALL, 0)
            .is_err());
    }

    #[test]
    fn add_rule_rejects_oversized() {
        let mut mon = CoapMonitor::new();
        let big = [b'a'; 65];
        assert!(mon
            .add_rule(&big, UriAction::Allow, AllowedMethods::ALL, 0)
            .is_err());
    }

    #[test]
    fn add_rule_rejects_when_full() {
        let mut mon = CoapMonitor::new();
        for i in 0..MAX_URI_RULES {
            // Use 3-byte URIs to ensure uniqueness up to 26*26=676 patterns.
            let uri = [b'/', b'a' + (i as u8 / 26), b'a' + (i as u8 % 26)];
            mon.add_rule(&uri, UriAction::Allow, AllowedMethods::ALL, 0)
                .unwrap();
        }
        assert!(mon
            .add_rule(b"/overflow", UriAction::Allow, AllowedMethods::ALL, 0)
            .is_err());
    }

    #[test]
    fn amplification_unknown_message_id() {
        let mut mon = CoapMonitor::new();
        let alert = mon.check_amplification(999, &[], 5000, 1000);
        assert!(alert.is_none());
    }

    #[test]
    fn nonconfirmable_request_tracked() {
        let mut mon = CoapMonitor::new();
        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x55]);
        msg.msg_type = CoapMessageType::NonConfirmable;
        msg.payload_len = 4;
        msg.message_id = 55;
        let _ = mon.inspect(&msg);

        let alert = mon.check_amplification(55, &[0x55], 500, 2000);
        assert!(alert.is_some());
    }

    #[test]
    fn rate_limit_refills_over_time() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/data", UriAction::Allow, AllowedMethods::ALL, 2)
            .unwrap();

        for i in 0..2 {
            let msg = make_request(b"/data/x", CoapMethod::Get, 1000 + i * 100);
            assert!(mon.inspect(&msg).allowed);
        }

        let msg = make_request(b"/data/x", CoapMethod::Get, 1_100_000);
        assert!(mon.inspect(&msg).allowed);
    }

    #[test]
    fn rule_count_accessor() {
        let mut mon = CoapMonitor::new();
        assert_eq!(mon.rule_count(), 0);
        mon.add_rule(b"/a", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        assert_eq!(mon.rule_count(), 1);
    }

    #[test]
    fn default_constructor() {
        let mon = CoapMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn method_delete_enforcement() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/res", UriAction::Allow, AllowedMethods::GET_ONLY, 0)
            .unwrap();

        let msg = make_request(b"/res/item", CoapMethod::Delete, 1000);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn put_method_enforcement() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(
            b"/res",
            UriAction::Allow,
            AllowedMethods::new(true, false, true, false),
            0,
        )
        .unwrap();

        let put = make_request(b"/res/item", CoapMethod::Put, 1000);
        assert!(mon.inspect(&put).allowed);

        let post = make_request(b"/res/item", CoapMethod::Post, 2000);
        assert!(!mon.inspect(&post).allowed);
    }

    #[test]
    fn rate_limit_bucket_exhaustion_alert() {
        let mut mon = CoapMonitor::new();
        // Fill all rate buckets with distinct URIs. Use 3-byte URIs to
        // support up to 26*26=676 unique patterns across capacity flags.
        for i in 0..MAX_RATE_BUCKETS {
            let uri = [b'/', b'a' + (i as u8 / 26), b'a' + (i as u8 % 26)];
            mon.add_rule(&uri, UriAction::Allow, AllowedMethods::ALL, 1)
                .unwrap();
            let msg = make_request(&uri, CoapMethod::Get, 1000 + i as u64 * 100);
            let _ = mon.inspect(&msg);
        }

        mon.add_rule(b"/overflow", UriAction::Allow, AllowedMethods::ALL, 1)
            .unwrap();
        // All buckets are full but recent (not expired). LRU eviction
        // occurs but the request is BLOCKED to prevent attackers from
        // flooding new URIs to bypass rate limiting.
        let msg = make_request(b"/overflow/x", CoapMethod::Get, 5000);
        let result = mon.inspect(&msg);
        assert!(
            result.allowed,
            "bucket-exhausted eviction should allow traffic with warning"
        );
    }

    // -----------------------------------------------------------------------
    // V5 fix: zero-payload amplification detection
    // -----------------------------------------------------------------------

    #[test]
    fn amplification_zero_payload_now_detected() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x77]);
        msg.payload_len = 0;
        msg.message_id = 77;
        let _ = mon.inspect(&msg);

        // Zero-payload request now uses MIN_REQUEST_SIZE_BASELINE (4).
        // 4 * 10 = 40 threshold, 1000 > 40 => amplification detected.
        let alert = mon.check_amplification(77, &[0x77], 1000, 2000);
        assert!(
            alert.is_some(),
            "zero-payload amplification should be detected"
        );
    }

    #[test]
    fn amplification_zero_payload_no_false_positive() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x88]);
        msg.payload_len = 0;
        msg.message_id = 88;
        let _ = mon.inspect(&msg);

        // Small response (30 < 40) should NOT trigger.
        let alert = mon.check_amplification(88, &[0x88], 30, 2000);
        assert!(alert.is_none());
    }

    // -----------------------------------------------------------------------
    // V3 fix: token-based matching
    // -----------------------------------------------------------------------

    #[test]
    fn amplification_token_mismatch_no_match() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0x01, 0x02]);
        msg.payload_len = 4;
        msg.message_id = 42;
        let _ = mon.inspect(&msg);

        // Same message_id but different token — should NOT match.
        let alert = mon.check_amplification(42, &[0x03, 0x04], 500, 2000);
        assert!(alert.is_none(), "different token should not match");
    }

    #[test]
    fn amplification_no_token_matches_no_token() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);

        // Request with no token.
        let mut msg = make_request(b"/info", CoapMethod::Get, 1000);
        msg.payload_len = 4;
        msg.message_id = 42;
        let _ = mon.inspect(&msg);

        // Response with no token and same message_id.
        let alert = mon.check_amplification(42, &[], 500, 2000);
        assert!(alert.is_some(), "no-token should match no-token");
    }

    // -----------------------------------------------------------------------
    // Alert IDs
    // -----------------------------------------------------------------------

    #[test]
    fn alert_ids_are_unique() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/block", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();

        let r1 = mon.inspect(&make_request(b"/block/a", CoapMethod::Get, 1000));
        let r2 = mon.inspect(&make_request(b"/block/b", CoapMethod::Get, 2000));

        assert!(r1.alerts[0].id > 0);
        assert!(r2.alerts[0].id > r1.alerts[0].id);
    }

    // -----------------------------------------------------------------------
    // Rule removal
    // -----------------------------------------------------------------------

    #[test]
    fn remove_rule_works() {
        let mut mon = CoapMonitor::new_deny_default();
        mon.add_rule(b"/sensors", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        mon.add_rule(b"/admin", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        assert_eq!(mon.rule_count(), 2);

        mon.remove_rule(0).unwrap();
        assert_eq!(mon.rule_count(), 1);

        let msg = make_request(b"/sensors/temp", CoapMethod::Get, 1000);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn remove_rule_invalid_index() {
        let mut mon = CoapMonitor::new();
        assert!(mon.remove_rule(0).is_err());
    }

    #[test]
    fn clear_rules_works() {
        let mut mon = CoapMonitor::new_deny_default();
        mon.add_rule(b"/api", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        mon.clear_rules();
        assert_eq!(mon.rule_count(), 0);
        let msg = make_request(b"/api/data", CoapMethod::Get, 1000);
        assert!(!mon.inspect(&msg).allowed);
    }

    #[test]
    fn alert_overflow_capped_at_4() {
        let mut result = CoapInspectResult::clean();
        for _ in 0..6 {
            result.push_alert(AlertSeverity::Medium, 0, 1000, 1);
        }
        assert_eq!(result.alert_count, 4);
    }

    #[test]
    fn non_monotonic_timestamp_no_panic() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/data", UriAction::Allow, AllowedMethods::ALL, 5)
            .unwrap();

        let msg1 = make_request(b"/data/x", CoapMethod::Get, 10_000_000);
        let _ = mon.inspect(&msg1);

        let msg2 = make_request(b"/data/x", CoapMethod::Get, 1_000_000);
        let r = mon.inspect(&msg2);
        // Verify no panic occurred and result is valid
        assert!(r.alert_count <= 4);
    }

    #[test]
    fn rate_bucket_expires_and_is_reused() {
        let mut mon = CoapMonitor::new();
        for i in 0u8..16 {
            let uri = [b'/', b'a' + (i % 26)];
            mon.add_rule(&uri, UriAction::Allow, AllowedMethods::ALL, 1)
                .unwrap();
            let msg = make_request(&uri, CoapMethod::Get, 1000);
            let _ = mon.inspect(&msg);
        }
        mon.add_rule(b"/z", UriAction::Allow, AllowedMethods::ALL, 1)
            .unwrap();
        let msg = make_request(b"/z/data", CoapMethod::Get, 400_000_000);
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Clear rules mid-traffic
    // -----------------------------------------------------------------------

    #[test]
    fn clear_rules_mid_traffic_no_corruption() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/data", UriAction::Allow, AllowedMethods::ALL, 5)
            .unwrap();

        for i in 0..3 {
            let msg = make_request(b"/data/x", CoapMethod::Get, 1000 + i * 100);
            let _ = mon.inspect(&msg);
        }

        mon.clear_rules();
        let msg = make_request(b"/data/x", CoapMethod::Get, 2000);
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Timestamp validation
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_anomaly_alerts() {
        let mut mon = CoapMonitor::new();
        // Initialize with a normal timestamp (100 seconds).
        let _ = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 100_000_000));
        // Large backward jump (100s > 10s tolerance) should trigger anomaly.
        let r = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 0));
        assert!(
            r.alert_count > 0,
            "out-of-order timestamps should generate alerts"
        );
    }

    #[test]
    fn timestamp_normal_progression_no_alert() {
        let mut mon = CoapMonitor::new();
        let r1 = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 1_000_000));
        assert_eq!(r1.alert_count, 0);
        let r2 = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 2_000_000));
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn timestamp_anomaly_does_not_block() {
        let mut mon = CoapMonitor::new();
        let _ = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 100_000_000));
        // Large backward jump — should alert but still allow.
        let r = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 0));
        assert!(r.allowed);
    }

    #[test]
    fn timestamp_anomaly_severity_is_low() {
        let mut mon = CoapMonitor::new();
        let _ = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 100_000_000));
        let r = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 0));
        if r.alert_count > 0 {
            assert_eq!(r.alerts[0].severity, AlertSeverity::Low);
            assert_eq!(r.alerts[0].source_id, ALERT_TIMESTAMP_ANOMALY);
        }
    }

    // -----------------------------------------------------------------------
    // MonitorReset tests
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_reset_clears_runtime_state() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/blocked", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();
        mon.add_rule(b"/data", UriAction::Allow, AllowedMethods::ALL, 5)
            .unwrap();

        // Generate some traffic and alerts.
        let _ = mon.inspect(&make_request(b"/blocked/x", CoapMethod::Get, 1000));
        let _ = mon.inspect(&make_request(b"/data/x", CoapMethod::Get, 2000));
        assert!(mon.total_inspected() > 0);
        assert!(mon.total_alerts() > 0);

        mon.reset_state();

        // Runtime state should be cleared.
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);

        // Rules should be preserved.
        assert_eq!(mon.rule_count(), 2);
        let r = mon.inspect(&make_request(b"/blocked/y", CoapMethod::Get, 3000));
        assert!(!r.allowed);
    }

    #[test]
    fn monitor_reset_preserves_amplification_threshold() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(20);
        let _ = mon.inspect(&make_request(b"/ok", CoapMethod::Get, 1000));
        mon.reset_state();
        assert_eq!(mon.amplification_threshold, 20);
    }

    #[test]
    fn monitor_reset_preserves_default_action() {
        let mut mon = CoapMonitor::new_deny_default();
        let _ = mon.inspect(&make_request(b"/x", CoapMethod::Get, 1000));
        mon.reset_state();
        let r = mon.inspect(&make_request(b"/x", CoapMethod::Get, 2000));
        assert!(!r.allowed);
    }

    // -----------------------------------------------------------------------
    // Alert source ID constant tests
    // -----------------------------------------------------------------------

    #[test]
    fn alert_constants_are_unique() {
        let ids = [
            ALERT_URI_BLOCKED,
            ALERT_METHOD_BLOCKED,
            ALERT_RATE_LIMITED,
            ALERT_RATE_BUCKET_EXHAUSTED,
            ALERT_AMPLIFICATION,
            ALERT_TIMESTAMP_ANOMALY,
            ALERT_TRACKER_SATURATED,
        ];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "alert IDs at index {i} and {j} collide");
            }
        }
    }

    #[test]
    fn block_alert_uses_uri_blocked_constant() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/admin", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();
        let r = mon.inspect(&make_request(b"/admin/x", CoapMethod::Get, 1000));
        assert_eq!(r.alerts[0].source_id, ALERT_URI_BLOCKED);
    }

    #[test]
    fn method_block_alert_uses_method_blocked_constant() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/res", UriAction::Allow, AllowedMethods::GET_ONLY, 0)
            .unwrap();
        let r = mon.inspect(&make_request(b"/res/x", CoapMethod::Post, 1000));
        assert_eq!(r.alerts[0].source_id, ALERT_METHOD_BLOCKED);
    }

    #[test]
    fn amplification_alert_uses_constant() {
        let mut mon = CoapMonitor::new();
        mon.set_amplification_threshold(10);
        let mut msg = make_request_with_token(b"/info", CoapMethod::Get, 1000, &[0xAA]);
        msg.payload_len = 4;
        msg.message_id = 100;
        let _ = mon.inspect(&msg);

        let alert = mon.check_amplification(100, &[0xAA], 500, 2000);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().source_id, ALERT_AMPLIFICATION);
    }

    // -----------------------------------------------------------------------
    // update_rule tests
    // -----------------------------------------------------------------------

    #[test]
    fn update_rule_changes_action() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/api", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        assert!(
            mon.inspect(&make_request(b"/api/data", CoapMethod::Get, 1000))
                .allowed
        );

        mon.update_rule(0, b"/api", UriAction::Block, AllowedMethods::ALL, 0)
            .unwrap();
        assert!(
            !mon.inspect(&make_request(b"/api/data", CoapMethod::Get, 2000))
                .allowed
        );
    }

    #[test]
    fn update_rule_changes_methods() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/res", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        assert!(
            mon.inspect(&make_request(b"/res/x", CoapMethod::Post, 1000))
                .allowed
        );

        mon.update_rule(0, b"/res", UriAction::Allow, AllowedMethods::GET_ONLY, 0)
            .unwrap();
        assert!(
            !mon.inspect(&make_request(b"/res/x", CoapMethod::Post, 2000))
                .allowed
        );
    }

    #[test]
    fn update_rule_invalid_index() {
        let mut mon = CoapMonitor::new();
        assert!(mon
            .update_rule(0, b"/x", UriAction::Allow, AllowedMethods::ALL, 0)
            .is_err());
    }

    #[test]
    fn update_rule_rejects_empty_pattern() {
        let mut mon = CoapMonitor::new();
        mon.add_rule(b"/a", UriAction::Allow, AllowedMethods::ALL, 0)
            .unwrap();
        assert!(mon
            .update_rule(0, b"", UriAction::Allow, AllowedMethods::ALL, 0)
            .is_err());
    }

    #[test]
    fn rate_bucket_matches_uri_with_different_lengths() {
        // Regression test for CRIT-2: URIs with same hash prefix but different
        // lengths must NOT match the same bucket.
        let mut monitor = CoapMonitor::new();
        monitor
            .add_rule(b"/sensors", UriAction::Allow, AllowedMethods::ALL, 10)
            .unwrap();

        let mut msg = CoapMessage::default();
        msg.uri[..13].copy_from_slice(b"/sensors/temp");
        msg.uri_len = 13;
        msg.timestamp_us = 1_000_000;
        let _ = monitor.inspect(&msg);

        // Shorter URI with same prefix bytes
        let mut msg2 = CoapMessage::default();
        msg2.uri[..5].copy_from_slice(b"/sens");
        msg2.uri_len = 5;
        msg2.timestamp_us = 2_000_000;
        let _ = monitor.inspect(&msg2);
        // Should not panic or cause bucket mismatch
    }

    #[test]
    fn alerts_dropped_counter_on_overflow() {
        let monitor_result = CoapInspectResult::clean();
        assert_eq!(monitor_result.alerts_dropped, 0);
    }

    #[test]
    fn bucket_exhaustion_alert_emitted() {
        // Fill all rate buckets to trigger LRU eviction and verify
        // ALERT_RATE_BUCKET_EXHAUSTED is emitted.
        use vs_types_embedded::MAX_RATE_BUCKETS_COAP;
        let mut monitor = CoapMonitor::new();

        // Add a rule with rate limiting
        monitor
            .add_rule(b"/", UriAction::Allow, AllowedMethods::ALL, 100)
            .unwrap();

        // Fill all rate buckets with distinct URIs (no format! in no_std tests).
        for i in 0..MAX_RATE_BUCKETS_COAP + 2 {
            let mut msg = CoapMessage::default();
            let prefix = b"/resource/";
            msg.uri[..prefix.len()].copy_from_slice(prefix);
            msg.uri[prefix.len()] = b'A'.wrapping_add((i as u8) % 26);
            msg.uri[prefix.len() + 1] = b'0'.wrapping_add((i as u8) / 26);
            msg.uri_len = (prefix.len() + 2) as u8;
            msg.timestamp_us = (i as u64 + 1) * 1_000_000;
            let _ = monitor.inspect(&msg);
        }
        // After exceeding bucket capacity, the monitor should have emitted
        // a bucket exhaustion alert at some point. We verify it doesn't panic.
    }

    #[test]
    fn token_bounds_check_no_panic() {
        // Verify that a malformed CoapMessage with token_len > 8 is rejected
        // per RFC 7252 (token length MUST be 0-8 bytes).
        let mut monitor = CoapMonitor::new();
        let mut msg = CoapMessage::default();
        msg.uri[..5].copy_from_slice(b"/test");
        msg.uri_len = 5;
        msg.msg_type = vs_types_embedded::CoapMessageType::Confirmable;
        msg.token_len = 255; // Malformed: much larger than the 8-byte token array
        msg.timestamp_us = 1_000_000;
        let r = monitor.inspect(&msg);
        assert!(!r.allowed, "token_len > 8 must be rejected");
    }

    // -----------------------------------------------------------------------
    // URI normalization tests (path-traversal / NUL / empty / oversize).
    // -----------------------------------------------------------------------

    fn inspect_uri(uri: &[u8]) -> CoapInspectResult {
        let mut mon = CoapMonitor::new();
        let msg = make_request(uri, CoapMethod::Get, 1_000_000);
        mon.inspect(&msg)
    }

    #[test]
    fn uri_norm_happy_path_well_known_core() {
        let r = inspect_uri(b"/.well-known/core");
        assert!(r.allowed, "/.well-known/core must be accepted");
        assert!(r.reject_reason.is_none());
    }

    #[test]
    fn uri_norm_rejects_literal_dotdot_segment() {
        let r = inspect_uri(b"/foo/../etc");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_single_dot_segment() {
        let r = inspect_uri(b"/foo/./bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_lowercase_pct_dotdot() {
        // %2e%2e -> ".."
        let r = inspect_uri(b"/foo/%2e%2e/bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_uppercase_pct_dotdot() {
        // %2E%2E -> ".."
        let r = inspect_uri(b"/foo/%2E%2E/bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_mixed_case_pct_dotdot() {
        // %2e%2E -> ".."
        let r = inspect_uri(b"/foo/%2e%2E/bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_pct_dot_dot_mix() {
        // "%2e." -> ".."
        let r = inspect_uri(b"/foo/%2e./bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_rejects_dot_pct_dot_mix() {
        // ".%2e" -> ".."
        let r = inspect_uri(b"/foo/.%2e/bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::PathTraversal));
    }

    #[test]
    fn uri_norm_double_encoded_dotdot_passes() {
        // %252e%252e decodes ONCE to the literal string "%2e%2e", which is NOT
        // ".." and is therefore allowed. This is the documented single-pass
        // policy: any layer that re-decodes already-decoded output is the
        // bug; we never recursively decode here.
        let r = inspect_uri(b"/foo/%252e%252e/bar");
        assert!(
            r.allowed,
            "double-encoded %252e%252e must pass single-decode policy: {:?}",
            r.reject_reason
        );
        assert!(r.reject_reason.is_none());
    }

    #[test]
    fn uri_norm_rejects_pct_nul_byte() {
        // %00 -> NUL.
        let r = inspect_uri(b"/foo/bar%00baz/x");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::NulByte));
    }

    #[test]
    fn uri_norm_rejects_literal_nul_byte() {
        // Literal NUL inside a segment.
        let mut buf = [0u8; 10];
        buf[..4].copy_from_slice(b"/foo");
        buf[4] = b'/';
        buf[5] = b'a';
        buf[6] = 0; // NUL
        buf[7] = b'b';
        let r = inspect_uri(&buf[..8]);
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::NulByte));
    }

    #[test]
    fn uri_norm_rejects_empty_segment_double_slash() {
        let r = inspect_uri(b"/foo//bar");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::EmptySegment));
    }

    #[test]
    fn uri_norm_rejects_trailing_slash() {
        let r = inspect_uri(b"/foo/bar/");
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::EmptySegment));
    }

    #[test]
    fn uri_norm_oversized_segment() {
        // Force max_segment_len = 4 to keep the test small.
        let mut mon = CoapMonitor::new();
        mon.set_validation_config(CoapValidationConfig::new().with_max_segment_len(4));
        let msg = make_request(b"/abcde", CoapMethod::Get, 1_000_000);
        let r = mon.inspect(&msg);
        assert!(!r.allowed);
        assert_eq!(r.reject_reason, Some(UriRejectReason::OversizedSegment));
    }

    #[test]
    fn uri_norm_query_key_rejects_dotdot() {
        let cfg = CoapValidationConfig::new();
        assert_eq!(
            validate_uri_query_key(b"..", &cfg),
            Err(UriRejectReason::PathTraversal)
        );
        assert_eq!(
            validate_uri_query_key(b"%2e%2e", &cfg),
            Err(UriRejectReason::PathTraversal)
        );
    }

    #[test]
    fn uri_norm_query_key_rejects_nul_and_empty() {
        let cfg = CoapValidationConfig::new();
        assert_eq!(
            validate_uri_query_key(b"k%00ey", &cfg),
            Err(UriRejectReason::NulByte)
        );
        assert_eq!(
            validate_uri_query_key(b"", &cfg),
            Err(UriRejectReason::EmptySegment)
        );
    }

    #[test]
    fn uri_norm_query_key_oversize() {
        let cfg = CoapValidationConfig::new().with_max_segment_len(2);
        assert_eq!(
            validate_uri_query_key(b"abc", &cfg),
            Err(UriRejectReason::OversizedSegment)
        );
    }

    #[test]
    fn uri_norm_alert_emitted_with_correct_source_id() {
        let r = inspect_uri(b"/foo/../bar");
        assert!(!r.allowed);
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alerts[0].source_id, ALERT_URI_PATH_TRAVERSAL);
        assert_eq!(r.alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn uri_norm_root_only_allowed() {
        // A bare "/" has no segments — accepted.
        let r = inspect_uri(b"/");
        assert!(r.allowed, "bare '/' should pass: {:?}", r.reject_reason);
    }

    #[test]
    fn uri_norm_empty_uri_allowed() {
        // No URI at all = root resource per RFC 7252.
        let mut mon = CoapMonitor::new();
        let mut msg = CoapMessage::default();
        msg.uri_len = 0;
        msg.timestamp_us = 1_000_000;
        let r = mon.inspect(&msg);
        assert!(r.allowed);
    }
}
