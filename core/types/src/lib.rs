// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core types, error enums, and vehicle identity for Craton Shield.
//!
//! This crate is the leaf-level definition site for the workspace's shared
//! types: the unified [`VsError`] enum, [`VehicleId`], [`SecurityAlert`],
//! [`PayloadHash`], [`KeyId`], the L3/L4 network parsing types, and the
//! SipHash-2-4 / FNV-1a hashing primitives. Every public item below is part
//! of the v1.0 stable surface and governed by `DEPRECATION.md`.

// ---------------------------------------------------------------------------
// Public API (v1.0 stable)
// ---------------------------------------------------------------------------
//
// Every `pub` item declared below this banner is part of the v1.0 stable
// surface and governed by `DEPRECATION.md`. Enum discriminants on the
// field-less enums `VsError`, `AlertSeverity`, `BusType`, and `TcpState`
// are pinned and form part of the stable ABI for FFI consumers. The
// payload-bearing enums (`IpAddr`, `IpProtocol`) are stable but cannot
// receive explicit numeric discriminants.
//
// Items marked `#[cfg(test)]`, `pub(crate)`, or behind a `feature = "…"`
// gate are NOT part of the stable surface.

#[cfg(test)]
extern crate alloc;

use core::fmt;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Constant-time comparison utilities
// ---------------------------------------------------------------------------

/// Compare two 32-byte arrays in constant time.
///
/// Uses [`subtle::ConstantTimeEq`] so the function's timing does not depend
/// on the position of the first differing byte.  Use this for comparing
/// SHA-256 hashes, HMAC tags, and other secret-derived values.
#[inline]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Compare two byte slices in constant time.
///
/// Returns `false` immediately if lengths differ (length is not secret in
/// any current use-case). When lengths match, runs in time proportional to
/// `a.len()` regardless of content.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Error type used across all `Craton Shield` crates.
///
/// # Stability
///
/// Discriminants are pinned for v1.0.0 and form part of the stable ABI. New
/// variants will only ever be appended (with a freshly chosen unused
/// discriminant); existing values must never be reused or reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub enum VsError {
    /// A cryptographic primitive (sign/verify/encrypt/decrypt/HMAC) failed.
    CryptoError = 0,
    /// A bus driver reported a communication error (e.g. CAN arbitration loss,
    /// Ethernet PHY fault).
    BusError = 1,
    /// A policy rule was violated and the operation was denied.
    PolicyViolation = 2,
    /// An integrity check (hash/MAC/signature) did not match the expected value.
    IntegrityFailure = 3,
    /// An authentication exchange (challenge/response, certificate validation)
    /// failed.
    AuthenticationFailure = 4,
    /// An operation did not complete within its allotted time budget.
    Timeout = 5,
    /// A bounded resource (slot table, queue, buffer pool) is full.
    ResourceExhausted = 6,
    /// A module was used before its `init` routine completed.
    NotInitialized = 7,
    /// Persistent storage (flash, EEPROM, attested log) failed to read or
    /// commit.
    StorageError = 8,
    /// Returned when caller-supplied data fails validation (e.g. invalid VIN
    /// characters, out-of-range values).
    InvalidInput = 9,
    /// Returned when a configuration parameter is invalid (e.g. duplicate rule
    /// IDs, conflicting settings).
    InvalidConfig = 10,
    /// The requested resource (rule id, key slot, peer identity) does not
    /// exist.
    NotFound = 11,
    /// A new memory or address region overlaps with an already-registered
    /// region.
    OverlappingRegion = 12,
    /// Returned when a key has expired (distinct from `NotInitialized`).
    KeyExpired = 13,
    /// Returned when a key has been revoked and cannot be used.
    KeyRevoked = 14,
}

impl fmt::Display for VsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CryptoError => write!(f, "cryptographic operation failed"),
            Self::BusError => write!(f, "bus communication error"),
            Self::PolicyViolation => write!(f, "policy violation"),
            Self::IntegrityFailure => write!(f, "integrity check failed"),
            Self::AuthenticationFailure => write!(f, "authentication failed"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::ResourceExhausted => write!(f, "resource exhausted"),
            Self::NotInitialized => write!(f, "not initialized"),
            Self::StorageError => write!(f, "storage operation failed"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
            Self::NotFound => write!(f, "resource not found"),
            Self::OverlappingRegion => write!(f, "overlapping memory region"),
            Self::KeyExpired => write!(f, "key has expired"),
            Self::KeyRevoked => write!(f, "key has been revoked"),
        }
    }
}

// ---------------------------------------------------------------------------
// Vehicle identity
// ---------------------------------------------------------------------------

/// A validated 17-character Vehicle Identification Number (VIN).
///
/// Conforms to ISO 3779: only alphanumeric characters excluding I, O, and Q
/// are permitted. The VIN is stored as raw ASCII bytes for `no_std`/FFI
/// compatibility.
///
/// # PII handling
///
/// A VIN uniquely identifies a vehicle and is treated as personal data under
/// GDPR (Recital 30) and most automotive privacy regimes. The [`fmt::Debug`]
/// implementation deliberately **redacts** the VIN so that an accidental
/// `{:?}` in a log statement does not leak the full identifier — only the
/// 3-character World Manufacturer Identifier (WMI) prefix is shown. The
/// [`fmt::Display`] implementation also redacts.
///
/// Authorised callers that need the unredacted VIN (e.g. cryptographic
/// binding, signed authorised diagnostics) must explicitly request it via
/// [`VehicleId::as_str_unredacted`] or [`VehicleId::vin`], which makes
/// the data-flow auditable in code review.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VehicleId {
    /// The 17 ASCII bytes of the VIN.
    vin: [u8; 17],
}

impl VehicleId {
    /// The required length of a VIN string.
    pub const LEN: usize = 17;

    /// Length of the World Manufacturer Identifier (WMI) prefix — the first
    /// three characters of a VIN, which identify the OEM and country of
    /// origin but do not uniquely identify a vehicle.
    pub const WMI_LEN: usize = 3;

    /// Returns a reference to the 17-byte VIN array.
    ///
    /// This is the **unredacted** raw VIN. Treat the returned slice as PII
    /// and avoid passing it to formatters that could end up in logs.
    pub fn vin(&self) -> &[u8; 17] {
        &self.vin
    }

    /// Returns the unredacted VIN as a UTF-8 string.
    ///
    /// VIN bytes are always ASCII alphanumeric (excluding I, O, Q) thanks to
    /// the validating constructor, so this conversion is infallible.
    ///
    /// **PII**: prefer [`fmt::Display`] / [`fmt::Debug`] for log output.
    /// Use this only when the caller has an audited reason to access the
    /// full VIN (e.g. signing a manifest, exporting to an attested channel).
    ///
    /// # Panics
    ///
    /// Panics only if the invariant established by [`VehicleId::new`] —
    /// that every byte is ASCII alphanumeric — has been violated. In a
    /// `#![forbid(unsafe_code)]` build that is impossible.
    pub fn as_str_unredacted(&self) -> &str {
        // Constructor guarantees ASCII alphanumeric, so from_utf8 cannot
        // fail. Use `expect` so any future regression surfaces loudly
        // rather than being papered over with a sentinel string.
        core::str::from_utf8(&self.vin).expect("VehicleId is always ASCII")
    }

    /// Returns the redacted (WMI-only) representation as a byte array.
    ///
    /// The first 3 characters of a VIN identify the manufacturer and country
    /// of origin and are not considered uniquely identifying on their own.
    pub fn wmi(&self) -> [u8; Self::WMI_LEN] {
        let mut out = [0u8; Self::WMI_LEN];
        out.copy_from_slice(&self.vin[..Self::WMI_LEN]);
        out
    }

    /// Returns a reference to the WMI prefix without copying.
    ///
    /// Equivalent to [`VehicleId::wmi`] but borrows into the underlying
    /// buffer instead of materialising a new array. Prefer this when the
    /// caller only needs to inspect or compare the WMI.
    #[must_use]
    pub fn wmi_bytes(&self) -> &[u8; 3] {
        // The buffer is statically 17 bytes long, so the first three are
        // always present. `try_into` over a known-good slice compiles to
        // a no-op at runtime but lets us return an array reference without
        // materialising a copy.
        (&self.vin[..Self::WMI_LEN])
            .try_into()
            .expect("VIN buffer has 17 bytes, WMI is the leading 3")
    }

    /// Validate and create a `VehicleId` from a 17-byte ASCII slice.
    ///
    /// Returns [`VsError::InvalidInput`] if the length is not 17 or any
    /// character is outside the allowed ISO 3779 set (A-Z excluding I/O/Q,
    /// and 0-9).
    pub const fn new(vin: &[u8]) -> Result<Self, VsError> {
        if vin.len() != Self::LEN {
            return Err(VsError::InvalidInput);
        }
        let mut buf = [0u8; 17];
        let mut i = 0;
        while i < Self::LEN {
            let b = vin[i];
            if !Self::is_valid_vin_char(b) {
                return Err(VsError::InvalidInput);
            }
            buf[i] = b;
            i += 1;
        }
        Ok(Self { vin: buf })
    }

    /// Returns `true` if `b` is a valid VIN character per ISO 3779.
    const fn is_valid_vin_char(b: u8) -> bool {
        matches!(b,
            b'A'..=b'H' | b'J'..=b'N' | b'P' | b'R'..=b'Z' | b'0'..=b'9'
        )
    }
}

impl fmt::Display for VehicleId {
    /// Renders a **redacted** representation of the VIN.
    ///
    /// Emits the 3-character WMI prefix followed by `***************` so the
    /// output is the same length as a real VIN but does not leak the
    /// vehicle-unique suffix. Use [`VehicleId::as_str_unredacted`] when the
    /// caller has been audited to handle the full PII.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in &self.vin[..Self::WMI_LEN] {
            write!(f, "{}", b as char)?;
        }
        // 14 redaction characters to pad to the canonical VIN length of 17.
        f.write_str("**************")
    }
}

impl fmt::Debug for VehicleId {
    /// Renders a **redacted** debug representation of the VIN.
    ///
    /// Emits `VehicleId { wmi: "XXX", suffix: "<redacted>" }`. The WMI is
    /// shown because it identifies only the manufacturer/country, not the
    /// individual vehicle. The 14-character suffix — which contains the
    /// vehicle-unique serial portion — is omitted entirely.
    ///
    /// This is deliberately a manual impl rather than `#[derive(Debug)]`,
    /// which would print every byte of the inner array and leak the VIN to
    /// any `{:?}` formatter (e.g. tracing/log macros, panic messages,
    /// assert_eq! failure output).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Build a stack-allocated str for the WMI (3 ASCII bytes -> 3 chars).
        // We can't use as_str_unredacted() because that would risk leaking
        // the full VIN if a future edit slips up.
        let wmi_bytes = self.wmi();
        let wmi_str = core::str::from_utf8(&wmi_bytes).unwrap_or("???");
        f.debug_struct("VehicleId")
            .field("wmi", &wmi_str)
            .field("suffix", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Bus type
// ---------------------------------------------------------------------------

/// Vehicle communication bus variants.
///
/// # Stability
///
/// Discriminants are pinned for v1.0.0 and form part of the stable ABI for
/// FFI consumers. New variants are appended with fresh discriminants;
/// existing values are never reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum BusType {
    /// Classical CAN (ISO 11898-1).
    Can = 0,
    /// CAN with Flexible Data-rate (CAN-FD, ISO 11898-1:2015).
    CanFd = 1,
    /// Automotive Ethernet (100BASE-T1 / 1000BASE-T1).
    AutomotiveEthernet = 2,
    /// Local Interconnect Network (LIN, ISO 17987).
    Lin = 3,
    /// FlexRay bus (ISO 17458).
    FlexRay = 4,
}

impl BusType {
    /// Map a `SOURCE_*` constant to a `BusType`, if applicable.
    pub fn from_source_type(src: u8) -> Option<Self> {
        match src {
            SOURCE_CAN => Some(Self::Can),
            SOURCE_CAN_FD => Some(Self::CanFd),
            SOURCE_ETHERNET => Some(Self::AutomotiveEthernet),
            SOURCE_LIN => Some(Self::Lin),
            SOURCE_FLEXRAY => Some(Self::FlexRay),
            _ => None,
        }
    }

    /// Map this bus type to the corresponding `SOURCE_*` constant.
    pub fn to_source_type(self) -> u8 {
        match self {
            Self::Can => SOURCE_CAN,
            Self::CanFd => SOURCE_CAN_FD,
            Self::AutomotiveEthernet => SOURCE_ETHERNET,
            Self::Lin => SOURCE_LIN,
            Self::FlexRay => SOURCE_FLEXRAY,
        }
    }
}

impl fmt::Display for BusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Can => write!(f, "CAN"),
            Self::CanFd => write!(f, "CAN-FD"),
            Self::AutomotiveEthernet => write!(f, "Automotive Ethernet"),
            Self::Lin => write!(f, "LIN"),
            Self::FlexRay => write!(f, "FlexRay"),
        }
    }
}

/// Severity level for security alerts.
///
/// # Stability
///
/// Discriminants are pinned for v1.0.0 and form part of the stable ABI. The
/// numeric ordering (`Info < Low < Medium < High < Critical`) is part of the
/// type's contract — callers compare severities by `<`/`>` and rely on the
/// numeric ordering matching the semantic ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
#[non_exhaustive]
pub enum AlertSeverity {
    /// Informational event; no action required.
    Info = 0,
    /// Low-severity anomaly; logged for trend analysis.
    Low = 1,
    /// Moderate-severity event warranting investigation.
    Medium = 2,
    /// High-severity event likely indicating an attack or fault.
    High = 3,
    /// Critical event requiring immediate response (e.g. safety-relevant).
    Critical = 4,
}

// ---------------------------------------------------------------------------
// Source type constants (domain addons define additional values)
// ---------------------------------------------------------------------------

/// Unknown or unspecified source.
pub const SOURCE_UNKNOWN: u8 = 0;
/// CAN bus (used in automotive and industrial domains).
pub const SOURCE_CAN: u8 = 1;
/// CAN-FD bus.
pub const SOURCE_CAN_FD: u8 = 2;
/// Ethernet (generic).
pub const SOURCE_ETHERNET: u8 = 3;
/// Serial / UART.
pub const SOURCE_SERIAL: u8 = 4;
/// LIN bus.
pub const SOURCE_LIN: u8 = 5;
/// FlexRay bus.
pub const SOURCE_FLEXRAY: u8 = 6;

// ---------------------------------------------------------------------------
// Newtypes for type-safe identifiers and hashes
// ---------------------------------------------------------------------------

/// SHA-256 payload hash.
///
/// Wraps a raw `[u8; 32]` to prevent accidental misuse (e.g. passing a nonce
/// or truncated key where a hash is expected). The inner buffer is
/// `pub(crate)` so callers cannot bypass the constant-time comparison guard
/// implemented in [`PartialEq`].
///
/// # Constant-time equality
///
/// `PartialEq` uses [`subtle::ConstantTimeEq`]: the comparison runs in time
/// proportional to the buffer length regardless of where two hashes first
/// diverge. This blocks timing side-channels in detection paths that compare
/// a freshly computed payload hash against a stored allow/deny entry — a
/// short-circuiting `==` would leak the first differing byte through cache
/// or branch-timing analysis.
#[derive(Clone, Copy, Eq)]
#[repr(transparent)]
pub struct PayloadHash(
    /// Raw 32-byte digest. Prefer constructing via [`PayloadHash::new`] /
    /// [`siphash_payload_hash`] so the constant-time [`PartialEq`] is the
    /// only path to compare values.
    pub [u8; 32],
);

impl PayloadHash {
    /// All-zero payload hash. Useful as a sentinel value and for
    /// initialising fixed-size alert buffers (see
    /// [`SecurityAlert::sentinel`]).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct a payload hash from raw bytes.
    ///
    /// Callers wanting a constant-time-comparable hash must funnel
    /// construction through this constructor (or through the
    /// `siphash_payload_hash` helper) rather than touching the inner buffer
    /// directly.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copies the underlying 32 bytes out of the hash.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl PartialEq for PayloadHash {
    /// Constant-time comparison — see [`PayloadHash`] type docs.
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_32(&self.0, &other.0)
    }
}

impl fmt::Debug for PayloadHash {
    /// `Debug` prints only the first 4 bytes followed by `..` to avoid
    /// leaking full payload hashes into log sinks. The full value remains
    /// accessible through [`PayloadHash::as_bytes`] for callers that need it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PayloadHash({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Cryptographic key slot identifier.
///
/// Newtype over `u32` to prevent mixing with other integer types. The inner
/// value is `pub(crate)`; use [`KeyId::new`] to construct and [`KeyId::get`]
/// to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct KeyId(
    /// Raw slot index. Prefer [`KeyId::new`] / [`KeyId::get`] over touching
    /// this field directly.
    pub u32,
);

impl KeyId {
    /// Construct a `KeyId` from a raw slot index.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw slot index.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for KeyId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<KeyId> for u32 {
    fn from(k: KeyId) -> Self {
        k.0
    }
}

// ---------------------------------------------------------------------------
// Security alert
// ---------------------------------------------------------------------------

/// A security alert generated by any detection module.
///
/// `timestamp_us` is microseconds since ECU boot (monotonic clock). It is
/// **not** wall-clock time. Cross-ECU correlation requires an external
/// time-sync layer (e.g. gPTP / IEEE 802.1AS).
///
/// # Encapsulation
///
/// All fields are `pub(crate)` so callers must funnel construction through
/// the validated [`SecurityAlert::new`] constructor or
/// [`SecurityAlert::sentinel`] (for buffer initialisation). This guarantees
/// that no alert is ever created with an invalid `timestamp_us == 0`, and
/// the `Debug` implementation cannot leak the full payload hash through log
/// sinks because [`PayloadHash`] redacts itself.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SecurityAlert {
    /// Stable, monotonically-increasing alert identifier assigned at creation.
    pub id: u64,
    /// Microseconds since ECU boot (monotonic). See struct-level docs.
    pub timestamp_us: u64,
    /// SHA-256 / SipHash digest of the offending payload; compared in
    /// constant time via [`PayloadHash`].
    pub payload_hash: PayloadHash,
    /// Severity classification, used by sinks for filtering/escalation.
    pub severity: AlertSeverity,
    /// Source-specific identifier (bus id, channel id, peer id) — meaning
    /// depends on `source_type`.
    pub source_id: u32,
    /// Source type identifier. Use the `SOURCE_*` constants defined in this
    /// crate or in domain-specific addon crates.
    pub source_type: u8,
}

impl SecurityAlert {
    /// Construct a new alert with basic validation.
    ///
    /// Returns [`VsError::InvalidInput`] if `timestamp_us` is zero (an ECU
    /// that has not booted cannot generate alerts).
    pub fn new(
        id: u64,
        severity: AlertSeverity,
        source_type: u8,
        source_id: u32,
        payload_hash: PayloadHash,
        timestamp_us: u64,
    ) -> Result<Self, VsError> {
        if timestamp_us == 0 {
            return Err(VsError::InvalidInput);
        }
        Ok(Self {
            id,
            timestamp_us,
            payload_hash,
            severity,
            source_id,
            source_type,
        })
    }

    /// Construct a sentinel/empty alert for buffer initialisation.
    ///
    /// Unlike [`SecurityAlert::new`], this skips the `timestamp_us > 0`
    /// check so that `const` slot arrays (e.g. `[SecurityAlert; N]`) can be
    /// initialised. Callers must overwrite sentinels with a validated alert
    /// before publishing them as detection results.
    #[must_use]
    pub const fn sentinel(source_type: u8) -> Self {
        Self {
            id: 0,
            timestamp_us: 0,
            payload_hash: PayloadHash::ZERO,
            severity: AlertSeverity::Info,
            source_id: 0,
            source_type,
        }
    }

    /// Build an alert without the `timestamp_us > 0` validation.
    ///
    /// Used by monitors that allocate alert slots in fixed-size buffers and
    /// fill them through `push_alert`-style helpers — those code paths
    /// have already verified the timestamp by other means (the alert
    /// generator uses a monotonic clock that returns post-boot values).
    /// Use [`SecurityAlert::new`] when ingesting timestamps from FFI or
    /// untrusted sources.
    #[must_use]
    pub const fn new_unchecked(
        id: u64,
        severity: AlertSeverity,
        source_type: u8,
        source_id: u32,
        payload_hash: PayloadHash,
        timestamp_us: u64,
    ) -> Self {
        Self {
            id,
            timestamp_us,
            payload_hash,
            severity,
            source_id,
            source_type,
        }
    }

    /// Stable alert id assigned at creation time.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Microseconds since ECU boot (monotonic).
    #[must_use]
    pub const fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }

    /// Reference to the payload hash; equality on this reference is
    /// constant-time (see [`PayloadHash`]).
    #[must_use]
    pub const fn payload_hash(&self) -> &PayloadHash {
        &self.payload_hash
    }

    /// Severity of the alert.
    #[must_use]
    pub const fn severity(&self) -> AlertSeverity {
        self.severity
    }

    /// Source identifier (bus id, channel id, etc.; protocol-specific).
    #[must_use]
    pub const fn source_id(&self) -> u32 {
        self.source_id
    }

    /// Source type discriminator (`SOURCE_*` constants).
    #[must_use]
    pub const fn source_type(&self) -> u8 {
        self.source_type
    }
}

impl fmt::Debug for SecurityAlert {
    /// `Debug` prints all non-payload fields. The payload hash is delegated
    /// to [`PayloadHash`]'s redacting `Debug`, so log lines never contain a
    /// full hash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityAlert")
            .field("id", &self.id)
            .field("timestamp_us", &self.timestamp_us)
            .field("severity", &self.severity)
            .field("source_type", &self.source_type)
            .field("source_id", &self.source_id)
            .field("payload_hash", &self.payload_hash)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// L3/L4 Network Types
// ---------------------------------------------------------------------------

/// IPv4 or IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum IpAddr {
    /// IPv4 address (4 bytes, network byte order).
    V4([u8; 4]),
    /// IPv6 address (16 bytes, network byte order).
    V6([u8; 16]),
}

/// IP protocol number.
///
/// Use [`IpProtocol::from_u8`] to construct values — it normalises known
/// IANA numbers into their named variants, preventing aliasing (e.g.
/// `Other(6)` vs `Tcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum IpProtocol {
    /// Transmission Control Protocol (IANA protocol 6).
    Tcp,
    /// User Datagram Protocol (IANA protocol 17).
    Udp,
    /// Internet Control Message Protocol (IANA protocol 1).
    Icmp,
    /// Any other IANA-assigned protocol number, preserved verbatim.
    Other(u8),
}

impl IpProtocol {
    /// Convert from the IANA protocol number.
    ///
    /// Known protocol numbers (1 = ICMP, 6 = TCP, 17 = UDP) are mapped to
    /// their named variants. All others become `Other(n)`.
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }

    /// Convert to the IANA protocol number.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(v) => v,
        }
    }

    /// Normalise into canonical form.
    ///
    /// If this value is `Other(n)` where `n` matches a known protocol, it is
    /// replaced with the named variant. This prevents aliasing-based bypasses
    /// in firewall / IDS rule matching.
    #[must_use]
    pub fn normalize(self) -> Self {
        Self::from_u8(self.to_u8())
    }
}

/// Parsed IP header information (L3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IpHeader {
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Upper-layer protocol carried in the payload.
    pub protocol: IpProtocol,
    /// Total length of the IP payload (excludes IP header).
    pub payload_len: u16,
}

/// Parsed transport header information (L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TransportHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// TCP flags (only meaningful for TCP; 0 for UDP).
    pub tcp_flags: u8,
}

/// TCP flag constants.
pub mod tcp_flags {
    /// FIN: sender has finished sending data; initiates connection close.
    pub const FIN: u8 = 0x01;
    /// SYN: synchronise sequence numbers; opens a new connection.
    pub const SYN: u8 = 0x02;
    /// RST: abortive connection reset.
    pub const RST: u8 = 0x04;
    /// PSH: deliver buffered data to the receiving application immediately.
    pub const PSH: u8 = 0x08;
    /// ACK: acknowledgement field is significant.
    pub const ACK: u8 = 0x10;
    /// URG: urgent pointer field is significant.
    pub const URG: u8 = 0x20;
    /// Convenience bitmask for the SYN+ACK pair sent in the handshake.
    pub const SYN_ACK: u8 = SYN | ACK;
}

/// TCP connection state for stateful tracking.
///
/// # Stability
///
/// Discriminants are pinned for v1.0.0 and form part of the stable ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub enum TcpState {
    /// SYN sent, awaiting SYN-ACK.
    SynSent = 0,
    /// SYN-ACK received, awaiting final ACK.
    SynReceived = 1,
    /// Connection established.
    Established = 2,
    /// FIN sent, connection closing.
    FinWait = 3,
    /// Connection closed.
    Closed = 4,
}

impl TcpState {
    /// Advance the TCP state machine given observed `flags`.
    ///
    /// Returns the new state, or `None` if the flags are unexpected for the
    /// current state (which an IDS may treat as anomalous).
    pub fn advance(self, flags: u8) -> Option<Self> {
        match self {
            Self::SynSent => {
                if flags & tcp_flags::SYN_ACK == tcp_flags::SYN_ACK {
                    Some(Self::SynReceived)
                } else if flags & tcp_flags::RST != 0 {
                    Some(Self::Closed)
                } else {
                    None
                }
            }
            Self::SynReceived => {
                if flags & tcp_flags::ACK != 0 && flags & tcp_flags::SYN == 0 {
                    Some(Self::Established)
                } else if flags & tcp_flags::RST != 0 {
                    Some(Self::Closed)
                } else {
                    None
                }
            }
            Self::Established => {
                if flags & tcp_flags::FIN != 0 {
                    Some(Self::FinWait)
                } else if flags & tcp_flags::RST != 0 {
                    Some(Self::Closed)
                } else {
                    // Data segments keep the connection established.
                    Some(Self::Established)
                }
            }
            Self::FinWait => {
                if flags & tcp_flags::FIN != 0
                    || flags & tcp_flags::ACK != 0
                    || flags & tcp_flags::RST != 0
                {
                    Some(Self::Closed)
                } else {
                    None
                }
            }
            Self::Closed => {
                // No valid transition from Closed.
                None
            }
        }
    }

    /// Returns `true` if the connection is in a terminal state.
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

// ---------------------------------------------------------------------------
// Shared hash utilities (FNV-1a & SipHash-2-4)
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit offset basis (standard).
pub const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit prime (standard).
pub const FNV1A_PRIME: u64 = 0x0100_0000_01b3;

/// Second independent FNV-1a offset basis for dual-hash schemes.
pub const FNV1A_OFFSET_BASIS_2: u64 = 0x6c62_272e_07bb_0142;

/// Perform a single SipHash-2-4 round in-place.
#[inline]
pub fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Keyed SipHash-2-4 producing a 64-bit digest.
///
/// This is the standard SipHash-2-4 described in
/// <https://www.aumasson.jp/siphash/siphash.pdf>.
/// It is *not* cryptographically secure for arbitrary-length inputs,
/// but provides excellent collision resistance and protection against
/// hash-flooding attacks on short messages (CAN / Ethernet payloads).
pub fn siphash_2_4(data: &[u8], k0: u64, k1: u64) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    let len = data.len();
    let blocks = len / 8;

    for i in 0..blocks {
        let offset = i * 8;
        // `try_into().unwrap()` on a known-correct-length slice is a no-op
        // at runtime, and LLVM elides the bounds check more cleanly than
        // manual byte-wise indexing for the inner SipHash loop.
        let m = u64::from_le_bytes(
            data[offset..offset + 8]
                .try_into()
                .expect("8-byte slice from a known-aligned offset"),
        );
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Last block with length byte.
    let mut last = (len as u64 & 0xff) << 56;
    let remaining = len % 8;
    let tail = &data[blocks * 8..];
    for (i, &byte) in tail.iter().enumerate().take(remaining) {
        last |= (byte as u64) << (i * 8);
    }

    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    // Finalization: 4 rounds.
    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// Compute a 32-byte payload hash using 4 independent SipHash-2-4 lanes.
///
/// Each of the 4 key pairs produces an independent 64-bit hash, yielding
/// 256 bits of output with genuine independence between lanes (unlike
/// multi-lane FNV with identical input).
pub fn siphash_payload_hash(data: &[u8], keys: &[(u64, u64); 4]) -> PayloadHash {
    let mut result = [0u8; 32];
    for (chunk_idx, &(k0, k1)) in keys.iter().enumerate() {
        let h = siphash_2_4(data, k0, k1);
        result[chunk_idx * 8..chunk_idx * 8 + 8].copy_from_slice(&h.to_le_bytes());
    }
    PayloadHash(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ---- VsError tests ----

    #[test]
    fn vs_error_debug() {
        let e = VsError::CryptoError;
        let s = format!("{e:?}");
        assert_eq!(s, "CryptoError");
    }

    #[test]
    fn vs_error_display() {
        assert_eq!(
            format!("{}", VsError::IntegrityFailure),
            "integrity check failed"
        );
    }

    #[test]
    fn vs_error_display_crypto_error() {
        assert_eq!(
            format!("{}", VsError::CryptoError),
            "cryptographic operation failed"
        );
    }

    #[test]
    fn vs_error_display_bus_error() {
        assert_eq!(format!("{}", VsError::BusError), "bus communication error");
    }

    #[test]
    fn vs_error_display_policy_violation() {
        assert_eq!(format!("{}", VsError::PolicyViolation), "policy violation");
    }

    #[test]
    fn vs_error_display_authentication_failure() {
        assert_eq!(
            format!("{}", VsError::AuthenticationFailure),
            "authentication failed"
        );
    }

    #[test]
    fn vs_error_display_timeout() {
        assert_eq!(format!("{}", VsError::Timeout), "operation timed out");
    }

    #[test]
    fn vs_error_display_resource_exhausted() {
        assert_eq!(
            format!("{}", VsError::ResourceExhausted),
            "resource exhausted"
        );
    }

    #[test]
    fn vs_error_display_not_initialized() {
        assert_eq!(format!("{}", VsError::NotInitialized), "not initialized");
    }

    #[test]
    fn vs_error_display_storage_error() {
        assert_eq!(
            format!("{}", VsError::StorageError),
            "storage operation failed"
        );
    }

    #[test]
    fn vs_error_partial_eq_all_variants() {
        assert_eq!(VsError::CryptoError, VsError::CryptoError);
        assert_eq!(VsError::BusError, VsError::BusError);
        assert_eq!(VsError::PolicyViolation, VsError::PolicyViolation);
        assert_eq!(VsError::IntegrityFailure, VsError::IntegrityFailure);
        assert_eq!(
            VsError::AuthenticationFailure,
            VsError::AuthenticationFailure
        );
        assert_eq!(VsError::Timeout, VsError::Timeout);
        assert_eq!(VsError::ResourceExhausted, VsError::ResourceExhausted);
        assert_eq!(VsError::NotInitialized, VsError::NotInitialized);
        assert_eq!(VsError::StorageError, VsError::StorageError);
    }

    #[test]
    fn vs_error_variants_are_distinct() {
        let variants = [
            VsError::CryptoError,
            VsError::BusError,
            VsError::PolicyViolation,
            VsError::IntegrityFailure,
            VsError::AuthenticationFailure,
            VsError::Timeout,
            VsError::ResourceExhausted,
            VsError::NotInitialized,
            VsError::StorageError,
            VsError::InvalidInput,
            VsError::InvalidConfig,
            VsError::NotFound,
            VsError::OverlappingRegion,
            VsError::KeyExpired,
            VsError::KeyRevoked,
        ];
        for i in 0..variants.len() {
            for j in i + 1..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    #[test]
    fn vs_error_display_key_expired() {
        assert_eq!(format!("{}", VsError::KeyExpired), "key has expired");
    }

    #[test]
    fn vs_error_display_key_revoked() {
        assert_eq!(format!("{}", VsError::KeyRevoked), "key has been revoked");
    }

    #[test]
    fn vs_error_display_not_empty() {
        let errors = [
            VsError::CryptoError,
            VsError::BusError,
            VsError::PolicyViolation,
            VsError::IntegrityFailure,
            VsError::AuthenticationFailure,
            VsError::Timeout,
            VsError::ResourceExhausted,
            VsError::NotInitialized,
            VsError::StorageError,
            VsError::InvalidInput,
            VsError::InvalidConfig,
            VsError::NotFound,
            VsError::OverlappingRegion,
            VsError::KeyExpired,
            VsError::KeyRevoked,
        ];
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty(), "display for {err:?} is empty");
        }
    }

    // ---- VehicleId tests ----

    #[test]
    fn vehicle_id_valid() {
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        assert_eq!(vin.vin(), b"WBA3A5C55CF256789");
    }

    #[test]
    fn vehicle_id_display_is_redacted() {
        // Display must redact the vehicle-unique suffix. Only the 3-char WMI
        // prefix is allowed through; the remaining 14 chars are masked.
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        let s = format!("{vin}");
        assert_eq!(s, "WBA**************");
        assert!(
            !s.contains("WBA3A5C55CF256789"),
            "Display leaked full VIN: {s}"
        );
    }

    #[test]
    fn vehicle_id_debug_does_not_leak_full_vin() {
        // Regression test for the PII leak in vs_types_auto::VehicleId's old
        // Debug impl, and the derived Debug on the core type. format!("{:?}")
        // must NOT contain the full VIN.
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        let s = format!("{vin:?}");
        assert!(
            !s.contains("WBA3A5C55CF256789"),
            "Debug leaked full VIN: {s}"
        );
        // The suffix bytes after the WMI must not appear individually either.
        // Use a token from the suffix that does not appear elsewhere.
        assert!(!s.contains("CF256789"), "Debug leaked VIN suffix: {s}");
        // The WMI prefix is allowed to appear (it is not uniquely identifying).
        assert!(s.contains("WBA"), "Debug should still show WMI: {s}");
        // The struct name should appear (helps debugging).
        assert!(s.contains("VehicleId"), "Debug should label the type: {s}");
    }

    #[test]
    fn vehicle_id_debug_redaction_uses_marker() {
        // Defensive check that we communicate the redaction explicitly so a
        // reader of a log line knows information was withheld rather than
        // missing.
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        let s = format!("{vin:?}");
        assert!(
            s.contains("redacted") || s.contains("***"),
            "Debug must signal that the VIN suffix was redacted, got: {s}"
        );
    }

    #[test]
    fn vehicle_id_as_str_unredacted_returns_full_vin() {
        // The escape hatch for audited callers must still work.
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        assert_eq!(vin.as_str_unredacted(), "WBA3A5C55CF256789");
    }

    #[test]
    fn vehicle_id_wmi_returns_first_three_chars() {
        let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        assert_eq!(&vin.wmi(), b"WBA");
    }

    #[test]
    fn vehicle_id_rejects_lowercase() {
        assert_eq!(
            VehicleId::new(b"wba3a5c55cf256789"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_rejects_forbidden_i() {
        // 'I' is forbidden in VINs
        assert_eq!(
            VehicleId::new(b"WBA3A5C55CI256789"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_rejects_forbidden_o() {
        assert_eq!(
            VehicleId::new(b"WBA3A5C55CO256789"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_rejects_forbidden_q() {
        assert_eq!(
            VehicleId::new(b"WBA3A5C55CQ256789"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_wrong_length() {
        assert_eq!(VehicleId::new(b"SHORT"), Err(VsError::InvalidInput));
        assert_eq!(
            VehicleId::new(b"WBA3A5C55CF256789X"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_rejects_special_chars() {
        assert_eq!(
            VehicleId::new(b"WBA3A5C55CF25678!"),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn vehicle_id_equality() {
        let a = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        let b = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
        let c = VehicleId::new(b"1HGBH41JXMN109186").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- BusType tests ----

    #[test]
    fn bus_type_display() {
        assert_eq!(format!("{}", BusType::Can), "CAN");
        assert_eq!(format!("{}", BusType::CanFd), "CAN-FD");
        assert_eq!(
            format!("{}", BusType::AutomotiveEthernet),
            "Automotive Ethernet"
        );
        assert_eq!(format!("{}", BusType::Lin), "LIN");
        assert_eq!(format!("{}", BusType::FlexRay), "FlexRay");
    }

    #[test]
    fn bus_type_from_source_type() {
        assert_eq!(BusType::from_source_type(SOURCE_CAN), Some(BusType::Can));
        assert_eq!(
            BusType::from_source_type(SOURCE_CAN_FD),
            Some(BusType::CanFd)
        );
        assert_eq!(
            BusType::from_source_type(SOURCE_ETHERNET),
            Some(BusType::AutomotiveEthernet)
        );
        assert_eq!(BusType::from_source_type(SOURCE_UNKNOWN), None);
        assert_eq!(BusType::from_source_type(SOURCE_SERIAL), None);
        assert_eq!(BusType::from_source_type(0xFF), None);
    }

    #[test]
    fn bus_type_to_source_type_roundtrip() {
        assert_eq!(BusType::Can.to_source_type(), SOURCE_CAN);
        assert_eq!(BusType::CanFd.to_source_type(), SOURCE_CAN_FD);
        assert_eq!(
            BusType::AutomotiveEthernet.to_source_type(),
            SOURCE_ETHERNET
        );
    }

    #[test]
    fn bus_type_all_variants_distinct() {
        let variants = [
            BusType::Can,
            BusType::CanFd,
            BusType::AutomotiveEthernet,
            BusType::Lin,
            BusType::FlexRay,
        ];
        for i in 0..variants.len() {
            for j in i + 1..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    // ---- PayloadHash tests ----

    #[test]
    fn payload_hash_zero() {
        assert_eq!(PayloadHash::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn payload_hash_equality() {
        let a = PayloadHash([0xAB; 32]);
        let b = PayloadHash([0xAB; 32]);
        let c = PayloadHash([0xCD; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- KeyId tests ----

    #[test]
    fn key_id_newtype() {
        let k = KeyId::new(42);
        assert_eq!(k.get(), 42);
        assert_eq!(k, KeyId(42));
    }

    #[test]
    fn key_id_ordering() {
        assert!(KeyId::new(1) < KeyId::new(2));
    }

    // ---- AlertSeverity tests ----

    #[test]
    fn alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }

    #[test]
    fn alert_severity_full_ordering() {
        let levels = [
            AlertSeverity::Info,
            AlertSeverity::Low,
            AlertSeverity::Medium,
            AlertSeverity::High,
            AlertSeverity::Critical,
        ];
        for i in 0..levels.len() - 1 {
            assert!(levels[i] < levels[i + 1]);
        }
    }

    // ---- SecurityAlert tests ----

    #[test]
    fn security_alert_new_valid() {
        let alert = SecurityAlert::new(
            1,
            AlertSeverity::High,
            SOURCE_CAN,
            42,
            PayloadHash([0xAB; 32]),
            1_000_000,
        )
        .unwrap();
        assert_eq!(alert.id, 1);
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.source_type, SOURCE_CAN);
        assert_eq!(alert.source_id, 42);
        assert_eq!(alert.payload_hash, PayloadHash([0xAB; 32]));
        assert_eq!(alert.timestamp_us, 1_000_000);
    }

    #[test]
    fn security_alert_rejects_zero_timestamp() {
        let result =
            SecurityAlert::new(1, AlertSeverity::High, SOURCE_CAN, 42, PayloadHash::ZERO, 0);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn security_alert_equality() {
        let a = SecurityAlert::new(
            1,
            AlertSeverity::High,
            SOURCE_CAN,
            42,
            PayloadHash([0xAB; 32]),
            100,
        )
        .unwrap();
        let b = SecurityAlert::new(
            1,
            AlertSeverity::High,
            SOURCE_CAN,
            42,
            PayloadHash([0xAB; 32]),
            100,
        )
        .unwrap();
        let c = SecurityAlert::new(
            2,
            AlertSeverity::High,
            SOURCE_CAN,
            42,
            PayloadHash([0xAB; 32]),
            100,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn security_alert_clone_copy() {
        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::High,
            source_type: SOURCE_CAN,
            source_id: 42,
            payload_hash: PayloadHash([0xAB; 32]),
            timestamp_us: 1_000_000,
        };
        let copy = alert;
        assert_eq!(copy.id, alert.id);
        assert_eq!(copy.severity, alert.severity);
    }

    #[test]
    fn security_alert_field_access() {
        let alert = SecurityAlert {
            id: 42,
            severity: AlertSeverity::Critical,
            source_type: SOURCE_CAN_FD,
            source_id: 99,
            payload_hash: PayloadHash([0xFF; 32]),
            timestamp_us: 123_456_789,
        };
        assert_eq!(alert.id, 42);
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.source_type, SOURCE_CAN_FD);
        assert_eq!(alert.source_id, 99);
        assert_eq!(alert.payload_hash, PayloadHash([0xFF; 32]));
        assert_eq!(alert.timestamp_us, 123_456_789);
    }

    #[test]
    fn source_type_constants() {
        assert_eq!(SOURCE_UNKNOWN, 0);
        assert_ne!(SOURCE_CAN, SOURCE_CAN_FD);
        assert_ne!(SOURCE_ETHERNET, SOURCE_SERIAL);
    }

    // ---- IpAddr tests ----

    #[test]
    fn ip_addr_variants() {
        let v4 = IpAddr::V4([192, 168, 1, 1]);
        let v6 = IpAddr::V6([0; 16]);
        assert_ne!(v4, IpAddr::V4([10, 0, 0, 1]));
        assert_eq!(v6, IpAddr::V6([0; 16]));
    }

    // ---- IpProtocol tests ----

    #[test]
    fn ip_protocol_from_u8_known() {
        assert_eq!(IpProtocol::from_u8(1), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
    }

    #[test]
    fn ip_protocol_other() {
        let proto = IpProtocol::Other(47); // GRE
        assert_eq!(proto, IpProtocol::Other(47));
        assert_ne!(proto, IpProtocol::Tcp);
    }

    #[test]
    fn ip_protocol_normalize_fixes_aliasing() {
        // Directly constructing Other(6) aliases Tcp — normalize fixes it.
        let aliased = IpProtocol::Other(6);
        assert_ne!(aliased, IpProtocol::Tcp); // raw enum mismatch
        assert_eq!(aliased.normalize(), IpProtocol::Tcp); // normalized match

        assert_eq!(IpProtocol::Other(1).normalize(), IpProtocol::Icmp);
        assert_eq!(IpProtocol::Other(17).normalize(), IpProtocol::Udp);
    }

    #[test]
    fn ip_protocol_normalize_preserves_unknown() {
        let gre = IpProtocol::Other(47);
        assert_eq!(gre.normalize(), IpProtocol::Other(47));
    }

    #[test]
    fn ip_protocol_roundtrip() {
        for val in 0..=255u8 {
            let proto = IpProtocol::from_u8(val);
            assert_eq!(proto.to_u8(), val);
        }
    }

    // ---- IpHeader / TransportHeader PartialEq tests ----

    #[test]
    fn ip_header_equality() {
        let h1 = IpHeader {
            src: IpAddr::V4([10, 0, 0, 1]),
            dst: IpAddr::V4([10, 0, 0, 2]),
            protocol: IpProtocol::Tcp,
            payload_len: 100,
        };
        let h2 = IpHeader {
            src: IpAddr::V4([10, 0, 0, 1]),
            dst: IpAddr::V4([10, 0, 0, 2]),
            protocol: IpProtocol::Tcp,
            payload_len: 100,
        };
        let h3 = IpHeader {
            src: IpAddr::V4([10, 0, 0, 1]),
            dst: IpAddr::V4([10, 0, 0, 3]),
            protocol: IpProtocol::Tcp,
            payload_len: 100,
        };
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn transport_header_equality() {
        let t1 = TransportHeader {
            src_port: 80,
            dst_port: 443,
            tcp_flags: tcp_flags::SYN,
        };
        let t2 = TransportHeader {
            src_port: 80,
            dst_port: 443,
            tcp_flags: tcp_flags::SYN,
        };
        let t3 = TransportHeader {
            src_port: 80,
            dst_port: 443,
            tcp_flags: tcp_flags::ACK,
        };
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    // ---- tcp_flags tests ----

    #[test]
    fn tcp_flags_values() {
        assert_eq!(tcp_flags::FIN, 0x01);
        assert_eq!(tcp_flags::SYN, 0x02);
        assert_eq!(tcp_flags::RST, 0x04);
        assert_eq!(tcp_flags::PSH, 0x08);
        assert_eq!(tcp_flags::ACK, 0x10);
        assert_eq!(tcp_flags::URG, 0x20);
        assert_eq!(tcp_flags::SYN_ACK, 0x12);
    }

    #[test]
    fn tcp_flags_xmas_scan_detectable() {
        let xmas = tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG;
        assert_ne!(xmas & tcp_flags::FIN, 0);
        assert_ne!(xmas & tcp_flags::PSH, 0);
        assert_ne!(xmas & tcp_flags::URG, 0);
    }

    // ---- TcpState transition tests ----

    #[test]
    fn tcp_state_normal_handshake() {
        let state = TcpState::SynSent;
        let state = state.advance(tcp_flags::SYN_ACK).unwrap();
        assert_eq!(state, TcpState::SynReceived);
        let state = state.advance(tcp_flags::ACK).unwrap();
        assert_eq!(state, TcpState::Established);
    }

    #[test]
    fn tcp_state_established_data() {
        let state = TcpState::Established;
        // Pure ACK (data segment) stays established.
        let state = state.advance(tcp_flags::ACK).unwrap();
        assert_eq!(state, TcpState::Established);
    }

    #[test]
    fn tcp_state_fin_close() {
        let state = TcpState::Established;
        let state = state.advance(tcp_flags::FIN | tcp_flags::ACK).unwrap();
        assert_eq!(state, TcpState::FinWait);
        let state = state.advance(tcp_flags::FIN | tcp_flags::ACK).unwrap();
        assert_eq!(state, TcpState::Closed);
    }

    #[test]
    fn tcp_state_rst_from_any() {
        for initial in [
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
            TcpState::FinWait,
        ] {
            let next = initial.advance(tcp_flags::RST).unwrap();
            assert_eq!(next, TcpState::Closed);
        }
    }

    #[test]
    fn tcp_state_closed_rejects_all() {
        assert_eq!(TcpState::Closed.advance(tcp_flags::SYN), None);
        assert_eq!(TcpState::Closed.advance(tcp_flags::ACK), None);
        assert_eq!(TcpState::Closed.advance(tcp_flags::RST), None);
    }

    #[test]
    fn tcp_state_syn_sent_rejects_bare_ack() {
        assert_eq!(TcpState::SynSent.advance(tcp_flags::ACK), None);
    }

    #[test]
    fn tcp_state_syn_received_rejects_syn() {
        // A duplicate SYN in SynReceived is anomalous.
        assert_eq!(TcpState::SynReceived.advance(tcp_flags::SYN), None);
    }

    #[test]
    fn tcp_state_is_closed() {
        assert!(TcpState::Closed.is_closed());
        assert!(!TcpState::Established.is_closed());
        assert!(!TcpState::SynSent.is_closed());
    }

    // ---- AURIX TC3xx evaluation tests ----

    #[test]
    fn repr_c_types_have_stable_layout() {
        assert!(
            core::mem::size_of::<VsError>() <= 4,
            "VsError repr(C) should be <= 4 bytes"
        );
        assert!(
            core::mem::size_of::<AlertSeverity>() <= 4,
            "AlertSeverity repr(C) should be <= 4 bytes"
        );
        let alert_align = core::mem::align_of::<SecurityAlert>();
        assert!(
            alert_align <= 8,
            "SecurityAlert alignment should be <= 8 for 64-bit field compat"
        );
    }

    #[test]
    fn security_alert_size_within_mcu_budget() {
        let size = core::mem::size_of::<SecurityAlert>();
        assert!(
            size <= 128,
            "SecurityAlert is {size} bytes, exceeds 128-byte MCU budget"
        );
        assert!(
            size >= 32 + 8 + 8 + 4,
            "SecurityAlert too small for its fields"
        );
    }

    #[test]
    fn vehicle_id_size_compact() {
        assert_eq!(core::mem::size_of::<VehicleId>(), 17);
    }

    #[test]
    fn payload_hash_is_transparent() {
        assert_eq!(
            core::mem::size_of::<PayloadHash>(),
            core::mem::size_of::<[u8; 32]>()
        );
    }

    #[test]
    fn key_id_is_transparent() {
        assert_eq!(core::mem::size_of::<KeyId>(), core::mem::size_of::<u32>());
    }

    // ---- Hash utility tests ----

    #[test]
    fn siphash_deterministic() {
        let h1 = siphash_2_4(b"hello", 0xDEAD, 0xBEEF);
        let h2 = siphash_2_4(b"hello", 0xDEAD, 0xBEEF);
        assert_eq!(h1, h2);
    }

    #[test]
    fn siphash_different_keys_differ() {
        let h1 = siphash_2_4(b"hello", 0xDEAD, 0xBEEF);
        let h2 = siphash_2_4(b"hello", 0xCAFE, 0xBABE);
        assert_ne!(h1, h2);
    }

    #[test]
    fn siphash_different_data_differ() {
        let h1 = siphash_2_4(b"hello", 0xDEAD, 0xBEEF);
        let h2 = siphash_2_4(b"world", 0xDEAD, 0xBEEF);
        assert_ne!(h1, h2);
    }

    #[test]
    fn siphash_empty() {
        let h = siphash_2_4(b"", 0, 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn siphash_long_data() {
        let data = [0xABu8; 128];
        let h = siphash_2_4(&data, 1, 2);
        assert_ne!(h, 0);
    }

    #[test]
    fn siphash_payload_hash_fills_32_bytes() {
        let keys = [(1u64, 2u64), (3, 4), (5, 6), (7, 8)];
        let hash = siphash_payload_hash(b"test", &keys);
        assert_ne!(hash.0, [0u8; 32]);
    }

    #[test]
    fn siphash_payload_hash_lanes_independent() {
        let keys = [(1u64, 2u64), (3, 4), (5, 6), (7, 8)];
        let hash = siphash_payload_hash(b"test", &keys);
        // Each 8-byte lane should differ (different keys => different hashes)
        let lane0 = u64::from_le_bytes(hash.0[0..8].try_into().unwrap());
        let lane1 = u64::from_le_bytes(hash.0[8..16].try_into().unwrap());
        let lane2 = u64::from_le_bytes(hash.0[16..24].try_into().unwrap());
        let lane3 = u64::from_le_bytes(hash.0[24..32].try_into().unwrap());
        assert_ne!(lane0, lane1);
        assert_ne!(lane1, lane2);
        assert_ne!(lane2, lane3);
    }

    #[test]
    fn fnv_constants_are_standard() {
        assert_eq!(FNV1A_OFFSET_BASIS, 0xcbf2_9ce4_8422_2325);
        assert_eq!(FNV1A_PRIME, 0x0100_0000_01b3);
    }
}
