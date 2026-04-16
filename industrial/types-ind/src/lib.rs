#![no_std]
#![deny(missing_docs)]

//! Industrial automation type extensions for `Craton Shield`.
//!
//! Provides domain-specific types for IEC 62443 / IEC 61508 environments:
//! Modbus RTU/TCP, OPC UA, and PROFINET.
//!
//! Source-type constants cover additional protocol monitors
//! (EtherNet/IP, DNP3, `BACnet`, S7comm, IEC 60870-5-104, IEC 61850)
//! which are all implemented.

// ---------------------------------------------------------------------------
// Public API (v1.0 stable)
// ---------------------------------------------------------------------------
//
// Every `pub` item below is part of the v1.0 stable surface and governed
// by `DEPRECATION.md`. `SecurityLevel`, `ModbusFunctionCode`,
// `OpcUaMessageType`, `OpcUaSecurityMode`, `ProfinetFrameType`, and
// `AlertCode` discriminants are pinned and form part of the stable ABI
// for industrial FFI consumers.

pub use vs_types;

// ---------------------------------------------------------------------------
// Source-type constants (range 30–49 reserved for industrial)
// ---------------------------------------------------------------------------

/// Modbus RTU (serial) traffic.
pub const SOURCE_MODBUS_RTU: u8 = 30;

/// Modbus TCP traffic.
pub const SOURCE_MODBUS_TCP: u8 = 31;

/// OPC UA (OPC Unified Architecture) traffic.
pub const SOURCE_OPCUA: u8 = 32;

/// PROFINET IO traffic.
pub const SOURCE_PROFINET: u8 = 33;

/// EtherNet/IP (CIP over Ethernet) traffic.
pub const SOURCE_ETHERNETIP: u8 = 34;

/// DNP3 (Distributed Network Protocol) traffic.
pub const SOURCE_DNP3: u8 = 35;

/// `BACnet` (Building Automation and Control) traffic.
pub const SOURCE_BACNET: u8 = 36;

/// HTTP-based industrial protocol traffic (e.g., REST/MQTT gateways).
pub const SOURCE_HTTP: u8 = 37;

/// S7comm (Siemens S7 Communication) traffic.
pub const SOURCE_S7COMM: u8 = 38;

/// IEC 60870-5-104 traffic.
pub const SOURCE_IEC60870: u8 = 39;

/// IEC 61850 MMS (Manufacturing Message Specification) traffic.
pub const SOURCE_IEC61850_MMS: u8 = 40;

/// IEC 61850 GOOSE (Generic Object Oriented Substation Event) traffic.
pub const SOURCE_IEC61850_GOOSE: u8 = 41;

/// IEC 61850-9-2 Sampled Values (SV) traffic.
pub const SOURCE_IEC61850_SV: u8 = 42;

// ---------------------------------------------------------------------------
// IEC 62443 Zone / Conduit model
// ---------------------------------------------------------------------------

/// Maximum number of security zones.
pub const MAX_ZONES: usize = 16;

/// Maximum number of conduits between zones.
pub const MAX_CONDUITS: usize = 32;

/// IEC 62443 security level (SL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SecurityLevel {
    /// SL 0: No specific requirements.
    Sl0 = 0,
    /// SL 1: Protection against casual or coincidental violation.
    Sl1 = 1,
    /// SL 2: Protection against intentional violation using simple means.
    Sl2 = 2,
    /// SL 3: Protection against sophisticated attack with moderate resources.
    Sl3 = 3,
    /// SL 4: Protection against state-sponsored attack with extensive resources.
    Sl4 = 4,
}

/// An IEC 62443 security zone.
#[derive(Debug, Clone, Copy)]
pub struct Zone {
    /// Zone identifier (0-based).
    pub id: u8,
    /// Target security level for this zone.
    pub target_sl: SecurityLevel,
    /// Achieved (current) security level.
    pub achieved_sl: SecurityLevel,
    /// Whether this zone is active.
    pub active: bool,
}

impl Zone {
    /// Create an empty zone slot.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            target_sl: SecurityLevel::Sl0,
            achieved_sl: SecurityLevel::Sl0,
            active: false,
        }
    }

    /// Check if the zone meets its target security level.
    pub fn meets_target(&self) -> bool {
        self.achieved_sl >= self.target_sl
    }
}

/// A conduit between two security zones.
#[derive(Debug, Clone, Copy)]
pub struct Conduit {
    /// Source zone ID.
    pub from_zone: u8,
    /// Destination zone ID.
    pub to_zone: u8,
    /// Allowed protocols on this conduit (bitmask, see `PROTO_*` constants).
    pub allowed_protocols: u16,
    /// Whether this conduit is active.
    pub active: bool,
}

impl Conduit {
    /// Create an empty conduit slot (inactive, no protocols allowed).
    pub const fn empty() -> Self {
        Self {
            from_zone: 0,
            to_zone: 0,
            allowed_protocols: 0,
            active: false,
        }
    }
}

/// Maximum number of alerts a single inspection can produce.
pub const MAX_ALERTS_PER_RESULT: usize = 4;

/// Protocol bitmask flags for conduit filtering.
///
/// Uses `u16` to support up to 16 protocol flags without overflow.
pub const PROTO_MODBUS_TCP: u16 = 1 << 0;
/// Modbus RTU (serial) protocol over conduits.
pub const PROTO_MODBUS_RTU: u16 = 1 << 1;
/// OPC UA protocol over conduits.
pub const PROTO_OPCUA: u16 = 1 << 2;
/// PROFINET IO protocol over conduits.
pub const PROTO_PROFINET: u16 = 1 << 3;
/// EtherNet/IP (CIP over Ethernet) protocol over conduits.
pub const PROTO_ETHERNETIP: u16 = 1 << 4;
/// DNP3 (Distributed Network Protocol) protocol over conduits.
pub const PROTO_DNP3: u16 = 1 << 5;
/// HTTP-based protocols over conduits.
pub const PROTO_HTTP: u16 = 1 << 6;
/// `BACnet` protocol over conduits.
pub const PROTO_BACNET: u16 = 1 << 7;
/// S7comm (Siemens S7 Communication) protocol over conduits.
pub const PROTO_S7COMM: u16 = 1 << 8;
/// IEC 60870-5-104 protocol over conduits.
pub const PROTO_IEC60870: u16 = 1 << 9;
/// IEC 61850 (MMS + GOOSE) protocol over conduits.
pub const PROTO_IEC61850: u16 = 1 << 10;

// ---------------------------------------------------------------------------
// Modbus types
// ---------------------------------------------------------------------------

/// Modbus function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModbusFunctionCode {
    /// Read coils (FC 01).
    ReadCoils = 0x01,
    /// Read discrete inputs (FC 02).
    ReadDiscreteInputs = 0x02,
    /// Read holding registers (FC 03).
    ReadHoldingRegisters = 0x03,
    /// Read input registers (FC 04).
    ReadInputRegisters = 0x04,
    /// Write single coil (FC 05).
    WriteSingleCoil = 0x05,
    /// Write single register (FC 06).
    WriteSingleRegister = 0x06,
    /// Write multiple coils (FC 15 / 0x0F).
    WriteMultipleCoils = 0x0F,
    /// Write multiple registers (FC 16 / 0x10).
    WriteMultipleRegisters = 0x10,
    /// Read/Write multiple registers (FC 23 / 0x17).
    ReadWriteMultipleRegisters = 0x17,
    /// Diagnostics (FC 08) — includes sub-functions like Restart
    /// Communications, Force Listen Only, etc.
    Diagnostics = 0x08,
    /// Unknown / custom function code.
    Unknown = 0xFF,
}

impl ModbusFunctionCode {
    /// Parse a raw function code byte.
    pub fn from_u8(code: u8) -> Self {
        match code {
            0x01 => Self::ReadCoils,
            0x02 => Self::ReadDiscreteInputs,
            0x03 => Self::ReadHoldingRegisters,
            0x04 => Self::ReadInputRegisters,
            0x05 => Self::WriteSingleCoil,
            0x06 => Self::WriteSingleRegister,
            0x0F => Self::WriteMultipleCoils,
            0x10 => Self::WriteMultipleRegisters,
            0x17 => Self::ReadWriteMultipleRegisters,
            0x08 => Self::Diagnostics,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this function code writes data.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Self::WriteSingleCoil
                | Self::WriteSingleRegister
                | Self::WriteMultipleCoils
                | Self::WriteMultipleRegisters
                | Self::ReadWriteMultipleRegisters
        )
    }

    /// Returns `true` if this function code is a diagnostic/management command.
    pub fn is_diagnostic(&self) -> bool {
        matches!(self, Self::Diagnostics)
    }
}

/// Maximum Modbus PDU payload size for inspection.
pub const MAX_MODBUS_PDU_LEN: usize = 253;

/// A Modbus TCP frame (MBAP header + PDU).
///
/// `#[repr(C)]` pins the field layout because the frame is forwarded across
/// the C FFI boundary in the integration shim. Reordering or repacking would
/// break the ABI contract. Every field is either a fixed-width integer, a
/// byte array, or a `#[repr(u8)]` enum, so the layout is genuinely stable.
///
/// # Encapsulation
///
/// The PDU buffer (`pdu_data`) and its declared length (`pdu_len`) are
/// `pub(crate)` rather than fully `pub`. Demoting them prevents callers from
/// desyncing the invariant `pdu_len as usize <= MAX_MODBUS_PDU_LEN` by
/// writing one and forgetting the other. Use:
///
/// - [`ModbusTcpFrame::with_pdu`] — validated constructor.
/// - [`ModbusTcpFrame::pdu`] / [`ModbusTcpFrame::pdu_len`] — read accessors.
/// - [`ModbusTcpFrame::set_pdu`] — write accessor that copies up to
///   [`MAX_MODBUS_PDU_LEN`] bytes and updates `pdu_len` atomically.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ModbusTcpFrame {
    /// Transaction identifier.
    pub transaction_id: u16,
    /// Protocol identifier (0x0000 for Modbus).
    pub protocol_id: u16,
    /// Unit identifier (slave address).
    pub unit_id: u8,
    /// Function code.
    pub function_code: ModbusFunctionCode,
    /// Raw function code byte (for detecting unknown codes).
    pub raw_function_code: u8,
    /// Starting register address (for read/write operations).
    pub start_address: u16,
    /// Number of registers/coils (for read/write operations).
    pub quantity: u16,
    /// PDU data bytes. Encapsulated; use [`Self::pdu`] / [`Self::set_pdu`].
    /// Raw PDU buffer. Public to allow downstream test helpers and FFI
    /// adapters to build frames directly; prefer [`Self::with_pdu`] /
    /// [`Self::set_pdu`] which enforce the
    /// `pdu_len <= MAX_MODBUS_PDU_LEN` invariant.
    pub pdu_data: [u8; MAX_MODBUS_PDU_LEN],
    /// Number of valid bytes in `pdu_data`. Encapsulated; use
    /// [`Self::pdu_len`] / [`Self::set_pdu`].
    /// Declared PDU length (bytes). Public to allow downstream test helpers
    /// and FFI adapters; prefer [`Self::with_pdu`] / [`Self::set_pdu`] which
    /// keep `pdu_len <= MAX_MODBUS_PDU_LEN`. Setting this directly bypasses
    /// the invariant — callers must validate via [`Self::pdu_len_overflow`].
    pub pdu_len: u8,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ModbusTcpFrame {
    /// Construct a Modbus TCP frame with a validated PDU.
    ///
    /// `pdu` is copied into the internal buffer up to
    /// [`MAX_MODBUS_PDU_LEN`] bytes. Anything beyond that is silently
    /// truncated — `pdu_len` is set to the *stored* length, never the
    /// caller-supplied length, so the invariant
    /// `pdu_len as usize <= MAX_MODBUS_PDU_LEN` always holds.
    #[must_use]
    pub fn with_pdu(
        transaction_id: u16,
        protocol_id: u16,
        unit_id: u8,
        function_code: ModbusFunctionCode,
        raw_function_code: u8,
        start_address: u16,
        quantity: u16,
        pdu: &[u8],
        timestamp_us: u64,
    ) -> Self {
        let mut frame = Self {
            transaction_id,
            protocol_id,
            unit_id,
            function_code,
            raw_function_code,
            start_address,
            quantity,
            pdu_data: [0u8; MAX_MODBUS_PDU_LEN],
            pdu_len: 0,
            timestamp_us,
        };
        frame.set_pdu(pdu);
        frame
    }

    /// Returns the valid portion of the PDU buffer.
    ///
    /// The slice length is always `<= MAX_MODBUS_PDU_LEN`.
    #[must_use]
    pub fn pdu(&self) -> &[u8] {
        &self.pdu_data[..self.valid_pdu_len()]
    }

    /// Returns the declared PDU length (never exceeds
    /// [`MAX_MODBUS_PDU_LEN`] when set through the validated API).
    #[must_use]
    pub fn pdu_len(&self) -> u8 {
        self.pdu_len
    }

    /// Replace the PDU contents. The slice is copied up to
    /// [`MAX_MODBUS_PDU_LEN`] bytes; excess is discarded. `pdu_len` is set
    /// to the number of bytes actually stored, keeping the buffer/length
    /// invariant in sync.
    pub fn set_pdu(&mut self, data: &[u8]) {
        let n = core::cmp::min(data.len(), MAX_MODBUS_PDU_LEN);
        self.pdu_data[..n].copy_from_slice(&data[..n]);
        // Zero any tail bytes from a previous, longer PDU so that a shorter
        // overwrite cannot leak prior payload through the buffer.
        self.pdu_data[n..].fill(0);
        // n is <= MAX_MODBUS_PDU_LEN (253) which fits in u8.
        debug_assert!(n <= MAX_MODBUS_PDU_LEN);
        self.pdu_len = n as u8;
    }

    /// Returns the PDU length clamped to [`MAX_MODBUS_PDU_LEN`].
    ///
    /// Callers should use this instead of `pdu_len as usize` directly to
    /// avoid out-of-bounds access when `pdu_len` exceeds the buffer size.
    pub fn valid_pdu_len(&self) -> usize {
        if (self.pdu_len as usize) <= MAX_MODBUS_PDU_LEN {
            self.pdu_len as usize
        } else {
            MAX_MODBUS_PDU_LEN
        }
    }

    /// Returns `true` if `pdu_len` exceeds [`MAX_MODBUS_PDU_LEN`].
    ///
    /// Cannot happen if the PDU was set through [`Self::set_pdu`] or
    /// [`Self::with_pdu`]; remains useful for frames built from raw FFI
    /// data where the length is not yet trusted.
    pub fn pdu_len_overflow(&self) -> bool {
        (self.pdu_len as usize) > MAX_MODBUS_PDU_LEN
    }

    /// **Test-only:** forcibly desync `pdu_len` from the buffer so the
    /// overflow handling code path can be exercised. Hidden from public
    /// docs and intended exclusively for regression tests that confirm the
    /// monitor rejects malformed FFI input.
    #[doc(hidden)]
    pub fn __set_pdu_len_unchecked(&mut self, len: u8) {
        self.pdu_len = len;
    }
}

impl Default for ModbusTcpFrame {
    fn default() -> Self {
        Self {
            transaction_id: 0,
            protocol_id: 0,
            unit_id: 0,
            function_code: ModbusFunctionCode::ReadHoldingRegisters,
            raw_function_code: 0x03,
            start_address: 0,
            quantity: 0,
            pdu_data: [0u8; MAX_MODBUS_PDU_LEN],
            pdu_len: 0,
            timestamp_us: 0,
        }
    }
}

/// A Modbus RTU frame (serial).
///
/// `#[repr(C)]` pins the field layout because the frame is forwarded across
/// the C FFI boundary in the integration shim. Reordering or repacking would
/// break the ABI contract. Every field is either a fixed-width integer, a
/// byte array, a `bool`, or a `#[repr(u8)]` enum, so the layout is genuinely
/// stable.
///
/// # Encapsulation
///
/// The PDU buffer and length are `pub(crate)` for the same reason as
/// [`ModbusTcpFrame`] — see that type's docs for the public read/write API.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ModbusRtuFrame {
    /// Slave address.
    pub slave_addr: u8,
    /// Function code.
    pub function_code: ModbusFunctionCode,
    /// Raw function code byte.
    pub raw_function_code: u8,
    /// Starting register address.
    pub start_address: u16,
    /// Number of registers/coils.
    pub quantity: u16,
    /// PDU data bytes. Encapsulated; use [`Self::pdu`] / [`Self::set_pdu`].
    /// Raw PDU buffer. Public to allow downstream test helpers and FFI
    /// adapters to build frames directly; prefer [`Self::with_pdu`] /
    /// [`Self::set_pdu`] which enforce the
    /// `pdu_len <= MAX_MODBUS_PDU_LEN` invariant.
    pub pdu_data: [u8; MAX_MODBUS_PDU_LEN],
    /// Number of valid bytes in `pdu_data`. Encapsulated; use
    /// [`Self::pdu_len`] / [`Self::set_pdu`].
    /// Declared PDU length (bytes). Public to allow downstream test helpers
    /// and FFI adapters; prefer [`Self::with_pdu`] / [`Self::set_pdu`] which
    /// keep `pdu_len <= MAX_MODBUS_PDU_LEN`. Setting this directly bypasses
    /// the invariant — callers must validate via [`Self::pdu_len_overflow`].
    pub pdu_len: u8,
    /// CRC-16 from the frame (for validation).
    pub crc: u16,
    /// Whether the CRC field was provided by the caller. When `false`,
    /// CRC validation is skipped (e.g. the lower layer already stripped
    /// or validated the CRC).
    pub crc_provided: bool,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ModbusRtuFrame {
    /// Construct a Modbus RTU frame with a validated PDU.
    ///
    /// `pdu` is copied into the internal buffer up to
    /// [`MAX_MODBUS_PDU_LEN`] bytes; excess is silently truncated. `pdu_len`
    /// is set to the stored length.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_pdu(
        slave_addr: u8,
        function_code: ModbusFunctionCode,
        raw_function_code: u8,
        start_address: u16,
        quantity: u16,
        pdu: &[u8],
        crc: u16,
        crc_provided: bool,
        timestamp_us: u64,
    ) -> Self {
        let mut frame = Self {
            slave_addr,
            function_code,
            raw_function_code,
            start_address,
            quantity,
            pdu_data: [0u8; MAX_MODBUS_PDU_LEN],
            pdu_len: 0,
            crc,
            crc_provided,
            timestamp_us,
        };
        frame.set_pdu(pdu);
        frame
    }

    /// Returns the valid portion of the PDU buffer.
    ///
    /// The slice length is always `<= MAX_MODBUS_PDU_LEN`.
    #[must_use]
    pub fn pdu(&self) -> &[u8] {
        &self.pdu_data[..self.valid_pdu_len()]
    }

    /// Returns the declared PDU length.
    #[must_use]
    pub fn pdu_len(&self) -> u8 {
        self.pdu_len
    }

    /// Replace the PDU contents. The slice is copied up to
    /// [`MAX_MODBUS_PDU_LEN`] bytes; excess is discarded.
    pub fn set_pdu(&mut self, data: &[u8]) {
        let n = core::cmp::min(data.len(), MAX_MODBUS_PDU_LEN);
        self.pdu_data[..n].copy_from_slice(&data[..n]);
        self.pdu_data[n..].fill(0);
        debug_assert!(n <= MAX_MODBUS_PDU_LEN);
        self.pdu_len = n as u8;
    }

    /// Returns the PDU length clamped to [`MAX_MODBUS_PDU_LEN`].
    pub fn valid_pdu_len(&self) -> usize {
        if (self.pdu_len as usize) <= MAX_MODBUS_PDU_LEN {
            self.pdu_len as usize
        } else {
            MAX_MODBUS_PDU_LEN
        }
    }

    /// Returns `true` if `pdu_len` exceeds [`MAX_MODBUS_PDU_LEN`].
    ///
    /// Cannot happen if the PDU was set through [`Self::set_pdu`] or
    /// [`Self::with_pdu`].
    pub fn pdu_len_overflow(&self) -> bool {
        (self.pdu_len as usize) > MAX_MODBUS_PDU_LEN
    }

    /// **Test-only:** forcibly desync `pdu_len` from the buffer so the
    /// overflow handling code path can be exercised. Hidden from public
    /// docs and intended exclusively for regression tests.
    #[doc(hidden)]
    pub fn __set_pdu_len_unchecked(&mut self, len: u8) {
        self.pdu_len = len;
    }
}

impl Default for ModbusRtuFrame {
    fn default() -> Self {
        Self {
            slave_addr: 0,
            function_code: ModbusFunctionCode::ReadHoldingRegisters,
            raw_function_code: 0x03,
            start_address: 0,
            quantity: 0,
            pdu_data: [0u8; MAX_MODBUS_PDU_LEN],
            pdu_len: 0,
            crc: 0,
            crc_provided: false,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// OPC UA types
// ---------------------------------------------------------------------------

/// Maximum OPC UA endpoint URL length.
pub const MAX_OPCUA_ENDPOINT_LEN: usize = 128;

/// OPC UA message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpcUaMessageType {
    /// Hello message.
    Hello = 0,
    /// Acknowledge message.
    Acknowledge = 1,
    /// Open Secure Channel request/response.
    OpenSecureChannel = 2,
    /// Close Secure Channel.
    CloseSecureChannel = 3,
    /// Create Session.
    CreateSession = 4,
    /// Activate Session.
    ActivateSession = 5,
    /// Close Session.
    CloseSession = 6,
    /// Browse request.
    Browse = 7,
    /// Read request.
    Read = 8,
    /// Write request.
    Write = 9,
    /// Call (method invocation).
    Call = 10,
    /// Subscription create.
    CreateSubscription = 11,
    /// Publish (subscription data).
    Publish = 12,
    /// Unknown/unrecognized.
    Unknown = 255,
}

/// OPC UA security mode.
///
/// Values match the OPC UA specification `MessageSecurityMode` enumeration
/// (1 = None, 2 = Sign, 3 = `SignAndEncrypt`). The spec's `Invalid (0)` value
/// is intentionally omitted — frames with security mode 0 should be rejected
/// at the parsing layer before reaching the monitor.
///
/// # Ordering invariant
///
/// The numeric discriminants are intentionally ordered from weakest to
/// strongest security: `None(1) < Sign(2) < SignAndEncrypt(3)`. The monitor
/// enforces minimum security levels by casting to `u8` and comparing
/// numerically (e.g., `msg.security_mode as u8 < min_mode as u8`). A
/// compile-time assertion below guarantees this invariant. **Never reorder
/// these variants or change their discriminants without updating that
/// assertion and every numeric comparison in `vs-opcua-monitor`.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpcUaSecurityMode {
    /// No security.
    None = 1,
    /// Sign only.
    Sign = 2,
    /// Sign and encrypt.
    SignAndEncrypt = 3,
}

// Compile-time guard: security mode numeric ordering must be strictly
// ascending (None < Sign < SignAndEncrypt) for the cast-and-compare pattern
// in vs-opcua-monitor to be sound.
const _: () = assert!(
    (OpcUaSecurityMode::None as u8) < (OpcUaSecurityMode::Sign as u8),
    "OpcUaSecurityMode::None must be numerically less than Sign"
);
const _: () = assert!(
    (OpcUaSecurityMode::Sign as u8) < (OpcUaSecurityMode::SignAndEncrypt as u8),
    "OpcUaSecurityMode::Sign must be numerically less than SignAndEncrypt"
);

/// An OPC UA message as seen by the IDS.
///
/// `#[repr(C)]` pins the field layout because the message is forwarded
/// across the C FFI boundary in the integration shim. Reordering or
/// repacking would break the ABI contract. Every field is either a
/// fixed-width integer, a byte array, or a `#[repr(u8)]` enum, so the
/// layout is genuinely stable.
///
/// # Encapsulation
///
/// `endpoint` and `endpoint_len` are `pub(crate)` to keep the invariant
/// `endpoint_len as usize <= MAX_OPCUA_ENDPOINT_LEN` in sync. Use
/// [`Self::endpoint`] / [`Self::endpoint_len`] to read and
/// [`Self::set_endpoint`] to write.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct OpcUaMessage {
    /// Message type.
    pub msg_type: OpcUaMessageType,
    /// Security mode of the channel.
    pub security_mode: OpcUaSecurityMode,
    /// Secure channel ID.
    pub channel_id: u32,
    /// Request/response sequence number.
    pub sequence_number: u32,
    /// Message size in bytes.
    pub message_size: u32,
    /// Endpoint URL buffer. Public for test helpers and FFI adapters;
    /// prefer [`Self::set_endpoint`] which keeps the invariant
    /// `endpoint_len as usize <= MAX_OPCUA_ENDPOINT_LEN`.
    pub endpoint: [u8; MAX_OPCUA_ENDPOINT_LEN],
    /// Declared endpoint length. Setting this directly bypasses the
    /// invariant — see [`Self::endpoint_len_overflow`].
    pub endpoint_len: u8,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl OpcUaMessage {
    /// Returns the valid portion of the endpoint buffer.
    ///
    /// The slice length is always `<= MAX_OPCUA_ENDPOINT_LEN`.
    #[must_use]
    pub fn endpoint(&self) -> &[u8] {
        &self.endpoint[..self.valid_endpoint_len()]
    }

    /// Returns the declared endpoint length.
    #[must_use]
    pub fn endpoint_len(&self) -> u8 {
        self.endpoint_len
    }

    /// Replace the endpoint contents. Bytes beyond [`MAX_OPCUA_ENDPOINT_LEN`]
    /// are discarded and the length is set to the stored count.
    pub fn set_endpoint(&mut self, data: &[u8]) {
        let n = core::cmp::min(data.len(), MAX_OPCUA_ENDPOINT_LEN);
        self.endpoint[..n].copy_from_slice(&data[..n]);
        self.endpoint[n..].fill(0);
        debug_assert!(n <= MAX_OPCUA_ENDPOINT_LEN);
        self.endpoint_len = n as u8;
    }

    /// Returns the endpoint length clamped to [`MAX_OPCUA_ENDPOINT_LEN`].
    pub fn valid_endpoint_len(&self) -> usize {
        if (self.endpoint_len as usize) <= MAX_OPCUA_ENDPOINT_LEN {
            self.endpoint_len as usize
        } else {
            MAX_OPCUA_ENDPOINT_LEN
        }
    }

    /// Returns `true` if `endpoint_len` exceeds [`MAX_OPCUA_ENDPOINT_LEN`].
    ///
    /// Cannot happen if the endpoint was set through [`Self::set_endpoint`].
    pub fn endpoint_len_overflow(&self) -> bool {
        (self.endpoint_len as usize) > MAX_OPCUA_ENDPOINT_LEN
    }

    /// **Test-only:** forcibly desync `endpoint_len` from the buffer so the
    /// overflow handling code path can be exercised. Hidden from public
    /// docs and intended exclusively for regression tests.
    #[doc(hidden)]
    pub fn __set_endpoint_len_unchecked(&mut self, len: u8) {
        self.endpoint_len = len;
    }
}

impl Default for OpcUaMessage {
    fn default() -> Self {
        Self {
            msg_type: OpcUaMessageType::Unknown,
            security_mode: OpcUaSecurityMode::None,
            channel_id: 0,
            sequence_number: 0,
            message_size: 0,
            endpoint: [0u8; MAX_OPCUA_ENDPOINT_LEN],
            endpoint_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PROFINET types
// ---------------------------------------------------------------------------

/// PROFINET frame types relevant for IDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProfinetFrameType {
    /// Cyclic Real-Time (RT) data.
    CyclicRT = 0,
    /// Acyclic Real-Time data.
    AcyclicRT = 1,
    /// DCP (Discovery and Configuration Protocol).
    Dcp = 2,
    /// Alarm frame.
    Alarm = 3,
    /// Unknown.
    Unknown = 255,
}

/// Maximum PROFINET payload for inspection.
pub const MAX_PROFINET_PAYLOAD_LEN: usize = 256;

/// A PROFINET IO frame as seen by the IDS.
///
/// `#[repr(C)]` pins the field layout because the frame is forwarded across
/// the C FFI boundary in the integration shim. Reordering or repacking would
/// break the ABI contract. Every field is either a fixed-width integer, a
/// byte array, or a `#[repr(u8)]` enum, so the layout is genuinely stable.
///
/// # Encapsulation
///
/// `payload` and `payload_len` are `pub(crate)` to keep the invariant
/// `payload_len as usize <= MAX_PROFINET_PAYLOAD_LEN` in sync. Use
/// [`Self::payload`] / [`Self::payload_len`] to read and
/// [`Self::set_payload`] to write.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ProfinetFrame {
    /// Frame type.
    pub frame_type: ProfinetFrameType,
    /// Frame ID (determines RT class).
    pub frame_id: u16,
    /// Cycle counter.
    pub cycle_counter: u16,
    /// Data status (valid/invalid, run/stop).
    pub data_status: u8,
    /// Transfer status.
    pub transfer_status: u8,
    /// Raw payload buffer. Public for test helpers and FFI adapters;
    /// prefer [`Self::set_payload`] which keeps the invariant
    /// `payload_len as usize <= MAX_PROFINET_PAYLOAD_LEN`.
    pub payload: [u8; MAX_PROFINET_PAYLOAD_LEN],
    /// Declared payload length. Setting this directly bypasses the
    /// invariant — see [`Self::payload_len_overflow`].
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ProfinetFrame {
    /// Returns the valid portion of the payload buffer.
    ///
    /// The slice length is always `<= MAX_PROFINET_PAYLOAD_LEN`.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.valid_payload_len()]
    }

    /// Returns the declared payload length.
    #[must_use]
    pub fn payload_len(&self) -> u16 {
        self.payload_len
    }

    /// Replace the payload contents. Bytes beyond
    /// [`MAX_PROFINET_PAYLOAD_LEN`] are discarded.
    pub fn set_payload(&mut self, data: &[u8]) {
        let n = core::cmp::min(data.len(), MAX_PROFINET_PAYLOAD_LEN);
        self.payload[..n].copy_from_slice(&data[..n]);
        self.payload[n..].fill(0);
        // n is <= MAX_PROFINET_PAYLOAD_LEN (256) which fits in u16.
        debug_assert!(n <= MAX_PROFINET_PAYLOAD_LEN);
        self.payload_len = n as u16;
    }

    /// Returns the payload length clamped to [`MAX_PROFINET_PAYLOAD_LEN`].
    pub fn valid_payload_len(&self) -> usize {
        if (self.payload_len as usize) <= MAX_PROFINET_PAYLOAD_LEN {
            self.payload_len as usize
        } else {
            MAX_PROFINET_PAYLOAD_LEN
        }
    }

    /// Returns `true` if `payload_len` exceeds [`MAX_PROFINET_PAYLOAD_LEN`].
    ///
    /// Cannot happen if the payload was set through [`Self::set_payload`].
    pub fn payload_len_overflow(&self) -> bool {
        (self.payload_len as usize) > MAX_PROFINET_PAYLOAD_LEN
    }

    /// **Test-only:** forcibly desync `payload_len` from the buffer so the
    /// overflow handling code path can be exercised. Hidden from public docs
    /// and intended exclusively for regression tests that confirm the
    /// monitor rejects malformed FFI input.
    #[doc(hidden)]
    pub fn __set_payload_len_unchecked(&mut self, len: u16) {
        self.payload_len = len;
    }
}

impl Default for ProfinetFrame {
    fn default() -> Self {
        Self {
            frame_type: ProfinetFrameType::Unknown,
            frame_id: 0,
            cycle_counter: 0,
            data_status: 0,
            transfer_status: 0,
            payload: [0u8; MAX_PROFINET_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// EtherNet/IP types
// ---------------------------------------------------------------------------

/// Maximum EtherNet/IP payload for inspection.
pub const MAX_ETHERNETIP_PAYLOAD_LEN: usize = 256;

/// An EtherNet/IP (CIP) frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct EtherNetIpFrame {
    /// Session handle.
    pub session_handle: u32,
    /// Encapsulation command code.
    pub command: u16,
    /// Payload data.
    pub payload: [u8; MAX_ETHERNETIP_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl EtherNetIpFrame {
    /// Returns the payload length clamped to [`MAX_ETHERNETIP_PAYLOAD_LEN`].
    pub fn valid_payload_len(&self) -> usize {
        if (self.payload_len as usize) <= MAX_ETHERNETIP_PAYLOAD_LEN {
            self.payload_len as usize
        } else {
            MAX_ETHERNETIP_PAYLOAD_LEN
        }
    }

    /// Returns `true` if `payload_len` exceeds [`MAX_ETHERNETIP_PAYLOAD_LEN`].
    pub fn payload_len_overflow(&self) -> bool {
        (self.payload_len as usize) > MAX_ETHERNETIP_PAYLOAD_LEN
    }
}

impl Default for EtherNetIpFrame {
    fn default() -> Self {
        Self {
            session_handle: 0,
            command: 0,
            payload: [0u8; MAX_ETHERNETIP_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DNP3 types
// ---------------------------------------------------------------------------

/// Maximum DNP3 payload for inspection (max fragment size).
pub const MAX_DNP3_PAYLOAD_LEN: usize = 292;

/// A DNP3 (Distributed Network Protocol) frame as seen by the IDS.
///
/// Layered fields follow IEEE 1815-2012:
///
/// - **Link layer:** `source_addr`, `dest_addr`, `link_crc`.
/// - **Transport layer:** `transport_byte` (`FIN | FIR | SEQ(6)`).
/// - **Application layer:** `function_code`, `sequence_number` (4-bit),
///   `iin1` (response IIN bits — 16 bits across IIN1/IIN2).
#[derive(Debug, Clone, Copy)]
pub struct Dnp3Frame {
    /// Source address.
    pub source_addr: u16,
    /// Destination address.
    pub dest_addr: u16,
    /// Application-layer function code.
    pub function_code: u8,
    /// Application-layer sequence number (bits 0–3, range 0–15).
    pub sequence_number: u8,
    /// Transport-layer header byte (IEEE 1815 §8.2):
    /// bit 7 = FIN, bit 6 = FIR, bits 5..0 = SEQ (0..63).
    pub transport_byte: u8,
    /// Link-layer CRC-16/DNP3 of the link header block (IEEE 1815 §9.2.2.4).
    ///
    /// Lower layers compute this value over the 8-byte link header
    /// (sync omitted) using the DNP3 polynomial `0x3D65` (init `0x0000`,
    /// final XOR `0xFFFF`, reflected). When [`Self::link_crc_provided`] is
    /// `false` the monitor skips link-CRC verification (e.g. a transport
    /// already validated and stripped the field).
    pub link_crc: u16,
    /// Whether `link_crc` was set by the caller (false → skip verification).
    pub link_crc_provided: bool,
    /// Combined IIN1/IIN2 internal indications from response frames.
    ///
    /// IIN1 occupies the low byte, IIN2 the high byte. Only present in
    /// responses (function codes 129/130). Bits used by the monitor:
    ///
    /// - `IIN1_BROADCAST_RECEIVED = 0x0001`
    /// - `IIN1_LOCAL_CONTROL      = 0x0080`
    /// - `IIN1_DEVICE_TROUBLE     = 0x0100`
    pub iin: u16,
    /// Payload data.
    pub payload: [u8; MAX_DNP3_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

/// IIN1 bit: broadcast message received by outstation.
pub const DNP3_IIN1_BROADCAST_RECEIVED: u16 = 0x0001;
/// IIN1 bit: outstation is in **local** mode (bypasses master).
pub const DNP3_IIN1_LOCAL_CONTROL: u16 = 0x0080;
/// IIN1 bit: outstation reports a device trouble condition.
pub const DNP3_IIN1_DEVICE_TROUBLE: u16 = 0x0100;

/// Transport header bit mask: FIN (last fragment) — IEEE 1815 §8.2.
pub const DNP3_TRANSPORT_FIN: u8 = 0x80;
/// Transport header bit mask: FIR (first fragment) — IEEE 1815 §8.2.
pub const DNP3_TRANSPORT_FIR: u8 = 0x40;
/// Transport header bit mask: 6-bit SEQ field — IEEE 1815 §8.2.
pub const DNP3_TRANSPORT_SEQ_MASK: u8 = 0x3F;

/// DNP3 Secure Authentication (DNP3-SA) request function code (IEEE 1815-1-2012).
pub const DNP3_FC_AUTH_REQUEST: u8 = 32;
/// DNP3 Secure Authentication (DNP3-SA) response function code (IEEE 1815-1-2012).
pub const DNP3_FC_AUTH_RESPONSE: u8 = 33;

impl Dnp3Frame {
    /// Returns the payload length clamped to [`MAX_DNP3_PAYLOAD_LEN`].
    pub fn valid_payload_len(&self) -> usize {
        if (self.payload_len as usize) <= MAX_DNP3_PAYLOAD_LEN {
            self.payload_len as usize
        } else {
            MAX_DNP3_PAYLOAD_LEN
        }
    }

    /// Returns `true` if `payload_len` exceeds [`MAX_DNP3_PAYLOAD_LEN`].
    pub fn payload_len_overflow(&self) -> bool {
        (self.payload_len as usize) > MAX_DNP3_PAYLOAD_LEN
    }

    /// Transport-layer SEQ (6-bit, 0..=63).
    pub fn transport_seq(&self) -> u8 {
        self.transport_byte & DNP3_TRANSPORT_SEQ_MASK
    }

    /// Transport-layer FIN bit (last fragment).
    pub fn transport_fin(&self) -> bool {
        (self.transport_byte & DNP3_TRANSPORT_FIN) != 0
    }

    /// Transport-layer FIR bit (first fragment).
    pub fn transport_fir(&self) -> bool {
        (self.transport_byte & DNP3_TRANSPORT_FIR) != 0
    }

    /// `true` if this frame is a DNP3 response (FC 129 or 130) that carries IIN.
    pub fn is_response(&self) -> bool {
        self.function_code == 129 || self.function_code == 130
    }
}

impl Default for Dnp3Frame {
    fn default() -> Self {
        Self {
            source_addr: 0,
            dest_addr: 0,
            function_code: 0,
            sequence_number: 0,
            transport_byte: 0,
            link_crc: 0,
            link_crc_provided: false,
            iin: 0,
            payload: [0u8; MAX_DNP3_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BACnet types
// ---------------------------------------------------------------------------

/// Maximum `BACnet` payload for inspection.
pub const MAX_BACNET_PAYLOAD_LEN: usize = 256;

/// `BACnet` Virtual Link Control (BVLC) function codes (BACnet/IP, B/IP).
///
/// Defined in ANSI/ASHRAE 135 Annex J.  Foreign-device and forwarded-NPDU
/// functions are the primary vectors for B/IP tunnel abuse: an attacker who
/// can register as a foreign device (or who can spoof a BBMD source) can
/// inject NPDUs that originate outside the local subnet.
pub const BVLC_RESULT: u8 = 0x00;
/// Write Broadcast Distribution Table (BBMD configuration).
pub const BVLC_WRITE_BDT: u8 = 0x01;
/// Read Broadcast Distribution Table.
pub const BVLC_READ_BDT: u8 = 0x02;
/// Forwarded NPDU — used by BBMDs to relay broadcasts across subnets.
pub const BVLC_FORWARDED_NPDU: u8 = 0x04;
/// Register foreign device — joins the BBMD's foreign-device table.
pub const BVLC_REGISTER_FOREIGN_DEVICE: u8 = 0x05;
/// Distribute broadcast to network.
pub const BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK: u8 = 0x0B;
/// Original-Unicast NPDU.
pub const BVLC_ORIGINAL_UNICAST_NPDU: u8 = 0x0A;
/// Original-Broadcast NPDU.
pub const BVLC_ORIGINAL_BROADCAST_NPDU: u8 = 0x09;

/// BVLC packet type byte (always 0x81 for BACnet/IP).
pub const BVLC_TYPE_BIP: u8 = 0x81;

/// A `BACnet` frame as seen by the IDS.
///
/// Carries both the BVLC (BACnet Virtual Link Control) and NPDU (Network
/// Protocol Data Unit) layer fields needed to detect tunnel-layer and
/// network-layer attacks (foreign-device abuse, NPDU forwarding loops,
/// broadcast amplification) in addition to the APDU service-layer
/// inspection performed by the existing `vs-bacnet-monitor`.
#[derive(Debug, Clone, Copy)]
pub struct BacnetFrame {
    /// Service choice (e.g., readProperty, writeProperty).
    pub service_choice: u8,
    /// Invoke ID for confirmed requests.
    pub invoke_id: u8,
    /// BVLC packet type — `BVLC_TYPE_BIP` (0x81) for `BACnet/IP`.
    pub bvlc_type: u8,
    /// BVLC function code — see `BVLC_*` constants.
    pub bvlc_function: u8,
    /// BVLC length field (total length of the BVLC packet in bytes,
    /// including the 4-byte BVLC header). Reported by the BVLC header
    /// itself; the monitor verifies it against the actual payload size.
    pub bvlc_length: u16,
    /// NPDU hop count, when the NPDU has the network-layer-message bit
    /// (`Bit 2` of the NPDU control octet) set. `None` for local-only
    /// NPDUs that omit the hop-count field.
    pub npdu_hop_count: Option<u8>,
    /// `true` when the BVLC function is `FORWARDED_NPDU`,
    /// `ORIGINAL_BROADCAST_NPDU`, or `DISTRIBUTE_BROADCAST_TO_NETWORK`,
    /// or when the NPDU destination is a broadcast network/MAC address.
    pub is_broadcast: bool,
    /// Originating network number (`DNET`/`SNET`) when the NPDU carries
    /// routing information. `None` for purely local traffic.
    pub network_number: Option<u16>,
    /// Source identifier of the originating B/IP peer, derived by the
    /// caller from the underlying transport (e.g. `ipv4_be_u32` of the
    /// remote address). Used as the key for per-source rate limiting of
    /// broadcast/foreign-device traffic.
    pub source_id: u32,
    /// Payload data (APDU bytes after the BVLC + NPDU headers).
    pub payload: [u8; MAX_BACNET_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl BacnetFrame {
    /// Returns the payload length clamped to [`MAX_BACNET_PAYLOAD_LEN`].
    pub fn valid_payload_len(&self) -> usize {
        if (self.payload_len as usize) <= MAX_BACNET_PAYLOAD_LEN {
            self.payload_len as usize
        } else {
            MAX_BACNET_PAYLOAD_LEN
        }
    }

    /// Returns `true` if `payload_len` exceeds [`MAX_BACNET_PAYLOAD_LEN`].
    pub fn payload_len_overflow(&self) -> bool {
        (self.payload_len as usize) > MAX_BACNET_PAYLOAD_LEN
    }
}

impl Default for BacnetFrame {
    fn default() -> Self {
        Self {
            service_choice: 0,
            invoke_id: 0,
            bvlc_type: BVLC_TYPE_BIP,
            bvlc_function: BVLC_ORIGINAL_UNICAST_NPDU,
            bvlc_length: 0,
            npdu_hop_count: None,
            is_broadcast: false,
            network_number: None,
            source_id: 0,
            payload: [0u8; MAX_BACNET_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IEC 61850-9-2 Sampled Values (SV) types
// ---------------------------------------------------------------------------

/// Maximum length of an SV `svID` (ASCII visible string identifier).
///
/// IEC 61850-9-2 limits `svID` to 65 octets in practice; the monitor caps at
/// 64 to keep the frame size aligned with the GOOSE control-block reference.
pub const MAX_SV_SVID_LEN: usize = 64;

/// Maximum length of an SV `datSet` reference.
pub const MAX_SV_DATASET_REF_LEN: usize = 64;

/// An IEC 61850-9-2 Sampled Values (SV) frame as seen by the IDS.
///
/// SV frames carry merging-unit sample data (typically 80 / 256 samples per
/// nominal cycle for protection / measurement applications). The frame is
/// EtherType `0x88BA`, optionally inside an 802.1Q VLAN tag.
///
/// # Field semantics
///
/// - `svid` / `svid_len` — ASN.1 visible string identifying the dataset
///   publisher.
/// - `smp_cnt` — monotonically increasing sample counter, wraps modulo a
///   nominal cycle. Replay / spoofing manifests as backwards step or
///   duplicate.
/// - `smp_rate` — declared sample rate (samples per nominal cycle, e.g. 80
///   for protection, 256 for measurement). 0 if absent on the wire.
/// - `dataset_ref` / `dataset_ref_len` — ObjectReference of the dataset.
/// - `src_mac` — Ethernet source MAC, used for IED-binding checks.
/// - `timestamp_us` — local capture timestamp (microseconds).
/// - `t_seconds_since_epoch` / `t_fraction_of_second` — IEC 61850 `t`
///   UTC-time field; copied from the wire (`t` is a `TimeStamp` in
///   IEC 61850-8-1 §6.2.3.7). Zero means "not present".
#[derive(Debug, Clone, Copy)]
pub struct SvFrame {
    /// Ethernet source MAC of the merging unit / publisher.
    pub src_mac: [u8; 6],
    /// `svID` length in bytes.
    pub svid_len: u8,
    /// `svID` ASCII bytes.
    pub svid: [u8; MAX_SV_SVID_LEN],
    /// Monotonically increasing sample counter (wraps each nominal cycle).
    pub smp_cnt: u16,
    /// Declared sample rate (samples per nominal cycle); 0 if absent.
    pub smp_rate: u16,
    /// `datSet` reference length in bytes.
    pub dataset_ref_len: u8,
    /// `datSet` reference bytes.
    pub dataset_ref: [u8; MAX_SV_DATASET_REF_LEN],
    /// Local capture timestamp (microseconds).
    pub timestamp_us: u64,
    /// IEC 61850 `t` field — seconds since Unix epoch (UTC). 0 if absent.
    pub t_seconds_since_epoch: u32,
    /// IEC 61850 `t` field — fractional seconds (24-bit value in u32).
    /// 0 if absent.
    pub t_fraction_of_second: u32,
}

impl SvFrame {
    /// Returns the `svID` length clamped to [`MAX_SV_SVID_LEN`].
    pub fn valid_svid_len(&self) -> usize {
        if (self.svid_len as usize) <= MAX_SV_SVID_LEN {
            self.svid_len as usize
        } else {
            MAX_SV_SVID_LEN
        }
    }

    /// Returns `true` if `svid_len` exceeds [`MAX_SV_SVID_LEN`].
    pub fn svid_len_overflow(&self) -> bool {
        (self.svid_len as usize) > MAX_SV_SVID_LEN
    }

    /// Returns the dataset-reference length clamped to
    /// [`MAX_SV_DATASET_REF_LEN`].
    pub fn valid_dataset_ref_len(&self) -> usize {
        if (self.dataset_ref_len as usize) <= MAX_SV_DATASET_REF_LEN {
            self.dataset_ref_len as usize
        } else {
            MAX_SV_DATASET_REF_LEN
        }
    }
}

impl Default for SvFrame {
    fn default() -> Self {
        Self {
            src_mac: [0u8; 6],
            svid_len: 0,
            svid: [0u8; MAX_SV_SVID_LEN],
            smp_cnt: 0,
            smp_rate: 0,
            dataset_ref_len: 0,
            dataset_ref: [0u8; MAX_SV_DATASET_REF_LEN],
            timestamp_us: 0,
            t_seconds_since_epoch: 0,
            t_fraction_of_second: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Alert codes
// ---------------------------------------------------------------------------

/// Machine-readable alert code identifying the specific condition detected.
///
/// Each alert carries an `AlertCode` so that operators and automation can
/// distinguish between different security events without relying on
/// severity + `source_id` encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertCode {
    /// No specific code (default for pre-existing alerts).
    Unspecified = 0,
    /// CRC-16 validation failure (Modbus RTU).
    CrcFailure = 1,
    /// Write to a read-only register range or object.
    WriteProtection = 2,
    /// Replay or duplicate sequence/transaction ID detected.
    ReplayDetected = 3,
    /// Rate limit exceeded.
    RateExceeded = 4,
    /// Broadcast/alarm flood abuse.
    FloodAbuse = 5,
    /// Conduit or zone policy violation.
    PolicyViolation = 6,
    /// Unknown or disallowed function/service code.
    UnknownFunctionCode = 7,
    /// Diagnostic command blocked.
    DiagnosticBlocked = 8,
    /// Endpoint blocked by allowlist/blocklist.
    EndpointBlocked = 9,
    /// Security mode below minimum requirement.
    SecurityModeViolation = 10,
    /// Session management anomaly (hijack, expired, eviction).
    SessionAnomaly = 11,
    /// Alarm flood detected (PROFINET).
    AlarmFlood = 12,
    /// Sequence number anomaly (missed cycles, etc.).
    SequenceAnomaly = 13,
    /// Payload length exceeds buffer size.
    PayloadOverflow = 14,
    /// Invalid protocol ID (e.g., Modbus TCP `protocol_id` != 0).
    InvalidProtocol = 15,
    /// No matching rule in strict mode.
    NoMatchingRule = 16,
    /// Message type not permitted by endpoint permissions.
    MessageTypeBlocked = 17,
    /// Provider state transition (Run → Stop).
    ProviderStateChange = 18,
    /// DCP (Discovery and Configuration Protocol) blocked.
    DcpBlocked = 19,
    /// Message size exceeds configured maximum.
    MessageSizeExceeded = 20,
    /// Address pair not permitted (DNP3).
    AddressViolation = 21,
    /// Session handle not registered (EtherNet/IP).
    UnknownSession = 22,
    /// Resource exhaustion (buckets, slots).
    ResourceExhausted = 23,
    /// `BACnet` object-level access denied (read/write of a protected object).
    ObjectAccessDenied = 24,
    /// `EtherNet/IP` embedded CIP service code not permitted by the service mask.
    CipServiceBlocked = 25,
    /// IEC 61850-9-2 Sampled-Values smpCnt replay or backwards step.
    SvReplay = 26,
    /// IEC 61850-9-2 Sampled-Values rate / smpCnt-gap anomaly.
    SvRateAnomaly = 27,
    /// IEC 61850 SV/GOOSE source MAC does not match the IED-registered MAC
    /// for the advertised `svID` / `goCBRef` (publisher impersonation).
    IedMismatch = 28,
    /// IEC 61850 MMS-reserved control block (GoCB / SvCB) addressed by a
    /// frame from a non-owning publisher — likely control-block hijack.
    CbHijack = 29,
    /// IEC 61850 GOOSE retransmission interval deviates from the documented
    /// decay schedule (T0, T1=T0*2, T2=T1*2, ..., max) — possible injection
    /// or starvation of legitimate retransmissions.
    RetransmissionAnomaly = 30,
    /// IEC 61850 GOOSE/SV `t` (timestamp) field went backwards or made an
    /// implausibly large forward jump — likely SNTP/PTP spoofing.
    TimeSyncSpoofing = 31,
    /// Modbus monotonic-timestamp regression detected.
    ClockRegression = 32,
    /// Modbus unit_id not in the configured allowlist.
    UnitNotAllowed = 33,
    /// Modbus unit_id is reserved (0 broadcast or > 247).
    InvalidUnitId = 34,
    /// Modbus TCP transaction-ID replay within the per-source window.
    TxIdReplay = 35,
    /// DNP3 link-layer CRC-16-DNP3 mismatch.
    BadLinkCrc = 36,
    /// DNP3 transport-layer sequence regression / replay.
    TransportSeqAnomaly = 37,
    /// DNP3-SA HMAC or key-wrap algorithm downgrade detected.
    SaDowngrade = 38,
    /// DNP3 IIN bit flap or spoofing (LOCAL_CONTROL / DEVICE_TROUBLE).
    IinFlagSpoofing = 39,
    /// BACnet BVLC foreign-device tunnelling abuse.
    ForeignDevice = 40,
    /// BACnet NPDU forwarding loop / hop-count exhaustion.
    NpduLoop = 41,
    /// BACnet broadcast amplification (per-source flood).
    BroadcastFlood = 42,
}

impl AlertCode {
    /// Returns the numeric identifier of this alert code.
    ///
    /// Suitable for SIEM integration, log serialization, and wire protocols
    /// that require a compact integer rather than a symbolic name.  The
    /// value is stable across patch releases; new variants will always
    /// receive previously unused numbers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vs_types_ind::AlertCode;
    /// assert_eq!(AlertCode::CrcFailure.code(), 1);
    /// assert_eq!(AlertCode::WriteProtection.code(), 2);
    /// assert_eq!(AlertCode::Unspecified.code(), 0);
    /// ```
    pub const fn code(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Unified inspection result
// ---------------------------------------------------------------------------

/// Unified inspection result shared across all protocol monitors.
///
/// Contains up to [`MAX_ALERTS_PER_RESULT`] security alerts generated during
/// inspection. The `payload_hash` field of each alert is zeroed — callers
/// that need payload hashing should compute it externally.
///
/// If more than [`MAX_ALERTS_PER_RESULT`] alerts are generated in a single
/// inspection, `alerts_truncated` is set to `true` and the excess alerts are
/// dropped. Callers should treat a truncated result as equally serious as a
/// full one.
#[derive(Debug, Clone, Copy)]
#[must_use = "inspection results must be checked — ignoring may allow malicious traffic"]
pub struct InspectResult {
    /// `true` when the inspected traffic is allowed to pass. Set to `false`
    /// automatically by [`InspectResult::push_alert_with_code`] when a
    /// `High` or `Critical` severity alert is pushed, and unconditionally by
    /// [`InspectResult::push_alert_blocking`].
    pub allowed: bool,
    /// Number of alerts currently populated in [`Self::alerts`]
    /// (`<= MAX_ALERTS_PER_RESULT`).
    pub alert_count: u8,
    /// Which protocol produced this result.
    pub source_type: u8,
    /// Fixed-size alert buffer; only the first [`Self::alert_count`] entries
    /// are meaningful.
    pub alerts: [vs_types::SecurityAlert; MAX_ALERTS_PER_RESULT],
    /// Machine-readable codes for each alert slot.
    pub alert_codes: [AlertCode; MAX_ALERTS_PER_RESULT],
    /// `true` when more than [`MAX_ALERTS_PER_RESULT`] alerts were generated
    /// and the excess were dropped. Indicates a compound attack or severe
    /// misconfiguration — treat with the same urgency as any High alert.
    pub alerts_truncated: bool,
}

impl InspectResult {
    /// Create a clean (no alerts, allowed) result for the given source type.
    pub fn clean(source_type: u8) -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            source_type,
            alerts: [vs_types::SecurityAlert {
                id: 0,
                severity: vs_types::AlertSeverity::Info,
                source_type,
                source_id: 0,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: 0,
            }; MAX_ALERTS_PER_RESULT],
            alert_codes: [AlertCode::Unspecified; MAX_ALERTS_PER_RESULT],
            alerts_truncated: false,
        }
    }

    /// Push an alert without a specific code.
    ///
    /// Prefer [`push_alert_with_code`](Self::push_alert_with_code) which
    /// includes a machine-readable [`AlertCode`] for automated triage.
    pub fn push_alert(
        &mut self,
        severity: vs_types::AlertSeverity,
        source_type: u8,
        source_id: u32,
        ts_us: u64,
        next_alert_id: &mut u64,
        total_alerts: &mut u64,
    ) {
        self.push_alert_with_code(
            severity,
            source_type,
            source_id,
            ts_us,
            next_alert_id,
            total_alerts,
            AlertCode::Unspecified,
        );
    }

    /// Push an alert with a specific [`AlertCode`].
    ///
    /// When the alert buffer is full (more than [`MAX_ALERTS_PER_RESULT`]
    /// alerts in one inspection), the excess alert is dropped and
    /// [`InspectResult::alerts_truncated`] is set to `true`.
    ///
    /// # Auto-deny policy
    ///
    /// If `severity` is [`vs_types::AlertSeverity::High`] or
    /// [`vs_types::AlertSeverity::Critical`], [`Self::allowed`] is set to
    /// `false` automatically. The deny applies even when the alert itself
    /// is dropped on the truncation path — a compound attack that overflows
    /// the alert buffer must never bypass the deny decision.
    /// Lower severities (Info / Low / Medium) leave `allowed` untouched.
    /// Callers that need an unconditional deny regardless of severity must
    /// use [`Self::push_alert_blocking`].
    #[allow(clippy::too_many_arguments)] // hot path — avoid struct packing overhead
    pub fn push_alert_with_code(
        &mut self,
        severity: vs_types::AlertSeverity,
        source_type: u8,
        source_id: u32,
        ts_us: u64,
        next_alert_id: &mut u64,
        total_alerts: &mut u64,
        code: AlertCode,
    ) {
        // Auto-deny on High/Critical regardless of whether the alert slot
        // is available — truncation must not bypass the deny decision.
        if matches!(
            severity,
            vs_types::AlertSeverity::High | vs_types::AlertSeverity::Critical
        ) {
            self.allowed = false;
        }
        if (self.alert_count as usize) < self.alerts.len() {
            let id = *next_alert_id;
            *next_alert_id = next_alert_id.wrapping_add(1);
            let idx = self.alert_count as usize;
            self.alerts[idx] = vs_types::SecurityAlert {
                id,
                severity,
                source_type,
                source_id,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: ts_us,
            };
            self.alert_codes[idx] = code;
            self.alert_count += 1;
            *total_alerts = total_alerts.saturating_add(1);
        } else {
            self.alerts_truncated = true;
        }
    }

    /// Push an alert that unconditionally denies the inspected traffic.
    ///
    /// Behaves exactly like [`Self::push_alert_with_code`] except that
    /// [`Self::allowed`] is set to `false` regardless of the alert's
    /// severity. Use this when policy mandates a deny decision (e.g.
    /// allowlist miss, blocked function code) even though the severity
    /// might otherwise be reported as Info / Low / Medium for SIEM
    /// triage purposes.
    #[allow(clippy::too_many_arguments)] // hot path — avoid struct packing overhead
    pub fn push_alert_blocking(
        &mut self,
        severity: vs_types::AlertSeverity,
        source_type: u8,
        source_id: u32,
        ts_us: u64,
        next_alert_id: &mut u64,
        total_alerts: &mut u64,
        code: AlertCode,
    ) {
        self.push_alert_with_code(
            severity,
            source_type,
            source_id,
            ts_us,
            next_alert_id,
            total_alerts,
            code,
        );
        // Always deny, even for Info / Low / Medium severities that would
        // leave `allowed` untouched on the auto-deny path.
        self.allowed = false;
    }
}

// ---------------------------------------------------------------------------
// Unified rate bucket
// ---------------------------------------------------------------------------

/// Token bucket rate limiter shared across protocol monitors.
///
/// # Stack budget
///
/// Each `RateBucket` is 28 bytes. Typical monitor allocations:
/// - Modbus: 32 buckets = 896 bytes
/// - OPC UA: 16 buckets = 448 bytes
#[derive(Debug, Clone, Copy)]
pub struct RateBucket {
    /// Key identifying the rate-limited entity (`unit_id`, `channel_id`, etc.).
    pub key: u32,
    /// Current number of available tokens.
    pub tokens: u16,
    /// Maximum tokens (requests per second).
    pub capacity: u16,
    /// Timestamp of last refill in microseconds.
    pub last_refill_us: u64,
    /// Whether this bucket is in use.
    pub active: bool,
    /// LRU generation counter for eviction ordering.
    pub last_used: u32,
}

impl RateBucket {
    /// Create an empty, inactive rate bucket.
    pub const fn empty() -> Self {
        Self {
            key: 0,
            tokens: 0,
            capacity: 0,
            last_refill_us: 0,
            active: false,
            last_used: 0,
        }
    }

    /// Try to consume one token. Returns `true` if allowed.
    ///
    /// Uses `checked_mul` to prevent overflow when elapsed time is very large
    /// (e.g., device sleep). On overflow the refill exceeds capacity anyway,
    /// so saturate — the subsequent `.min(capacity)` caps the result.
    ///
    /// **Clock wraparound handling:** if `now_us < self.last_refill_us`
    /// (the system clock stepped backwards, e.g. after a time sync), the
    /// bucket is refilled to full capacity and `last_refill_us` is reset to
    /// `now_us`. Without this, a backwards step would freeze the bucket and
    /// deny legitimate traffic until real time caught up again.
    pub fn try_consume(&mut self, now_us: u64) -> bool {
        if now_us < self.last_refill_us {
            // Clock stepped backwards — resync and give the bucket a fresh fill.
            self.tokens = self.capacity;
            self.last_refill_us = now_us;
        } else {
            let elapsed = now_us - self.last_refill_us;
            let refill = elapsed
                .checked_mul(self.capacity as u64)
                .map_or(u64::MAX, |v| v / 1_000_000);
            if refill > 0 {
                self.tokens = self
                    .tokens
                    .saturating_add(refill.min(u16::MAX as u64) as u16)
                    .min(self.capacity);
                self.last_refill_us = now_us;
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// The S7comm family carries a protocol-identifier byte at the start of the
/// PDU header which distinguishes the classic S7-300/400 dialect (`0x32`) from
/// the newer S7comm-plus dialect (`0x72`) used by S7-1200/1500 PLCs.
///
/// The two variants share the same TPKT/COTP envelope but use incompatible
/// PDU encodings and security primitives.  Mixing variants on the same TCP
/// connection is anomalous and strongly suggests man-in-the-middle activity
/// (e.g. a downgrade attempt against an S7-1500 controller).
///
/// `#[non_exhaustive]` so that future S7 dialects (e.g. firmware service
/// channels) can be added without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum S7CommVariant {
    /// Classic S7comm — protocol id `0x32`. Used by S7-300/400 PLCs and
    /// (in legacy mode) by S7-1200/1500.
    Classic = 0x32,
    /// S7comm-plus — protocol id `0x72`. Used by S7-1200/1500 PLCs.
    Plus = 0x72,
}

impl S7CommVariant {
    /// Parse a variant from the raw protocol-id byte.
    ///
    /// Returns `None` for any value other than the two well-known dialects.
    /// Callers should treat an unrecognised byte as a parse failure rather
    /// than silently coercing to a default.
    pub fn from_protocol_id(b: u8) -> Option<Self> {
        match b {
            0x32 => Some(Self::Classic),
            0x72 => Some(Self::Plus),
            _ => None,
        }
    }

    /// Returns the on-the-wire protocol-id byte.
    pub const fn protocol_id(self) -> u8 {
        self as u8
    }
}

/// Logical session type for an S7comm TCP connection.
///
/// Siemens PLCs distinguish "programming device" (PG) sessions, used by
/// engineering workstations running TIA Portal / Step 7, from "HMI" sessions
/// used by panels and SCADA, and from generic "PUT/GET" (OP) data exchange.
///
/// The session type is established at connect-up time via the
/// COTP-Connect "calling TSAP" / S7 SetupComm parameters; once chosen it
/// stays fixed for the lifetime of the TCP connection.
///
/// Several high-impact S7 sub-functions — most notably the Security group
/// (FC `0x29`: password set, key install, access-level change) — should
/// only ever be issued from a PG session.  Seeing them on an HMI or
/// OP session indicates either a misconfigured device or an attacker
/// abusing a less-privileged channel.
///
/// `#[non_exhaustive]` so additional session classes (e.g. firmware
/// update, web-server) can be added without breaking the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum S7SessionType {
    /// Unknown or not yet negotiated.
    Unknown = 0,
    /// Programming-device (PG) session — engineering workstation.
    Pg = 1,
    /// Human-machine-interface (HMI) panel.
    Hmi = 2,
    /// PUT/GET (OP) data-exchange session.
    Op = 3,
}

impl S7SessionType {
    /// Numeric session-type identifier (1-bit mask position).
    pub const fn bit(self) -> u8 {
        self as u8
    }

    /// Single-bit mask suitable for an allowlist bitmap.
    pub const fn mask(self) -> u8 {
        1u8 << (self as u8)
    }
}

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
    /// Security function group (`0x29`) — password set, key install,
    /// access-level change.  This was previously labelled `PlcStop` for
    /// historical compatibility; treat as a security-sensitive function
    /// that should be restricted to programming-device sessions.
    Security = 0x29,
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
            0x29 => Self::Security,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this function code modifies PLC state.
    ///
    /// `Security (0x29)` is treated as a write because installing a key
    /// or changing the access level mutates persistent device state.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::WriteVar
                | Self::RequestDownload
                | Self::DownloadBlock
                | Self::DownloadEnded
                | Self::PlcControl
                | Self::Security
        )
    }

    /// Map known function codes to bit positions 0..=9 for `fc_mask` checking.
    ///
    /// Returns `None` for `Unknown` (0xFF) since it has no assigned bit.
    pub fn bit_index(self) -> Option<u8> {
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
            Self::Security => Some(9),
            Self::Unknown => None,
        }
    }
}

/// An S7comm frame as seen by the IDS.
///
/// The frame carries both the parsed PDU view (`pdu_type`, `function`) and
/// the raw bytes (`raw_pdu_type`, `raw_function`) so that the monitor can
/// surface unknown-code alerts without losing the original value.
///
/// **Variant awareness.**  `s7_variant` records whether the parser
/// observed classic S7comm (`0x32`) or S7comm-plus (`0x72`).  The monitor
/// pins a session to its first observed variant and rejects subsequent
/// frames whose variant differs — a mixed-variant connection is a strong
/// MITM indicator.
///
/// **Connection identity.**  `connection_id` is a TCP-level identifier
/// supplied by the upstream demultiplexer (typically a hash of the
/// 5-tuple or a kernel socket cookie).  It keys the per-session replay
/// table inside the monitor; reusing the same value across genuinely
/// different connections defeats the replay defense.
#[derive(Debug, Clone, Copy)]
pub struct S7commFrame {
    /// TCP connection identifier (5-tuple hash / socket cookie).
    pub connection_id: u32,
    /// Protocol variant — `Classic (0x32)` or `Plus (0x72)`.
    pub s7_variant: S7CommVariant,
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
    /// Session-type hint supplied by the parser (PG / HMI / OP).
    ///
    /// `S7SessionType::Unknown` means the parser has not yet observed the
    /// COTP-Connect / SetupComm handshake.  The default SF 0x29
    /// session-type allowlist (`SF_SECURITY_DEFAULT_SESSION_MASK` in
    /// `vs-s7comm-monitor`) is PG-only and does NOT include `Unknown`, so
    /// untyped sessions cannot issue the Security function group without
    /// an explicit opt-in via the monitor's `add_rule_full` API.
    pub session_type: S7SessionType,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl Default for S7commFrame {
    fn default() -> Self {
        Self {
            connection_id: 0,
            s7_variant: S7CommVariant::Classic,
            pdu_type: S7commPduType::JobRequest,
            raw_pdu_type: 0x01,
            function: S7commFunction::ReadVar,
            raw_function: 0x04,
            pdu_ref: 0,
            session_type: S7SessionType::Unknown,
            timestamp_us: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_constants_in_industrial_range() {
        const _: () = {
            assert!(SOURCE_MODBUS_RTU >= 30 && SOURCE_MODBUS_RTU < 50);
            assert!(SOURCE_MODBUS_TCP >= 30 && SOURCE_MODBUS_TCP < 50);
            assert!(SOURCE_OPCUA >= 30 && SOURCE_OPCUA < 50);
            assert!(SOURCE_PROFINET >= 30 && SOURCE_PROFINET < 50);
            assert!(SOURCE_ETHERNETIP >= 30 && SOURCE_ETHERNETIP < 50);
            assert!(SOURCE_DNP3 >= 30 && SOURCE_DNP3 < 50);
            assert!(SOURCE_BACNET >= 30 && SOURCE_BACNET < 50);
            assert!(SOURCE_HTTP >= 30 && SOURCE_HTTP < 50);
            assert!(SOURCE_S7COMM >= 30 && SOURCE_S7COMM < 50);
            assert!(SOURCE_IEC60870 >= 30 && SOURCE_IEC60870 < 50);
            assert!(SOURCE_IEC61850_MMS >= 30 && SOURCE_IEC61850_MMS < 50);
            assert!(SOURCE_IEC61850_GOOSE >= 30 && SOURCE_IEC61850_GOOSE < 50);
            assert!(SOURCE_IEC61850_SV >= 30 && SOURCE_IEC61850_SV < 50);
        };
    }

    #[test]
    fn source_constants_unique() {
        let sources = [
            SOURCE_MODBUS_RTU,
            SOURCE_MODBUS_TCP,
            SOURCE_OPCUA,
            SOURCE_PROFINET,
            SOURCE_ETHERNETIP,
            SOURCE_DNP3,
            SOURCE_BACNET,
            SOURCE_HTTP,
            SOURCE_S7COMM,
            SOURCE_IEC60870,
            SOURCE_IEC61850_MMS,
            SOURCE_IEC61850_GOOSE,
            SOURCE_IEC61850_SV,
        ];
        for i in 0..sources.len() {
            for j in (i + 1)..sources.len() {
                assert_ne!(sources[i], sources[j]);
            }
        }
    }

    #[test]
    fn sv_frame_default() {
        let f = SvFrame::default();
        assert_eq!(f.svid_len, 0);
        assert_eq!(f.smp_cnt, 0);
        assert_eq!(f.smp_rate, 0);
        assert!(!f.svid_len_overflow());
        assert_eq!(f.valid_svid_len(), 0);
        assert_eq!(f.valid_dataset_ref_len(), 0);
    }

    #[test]
    fn sv_frame_overflow_clamps() {
        let f = SvFrame {
            svid_len: 200,
            dataset_ref_len: 200,
            ..SvFrame::default()
        };
        assert!(f.svid_len_overflow());
        assert_eq!(f.valid_svid_len(), MAX_SV_SVID_LEN);
        assert_eq!(f.valid_dataset_ref_len(), MAX_SV_DATASET_REF_LEN);
    }

    #[test]
    fn sv_frame_fields_round_trip() {
        let mut svid = [0u8; MAX_SV_SVID_LEN];
        svid[..3].copy_from_slice(b"MU1");
        let f = SvFrame {
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            svid_len: 3,
            svid,
            smp_cnt: 1234,
            smp_rate: 80,
            t_seconds_since_epoch: 1_700_000_000,
            t_fraction_of_second: 0x80_0000,
            ..SvFrame::default()
        };
        assert_eq!(f.valid_svid_len(), 3);
        assert_eq!(&f.svid[..f.valid_svid_len()], b"MU1");
        assert_eq!(f.smp_cnt, 1234);
        assert_eq!(f.smp_rate, 80);
        assert_eq!(f.t_seconds_since_epoch, 1_700_000_000);
    }

    #[test]
    fn alert_code_v09_new_codes_distinct() {
        // 2026-05 honesty-pass additions for IEC 61850-9-2 SV /
        // control-block hijack / retx interval / time-sync spoofing.
        let codes: [u8; 6] = [
            AlertCode::SvReplay.code(),
            AlertCode::SvRateAnomaly.code(),
            AlertCode::IedMismatch.code(),
            AlertCode::CbHijack.code(),
            AlertCode::RetransmissionAnomaly.code(),
            AlertCode::TimeSyncSpoofing.code(),
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
            // Must not collide with any pre-existing code (0..=25).
            assert!(codes[i] >= 26);
        }
    }

    #[test]
    fn modbus_function_code_parsing() {
        assert_eq!(
            ModbusFunctionCode::from_u8(0x03),
            ModbusFunctionCode::ReadHoldingRegisters
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x10),
            ModbusFunctionCode::WriteMultipleRegisters
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0xAB),
            ModbusFunctionCode::Unknown
        );
    }

    #[test]
    fn modbus_function_code_is_write() {
        assert!(ModbusFunctionCode::WriteSingleCoil.is_write());
        assert!(ModbusFunctionCode::WriteMultipleRegisters.is_write());
        assert!(!ModbusFunctionCode::ReadCoils.is_write());
        assert!(!ModbusFunctionCode::ReadHoldingRegisters.is_write());
    }

    #[test]
    fn modbus_function_code_is_diagnostic() {
        assert!(ModbusFunctionCode::Diagnostics.is_diagnostic());
        assert!(!ModbusFunctionCode::ReadCoils.is_diagnostic());
    }

    #[test]
    fn security_level_ordering() {
        assert!(SecurityLevel::Sl4 > SecurityLevel::Sl3);
        assert!(SecurityLevel::Sl3 > SecurityLevel::Sl2);
        assert!(SecurityLevel::Sl2 > SecurityLevel::Sl1);
        assert!(SecurityLevel::Sl1 > SecurityLevel::Sl0);
    }

    #[test]
    fn zone_meets_target() {
        let mut zone = Zone::empty();
        zone.target_sl = SecurityLevel::Sl2;
        zone.achieved_sl = SecurityLevel::Sl2;
        assert!(zone.meets_target());

        zone.achieved_sl = SecurityLevel::Sl3;
        assert!(zone.meets_target());

        zone.achieved_sl = SecurityLevel::Sl1;
        assert!(!zone.meets_target());
    }

    #[test]
    fn modbus_tcp_frame_default() {
        let f = ModbusTcpFrame::default();
        assert_eq!(f.function_code, ModbusFunctionCode::ReadHoldingRegisters);
        assert_eq!(f.protocol_id, 0);
        assert_eq!(f.pdu_len, 0);
    }

    #[test]
    fn modbus_rtu_frame_default() {
        let f = ModbusRtuFrame::default();
        assert_eq!(f.function_code, ModbusFunctionCode::ReadHoldingRegisters);
        assert_eq!(f.crc, 0);
        assert!(!f.crc_provided);
    }

    #[test]
    fn opcua_message_default() {
        let m = OpcUaMessage::default();
        assert_eq!(m.msg_type, OpcUaMessageType::Unknown);
        assert_eq!(m.security_mode, OpcUaSecurityMode::None);
    }

    #[test]
    fn profinet_frame_default() {
        let f = ProfinetFrame::default();
        assert_eq!(f.frame_type, ProfinetFrameType::Unknown);
        assert_eq!(f.payload_len, 0);
    }

    // -----------------------------------------------------------------------
    // Additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_fc_all_reads() {
        assert!(!ModbusFunctionCode::ReadCoils.is_write());
        assert!(!ModbusFunctionCode::ReadDiscreteInputs.is_write());
        assert!(!ModbusFunctionCode::ReadHoldingRegisters.is_write());
        assert!(!ModbusFunctionCode::ReadInputRegisters.is_write());
    }

    #[test]
    fn modbus_fc_all_writes() {
        assert!(ModbusFunctionCode::WriteSingleCoil.is_write());
        assert!(ModbusFunctionCode::WriteSingleRegister.is_write());
        assert!(ModbusFunctionCode::WriteMultipleCoils.is_write());
        assert!(ModbusFunctionCode::WriteMultipleRegisters.is_write());
        assert!(ModbusFunctionCode::ReadWriteMultipleRegisters.is_write());
    }

    #[test]
    fn modbus_fc_parse_all_known() {
        assert_eq!(
            ModbusFunctionCode::from_u8(0x01),
            ModbusFunctionCode::ReadCoils
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x02),
            ModbusFunctionCode::ReadDiscreteInputs
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x04),
            ModbusFunctionCode::ReadInputRegisters
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x05),
            ModbusFunctionCode::WriteSingleCoil
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x06),
            ModbusFunctionCode::WriteSingleRegister
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x0F),
            ModbusFunctionCode::WriteMultipleCoils
        );
        assert_eq!(
            ModbusFunctionCode::from_u8(0x17),
            ModbusFunctionCode::ReadWriteMultipleRegisters
        );
    }

    #[test]
    fn zone_empty() {
        let z = Zone::empty();
        assert!(!z.active);
        assert!(z.meets_target()); // SL0 meets SL0
    }

    #[test]
    fn conduit_empty() {
        let c = Conduit::empty();
        assert!(!c.active);
        assert_eq!(c.allowed_protocols, 0);
    }

    #[test]
    fn protocol_bitmask_flags() {
        let combined = PROTO_MODBUS_TCP | PROTO_OPCUA;
        assert_ne!(combined & PROTO_MODBUS_TCP, 0);
        assert_ne!(combined & PROTO_OPCUA, 0);
        assert_eq!(combined & PROTO_PROFINET, 0);
        assert_eq!(combined & PROTO_ETHERNETIP, 0);
        assert_eq!(combined & PROTO_DNP3, 0);
        assert_eq!(combined & PROTO_HTTP, 0);
        assert_eq!(combined & PROTO_MODBUS_RTU, 0);
    }

    #[test]
    fn protocol_bitmask_all_unique() {
        let flags: [u16; 11] = [
            PROTO_MODBUS_TCP,
            PROTO_MODBUS_RTU,
            PROTO_OPCUA,
            PROTO_PROFINET,
            PROTO_ETHERNETIP,
            PROTO_DNP3,
            PROTO_HTTP,
            PROTO_BACNET,
            PROTO_S7COMM,
            PROTO_IEC60870,
            PROTO_IEC61850,
        ];
        for i in 0..flags.len() {
            assert!(flags[i].is_power_of_two(), "flag {i} must be a single bit");
            for j in (i + 1)..flags.len() {
                assert_eq!(flags[i] & flags[j], 0, "flags {i} and {j} overlap");
            }
        }
    }

    #[test]
    fn security_level_equality() {
        assert_eq!(SecurityLevel::Sl2, SecurityLevel::Sl2);
        assert_ne!(SecurityLevel::Sl1, SecurityLevel::Sl3);
    }

    #[test]
    fn opcua_security_mode_values() {
        assert_eq!(OpcUaSecurityMode::None as u8, 1);
        assert_eq!(OpcUaSecurityMode::Sign as u8, 2);
        assert_eq!(OpcUaSecurityMode::SignAndEncrypt as u8, 3);
    }

    #[test]
    fn opcua_message_types_distinct() {
        assert_ne!(OpcUaMessageType::Read as u8, OpcUaMessageType::Write as u8);
        assert_ne!(OpcUaMessageType::Browse as u8, OpcUaMessageType::Call as u8);
        assert_ne!(
            OpcUaMessageType::Hello as u8,
            OpcUaMessageType::Acknowledge as u8
        );
    }

    #[test]
    fn profinet_frame_types_distinct() {
        assert_ne!(
            ProfinetFrameType::CyclicRT as u8,
            ProfinetFrameType::AcyclicRT as u8
        );
        assert_ne!(ProfinetFrameType::Dcp as u8, ProfinetFrameType::Alarm as u8);
    }

    #[test]
    fn modbus_tcp_frame_fields() {
        let f = ModbusTcpFrame {
            transaction_id: 123,
            unit_id: 5,
            start_address: 100,
            quantity: 10,
            ..ModbusTcpFrame::default()
        };
        assert_eq!(f.transaction_id, 123);
        assert_eq!(f.unit_id, 5);
    }

    #[test]
    fn modbus_tcp_valid_pdu_len() {
        let f = ModbusTcpFrame {
            pdu_len: 100,
            ..Default::default()
        };
        assert_eq!(f.valid_pdu_len(), 100);
        assert!(!f.pdu_len_overflow());

        let f = ModbusTcpFrame {
            pdu_len: 253,
            ..Default::default()
        };
        assert_eq!(f.valid_pdu_len(), 253);
        assert!(!f.pdu_len_overflow());

        let f = ModbusTcpFrame {
            pdu_len: 255,
            ..Default::default()
        };
        assert_eq!(f.valid_pdu_len(), MAX_MODBUS_PDU_LEN);
        assert!(f.pdu_len_overflow());
    }

    #[test]
    fn modbus_rtu_valid_pdu_len() {
        let f = ModbusRtuFrame {
            pdu_len: 255,
            ..Default::default()
        };
        assert_eq!(f.valid_pdu_len(), MAX_MODBUS_PDU_LEN);
        assert!(f.pdu_len_overflow());
    }

    #[test]
    fn opcua_valid_endpoint_len() {
        let m = OpcUaMessage {
            endpoint_len: 64,
            ..Default::default()
        };
        assert_eq!(m.valid_endpoint_len(), 64);
        assert!(!m.endpoint_len_overflow());

        let m = OpcUaMessage {
            endpoint_len: 255,
            ..Default::default()
        };
        assert_eq!(m.valid_endpoint_len(), MAX_OPCUA_ENDPOINT_LEN);
        assert!(m.endpoint_len_overflow());
    }

    #[test]
    fn profinet_valid_payload_len() {
        let f = ProfinetFrame {
            payload_len: 300,
            ..ProfinetFrame::default()
        };
        assert_eq!(f.valid_payload_len(), MAX_PROFINET_PAYLOAD_LEN);
        assert!(f.payload_len_overflow());

        let f2 = ProfinetFrame {
            payload_len: 128,
            ..ProfinetFrame::default()
        };
        assert_eq!(f2.valid_payload_len(), 128);
        assert!(!f2.payload_len_overflow());
    }

    #[test]
    fn max_alerts_per_result_constant() {
        assert_eq!(MAX_ALERTS_PER_RESULT, 4);
    }

    // -----------------------------------------------------------------------
    // InspectResult
    // -----------------------------------------------------------------------

    #[test]
    fn inspect_result_clean() {
        let r = InspectResult::clean(SOURCE_MODBUS_TCP);
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
        assert_eq!(r.source_type, SOURCE_MODBUS_TCP);
        assert_eq!(r.alerts[0].source_type, SOURCE_MODBUS_TCP);
        assert_eq!(r.alert_codes[0], AlertCode::Unspecified);
    }

    #[test]
    fn inspect_result_push_alert() {
        let mut r = InspectResult::clean(SOURCE_OPCUA);
        let mut next_id = 1u64;
        let mut total = 0u64;
        r.push_alert(
            vs_types::AlertSeverity::High,
            SOURCE_OPCUA,
            42,
            1000,
            &mut next_id,
            &mut total,
        );
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alerts[0].id, 1);
        assert_eq!(r.alerts[0].source_id, 42);
        assert_eq!(next_id, 2);
        assert_eq!(total, 1);
    }

    #[test]
    fn inspect_result_push_alert_saturates_at_max() {
        let mut r = InspectResult::clean(SOURCE_PROFINET);
        let mut next_id = 1u64;
        let mut total = 0u64;
        for i in 0..MAX_ALERTS_PER_RESULT + 2 {
            r.push_alert(
                vs_types::AlertSeverity::Medium,
                SOURCE_PROFINET,
                i as u32,
                1000,
                &mut next_id,
                &mut total,
            );
        }
        assert_eq!(r.alert_count as usize, MAX_ALERTS_PER_RESULT);
        assert_eq!(total as usize, MAX_ALERTS_PER_RESULT);
        assert!(
            r.alerts_truncated,
            "excess alerts must set alerts_truncated"
        );
    }

    #[test]
    fn alerts_truncated_false_when_within_capacity() {
        let mut r = InspectResult::clean(SOURCE_MODBUS_TCP);
        let mut id = 1u64;
        let mut total = 0u64;
        for _ in 0..MAX_ALERTS_PER_RESULT {
            r.push_alert_with_code(
                vs_types::AlertSeverity::Medium,
                SOURCE_MODBUS_TCP,
                0,
                0,
                &mut id,
                &mut total,
                AlertCode::RateExceeded,
            );
        }
        assert!(!r.alerts_truncated);
        assert_eq!(r.alert_count as usize, MAX_ALERTS_PER_RESULT);
        // One more must flip the flag.
        r.push_alert_with_code(
            vs_types::AlertSeverity::High,
            SOURCE_MODBUS_TCP,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::WriteProtection,
        );
        assert!(r.alerts_truncated);
        // Count must not grow beyond capacity.
        assert_eq!(r.alert_count as usize, MAX_ALERTS_PER_RESULT);
    }

    #[test]
    fn inspect_result_clean_not_truncated() {
        let r = InspectResult::clean(SOURCE_DNP3);
        assert!(!r.alerts_truncated);
    }

    // -----------------------------------------------------------------------
    // Regression: encapsulated buffers stay in sync with their length field.
    //
    // The buffer/length fields on ModbusTcpFrame, ModbusRtuFrame, OpcUaMessage
    // and ProfinetFrame are pub(crate). The validated constructors and
    // set_* mutators must preserve the invariant
    // `*_len as usize <= MAX_*_LEN` and must clamp callers' oversized input.
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_tcp_set_pdu_within_limit_preserves_length() {
        let mut f = ModbusTcpFrame::default();
        let data = [0xAA; 10];
        f.set_pdu(&data);
        assert_eq!(f.pdu_len(), 10);
        assert_eq!(f.pdu().len(), 10);
        assert_eq!(f.pdu(), &data);
        assert!(!f.pdu_len_overflow());
    }

    #[test]
    fn modbus_tcp_set_pdu_clamps_oversize_input() {
        let mut f = ModbusTcpFrame::default();
        let big = [0xBBu8; MAX_MODBUS_PDU_LEN + 100];
        f.set_pdu(&big);
        assert_eq!(f.pdu_len() as usize, MAX_MODBUS_PDU_LEN);
        assert_eq!(f.pdu().len(), MAX_MODBUS_PDU_LEN);
        assert!(!f.pdu_len_overflow());
    }

    #[test]
    fn modbus_tcp_set_pdu_zeros_trailing_bytes() {
        let mut f = ModbusTcpFrame::default();
        // First, fill with a long PDU.
        let long = [0xFFu8; 200];
        f.set_pdu(&long);
        // Then overwrite with a shorter PDU.
        let short = [0x11u8; 4];
        f.set_pdu(&short);
        assert_eq!(f.pdu_len(), 4);
        // The tail beyond the new length must be zeroed so that a stale
        // previous payload cannot leak through.
        let raw = &f.pdu_data[..];
        for (i, byte) in raw.iter().enumerate().skip(4).take(20) {
            assert_eq!(
                *byte, 0,
                "stale byte at index {i} after set_pdu shorter overwrite"
            );
        }
    }

    #[test]
    fn modbus_tcp_with_pdu_validates() {
        let big = [0u8; MAX_MODBUS_PDU_LEN + 50];
        let f = ModbusTcpFrame::with_pdu(
            1,
            0,
            1,
            ModbusFunctionCode::ReadHoldingRegisters,
            0x03,
            0,
            0,
            &big,
            0,
        );
        assert_eq!(f.pdu_len() as usize, MAX_MODBUS_PDU_LEN);
        assert!(!f.pdu_len_overflow());
    }

    #[test]
    fn modbus_rtu_set_pdu_clamps_oversize_input() {
        let mut f = ModbusRtuFrame::default();
        let big = [0xCCu8; MAX_MODBUS_PDU_LEN + 32];
        f.set_pdu(&big);
        assert_eq!(f.pdu_len() as usize, MAX_MODBUS_PDU_LEN);
        assert!(!f.pdu_len_overflow());
    }

    #[test]
    fn opcua_set_endpoint_clamps_oversize_input() {
        let mut m = OpcUaMessage::default();
        let big = [b'a'; MAX_OPCUA_ENDPOINT_LEN + 10];
        m.set_endpoint(&big);
        assert_eq!(m.endpoint_len() as usize, MAX_OPCUA_ENDPOINT_LEN);
        assert_eq!(m.endpoint().len(), MAX_OPCUA_ENDPOINT_LEN);
        assert!(!m.endpoint_len_overflow());
    }

    #[test]
    fn opcua_set_endpoint_zeros_trailing_bytes() {
        let mut m = OpcUaMessage::default();
        m.set_endpoint(b"opc.tcp://server.example:4840/very/long/path");
        let len_before = m.endpoint_len() as usize;
        m.set_endpoint(b"short");
        assert_eq!(m.endpoint_len(), 5);
        // Tail beyond the new length must be zeroed.
        let raw = &m.endpoint[..];
        for (i, byte) in raw.iter().enumerate().take(len_before).skip(5) {
            assert_eq!(*byte, 0, "stale byte at index {i}");
        }
    }

    #[test]
    fn profinet_set_payload_clamps_oversize_input() {
        let mut f = ProfinetFrame::default();
        let big = [0xDDu8; MAX_PROFINET_PAYLOAD_LEN + 64];
        f.set_payload(&big);
        assert_eq!(f.payload_len() as usize, MAX_PROFINET_PAYLOAD_LEN);
        assert!(!f.payload_len_overflow());
    }

    #[test]
    fn profinet_set_payload_zeros_trailing_bytes() {
        let mut f = ProfinetFrame::default();
        let long = [0xAAu8; 100];
        f.set_payload(&long);
        let short = [0x55u8; 8];
        f.set_payload(&short);
        assert_eq!(f.payload_len(), 8);
        let raw = &f.payload[..];
        for (i, byte) in raw.iter().enumerate().take(50).skip(8) {
            assert_eq!(*byte, 0, "stale byte at index {i}");
        }
    }

    #[test]
    fn unchecked_setters_can_simulate_ffi_corruption() {
        // The __set_*_unchecked test helpers exist specifically to exercise
        // the defence-in-depth overflow path. They must still bypass the
        // validation, otherwise we cannot test the monitor's response to
        // malformed FFI input.
        let mut f = ModbusTcpFrame::default();
        f.__set_pdu_len_unchecked(u8::MAX);
        assert!(f.pdu_len_overflow());

        let mut m = OpcUaMessage::default();
        m.__set_endpoint_len_unchecked(u8::MAX);
        assert!(m.endpoint_len_overflow());

        let mut p = ProfinetFrame::default();
        p.__set_payload_len_unchecked(u16::MAX);
        assert!(p.payload_len_overflow());
    }

    // -----------------------------------------------------------------------
    // Regression: push_alert deny policy.
    //
    // Pushing a Critical or High alert must automatically flip
    // `allowed = false`, so the deny decision no longer relies on every
    // caller remembering to set `result.allowed = false` separately. Lower
    // severities must leave `allowed` untouched, and the explicit
    // `push_alert_blocking` variant must always deny.
    // -----------------------------------------------------------------------

    #[test]
    fn push_alert_high_flips_allowed_to_false() {
        let mut r = InspectResult::clean(SOURCE_MODBUS_TCP);
        assert!(r.allowed, "clean result starts allowed");
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert(
            vs_types::AlertSeverity::High,
            SOURCE_MODBUS_TCP,
            0,
            0,
            &mut id,
            &mut total,
        );
        assert!(!r.allowed, "pushing a High alert must clear `allowed`");
    }

    #[test]
    fn push_alert_critical_flips_allowed_to_false() {
        let mut r = InspectResult::clean(SOURCE_OPCUA);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert_with_code(
            vs_types::AlertSeverity::Critical,
            SOURCE_OPCUA,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::PolicyViolation,
        );
        assert!(!r.allowed, "pushing a Critical alert must clear `allowed`");
    }

    #[test]
    fn push_alert_medium_leaves_allowed_unchanged() {
        let mut r = InspectResult::clean(SOURCE_PROFINET);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert(
            vs_types::AlertSeverity::Medium,
            SOURCE_PROFINET,
            0,
            0,
            &mut id,
            &mut total,
        );
        assert!(r.allowed, "Medium alerts must not implicitly deny");
    }

    #[test]
    fn push_alert_low_leaves_allowed_unchanged() {
        let mut r = InspectResult::clean(SOURCE_DNP3);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert(
            vs_types::AlertSeverity::Low,
            SOURCE_DNP3,
            0,
            0,
            &mut id,
            &mut total,
        );
        assert!(r.allowed, "Low alerts must not implicitly deny");
    }

    #[test]
    fn push_alert_info_leaves_allowed_unchanged() {
        let mut r = InspectResult::clean(SOURCE_BACNET);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert(
            vs_types::AlertSeverity::Info,
            SOURCE_BACNET,
            0,
            0,
            &mut id,
            &mut total,
        );
        assert!(r.allowed, "Info alerts must not implicitly deny");
    }

    #[test]
    fn push_alert_blocking_denies_on_medium() {
        let mut r = InspectResult::clean(SOURCE_S7COMM);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert_blocking(
            vs_types::AlertSeverity::Medium,
            SOURCE_S7COMM,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::PolicyViolation,
        );
        assert!(
            !r.allowed,
            "push_alert_blocking must always clear `allowed`"
        );
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alert_codes[0], AlertCode::PolicyViolation);
    }

    #[test]
    fn push_alert_blocking_denies_on_info() {
        let mut r = InspectResult::clean(SOURCE_IEC60870);
        let mut id = 1u64;
        let mut total = 0u64;
        r.push_alert_blocking(
            vs_types::AlertSeverity::Info,
            SOURCE_IEC60870,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::PolicyViolation,
        );
        assert!(
            !r.allowed,
            "push_alert_blocking must deny even for Info severity"
        );
    }

    #[test]
    fn dropped_high_alert_still_flips_allowed() {
        // Fill the buffer with Medium alerts first so the eventual High
        // push lands on the truncation path. The deny policy must still
        // apply — truncation must never bypass a Critical/High deny.
        let mut r = InspectResult::clean(SOURCE_ETHERNETIP);
        let mut id = 1u64;
        let mut total = 0u64;
        for _ in 0..MAX_ALERTS_PER_RESULT {
            r.push_alert(
                vs_types::AlertSeverity::Medium,
                SOURCE_ETHERNETIP,
                0,
                0,
                &mut id,
                &mut total,
            );
        }
        assert!(
            r.allowed,
            "Medium-only alerts must keep result allowed before the deny push"
        );
        assert!(
            !r.alerts_truncated,
            "buffer was filled exactly, not exceeded"
        );

        // This High push is dropped, but the deny must still register.
        r.push_alert_with_code(
            vs_types::AlertSeverity::High,
            SOURCE_ETHERNETIP,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::WriteProtection,
        );
        assert!(
            r.alerts_truncated,
            "the excess alert must mark the result as truncated"
        );
        assert!(
            !r.allowed,
            "a truncated High alert must still flip `allowed = false`"
        );
    }

    #[test]
    fn dropped_critical_alert_still_flips_allowed() {
        let mut r = InspectResult::clean(SOURCE_DNP3);
        let mut id = 1u64;
        let mut total = 0u64;
        for _ in 0..MAX_ALERTS_PER_RESULT {
            r.push_alert(
                vs_types::AlertSeverity::Low,
                SOURCE_DNP3,
                0,
                0,
                &mut id,
                &mut total,
            );
        }
        r.push_alert_with_code(
            vs_types::AlertSeverity::Critical,
            SOURCE_DNP3,
            0,
            0,
            &mut id,
            &mut total,
            AlertCode::FloodAbuse,
        );
        assert!(r.alerts_truncated);
        assert!(
            !r.allowed,
            "a truncated Critical alert must still flip `allowed = false`"
        );
    }

    // -----------------------------------------------------------------------
    // RateBucket
    // -----------------------------------------------------------------------

    #[test]
    fn rate_bucket_empty() {
        let b = RateBucket::empty();
        assert!(!b.active);
        assert_eq!(b.tokens, 0);
    }

    #[test]
    fn rate_bucket_try_consume() {
        let mut b = RateBucket {
            key: 1,
            tokens: 3,
            capacity: 5,
            last_refill_us: 0,
            active: true,
            last_used: 0,
        };
        assert!(b.try_consume(0));
        assert!(b.try_consume(0));
        assert!(b.try_consume(0));
        assert!(!b.try_consume(0));
        // Refill after 1 second.
        assert!(b.try_consume(1_000_000));
    }

    #[test]
    fn rate_bucket_overflow_protection() {
        let mut b = RateBucket {
            key: 1,
            tokens: 0,
            capacity: 10,
            last_refill_us: 0,
            active: true,
            last_used: 0,
        };
        // Very large elapsed time should not overflow.
        assert!(b.try_consume(u64::MAX));
        assert_eq!(b.tokens, 9); // 10 refilled, 1 consumed
    }

    // -----------------------------------------------------------------------
    // EtherNet/IP frame
    // -----------------------------------------------------------------------

    #[test]
    fn ethernetip_frame_default() {
        let f = EtherNetIpFrame::default();
        assert_eq!(f.session_handle, 0);
        assert_eq!(f.command, 0);
        assert_eq!(f.payload_len, 0);
        assert!(!f.payload_len_overflow());
    }

    #[test]
    fn ethernetip_frame_valid_payload_len() {
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        assert_eq!(f.valid_payload_len(), MAX_ETHERNETIP_PAYLOAD_LEN);
        assert!(f.payload_len_overflow());
    }

    // -----------------------------------------------------------------------
    // DNP3 frame
    // -----------------------------------------------------------------------

    #[test]
    fn dnp3_frame_default() {
        let f = Dnp3Frame::default();
        assert_eq!(f.source_addr, 0);
        assert_eq!(f.dest_addr, 0);
        assert_eq!(f.function_code, 0);
        assert!(!f.payload_len_overflow());
    }

    #[test]
    fn dnp3_frame_valid_payload_len() {
        let f = Dnp3Frame {
            payload_len: 500,
            ..Default::default()
        };
        assert_eq!(f.valid_payload_len(), MAX_DNP3_PAYLOAD_LEN);
        assert!(f.payload_len_overflow());
    }

    // -----------------------------------------------------------------------
    // BACnet frame
    // -----------------------------------------------------------------------

    #[test]
    fn bacnet_frame_default() {
        let f = BacnetFrame::default();
        assert_eq!(f.service_choice, 0);
        assert_eq!(f.invoke_id, 0);
        assert!(!f.payload_len_overflow());
    }

    #[test]
    fn bacnet_frame_valid_payload_len() {
        let f = BacnetFrame {
            payload_len: 300,
            ..Default::default()
        };
        assert_eq!(f.valid_payload_len(), MAX_BACNET_PAYLOAD_LEN);
        assert!(f.payload_len_overflow());
    }

    #[test]
    fn protocol_bitmask_bacnet() {
        let combined = PROTO_MODBUS_TCP | PROTO_BACNET;
        assert_ne!(combined & PROTO_BACNET, 0);
        assert_eq!(combined & PROTO_OPCUA, 0);
    }

    #[test]
    fn alert_code_distinct_values() {
        assert_ne!(AlertCode::CrcFailure, AlertCode::WriteProtection);
        assert_ne!(AlertCode::ReplayDetected, AlertCode::RateExceeded);
        assert_eq!(AlertCode::Unspecified as u8, 0);
    }

    #[test]
    fn inspect_result_push_alert_with_code() {
        let mut r = InspectResult::clean(SOURCE_OPCUA);
        let mut next_id = 1u64;
        let mut total = 0u64;
        r.push_alert_with_code(
            vs_types::AlertSeverity::High,
            SOURCE_OPCUA,
            42,
            1000,
            &mut next_id,
            &mut total,
            AlertCode::ReplayDetected,
        );
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alert_codes[0], AlertCode::ReplayDetected);
        assert_eq!(r.alerts[0].id, 1);
    }

    #[test]
    fn dnp3_frame_sequence_number() {
        let f = Dnp3Frame {
            sequence_number: 7,
            ..Default::default()
        };
        assert_eq!(f.sequence_number, 7);
    }

    #[test]
    fn modbus_rtu_frame_fields() {
        let f = ModbusRtuFrame {
            slave_addr: 3,
            start_address: 50,
            quantity: 5,
            crc: 0xABCD,
            crc_provided: true,
            ..ModbusRtuFrame::default()
        };
        assert_eq!(f.slave_addr, 3);
        assert_eq!(f.crc, 0xABCD);
        assert!(f.crc_provided);
    }

    // -----------------------------------------------------------------------
    // Regression: RateBucket clock wraparound (M4).
    //
    // If `now_us < last_refill_us` (clock stepped backwards), the bucket
    // must resync to full capacity instead of freezing forever.
    // -----------------------------------------------------------------------
    #[test]
    fn rate_bucket_recovers_from_backwards_clock() {
        let mut b = RateBucket {
            key: 0,
            tokens: 1,
            capacity: 4,
            last_refill_us: 10_000_000,
            active: true,
            last_used: 0,
        };
        // Drain the bucket.
        assert!(b.try_consume(10_000_000));
        assert!(!b.try_consume(10_000_000));

        // Clock jumps backwards by 5 seconds (e.g. NTP step).
        // Previously this would saturate `elapsed` to 0 and deny forever.
        // Now it resyncs and refills to capacity.
        assert!(b.try_consume(5_000_000));
        assert_eq!(b.last_refill_us, 5_000_000);
    }

    #[test]
    fn rate_bucket_forward_refill_still_works() {
        let mut b = RateBucket {
            key: 0,
            tokens: 0,
            capacity: 10,
            last_refill_us: 0,
            active: true,
            last_used: 0,
        };
        // 1 second of elapsed time → refill to capacity.
        assert!(b.try_consume(1_000_000));
        // At least one token was consumed.
        assert!(b.tokens <= 9);
    }

    // -----------------------------------------------------------------------
    // AlertCode::code() — stable numeric identifiers
    // -----------------------------------------------------------------------

    #[test]
    fn alert_code_numeric_values_are_stable() {
        // These discriminants are stable across patch releases and documented
        // in the public API. Any change here must be a breaking semver bump.
        assert_eq!(AlertCode::Unspecified.code(), 0);
        assert_eq!(AlertCode::CrcFailure.code(), 1);
        assert_eq!(AlertCode::WriteProtection.code(), 2);
        assert_eq!(AlertCode::ReplayDetected.code(), 3);
        assert_eq!(AlertCode::RateExceeded.code(), 4);
        assert_eq!(AlertCode::FloodAbuse.code(), 5);
        assert_eq!(AlertCode::PolicyViolation.code(), 6);
        assert_eq!(AlertCode::UnknownFunctionCode.code(), 7);
        assert_eq!(AlertCode::DiagnosticBlocked.code(), 8);
        assert_eq!(AlertCode::EndpointBlocked.code(), 9);
        assert_eq!(AlertCode::SecurityModeViolation.code(), 10);
        assert_eq!(AlertCode::SessionAnomaly.code(), 11);
        assert_eq!(AlertCode::AlarmFlood.code(), 12);
        assert_eq!(AlertCode::SequenceAnomaly.code(), 13);
        assert_eq!(AlertCode::PayloadOverflow.code(), 14);
        assert_eq!(AlertCode::InvalidProtocol.code(), 15);
        assert_eq!(AlertCode::NoMatchingRule.code(), 16);
        assert_eq!(AlertCode::MessageTypeBlocked.code(), 17);
        assert_eq!(AlertCode::ProviderStateChange.code(), 18);
        assert_eq!(AlertCode::DcpBlocked.code(), 19);
        assert_eq!(AlertCode::MessageSizeExceeded.code(), 20);
        assert_eq!(AlertCode::AddressViolation.code(), 21);
        assert_eq!(AlertCode::UnknownSession.code(), 22);
        assert_eq!(AlertCode::ResourceExhausted.code(), 23);
        assert_eq!(AlertCode::ObjectAccessDenied.code(), 24);
        assert_eq!(AlertCode::CipServiceBlocked.code(), 25);
        // IEC 61850-9-2 Sampled-Values / GOOSE additions.
        assert_eq!(AlertCode::SvReplay.code(), 26);
        assert_eq!(AlertCode::SvRateAnomaly.code(), 27);
        assert_eq!(AlertCode::IedMismatch.code(), 28);
        assert_eq!(AlertCode::CbHijack.code(), 29);
        assert_eq!(AlertCode::RetransmissionAnomaly.code(), 30);
        assert_eq!(AlertCode::TimeSyncSpoofing.code(), 31);
        // v0.9 modbus-monitor-ind honesty-pass additions.
        assert_eq!(AlertCode::ClockRegression.code(), 32);
        assert_eq!(AlertCode::UnitNotAllowed.code(), 33);
        assert_eq!(AlertCode::InvalidUnitId.code(), 34);
        assert_eq!(AlertCode::TxIdReplay.code(), 35);
        // DNP3 / DNP3-SA additions.
        assert_eq!(AlertCode::BadLinkCrc.code(), 36);
        assert_eq!(AlertCode::TransportSeqAnomaly.code(), 37);
        assert_eq!(AlertCode::SaDowngrade.code(), 38);
        assert_eq!(AlertCode::IinFlagSpoofing.code(), 39);
        // BACnet BVLC / NPDU additions.
        assert_eq!(AlertCode::ForeignDevice.code(), 40);
        assert_eq!(AlertCode::NpduLoop.code(), 41);
        assert_eq!(AlertCode::BroadcastFlood.code(), 42);
    }

    #[test]
    fn alert_code_code_roundtrips_via_u8() {
        // Every variant's code() value must be unique (no two variants share
        // the same numeric identifier).
        let codes: [u8; 8] = [
            AlertCode::Unspecified.code(),
            AlertCode::CrcFailure.code(),
            AlertCode::WriteProtection.code(),
            AlertCode::ReplayDetected.code(),
            AlertCode::RateExceeded.code(),
            AlertCode::FloodAbuse.code(),
            AlertCode::PolicyViolation.code(),
            AlertCode::UnknownFunctionCode.code(),
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "duplicate code at indices {i} and {j}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // VULN-06: OpcUaSecurityMode discriminant ordering invariant.
    //
    // The OPC UA monitor enforces minimum security levels by casting
    // OpcUaSecurityMode to u8 and comparing numerically.  The variant
    // ordering (None=1 < Sign=2 < SignAndEncrypt=3) is a security invariant:
    // if the ordering were reversed, the minimum-mode check would accept
    // weaker security instead of rejecting it.
    //
    // The compile-time assertions in types-ind guarantee the ordering at
    // build time. These runtime tests document the expected values so that
    // any accidental reordering (e.g. via a `#[repr(u8)]` change) fails
    // both at compile time and in the test suite.
    // -----------------------------------------------------------------------

    #[test]
    fn vuln06_security_mode_discriminants_are_ordered_weakest_to_strongest() {
        let none = OpcUaSecurityMode::None as u8;
        let sign = OpcUaSecurityMode::Sign as u8;
        let sign_enc = OpcUaSecurityMode::SignAndEncrypt as u8;

        assert!(none < sign, "None must be weaker (smaller) than Sign");
        assert!(
            sign < sign_enc,
            "Sign must be weaker (smaller) than SignAndEncrypt"
        );
    }

    #[test]
    fn vuln06_security_mode_numeric_minimum_check_is_correct() {
        // Simulate the cast-and-compare pattern used by the OPC UA monitor:
        // `msg.security_mode as u8 >= min_mode as u8`
        let min_mode = OpcUaSecurityMode::Sign;

        // A message with None security should fail the minimum check.
        let mode_none = OpcUaSecurityMode::None;
        assert!(
            (mode_none as u8) < (min_mode as u8),
            "None must fail a Sign minimum requirement"
        );

        // A message with SignAndEncrypt should pass.
        let mode_enc = OpcUaSecurityMode::SignAndEncrypt;
        assert!(
            (mode_enc as u8) >= (min_mode as u8),
            "SignAndEncrypt must satisfy a Sign minimum requirement"
        );
    }

    // -----------------------------------------------------------------------
    // S7CommVariant / S7SessionType / S7commFrame
    // -----------------------------------------------------------------------

    #[test]
    fn s7_variant_round_trips_protocol_id() {
        assert_eq!(S7CommVariant::Classic.protocol_id(), 0x32);
        assert_eq!(S7CommVariant::Plus.protocol_id(), 0x72);
        assert_eq!(
            S7CommVariant::from_protocol_id(0x32),
            Some(S7CommVariant::Classic)
        );
        assert_eq!(
            S7CommVariant::from_protocol_id(0x72),
            Some(S7CommVariant::Plus)
        );
        assert_eq!(S7CommVariant::from_protocol_id(0x00), None);
    }

    #[test]
    fn s7_session_type_mask_is_a_single_bit_per_variant() {
        for st in [
            S7SessionType::Unknown,
            S7SessionType::Pg,
            S7SessionType::Hmi,
            S7SessionType::Op,
        ] {
            assert!(st.mask().is_power_of_two());
            assert_eq!(st.bit(), st as u8);
        }
    }

    #[test]
    fn s7comm_frame_default_carries_connection_and_variant_defaults() {
        let f = S7commFrame::default();
        assert_eq!(f.connection_id, 0);
        assert_eq!(f.s7_variant, S7CommVariant::Classic);
        assert_eq!(f.session_type, S7SessionType::Unknown);
        assert_eq!(f.pdu_type, S7commPduType::JobRequest);
        assert_eq!(f.function, S7commFunction::ReadVar);
        assert_eq!(f.pdu_ref, 0);
        assert_eq!(f.timestamp_us, 0);
    }

    #[test]
    fn s7comm_function_security_replaces_plc_stop_at_0x29() {
        // 0x29 is now classified as the Security function group, not PlcStop.
        assert_eq!(S7commFunction::from_u8(0x29), S7commFunction::Security);
        // Security counts as a write because key install / access-level
        // change mutate persistent device state.
        assert!(S7commFunction::Security.is_write());
        // bit 9 is reserved for Security in the fc_mask.
        assert_eq!(S7commFunction::Security.bit_index(), Some(9));
    }
}
