#![no_std]

//! Industrial automation type extensions for `Craton Shield`.
//!
//! Provides domain-specific types for IEC 62443 / IEC 61508 environments:
//! Modbus RTU/TCP, OPC UA, and PROFINET.
//!
//! Source-type constants cover additional protocol monitors
//! (EtherNet/IP, DNP3, `BACnet`, S7comm, IEC 60870-5-104, IEC 61850)
//! which are all implemented.

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
pub const PROTO_OPCUA: u16 = 1 << 2;
pub const PROTO_PROFINET: u16 = 1 << 3;
pub const PROTO_ETHERNETIP: u16 = 1 << 4;
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
#[derive(Debug, Clone, Copy)]
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
    /// PDU data bytes.
    pub pdu_data: [u8; MAX_MODBUS_PDU_LEN],
    /// Number of valid bytes in `pdu_data`.
    pub pdu_len: u8,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ModbusTcpFrame {
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
    pub fn pdu_len_overflow(&self) -> bool {
        (self.pdu_len as usize) > MAX_MODBUS_PDU_LEN
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
#[derive(Debug, Clone, Copy)]
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
    /// PDU data bytes.
    pub pdu_data: [u8; MAX_MODBUS_PDU_LEN],
    /// Number of valid bytes in `pdu_data`.
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
    /// Returns the PDU length clamped to [`MAX_MODBUS_PDU_LEN`].
    pub fn valid_pdu_len(&self) -> usize {
        if (self.pdu_len as usize) <= MAX_MODBUS_PDU_LEN {
            self.pdu_len as usize
        } else {
            MAX_MODBUS_PDU_LEN
        }
    }

    /// Returns `true` if `pdu_len` exceeds [`MAX_MODBUS_PDU_LEN`].
    pub fn pdu_len_overflow(&self) -> bool {
        (self.pdu_len as usize) > MAX_MODBUS_PDU_LEN
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
#[derive(Debug, Clone, Copy)]
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
    /// Endpoint URL (for Hello/OpenSecureChannel).
    pub endpoint: [u8; MAX_OPCUA_ENDPOINT_LEN],
    /// Number of valid bytes in `endpoint`.
    pub endpoint_len: u8,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl OpcUaMessage {
    /// Returns the endpoint length clamped to [`MAX_OPCUA_ENDPOINT_LEN`].
    pub fn valid_endpoint_len(&self) -> usize {
        if (self.endpoint_len as usize) <= MAX_OPCUA_ENDPOINT_LEN {
            self.endpoint_len as usize
        } else {
            MAX_OPCUA_ENDPOINT_LEN
        }
    }

    /// Returns `true` if `endpoint_len` exceeds [`MAX_OPCUA_ENDPOINT_LEN`].
    pub fn endpoint_len_overflow(&self) -> bool {
        (self.endpoint_len as usize) > MAX_OPCUA_ENDPOINT_LEN
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
#[derive(Debug, Clone, Copy)]
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
    /// Payload.
    pub payload: [u8; MAX_PROFINET_PAYLOAD_LEN],
    /// Payload length.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ProfinetFrame {
    /// Returns the payload length clamped to [`MAX_PROFINET_PAYLOAD_LEN`].
    pub fn valid_payload_len(&self) -> usize {
        if (self.payload_len as usize) <= MAX_PROFINET_PAYLOAD_LEN {
            self.payload_len as usize
        } else {
            MAX_PROFINET_PAYLOAD_LEN
        }
    }

    /// Returns `true` if `payload_len` exceeds [`MAX_PROFINET_PAYLOAD_LEN`].
    pub fn payload_len_overflow(&self) -> bool {
        (self.payload_len as usize) > MAX_PROFINET_PAYLOAD_LEN
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
    /// Payload data.
    pub payload: [u8; MAX_DNP3_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

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
}

impl Default for Dnp3Frame {
    fn default() -> Self {
        Self {
            source_addr: 0,
            dest_addr: 0,
            function_code: 0,
            sequence_number: 0,
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

/// A `BACnet` frame as seen by the IDS.
#[derive(Debug, Clone, Copy)]
pub struct BacnetFrame {
    /// Service choice (e.g., readProperty, writeProperty).
    pub service_choice: u8,
    /// Invoke ID for confirmed requests.
    pub invoke_id: u8,
    /// Payload data.
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
            payload: [0u8; MAX_BACNET_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
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
    pub allowed: bool,
    pub alert_count: u8,
    /// Which protocol produced this result.
    pub source_type: u8,
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
        ];
        for i in 0..sources.len() {
            for j in (i + 1)..sources.len() {
                assert_ne!(sources[i], sources[j]);
            }
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
}
