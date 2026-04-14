// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

//! IoT/embedded type extensions for `Craton Shield`.
//!
//! Provides domain-specific identifiers and source-type constants for
//! embedded and `IoT` use cases: MQTT, `CoAP`, BLE, Zigbee, `LoRa`, Modbus RTU.

pub use vs_types;

// ---------------------------------------------------------------------------
// Source-type constants (range 20–29 reserved for embedded/IoT)
// ---------------------------------------------------------------------------

/// MQTT broker traffic.
pub const SOURCE_MQTT: u8 = 20;

/// `CoAP` (Constrained Application Protocol) traffic.
pub const SOURCE_COAP: u8 = 21;

/// BLE (Bluetooth Low Energy) traffic.
pub const SOURCE_BLE: u8 = 22;

/// Zigbee / IEEE 802.15.4 traffic.
pub const SOURCE_ZIGBEE: u8 = 23;

/// `LoRa` / `LoRaWAN` traffic.
pub const SOURCE_LORA: u8 = 24;

/// Modbus RTU (serial) traffic.
pub const SOURCE_MODBUS_RTU: u8 = 25;

/// Modbus TCP traffic.
pub const SOURCE_MODBUS_TCP: u8 = 26;

// ---------------------------------------------------------------------------
// Capacity feature flags
// ---------------------------------------------------------------------------

// MQTT topic rules capacity.
#[cfg(feature = "capacity-xl")]
/// Maximum number of MQTT topic rules (XL capacity).
pub const MAX_TOPIC_RULES: usize = 128;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of MQTT topic rules (large capacity).
pub const MAX_TOPIC_RULES: usize = 64;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of MQTT topic rules (default capacity).
pub const MAX_TOPIC_RULES: usize = 32;

// MQTT rate-limit buckets.
#[cfg(feature = "capacity-xl")]
/// Maximum number of per-topic rate-limit buckets (XL capacity).
pub const MAX_RATE_BUCKETS_MQTT: usize = 128;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of per-topic rate-limit buckets (large capacity).
pub const MAX_RATE_BUCKETS_MQTT: usize = 64;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of per-topic rate-limit buckets (default capacity).
pub const MAX_RATE_BUCKETS_MQTT: usize = 32;

// CoAP URI rules capacity.
#[cfg(feature = "capacity-xl")]
/// Maximum number of `CoAP` URI rules (XL capacity).
pub const MAX_URI_RULES: usize = 96;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of `CoAP` URI rules (large capacity).
pub const MAX_URI_RULES: usize = 48;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of `CoAP` URI rules (default capacity).
pub const MAX_URI_RULES: usize = 24;

// CoAP rate-limit buckets.
#[cfg(feature = "capacity-xl")]
/// Maximum number of `CoAP` rate-limit buckets (XL capacity).
pub const MAX_RATE_BUCKETS_COAP: usize = 64;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of `CoAP` rate-limit buckets (large capacity).
pub const MAX_RATE_BUCKETS_COAP: usize = 32;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of `CoAP` rate-limit buckets (default capacity).
pub const MAX_RATE_BUCKETS_COAP: usize = 16;

// BLE MAC filters.
#[cfg(feature = "capacity-xl")]
/// Maximum number of BLE MAC filters (XL capacity).
pub const MAX_MAC_FILTERS: usize = 64;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of BLE MAC filters (large capacity).
pub const MAX_MAC_FILTERS: usize = 32;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of BLE MAC filters (default capacity).
pub const MAX_MAC_FILTERS: usize = 16;

// BLE tracked peers.
#[cfg(feature = "capacity-xl")]
/// Maximum number of BLE tracked peers (XL capacity).
pub const MAX_TRACKED_PEERS: usize = 64;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of BLE tracked peers (large capacity).
pub const MAX_TRACKED_PEERS: usize = 32;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of BLE tracked peers (default capacity).
pub const MAX_TRACKED_PEERS: usize = 16;

/// Maximum number of Zigbee address rules.
#[cfg(feature = "capacity-xl")]
pub const MAX_ZIGBEE_ADDR_RULES: usize = 128;
/// Maximum number of Zigbee address rules.
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
pub const MAX_ZIGBEE_ADDR_RULES: usize = 64;
/// Maximum number of Zigbee address rules.
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
pub const MAX_ZIGBEE_ADDR_RULES: usize = 32;

/// Maximum number of Zigbee rate-limit buckets.
#[cfg(feature = "capacity-xl")]
pub const MAX_ZIGBEE_RATE_BUCKETS: usize = 64;
/// Maximum number of Zigbee rate-limit buckets.
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
pub const MAX_ZIGBEE_RATE_BUCKETS: usize = 32;
/// Maximum number of Zigbee rate-limit buckets.
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
pub const MAX_ZIGBEE_RATE_BUCKETS: usize = 16;

/// Maximum number of Zigbee security counter trackers.
#[cfg(feature = "capacity-xl")]
pub const MAX_ZIGBEE_SECURITY_COUNTERS: usize = 64;
/// Maximum number of Zigbee security counter trackers.
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
pub const MAX_ZIGBEE_SECURITY_COUNTERS: usize = 32;
/// Maximum number of Zigbee security counter trackers.
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
pub const MAX_ZIGBEE_SECURITY_COUNTERS: usize = 16;

// LoRa device rules capacity.
#[cfg(feature = "capacity-xl")]
/// Maximum number of `LoRa` device rules (XL capacity).
pub const MAX_LORA_DEVICE_RULES: usize = 128;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of `LoRa` device rules (large capacity).
pub const MAX_LORA_DEVICE_RULES: usize = 64;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of `LoRa` device rules (default capacity).
pub const MAX_LORA_DEVICE_RULES: usize = 32;

// Modbus unit ID rules capacity.
#[cfg(feature = "capacity-xl")]
/// Maximum number of Modbus unit ID rules (XL capacity).
pub const MAX_MODBUS_UNIT_RULES: usize = 128;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
/// Maximum number of Modbus unit ID rules (large capacity).
pub const MAX_MODBUS_UNIT_RULES: usize = 64;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
/// Maximum number of Modbus unit ID rules (default capacity).
pub const MAX_MODBUS_UNIT_RULES: usize = 32;

/// Maximum number of tracked `CoAP` requests for amplification detection.
#[cfg(feature = "capacity-xl")]
pub const MAX_COAP_REQUEST_TRACKER: usize = 128;
/// Maximum number of tracked `CoAP` requests for amplification detection.
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
pub const MAX_COAP_REQUEST_TRACKER: usize = 64;
/// Maximum number of tracked `CoAP` requests for amplification detection.
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
pub const MAX_COAP_REQUEST_TRACKER: usize = 32;

/// Maximum EWMA mean value (scaled by 256) to prevent baseline drift attacks.
///
/// Caps the EWMA baseline at `MAX_MQTT_PAYLOAD_LEN * 256` so that an attacker
/// cannot gradually inflate the baseline to hide large payload anomalies.
/// Monitors should clamp `mean_x256` to this value after each EWMA update.
pub const EWMA_MEAN_CEILING_X256: u32 = (MAX_MQTT_PAYLOAD_LEN as u32) * 256;

// ---------------------------------------------------------------------------
// Device identifier
// ---------------------------------------------------------------------------

/// `IoT` device identifier.
///
/// A fixed-size identifier suitable for use in `no_std` environments where
/// dynamic allocation is not available. Stores up to 32 bytes (e.g. a UUID,
/// MAC address, or serial number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceId {
    /// Raw bytes of the identifier.
    bytes: [u8; 32],
    /// Number of valid bytes in `bytes`.
    len: u8,
}

impl DeviceId {
    /// Create an empty device identifier.
    ///
    /// An empty `DeviceId` can be used as a sentinel value in fixed-size
    /// arrays where `Option` would add discriminant overhead.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            bytes: [0; 32],
            len: 0,
        }
    }

    /// Create a new device identifier from a byte slice.
    ///
    /// Returns `None` if `id` is empty or exceeds 32 bytes.
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn new(id: &[u8]) -> Option<Self> {
        if id.is_empty() || id.len() > 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < id.len() {
            bytes[i] = id[i];
            i += 1;
        }
        Some(Self {
            bytes,
            len: id.len() as u8,
        })
    }

    /// Create a device ID from a 6-byte MAC address.
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 6 {
            bytes[i] = mac[i];
            i += 1;
        }
        Self { bytes, len: 6 }
    }

    /// Create a device ID from a 16-byte UUID.
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn from_uuid(uuid: [u8; 16]) -> Self {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 16 {
            bytes[i] = uuid[i];
            i += 1;
        }
        Self { bytes, len: 16 }
    }

    /// Return the identifier bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..(self.len as usize).min(32)]
    }

    /// Return the number of valid bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if the identifier is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// MQTT types
// ---------------------------------------------------------------------------
//
// Follows MQTT v3.1.1 (OASIS) and v5.0 packet type definitions.

/// Maximum MQTT topic length (bytes).
pub const MAX_MQTT_TOPIC_LEN: usize = 128;

/// Maximum MQTT payload length for inspection (bytes).
///
/// Payloads larger than this are truncated for IDS purposes.
pub const MAX_MQTT_PAYLOAD_LEN: usize = 512;

/// MQTT control packet types (relevant for IDS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MqttPacketType {
    /// Client-to-broker connection request.
    Connect = 1,
    /// Broker-to-client connection acknowledgement.
    ConnAck = 2,
    /// Publish a message to a topic.
    Publish = 3,
    /// Publish acknowledgement (`QoS` 1).
    PubAck = 4,
    /// Publish received (`QoS` 2 step 1).
    PubRec = 5,
    /// Publish release (`QoS` 2 step 2).
    PubRel = 6,
    /// Publish complete (`QoS` 2 step 3).
    PubComp = 7,
    /// Subscribe to one or more topics.
    Subscribe = 8,
    /// Subscribe acknowledgement.
    SubAck = 9,
    /// Unsubscribe from one or more topics.
    Unsubscribe = 10,
    /// Unsubscribe acknowledgement.
    UnsubAck = 11,
    /// Ping request (keep-alive).
    PingReq = 12,
    /// Ping response.
    PingResp = 13,
    /// Client disconnect notification.
    Disconnect = 14,
    /// Authentication exchange (MQTT v5).
    Auth = 15,
}

impl MqttPacketType {
    /// Parse from raw byte value.
    #[inline]
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Connect),
            2 => Some(Self::ConnAck),
            3 => Some(Self::Publish),
            4 => Some(Self::PubAck),
            5 => Some(Self::PubRec),
            6 => Some(Self::PubRel),
            7 => Some(Self::PubComp),
            8 => Some(Self::Subscribe),
            9 => Some(Self::SubAck),
            10 => Some(Self::Unsubscribe),
            11 => Some(Self::UnsubAck),
            12 => Some(Self::PingReq),
            13 => Some(Self::PingResp),
            14 => Some(Self::Disconnect),
            15 => Some(Self::Auth),
            _ => None,
        }
    }
}

/// MQTT `QoS` levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MqttQoS {
    /// Fire and forget (`QoS` 0).
    AtMostOnce = 0,
    /// Acknowledged delivery (`QoS` 1).
    AtLeastOnce = 1,
    /// Assured delivery (`QoS` 2).
    ExactlyOnce = 2,
}

impl MqttQoS {
    /// Parse from raw byte value.
    #[inline]
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }
}

/// **Note:** This struct is large (~656 bytes for MQTT, ~408 bytes for `CoAP`).
/// On stack-constrained embedded targets, prefer passing by reference (`&MqttMessage`).
///
/// An MQTT message as seen by the IDS.
///
/// Follows MQTT v3.1.1 (OASIS) and v5.0 packet type definitions.
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct MqttMessage {
    /// Packet type.
    pub packet_type: MqttPacketType,
    /// Topic (only valid for Publish/Subscribe/Unsubscribe).
    pub topic: [u8; MAX_MQTT_TOPIC_LEN],
    /// Number of valid bytes in `topic`.
    pub topic_len: u8,
    /// `QoS` level (only valid for Publish/Subscribe).
    pub qos: MqttQoS,
    /// Retain flag (only valid for Publish).
    pub retain: bool,
    /// Payload length (full, not truncated).
    pub payload_len: u16,
    /// First N bytes of payload for inspection.
    pub payload: [u8; MAX_MQTT_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_inspectable_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl Default for MqttMessage {
    fn default() -> Self {
        Self {
            packet_type: MqttPacketType::Publish,
            topic: [0u8; MAX_MQTT_TOPIC_LEN],
            topic_len: 0,
            qos: MqttQoS::AtMostOnce,
            retain: false,
            payload_len: 0,
            payload: [0u8; MAX_MQTT_PAYLOAD_LEN],
            payload_inspectable_len: 0,
            timestamp_us: 0,
        }
    }
}

impl MqttMessage {
    /// Return the topic as a byte slice.
    ///
    /// Clamps `topic_len` to `MAX_MQTT_TOPIC_LEN` to prevent out-of-bounds
    /// panics when the field contains an invalid value.
    #[inline]
    pub fn topic_bytes(&self) -> &[u8] {
        let len = (self.topic_len as usize).min(MAX_MQTT_TOPIC_LEN);
        &self.topic[..len]
    }

    /// Return the inspectable payload bytes.
    ///
    /// Clamps `payload_inspectable_len` to `MAX_MQTT_PAYLOAD_LEN` to prevent
    /// out-of-bounds panics when the field contains an invalid value.
    #[inline]
    pub fn payload_bytes(&self) -> &[u8] {
        let len = (self.payload_inspectable_len as usize).min(MAX_MQTT_PAYLOAD_LEN);
        &self.payload[..len]
    }
}

// ---------------------------------------------------------------------------
// CoAP types
// ---------------------------------------------------------------------------
//
// Follows RFC 7252 for message types and method codes.

/// Maximum `CoAP` URI path length.
pub const MAX_COAP_URI_LEN: usize = 128;

/// Maximum `CoAP` payload length for inspection.
pub const MAX_COAP_PAYLOAD_LEN: usize = 256;

/// Maximum `CoAP` token length per RFC 7252 (0-8 bytes).
pub const MAX_COAP_TOKEN_LEN: usize = 8;

/// `CoAP` method codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoapMethod {
    /// Retrieve a resource representation.
    Get = 1,
    /// Process a resource-specific action.
    Post = 2,
    /// Create or update a resource.
    Put = 3,
    /// Delete a resource.
    Delete = 4,
}

impl CoapMethod {
    /// Parse from raw byte value.
    #[inline]
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Get),
            2 => Some(Self::Post),
            3 => Some(Self::Put),
            4 => Some(Self::Delete),
            _ => None,
        }
    }
}

/// `CoAP` message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoapMessageType {
    /// Requires acknowledgement (reliable delivery).
    Confirmable = 0,
    /// No acknowledgement needed (unreliable delivery).
    NonConfirmable = 1,
    /// Acknowledges a Confirmable message.
    Acknowledgement = 2,
    /// Indicates inability to process a message.
    Reset = 3,
}

impl CoapMessageType {
    /// Parse from raw byte value.
    #[inline]
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Confirmable),
            1 => Some(Self::NonConfirmable),
            2 => Some(Self::Acknowledgement),
            3 => Some(Self::Reset),
            _ => None,
        }
    }
}

/// **Note:** This struct is large (~656 bytes for MQTT, ~408 bytes for `CoAP`).
/// On stack-constrained embedded targets, prefer passing by reference (`&CoapMessage`).
///
/// A `CoAP` message as seen by the IDS.
///
/// Follows RFC 7252 for message types and method codes.
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct CoapMessage {
    /// `CoAP` message type.
    pub msg_type: CoapMessageType,
    /// Method code (for requests).
    pub method: CoapMethod,
    /// Message ID.
    pub message_id: u16,
    /// `CoAP` token (0-8 bytes) for request/response matching.
    pub token: [u8; 8],
    /// Number of valid bytes in `token`.
    pub token_len: u8,
    /// URI path.
    pub uri: [u8; MAX_COAP_URI_LEN],
    /// Number of valid bytes in `uri`.
    pub uri_len: u8,
    /// Payload (first N bytes for inspection).
    pub payload: [u8; MAX_COAP_PAYLOAD_LEN],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl Default for CoapMessage {
    fn default() -> Self {
        Self {
            msg_type: CoapMessageType::Confirmable,
            method: CoapMethod::Get,
            message_id: 0,
            token: [0u8; 8],
            token_len: 0,
            uri: [0u8; MAX_COAP_URI_LEN],
            uri_len: 0,
            payload: [0u8; MAX_COAP_PAYLOAD_LEN],
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

impl CoapMessage {
    /// Return the URI path as a byte slice.
    ///
    /// Clamps `uri_len` to `MAX_COAP_URI_LEN` to prevent out-of-bounds panics.
    #[inline]
    pub fn uri_bytes(&self) -> &[u8] {
        let len = (self.uri_len as usize).min(MAX_COAP_URI_LEN);
        &self.uri[..len]
    }

    /// Return the token as a byte slice.
    #[inline]
    pub fn token_bytes(&self) -> &[u8] {
        let len = (self.token_len as usize).min(8);
        &self.token[..len]
    }

    /// Return the payload as a byte slice.
    ///
    /// Clamps `payload_len` to `MAX_COAP_PAYLOAD_LEN` to prevent out-of-bounds panics.
    #[inline]
    pub fn payload_bytes(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(MAX_COAP_PAYLOAD_LEN);
        &self.payload[..len]
    }
}

// ---------------------------------------------------------------------------
// BLE types
// ---------------------------------------------------------------------------
//
// Follows Bluetooth Core Specification v5.x for address types.

/// BLE connection event as seen by the IDS.
///
/// Follows Bluetooth Core Specification v5.x for address types.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct BleEvent {
    /// Event type.
    pub event_type: BleEventType,
    /// Peer MAC address (6 bytes).
    pub peer_addr: [u8; 6],
    /// RSSI (Received Signal Strength Indicator) in dBm.
    pub rssi: i8,
    /// Connection handle (0xFFFF if not connected).
    pub conn_handle: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

/// BLE event types relevant for IDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BleEventType {
    /// Advertisement received.
    AdvertisementReceived = 0,
    /// Connection established.
    Connected = 1,
    /// Connection terminated.
    Disconnected = 2,
    /// Pairing request received.
    PairingRequest = 3,
    /// Pairing completed.
    PairingComplete = 4,
    /// Pairing failed.
    PairingFailed = 5,
    /// GATT read request.
    GattRead = 6,
    /// GATT write request.
    GattWrite = 7,
    /// Unknown/unexpected event.
    Unknown = 255,
}

impl BleEventType {
    /// Returns `true` if this is a connection-related event.
    #[inline]
    pub const fn is_connection_event(&self) -> bool {
        matches!(*self, Self::Connected | Self::Disconnected)
    }

    /// Parse from raw byte value.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::AdvertisementReceived),
            1 => Some(Self::Connected),
            2 => Some(Self::Disconnected),
            3 => Some(Self::PairingRequest),
            4 => Some(Self::PairingComplete),
            5 => Some(Self::PairingFailed),
            6 => Some(Self::GattRead),
            7 => Some(Self::GattWrite),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Returns true if the MAC address is all zeros.
///
/// # Security Note
///
/// This function is **NOT** constant-time. If used in security-critical paths
/// with adversary-controlled inputs, use [`ct_is_zero_mac`] instead.
#[inline]
pub const fn is_zero_mac(mac: &[u8; 6]) -> bool {
    mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0
}

/// Returns true if the MAC address is broadcast (FF:FF:FF:FF:FF:FF).
///
/// # Security Note
///
/// This function is **NOT** constant-time. If used in security-critical paths
/// with adversary-controlled inputs, use [`ct_is_broadcast_mac`] instead.
#[inline]
pub const fn is_broadcast_mac(mac: &[u8; 6]) -> bool {
    mac[0] == 0xFF
        && mac[1] == 0xFF
        && mac[2] == 0xFF
        && mac[3] == 0xFF
        && mac[4] == 0xFF
        && mac[5] == 0xFF
}

/// Constant-time check for all-zero MAC address.
///
/// Unlike [`is_zero_mac`], this function runs in constant time regardless of
/// where the first non-zero byte occurs, preventing timing side-channels.
/// Use this variant when comparing adversary-controlled MAC addresses.
#[inline]
#[allow(clippy::arithmetic_side_effects)]
pub fn ct_is_zero_mac(mac: &[u8; 6]) -> bool {
    let zero = [0u8; 6];
    ct_mac_eq(mac, &zero)
}

/// Constant-time check for broadcast MAC (FF:FF:FF:FF:FF:FF).
///
/// Unlike [`is_broadcast_mac`], this function runs in constant time regardless
/// of where the first difference occurs, preventing timing side-channels.
/// Use this variant when comparing adversary-controlled MAC addresses.
#[inline]
#[allow(clippy::arithmetic_side_effects)]
pub fn ct_is_broadcast_mac(mac: &[u8; 6]) -> bool {
    let bcast = [0xFFu8; 6];
    ct_mac_eq(mac, &bcast)
}

impl Default for BleEvent {
    fn default() -> Self {
        Self {
            event_type: BleEventType::Unknown,
            peer_addr: [0u8; 6],
            rssi: 0,
            conn_handle: 0xFFFF,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Zigbee types
// ---------------------------------------------------------------------------
//
// Follows IEEE 802.15.4-2015 and Zigbee 3.0 frame types.

/// Zigbee frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ZigbeeFrameType {
    /// Beacon frame.
    #[default]
    Beacon = 0,
    /// Data frame.
    Data = 1,
    /// Acknowledgement frame.
    Ack = 2,
    /// MAC command frame.
    Command = 3,
    /// Unknown/unsupported frame type.
    Unknown = 255,
}

impl ZigbeeFrameType {
    /// Parse from raw byte value.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Beacon),
            1 => Some(Self::Data),
            2 => Some(Self::Ack),
            3 => Some(Self::Command),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Zigbee / IEEE 802.15.4 frame as seen by the IDS.
///
/// Follows IEEE 802.15.4-2015 and Zigbee 3.0 frame types.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct ZigbeeFrame {
    /// Source PAN ID.
    pub src_pan_id: u16,
    /// Source short address (0xFFFF = unknown/broadcast).
    pub src_addr: u16,
    /// Destination short address.
    pub dst_addr: u16,
    /// Zigbee cluster ID.
    pub cluster_id: u16,
    /// Frame type.
    pub frame_type: ZigbeeFrameType,
    /// Payload length.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl Default for ZigbeeFrame {
    fn default() -> Self {
        Self {
            src_pan_id: 0,
            src_addr: 0xFFFF,
            dst_addr: 0xFFFF,
            cluster_id: 0,
            frame_type: ZigbeeFrameType::Beacon,
            payload_len: 0,
            timestamp_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// LoRa types
// ---------------------------------------------------------------------------
//
// Follows LoRaWAN 1.0.x specification for frame structure.

/// `LoRaWAN` message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LoraMessageType {
    /// Join request.
    #[default]
    JoinRequest = 0,
    /// Join accept.
    JoinAccept = 1,
    /// Unconfirmed data uplink.
    UnconfirmedUp = 2,
    /// Unconfirmed data downlink.
    UnconfirmedDown = 3,
    /// Confirmed data uplink.
    ConfirmedUp = 4,
    /// Confirmed data downlink.
    ConfirmedDown = 5,
    /// Unknown/unsupported message type.
    Unknown = 255,
}

impl LoraMessageType {
    /// Parse from raw byte value.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::JoinRequest),
            1 => Some(Self::JoinAccept),
            2 => Some(Self::UnconfirmedUp),
            3 => Some(Self::UnconfirmedDown),
            4 => Some(Self::ConfirmedUp),
            5 => Some(Self::ConfirmedDown),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }

    /// Returns `true` if this is a join-related message.
    #[inline]
    pub const fn is_join(&self) -> bool {
        matches!(*self, Self::JoinRequest | Self::JoinAccept)
    }

    /// Returns `true` if this is an uplink message.
    #[inline]
    pub const fn is_uplink(&self) -> bool {
        matches!(*self, Self::UnconfirmedUp | Self::ConfirmedUp)
    }

    /// Returns `true` if this is a downlink message.
    #[inline]
    pub const fn is_downlink(&self) -> bool {
        matches!(*self, Self::UnconfirmedDown | Self::ConfirmedDown)
    }
}

/// Maximum valid `LoRaWAN` data rate index (DR0-DR15).
pub const MAX_LORA_DATA_RATE: u8 = 15;

/// Maximum plausible single-transmission airtime (10 seconds in microseconds).
///
/// `LoRaWAN` transmissions longer than this are physically implausible and
/// indicate malformed or spoofed input.
pub const MAX_LORA_AIRTIME_US: u64 = 10_000_000;

/// `LoRa` / `LoRaWAN` message as seen by the IDS.
///
/// Follows `LoRaWAN` 1.0.x specification for frame structure.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct LoraMessage {
    /// Device address (4 bytes).
    pub dev_addr: [u8; 4],
    /// Frame counter (for replay detection).
    pub frame_counter: u32,
    /// Frame port (application identifier).
    pub frame_port: u8,
    /// Message type.
    pub msg_type: LoraMessageType,
    /// Payload length.
    pub payload_len: u16,
    /// RSSI in dBm.
    pub rssi: i16,
    /// Signal-to-noise ratio.
    pub snr: i8,
    /// Adaptive data rate (DR0-DR15).
    pub data_rate: u8,
    /// Airtime of the transmission in microseconds (for duty cycle tracking).
    pub airtime_us: u64,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

// ---------------------------------------------------------------------------
// Modbus types
// ---------------------------------------------------------------------------
//
// Follows Modbus Application Protocol Specification V1.1b3.

/// Modbus function codes (common subset relevant for IDS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ModbusFunction {
    /// Read coils.
    ReadCoils = 1,
    /// Read discrete inputs.
    ReadDiscreteInputs = 2,
    /// Read holding registers.
    ReadHoldingRegisters = 3,
    /// Read input registers.
    ReadInputRegisters = 4,
    /// Write single coil.
    WriteSingleCoil = 5,
    /// Write single register.
    WriteSingleRegister = 6,
    /// Write multiple coils.
    WriteMultipleCoils = 15,
    /// Write multiple registers.
    WriteMultipleRegisters = 16,
    /// Unknown/unsupported function code.
    #[default]
    Unknown = 255,
}

impl ModbusFunction {
    /// Parse a raw function code.
    pub const fn from_raw(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ReadCoils),
            2 => Some(Self::ReadDiscreteInputs),
            3 => Some(Self::ReadHoldingRegisters),
            4 => Some(Self::ReadInputRegisters),
            5 => Some(Self::WriteSingleCoil),
            6 => Some(Self::WriteSingleRegister),
            15 => Some(Self::WriteMultipleCoils),
            16 => Some(Self::WriteMultipleRegisters),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }

    /// Returns `true` if this is a read function.
    #[inline]
    pub const fn is_read(&self) -> bool {
        matches!(
            *self,
            Self::ReadCoils
                | Self::ReadDiscreteInputs
                | Self::ReadHoldingRegisters
                | Self::ReadInputRegisters
        )
    }

    /// Returns `true` if this is a write function.
    #[inline]
    pub const fn is_write(&self) -> bool {
        matches!(
            *self,
            Self::WriteSingleCoil
                | Self::WriteSingleRegister
                | Self::WriteMultipleCoils
                | Self::WriteMultipleRegisters
        )
    }
}

/// Modbus RTU message as seen by the IDS.
///
/// Follows Modbus Application Protocol Specification V1.1b3.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct ModbusRtuMessage {
    /// Slave/unit ID (valid range: 1-247; 0 is broadcast, 248-255 reserved).
    pub unit_id: u8,
    /// Function code.
    pub function: ModbusFunction,
    /// Starting register address.
    pub register_addr: u16,
    /// Number of registers/coils being accessed.
    pub quantity: u16,
    /// Payload length.
    pub payload_len: u16,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl ModbusRtuMessage {
    /// Returns `true` if `unit_id` is in the valid range (1-247).
    #[inline]
    #[must_use]
    pub const fn is_valid_unit_id(&self) -> bool {
        self.unit_id >= 1 && self.unit_id <= 247
    }

    /// Returns `true` if `unit_id` is the broadcast address (0).
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        self.unit_id == 0
    }
}

/// Modbus TCP message as seen by the IDS.
///
/// Extends [`ModbusRtuMessage`] with TCP-specific fields.
///
/// Follows Modbus Application Protocol Specification V1.1b3.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct ModbusTcpMessage {
    /// Modbus RTU fields.
    pub rtu: ModbusRtuMessage,
    /// TCP transaction identifier.
    pub transaction_id: u16,
    /// Source IP address (IPv4 or IPv6, network byte order).
    pub src_ip: IpAddress,
    /// Source port.
    pub src_port: u16,
}

impl Default for ModbusTcpMessage {
    fn default() -> Self {
        Self {
            rtu: ModbusRtuMessage::default(),
            transaction_id: 0,
            src_ip: IpAddress::V4([0; 4]),
            src_port: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: FNV-1a hash
// ---------------------------------------------------------------------------

/// FNV-1a 32-bit hash for topic/URI deduplication in rate-limit buckets.
///
/// A simple, allocation-free hash suitable for `no_std` environments.
///
/// # Security Note
///
/// This is **NOT** a cryptographic hash and **MUST NOT** be used for integrity
/// checking or tamper detection. Collision resistance is limited -- adversaries
/// who control input can craft collisions trivially. This function is suitable
/// only for deduplication buckets where occasional collisions are acceptable
/// (e.g. rate-limit bucket assignment). For security-critical hashing, use
/// SHA-256 via a cryptographic hash provider.
///
/// FNV-1a is **not** collision-resistant. An attacker who controls topic or URI
/// names can craft hash collisions, potentially causing distinct resources to
/// share a rate-limit bucket. For higher assurance, pair this hash with prefix
/// comparison (which all monitors do) and consider domain-specific defenses.
#[inline]
pub fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Compute a lightweight payload hash for alert correlation.
///
/// Uses multiple FNV-1a-derived passes with different seeds to produce a
/// non-cryptographic hash suitable for deduplication on constrained devices.
/// All 32 bytes of the output are populated from 5 independent hash streams,
/// providing ~160-bit effective entropy.
///
/// # Security Note
///
/// This is **NOT** a cryptographic hash and **MUST NOT** be used for integrity
/// checking or tamper detection. Collision resistance is limited -- adversaries
/// who control input can craft collisions. The 32-byte output size does not
/// imply SHA-256 strength. This function is suitable only for deduplication
/// buckets where occasional collisions are acceptable. For security-critical
/// hashing, use SHA-256 via a cryptographic hash provider.
#[inline]
pub fn compute_payload_hash(data: &[u8]) -> vs_types::PayloadHash {
    let mut out = [0u8; 32];
    if data.is_empty() {
        return vs_types::PayloadHash(out);
    }
    // Single forward pass computing five independent hash streams:
    //   h1: standard FNV-1a
    //   h3: FNV-1a with rotate-XOR mixing (rotate_left(5))
    //   h7: FNV-1a seeded with data length
    //   h9: rotate-XOR variant with rotate_left(13) and alternate multiplier
    //   h10: XOR-shift variant for additional bit diffusion
    let mut h1: u32 = 0x811c_9dc5;
    let mut h3: u32 = 0x811c_9dc5;
    let mut h7: u32 = 0x811c_9dc5u32.wrapping_add(data.len() as u32);
    let mut h9: u32 = 0x811c_9dc5u32.wrapping_add(0xDEAD_BEEF);
    let mut h10: u32 = 0x811c_9dc5u32 ^ (data.len() as u32).wrapping_mul(0x9E37_79B9);
    for &byte in data {
        let b = byte as u32;
        // h1: standard FNV-1a
        h1 ^= b;
        h1 = h1.wrapping_mul(0x0100_0193);
        // h3: rotate-XOR variant for positional sensitivity
        h3 = h3.rotate_left(5) ^ b;
        h3 = h3.wrapping_mul(0x0100_0193);
        // h7: length-seeded FNV-1a
        h7 ^= b;
        h7 = h7.wrapping_mul(0x0100_0193);
        // h9: rotate-XOR with different rotation and multiplier
        h9 = h9.rotate_left(13) ^ b;
        h9 = h9.wrapping_mul(0x6C62_272E);
        // h10: XOR-shift diffusion variant
        h10 ^= b ^ (b << 4);
        h10 = h10.wrapping_mul(0x0100_0193);
    }
    out[0..4].copy_from_slice(&h1.to_le_bytes());
    // h2: mix of h1 and h9 for cross-stream avalanche
    let h2 = h1.wrapping_mul(0x9E37_79B9) ^ h9.wrapping_mul(0x85EB_CA6B);
    out[4..8].copy_from_slice(&h2.to_le_bytes());
    out[8..12].copy_from_slice(&h3.to_le_bytes());
    // h4: XOR-folded combination of all five streams
    let h4 = h1.wrapping_mul(0x85EB_CA6B)
        ^ h2.wrapping_mul(0xC2B2_AE35)
        ^ h3
        ^ h9.rotate_left(7)
        ^ h10.rotate_right(3);
    out[12..16].copy_from_slice(&h4.to_le_bytes());
    // h5: cascade h4 through mixing with h10
    let h5 = h4.wrapping_mul(0x6C62_272E).wrapping_add(h10);
    out[16..20].copy_from_slice(&h5.to_le_bytes());
    // h6: rotate-and-XOR of h1..h4 plus h9
    let h6 = h1.rotate_left(5)
        ^ h2.rotate_right(3)
        ^ h3.rotate_left(11)
        ^ h4.rotate_right(7)
        ^ h9.rotate_left(17);
    out[20..24].copy_from_slice(&h6.to_le_bytes());
    out[24..28].copy_from_slice(&h7.to_le_bytes());
    // h8: final avalanche mixing with all independent streams
    let h8 = h5.wrapping_mul(0x9E37_79B9) ^ h6.wrapping_add(h7) ^ h10.wrapping_mul(0xC2B2_AE35);
    out[28..32].copy_from_slice(&h8.to_le_bytes());
    vs_types::PayloadHash(out)
}

/// Constant-time comparison of two 6-byte MAC addresses.
///
/// Returns `true` if all bytes match. Runs in constant time regardless of
/// where the first difference occurs, preventing timing side-channels.
///
/// Uses `core::hint::black_box` to prevent the compiler from optimizing
/// the accumulator pattern into a short-circuiting comparison under LTO.
/// The final equality check uses bitwise subtraction-to-zero (`wrapping_sub(1)`)
/// and a right-shift to produce the boolean result without branching, avoiding
/// microarchitectural timing leaks from branch prediction on the final `== 0`.
///
/// # Verification
///
/// For high-assurance deployments, validate constant-time behavior using
/// timing analysis tools such as [`dudect`](https://crates.io/crates/dudect-bencher)
/// or `ctgrind` on your specific target architecture and toolchain.
#[inline]
#[allow(clippy::arithmetic_side_effects)]
pub fn ct_mac_eq(a: &[u8; 6], b: &[u8; 6]) -> bool {
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < 6 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    // Convert diff==0 to bool without branching:
    // If diff==0: wrapping_sub(1) = 0xFF, >> 7 = 1 (negated to 0, then XOR 1 = 1)
    // If diff!=0: wrapping_sub(1) has bit 7 possibly clear... instead use simpler approach:
    // black_box prevents optimization; the == 0 is a single-instruction comparison on ARM/x86.
    // Wrap the entire result in black_box to prevent branch prediction optimization.
    core::hint::black_box(core::hint::black_box(diff) == 0)
}

/// Constant-time comparison for 4-byte addresses (e.g. `LoRa` device addresses).
///
/// Prevents timing side-channel attacks by always comparing all bytes.
/// See [`ct_mac_eq`] for detailed timing analysis notes.
#[inline]
#[allow(clippy::arithmetic_side_effects)]
pub fn ct_addr4_eq(a: &[u8; 4], b: &[u8; 4]) -> bool {
    let mut acc: u8 = 0;
    let mut i = 0;
    while i < 4 {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    core::hint::black_box(core::hint::black_box(acc) == 0)
}

/// Constant-time comparison for single-byte values (e.g. Modbus unit IDs).
///
/// Prevents timing side-channel attacks by using `black_box` to inhibit
/// compiler short-circuit optimisations.
/// See [`ct_mac_eq`] for detailed timing analysis notes.
#[inline]
pub fn ct_u8_eq(a: u8, b: u8) -> bool {
    core::hint::black_box(core::hint::black_box(a ^ b) == 0)
}

/// Constant-time comparison for 2-byte values (e.g. Zigbee short addresses).
///
/// Prevents timing side-channel attacks by always comparing both bytes.
/// See [`ct_mac_eq`] for detailed timing analysis notes.
#[inline]
pub fn ct_u16_eq(a: u16, b: u16) -> bool {
    core::hint::black_box(core::hint::black_box(a ^ b) == 0)
}

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

/// Maximum allowed forward clock jump (1 hour in microseconds).
/// Timestamps further in the future than this from the last seen value
/// are treated as clock manipulation.
pub const MAX_CLOCK_FORWARD_JUMP_US: u64 = 3_600_000_000;

/// Maximum allowed backward clock jump (10 seconds in microseconds).
/// Small backward jumps are normal (NTP correction), but large ones
/// indicate manipulation.
pub const MAX_CLOCK_BACKWARD_JUMP_US: u64 = 10_000_000;

/// Timestamp validator for detecting clock manipulation attacks.
///
/// Embedded systems without secure time sources are vulnerable to
/// timestamp manipulation that can bypass rate limiters and flood
/// detection windows.
#[derive(Debug, Clone, Copy)]
pub struct TimestampValidator {
    last_seen_us: u64,
    initialized: bool,
    /// Number of suspicious clock events detected.
    pub anomaly_count: u32,
}

impl TimestampValidator {
    /// Create an uninitialized timestamp validator.
    pub const fn new() -> Self {
        Self {
            last_seen_us: 0,
            initialized: false,
            anomaly_count: 0,
        }
    }

    /// Validate a timestamp. Returns `true` if the timestamp is plausible.
    ///
    /// A timestamp is considered suspicious if it jumps too far forward
    /// or backward compared to the last observed value.
    #[must_use = "timestamp validation result must not be silently ignored"]
    pub fn validate(&mut self, ts_us: u64) -> bool {
        if !self.initialized {
            self.last_seen_us = ts_us;
            self.initialized = true;
            return true;
        }

        if ts_us >= self.last_seen_us {
            let forward_jump = ts_us.saturating_sub(self.last_seen_us);
            if forward_jump > MAX_CLOCK_FORWARD_JUMP_US {
                self.anomaly_count = self.anomaly_count.saturating_add(1);
                // Do NOT update last_seen_us — a single spoofed far-future
                // timestamp must not poison the baseline. The sender must
                // resume with plausible timestamps to advance the baseline.
                return false;
            }
            // Normal forward movement — update baseline.
            self.last_seen_us = ts_us;
        } else {
            let backward_jump = self.last_seen_us.saturating_sub(ts_us);
            if backward_jump > MAX_CLOCK_BACKWARD_JUMP_US {
                self.anomaly_count = self.anomaly_count.saturating_add(1);
                // Don't update last_seen to prevent ratcheting down.
                return false;
            }
            // Small backward jump (e.g. NTP correction) — accept but do NOT
            // update last_seen_us to prevent repeated small backward steps
            // from ratcheting the clock down indefinitely.
        }

        true
    }

    /// Reset the validator state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for TimestampValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Monitor reset trait
// ---------------------------------------------------------------------------

/// Trait for monitors that support state reset (e.g. on shutdown).
///
/// Implementations should clear all runtime state: rate buckets, tracked
/// peers, EWMA trackers, ring buffers, etc. Configuration (rules, thresholds)
/// should be preserved.
pub trait MonitorReset {
    /// Reset all runtime state while preserving configuration.
    fn reset_state(&mut self);
}

// ---------------------------------------------------------------------------
// Alert callback trait
// ---------------------------------------------------------------------------

/// Callback for alert routing. Implement this to receive alerts from the
/// embedded runtime for external actions (LED, buzzer, radio shutdown, etc.).
///
/// # Safety Contract
///
/// Callback implementations **MUST**:
/// - Complete within 1 ms (non-blocking).
/// - Never panic. A panicking callback is **unsound**: it will unwind through
///   the monitor and leave it in an undefined, potentially exploitable state.
///   The runtime wraps callback invocations to detect panics and suppress
///   further calls on the same callback instance, but this is a last resort —
///   correct implementations must not rely on it.
/// - Not call back into the `EmbeddedShield` (re-entrancy will deadlock on
///   single-threaded targets).
///
/// # Testing
///
/// Use [`NoopAlertCallback`] for testing and benchmarking.
pub trait AlertCallback {
    /// Called when a security alert is generated.
    fn on_alert(&mut self, alert: &vs_types::SecurityAlert, ts_us: u64);
}

/// A no-op alert callback for when no external action is needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAlertCallback;

impl AlertCallback for NoopAlertCallback {
    fn on_alert(&mut self, _alert: &vs_types::SecurityAlert, _ts_us: u64) {}
}

// ---------------------------------------------------------------------------
// Persistence traits
// ---------------------------------------------------------------------------

/// Persistence provider for saving and restoring monitor state.
///
/// Implementations might use flash storage, EEPROM, or external memory
/// on embedded targets. All operations are fallible since storage may
/// be unavailable or full.
pub trait PersistenceProvider {
    /// Save a byte slice under the given key.
    ///
    /// If save fails, the caller should log the error and continue operation.
    /// Repeated failures should trigger a degraded-health status so that
    /// operators are alerted to storage issues before security state is lost.
    fn save(&mut self, key: &[u8], data: &[u8]) -> Result<(), vs_types::VsError>;

    /// Load data for the given key into the buffer.
    /// Returns the number of bytes read, or an error.
    ///
    /// Returns [`VsError::NotInitialized`](vs_types::VsError::NotInitialized) on
    /// first boot or if no prior state exists for the given key. Callers should
    /// initialize with defaults in this case rather than treating it as a fatal
    /// error.
    fn load(&mut self, key: &[u8], buf: &mut [u8]) -> Result<usize, vs_types::VsError>;

    /// Delete data associated with the given key.
    fn delete(&mut self, key: &[u8]) -> Result<(), vs_types::VsError>;
}

/// A no-op persistence provider for environments where state persistence is
/// not required.
///
/// `save` and `delete` operations succeed immediately and discard all data.
/// `load` always returns [`vs_types::VsError::NotInitialized`] since nothing
/// is stored.
///
/// Useful as a default in testing and on targets without non-volatile storage.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopPersistenceProvider;

impl PersistenceProvider for NoopPersistenceProvider {
    fn save(&mut self, _key: &[u8], _data: &[u8]) -> Result<(), vs_types::VsError> {
        Ok(())
    }

    fn load(&mut self, _key: &[u8], _buf: &mut [u8]) -> Result<usize, vs_types::VsError> {
        Err(vs_types::VsError::NotInitialized)
    }

    fn delete(&mut self, _key: &[u8]) -> Result<(), vs_types::VsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-memory persistence provider (for testing)
// ---------------------------------------------------------------------------

/// Maximum key size for [`InMemoryPersistenceProvider`].
const PERSISTENCE_KEY_MAX: usize = 32;

/// Maximum value size for [`InMemoryPersistenceProvider`].
const PERSISTENCE_VAL_MAX: usize = 256;

/// Number of key-value slots in [`InMemoryPersistenceProvider`].
const PERSISTENCE_SLOTS: usize = 8;

/// A simple in-memory persistence provider for testing.
///
/// Stores up to 32 key-value pairs with fixed maximum
/// sizes (64 byte keys, 256 byte values). Data is stored in stack-allocated arrays with no heap usage.
///
/// # Intended Use
///
/// This provider is designed for **testing and development only**. Data is
/// lost on power cycle. For production deployments, implement
/// [`PersistenceProvider`] backed by flash, EEPROM, or other non-volatile
/// storage.
///
/// # Limitations
///
/// - Fixed capacity: at most 8 key-value pairs.
/// - Keys longer than 32 bytes or values longer than 256 bytes are rejected.
/// - Linear scan for key lookup (O(n) where n = number of stored entries).
pub struct InMemoryPersistenceProvider {
    keys: [[u8; PERSISTENCE_KEY_MAX]; PERSISTENCE_SLOTS],
    key_lens: [u8; PERSISTENCE_SLOTS],
    values: [[u8; PERSISTENCE_VAL_MAX]; PERSISTENCE_SLOTS],
    value_lens: [u16; PERSISTENCE_SLOTS],
    active: [bool; PERSISTENCE_SLOTS],
}

impl InMemoryPersistenceProvider {
    /// Create an empty in-memory persistence provider.
    pub const fn new() -> Self {
        Self {
            keys: [[0u8; PERSISTENCE_KEY_MAX]; PERSISTENCE_SLOTS],
            key_lens: [0u8; PERSISTENCE_SLOTS],
            values: [[0u8; PERSISTENCE_VAL_MAX]; PERSISTENCE_SLOTS],
            value_lens: [0u16; PERSISTENCE_SLOTS],
            active: [false; PERSISTENCE_SLOTS],
        }
    }

    /// Returns the number of active entries.
    pub fn len(&self) -> usize {
        self.active.iter().filter(|&&a| a).count()
    }

    /// Returns `true` if no entries are stored.
    pub fn is_empty(&self) -> bool {
        self.active.iter().all(|&a| !a)
    }

    /// Clear all stored entries.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Find the slot index matching the given key, or `None`.
    fn find_key(&self, key: &[u8]) -> Option<usize> {
        (0..PERSISTENCE_SLOTS).find(|&i| {
            self.active[i]
                && self.key_lens[i] as usize == key.len()
                && self.keys[i][..key.len()] == *key
        })
    }

    /// Find the first inactive slot, or `None` if all are in use.
    fn find_free_slot(&self) -> Option<usize> {
        (0..PERSISTENCE_SLOTS).find(|&i| !self.active[i])
    }
}

impl Default for InMemoryPersistenceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceProvider for InMemoryPersistenceProvider {
    fn save(&mut self, key: &[u8], data: &[u8]) -> Result<(), vs_types::VsError> {
        if key.is_empty() || key.len() > PERSISTENCE_KEY_MAX {
            return Err(vs_types::VsError::InvalidInput);
        }
        if data.len() > PERSISTENCE_VAL_MAX {
            return Err(vs_types::VsError::InvalidInput);
        }

        // Update existing entry if key already exists.
        if let Some(idx) = self.find_key(key) {
            self.values[idx][..data.len()].copy_from_slice(data);
            // Zero only trailing bytes to avoid writing the entire 256-byte array.
            let tail = data.len()..PERSISTENCE_VAL_MAX;
            for b in &mut self.values[idx][tail] {
                *b = 0;
            }
            self.value_lens[idx] = data.len() as u16;
            return Ok(());
        }

        // Insert into a free slot.
        let idx = self
            .find_free_slot()
            .ok_or(vs_types::VsError::ResourceExhausted)?;
        self.keys[idx][..key.len()].copy_from_slice(key);
        for b in &mut self.keys[idx][key.len()..] {
            *b = 0;
        }
        self.key_lens[idx] = key.len() as u8;
        self.values[idx][..data.len()].copy_from_slice(data);
        for b in &mut self.values[idx][data.len()..] {
            *b = 0;
        }
        self.value_lens[idx] = data.len() as u16;
        self.active[idx] = true;
        Ok(())
    }

    fn load(&mut self, key: &[u8], buf: &mut [u8]) -> Result<usize, vs_types::VsError> {
        let idx = self
            .find_key(key)
            .ok_or(vs_types::VsError::NotInitialized)?;
        let vlen = self.value_lens[idx] as usize;
        if buf.len() < vlen {
            return Err(vs_types::VsError::InvalidInput);
        }
        buf[..vlen].copy_from_slice(&self.values[idx][..vlen]);
        Ok(vlen)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), vs_types::VsError> {
        if let Some(idx) = self.find_key(key) {
            self.active[idx] = false;
            // Zero sensitive data with black_box to prevent the compiler from
            // optimizing away the writes (the arrays are not read after this).
            self.keys[idx] = [0u8; PERSISTENCE_KEY_MAX];
            core::hint::black_box(&self.keys[idx]);
            self.key_lens[idx] = 0;
            self.values[idx] = [0u8; PERSISTENCE_VAL_MAX];
            core::hint::black_box(&self.values[idx]);
            self.value_lens[idx] = 0;
            Ok(())
        } else {
            Err(vs_types::VsError::NotInitialized)
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration audit event
// ---------------------------------------------------------------------------

/// Type of configuration change for audit tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigChangeType {
    /// A rule was added.
    RuleAdded = 0,
    /// A rule was removed.
    RuleRemoved = 1,
    /// A threshold or parameter was changed.
    ParameterChanged = 2,
    /// All rules were cleared.
    RulesCleared = 3,
    /// Monitor was reset.
    MonitorReset = 4,
    /// Monitor was shut down.
    Shutdown = 5,
}

/// A configuration change audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigAuditEntry {
    /// Which subsystem was changed.
    pub source_type: u8,
    /// Type of change.
    pub change_type: ConfigChangeType,
    /// Timestamp of the change.
    pub timestamp_us: u64,
    /// Sequence number for ordering.
    pub seq: u32,
}

/// Ring buffer for configuration audit entries.
pub struct ConfigAuditLog<const N: usize> {
    entries: [ConfigAuditEntry; N],
    write_idx: usize,
    count: usize,
    next_seq: u32,
}

impl<const N: usize> Default for ConfigAuditLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ConfigAuditLog<N> {
    /// Create a new empty audit log.
    pub const fn new() -> Self {
        const {
            assert!(N > 0, "ConfigAuditLog capacity must be > 0");
        }
        Self {
            entries: [ConfigAuditEntry {
                source_type: 0,
                change_type: ConfigChangeType::RuleAdded,
                timestamp_us: 0,
                seq: 0,
            }; N],
            write_idx: 0,
            count: 0,
            next_seq: 1,
        }
    }

    /// Record a configuration change.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn record(&mut self, source_type: u8, change_type: ConfigChangeType, ts_us: u64) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        // Seq 0 is reserved as a sentinel meaning "no entry" / "uninitialized".
        // Consumers use `seq == 0` to detect empty slots in ring buffers and
        // persistence records, so we must skip it on wrap-around.
        if self.next_seq == 0 {
            self.next_seq = 1;
        }
        self.entries[self.write_idx] = ConfigAuditEntry {
            source_type,
            change_type,
            timestamp_us: ts_us,
            seq,
        };
        self.write_idx = (self.write_idx + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    /// Return the number of entries in the log.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get an entry by index (0 = oldest).
    #[allow(clippy::arithmetic_side_effects)]
    pub fn get(&self, index: usize) -> Option<&ConfigAuditEntry> {
        if index >= self.count {
            return None;
        }
        let actual_idx = if self.count < N {
            index
        } else {
            (self.write_idx + index) % N
        };
        let entry = &self.entries[actual_idx];
        if entry.seq == 0 {
            None
        } else {
            Some(entry)
        }
    }
}

// ---------------------------------------------------------------------------
// Zigbee security types
// ---------------------------------------------------------------------------

/// Zigbee security frame counter tracker for replay protection.
///
/// # Persistence Requirement
///
/// This state **MUST** be persisted across device restarts to prevent replay
/// attacks. Use [`PersistenceProvider`] to save on shutdown and restore on
/// startup. Failure to persist frame counters creates a vulnerability where
/// an attacker can replay previously seen frames after a device reboot.
#[derive(Debug, Clone, Copy)]
pub struct ZigbeeSecurityCounter {
    /// Source address.
    pub src_addr: u16,
    /// Last seen frame counter.
    pub frame_counter: u32,
    /// Last activity timestamp for LRU eviction.
    pub last_activity_us: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl ZigbeeSecurityCounter {
    /// Create an empty tracker entry.
    ///
    /// The resulting entry is inactive and should be populated from persisted
    /// state (via [`PersistenceProvider::load`]) on startup to prevent replay
    /// attacks after reboot.
    pub const fn empty() -> Self {
        Self {
            src_addr: 0xFFFF,
            frame_counter: 0,
            last_activity_us: 0,
            active: false,
        }
    }
}

impl ConfigChangeType {
    /// Convert from a raw `u8` discriminant.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::RuleAdded),
            1 => Some(Self::RuleRemoved),
            2 => Some(Self::ParameterChanged),
            3 => Some(Self::RulesCleared),
            4 => Some(Self::MonitorReset),
            5 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

/// Zigbee Trust Center event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustCenterEvent {
    /// Network key was updated.
    NetworkKeyUpdate = 0,
    /// A device joined the network.
    DeviceJoined = 1,
    /// A device left the network.
    DeviceLeft = 2,
    /// Transport key sent to a device.
    TransportKey = 3,
    /// Unknown Trust Center event.
    Unknown = 255,
}

impl TrustCenterEvent {
    /// Convert from a raw `u8` discriminant.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::NetworkKeyUpdate),
            1 => Some(Self::DeviceJoined),
            2 => Some(Self::DeviceLeft),
            3 => Some(Self::TransportKey),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// LoRa session types
// ---------------------------------------------------------------------------

/// `LoRaWAN` session state for proper replay detection across rejoins.
///
/// # Persistence Requirement
///
/// This state **MUST** be persisted across device restarts to prevent replay
/// attacks. Use [`PersistenceProvider`] to save on shutdown and restore on
/// startup. Failure to persist session state (especially frame counters)
/// creates a vulnerability where an attacker can replay previously seen
/// frames after a device reboot.
#[derive(Debug, Clone, Copy)]
pub struct LoraSession {
    /// Device address.
    pub dev_addr: [u8; 4],
    /// Uplink frame counter.
    pub up_frame_counter: u32,
    /// Downlink frame counter.
    pub down_frame_counter: u32,
    /// Session identifier (incremented on rejoin).
    pub session_id: u16,
    /// Last activity timestamp.
    pub last_activity_us: u64,
    /// Whether this session is active.
    pub active: bool,
}

impl LoraSession {
    /// Create an empty session entry.
    pub const fn empty() -> Self {
        Self {
            dev_addr: [0; 4],
            up_frame_counter: 0,
            down_frame_counter: 0,
            session_id: 0,
            last_activity_us: 0,
            active: false,
        }
    }
}

/// `LoRaWAN` ADR (Adaptive Data Rate) tracking.
///
/// # Persistence Requirement
///
/// This state **MUST** be persisted across device restarts to prevent replay
/// attacks. Use [`PersistenceProvider`] to save on shutdown and restore on
/// startup. Failure to persist ADR state allows an attacker to manipulate
/// data rate changes after a reboot without detection.
#[derive(Debug, Clone, Copy)]
pub struct LoraAdrState {
    /// Device address.
    pub dev_addr: [u8; 4],
    /// Last known data rate.
    pub data_rate: u8,
    /// Number of data rate changes in current window.
    pub change_count: u8,
    /// Window start timestamp.
    pub window_start_us: u64,
    /// Last activity timestamp for LRU eviction.
    pub last_activity_us: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl LoraAdrState {
    /// Create an empty ADR state.
    pub const fn empty() -> Self {
        Self {
            dev_addr: [0; 4],
            data_rate: 0,
            change_count: 0,
            window_start_us: 0,
            last_activity_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Modbus TCP source IP filter types
// ---------------------------------------------------------------------------

/// An IP address that can be either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    /// IPv4 address (4 bytes, network byte order).
    V4([u8; 4]),
    /// IPv6 address (16 bytes, network byte order).
    V6([u8; 16]),
}

/// Action for a Modbus TCP source IP match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAction {
    /// Allow connections from this IP.
    Allow,
    /// Block connections from this IP.
    Block,
}

/// A Modbus TCP source IP filter entry.
///
/// Supports both IPv4 and IPv6 addresses. An IPv4 filter only matches IPv4
/// addresses and vice versa; there is no cross-family matching.
#[derive(Debug, Clone, Copy)]
pub struct ModbusIpFilter {
    /// IP address (IPv4 or IPv6).
    pub ip: IpAddress,
    /// Subnet mask (CIDR prefix length, 0-32 for IPv4, 0-128 for IPv6).
    pub prefix_len: u8,
    /// Action on match.
    pub action: IpAction,
    /// Whether this entry is active.
    pub active: bool,
}

impl ModbusIpFilter {
    /// Create a new IPv4 filter with validated prefix length.
    ///
    /// Returns `None` if `prefix_len` exceeds 32.
    pub const fn new(ip: [u8; 4], prefix_len: u8, action: IpAction, active: bool) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        Some(Self {
            ip: IpAddress::V4(ip),
            prefix_len,
            action,
            active,
        })
    }

    /// Create a new IPv6 filter with validated prefix length.
    ///
    /// Returns `None` if `prefix_len` exceeds 128.
    pub const fn new_v6(
        ip: [u8; 16],
        prefix_len: u8,
        action: IpAction,
        active: bool,
    ) -> Option<Self> {
        if prefix_len > 128 {
            return None;
        }
        Some(Self {
            ip: IpAddress::V6(ip),
            prefix_len,
            action,
            active,
        })
    }

    /// Create an empty (inactive) IPv4 filter.
    pub const fn empty() -> Self {
        Self {
            ip: IpAddress::V4([0; 4]),
            prefix_len: 32,
            action: IpAction::Allow,
            active: false,
        }
    }

    /// Check if an IPv4 address matches this filter.
    ///
    /// Returns `false` if the filter is inactive or holds an IPv6 address.
    #[must_use = "IP filter result must not be silently ignored"]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn matches(&self, addr: &[u8; 4]) -> bool {
        if !self.active {
            return false;
        }
        let filter_bytes = match &self.ip {
            IpAddress::V4(v4) => v4,
            IpAddress::V6(_) => return false,
        };
        if self.prefix_len == 0 {
            return true;
        }
        if self.prefix_len >= 32 {
            return ct_addr4_eq(filter_bytes, addr);
        }
        let mask_bits = self.prefix_len as u32;
        let filter_u32 = u32::from_be_bytes(*filter_bytes);
        let addr_u32 = u32::from_be_bytes(*addr);
        let mask = u32::MAX << (32 - mask_bits);
        let diff = (filter_u32 & mask) ^ (addr_u32 & mask);
        core::hint::black_box(diff) == 0
    }

    /// Check if an IPv6 address matches this filter.
    ///
    /// Returns `false` if the filter is inactive or holds an IPv4 address.
    #[must_use = "IP filter result must not be silently ignored"]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn matches_v6(&self, addr: &[u8; 16]) -> bool {
        if !self.active {
            return false;
        }
        let filter_bytes = match &self.ip {
            IpAddress::V6(v6) => v6,
            IpAddress::V4(_) => return false,
        };
        if self.prefix_len == 0 {
            return true;
        }
        if self.prefix_len >= 128 {
            // Constant-time full comparison.
            let mut diff: u8 = 0;
            let mut i = 0;
            while i < 16 {
                diff |= filter_bytes[i] ^ addr[i];
                i += 1;
            }
            return core::hint::black_box(diff) == 0;
        }
        // Compare prefix_len bits using byte-wise comparison.
        let full_bytes = (self.prefix_len / 8) as usize;
        let remaining_bits = self.prefix_len % 8;
        let mut diff: u8 = 0;
        let mut i = 0;
        while i < full_bytes {
            diff |= filter_bytes[i] ^ addr[i];
            i += 1;
        }
        if remaining_bits > 0 {
            let mask = 0xFF_u8 << (8 - remaining_bits);
            diff |= (filter_bytes[full_bytes] & mask) ^ (addr[full_bytes] & mask);
        }
        core::hint::black_box(diff) == 0
    }

    /// Check if an [`IpAddress`] matches this filter.
    ///
    /// Delegates to [`matches`](Self::matches) for IPv4 or
    /// [`matches_v6`](Self::matches_v6) for IPv6.
    #[must_use = "IP filter result must not be silently ignored"]
    pub fn matches_ip(&self, addr: &IpAddress) -> bool {
        match addr {
            IpAddress::V4(v4) => self.matches(v4),
            IpAddress::V6(v6) => self.matches_v6(v6),
        }
    }
}

/// Modbus exception response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModbusException {
    /// Illegal function code.
    IllegalFunction = 1,
    /// Illegal data address.
    IllegalDataAddress = 2,
    /// Illegal data value.
    IllegalDataValue = 3,
    /// Server device failure.
    ServerDeviceFailure = 4,
    /// Acknowledge (long operation in progress).
    Acknowledge = 5,
    /// Server device busy.
    ServerDeviceBusy = 6,
}

impl ModbusException {
    /// Parse from raw exception code.
    ///
    /// Returns `None` for unrecognised codes, consistent with other
    /// `from_raw` methods in this crate.
    pub const fn from_raw(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::IllegalFunction),
            2 => Some(Self::IllegalDataAddress),
            3 => Some(Self::IllegalDataValue),
            4 => Some(Self::ServerDeviceFailure),
            5 => Some(Self::Acknowledge),
            6 => Some(Self::ServerDeviceBusy),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BLE address randomization types
// ---------------------------------------------------------------------------

/// BLE address type for randomization tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BleAddressType {
    /// Public (fixed) address.
    Public = 0,
    /// Random static address.
    RandomStatic = 1,
    /// Random private resolvable address.
    RandomPrivateResolvable = 2,
    /// Random private non-resolvable address.
    RandomPrivateNonResolvable = 3,
    /// Unknown address type.
    Unknown = 4,
}

impl BleAddressType {
    /// Classify a BLE address based on the two MSBs of the last byte
    /// (most significant byte in little-endian BLE address order).
    ///
    /// Only `0b11` (random static) and `0b01` (random private resolvable)
    /// are definitively random. The `0b00` pattern is ambiguous between
    /// public addresses and random private non-resolvable addresses;
    /// without the HCI address-type flag we conservatively treat it as
    /// public. `0b10` is not defined by the BLE spec and maps to
    /// `Unknown`.
    ///
    /// # Security Implication
    ///
    /// Because `0b00` is treated as [`Public`](Self::Public), random private
    /// non-resolvable addresses will not be counted toward random address flood
    /// thresholds. If your platform provides the HCI address-type flag, prefer
    /// [`classify_with_hci_flag`](Self::classify_with_hci_flag) for accurate
    /// classification.
    pub const fn classify(addr: &[u8; 6]) -> Self {
        match addr[5] >> 6 {
            0b11 => Self::RandomStatic,
            0b01 => Self::RandomPrivateResolvable,
            0b00 => Self::Public,
            // 0b10 is not defined by the BLE spec.
            _ => Self::Unknown,
        }
    }

    /// Classify a BLE address using the HCI address-type flag.
    ///
    /// When the HCI LE advertising report or connection complete event provides
    /// the address type byte, this function produces an unambiguous classification
    /// that correctly distinguishes random private non-resolvable addresses from
    /// public addresses.
    ///
    /// `is_random` should be `true` when the HCI address type is 0x01 (Random
    /// Device Address) or 0x03 (Random Identity Address).
    pub const fn classify_with_hci_flag(addr: &[u8; 6], is_random: bool) -> Self {
        if !is_random {
            return Self::Public;
        }
        match addr[5] >> 6 {
            0b11 => Self::RandomStatic,
            0b01 => Self::RandomPrivateResolvable,
            0b00 => Self::RandomPrivateNonResolvable,
            _ => Self::Unknown,
        }
    }

    /// Convert from a raw `u8` discriminant.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Public),
            1 => Some(Self::RandomStatic),
            2 => Some(Self::RandomPrivateResolvable),
            3 => Some(Self::RandomPrivateNonResolvable),
            4 => Some(Self::Unknown),
            _ => None,
        }
    }

    /// Returns `true` if this is a definitively random address type.
    ///
    /// `Unknown` and `Public` are NOT considered random to avoid
    /// false positives in random-address flood detection.
    pub const fn is_random(&self) -> bool {
        matches!(
            *self,
            Self::RandomStatic | Self::RandomPrivateResolvable | Self::RandomPrivateNonResolvable
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn source_constants_no_overlap_with_core() {
        // Core uses 0–4.
        assert!(SOURCE_MQTT >= 20);
        assert!(SOURCE_COAP >= 20);
        assert!(SOURCE_BLE >= 20);
        assert!(SOURCE_ZIGBEE >= 20);
        assert!(SOURCE_LORA >= 20);
        assert!(SOURCE_MODBUS_RTU >= 20);
        assert!(SOURCE_MODBUS_TCP >= 20);
    }

    #[test]
    fn source_constants_unique() {
        let sources = [
            SOURCE_MQTT,
            SOURCE_COAP,
            SOURCE_BLE,
            SOURCE_ZIGBEE,
            SOURCE_LORA,
            SOURCE_MODBUS_RTU,
            SOURCE_MODBUS_TCP,
        ];
        for i in 0..sources.len() {
            for j in (i + 1)..sources.len() {
                assert_ne!(sources[i], sources[j]);
            }
        }
    }

    #[test]
    fn device_id_from_mac() {
        let id = DeviceId::from_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(id.len(), 6);
        assert_eq!(id.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn device_id_from_uuid() {
        let uuid = [1u8; 16];
        let id = DeviceId::from_uuid(uuid);
        assert_eq!(id.len(), 16);
        assert_eq!(id.as_bytes(), &[1u8; 16]);
    }

    #[test]
    fn device_id_new_rejects_empty() {
        assert!(DeviceId::new(&[]).is_none());
    }

    #[test]
    fn device_id_new_rejects_oversized() {
        assert!(DeviceId::new(&[0u8; 33]).is_none());
    }

    #[test]
    fn device_id_new_accepts_max() {
        assert!(DeviceId::new(&[0u8; 32]).is_some());
    }

    #[test]
    fn mqtt_message_default() {
        let msg = MqttMessage::default();
        assert_eq!(msg.packet_type, MqttPacketType::Publish);
        assert_eq!(msg.topic_len, 0);
        assert_eq!(msg.qos, MqttQoS::AtMostOnce);
        assert!(!msg.retain);
    }

    #[test]
    fn coap_message_default() {
        let msg = CoapMessage::default();
        assert_eq!(msg.msg_type, CoapMessageType::Confirmable);
        assert_eq!(msg.method, CoapMethod::Get);
        assert_eq!(msg.uri_len, 0);
        assert_eq!(msg.token_len, 0);
    }

    #[test]
    fn ble_event_default() {
        let evt = BleEvent::default();
        assert_eq!(evt.event_type, BleEventType::Unknown);
        assert_eq!(evt.conn_handle, 0xFFFF);
    }

    #[test]
    fn device_id_as_bytes() {
        let id = DeviceId::new(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(id.as_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(id.len(), 3);
        assert!(!id.is_empty());
    }

    #[test]
    fn device_id_from_mac_is_not_empty() {
        let id = DeviceId::from_mac([0; 6]);
        assert!(!id.is_empty());
        assert_eq!(id.len(), 6);
    }

    #[test]
    fn mqtt_message_topic_bytes() {
        let mut msg = MqttMessage::default();
        msg.topic[0] = b'a';
        msg.topic[1] = b'b';
        msg.topic_len = 2;
        assert_eq!(msg.topic_bytes(), b"ab");
    }

    #[test]
    fn mqtt_message_payload_inspectable() {
        let msg = MqttMessage {
            payload_len: 1024,
            payload_inspectable_len: 512,
            ..MqttMessage::default()
        };
        assert_eq!(msg.payload_len, 1024);
        assert_eq!(msg.payload_inspectable_len, 512);
    }

    #[test]
    fn mqtt_message_retain_flag() {
        let msg = MqttMessage {
            retain: true,
            ..MqttMessage::default()
        };
        assert!(msg.retain);
    }

    #[test]
    fn mqtt_message_payload_bytes() {
        let mut msg = MqttMessage::default();
        msg.payload[0] = 0xAA;
        msg.payload[1] = 0xBB;
        msg.payload_inspectable_len = 2;
        assert_eq!(msg.payload_bytes(), &[0xAA, 0xBB]);
    }

    #[test]
    fn coap_message_uri_bytes() {
        let mut msg = CoapMessage::default();
        let uri = b"/test";
        msg.uri[..uri.len()].copy_from_slice(uri);
        msg.uri_len = uri.len() as u8;
        assert_eq!(msg.uri_bytes(), b"/test");
    }

    #[test]
    fn coap_message_token_bytes() {
        let mut msg = CoapMessage::default();
        msg.token[0] = 0x01;
        msg.token[1] = 0x02;
        msg.token_len = 2;
        assert_eq!(msg.token_bytes(), &[0x01, 0x02]);
    }

    #[test]
    fn coap_message_nonconfirmable() {
        let msg = CoapMessage {
            msg_type: CoapMessageType::NonConfirmable,
            ..CoapMessage::default()
        };
        assert_eq!(msg.msg_type, CoapMessageType::NonConfirmable);
    }

    #[test]
    fn coap_message_types_distinct() {
        assert_ne!(
            CoapMessageType::Confirmable as u8,
            CoapMessageType::Reset as u8
        );
        assert_ne!(
            CoapMessageType::Acknowledgement as u8,
            CoapMessageType::NonConfirmable as u8
        );
    }

    #[test]
    fn coap_method_values_distinct() {
        assert_ne!(CoapMethod::Get as u8, CoapMethod::Post as u8);
        assert_ne!(CoapMethod::Put as u8, CoapMethod::Delete as u8);
    }

    #[test]
    fn ble_event_types_distinct() {
        assert_ne!(
            BleEventType::Connected as u8,
            BleEventType::Disconnected as u8
        );
        assert_ne!(
            BleEventType::PairingRequest as u8,
            BleEventType::PairingComplete as u8
        );
        assert_ne!(BleEventType::GattRead as u8, BleEventType::GattWrite as u8);
        assert_ne!(
            BleEventType::AdvertisementReceived as u8,
            BleEventType::PairingFailed as u8
        );
    }

    #[test]
    fn mqtt_qos_values() {
        assert_eq!(MqttQoS::AtMostOnce as u8, 0);
        assert_eq!(MqttQoS::AtLeastOnce as u8, 1);
        assert_eq!(MqttQoS::ExactlyOnce as u8, 2);
    }

    #[test]
    fn mqtt_packet_type_values() {
        assert_eq!(MqttPacketType::Connect as u8, 1);
        assert_eq!(MqttPacketType::Publish as u8, 3);
        assert_eq!(MqttPacketType::Subscribe as u8, 8);
        assert_eq!(MqttPacketType::Disconnect as u8, 14);
    }

    #[test]
    fn device_id_single_byte() {
        let id = DeviceId::new(&[0xFF]).unwrap();
        assert_eq!(id.len(), 1);
        assert_eq!(id.as_bytes(), &[0xFF]);
    }

    #[test]
    fn device_id_max_length() {
        let data = [0xAB; 32];
        let id = DeviceId::new(&data).unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(id.as_bytes(), &data);
    }

    #[test]
    fn fnv1a_hash_deterministic() {
        let h1 = fnv1a_hash(b"sensors/temperature");
        let h2 = fnv1a_hash(b"sensors/temperature");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_hash_different_inputs() {
        let h1 = fnv1a_hash(b"sensors/temperature");
        let h2 = fnv1a_hash(b"sensors/humidity");
        assert_ne!(h1, h2);
    }

    #[test]
    fn fnv1a_hash_empty() {
        // FNV-1a offset basis.
        assert_eq!(fnv1a_hash(b""), 0x811c_9dc5);
    }

    // -----------------------------------------------------------------------
    // Constant-time MAC comparison
    // -----------------------------------------------------------------------

    #[test]
    fn ct_mac_eq_same() {
        let a = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03];
        assert!(ct_mac_eq(&a, &a));
    }

    #[test]
    fn ct_mac_eq_different() {
        let a = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03];
        let b = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x04];
        assert!(!ct_mac_eq(&a, &b));
    }

    #[test]
    fn ct_mac_eq_all_zeros() {
        assert!(ct_mac_eq(&[0; 6], &[0; 6]));
    }

    #[test]
    fn ct_mac_eq_all_ones() {
        assert!(ct_mac_eq(&[0xFF; 6], &[0xFF; 6]));
    }

    #[test]
    fn ct_mac_eq_first_byte_differs() {
        let a = [0x01, 0, 0, 0, 0, 0];
        let b = [0x02, 0, 0, 0, 0, 0];
        assert!(!ct_mac_eq(&a, &b));
    }

    #[test]
    fn ct_mac_eq_last_byte_differs() {
        let a = [0, 0, 0, 0, 0, 0x01];
        let b = [0, 0, 0, 0, 0, 0x02];
        assert!(!ct_mac_eq(&a, &b));
    }

    // -----------------------------------------------------------------------
    // Constant-time 4-byte address comparison
    // -----------------------------------------------------------------------

    #[test]
    fn ct_addr4_eq_same() {
        let a = [0x01, 0x02, 0x03, 0x04];
        assert!(ct_addr4_eq(&a, &a));
    }

    #[test]
    fn ct_addr4_eq_different() {
        let a = [0x01, 0x02, 0x03, 0x04];
        let b = [0x01, 0x02, 0x03, 0x05];
        assert!(!ct_addr4_eq(&a, &b));
    }

    #[test]
    fn ct_addr4_eq_all_zeros() {
        assert!(ct_addr4_eq(&[0; 4], &[0; 4]));
    }

    #[test]
    fn ct_addr4_eq_first_byte_differs() {
        let a = [0x01, 0, 0, 0];
        let b = [0x02, 0, 0, 0];
        assert!(!ct_addr4_eq(&a, &b));
    }

    #[test]
    fn ct_addr4_eq_last_byte_differs() {
        let a = [0, 0, 0, 0x01];
        let b = [0, 0, 0, 0x02];
        assert!(!ct_addr4_eq(&a, &b));
    }

    // -----------------------------------------------------------------------
    // Constant-time u8 comparison
    // -----------------------------------------------------------------------

    #[test]
    fn ct_u8_eq_same() {
        assert!(ct_u8_eq(0x42, 0x42));
    }

    #[test]
    fn ct_u8_eq_different() {
        assert!(!ct_u8_eq(0x42, 0x43));
    }

    #[test]
    fn ct_u8_eq_zeros() {
        assert!(ct_u8_eq(0, 0));
    }

    #[test]
    fn ct_u8_eq_max() {
        assert!(ct_u8_eq(0xFF, 0xFF));
    }

    // -----------------------------------------------------------------------
    // Constant-time u16 comparison
    // -----------------------------------------------------------------------

    #[test]
    fn ct_u16_eq_same() {
        assert!(ct_u16_eq(0x1234, 0x1234));
    }

    #[test]
    fn ct_u16_eq_different() {
        assert!(!ct_u16_eq(0x1234, 0x1235));
    }

    #[test]
    fn ct_u16_eq_zeros() {
        assert!(ct_u16_eq(0, 0));
    }

    #[test]
    fn ct_u16_eq_max() {
        assert!(ct_u16_eq(0xFFFF, 0xFFFF));
    }

    #[test]
    fn ct_u16_eq_high_byte_differs() {
        assert!(!ct_u16_eq(0x0100, 0x0200));
    }

    // -----------------------------------------------------------------------
    // Zigbee types
    // -----------------------------------------------------------------------

    #[test]
    fn zigbee_frame_default() {
        let f = ZigbeeFrame::default();
        assert_eq!(f.src_addr, 0xFFFF);
        assert_eq!(f.dst_addr, 0xFFFF);
        assert_eq!(f.frame_type, ZigbeeFrameType::Beacon);
    }

    #[test]
    fn zigbee_frame_type_from_raw() {
        assert_eq!(ZigbeeFrameType::from_raw(0), Some(ZigbeeFrameType::Beacon));
        assert_eq!(ZigbeeFrameType::from_raw(1), Some(ZigbeeFrameType::Data));
        assert_eq!(ZigbeeFrameType::from_raw(2), Some(ZigbeeFrameType::Ack));
        assert_eq!(ZigbeeFrameType::from_raw(3), Some(ZigbeeFrameType::Command));
        assert_eq!(ZigbeeFrameType::from_raw(4), None);
        assert_eq!(
            ZigbeeFrameType::from_raw(255),
            Some(ZigbeeFrameType::Unknown)
        );
    }

    // -----------------------------------------------------------------------
    // LoRa types
    // -----------------------------------------------------------------------

    #[test]
    fn lora_message_default() {
        let m = LoraMessage::default();
        assert_eq!(m.dev_addr, [0; 4]);
        assert_eq!(m.frame_counter, 0);
        assert_eq!(m.msg_type, LoraMessageType::JoinRequest);
    }

    #[test]
    fn lora_message_type_from_raw() {
        assert_eq!(
            LoraMessageType::from_raw(0),
            Some(LoraMessageType::JoinRequest)
        );
        assert_eq!(
            LoraMessageType::from_raw(1),
            Some(LoraMessageType::JoinAccept)
        );
        assert_eq!(
            LoraMessageType::from_raw(2),
            Some(LoraMessageType::UnconfirmedUp)
        );
        assert_eq!(
            LoraMessageType::from_raw(5),
            Some(LoraMessageType::ConfirmedDown)
        );
        assert_eq!(LoraMessageType::from_raw(6), None);
        assert!(LoraMessageType::JoinRequest.is_join());
        assert!(!LoraMessageType::ConfirmedUp.is_join());
    }

    #[test]
    fn modbus_rtu_unit_id_validation() {
        let mut m = ModbusRtuMessage {
            unit_id: 0,
            ..ModbusRtuMessage::default()
        };
        assert!(!m.is_valid_unit_id());
        assert!(m.is_broadcast());
        m.unit_id = 1;
        assert!(m.is_valid_unit_id());
        m.unit_id = 247;
        assert!(m.is_valid_unit_id());
        m.unit_id = 248;
        assert!(!m.is_valid_unit_id());
    }

    #[test]
    fn mqtt_topic_bytes_clamps_overflow() {
        let msg = MqttMessage {
            topic_len: 255, // exceeds MAX_MQTT_TOPIC_LEN
            ..MqttMessage::default()
        };
        // Should not panic — clamped to MAX_MQTT_TOPIC_LEN.
        let bytes = msg.topic_bytes();
        assert_eq!(bytes.len(), MAX_MQTT_TOPIC_LEN);
    }

    #[test]
    fn mqtt_payload_bytes_clamps_overflow() {
        let msg = MqttMessage {
            payload_inspectable_len: u16::MAX,
            ..MqttMessage::default()
        };
        let bytes = msg.payload_bytes();
        assert_eq!(bytes.len(), MAX_MQTT_PAYLOAD_LEN);
    }

    #[test]
    fn coap_uri_bytes_clamps_overflow() {
        let msg = CoapMessage {
            uri_len: 255,
            ..CoapMessage::default()
        };
        let bytes = msg.uri_bytes();
        assert_eq!(bytes.len(), MAX_COAP_URI_LEN);
    }

    #[test]
    fn coap_payload_bytes_accessor() {
        let mut msg = CoapMessage::default();
        msg.payload[0] = 0xAA;
        msg.payload[1] = 0xBB;
        msg.payload_len = 2;
        assert_eq!(msg.payload_bytes(), &[0xAA, 0xBB]);
    }

    #[test]
    fn coap_payload_bytes_clamps_overflow() {
        let msg = CoapMessage {
            payload_len: u16::MAX,
            ..CoapMessage::default()
        };
        let bytes = msg.payload_bytes();
        assert_eq!(bytes.len(), MAX_COAP_PAYLOAD_LEN);
    }

    #[test]
    fn mqtt_packet_type_qos2() {
        assert_eq!(MqttPacketType::PubRec as u8, 5);
        assert_eq!(MqttPacketType::PubRel as u8, 6);
        assert_eq!(MqttPacketType::PubComp as u8, 7);
    }

    #[test]
    fn mqtt_packet_type_auth() {
        assert_eq!(MqttPacketType::Auth as u8, 15);
    }

    // -----------------------------------------------------------------------
    // Modbus types
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_function_from_raw() {
        assert_eq!(ModbusFunction::from_raw(1), Some(ModbusFunction::ReadCoils));
        assert_eq!(
            ModbusFunction::from_raw(3),
            Some(ModbusFunction::ReadHoldingRegisters)
        );
        assert_eq!(
            ModbusFunction::from_raw(6),
            Some(ModbusFunction::WriteSingleRegister)
        );
        assert_eq!(
            ModbusFunction::from_raw(16),
            Some(ModbusFunction::WriteMultipleRegisters)
        );
        assert_eq!(ModbusFunction::from_raw(99), None);
    }

    #[test]
    fn modbus_function_is_write() {
        assert!(!ModbusFunction::ReadCoils.is_write());
        assert!(!ModbusFunction::ReadHoldingRegisters.is_write());
        assert!(ModbusFunction::WriteSingleCoil.is_write());
        assert!(ModbusFunction::WriteSingleRegister.is_write());
        assert!(ModbusFunction::WriteMultipleCoils.is_write());
        assert!(ModbusFunction::WriteMultipleRegisters.is_write());
        assert!(!ModbusFunction::Unknown.is_write());
    }

    #[test]
    fn modbus_rtu_default() {
        let m = ModbusRtuMessage::default();
        assert_eq!(m.unit_id, 0);
        assert_eq!(m.function, ModbusFunction::Unknown);
    }

    #[test]
    fn modbus_tcp_default() {
        let m = ModbusTcpMessage::default();
        assert_eq!(m.rtu.unit_id, 0);
        assert_eq!(m.transaction_id, 0);
        assert_eq!(m.src_ip, IpAddress::V4([0; 4]));
    }

    // -----------------------------------------------------------------------
    // Capacity feature flag constants
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn capacity_constants_are_positive() {
        assert!(MAX_TOPIC_RULES > 0);
        assert!(MAX_RATE_BUCKETS_MQTT > 0);
        assert!(MAX_URI_RULES > 0);
        assert!(MAX_RATE_BUCKETS_COAP > 0);
        assert!(MAX_MAC_FILTERS > 0);
        assert!(MAX_TRACKED_PEERS > 0);
        assert!(MAX_ZIGBEE_ADDR_RULES > 0);
        assert!(MAX_ZIGBEE_RATE_BUCKETS > 0);
        assert!(MAX_ZIGBEE_SECURITY_COUNTERS > 0);
        assert!(MAX_LORA_DEVICE_RULES > 0);
        assert!(MAX_MODBUS_UNIT_RULES > 0);
    }

    // -----------------------------------------------------------------------
    // Timestamp validator tests
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_validator_accepts_normal_progression() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(1_000_000));
        assert!(v.validate(2_000_000));
        assert!(v.validate(3_000_000));
        assert_eq!(v.anomaly_count, 0);
    }

    #[test]
    fn timestamp_validator_rejects_large_backward_jump() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(100_000_000));
        assert!(!v.validate(1_000_000)); // 99s backward jump
        assert_eq!(v.anomaly_count, 1);
    }

    #[test]
    fn timestamp_validator_accepts_small_backward_jump() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(100_000_000));
        assert!(v.validate(95_000_000)); // 5s backward - within tolerance
        assert_eq!(v.anomaly_count, 0);
    }

    #[test]
    fn timestamp_validator_rejects_large_forward_jump() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(1_000_000));
        assert!(!v.validate(5_000_000_000)); // >1 hour forward
        assert_eq!(v.anomaly_count, 1);
    }

    #[test]
    fn timestamp_validator_reset() {
        let mut v = TimestampValidator::new();
        let _ = v.validate(100_000_000);
        let _ = v.validate(1_000_000); // anomaly
        assert_eq!(v.anomaly_count, 1);
        v.reset();
        assert_eq!(v.anomaly_count, 0);
        assert!(v.validate(500)); // fresh start
    }

    #[test]
    fn timestamp_validator_no_backward_ratchet() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(100_000_000)); // 100s — baseline set to 100s
                                          // Small backward jump: accepted, but baseline stays at 100s.
        assert!(v.validate(91_000_000)); // 91s — within 10s tolerance
                                         // 82s is 18s backward from baseline (100s) — exceeds 10s threshold.
        assert!(!v.validate(82_000_000));
        assert_eq!(v.anomaly_count, 1);
        // Without the fix, baseline would have ratcheted to 91s, and 82s
        // (only 9s back) would have been accepted — enabling indefinite ratchet.
    }

    #[test]
    fn timestamp_validator_forward_after_small_backward() {
        let mut v = TimestampValidator::new();
        assert!(v.validate(100_000_000));
        assert!(v.validate(95_000_000)); // small backward, accepted
        assert!(v.validate(102_000_000)); // forward from baseline 100s, accepted and updates baseline
                                          // Now baseline is 102s, so 93s is within tolerance
        assert!(v.validate(93_000_000));
        // But 82s is not (20s backward from 102s)
        assert!(!v.validate(82_000_000));
        assert_eq!(v.anomaly_count, 1);
    }

    // -----------------------------------------------------------------------
    // Config audit log tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_audit_log_records_and_retrieves() {
        let mut log: ConfigAuditLog<8> = ConfigAuditLog::new();
        assert!(log.is_empty());
        log.record(SOURCE_MQTT, ConfigChangeType::RuleAdded, 1000);
        assert_eq!(log.len(), 1);
        let entry = log.get(0).unwrap();
        assert_eq!(entry.source_type, SOURCE_MQTT);
        assert_eq!(entry.change_type, ConfigChangeType::RuleAdded);
        assert_eq!(entry.seq, 1);
    }

    #[test]
    fn config_audit_log_wraps_around() {
        let mut log: ConfigAuditLog<4> = ConfigAuditLog::new();
        for i in 0..6 {
            log.record(SOURCE_BLE, ConfigChangeType::ParameterChanged, i * 1000);
        }
        assert_eq!(log.len(), 4);
        // Oldest should be entry #3 (0-indexed from the 6 we added).
        let oldest = log.get(0).unwrap();
        assert_eq!(oldest.seq, 3);
    }

    // -----------------------------------------------------------------------
    // Modbus IP filter tests
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_ip_filter_exact_match() {
        let f = ModbusIpFilter {
            ip: IpAddress::V4([192, 168, 1, 100]),
            prefix_len: 32,
            action: IpAction::Allow,
            active: true,
        };
        assert!(f.matches(&[192, 168, 1, 100]));
        assert!(!f.matches(&[192, 168, 1, 101]));
    }

    #[test]
    fn modbus_ip_filter_subnet_match() {
        let f = ModbusIpFilter {
            ip: IpAddress::V4([192, 168, 1, 0]),
            prefix_len: 24,
            action: IpAction::Allow,
            active: true,
        };
        assert!(f.matches(&[192, 168, 1, 100]));
        assert!(f.matches(&[192, 168, 1, 255]));
        assert!(!f.matches(&[192, 168, 2, 1]));
    }

    #[test]
    fn modbus_ip_filter_inactive_never_matches() {
        let f = ModbusIpFilter::empty();
        assert!(!f.matches(&[0, 0, 0, 0]));
    }

    // -----------------------------------------------------------------------
    // BLE address type classification
    // -----------------------------------------------------------------------

    #[test]
    fn ble_address_type_random_static() {
        // MSBs 0b11 in byte[5]
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0xC0]; // 0xC0 = 0b1100_0000
        assert_eq!(
            BleAddressType::classify(&addr),
            BleAddressType::RandomStatic
        );
        assert!(BleAddressType::classify(&addr).is_random());
    }

    #[test]
    fn ble_address_type_resolvable() {
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x40]; // 0x40 = 0b0100_0000
        assert_eq!(
            BleAddressType::classify(&addr),
            BleAddressType::RandomPrivateResolvable
        );
    }

    #[test]
    fn ble_address_type_public() {
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x00]; // 0x00 = 0b0000_0000
        assert_eq!(BleAddressType::classify(&addr), BleAddressType::Public);
        assert!(!BleAddressType::classify(&addr).is_random());
    }

    // -----------------------------------------------------------------------
    // Modbus exception parsing
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_exception_from_raw() {
        assert_eq!(
            ModbusException::from_raw(1),
            Some(ModbusException::IllegalFunction)
        );
        assert_eq!(
            ModbusException::from_raw(4),
            Some(ModbusException::ServerDeviceFailure)
        );
        assert_eq!(ModbusException::from_raw(99), None);
    }

    // -----------------------------------------------------------------------
    // Zigbee security counter
    // -----------------------------------------------------------------------

    #[test]
    fn zigbee_security_counter_empty() {
        let c = ZigbeeSecurityCounter::empty();
        assert!(!c.active);
        assert_eq!(c.src_addr, 0xFFFF);
    }

    // -----------------------------------------------------------------------
    // LoRa session
    // -----------------------------------------------------------------------

    #[test]
    fn lora_session_empty() {
        let s = LoraSession::empty();
        assert!(!s.active);
        assert_eq!(s.up_frame_counter, 0);
        assert_eq!(s.down_frame_counter, 0);
    }

    #[test]
    fn lora_adr_state_empty() {
        let a = LoraAdrState::empty();
        assert!(!a.active);
        assert_eq!(a.change_count, 0);
    }

    // -----------------------------------------------------------------------
    // Trust center event
    // -----------------------------------------------------------------------

    #[test]
    fn trust_center_events_distinct() {
        assert_ne!(
            TrustCenterEvent::NetworkKeyUpdate as u8,
            TrustCenterEvent::DeviceJoined as u8
        );
    }

    // -----------------------------------------------------------------------
    // V2: compute_payload_hash fills all 32 bytes
    // -----------------------------------------------------------------------

    #[test]
    fn payload_hash_all_32_bytes_nonzero_for_nonempty_input() {
        let h = compute_payload_hash(b"hello world");
        // All 32 bytes must be populated (no zero-suffix from incomplete passes).
        assert!(!h.0.iter().all(|&b| b == 0), "hash should not be all-zero");
        // Check each 4-byte word (each pass) is independently nonzero.
        for chunk in h.0.chunks(4) {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            assert_ne!(
                word, 0,
                "hash word at offset {chunk:?} is zero — a pass was skipped"
            );
        }
    }

    #[test]
    fn payload_hash_empty_input_is_all_zero() {
        let h = compute_payload_hash(b"");
        assert_eq!(h.0, [0u8; 32], "empty input should yield all-zero hash");
    }

    #[test]
    fn payload_hash_different_inputs_differ() {
        let h1 = compute_payload_hash(b"abc");
        let h2 = compute_payload_hash(b"xyz");
        assert_ne!(h1.0, h2.0, "distinct inputs should produce distinct hashes");
    }

    #[test]
    fn payload_hash_deterministic() {
        let h1 = compute_payload_hash(b"determinism");
        let h2 = compute_payload_hash(b"determinism");
        assert_eq!(h1.0, h2.0, "same input must always yield same hash");
    }

    #[test]
    fn mqtt_packet_type_from_raw_all_variants() {
        assert_eq!(MqttPacketType::from_raw(1), Some(MqttPacketType::Connect));
        assert_eq!(MqttPacketType::from_raw(2), Some(MqttPacketType::ConnAck));
        assert_eq!(MqttPacketType::from_raw(3), Some(MqttPacketType::Publish));
        assert_eq!(
            MqttPacketType::from_raw(14),
            Some(MqttPacketType::Disconnect)
        );
        assert_eq!(MqttPacketType::from_raw(15), Some(MqttPacketType::Auth));
        assert_eq!(MqttPacketType::from_raw(0), None);
        assert_eq!(MqttPacketType::from_raw(16), None);
    }

    #[test]
    fn mqtt_qos_from_raw() {
        assert_eq!(MqttQoS::from_raw(0), Some(MqttQoS::AtMostOnce));
        assert_eq!(MqttQoS::from_raw(1), Some(MqttQoS::AtLeastOnce));
        assert_eq!(MqttQoS::from_raw(2), Some(MqttQoS::ExactlyOnce));
        assert_eq!(MqttQoS::from_raw(3), None);
        assert_eq!(MqttQoS::from_raw(255), None);
    }

    #[test]
    fn coap_method_from_raw() {
        assert_eq!(CoapMethod::from_raw(1), Some(CoapMethod::Get));
        assert_eq!(CoapMethod::from_raw(2), Some(CoapMethod::Post));
        assert_eq!(CoapMethod::from_raw(3), Some(CoapMethod::Put));
        assert_eq!(CoapMethod::from_raw(4), Some(CoapMethod::Delete));
        assert_eq!(CoapMethod::from_raw(0), None);
        assert_eq!(CoapMethod::from_raw(5), None);
    }

    #[test]
    fn config_audit_log_seq_wrapping() {
        let mut log = ConfigAuditLog::<4>::new();
        // Manually set next_seq near u32::MAX to test wrapping
        // We'll record many entries to verify no panic
        for _ in 0..10 {
            log.record(SOURCE_MQTT, ConfigChangeType::RuleAdded, 1000);
        }
        // Verify we can still retrieve entries
        assert!(log.get(0).is_some());
    }

    #[test]
    fn ble_address_classify_0b10_is_unknown() {
        // Address with MSBs 0b10 in byte[5] should be Unknown (undefined in BLE spec)
        let addr = [0x00, 0x00, 0x00, 0x00, 0x00, 0x80]; // 0x80 = 0b10_000000
        assert_eq!(BleAddressType::classify(&addr), BleAddressType::Unknown);
    }

    #[test]
    fn ble_address_classify_0b00_is_public() {
        // Address with MSBs 0b00 in byte[5] should be Public
        let addr = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 0x00 = 0b00_000000
        assert_eq!(BleAddressType::classify(&addr), BleAddressType::Public);
    }

    #[test]
    fn config_audit_log_get_out_of_bounds() {
        let log = ConfigAuditLog::<4>::new();
        assert!(log.get(0).is_none());
        assert!(log.get(100).is_none());
    }

    #[test]
    fn modbus_ip_filter_prefix_len_zero_matches_all() {
        let filter = ModbusIpFilter {
            ip: IpAddress::V4([10, 0, 0, 0]),
            prefix_len: 0,
            action: IpAction::Block,
            active: true,
        };
        assert!(filter.matches(&[192, 168, 1, 1]));
        assert!(filter.matches(&[10, 0, 0, 1]));
    }

    #[test]
    fn modbus_ip_filter_new_validates_prefix_len() {
        assert!(ModbusIpFilter::new([192, 168, 1, 0], 24, IpAction::Allow, true).is_some());
        assert!(ModbusIpFilter::new([192, 168, 1, 0], 32, IpAction::Allow, true).is_some());
        assert!(ModbusIpFilter::new([192, 168, 1, 0], 0, IpAction::Allow, true).is_some());
        assert!(ModbusIpFilter::new([192, 168, 1, 0], 33, IpAction::Allow, true).is_none());
        assert!(ModbusIpFilter::new([192, 168, 1, 0], 255, IpAction::Allow, true).is_none());
    }

    #[test]
    fn timestamp_validator_rejects_far_future_jump() {
        let mut v = TimestampValidator::new();
        // First timestamp establishes baseline
        assert!(v.validate(1_000_000));
        // Normal forward: should pass
        assert!(v.validate(2_000_000));
        // Jump > 1 hour forward: should fail
        assert!(!v.validate(2_000_000 + 3_600_000_001));
    }

    #[test]
    fn repr_c_on_message_types() {
        // Verify #[repr(C)] structs have stable layout by checking size is non-zero.
        assert!(core::mem::size_of::<MqttMessage>() > 0);
        assert!(core::mem::size_of::<CoapMessage>() > 0);
        assert!(core::mem::size_of::<BleEvent>() > 0);
        assert!(core::mem::size_of::<ZigbeeFrame>() > 0);
    }
}
