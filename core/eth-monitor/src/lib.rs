// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Automotive Ethernet intrusion detection monitor.
//!
//! # Public API (0.7.x)
//!
//! The `EthMonitor` type, its allow-list / rate-limit configuration
//! methods, and the `EthPacket` type form the `0.7.x` public API
//! surface and are governed by the workspace `DEPRECATION.md`.

use vs_types::{
    AlertSeverity, IpAddr, IpHeader, IpProtocol, SecurityAlert, TransportHeader, VsError,
    SOURCE_ETHERNET,
};

/// Benchmark-only access to the fused 4-lane SipHash payload hash.
///
/// Exposed under the `bench` feature so the criterion bench harness can call
/// it directly without going through the full alert-generation path. Not part
/// of the public API; do not depend on this from non-bench code.
#[cfg(feature = "bench")]
#[doc(hidden)]
pub fn bench_compute_payload_hash(payload: &[u8], keys: &[(u64, u64); 4]) -> [u8; 32] {
    compute_payload_hash(payload, keys)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the allow-list of (`src_mac`, `dst_mac`, `service_id`) tuples.
const MAX_ALLOW_LIST: usize = 64;

/// Maximum number of allowed VLAN IDs.
const MAX_ALLOWED_VLANS: usize = 64;

/// Maximum entries in the learned IP-to-MAC table for ARP spoofing detection.
///
/// Sized to resist ARP cache eviction attacks: an attacker needs to flood
/// more entries than this to evict a legitimate binding.
const MAX_ARP_ENTRIES: usize = 256;

/// Maximum simultaneous `DoIP` sessions.
const MAX_DOIP_SESSIONS: usize = 32;

/// `DoIP` session inactivity timeout in microseconds (30 seconds).
const DOIP_SESSION_TIMEOUT_US: u64 = 30_000_000;

/// Default maximum SOME/IP payload length.
const DEFAULT_SOMEIP_MAX_LEN: u32 = 65535;

/// `EtherType` for ARP.
const ETHERTYPE_ARP: u16 = 0x0806;

/// ARP operation code: reply.
const ARP_OP_REPLY: u16 = 2;

/// SOME/IP header size in bytes.
const SOMEIP_HEADER_SIZE: usize = 16;

/// `DoIP` generic header size in bytes.
const DOIP_HEADER_SIZE: usize = 8;

/// `DoIP` payload type: routing activation request.
const DOIP_ROUTING_ACTIVATION_REQUEST: u16 = 0x0005;

/// `DoIP` payload type: routing activation response.
const DOIP_ROUTING_ACTIVATION_RESPONSE: u16 = 0x0006;

/// `DoIP` payload type: diagnostic message.
const DOIP_DIAGNOSTIC_MESSAGE: u16 = 0x8001;

/// `DoIP` payload type: diagnostic message positive ack.
const DOIP_DIAGNOSTIC_POSITIVE_ACK: u16 = 0x8002;

/// `DoIP` payload type: diagnostic message negative ack.
const DOIP_DIAGNOSTIC_NEGATIVE_ACK: u16 = 0x8003;

/// `EtherType` for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// `EtherType` for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// IPv4 minimum header length (no options).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// IPv6 fixed header length.
const IPV6_HEADER_LEN: usize = 40;

/// TCP minimum header length.
const TCP_MIN_HEADER_LEN: usize = 20;

/// UDP header length.
const UDP_HEADER_LEN: usize = 8;

/// SOME/IP-SD well-known service ID.
const SOMEIP_SD_SERVICE_ID: u16 = 0xFFFF;

/// SOME/IP-SD well-known method ID.
const SOMEIP_SD_METHOD_ID: u16 = 0x8100;

/// SOME/IP-SD header size: flags(1) + reserved(3) + `length_of_entries`(4) = 8 bytes.
const SOMEIP_SD_HEADER_SIZE: usize = 8;

/// SOME/IP-SD entry size in bytes.
const SOMEIP_SD_ENTRY_SIZE: usize = 16;

/// Maximum number of SD entries parsed from a single message.
const MAX_SD_ENTRIES_PER_MSG: usize = 16;

/// Maximum tracked SD services in the service table.
const MAX_SD_SERVICES: usize = 32;

/// SD message rate threshold (per inspect cycle) above which a flood alert is raised.
const SD_FLOOD_THRESHOLD: u32 = 100;

/// Alert ID namespace for Ethernet monitor alerts.
const ALERT_ID_VLAN_HOPPING: u64 = 0xE000_0001;
const ALERT_ID_ARP_SPOOF: u64 = 0xE000_0002;
const ALERT_ID_SOMEIP_UNKNOWN: u64 = 0xE000_0003;
const ALERT_ID_DOIP_UNAUTH: u64 = 0xE000_0004;
const ALERT_ID_SOMEIP_OVERSIZE: u64 = 0xE000_0005;
const ALERT_ID_SOMEIP_SD_UNAUTH: u64 = 0xE000_0006;
const ALERT_ID_SOMEIP_SD_FLOOD: u64 = 0xE000_0007;
const ALERT_ID_ARP_EVICTION_FLOOD: u64 = 0xE000_0008;
const ALERT_ID_SOMEIP_LENGTH_MISMATCH: u64 = 0xE000_0009;

/// Well-known `DoIP` TCP port.
const DOIP_TCP_PORT: u16 = 13400;

/// Well-known SOME/IP UDP port.
const SOMEIP_UDP_PORT: u16 = 30490;

/// ARP operation code: request.
const ARP_OP_REQUEST: u16 = 1;

/// Maximum ARP entries learned per tick cycle before rate limiting.
const MAX_ARP_LEARNS_PER_TICK: u32 = 8;

/// ARP table eviction flood threshold per tick cycle.
const ARP_EVICTION_FLOOD_THRESHOLD: u32 = 16;

// ---------------------------------------------------------------------------
// Constant-time byte comparison
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Packet representation (zero-copy)
// ---------------------------------------------------------------------------

/// Zero-copy Ethernet packet representation.
#[derive(Debug, Clone, Copy)]
pub struct EthPacket<'a> {
    /// Source MAC address (6 octets, network order).
    pub src_mac: [u8; 6],
    /// Destination MAC address (6 octets, network order).
    pub dst_mac: [u8; 6],
    /// VLAN ID (12 bits) if the frame was 802.1Q tagged, else `None`.
    pub vlan_id: Option<u16>,
    /// Ethernet `EtherType` field (e.g. `0x0800` for IPv4, `0x0806` for ARP).
    pub ethertype: u16,
    /// Transport-layer destination port, when known to the caller. Used by
    /// the monitor to dispatch SOME/IP / DoIP / generic protocol checks.
    pub dst_port: Option<u16>,
    /// Payload following the Ethernet header (and any VLAN tag).
    pub payload: &'a [u8],
}

// ---------------------------------------------------------------------------
// SOME/IP
// ---------------------------------------------------------------------------

/// Parsed SOME/IP header (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomeIpHeader {
    /// SOME/IP service identifier (`0xFFFF` indicates SD).
    pub service_id: u16,
    /// SOME/IP method identifier (`0x8100` together with `service_id=0xFFFF` indicates SD).
    pub method_id: u16,
    /// Length field — covers the rest of the SOME/IP message after this
    /// length word, i.e. payload size + 8 bytes (`client_id` through
    /// `return_code`) per AUTOSAR semantics.
    pub length: u32,
    /// Client identifier issuing the request.
    pub client_id: u16,
    /// Per-client session identifier.
    pub session_id: u16,
    /// SOME/IP protocol version (typically `0x01`).
    pub protocol_version: u8,
    /// Service interface version.
    pub interface_version: u8,
    /// Message type (request, response, notification, etc.).
    pub message_type: u8,
    /// Return code (0 = OK on responses).
    pub return_code: u8,
}

/// Parse a SOME/IP header from the beginning of `data`.
///
/// Returns `None` when `data` is shorter than 16 bytes.
pub fn parse_someip_header(data: &[u8]) -> Option<SomeIpHeader> {
    if data.len() < SOMEIP_HEADER_SIZE {
        return None;
    }
    Some(SomeIpHeader {
        service_id: u16::from_be_bytes([data[0], data[1]]),
        method_id: u16::from_be_bytes([data[2], data[3]]),
        length: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        client_id: u16::from_be_bytes([data[8], data[9]]),
        session_id: u16::from_be_bytes([data[10], data[11]]),
        protocol_version: data[12],
        interface_version: data[13],
        message_type: data[14],
        return_code: data[15],
    })
}

// ---------------------------------------------------------------------------
// SOME/IP-SD (Service Discovery)
// ---------------------------------------------------------------------------

/// SOME/IP-SD entry type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SdEntryType {
    /// Type 0x00 — Find Service.
    FindService = 0x00,
    /// Type 0x01 — Offer Service.
    OfferService = 0x01,
    /// Type 0x06 — Subscribe Eventgroup.
    SubscribeEventgroup = 0x06,
    /// Type 0x07 — Stop Subscribe Eventgroup.
    StopSubscribe = 0x07,
}

impl SdEntryType {
    /// Convert a raw byte to an `SdEntryType`, returning `None` for unknown values.
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::FindService),
            0x01 => Some(Self::OfferService),
            0x06 => Some(Self::SubscribeEventgroup),
            0x07 => Some(Self::StopSubscribe),
            _ => None,
        }
    }
}

/// A single parsed SOME/IP-SD entry (16 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomeIpSdEntry {
    /// Entry type (Find/Offer/Subscribe/StopSubscribe).
    pub entry_type: SdEntryType,
    /// Service identifier this entry refers to.
    pub service_id: u16,
    /// Instance identifier within `service_id`.
    pub instance_id: u16,
    /// Major version of the service interface.
    pub major_version: u8,
    /// Time-to-live in seconds. `0` indicates a stop-offer.
    pub ttl: u32,
    /// Minor version of the service interface.
    pub minor_version: u32,
}

/// Parse SOME/IP-SD entries from the SD payload (after the 16-byte SOME/IP header).
///
/// SD payload layout:
///   - flags (1 byte)
///   - reserved (3 bytes)
///   - `length_of_entries_array` (4 bytes, big-endian)
///   - entries (16 bytes each)
///   - `length_of_options_array` (4 bytes, big-endian)
///   - options (variable, not parsed here)
///
/// Returns `(flags, count, entries)`.
pub fn parse_sd_entries(
    sd_payload: &[u8],
) -> (u8, usize, [Option<SomeIpSdEntry>; MAX_SD_ENTRIES_PER_MSG]) {
    const NONE_ENTRY: Option<SomeIpSdEntry> = None;
    let mut entries = [NONE_ENTRY; MAX_SD_ENTRIES_PER_MSG];

    if sd_payload.len() < SOMEIP_SD_HEADER_SIZE {
        return (0, 0, entries);
    }

    let flags = sd_payload[0];
    let entries_array_len =
        u32::from_be_bytes([sd_payload[4], sd_payload[5], sd_payload[6], sd_payload[7]]) as usize;

    // Validate entries_array_len is a multiple of entry size. A non-aligned
    // value indicates a malformed or tampered SD message.
    if entries_array_len % SOMEIP_SD_ENTRY_SIZE != 0 {
        return (flags, 0, entries);
    }

    let entries_start = SOMEIP_SD_HEADER_SIZE;
    let available = sd_payload.len().saturating_sub(entries_start);
    let actual_len = entries_array_len.min(available);
    let entry_count = actual_len / SOMEIP_SD_ENTRY_SIZE;
    let entry_count = entry_count.min(MAX_SD_ENTRIES_PER_MSG);

    // Defensive overflow guard for 32-bit targets: even though
    // `entry_count` is bounded by `MAX_SD_ENTRIES_PER_MSG` and
    // `SOMEIP_SD_ENTRY_SIZE` is 16, prefer checked arithmetic at the
    // boundary so any future relaxation of either bound cannot silently
    // wrap `entries_start + entry_count * SOMEIP_SD_ENTRY_SIZE` into a
    // small value that passes the per-iteration bound check.
    let Some(entries_end) = entry_count
        .checked_mul(SOMEIP_SD_ENTRY_SIZE)
        .and_then(|n| entries_start.checked_add(n))
    else {
        return (flags, 0, entries);
    };
    if entries_end > sd_payload.len() {
        // Shouldn't happen given the `available` clamp above, but
        // double-check before indexing.
        return (flags, 0, entries);
    }

    let mut count = 0;
    for i in 0..entry_count {
        let offset = entries_start + i * SOMEIP_SD_ENTRY_SIZE;
        if offset + SOMEIP_SD_ENTRY_SIZE > sd_payload.len() {
            break;
        }

        let type_byte = sd_payload[offset];
        let Some(entry_type) = SdEntryType::from_u8(type_byte) else {
            continue; // Skip unknown entry types
        };

        let service_id = u16::from_be_bytes([sd_payload[offset + 4], sd_payload[offset + 5]]);
        let instance_id = u16::from_be_bytes([sd_payload[offset + 6], sd_payload[offset + 7]]);
        let major_version = sd_payload[offset + 8];
        // TTL is 3 bytes (bytes 9..12 but only lower 3 bytes)
        let ttl = u32::from_be_bytes([
            0,
            sd_payload[offset + 9],
            sd_payload[offset + 10],
            sd_payload[offset + 11],
        ]);
        let minor_version = u32::from_be_bytes([
            sd_payload[offset + 12],
            sd_payload[offset + 13],
            sd_payload[offset + 14],
            sd_payload[offset + 15],
        ]);

        entries[count] = Some(SomeIpSdEntry {
            entry_type,
            service_id,
            instance_id,
            major_version,
            ttl,
            minor_version,
        });
        count += 1;
    }

    (flags, count, entries)
}

/// Tracked SOME/IP-SD service in the service table.
#[derive(Debug, Clone, Copy)]
struct SdServiceEntry {
    service_id: u16,
    instance_id: u16,
    source_mac: [u8; 6],
    ttl_remaining: u32,
    /// Monotonic counter recording when this entry was inserted.
    /// Lower values indicate older entries.
    insertion_order: u64,
    active: bool,
}

impl SdServiceEntry {
    const fn empty() -> Self {
        Self {
            service_id: 0,
            instance_id: 0,
            source_mac: [0; 6],
            ttl_remaining: 0,
            insertion_order: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DoIP
// ---------------------------------------------------------------------------

/// Parsed `DoIP` generic header (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoIpHeader {
    /// `DoIP` protocol version (e.g. `0x02` for ISO 13400-2:2012).
    pub protocol_version: u8,
    /// Bitwise NOT of `protocol_version`; validated by the monitor.
    pub inverse_version: u8,
    /// Payload type (routing activation request/response, diagnostic
    /// message, etc.).
    pub payload_type: u16,
    /// Length in bytes of the data following the 8-byte generic header.
    pub payload_length: u32,
}

/// Parse a `DoIP` generic header from the beginning of `data`.
///
/// Returns `None` when `data` is shorter than 8 bytes.
pub fn parse_doip_header(data: &[u8]) -> Option<DoIpHeader> {
    if data.len() < DOIP_HEADER_SIZE {
        return None;
    }
    Some(DoIpHeader {
        protocol_version: data[0],
        inverse_version: data[1],
        payload_type: u16::from_be_bytes([data[2], data[3]]),
        payload_length: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    })
}

/// State of a single `DoIP` session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoIpSessionState {
    /// No session: the slot is unbound and accepts a new activation request.
    Idle,
    /// Routing activation request observed; awaiting the matching response
    /// from the expected responder.
    RoutingActivated,
    /// Routing activation completed; diagnostic messages are authorised.
    Active,
}

/// Tracked `DoIP` session keyed by the TCP tuple (`src_mac`, `dst_port`).
///
/// `DoIP` runs over TCP (RFC 13400) where each diagnostic session is bound
/// to a single TCP connection. Keying the session table on `src_mac` alone
/// would let an attacker who can spoof a victim client's MAC inherit the
/// victim's activated state by sending packets to a different `DoIP`
/// server port. Binding on `(src_mac, dst_port)` ensures that an activation
/// performed against server port X does not authorize diagnostics against
/// server port Y.
#[derive(Debug, Clone, Copy)]
struct DoIpSession {
    src_mac: [u8; 6],
    /// The MAC address of the entity this session's routing activation
    /// request was sent to. Used to validate that routing activation
    /// responses come from the expected responder, preventing session
    /// hijack via spoofed responses.
    expected_responder: [u8; 6],
    /// The destination TCP port the activation request was sent to (the
    /// server-side port of the `DoIP` TCP connection). Together with
    /// `src_mac` this forms the TCP-tuple key for the session. `None`
    /// means the slot is unbound (only valid for `Idle` state).
    dst_port: Option<u16>,
    state: DoIpSessionState,
    last_activity: u64,
}

impl DoIpSession {
    const fn empty() -> Self {
        Self {
            src_mac: [0; 6],
            expected_responder: [0; 6],
            dst_port: None,
            state: DoIpSessionState::Idle,
            last_activity: 0,
        }
    }
}

/// Returns `true` if `mac` is a broadcast or multicast Ethernet address.
///
/// Multicast addresses have the least-significant bit of the first byte
/// set (per IEEE 802.3). Broadcast (`FF:FF:FF:FF:FF:FF`) is the
/// degenerate multicast where every byte is `0xFF`. An attacker who
/// successfully tricks the monitor into recording a multicast/broadcast
/// "expected responder" can spoof activation responses from any source
/// MAC, so we must reject these as `expected_responder` candidates at
/// request time.
fn is_broadcast_or_multicast_mac(mac: &[u8; 6]) -> bool {
    (mac[0] & 0x01) != 0
}

// ---------------------------------------------------------------------------
// ARP entry
// ---------------------------------------------------------------------------

/// Learned IP-to-MAC binding for ARP spoof detection.
#[derive(Debug, Clone, Copy)]
struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
    valid: bool,
}

impl ArpEntry {
    const fn empty() -> Self {
        Self {
            ip: [0; 4],
            mac: [0; 6],
            valid: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Allow-list entry
// ---------------------------------------------------------------------------

/// An entry in the allow-list: (`src_mac`, `dst_mac`, `service_id`).
#[derive(Debug, Clone, Copy)]
pub struct AllowListEntry {
    /// Source MAC permitted to invoke `service_id` towards `dst_mac`.
    pub src_mac: [u8; 6],
    /// Destination MAC that hosts the service.
    pub dst_mac: [u8; 6],
    /// SOME/IP service identifier authorised between this MAC pair.
    pub service_id: u16,
}

/// Hash an allow-list key to a bucket index.
/// Uses a fast FNV-1a-style mix of the 14-byte key.
fn allow_list_hash(src_mac: &[u8; 6], dst_mac: &[u8; 6], service_id: u16) -> usize {
    let mut h: u64 = vs_types::FNV1A_OFFSET_BASIS; // FNV-1a offset basis
    for &b in src_mac {
        h ^= b as u64;
        h = h.wrapping_mul(vs_types::FNV1A_PRIME);
    }
    for &b in dst_mac {
        h ^= b as u64;
        h = h.wrapping_mul(vs_types::FNV1A_PRIME);
    }
    h ^= (service_id & 0xFF) as u64;
    h = h.wrapping_mul(vs_types::FNV1A_PRIME);
    h ^= (service_id >> 8) as u64;
    h = h.wrapping_mul(vs_types::FNV1A_PRIME);
    // Fold to ALLOW_HASH_CAPACITY (power of 2)
    (h as usize) & (ALLOW_HASH_CAPACITY - 1)
}

/// Power-of-2 hash table capacity for allow-list fast lookup.
const ALLOW_HASH_CAPACITY: usize = 128;

/// Hash bucket entry: stores the index into the flat allow_list array.
/// `0xFF` sentinel means empty slot.
const ALLOW_HASH_EMPTY: u8 = 0xFF;

// ---------------------------------------------------------------------------
// EthMonitor configuration
// ---------------------------------------------------------------------------

/// Configuration for the Ethernet monitor.
///
/// All arrays are fixed-capacity (no_std, no heap). The `_len` fields name
/// how many leading slots are valid; `EthMonitor::new` re-derives the
/// effective length by scanning the prefix, so a desync between `_len`
/// and the actual `Option` contents is corrected at construction time.
pub struct EthMonitorConfig {
    /// Allow-list entries (`src_mac`, `dst_mac`, `service_id`).
    pub allow_list: [Option<AllowListEntry>; MAX_ALLOW_LIST],
    /// Number of valid entries in `allow_list`.
    pub allow_list_len: usize,
    /// Set of VLAN IDs that are permitted.
    pub allowed_vlans: [Option<u16>; MAX_ALLOWED_VLANS],
    /// Number of valid entries in `allowed_vlans`.
    pub allowed_vlans_len: usize,
    /// Maximum allowed SOME/IP message length field (payload + 8 per
    /// AUTOSAR). `0` is treated as "use the minimum sensible default".
    pub someip_max_length: u32,
}

impl Default for EthMonitorConfig {
    fn default() -> Self {
        const NONE_ENTRY: Option<AllowListEntry> = None;
        const NONE_VLAN: Option<u16> = None;
        Self {
            allow_list: [NONE_ENTRY; MAX_ALLOW_LIST],
            allow_list_len: 0,
            allowed_vlans: [NONE_VLAN; MAX_ALLOWED_VLANS],
            allowed_vlans_len: 0,
            someip_max_length: DEFAULT_SOMEIP_MAX_LEN,
        }
    }
}

// ---------------------------------------------------------------------------
// EthMonitor
// ---------------------------------------------------------------------------

/// Automotive Ethernet intrusion-detection monitor.
///
/// Inspects Ethernet packets for VLAN hopping, ARP spoofing, unknown SOME/IP
/// services, oversized SOME/IP payloads, and unauthenticated `DoIP` diagnostic
/// requests.
pub struct EthMonitor {
    /// Configuration / allow-list.
    allow_list: [Option<AllowListEntry>; MAX_ALLOW_LIST],
    allow_list_len: usize,
    /// Hash table for O(1) average allow-list lookups.
    /// Each slot stores the index into `allow_list`, or `ALLOW_HASH_EMPTY`.
    allow_hash: [u8; ALLOW_HASH_CAPACITY],

    /// Allowed VLAN IDs.
    allowed_vlans: [Option<u16>; MAX_ALLOWED_VLANS],
    allowed_vlans_len: usize,

    /// Maximum allowed SOME/IP length.
    someip_max_length: u32,

    /// Learned IP-to-MAC bindings.
    arp_table: [ArpEntry; MAX_ARP_ENTRIES],

    /// Tracked `DoIP` sessions.
    doip_sessions: [DoIpSession; MAX_DOIP_SESSIONS],

    /// Tracked SOME/IP-SD service table.
    sd_service_table: [SdServiceEntry; MAX_SD_SERVICES],

    /// SD message counter for flood detection (decayed via `sd_tick`).
    sd_message_count: u32,

    /// Monotonic counter for SD service insertion ordering.
    sd_insertion_counter: u64,

    /// Monotonic alert counter (used as `source_id` differentiator).
    /// Saturates at `u64::MAX` for consistency with the CAN monitor.
    /// Truncated to `u32` when stored in `SecurityAlert::source_id`.
    alert_counter: u64,

    /// ARP learning rate counter (reset by `arp_tick`).
    arp_learn_count: u32,

    /// ARP eviction counter for detecting table-thrashing attacks.
    arp_eviction_count: u32,

    /// Set once per tick when ARP rate-limit fires, to emit only one alert.
    arp_rate_limit_alerted: bool,

    /// `true` once every slot in `arp_table` is occupied. Lets `learn_arp`
    /// skip the empty-slot probe and go straight to hash-slot eviction.
    /// Reset whenever an entry transitions from occupied to free (e.g.
    /// in future TTL-driven eviction paths) — today the table is
    /// monotonically growing within a learn cycle, so this stays `true`
    /// until external state is rebuilt.
    arp_table_full: bool,

    /// `DoIP` routing activation rate counter (reset by `doip_tick`).
    doip_activation_count: u32,

    /// SipHash keys used for forensic payload hashing.
    siphash_keys: [(u64, u64); 4],
}

/// Minimum valid SOME/IP max-length (8 bytes covers the header fields after
/// the length field: `client_id` + `session_id` + proto/iface/msg/rc).
const SOMEIP_MIN_MAX_LENGTH: u32 = 8;

/// Maximum `DoIP` routing activation requests per tick cycle before rate limiting.
const MAX_DOIP_ACTIVATIONS_PER_TICK: u32 = 8;

/// Alert ID for malformed `DoIP` payload length.
const ALERT_ID_DOIP_MALFORMED: u64 = 0xE000_000A;

/// Alert ID for `DoIP` routing activation rate limit exceeded.
const ALERT_ID_DOIP_RATE_LIMIT: u64 = 0xE000_000B;

/// Alert ID for `DoIP` session eviction (table full).
const ALERT_ID_DOIP_SESSION_EVICTION: u64 = 0xE000_000C;

/// Alert ID for ARP learning rate limit exceeded (possible ARP flood).
const ALERT_ID_ARP_RATE_LIMIT: u64 = 0xE000_000D;

/// Default SipHash keys for forensic payload hashing.
///
/// **WARNING — FOR TESTING AND EXAMPLES ONLY.**  These keys are publicly
/// known and predictable.  Production deployments MUST supply unique,
/// randomly generated keys from the platform TRNG.  The runtime generates
/// fresh TRNG keys automatically via `CratonShield::init`; only use this
/// constant in unit tests, integration tests, and examples.
pub const DEFAULT_SIPHASH_KEYS: [(u64, u64); 4] = [
    (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
    (0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918),
    (0x2726_2524_2322_2120, 0x2f2e_2d2c_2b2a_2928),
    (0x3736_3534_3332_3130, 0x3f3e_3d3c_3b3a_3938),
];

/// SipHash-2-4 based payload fingerprint for forensic correlation.
///
/// Produces a 32-byte output by running SipHash-2-4 with four different keys
/// and concatenating the 8-byte results. This provides collision resistance
/// suitable for forensic correlation (unlike a simple XOR-fold).
///
/// # Fused 4-lane implementation
///
/// The naive implementation runs SipHash-2-4 four times, walking the payload
/// four times over and re-loading each 8-byte block from memory each pass.
/// The fused implementation here maintains 4 independent SipHash states
/// `(v0..v3)` and feeds each 8-byte block to all four lanes in a single pass.
/// Each lane's state is independent (its own key, its own constants), so the
/// output is byte-for-byte identical to the per-lane version — but with one
/// payload load per block instead of four.
fn compute_payload_hash(payload: &[u8], keys: &[(u64, u64); 4]) -> [u8; 32] {
    use vs_types::sip_round;

    // Per-lane initial states; SipHash-2-4 constants XOR'd with the lane's key.
    let mut v0 = [0u64; 4];
    let mut v1 = [0u64; 4];
    let mut v2 = [0u64; 4];
    let mut v3 = [0u64; 4];
    let mut lane = 0;
    while lane < 4 {
        let (k0, k1) = keys[lane];
        v0[lane] = k0 ^ 0x736f_6d65_7073_6575;
        v1[lane] = k1 ^ 0x646f_7261_6e64_6f6d;
        v2[lane] = k0 ^ 0x6c79_6765_6e65_7261;
        v3[lane] = k1 ^ 0x7465_6462_7974_6573;
        lane += 1;
    }

    let len = payload.len();
    let blocks = len / 8;

    // Walk the payload once, feeding each 8-byte block to all four lanes.
    let mut i = 0;
    while i < blocks {
        let offset = i * 8;
        let m = u64::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        let mut l = 0;
        while l < 4 {
            v3[l] ^= m;
            sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
            sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
            v0[l] ^= m;
            l += 1;
        }
        i += 1;
    }

    // Tail block: same encoding as the canonical SipHash-2-4.
    let mut last = (len as u64 & 0xff) << 56;
    let remaining = len % 8;
    let tail = &payload[blocks * 8..];
    let mut t = 0;
    while t < remaining {
        last |= (tail[t] as u64) << (t * 8);
        t += 1;
    }
    let mut l = 0;
    while l < 4 {
        v3[l] ^= last;
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        v0[l] ^= last;
        l += 1;
    }

    // Finalization: 4 rounds per lane.
    let mut l = 0;
    while l < 4 {
        v2[l] ^= 0xff;
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        sip_round(&mut v0[l], &mut v1[l], &mut v2[l], &mut v3[l]);
        l += 1;
    }

    let mut result = [0u8; 32];
    let mut l = 0;
    while l < 4 {
        let h = v0[l] ^ v1[l] ^ v2[l] ^ v3[l];
        result[l * 8..l * 8 + 8].copy_from_slice(&h.to_le_bytes());
        l += 1;
    }
    result
}

impl EthMonitor {
    /// Create a new `EthMonitor` from the given configuration.
    ///
    /// The `allow_list_len` and `allowed_vlans_len` are validated against
    /// the actual array contents: the effective length is the minimum of
    /// the declared length and the count of `Some` entries in the prefix.
    pub fn new(config: &EthMonitorConfig, siphash_keys: [(u64, u64); 4]) -> Result<Self, VsError> {
        // Reject all-zero SipHash keys — these provide no hash randomisation
        // and indicate the caller forgot to supply TRNG-generated keys.
        let all_zero = siphash_keys.iter().all(|(k0, k1)| *k0 == 0 && *k1 == 0);
        if all_zero {
            return Err(VsError::InvalidConfig);
        }

        // Compute effective lengths by scanning the arrays — this prevents
        // desync between the len field and the actual Option contents.
        let allow_list_len = {
            let declared = config.allow_list_len.min(MAX_ALLOW_LIST);
            let mut effective = 0;
            for i in 0..declared {
                if config.allow_list[i].is_some() {
                    effective = i + 1;
                }
            }
            effective
        };
        let allowed_vlans_len = {
            let declared = config.allowed_vlans_len.min(MAX_ALLOWED_VLANS);
            let mut effective = 0;
            for i in 0..declared {
                if config.allowed_vlans[i].is_some() {
                    effective = i + 1;
                }
            }
            effective
        };
        // Reject someip_max_length below the minimum that covers at least the
        // SOME/IP header fields after the length word.
        if config.someip_max_length != 0 && config.someip_max_length < SOMEIP_MIN_MAX_LENGTH {
            return Err(VsError::InvalidConfig);
        }
        let someip_max_length = if config.someip_max_length == 0 {
            SOMEIP_MIN_MAX_LENGTH
        } else {
            config.someip_max_length
        };

        // Build the hash table from the initial allow-list entries.
        let mut allow_hash = [ALLOW_HASH_EMPTY; ALLOW_HASH_CAPACITY];
        for i in 0..allow_list_len {
            if let Some(entry) = &config.allow_list[i] {
                // Bounds check: u8 index cannot represent list_idx >= 256
                // (or >= ALLOW_HASH_CAPACITY which is 128).
                if i >= ALLOW_HASH_CAPACITY || i > u8::MAX as usize {
                    return Err(VsError::ResourceExhausted);
                }
                let h = allow_list_hash(&entry.src_mac, &entry.dst_mac, entry.service_id);
                // Linear probe to find an empty slot.
                let mut inserted = false;
                for j in 0..ALLOW_HASH_CAPACITY {
                    let idx = (h + j) & (ALLOW_HASH_CAPACITY - 1);
                    if allow_hash[idx] == ALLOW_HASH_EMPTY {
                        allow_hash[idx] = i as u8;
                        inserted = true;
                        break;
                    }
                }
                if !inserted {
                    return Err(VsError::ResourceExhausted);
                }
            }
        }

        Ok(Self {
            allow_list: config.allow_list,
            allow_list_len,
            allow_hash,
            allowed_vlans: config.allowed_vlans,
            allowed_vlans_len,
            someip_max_length,
            arp_table: [ArpEntry::empty(); MAX_ARP_ENTRIES],
            doip_sessions: [DoIpSession::empty(); MAX_DOIP_SESSIONS],
            sd_service_table: [SdServiceEntry::empty(); MAX_SD_SERVICES],
            sd_message_count: 0,
            sd_insertion_counter: 0,
            alert_counter: 0u64,
            arp_learn_count: 0,
            arp_eviction_count: 0,
            arp_rate_limit_alerted: false,
            arp_table_full: false,
            doip_activation_count: 0,
            siphash_keys,
        })
    }

    /// Override the SipHash keys used for forensic payload hashing.
    pub fn set_siphash_keys(&mut self, keys: [(u64, u64); 4]) {
        self.siphash_keys = keys;
    }

    /// Returns (active_entries, total_capacity) for the monitor's allow list.
    pub fn capacity(&self) -> (usize, usize) {
        let mut active = 0;
        for i in 0..self.allow_list_len {
            if self.allow_list[i].is_some() {
                active += 1;
            }
        }
        (active, MAX_ALLOW_LIST)
    }

    /// Add an allow-list entry. Returns `Err(VsError::ResourceExhausted)` if
    /// the list or hash table is full, or the index would overflow a `u8`.
    pub fn add_allow_entry(&mut self, entry: AllowListEntry) -> Result<bool, VsError> {
        if self.allow_list_len >= MAX_ALLOW_LIST {
            return Ok(false);
        }
        let list_idx = self.allow_list_len;

        // Bounds check: u8 index cannot represent list_idx >= 256
        // (or >= ALLOW_HASH_CAPACITY which is 128).
        if list_idx >= ALLOW_HASH_CAPACITY || list_idx > u8::MAX as usize {
            return Err(VsError::ResourceExhausted);
        }

        // Insert into hash table for fast lookup.
        let h = allow_list_hash(&entry.src_mac, &entry.dst_mac, entry.service_id);
        let mut inserted = false;
        for j in 0..ALLOW_HASH_CAPACITY {
            let idx = (h + j) & (ALLOW_HASH_CAPACITY - 1);
            if self.allow_hash[idx] == ALLOW_HASH_EMPTY {
                self.allow_hash[idx] = list_idx as u8;
                inserted = true;
                break;
            }
        }
        if !inserted {
            return Err(VsError::ResourceExhausted);
        }

        self.allow_list[list_idx] = Some(entry);
        self.allow_list_len += 1;

        Ok(true)
    }

    /// Add a VLAN ID to the allowed set. Returns `false` if the list is full.
    pub fn add_allowed_vlan(&mut self, vlan_id: u16) -> bool {
        if self.allowed_vlans_len >= MAX_ALLOWED_VLANS {
            return false;
        }
        self.allowed_vlans[self.allowed_vlans_len] = Some(vlan_id);
        self.allowed_vlans_len += 1;
        true
    }

    /// Inspect a packet and return a [`SecurityAlert`] if a threat is detected.
    ///
    /// The checks are run in order; the first matching threat generates the
    /// alert. Only one alert is returned per call.
    #[inline]
    pub fn inspect_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        // 1. VLAN hopping
        if let Some(alert) = self.check_vlan_hopping(pkt, ts_us) {
            return Some(alert);
        }

        // 2. ARP spoofing
        if let Some(alert) = self.check_arp_spoofing(pkt, ts_us) {
            return Some(alert);
        }

        // 3. Protocol discrimination.
        //
        // The SOME/IP and DoIP checkers operate on an *already-stripped*
        // L4 payload and a confirmed transport port. There are two ways
        // the caller can present a packet:
        //
        //   a) `dst_port` is `Some(_)` — the caller has already stripped
        //      the L3/L4 headers and `payload` is the L4 payload. We
        //      dispatch directly on the supplied port.
        //   b) `dst_port` is `None` — `payload` is the raw IP packet
        //      (the EthPacket contract: payload follows the Ethernet
        //      header). We parse L3/L4 ourselves via `parse_ip` /
        //      `parse_transport`, derive the real transport port, and
        //      dispatch on the stripped L4 payload.
        //
        // Fail closed: if the protocol cannot be positively identified
        // (non-IP EtherType, truncated/unparseable headers, or a
        // non-TCP/UDP transport) no SOME/IP/DoIP check runs. This avoids
        // re-interpreting arbitrary bytes as a protocol header.
        if let Some(port) = pkt.dst_port {
            self.dispatch_protocol(pkt, port, ts_us)
        } else {
            let (stripped, port) = strip_l3_l4(pkt.ethertype, pkt.payload)?;
            let derived = EthPacket {
                dst_port: Some(port),
                payload: stripped,
                ..*pkt
            };
            self.dispatch_protocol(&derived, port, ts_us)
        }
    }

    /// Dispatch a packet whose transport `port` and (in `pkt.payload`)
    /// stripped L4 payload are known to the matching protocol checker.
    fn dispatch_protocol(
        &mut self,
        pkt: &EthPacket<'_>,
        port: u16,
        ts_us: u64,
    ) -> Option<SecurityAlert> {
        match port {
            DOIP_TCP_PORT => self.check_doip(pkt, ts_us),
            SOMEIP_UDP_PORT => self.check_someip(pkt, ts_us),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn next_alert_counter(&mut self) -> u32 {
        let c = self.alert_counter;
        self.alert_counter = self.alert_counter.saturating_add(1);
        c as u32
    }

    fn make_alert(
        &mut self,
        id: u64,
        severity: AlertSeverity,
        ts_us: u64,
        payload: &[u8],
    ) -> SecurityAlert {
        SecurityAlert {
            id,
            severity,
            source_type: SOURCE_ETHERNET,
            source_id: self.next_alert_counter(),
            payload_hash: vs_types::PayloadHash(compute_payload_hash(payload, &self.siphash_keys)),
            timestamp_us: ts_us,
        }
    }

    /// VLAN hopping: if the packet carries a VLAN tag and that VLAN is not in
    /// the allowed set, raise an alert. If the allowed-vlans set is empty,
    /// any VLAN-tagged packet is considered suspicious (no VLAN policy has
    /// been configured, so tagged frames are unexpected).
    fn check_vlan_hopping(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        let vid = pkt.vlan_id?;

        if self.allowed_vlans_len == 0 {
            // No VLAN policy configured — any tagged frame is suspicious.
            return Some(self.make_alert(
                ALERT_ID_VLAN_HOPPING,
                AlertSeverity::High,
                ts_us,
                pkt.payload,
            ));
        }

        for i in 0..self.allowed_vlans_len {
            if self.allowed_vlans[i] == Some(vid) {
                return None;
            }
        }

        Some(self.make_alert(
            ALERT_ID_VLAN_HOPPING,
            AlertSeverity::High,
            ts_us,
            pkt.payload,
        ))
    }

    /// ARP spoofing: for ARP replies and gratuitous ARP requests, check the
    /// sender MAC/IP binding against the learned table. If a binding already
    /// exists for the IP but with a different MAC, raise an alert. Otherwise
    /// learn the new binding (rate-limited, round-robin eviction).
    fn check_arp_spoofing(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        if pkt.ethertype != ETHERTYPE_ARP {
            return None;
        }

        // Minimal ARP payload: 28 bytes for IPv4-over-Ethernet ARP.
        if pkt.payload.len() < 28 {
            return None;
        }

        // Validate hardware type (Ethernet = 1) and protocol type (IPv4 = 0x0800).
        let hw_type = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);
        let proto_type = u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]);
        if hw_type != 1 || proto_type != 0x0800 {
            return None;
        }

        // Validate hardware-address length (hlen=6 for Ethernet MAC) and
        // protocol-address length (plen=4 for IPv4). Malformed ARP frames
        // with off-spec lengths would cause us to read sender/target
        // fields from the wrong offsets and either learn garbage
        // bindings or miss spoofs. The fixed offsets used below assume
        // hlen=6/plen=4, so we must reject anything else outright.
        if pkt.payload[4] != 6 || pkt.payload[5] != 4 {
            return None;
        }

        let operation = u16::from_be_bytes([pkt.payload[6], pkt.payload[7]]);

        // Process ARP replies and gratuitous ARP requests (sender_ip == target_ip).
        let is_reply = operation == ARP_OP_REPLY;
        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&pkt.payload[14..18]);
        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&pkt.payload[24..28]);
        let is_gratuitous = operation == ARP_OP_REQUEST && sender_ip == target_ip;

        if !is_reply && !is_gratuitous {
            return None;
        }

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&pkt.payload[8..14]);

        // Check binding in learned table.
        self.check_arp_binding(sender_ip, sender_mac, pkt, ts_us)
    }

    /// Check an IP-to-MAC binding against the ARP table, learn if new.
    fn check_arp_binding(
        &mut self,
        ip: [u8; 4],
        mac: [u8; 6],
        pkt: &EthPacket<'_>,
        ts_us: u64,
    ) -> Option<SecurityAlert> {
        // Hash-indexed lookup: O(1) average via open addressing with SipHash.
        let start = self.arp_slot_for_ip(&ip);
        for i in 0..MAX_ARP_ENTRIES {
            let idx = (start + i) & (MAX_ARP_ENTRIES - 1);
            let entry = &self.arp_table[idx];
            if !entry.valid {
                break; // empty slot → IP not in table
            }
            if entry.ip == ip {
                // Constant-time comparison to prevent timing side-channels
                // that could leak MAC address bytes.
                if !vs_types::constant_time_eq(&entry.mac, &mac) {
                    return Some(self.make_alert(
                        ALERT_ID_ARP_SPOOF,
                        AlertSeverity::Critical,
                        ts_us,
                        pkt.payload,
                    ));
                }
                return None;
            }
        }

        // Rate limit learning — emit a Medium alert once per tick so ARP
        // flood attacks are not silently swallowed.
        if self.arp_learn_count >= MAX_ARP_LEARNS_PER_TICK {
            if !self.arp_rate_limit_alerted {
                self.arp_rate_limit_alerted = true;
                return Some(self.make_alert(
                    ALERT_ID_ARP_RATE_LIMIT,
                    AlertSeverity::Medium,
                    ts_us,
                    pkt.payload,
                ));
            }
            return None;
        }

        let evicted = self.learn_arp(ip, mac);
        if evicted {
            self.arp_eviction_count += 1;
            if self.arp_eviction_count >= ARP_EVICTION_FLOOD_THRESHOLD {
                return Some(self.make_alert(
                    ALERT_ID_ARP_EVICTION_FLOOD,
                    AlertSeverity::High,
                    ts_us,
                    pkt.payload,
                ));
            }
        }
        None
    }

    /// Hash an IP address to an ARP table slot index using SipHash.
    fn arp_slot_for_ip(&self, ip: &[u8; 4]) -> usize {
        let h = vs_types::siphash_2_4(ip, self.siphash_keys[0].0, self.siphash_keys[0].1);
        (h as usize) & (MAX_ARP_ENTRIES - 1)
    }

    /// Learn a new ARP binding. Returns `true` if an existing entry was evicted.
    ///
    /// Eviction policy: when the table is full, the new binding overwrites
    /// the entry at the hash slot derived from `ip`. The slot is computed
    /// via SipHash keyed with `siphash_keys[0]`, which the workspace
    /// invariant requires to come from the platform TRNG — see
    /// `EthMonitor::new`, which rejects all-zero keys. An attacker cannot
    /// predict which legitimate binding they would dislodge, so targeted
    /// eviction of a specific known victim is not feasible.
    fn learn_arp(&mut self, ip: [u8; 4], mac: [u8; 6]) -> bool {
        self.arp_learn_count += 1;

        let start = self.arp_slot_for_ip(&ip);

        // Open-addressing insert: probe from the hash slot. Skip the probe
        // entirely once `arp_table_full` is latched — every slot is
        // occupied, so the loop below would just fall through to the
        // eviction branch. This saves up to MAX_ARP_ENTRIES iterations
        // per learn call on a saturated table (the steady state under
        // flood).
        if !self.arp_table_full {
            for i in 0..MAX_ARP_ENTRIES {
                let idx = (start + i) & (MAX_ARP_ENTRIES - 1);
                if !self.arp_table[idx].valid {
                    self.arp_table[idx] = ArpEntry {
                        ip,
                        mac,
                        valid: true,
                    };
                    // If this was the last possible empty slot reachable
                    // by the probe sequence, latch the table-full flag so
                    // the next learn skips the probe entirely.
                    if i == MAX_ARP_ENTRIES - 1 {
                        self.arp_table_full = true;
                    }
                    return false;
                }
            }
            // Loop exhausted with no empty slot found → table is full.
            self.arp_table_full = true;
        }
        // Table full — evict at the hash slot. SipHash keys are
        // TRNG-derived (see doc above), so the victim slot is
        // unpredictable for an attacker that only sees plaintext IPs.
        self.arp_table[start] = ArpEntry {
            ip,
            mac,
            valid: true,
        };
        true
    }

    /// Periodic tick for ARP: resets learning rate and eviction counters.
    pub fn arp_tick(&mut self) {
        self.arp_learn_count = 0;
        self.arp_eviction_count = 0;
        self.arp_rate_limit_alerted = false;
    }

    /// SOME/IP checks:
    ///   - Unknown service: `service_id` not in allow-list for this MAC pair.
    ///   - Oversized payload: length > configured max.
    ///   - SD (Service Discovery) messages: parse entries, track services,
    ///     detect unauthorized offers and flood.
    ///
    /// SOME/IP runs on top of IP/UDP (well-known port `30490`). This
    /// helper requires `dst_port` to explicitly match the SOME/IP UDP
    /// port and treats `pkt.payload` as the already-stripped SOME/IP
    /// message (the L3/L4 headers removed). `inspect_packet` derives
    /// both fields via the L3/L4 parsers before dispatching here.
    ///
    /// SECURITY: this checker must never be invoked on a raw IP payload
    /// (IP header still present). Doing so reinterprets IP-header bytes
    /// 4..8 as the SOME/IP `length` field, producing spurious
    /// `ALERT_ID_SOMEIP_OVERSIZE` false positives. The `dst_port` gate
    /// fails closed: a packet without a confirmed SOME/IP port is
    /// ignored rather than mis-parsed.
    fn check_someip(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        // Fail closed: only parse SOME/IP when the transport destination
        // port is confirmed to be the SOME/IP UDP port. The EtherType
        // alone is insufficient — it does not imply the payload has been
        // stripped down to the SOME/IP message.
        if pkt.dst_port != Some(SOMEIP_UDP_PORT) {
            return None;
        }
        let hdr = parse_someip_header(pkt.payload)?;

        // Check oversized payload — both header length field and actual size.
        //
        // AUTOSAR / SOME/IP semantics: `hdr.length` measures everything
        // after the length word itself (8 fixed header bytes + variable
        // payload). `someip_max_length` is the operator-configured cap
        // applied directly to the wire `length` field, matching how
        // boundary tests (e.g. `someip_exact_max_length_boundary`,
        // `someip_within_budget_exact_boundary`) describe the contract:
        // `length == someip_max_length` passes; one byte over rejects.
        if hdr.length > self.someip_max_length {
            return Some(self.make_alert(
                ALERT_ID_SOMEIP_OVERSIZE,
                AlertSeverity::High,
                ts_us,
                pkt.payload,
            ));
        }
        if pkt.payload.len() > (self.someip_max_length as usize).saturating_add(SOMEIP_HEADER_SIZE)
        {
            return Some(self.make_alert(
                ALERT_ID_SOMEIP_LENGTH_MISMATCH,
                AlertSeverity::High,
                ts_us,
                pkt.payload,
            ));
        }

        // Detect SOME/IP-SD messages (service_id=0xFFFF, method_id=0x8100).
        if hdr.service_id == SOMEIP_SD_SERVICE_ID && hdr.method_id == SOMEIP_SD_METHOD_ID {
            return self.check_someip_sd(pkt, ts_us);
        }

        // Check allow-list.
        if self.allow_list_len > 0 && !self.is_service_allowed(pkt, hdr.service_id) {
            return Some(self.make_alert(
                ALERT_ID_SOMEIP_UNKNOWN,
                AlertSeverity::Medium,
                ts_us,
                pkt.payload,
            ));
        }

        None
    }

    fn is_service_allowed(&self, pkt: &EthPacket<'_>, service_id: u16) -> bool {
        // Use hash table for O(1) average-case lookup instead of O(n) scan.
        //
        // The lookup probe length must match the insertion probe length
        // (`ALLOW_HASH_CAPACITY`); otherwise an entry inserted past the
        // lookup cap becomes "ghost-deny" — present in the table but
        // unreachable from queries, silently denying authorized traffic.
        // The table's worst case is bounded by occupancy (`MAX_ALLOW_LIST`
        // = 64 entries in a 128-slot table = 50% load factor), so the
        // expected probe chain is short and a full-capacity probe is
        // safe.
        let h = allow_list_hash(&pkt.src_mac, &pkt.dst_mac, service_id);
        for j in 0..ALLOW_HASH_CAPACITY {
            let idx = (h + j) & (ALLOW_HASH_CAPACITY - 1);
            let slot = self.allow_hash[idx];
            if slot == ALLOW_HASH_EMPTY {
                return false; // Not found.
            }
            // Bounds-check slot index before array access to prevent
            // out-of-bounds access from corrupted hash table state.
            let slot_usize = slot as usize;
            if slot_usize >= self.allow_list.len() {
                return false;
            }
            if let Some(entry) = &self.allow_list[slot_usize] {
                if vs_types::constant_time_eq(&entry.src_mac, &pkt.src_mac)
                    && vs_types::constant_time_eq(&entry.dst_mac, &pkt.dst_mac)
                    && entry.service_id == service_id
                {
                    return true;
                }
            }
        }
        false
    }

    /// `DoIP` checks: ensure routing activation has been completed before
    /// diagnostic messages are accepted. Validates `payload_length` against
    /// actual data and rate-limits session creation.
    fn check_doip(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        let hdr = parse_doip_header(pkt.payload)?;

        // Validate inverse version (should be bitwise NOT of protocol_version).
        if hdr.inverse_version != !hdr.protocol_version {
            return None;
        }

        // Validate payload_length against actual remaining data.
        // Use u32::try_from to avoid silent truncation on 64-bit systems
        // where payload.len() could theoretically exceed u32::MAX.
        let Ok(remaining) = u32::try_from(pkt.payload.len().saturating_sub(DOIP_HEADER_SIZE))
        else {
            // Payload length exceeds u32::MAX — flag as anomaly rather
            // than silently accepting with a sentinel value.
            return Some(self.make_alert(
                ALERT_ID_DOIP_MALFORMED,
                AlertSeverity::High,
                ts_us,
                pkt.payload,
            ));
        };
        if hdr.payload_length > remaining {
            return Some(self.make_alert(
                ALERT_ID_DOIP_MALFORMED,
                AlertSeverity::Medium,
                ts_us,
                pkt.payload,
            ));
        }

        match hdr.payload_type {
            DOIP_ROUTING_ACTIVATION_REQUEST => {
                // Reject activation requests sent to a broadcast or
                // multicast destination MAC: such a request cannot have
                // a single expected responder, and recording one would
                // let any host on the segment forge the activation
                // response. Silently dropping is sufficient — no session
                // is created.
                if is_broadcast_or_multicast_mac(&pkt.dst_mac) {
                    return None;
                }
                // Require a bound TCP destination port. `DoIP` runs over
                // TCP; an activation request without a destination port
                // has no TCP-tuple to bind the session to and cannot be
                // safely promoted later.
                let dst_port = pkt.dst_port?;
                // Rate-limit session creation to prevent table exhaustion.
                if self.doip_activation_count >= MAX_DOIP_ACTIVATIONS_PER_TICK {
                    return Some(self.make_alert(
                        ALERT_ID_DOIP_RATE_LIMIT,
                        AlertSeverity::High,
                        ts_us,
                        pkt.payload,
                    ));
                }
                self.doip_activation_count += 1;
                let evicted = self.doip_set_state(
                    pkt.src_mac,
                    DoIpSessionState::RoutingActivated,
                    ts_us,
                    pkt.dst_mac,
                    dst_port,
                );
                if evicted {
                    return Some(self.make_alert(
                        ALERT_ID_DOIP_SESSION_EVICTION,
                        AlertSeverity::Medium,
                        ts_us,
                        pkt.payload,
                    ));
                }
                None
            }
            DOIP_ROUTING_ACTIVATION_RESPONSE => {
                // Only promote to Active if the target MAC already has an
                // existing session in RoutingActivated state AND the response
                // comes from the expected responder bound at request time.
                // Looking up by `pkt.dst_mac` alone would let an attacker
                // promote any session whose client MAC they can spoof;
                // requiring the responder match prevents that.
                //
                // We don't match the response packet's `dst_port` against
                // the stored one because the response travels in the
                // reverse direction over the same TCP connection — its
                // dst_port is the client's ephemeral source port, not
                // the original server port. The TCP-tuple binding is
                // enforced at the diagnostic-message check below.
                let dst_mac = pkt.dst_mac;
                let src_mac = pkt.src_mac;
                let session_idx = self.doip_find_session_for_promotion(dst_mac, src_mac);
                if let Some(idx) = session_idx {
                    self.doip_sessions[idx].state = DoIpSessionState::Active;
                    self.doip_sessions[idx].last_activity = ts_us;
                }
                None
            }
            DOIP_DIAGNOSTIC_MESSAGE
            | DOIP_DIAGNOSTIC_POSITIVE_ACK
            | DOIP_DIAGNOSTIC_NEGATIVE_ACK => {
                // Diagnostic messages must match the activated session's
                // TCP tuple: same src_mac AND same dst_port. An attacker
                // who has activated a session against server port X must
                // not be able to send diagnostics against server port Y
                // on the same MAC.
                let state = self.doip_get_state(pkt.src_mac, pkt.dst_port);
                match state {
                    DoIpSessionState::RoutingActivated | DoIpSessionState::Active => None,
                    DoIpSessionState::Idle => Some(self.make_alert(
                        ALERT_ID_DOIP_UNAUTH,
                        AlertSeverity::Critical,
                        ts_us,
                        pkt.payload,
                    )),
                }
            }
            _ => None,
        }
    }

    /// Look up the state of the session bound to `(mac, dst_port)`.
    ///
    /// The TCP-tuple binding (src_mac + dst_port) prevents an activated
    /// session against one server port from authorizing traffic against
    /// another. A diagnostic packet without a `dst_port` cannot match a
    /// session (sessions always have a bound port) and is treated as
    /// `Idle`.
    fn doip_get_state(&self, mac: [u8; 6], dst_port: Option<u16>) -> DoIpSessionState {
        let Some(port) = dst_port else {
            return DoIpSessionState::Idle;
        };
        let mut result = DoIpSessionState::Idle;
        for session in &self.doip_sessions {
            if vs_types::constant_time_eq(&session.src_mac, &mac)
                && session.dst_port == Some(port)
                && session.state != DoIpSessionState::Idle
            {
                result = session.state;
            }
        }
        result
    }

    /// Find a session eligible for promotion to `Active` given an
    /// incoming routing-activation response.
    ///
    /// Returns the index of a session whose `src_mac` matches
    /// `session_mac` (the client MAC), whose `expected_responder`
    /// matches `responder_mac` (the response's src MAC), and which is
    /// currently in `RoutingActivated` state. Returns `None` if no such
    /// session exists, preventing forged responses from elevating an
    /// arbitrary or unbound session.
    fn doip_find_session_for_promotion(
        &self,
        session_mac: [u8; 6],
        responder_mac: [u8; 6],
    ) -> Option<usize> {
        let mut found = None;
        for (i, session) in self.doip_sessions.iter().enumerate() {
            if session.state == DoIpSessionState::RoutingActivated
                && vs_types::constant_time_eq(&session.src_mac, &session_mac)
                && vs_types::constant_time_eq(&session.expected_responder, &responder_mac)
            {
                found = Some(i);
            }
        }
        found
    }

    /// Set the state of a `DoIP` session, keyed by the TCP tuple
    /// `(mac, dst_port)`. Returns `true` if an existing session was
    /// evicted to make room for the new one.
    fn doip_set_state(
        &mut self,
        mac: [u8; 6],
        state: DoIpSessionState,
        ts_us: u64,
        responder: [u8; 6],
        dst_port: u16,
    ) -> bool {
        // Update existing session bound to the same TCP tuple.
        for session in &mut self.doip_sessions {
            if vs_types::constant_time_eq(&session.src_mac, &mac)
                && session.dst_port == Some(dst_port)
                && session.state != DoIpSessionState::Idle
            {
                session.state = state;
                session.last_activity = ts_us;
                session.expected_responder = responder;
                return false;
            }
        }
        // Allocate a new session slot.
        for session in &mut self.doip_sessions {
            if session.state == DoIpSessionState::Idle {
                session.src_mac = mac;
                session.state = state;
                session.last_activity = ts_us;
                session.expected_responder = responder;
                session.dst_port = Some(dst_port);
                return false;
            }
        }
        // All slots occupied — evict the oldest (least recently active) session.
        let mut oldest_idx = 0;
        let mut oldest_ts = u64::MAX;
        for (i, session) in self.doip_sessions.iter().enumerate() {
            if session.last_activity < oldest_ts {
                oldest_ts = session.last_activity;
                oldest_idx = i;
            }
        }
        self.doip_sessions[oldest_idx].src_mac = mac;
        self.doip_sessions[oldest_idx].state = state;
        self.doip_sessions[oldest_idx].last_activity = ts_us;
        self.doip_sessions[oldest_idx].expected_responder = responder;
        self.doip_sessions[oldest_idx].dst_port = Some(dst_port);
        true
    }

    // -----------------------------------------------------------------------
    // SOME/IP-SD helpers
    // -----------------------------------------------------------------------

    /// Check a SOME/IP-SD message for unauthorized service offers and flood.
    fn check_someip_sd(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        // Increment SD message counter for flood detection.
        self.sd_message_count = self.sd_message_count.saturating_add(1);
        if self.sd_message_count >= SD_FLOOD_THRESHOLD {
            return Some(self.make_alert(
                ALERT_ID_SOMEIP_SD_FLOOD,
                AlertSeverity::High,
                ts_us,
                pkt.payload,
            ));
        }

        // Parse SD entries from the payload after the 16-byte SOME/IP header.
        let sd_payload = if pkt.payload.len() > SOMEIP_HEADER_SIZE {
            &pkt.payload[SOMEIP_HEADER_SIZE..]
        } else {
            return None;
        };

        let (_flags, count, entries) = parse_sd_entries(sd_payload);

        // Cache the allow-list lookup: `pkt.src_mac` is constant across
        // every entry in this SD message, but `is_mac_in_allow_list` is
        // a constant-time MAX_ALLOW_LIST-iteration scan. Doing it once
        // saves O(entries * MAX_ALLOW_LIST) work per OfferService-heavy
        // SD message. The boolean carries no timing signal about which
        // entry matched.
        let src_allowed = self.is_mac_in_allow_list(pkt.src_mac);

        for entry in entries.iter().take(count) {
            let Some(entry) = entry else {
                continue;
            };

            match entry.entry_type {
                SdEntryType::OfferService => {
                    // Check if the source MAC is authorized to offer services.
                    if self.allow_list_len > 0 && !src_allowed {
                        return Some(self.make_alert(
                            ALERT_ID_SOMEIP_SD_UNAUTH,
                            AlertSeverity::High,
                            ts_us,
                            pkt.payload,
                        ));
                    }

                    // TTL=0 means the service is being stopped.
                    if entry.ttl == 0 {
                        self.sd_remove_service(entry.service_id, entry.instance_id, pkt.src_mac);
                    } else {
                        self.sd_track_service(
                            entry.service_id,
                            entry.instance_id,
                            pkt.src_mac,
                            entry.ttl,
                        );
                    }
                }
                SdEntryType::StopSubscribe
                | SdEntryType::FindService
                | SdEntryType::SubscribeEventgroup => {
                    // Stop-subscribe, find, and subscribe are normal SD operations, no alert needed.
                }
            }
        }

        None
    }

    /// Check whether a source MAC appears anywhere in the allow-list.
    ///
    /// Uses constant-time comparison and a full scan to avoid leaking
    /// allow-list contents via timing side-channels.
    fn is_mac_in_allow_list(&self, src_mac: [u8; 6]) -> bool {
        let mut found = false;
        // Iterate full capacity to prevent timing side-channel leaking
        // the number of entries in the allow list.
        for i in 0..MAX_ALLOW_LIST {
            if let Some(entry) = &self.allow_list[i] {
                found |= vs_types::constant_time_eq(&entry.src_mac, &src_mac);
            }
        }
        found
    }

    /// Track or update a service in the SD service table.
    fn sd_track_service(
        &mut self,
        service_id: u16,
        instance_id: u16,
        source_mac: [u8; 6],
        ttl: u32,
    ) {
        // Update existing entry if present.
        for entry in &mut self.sd_service_table {
            if entry.active
                && entry.service_id == service_id
                && entry.instance_id == instance_id
                && entry.source_mac == source_mac
            {
                entry.ttl_remaining = ttl;
                return;
            }
        }
        // Find an empty slot.
        self.sd_insertion_counter = self.sd_insertion_counter.saturating_add(1);
        for entry in &mut self.sd_service_table {
            if !entry.active {
                entry.service_id = service_id;
                entry.instance_id = instance_id;
                entry.source_mac = source_mac;
                entry.ttl_remaining = ttl;
                entry.insertion_order = self.sd_insertion_counter;
                entry.active = true;
                return;
            }
        }
        // Table full — evict the oldest-inserted entry (lowest
        // insertion_order), or an entry whose TTL has already reached 0.
        // This prevents an attacker from flooding the table with
        // high-TTL entries to push out legitimate services, since newly
        // injected entries are the *youngest* and thus evicted first on
        // the next round.
        let mut victim_idx = 0;
        let mut victim_order = u64::MAX;
        for (i, entry) in self.sd_service_table.iter().enumerate() {
            // Prefer entries with TTL=0 (expired but not yet reaped).
            if entry.ttl_remaining == 0 {
                victim_idx = i;
                break;
            }
            if entry.insertion_order < victim_order {
                victim_order = entry.insertion_order;
                victim_idx = i;
            }
        }
        let slot = &mut self.sd_service_table[victim_idx];
        slot.service_id = service_id;
        slot.instance_id = instance_id;
        slot.source_mac = source_mac;
        slot.ttl_remaining = ttl;
        slot.insertion_order = self.sd_insertion_counter;
        slot.active = true;
    }

    /// Remove a service from the SD service table (TTL=0 stop-offer).
    fn sd_remove_service(&mut self, service_id: u16, instance_id: u16, source_mac: [u8; 6]) {
        for entry in &mut self.sd_service_table {
            if entry.active
                && entry.service_id == service_id
                && entry.instance_id == instance_id
                && vs_types::constant_time_eq(&entry.source_mac, &source_mac)
            {
                *entry = SdServiceEntry::empty();
                return;
            }
        }
    }

    /// Periodic tick for SD: decrement TTLs and deactivate expired services.
    /// Also resets the SD flood counter.
    pub fn sd_tick(&mut self) {
        for entry in &mut self.sd_service_table {
            if entry.active {
                if entry.ttl_remaining == 0 {
                    *entry = SdServiceEntry::empty();
                } else {
                    entry.ttl_remaining = entry.ttl_remaining.saturating_sub(1);
                }
            }
        }
        // Decay by 25% per tick instead of 50%. This makes sustained
        // medium-rate floods (e.g., 50 msgs/tick) eventually cross the
        // threshold. Equilibrium point: count * 0.75 + rate = count →
        // count = rate * 4. So 26+ msgs/tick will eventually trigger
        // the threshold of 100.
        self.sd_message_count = self
            .sd_message_count
            .saturating_sub(self.sd_message_count / 4);
    }

    /// Returns the number of currently active (tracked) SD services.
    pub fn sd_active_service_count(&self) -> usize {
        self.sd_service_table.iter().filter(|e| e.active).count()
    }

    /// Periodic tick for `DoIP`: expire sessions inactive for longer than
    /// `DOIP_SESSION_TIMEOUT_US` and reset the activation rate counter.
    pub fn doip_tick(&mut self, now_us: u64) {
        for session in &mut self.doip_sessions {
            if session.state != DoIpSessionState::Idle
                && now_us.saturating_sub(session.last_activity) > DOIP_SESSION_TIMEOUT_US
            {
                *session = DoIpSession::empty();
            }
        }
        self.doip_activation_count = 0;
    }
}

// ===========================================================================
// L3/L4 Parsing (zero-copy, no_std)
// ===========================================================================

/// Parse an IPv4 header from the Ethernet payload.
/// Returns `None` if the payload is too short or the version field is wrong.
pub fn parse_ipv4(payload: &[u8]) -> Option<IpHeader> {
    if payload.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let version = payload[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (payload[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    if header_len < IPV4_MIN_HEADER_LEN || payload.len() < header_len {
        return None;
    }
    let total_len = u16::from_be_bytes([payload[2], payload[3]]);
    let protocol = IpProtocol::from_u8(payload[9]);

    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&payload[12..16]);
    dst.copy_from_slice(&payload[16..20]);

    let payload_len = total_len.saturating_sub(header_len as u16);

    Some(IpHeader {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        payload_len,
    })
}

/// Check whether an IPv6 Next Header value is an extension header that
/// should be chained through (i.e., not an upper-layer protocol).
///
/// The following extension-header types are **deliberately not walked**;
/// they terminate the chain so the upper-layer dispatcher treats them as
/// an unknown protocol rather than continuing past them:
///
/// - **50** (ESP) — payload is encrypted, the inner Next Header is not
///   visible in cleartext.
/// - **135** (Mobility Header, RFC 6275) — used by Mobile IPv6; not
///   relevant for automotive Ethernet IDS and the encoding is
///   message-type specific rather than a generic ext-hdr layout.
/// - **139** (HIP, RFC 7401) and **140** (Shim6, RFC 5533) — niche
///   protocols not present on automotive networks; walking them would
///   require protocol-specific parsing.
/// - **253**, **254** — reserved for experimentation (RFC 3692); we
///   refuse to interpret them so a malformed experimental header
///   cannot drive the chain walker past attacker-controlled offsets.
fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0  |  // Hop-by-Hop Options
        43 |  // Routing
        44 |  // Fragment
        60 |  // Destination Options
        51 // Authentication Header (AH)
    )
}

/// Walk the IPv6 extension header chain starting at `offset` in `payload`.
///
/// Returns `(upper_layer_protocol, offset_to_upper_layer)` by following
/// the Next Header + Hdr Ext Len fields of each extension header.
///
/// Stops at the first non-extension Next Header value (TCP, UDP, ICMP,
/// ESP, etc.) or when the payload is exhausted.
fn walk_ipv6_extension_headers(
    payload: &[u8],
    first_next_header: u8,
    start_offset: usize,
) -> (u8, usize) {
    let mut nh = first_next_header;
    let mut offset = start_offset;

    // Safety limit: at most 16 extension headers to prevent infinite loops
    // in malformed packets.
    for _ in 0..16 {
        if !is_ipv6_extension_header(nh) {
            break;
        }

        // All extension headers (except Fragment) have:
        //   byte 0: Next Header
        //   byte 1: Hdr Ext Len (in 8-byte units, not counting first 8 bytes)
        // Fragment header is fixed 8 bytes with byte 1 being "Reserved".
        if offset + 2 > payload.len() {
            break;
        }

        let next = payload[offset];

        if nh == 44 {
            // Fragment header: fixed 8 bytes.
            if offset + 8 > payload.len() {
                break;
            }
            offset += 8;
        } else if nh == 51 {
            // Authentication Header (RFC 4302 §2.2): the length field is
            // "Payload Len" — the AH header length in 4-octet units,
            // minus 2 (i.e. the count of 4-octet words past the first
            // 8 bytes). Concretely the on-the-wire size is
            // `(payload_len + 2) * 4` bytes. The IPv6-generic
            // `(Hdr Ext Len + 1) * 8` formula used for Hop-by-Hop /
            // Routing / Destination Options does NOT apply here.
            let payload_len = payload[offset + 1] as usize;
            let hdr_size = (payload_len + 2) * 4;
            if offset + hdr_size > payload.len() {
                break;
            }
            offset += hdr_size;
        } else {
            // Standard extension header: (Hdr Ext Len + 1) * 8 bytes.
            let hdr_ext_len = payload[offset + 1] as usize;
            let hdr_size = (hdr_ext_len + 1) * 8;
            if offset + hdr_size > payload.len() {
                break;
            }
            offset += hdr_size;
        }

        nh = next;
    }

    (nh, offset)
}

/// Parse an IPv6 header from the Ethernet payload, walking through any
/// extension headers (Hop-by-Hop, Routing, Fragment, Destination Options,
/// Authentication Header) to find the upper-layer protocol.
///
/// Returns `None` if the payload is too short or the version field is wrong.
pub fn parse_ipv6(payload: &[u8]) -> Option<IpHeader> {
    if payload.len() < IPV6_HEADER_LEN {
        return None;
    }
    let version = payload[0] >> 4;
    if version != 6 {
        return None;
    }
    let payload_length = u16::from_be_bytes([payload[4], payload[5]]);
    let next_header = payload[6];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    dst.copy_from_slice(&payload[24..40]);

    // Walk extension header chain to find the actual upper-layer protocol.
    let (upper_proto, _) = walk_ipv6_extension_headers(payload, next_header, IPV6_HEADER_LEN);
    let protocol = IpProtocol::from_u8(upper_proto);

    Some(IpHeader {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol,
        payload_len: payload_length,
    })
}

/// Parse an IPv6 header and return the offset to the upper-layer payload
/// (after any extension headers).
fn parse_ipv6_with_offset(payload: &[u8]) -> Option<(IpHeader, usize)> {
    if payload.len() < IPV6_HEADER_LEN {
        return None;
    }
    let version = payload[0] >> 4;
    if version != 6 {
        return None;
    }
    let payload_length = u16::from_be_bytes([payload[4], payload[5]]);
    let next_header = payload[6];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    dst.copy_from_slice(&payload[24..40]);

    let (upper_proto, offset) = walk_ipv6_extension_headers(payload, next_header, IPV6_HEADER_LEN);
    let protocol = IpProtocol::from_u8(upper_proto);

    Some((
        IpHeader {
            src: IpAddr::V6(src),
            dst: IpAddr::V6(dst),
            protocol,
            payload_len: payload_length,
        },
        offset,
    ))
}

/// Parse an IP header (auto-detecting v4 vs v6) from the Ethernet payload.
/// Returns the `IpHeader` and the offset to the transport header.
pub fn parse_ip(ethertype: u16, payload: &[u8]) -> Option<(IpHeader, usize)> {
    match ethertype {
        ETHERTYPE_IPV4 => {
            let hdr = parse_ipv4(payload)?;
            let ihl = (payload[0] & 0x0F) as usize;
            Some((hdr, ihl * 4))
        }
        ETHERTYPE_IPV6 => parse_ipv6_with_offset(payload),
        _ => None,
    }
}

/// Parse a TCP or UDP transport header from the payload at the given offset.
pub fn parse_transport(
    protocol: IpProtocol,
    data: &[u8],
    offset: usize,
) -> Option<TransportHeader> {
    let remaining = data.get(offset..)?;
    match protocol {
        IpProtocol::Tcp => {
            if remaining.len() < TCP_MIN_HEADER_LEN {
                return None;
            }
            let src_port = u16::from_be_bytes([remaining[0], remaining[1]]);
            let dst_port = u16::from_be_bytes([remaining[2], remaining[3]]);
            let flags = remaining[13];
            Some(TransportHeader {
                src_port,
                dst_port,
                tcp_flags: flags,
            })
        }
        IpProtocol::Udp => {
            if remaining.len() < UDP_HEADER_LEN {
                return None;
            }
            let src_port = u16::from_be_bytes([remaining[0], remaining[1]]);
            let dst_port = u16::from_be_bytes([remaining[2], remaining[3]]);
            Some(TransportHeader {
                src_port,
                dst_port,
                tcp_flags: 0,
            })
        }
        _ => None,
    }
}

/// Strip the L3 (IP) and L4 (TCP/UDP) headers from a raw IP packet,
/// returning the L4 payload slice and the transport destination port.
///
/// Used by [`EthMonitor::inspect_packet`] to derive the protocol
/// dispatch key (`dst_port`) and the stripped payload internally when
/// the caller did not pre-populate `EthPacket::dst_port`.
///
/// Returns `None` (fail closed) when:
///   - the EtherType is not IPv4/IPv6,
///   - the IP header is truncated or malformed,
///   - the transport protocol is not TCP or UDP,
///   - the transport header is truncated, or
///   - the computed L4 offset would exceed the buffer.
fn strip_l3_l4(ethertype: u16, payload: &[u8]) -> Option<(&[u8], u16)> {
    let (ip_hdr, l4_offset) = parse_ip(ethertype, payload)?;
    let transport = parse_transport(ip_hdr.protocol, payload, l4_offset)?;
    // Compute the L4 header length so the payload can be stripped down
    // to the upper-layer message (SOME/IP / DoIP).
    let l4_hdr_len = match ip_hdr.protocol {
        IpProtocol::Udp => UDP_HEADER_LEN,
        IpProtocol::Tcp => {
            // TCP data offset is in the high nibble of byte 12, measured
            // in 32-bit words. Bounded to >= TCP_MIN_HEADER_LEN so a
            // crafted small data-offset cannot under-strip the header.
            let data_off_byte = *payload.get(l4_offset.checked_add(12)?)?;
            let words = (data_off_byte >> 4) as usize;
            (words * 4).max(TCP_MIN_HEADER_LEN)
        }
        _ => return None,
    };
    let payload_start = l4_offset.checked_add(l4_hdr_len)?;
    let stripped = payload.get(payload_start..)?;
    Some((stripped, transport.dst_port))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference (unfused) implementation: 4 separate SipHash-2-4 passes
    /// over the payload. Used to validate the fused implementation.
    fn compute_payload_hash_reference(payload: &[u8], keys: &[(u64, u64); 4]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (chunk_idx, &(k0, k1)) in keys.iter().enumerate() {
            let h = vs_types::siphash_2_4(payload, k0, k1);
            result[chunk_idx * 8..chunk_idx * 8 + 8].copy_from_slice(&h.to_le_bytes());
        }
        result
    }

    #[test]
    fn fused_payload_hash_matches_reference() {
        // Test across boundary cases that exercise the tail-block path:
        // empty, sub-block (1..7), exact block (8), block + tail (9..15),
        // multiple blocks (16..), and odd large size.
        let lengths: &[usize] = &[0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 200];
        for &n in lengths {
            // Build a deterministic test payload.
            let mut payload = [0u8; 256];
            for i in 0..n {
                payload[i] = ((i as u8).wrapping_mul(31)).wrapping_add(7);
            }
            let p = &payload[..n];
            let fused = compute_payload_hash(p, &DEFAULT_SIPHASH_KEYS);
            let reference = compute_payload_hash_reference(p, &DEFAULT_SIPHASH_KEYS);
            assert_eq!(
                fused, reference,
                "fused 4-lane SipHash output differs from 4x naive at len={n}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Helper builders
    // -----------------------------------------------------------------------

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const MAC_C: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    fn default_monitor() -> EthMonitor {
        EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap()
    }

    /// Build a minimal SOME/IP payload from the given header fields.
    #[allow(clippy::too_many_arguments)]
    fn make_someip_payload(
        service_id: u16,
        method_id: u16,
        length: u32,
        client_id: u16,
        session_id: u16,
        protocol_version: u8,
        interface_version: u8,
        message_type: u8,
        return_code: u8,
    ) -> [u8; SOMEIP_HEADER_SIZE] {
        let mut buf = [0u8; SOMEIP_HEADER_SIZE];
        buf[0..2].copy_from_slice(&service_id.to_be_bytes());
        buf[2..4].copy_from_slice(&method_id.to_be_bytes());
        buf[4..8].copy_from_slice(&length.to_be_bytes());
        buf[8..10].copy_from_slice(&client_id.to_be_bytes());
        buf[10..12].copy_from_slice(&session_id.to_be_bytes());
        buf[12] = protocol_version;
        buf[13] = interface_version;
        buf[14] = message_type;
        buf[15] = return_code;
        buf
    }

    /// Build a minimal `DoIP` generic header payload.
    fn make_doip_payload(
        protocol_version: u8,
        payload_type: u16,
        payload_length: u32,
    ) -> [u8; DOIP_HEADER_SIZE] {
        let mut buf = [0u8; DOIP_HEADER_SIZE];
        buf[0] = protocol_version;
        buf[1] = !protocol_version;
        buf[2..4].copy_from_slice(&payload_type.to_be_bytes());
        buf[4..8].copy_from_slice(&payload_length.to_be_bytes());
        buf
    }

    /// Build a minimal ARP reply payload (28 bytes for IPv4-over-Ethernet).
    fn make_arp_reply(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> [u8; 28] {
        let mut buf = [0u8; 28];
        // Hardware type = Ethernet (1)
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        // Protocol type = IPv4 (0x0800)
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        // Hardware addr len = 6, Protocol addr len = 4
        buf[4] = 6;
        buf[5] = 4;
        // Operation = Reply (2)
        buf[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
        // Sender MAC
        buf[8..14].copy_from_slice(&sender_mac);
        // Sender IP
        buf[14..18].copy_from_slice(&sender_ip);
        // Target fields left as zero — not needed for detection.
        buf
    }

    // -----------------------------------------------------------------------
    // SOME/IP parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn someip_parse_valid_header() {
        let payload = make_someip_payload(0x1234, 0x5678, 100, 0x0A0B, 0x0C0D, 1, 2, 0x00, 0x00);
        let hdr = parse_someip_header(&payload);
        assert!(hdr.is_some());
        let hdr = hdr.unwrap();
        assert_eq!(hdr.service_id, 0x1234);
        assert_eq!(hdr.method_id, 0x5678);
        assert_eq!(hdr.length, 100);
        assert_eq!(hdr.client_id, 0x0A0B);
        assert_eq!(hdr.session_id, 0x0C0D);
        assert_eq!(hdr.protocol_version, 1);
        assert_eq!(hdr.interface_version, 2);
        assert_eq!(hdr.message_type, 0x00);
        assert_eq!(hdr.return_code, 0x00);
    }

    #[test]
    fn someip_parse_too_short() {
        let payload = [0u8; 15]; // one byte short
        assert!(parse_someip_header(&payload).is_none());
    }

    #[test]
    fn someip_parse_empty() {
        assert!(parse_someip_header(&[]).is_none());
    }

    #[test]
    fn someip_parse_exact_size() {
        let payload = make_someip_payload(1, 2, 8, 3, 4, 1, 1, 0, 0);
        assert!(parse_someip_header(&payload).is_some());
    }

    #[test]
    fn someip_parse_extra_bytes() {
        let mut buf = [0u8; 32];
        let header = make_someip_payload(0xFFFF, 0x0001, 500, 10, 20, 1, 1, 0, 0);
        buf[..SOMEIP_HEADER_SIZE].copy_from_slice(&header);
        buf[SOMEIP_HEADER_SIZE..].fill(0xAA);
        let hdr = parse_someip_header(&buf).unwrap();
        assert_eq!(hdr.service_id, 0xFFFF);
        assert_eq!(hdr.length, 500);
    }

    // -----------------------------------------------------------------------
    // DoIP parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn doip_parse_valid_header() {
        let payload = make_doip_payload(0x02, 0x0005, 1024);
        let hdr = parse_doip_header(&payload);
        assert!(hdr.is_some());
        let hdr = hdr.unwrap();
        assert_eq!(hdr.protocol_version, 0x02);
        assert_eq!(hdr.inverse_version, 0xFD);
        assert_eq!(hdr.payload_type, 0x0005);
        assert_eq!(hdr.payload_length, 1024);
    }

    #[test]
    fn doip_parse_too_short() {
        assert!(parse_doip_header(&[0u8; 7]).is_none());
    }

    #[test]
    fn doip_parse_empty() {
        assert!(parse_doip_header(&[]).is_none());
    }

    // -----------------------------------------------------------------------
    // VLAN hopping detection
    // -----------------------------------------------------------------------

    #[test]
    fn vlan_hopping_no_vlan_no_alert() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn vlan_hopping_tagged_no_policy_alerts() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(10),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 200);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.id, ALERT_ID_VLAN_HOPPING);
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.source_type, SOURCE_ETHERNET);
        assert_eq!(alert.timestamp_us, 200);
    }

    #[test]
    fn vlan_hopping_allowed_vlan_no_alert() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(10);
        mon.add_allowed_vlan(20);

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(10),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 300).is_none());
    }

    #[test]
    fn vlan_hopping_disallowed_vlan_alerts() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(10);
        mon.add_allowed_vlan(20);

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(99),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 400);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_VLAN_HOPPING);
    }

    // -----------------------------------------------------------------------
    // ARP spoofing detection
    // -----------------------------------------------------------------------

    #[test]
    fn arp_learn_then_spoof_detected() {
        let mut mon = default_monitor();
        let ip = [192, 168, 1, 100];

        // First ARP reply — learn the binding.
        let arp1 = make_arp_reply(MAC_A, ip);
        let pkt1 = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp1,
        };
        assert!(mon.inspect_packet(&pkt1, 1000).is_none());

        // Second ARP reply — same IP, different MAC → spoof.
        let arp2 = make_arp_reply(MAC_B, ip);
        let pkt2 = EthPacket {
            src_mac: MAC_B,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp2,
        };
        let alert = mon.inspect_packet(&pkt2, 1001);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_ARP_SPOOF);
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    #[test]
    fn arp_same_mac_no_spoof() {
        let mut mon = default_monitor();
        let ip = [10, 0, 0, 1];
        let arp = make_arp_reply(MAC_A, ip);

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        // Learn.
        assert!(mon.inspect_packet(&pkt, 500).is_none());
        // Repeat — same binding, no alert.
        assert!(mon.inspect_packet(&pkt, 501).is_none());
    }

    #[test]
    fn arp_request_ignored() {
        let mut mon = default_monitor();
        // Build an ARP *request* (op = 1).
        let mut arp = make_arp_reply(MAC_A, [10, 0, 0, 1]);
        arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // op = request

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        assert!(mon.inspect_packet(&pkt, 600).is_none());
    }

    #[test]
    fn arp_short_payload_ignored() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &[0u8; 10], // too short for ARP
        };
        assert!(mon.inspect_packet(&pkt, 700).is_none());
    }

    // -----------------------------------------------------------------------
    // SOME/IP unknown service
    // -----------------------------------------------------------------------

    #[test]
    fn someip_unknown_service_alerts() {
        let mut mon = default_monitor();
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1000,
        })
        .unwrap();

        let payload = make_someip_payload(0x2000, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 800);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_UNKNOWN);
        assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
    }

    #[test]
    fn someip_allowed_service_no_alert() {
        let mut mon = default_monitor();
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1000,
        })
        .unwrap();

        let payload = make_someip_payload(0x1000, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 900).is_none());
    }

    #[test]
    fn someip_no_allow_list_no_unknown_alert() {
        // When the allow-list is empty, we do not flag unknown services.
        let mut mon = default_monitor();

        let payload = make_someip_payload(0x9999, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 1000).is_none());
    }

    // -----------------------------------------------------------------------
    // SOME/IP oversized payload
    // -----------------------------------------------------------------------

    #[test]
    fn someip_oversized_payload_alerts() {
        let config = EthMonitorConfig {
            someip_max_length: 1024,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        let payload = make_someip_payload(0x1000, 0x0001, 2048, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 1100);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_OVERSIZE);
    }

    #[test]
    fn someip_within_budget_no_alert() {
        let config = EthMonitorConfig {
            someip_max_length: 1024,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        let payload = make_someip_payload(0x1000, 0x0001, 512, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 1200).is_none());
    }

    #[test]
    fn someip_exact_budget_no_alert() {
        let config = EthMonitorConfig {
            someip_max_length: 1024,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        let payload = make_someip_payload(0x1000, 0x0001, 1024, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 1300).is_none());
    }

    // -----------------------------------------------------------------------
    // DoIP unauthenticated diagnostic
    // -----------------------------------------------------------------------

    #[test]
    fn doip_diagnostic_without_routing_alerts() {
        let mut mon = default_monitor();

        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 1400);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    #[test]
    fn doip_diagnostic_after_routing_no_alert() {
        let mut mon = default_monitor();

        // Step 1: Routing activation request from MAC_A.
        let routing_req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &routing_req,
        };
        assert!(mon.inspect_packet(&pkt_req, 1500).is_none());

        // Step 2: Routing activation response to MAC_A.
        let routing_resp = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_RESPONSE, 0);
        let pkt_resp = EthPacket {
            src_mac: MAC_B,
            dst_mac: MAC_A,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &routing_resp,
        };
        assert!(mon.inspect_packet(&pkt_resp, 1501).is_none());

        // Step 3: Diagnostic message from MAC_A — should be allowed now.
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        assert!(mon.inspect_packet(&pkt_diag, 1502).is_none());
    }

    #[test]
    fn doip_diagnostic_only_routing_request_still_allowed() {
        // Even without the response, the routing-activated state should
        // permit diagnostic traffic (the requester has shown intent).
        let mut mon = default_monitor();

        let routing_req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &routing_req,
        };
        assert!(mon.inspect_packet(&pkt_req, 1600).is_none());

        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        assert!(mon.inspect_packet(&pkt_diag, 1601).is_none());
    }

    #[test]
    fn doip_different_mac_still_unauthenticated() {
        let mut mon = default_monitor();

        // MAC_A activates routing.
        let routing_req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &routing_req,
        };
        assert!(mon.inspect_packet(&pkt_req, 1700).is_none());

        // MAC_C (never activated) tries to send a diagnostic.
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_C,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        let alert = mon.inspect_packet(&pkt_diag, 1701);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    #[test]
    fn doip_positive_ack_without_routing_alerts() {
        let mut mon = default_monitor();

        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_POSITIVE_ACK, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 1800);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    #[test]
    fn doip_negative_ack_without_routing_alerts() {
        let mut mon = default_monitor();

        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_NEGATIVE_ACK, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 1900);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    // -----------------------------------------------------------------------
    // Malformed packet handling
    // -----------------------------------------------------------------------

    #[test]
    fn empty_payload_no_crash() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 2000).is_none());
    }

    #[test]
    fn very_short_payload_no_crash() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0x01, 0x02, 0x03],
        };
        assert!(mon.inspect_packet(&pkt, 2100).is_none());
    }

    #[test]
    fn malformed_doip_inverse_version_ignored() {
        let mut mon = default_monitor();

        // Build a DoIP header with incorrect inverse version.
        let mut payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 10);
        payload[1] = 0x00; // wrong inverse — should be 0xFD for version 0x02

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        // Should not alert — malformed header is silently ignored.
        assert!(mon.inspect_packet(&pkt, 2200).is_none());
    }

    // -----------------------------------------------------------------------
    // Capacity / edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn allow_list_full_returns_false() {
        let mut mon = default_monitor();
        for i in 0..MAX_ALLOW_LIST {
            let entry = AllowListEntry {
                src_mac: [i as u8; 6],
                dst_mac: [0; 6],
                service_id: i as u16,
            };
            assert!(mon.add_allow_entry(entry).unwrap());
        }
        // 65th entry should fail.
        let entry = AllowListEntry {
            src_mac: [0xFF; 6],
            dst_mac: [0xFF; 6],
            service_id: 0xFFFF,
        };
        assert!(!mon.add_allow_entry(entry).unwrap());
    }

    #[test]
    fn vlan_list_full_returns_false() {
        let mut mon = default_monitor();
        for i in 0..MAX_ALLOWED_VLANS {
            assert!(mon.add_allowed_vlan(i as u16));
        }
        assert!(!mon.add_allowed_vlan(999));
    }

    #[test]
    fn alert_counter_increments() {
        let mut mon = default_monitor();

        // Two VLAN-hopping alerts should have sequential source_ids.
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(42),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let a1 = mon.inspect_packet(&pkt, 3000).unwrap();
        let a2 = mon.inspect_packet(&pkt, 3001).unwrap();
        assert_eq!(a1.source_id, 0);
        assert_eq!(a2.source_id, 1);
    }

    #[test]
    fn doip_session_state_enum() {
        // Basic enum coverage.
        assert_eq!(DoIpSessionState::Idle, DoIpSessionState::Idle);
        assert_ne!(DoIpSessionState::Idle, DoIpSessionState::RoutingActivated);
        assert_ne!(DoIpSessionState::RoutingActivated, DoIpSessionState::Active);
    }

    #[test]
    fn eth_packet_is_copy() {
        let payload = [0u8; 4];
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        let copy = pkt;
        assert_eq!(copy.src_mac, pkt.src_mac);
        assert_eq!(copy.ethertype, pkt.ethertype);
    }

    #[test]
    fn someip_header_is_copy() {
        let hdr = SomeIpHeader {
            service_id: 1,
            method_id: 2,
            length: 8,
            client_id: 3,
            session_id: 4,
            protocol_version: 1,
            interface_version: 1,
            message_type: 0,
            return_code: 0,
        };
        let copy = hdr;
        assert_eq!(copy, hdr);
    }

    #[test]
    fn doip_header_is_copy() {
        let hdr = DoIpHeader {
            protocol_version: 2,
            inverse_version: 0xFD,
            payload_type: 5,
            payload_length: 100,
        };
        let copy = hdr;
        assert_eq!(copy, hdr);
    }

    #[test]
    fn multiple_doip_sessions_tracked() {
        let mut mon = default_monitor();

        // Activate routing for multiple MACs.
        // Rate limit is MAX_DOIP_ACTIVATIONS_PER_TICK (8), so reset between batches.
        for i in 0..MAX_DOIP_SESSIONS {
            if i > 0 && i % MAX_DOIP_ACTIVATIONS_PER_TICK as usize == 0 {
                mon.doip_tick(3999 + i as u64);
            }
            let mac = [i as u8; 6];
            let routing_req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
            let pkt = EthPacket {
                src_mac: mac,
                dst_mac: MAC_B,
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: Some(DOIP_TCP_PORT),
                payload: &routing_req,
            };
            assert!(mon.inspect_packet(&pkt, 4000 + i as u64).is_none());
        }

        // All should be able to send diagnostics without alert.
        for i in 0..MAX_DOIP_SESSIONS {
            let mac = [i as u8; 6];
            let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
            let pkt = EthPacket {
                src_mac: mac,
                dst_mac: MAC_B,
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: Some(DOIP_TCP_PORT),
                payload: &diag,
            };
            assert!(
                mon.inspect_packet(&pkt, 5000 + i as u64).is_none(),
                "session {i} should be authenticated"
            );
        }
    }

    // ---- New tests ----

    #[test]
    fn someip_header_service_id_zero() {
        let payload = make_someip_payload(0x0000, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let hdr = parse_someip_header(&payload).unwrap();
        assert_eq!(hdr.service_id, 0x0000);
    }

    #[test]
    fn someip_header_max_service_id() {
        let payload = make_someip_payload(0xFFFF, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let hdr = parse_someip_header(&payload).unwrap();
        assert_eq!(hdr.service_id, 0xFFFF);
    }

    #[test]
    fn someip_header_method_id_parsing() {
        let payload = make_someip_payload(0x1000, 0xABCD, 8, 1, 1, 1, 1, 0, 0);
        let hdr = parse_someip_header(&payload).unwrap();
        assert_eq!(hdr.method_id, 0xABCD);
    }

    #[test]
    fn doip_header_routing_request_type() {
        let payload = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let hdr = parse_doip_header(&payload).unwrap();
        assert_eq!(hdr.payload_type, 0x0005);
    }

    #[test]
    fn doip_header_routing_response_type() {
        let payload = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_RESPONSE, 0);
        let hdr = parse_doip_header(&payload).unwrap();
        assert_eq!(hdr.payload_type, 0x0006);
    }

    #[test]
    fn doip_header_diagnostic_type() {
        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 50);
        let hdr = parse_doip_header(&payload).unwrap();
        assert_eq!(hdr.payload_type, 0x8001);
    }

    #[test]
    fn doip_header_negative_ack_type() {
        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_NEGATIVE_ACK, 0);
        let hdr = parse_doip_header(&payload).unwrap();
        assert_eq!(hdr.payload_type, 0x8003);
    }

    #[test]
    fn doip_header_positive_ack_type() {
        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_POSITIVE_ACK, 0);
        let hdr = parse_doip_header(&payload).unwrap();
        assert_eq!(hdr.payload_type, 0x8002);
    }

    #[test]
    fn doip_session_lifecycle_routing_then_diagnostic() {
        let mut mon = default_monitor();

        // 1. Routing activation request
        let req_payload = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &req_payload,
        };
        assert!(mon.inspect_packet(&pkt_req, 100).is_none());

        // 2. Routing activation response (positive ack)
        let resp_payload = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_RESPONSE, 0);
        let pkt_resp = EthPacket {
            src_mac: MAC_B,
            dst_mac: MAC_A,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &resp_payload,
        };
        assert!(mon.inspect_packet(&pkt_resp, 101).is_none());

        // 3. Diagnostic message from MAC_A
        let diag_payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag_payload,
        };
        assert!(mon.inspect_packet(&pkt_diag, 102).is_none());
    }

    #[test]
    fn arp_learn_two_different_ips() {
        let mut mon = default_monitor();
        let ip1 = [10, 0, 0, 1];
        let ip2 = [10, 0, 0, 2];

        // Learn first IP
        let arp1 = make_arp_reply(MAC_A, ip1);
        let pkt1 = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp1,
        };
        assert!(mon.inspect_packet(&pkt1, 100).is_none());

        // Learn second IP
        let arp2 = make_arp_reply(MAC_B, ip2);
        let pkt2 = EthPacket {
            src_mac: MAC_B,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp2,
        };
        assert!(mon.inspect_packet(&pkt2, 101).is_none());

        // Verify both are stored: re-send same bindings should still be fine
        assert!(mon.inspect_packet(&pkt1, 102).is_none());
        assert!(mon.inspect_packet(&pkt2, 103).is_none());
    }

    #[test]
    fn arp_table_full_eviction() {
        let mut mon = default_monitor();

        // Fill ARP table with MAX_ARP_ENTRIES entries, ticking between
        // batches to reset the per-tick learn rate limit.
        for i in 0..MAX_ARP_ENTRIES {
            if i > 0 && i % (MAX_ARP_LEARNS_PER_TICK as usize) == 0 {
                mon.arp_tick();
            }
            let mac = [i as u8, 0x01, 0x02, 0x03, 0x04, 0x05];
            let ip = [10, 0, 0, i as u8];
            let arp = make_arp_reply(mac, ip);
            let pkt = EthPacket {
                src_mac: mac,
                dst_mac: [0xFF; 6],
                vlan_id: None,
                ethertype: ETHERTYPE_ARP,
                dst_port: None,
                payload: &arp,
            };
            assert!(mon.inspect_packet(&pkt, i as u64).is_none());
        }

        // Add one more — should evict entry 0 without panic
        mon.arp_tick();
        let new_mac = [0xFF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let new_ip = [10, 0, 1, 0];
        let arp = make_arp_reply(new_mac, new_ip);
        let pkt = EthPacket {
            src_mac: new_mac,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn vlan_id_boundary_zero() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(0);

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(0),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn vlan_id_boundary_4095() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(4095);

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(4095),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn allow_list_exact_match_vs_partial_match() {
        let mut mon = default_monitor();
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1000,
        })
        .unwrap();

        // Exact match — no alert
        let payload = make_someip_payload(0x1000, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt_ok = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt_ok, 100).is_none());

        // Different src_mac — should alert (partial match)
        let pkt_bad = EthPacket {
            src_mac: MAC_C,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt_bad, 101);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_UNKNOWN);
    }

    #[test]
    fn eth_packet_ethertype_ipv4() {
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert_eq!(pkt.ethertype, 0x0800);
    }

    #[test]
    fn eth_packet_ethertype_ipv6() {
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x86DD,
            dst_port: None,
            payload: &[],
        };
        assert_eq!(pkt.ethertype, 0x86DD);
    }

    #[test]
    fn multiple_vlan_allowed_entries() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(10);
        mon.add_allowed_vlan(20);
        mon.add_allowed_vlan(30);

        for vid in &[10, 20, 30] {
            let pkt = EthPacket {
                src_mac: MAC_A,
                dst_mac: MAC_B,
                vlan_id: Some(*vid),
                ethertype: 0x0800,
                dst_port: None,
                payload: &[],
            };
            assert!(
                mon.inspect_packet(&pkt, 100).is_none(),
                "VLAN {vid} should be allowed"
            );
        }
    }

    #[test]
    fn empty_allow_list_all_services_pass() {
        // No allow list entries means no unknown service check
        let mut mon = default_monitor();
        assert_eq!(mon.allow_list_len, 0);

        let payload = make_someip_payload(0xABCD, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn someip_exact_max_length_boundary() {
        let config = EthMonitorConfig {
            someip_max_length: 500,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        // Exactly at boundary
        let payload = make_someip_payload(0x1000, 0x0001, 500, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn someip_length_just_over_boundary() {
        let config = EthMonitorConfig {
            someip_max_length: 500,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        // One over boundary
        let payload = make_someip_payload(0x1000, 0x0001, 501, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 100);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_OVERSIZE);
    }

    #[test]
    fn doip_routing_from_two_different_macs() {
        let mut mon = default_monitor();

        // MAC_A activates routing
        let req1 = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt1 = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &req1,
        };
        assert!(mon.inspect_packet(&pkt1, 100).is_none());

        // MAC_C also activates routing
        let req2 = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt2 = EthPacket {
            src_mac: MAC_C,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &req2,
        };
        assert!(mon.inspect_packet(&pkt2, 101).is_none());

        // Both should be able to send diagnostics
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag_a = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        assert!(mon.inspect_packet(&pkt_diag_a, 102).is_none());

        let pkt_diag_c = EthPacket {
            src_mac: MAC_C,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        assert!(mon.inspect_packet(&pkt_diag_c, 103).is_none());
    }

    #[test]
    fn arp_same_ip_same_mac_no_spoof_repeated() {
        let mut mon = default_monitor();
        let ip = [192, 168, 1, 1];
        let arp = make_arp_reply(MAC_A, ip);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        // Learn
        assert!(mon.inspect_packet(&pkt, 100).is_none());
        // Repeat same binding many times — no spoof
        for t in 101..110 {
            assert!(mon.inspect_packet(&pkt, t).is_none());
        }
    }

    #[test]
    fn arp_sender_ip_different_positions_in_table() {
        let mut mon = default_monitor();

        // Learn IP 10.0.0.1 with MAC_A
        let ip1 = [10, 0, 0, 1];
        let arp1 = make_arp_reply(MAC_A, ip1);
        let pkt1 = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp1,
        };
        assert!(mon.inspect_packet(&pkt1, 100).is_none());

        // Learn IP 10.0.0.2 with MAC_B
        let ip2 = [10, 0, 0, 2];
        let arp2 = make_arp_reply(MAC_B, ip2);
        let pkt2 = EthPacket {
            src_mac: MAC_B,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp2,
        };
        assert!(mon.inspect_packet(&pkt2, 101).is_none());

        // Now spoof IP 10.0.0.2 from MAC_A — should alert
        let arp_spoof = make_arp_reply(MAC_A, ip2);
        let pkt_spoof = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp_spoof,
        };
        let alert = mon.inspect_packet(&pkt_spoof, 102);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_ARP_SPOOF);
    }

    #[test]
    fn monitor_with_all_default_config() {
        let config = EthMonitorConfig::default();
        assert_eq!(config.allow_list_len, 0);
        assert_eq!(config.allowed_vlans_len, 0);
        assert_eq!(config.someip_max_length, DEFAULT_SOMEIP_MAX_LEN);

        let mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();
        assert_eq!(mon.allow_list_len, 0);
        assert_eq!(mon.allowed_vlans_len, 0);
        assert_eq!(mon.someip_max_length, DEFAULT_SOMEIP_MAX_LEN);
        assert_eq!(mon.alert_counter, 0);
    }

    #[test]
    fn alert_severity_vlan_hopping_is_high() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(99),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn alert_severity_arp_spoof_is_critical() {
        let mut mon = default_monitor();
        let ip = [10, 0, 0, 1];

        let arp1 = make_arp_reply(MAC_A, ip);
        let pkt1 = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp1,
        };
        mon.inspect_packet(&pkt1, 100);

        let arp2 = make_arp_reply(MAC_B, ip);
        let pkt2 = EthPacket {
            src_mac: MAC_B,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp2,
        };
        let alert = mon.inspect_packet(&pkt2, 101).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    #[test]
    fn alert_severity_someip_unknown_is_medium() {
        let mut mon = default_monitor();
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1000,
        })
        .unwrap();
        let payload = make_someip_payload(0x9999, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
    }

    #[test]
    fn alert_severity_someip_oversize_is_high() {
        let config = EthMonitorConfig {
            someip_max_length: 100,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        let payload = make_someip_payload(0x1000, 0x0001, 200, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn alert_severity_doip_unauth_is_critical() {
        let mut mon = default_monitor();
        let payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    #[test]
    fn inspect_returns_none_for_normal_traffic() {
        let mut mon = default_monitor();
        // Normal IPv4 packet with no VLAN, too short for SOME/IP or DoIP
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0x45, 0x00, 0x00, 0x28], // IPv4 header start (too short for SOME/IP)
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn vlan_tag_parsing_different_ethertypes() {
        let mut mon = default_monitor();
        // Tagged packet with ethertype 0x86DD (IPv6) — no VLAN policy → alert
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(10),
            ethertype: 0x86DD,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 100);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_VLAN_HOPPING);
    }

    #[test]
    fn doip_version_mismatch_ignored() {
        let mut mon = default_monitor();
        // Build DoIP header with wrong inverse version
        let mut payload = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 10);
        payload[1] = 0x00; // Should be 0xFD for version 0x02

        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        // Malformed → silently ignored (no alert)
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn someip_protocol_version_field_access() {
        let payload = make_someip_payload(0x1000, 0x0001, 8, 1, 1, 42, 7, 0x01, 0x02);
        let hdr = parse_someip_header(&payload).unwrap();
        assert_eq!(hdr.protocol_version, 42);
        assert_eq!(hdr.interface_version, 7);
        assert_eq!(hdr.message_type, 0x01);
        assert_eq!(hdr.return_code, 0x02);
    }

    #[test]
    fn empty_packet_zero_byte_payload_no_crash() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        // Should not crash — returns None
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn one_byte_payload_no_crash() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0xFF],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn fourteen_byte_payload_no_crash() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0u8; 14],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn fifteen_byte_payload_someip_boundary_minus_one() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[0u8; 15], // SOME/IP header is 16 bytes, so 15 fails to parse
        };
        // Too short for SOME/IP or DoIP (8 bytes), DoIP parses but version check fails
        // (all zeros: version=0, inverse=0, 0 != !0=0xFF)
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn sixteen_byte_payload_exactly_someip_header_parses() {
        let payload = make_someip_payload(0x1000, 0x0001, 8, 1, 1, 1, 1, 0, 0);
        assert_eq!(payload.len(), 16);
        let hdr = parse_someip_header(&payload);
        assert!(hdr.is_some());
    }

    #[test]
    fn packet_with_broadcast_dst_mac() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn multiple_inspect_calls_idempotent_for_non_stateful() {
        let mut mon = default_monitor();
        mon.add_allowed_vlan(10);

        // Non-stateful check (VLAN allowed) should give same result repeatedly
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(10),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
        assert!(mon.inspect_packet(&pkt, 101).is_none());
        assert!(mon.inspect_packet(&pkt, 102).is_none());
    }

    #[test]
    fn alert_counter_starts_at_zero_for_first_alert() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(99), // triggers VLAN hopping
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.source_id, 0);
    }

    #[test]
    fn doip_diagnostic_message_type_value() {
        assert_eq!(DOIP_DIAGNOSTIC_MESSAGE, 0x8001);
    }

    #[test]
    fn monitor_config_zero_max_length() {
        // someip_max_length of 0 is clamped to SOMEIP_MIN_MAX_LENGTH (8).
        let config = EthMonitorConfig {
            someip_max_length: 0,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        // SOME/IP message with length > 8 (clamped min) should be oversize
        let payload = make_someip_payload(0x1000, 0x0001, 9, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        let alert = mon.inspect_packet(&pkt, 100);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_OVERSIZE);
    }

    #[test]
    fn someip_within_budget_exact_boundary() {
        let config = EthMonitorConfig {
            someip_max_length: 256,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        // Exactly at boundary
        let payload = make_someip_payload(0x1000, 0x0001, 256, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn arp_request_opcode_1_vs_reply_opcode_2() {
        let mut mon = default_monitor();
        let ip = [10, 0, 0, 1];

        // ARP request (opcode 1) — should be ignored by spoof detection
        let mut arp_req = make_arp_reply(MAC_A, ip);
        arp_req[6..8].copy_from_slice(&1u16.to_be_bytes()); // opcode = request
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp_req,
        };
        assert!(mon.inspect_packet(&pkt_req, 100).is_none());

        // ARP reply (opcode 2) — should learn binding
        let arp_reply = make_arp_reply(MAC_A, ip);
        let pkt_reply = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp_reply,
        };
        assert!(mon.inspect_packet(&pkt_reply, 101).is_none());
    }

    #[test]
    fn eth_packet_copy_semantics() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(10),
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        let copy = pkt;
        assert_eq!(copy.src_mac, MAC_A);
        assert_eq!(copy.dst_mac, MAC_B);
        assert_eq!(copy.vlan_id, Some(10));
        assert_eq!(copy.ethertype, 0x0800);
        assert_eq!(copy.payload, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn doip_unknown_payload_type_no_alert() {
        let mut mon = default_monitor();
        // Unknown DoIP payload type (0x0099) — should be silently ignored
        let payload = make_doip_payload(0x02, 0x0099, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn doip_version_zero_with_correct_inverse() {
        let mut mon = default_monitor();
        // Version 0x00, inverse should be 0xFF
        let payload = make_doip_payload(0x00, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &payload,
        };
        // Should not alert — routing request is fine
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn alert_bus_type_is_automotive_ethernet() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(99),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 100).unwrap();
        assert_eq!(alert.source_type, SOURCE_ETHERNET);
    }

    #[test]
    fn someip_zero_length_within_zero_max() {
        let config = EthMonitorConfig {
            someip_max_length: 0,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

        // SOME/IP with length 0 should be within budget (0 <= 0)
        let payload = make_someip_payload(0x1000, 0x0001, 0, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &payload,
        };
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn arp_ethertype_skips_someip_check() {
        let mut mon = default_monitor();
        // ARP packets should skip SOME/IP checks entirely
        let payload = make_someip_payload(0x1000, 0x0001, 99999, 1, 1, 1, 1, 0, 0);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &payload,
        };
        // ARP with short payload (16 bytes) fails ARP length check (needs 28)
        // but SOME/IP check is skipped due to ethertype
        assert!(mon.inspect_packet(&pkt, 100).is_none());
    }

    #[test]
    fn doip_parse_exact_8_bytes() {
        let payload = make_doip_payload(0x01, 0x0005, 0);
        assert_eq!(payload.len(), 8);
        let hdr = parse_doip_header(&payload);
        assert!(hdr.is_some());
        let hdr = hdr.unwrap();
        assert_eq!(hdr.protocol_version, 0x01);
        assert_eq!(hdr.inverse_version, !0x01u8);
    }

    #[test]
    fn add_allow_entry_returns_true_within_capacity() {
        let mut mon = default_monitor();
        let entry = AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1000,
        };
        assert!(mon.add_allow_entry(entry).unwrap());
    }

    #[test]
    fn add_allowed_vlan_returns_true_within_capacity() {
        let mut mon = default_monitor();
        assert!(mon.add_allowed_vlan(42));
    }

    #[test]
    fn vlan_hopping_alert_has_correct_timestamp() {
        let mut mon = default_monitor();
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: Some(99),
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let alert = mon.inspect_packet(&pkt, 123_456).unwrap();
        assert_eq!(alert.timestamp_us, 123_456);
    }

    // -- L3/L4 parser tests -------------------------------------------------

    #[test]
    fn parse_ipv4_valid_tcp() {
        // Minimal IPv4 header: version=4, IHL=5, total_len=40, proto=TCP(6),
        // src=192.168.1.1, dst=10.0.0.1
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0x00;
        pkt[3] = 40; // total_len = 40
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        // TCP header at offset 20: src_port=80, dst_port=443, flags=SYN
        pkt[20] = 0;
        pkt[21] = 80; // src_port
        pkt[22] = 1;
        pkt[23] = 0xBB; // dst_port = 443
        pkt[33] = 0x02; // SYN flag

        let hdr = parse_ipv4(&pkt).unwrap();
        assert_eq!(hdr.src, IpAddr::V4([192, 168, 1, 1]));
        assert_eq!(hdr.dst, IpAddr::V4([10, 0, 0, 1]));
        assert_eq!(hdr.protocol, IpProtocol::Tcp);
        assert_eq!(hdr.payload_len, 20);

        let (ip, offset) = parse_ip(0x0800, &pkt).unwrap();
        assert_eq!(offset, 20);
        let transport = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(transport.src_port, 80);
        assert_eq!(transport.dst_port, 443);
        assert_eq!(transport.tcp_flags & 0x02, 0x02); // SYN
    }

    #[test]
    fn parse_ipv4_udp() {
        let mut pkt = [0u8; 28]; // 20 IP + 8 UDP
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 28;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 1, 2, 3]);
        pkt[16..20].copy_from_slice(&[10, 4, 5, 6]);
        // UDP: src_port=53, dst_port=1024
        pkt[20] = 0;
        pkt[21] = 53;
        pkt[22] = 4;
        pkt[23] = 0;

        let (ip, offset) = parse_ip(0x0800, &pkt).unwrap();
        assert_eq!(ip.protocol, IpProtocol::Udp);
        let transport = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(transport.src_port, 53);
        assert_eq!(transport.dst_port, 1024);
        assert_eq!(transport.tcp_flags, 0);
    }

    #[test]
    fn parse_ipv6_valid() {
        let mut pkt = [0u8; 60]; // 40 IPv6 + 20 TCP
        pkt[0] = 0x60; // version=6
        pkt[4] = 0;
        pkt[5] = 20; // payload length = 20
        pkt[6] = 6; // next_header = TCP
                    // src: ::1
        pkt[23] = 1;
        // dst: ::2
        pkt[39] = 2;
        // TCP at offset 40: src=8080, dst=80
        pkt[40] = 0x1F;
        pkt[41] = 0x90; // 8080
        pkt[42] = 0;
        pkt[43] = 80;
        pkt[53] = 0x02; // SYN

        let (ip, offset) = parse_ip(0x86DD, &pkt).unwrap();
        assert_eq!(offset, 40);
        assert!(matches!(ip.src, IpAddr::V6(_)));
        assert_eq!(ip.protocol, IpProtocol::Tcp);
        assert_eq!(ip.payload_len, 20);
        let transport = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(transport.src_port, 8080);
        assert_eq!(transport.dst_port, 80);
    }

    #[test]
    fn parse_ipv4_too_short() {
        let pkt = [0u8; 10]; // too short for IPv4
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn parse_ipv4_wrong_version() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x65; // version=6, not 4
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_too_short() {
        let pkt = [0u8; 30]; // too short for IPv6 (needs 40)
        assert!(parse_ipv6(&pkt).is_none());
    }

    #[test]
    fn parse_ip_non_ip_ethertype() {
        let pkt = [0u8; 40];
        assert!(parse_ip(0x0806, &pkt).is_none()); // ARP, not IP
    }

    #[test]
    fn parse_transport_tcp_too_short() {
        let data = [0u8; 30]; // IP + only 10 bytes of TCP (needs 20)
        assert!(parse_transport(IpProtocol::Tcp, &data, 20).is_none());
    }

    #[test]
    fn parse_transport_icmp_returns_none() {
        let data = [0u8; 40];
        assert!(parse_transport(IpProtocol::Icmp, &data, 20).is_none());
    }

    // -- IPv6 extension header tests --

    #[test]
    fn ipv6_with_hop_by_hop_extension_header() {
        // IPv6 fixed header (40) + Hop-by-Hop (8) + TCP (20) = 68 bytes
        let mut pkt = [0u8; 68];
        pkt[0] = 0x60; // version=6
        pkt[4] = 0;
        pkt[5] = 28; // payload length = 8 (ext) + 20 (TCP)
        pkt[6] = 0; // next_header = Hop-by-Hop Options (0)
        pkt[23] = 1; // src = ::1
        pkt[39] = 2; // dst = ::2
                     // Hop-by-Hop extension header at offset 40:
        pkt[40] = 6; // Next Header = TCP
        pkt[41] = 0; // Hdr Ext Len = 0 => (0+1)*8 = 8 bytes
                     // TCP at offset 48:
        pkt[48] = 0x1F;
        pkt[49] = 0x90; // src_port = 8080
        pkt[50] = 0x00;
        pkt[51] = 0x50; // dst_port = 80
        pkt[61] = 0x02; // SYN flag

        let hdr = parse_ipv6(&pkt).unwrap();
        assert_eq!(hdr.protocol, IpProtocol::Tcp);

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 48); // past Hop-by-Hop
        assert_eq!(ip.protocol, IpProtocol::Tcp);
        let t = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(t.src_port, 8080);
        assert_eq!(t.dst_port, 80);
    }

    #[test]
    fn ipv6_with_routing_extension_header() {
        // IPv6 (40) + Routing (24, Hdr Ext Len=2) + UDP (8) = 72 bytes
        let mut pkt = [0u8; 80];
        pkt[0] = 0x60; // version=6
        pkt[5] = 32; // payload_length
        pkt[6] = 43; // next_header = Routing
        pkt[23] = 1;
        pkt[39] = 2;
        // Routing extension header at offset 40:
        pkt[40] = 17; // Next Header = UDP
        pkt[41] = 2; // Hdr Ext Len = 2 => (2+1)*8 = 24 bytes
                     // UDP at offset 64:
        pkt[64] = 0x00;
        pkt[65] = 0x35; // src_port = 53
        pkt[66] = 0x1F;
        pkt[67] = 0x90; // dst_port = 8080

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 64);
        assert_eq!(ip.protocol, IpProtocol::Udp);
        let t = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(t.src_port, 53);
        assert_eq!(t.dst_port, 8080);
    }

    #[test]
    fn ipv6_with_fragment_extension_header() {
        // IPv6 (40) + Fragment (8, fixed size) + TCP (20) = 68 bytes
        let mut pkt = [0u8; 68];
        pkt[0] = 0x60;
        pkt[5] = 28; // payload_length = 8 + 20
        pkt[6] = 44; // next_header = Fragment
        pkt[23] = 1;
        pkt[39] = 2;
        // Fragment header at offset 40:
        pkt[40] = 6; // Next Header = TCP
        pkt[41] = 0; // Reserved
                     // Offset/flags at [42..44], identification at [44..48] — leave zero
                     // TCP at offset 48:
        pkt[48] = 0x00;
        pkt[49] = 0x50; // src_port = 80
        pkt[50] = 0x00;
        pkt[51] = 0x51; // dst_port = 81
        pkt[61] = 0x10; // ACK flag

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 48);
        assert_eq!(ip.protocol, IpProtocol::Tcp);
        let t = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(t.src_port, 80);
        assert_eq!(t.dst_port, 81);
    }

    #[test]
    fn ipv6_with_destination_options_extension_header() {
        // IPv6 (40) + Dest Options (16, Hdr Ext Len=1) + UDP (8) = 64 bytes
        let mut pkt = [0u8; 64];
        pkt[0] = 0x60;
        pkt[5] = 24; // payload_length = 16 + 8
        pkt[6] = 60; // next_header = Destination Options
        pkt[23] = 1;
        pkt[39] = 2;
        // Destination Options at offset 40:
        pkt[40] = 17; // Next Header = UDP
        pkt[41] = 1; // Hdr Ext Len = 1 => (1+1)*8 = 16 bytes
                     // UDP at offset 56:
        pkt[56] = 0x04;
        pkt[57] = 0x00; // src_port = 1024
        pkt[58] = 0x00;
        pkt[59] = 0x50; // dst_port = 80

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 56);
        assert_eq!(ip.protocol, IpProtocol::Udp);
        let t = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(t.src_port, 1024);
        assert_eq!(t.dst_port, 80);
    }

    #[test]
    fn ipv6_chained_extension_headers() {
        // IPv6 (40) + Hop-by-Hop (8) + Routing (8) + Fragment (8) + TCP (20) = 84
        let mut pkt = [0u8; 84];
        pkt[0] = 0x60;
        pkt[5] = 44; // payload_length = 8 + 8 + 8 + 20
        pkt[6] = 0; // next_header = Hop-by-Hop
        pkt[23] = 1;
        pkt[39] = 2;
        // Hop-by-Hop at offset 40:
        pkt[40] = 43; // Next Header = Routing
        pkt[41] = 0; // Hdr Ext Len = 0 => 8 bytes
                     // Routing at offset 48:
        pkt[48] = 44; // Next Header = Fragment
        pkt[49] = 0; // Hdr Ext Len = 0 => 8 bytes
                     // Fragment at offset 56:
        pkt[56] = 6; // Next Header = TCP
        pkt[57] = 0; // Reserved
                     // TCP at offset 64:
        pkt[64] = 0x00;
        pkt[65] = 0x16; // src_port = 22
        pkt[66] = 0x00;
        pkt[67] = 0x50; // dst_port = 80
        pkt[77] = 0x02; // SYN

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 64);
        assert_eq!(ip.protocol, IpProtocol::Tcp);
        let t = parse_transport(ip.protocol, &pkt, offset).unwrap();
        assert_eq!(t.src_port, 22);
        assert_eq!(t.dst_port, 80);
    }

    #[test]
    fn ipv6_no_extension_headers_still_works() {
        // Plain IPv6 with TCP directly (no extension headers).
        let mut pkt = [0u8; 60];
        pkt[0] = 0x60;
        pkt[5] = 20;
        pkt[6] = 6; // TCP directly
        pkt[23] = 1;
        pkt[39] = 2;
        pkt[40] = 0x00;
        pkt[41] = 0x50; // src=80
        pkt[42] = 0x1F;
        pkt[43] = 0x90; // dst=8080
        pkt[53] = 0x10;

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 40); // No extension headers
        assert_eq!(ip.protocol, IpProtocol::Tcp);
    }

    #[test]
    fn ipv6_with_auth_header_extension() {
        // RFC 4302 §2.2: AH length is `(payload_len + 2) * 4` bytes (NOT
        // the generic ext-hdr `(Hdr Ext Len + 1) * 8`). With
        // `payload_len = 4` this gives a 24-byte AH (a 12-byte ICV +
        // SPI/seq/next/payload-len/reserved). Layout: IPv6 (40) + AH
        // (24) + TCP (20) = 84.
        let mut pkt = [0u8; 84];
        pkt[0] = 0x60;
        pkt[5] = 44; // payload_length = 24 + 20
        pkt[6] = 51; // next_header = Authentication Header
        pkt[23] = 1;
        pkt[39] = 2;
        // AH at offset 40:
        pkt[40] = 6; // Next Header = TCP
        pkt[41] = 4; // Payload Len = 4 => (4+2)*4 = 24 bytes
                     // SPI / sequence / ICV bytes left as zero.
                     // TCP at offset 64:
        pkt[64] = 0x00;
        pkt[65] = 0x50; // src=80
        pkt[66] = 0x00;
        pkt[67] = 0x51; // dst=81
        pkt[77] = 0x02;

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(offset, 64);
        assert_eq!(ip.protocol, IpProtocol::Tcp);
    }

    #[test]
    fn ipv6_ah_chain_walks_to_upper_layer_protocol() {
        // Regression for the AH-length formula: walking Hop-by-Hop ->
        // AH -> UDP must land on UDP at the correct offset. AH uses the
        // RFC 4302 `(payload_len + 2) * 4` formula, distinct from the
        // generic `(Hdr Ext Len + 1) * 8` used by Hop-by-Hop / Routing /
        // Destination Options.
        //
        // Layout:
        //   IPv6           (40)  — Next Header = 0 (Hop-by-Hop)
        //   Hop-by-Hop      (8)  — Hdr Ext Len = 0 -> (0+1)*8 = 8
        //                          Next Header = 51 (AH)
        //   AH             (12)  — Payload Len = 1 -> (1+2)*4 = 12
        //                          Next Header = 17 (UDP)
        //   UDP             (8)
        // Total: 68 bytes.
        let mut pkt = [0u8; 68];
        pkt[0] = 0x60; // IPv6 version
        pkt[5] = 28; // payload_length = 8 + 12 + 8
        pkt[6] = 0; // next_header = Hop-by-Hop
        pkt[23] = 1; // src non-zero so .copy_from_slice is meaningful
        pkt[39] = 2;

        // Hop-by-Hop at offset 40:
        pkt[40] = 51; // Next Header = AH
        pkt[41] = 0; // Hdr Ext Len = 0 -> 8 bytes total

        // AH at offset 48:
        pkt[48] = 17; // Next Header = UDP
        pkt[49] = 1; // Payload Len = 1 -> (1+2)*4 = 12 bytes
                     // bytes 50..60 are SPI / sequence / ICV (zero is fine)

        // UDP at offset 60:
        pkt[60] = 0xC0;
        pkt[61] = 0x00; // src_port = 0xC000
        pkt[62] = 0x77;
        pkt[63] = 0x1A; // dst_port = 30490 (SOME/IP)
        pkt[64] = 0x00;
        pkt[65] = 0x08; // udp length = 8
                        // checksum bytes 66..68 = 0

        let (ip, offset) = parse_ip(ETHERTYPE_IPV6, &pkt).unwrap();
        assert_eq!(
            offset, 60,
            "AH chain must land transport at offset 60 with RFC 4302 sizing"
        );
        assert_eq!(ip.protocol, IpProtocol::Udp);

        // And the transport header should parse correctly from that
        // offset — proving the AH length advanced the cursor to the
        // right place rather than dumping us mid-AH.
        let tport = parse_transport(IpProtocol::Udp, &pkt, offset).unwrap();
        assert_eq!(tport.dst_port, 30490);
    }

    #[test]
    fn ipv6_extension_header_truncated_packet_falls_through() {
        // IPv6 header says Hop-by-Hop but packet is truncated.
        let mut pkt = [0u8; 42]; // 40 + only 2 bytes
        pkt[0] = 0x60;
        pkt[5] = 20;
        pkt[6] = 0; // Hop-by-Hop
                    // Extension header at offset 40, but only 2 bytes available — too short
        pkt[40] = 6; // Next Header = TCP (but can't read full ext header)
        pkt[41] = 0;

        // Should still parse the IPv6 header but stop at the extension header
        let hdr = parse_ipv6(&pkt).unwrap();
        // Falls back to the extension header type since it can't walk further
        assert_eq!(hdr.protocol, IpProtocol::Other(0)); // Hop-by-Hop = 0
    }

    // -----------------------------------------------------------------------
    // SOME/IP-SD parsing and detection tests
    // -----------------------------------------------------------------------

    /// Build a SOME/IP header for SD (`service_id=0xFFFF`, `method_id=0x8100`)
    /// followed by an SD payload with the given entries.
    fn make_sd_packet(entries: &[SomeIpSdEntry]) -> [u8; 256] {
        let mut buf = [0u8; 256];
        // SOME/IP header: service_id=0xFFFF, method_id=0x8100
        let someip = make_someip_payload(
            SOMEIP_SD_SERVICE_ID,
            SOMEIP_SD_METHOD_ID,
            (SOMEIP_SD_HEADER_SIZE + entries.len() * SOMEIP_SD_ENTRY_SIZE + 4) as u32 + 8,
            0x0000,
            0x0001,
            1,
            1,
            0x02, // notification
            0x00,
        );
        buf[..SOMEIP_HEADER_SIZE].copy_from_slice(&someip);

        // SD header: flags=0xC0 (reboot + unicast), reserved=0, length_of_entries
        let sd_offset = SOMEIP_HEADER_SIZE;
        buf[sd_offset] = 0xC0; // flags
                               // reserved bytes [1..3] = 0
        let entries_len = (entries.len() * SOMEIP_SD_ENTRY_SIZE) as u32;
        buf[sd_offset + 4..sd_offset + 8].copy_from_slice(&entries_len.to_be_bytes());

        // Write entries
        let entries_start = sd_offset + SOMEIP_SD_HEADER_SIZE;
        for (i, entry) in entries.iter().enumerate() {
            let off = entries_start + i * SOMEIP_SD_ENTRY_SIZE;
            buf[off] = entry.entry_type as u8;
            // bytes 1-3: index/options info (zero for tests)
            buf[off + 4..off + 6].copy_from_slice(&entry.service_id.to_be_bytes());
            buf[off + 6..off + 8].copy_from_slice(&entry.instance_id.to_be_bytes());
            buf[off + 8] = entry.major_version;
            // TTL is 3 bytes (big-endian, stored in bytes 9-11)
            let ttl_bytes = entry.ttl.to_be_bytes();
            buf[off + 9] = ttl_bytes[1];
            buf[off + 10] = ttl_bytes[2];
            buf[off + 11] = ttl_bytes[3];
            buf[off + 12..off + 16].copy_from_slice(&entry.minor_version.to_be_bytes());
        }

        // Options array length (0 = no options)
        let options_off = entries_start + entries.len() * SOMEIP_SD_ENTRY_SIZE;
        buf[options_off..options_off + 4].copy_from_slice(&0u32.to_be_bytes());

        buf
    }

    #[test]
    fn sd_parse_valid_offer_entry() {
        let entry = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x1234,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 300,
            minor_version: 0x0000_0002,
        };
        let pkt_data = make_sd_packet(&[entry]);
        let sd_payload = &pkt_data[SOMEIP_HEADER_SIZE..];
        let (flags, count, entries) = parse_sd_entries(sd_payload);
        assert_eq!(flags, 0xC0);
        assert_eq!(count, 1);
        let parsed = entries[0].unwrap();
        assert_eq!(parsed.entry_type, SdEntryType::OfferService);
        assert_eq!(parsed.service_id, 0x1234);
        assert_eq!(parsed.instance_id, 0x0001);
        assert_eq!(parsed.major_version, 1);
        assert_eq!(parsed.ttl, 300);
        assert_eq!(parsed.minor_version, 2);
    }

    #[test]
    fn sd_parse_valid_find_entry() {
        let entry = SomeIpSdEntry {
            entry_type: SdEntryType::FindService,
            service_id: 0xABCD,
            instance_id: 0xFFFF,
            major_version: 0xFF,
            ttl: 3,
            minor_version: 0xFFFF_FFFF,
        };
        let pkt_data = make_sd_packet(&[entry]);
        let sd_payload = &pkt_data[SOMEIP_HEADER_SIZE..];
        let (_, count, entries) = parse_sd_entries(sd_payload);
        assert_eq!(count, 1);
        let parsed = entries[0].unwrap();
        assert_eq!(parsed.entry_type, SdEntryType::FindService);
        assert_eq!(parsed.service_id, 0xABCD);
    }

    #[test]
    fn sd_parse_subscribe_and_stop_entries() {
        let entries_in = [
            SomeIpSdEntry {
                entry_type: SdEntryType::SubscribeEventgroup,
                service_id: 0x0010,
                instance_id: 0x0001,
                major_version: 1,
                ttl: 60,
                minor_version: 0,
            },
            SomeIpSdEntry {
                entry_type: SdEntryType::StopSubscribe,
                service_id: 0x0010,
                instance_id: 0x0001,
                major_version: 1,
                ttl: 0,
                minor_version: 0,
            },
        ];
        let pkt_data = make_sd_packet(&entries_in);
        let sd_payload = &pkt_data[SOMEIP_HEADER_SIZE..];
        let (_, count, parsed) = parse_sd_entries(sd_payload);
        assert_eq!(count, 2);
        assert_eq!(
            parsed[0].unwrap().entry_type,
            SdEntryType::SubscribeEventgroup
        );
        assert_eq!(parsed[1].unwrap().entry_type, SdEntryType::StopSubscribe);
    }

    #[test]
    fn sd_parse_multiple_entries() {
        let entries_in: [SomeIpSdEntry; 3] = [
            SomeIpSdEntry {
                entry_type: SdEntryType::OfferService,
                service_id: 0x0001,
                instance_id: 0x0001,
                major_version: 1,
                ttl: 100,
                minor_version: 0,
            },
            SomeIpSdEntry {
                entry_type: SdEntryType::OfferService,
                service_id: 0x0002,
                instance_id: 0x0001,
                major_version: 1,
                ttl: 200,
                minor_version: 0,
            },
            SomeIpSdEntry {
                entry_type: SdEntryType::FindService,
                service_id: 0x0003,
                instance_id: 0xFFFF,
                major_version: 0xFF,
                ttl: 5,
                minor_version: 0xFFFF_FFFF,
            },
        ];
        let pkt_data = make_sd_packet(&entries_in);
        let sd_payload = &pkt_data[SOMEIP_HEADER_SIZE..];
        let (_, count, _) = parse_sd_entries(sd_payload);
        assert_eq!(count, 3);
    }

    #[test]
    fn sd_parse_short_payload_returns_empty() {
        let short = [0u8; 4]; // Less than SD header
        let (_, count, _) = parse_sd_entries(&short);
        assert_eq!(count, 0);
    }

    #[test]
    fn sd_parse_zero_entries() {
        // SD header with entries_len = 0
        let mut sd_payload = [0u8; 16];
        sd_payload[0] = 0xC0; // flags
                              // entries_len = 0 (bytes 4-7 = 0)
                              // options_len (bytes 8-11 = 0)
        let (flags, count, _) = parse_sd_entries(&sd_payload);
        assert_eq!(flags, 0xC0);
        assert_eq!(count, 0);
    }

    #[test]
    fn sd_offer_from_allowed_source_no_alert() {
        let mut mon = default_monitor();
        // Add MAC_A to allow-list with a dummy service
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1234,
        })
        .unwrap();

        let offer = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x5678,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 300,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[offer]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        let alert = mon.inspect_packet(&pkt, 1000);
        assert!(
            alert.is_none(),
            "allowed source should not trigger SD alert"
        );
        assert_eq!(mon.sd_active_service_count(), 1);
    }

    #[test]
    fn sd_offer_from_unknown_source_triggers_alert() {
        let mut mon = default_monitor();
        // Add MAC_A to allow-list, but use MAC_C as source
        mon.add_allow_entry(AllowListEntry {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            service_id: 0x1234,
        })
        .unwrap();

        let offer = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x5678,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 300,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[offer]);
        let pkt = EthPacket {
            src_mac: MAC_C, // Not in allow-list
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        let alert = mon.inspect_packet(&pkt, 1000);
        assert!(
            alert.is_some(),
            "unknown source should trigger SD unauth alert"
        );
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_SD_UNAUTH);
    }

    #[test]
    fn sd_flood_detection() {
        let mut mon = default_monitor();
        let offer = SomeIpSdEntry {
            entry_type: SdEntryType::FindService,
            service_id: 0x0001,
            instance_id: 0xFFFF,
            major_version: 0xFF,
            ttl: 3,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[offer]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };

        // Send SD_FLOOD_THRESHOLD - 1 messages — no alert
        for i in 0..(SD_FLOOD_THRESHOLD - 1) {
            let alert = mon.inspect_packet(&pkt, i as u64);
            assert!(alert.is_none(), "no alert until threshold reached (i={i})");
        }

        // The next message should trigger flood alert (count == SD_FLOOD_THRESHOLD)
        let alert = mon.inspect_packet(&pkt, SD_FLOOD_THRESHOLD as u64);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().id, ALERT_ID_SOMEIP_SD_FLOOD);
    }

    #[test]
    fn sd_ttl_expiry_removes_service() {
        let mut mon = default_monitor();
        let offer = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x1234,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 2, // TTL = 2 ticks
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[offer]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        mon.inspect_packet(&pkt, 1000);
        assert_eq!(mon.sd_active_service_count(), 1);

        // Tick down TTL: 2 → 1
        mon.sd_tick();
        assert_eq!(mon.sd_active_service_count(), 1);

        // Tick down TTL: 1 → 0
        mon.sd_tick();
        assert_eq!(mon.sd_active_service_count(), 1);

        // TTL is now 0, next tick removes it
        mon.sd_tick();
        assert_eq!(mon.sd_active_service_count(), 0);
    }

    #[test]
    fn sd_service_table_full_gracefully_handled() {
        let mut mon = default_monitor();
        // Fill the service table completely
        for i in 0..MAX_SD_SERVICES as u16 {
            let offer = SomeIpSdEntry {
                entry_type: SdEntryType::OfferService,
                service_id: i,
                instance_id: 0x0001,
                major_version: 1,
                ttl: 300,
                minor_version: 0,
            };
            let pkt_data = make_sd_packet(&[offer]);
            let pkt = EthPacket {
                src_mac: MAC_A,
                dst_mac: MAC_B,
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: Some(SOMEIP_UDP_PORT),
                payload: &pkt_data,
            };
            mon.inspect_packet(&pkt, 1000);
        }
        assert_eq!(mon.sd_active_service_count(), MAX_SD_SERVICES);

        // One more should be silently dropped
        let extra = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0xFFFF,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 300,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[extra]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        mon.inspect_packet(&pkt, 2000);
        // Still at max capacity — extra was silently dropped
        assert_eq!(mon.sd_active_service_count(), MAX_SD_SERVICES);
    }

    #[test]
    fn sd_flags_byte_parsed() {
        let mut sd_payload = [0u8; 24];
        sd_payload[0] = 0x40; // unicast flag only
                              // entries_len = 0
        let (flags, count, _) = parse_sd_entries(&sd_payload);
        assert_eq!(flags, 0x40);
        assert_eq!(count, 0);
    }

    #[test]
    fn sd_entry_type_discriminant_values() {
        assert_eq!(SdEntryType::FindService as u8, 0x00);
        assert_eq!(SdEntryType::OfferService as u8, 0x01);
        assert_eq!(SdEntryType::SubscribeEventgroup as u8, 0x06);
        assert_eq!(SdEntryType::StopSubscribe as u8, 0x07);
    }

    #[test]
    fn sd_unknown_entry_type_skipped() {
        // Build raw SD payload with an unknown entry type (0xFF)
        let mut sd_payload = [0u8; 32];
        sd_payload[0] = 0xC0;
        // entries_len = 16 (one entry)
        sd_payload[4..8].copy_from_slice(&16u32.to_be_bytes());
        // Entry at offset 8 with type 0xFF (unknown)
        sd_payload[8] = 0xFF;
        sd_payload[12..14].copy_from_slice(&0x1234u16.to_be_bytes());

        let (_, count, _) = parse_sd_entries(&sd_payload);
        assert_eq!(count, 0, "unknown entry type should be skipped");
    }

    #[test]
    fn sd_ttl_zero_is_stop_offer() {
        let mut mon = default_monitor();

        // First: offer a service
        let offer = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x1234,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 300,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[offer]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        mon.inspect_packet(&pkt, 1000);
        assert_eq!(mon.sd_active_service_count(), 1);

        // Stop offer: TTL=0
        let stop = SomeIpSdEntry {
            entry_type: SdEntryType::OfferService,
            service_id: 0x1234,
            instance_id: 0x0001,
            major_version: 1,
            ttl: 0, // Stop offer
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[stop]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };
        mon.inspect_packet(&pkt, 2000);
        assert_eq!(
            mon.sd_active_service_count(),
            0,
            "TTL=0 should remove service"
        );
    }

    #[test]
    fn sd_flood_counter_resets_on_tick() {
        let mut mon = default_monitor();

        // Accumulate some SD messages
        let find = SomeIpSdEntry {
            entry_type: SdEntryType::FindService,
            service_id: 0x0001,
            instance_id: 0xFFFF,
            major_version: 0xFF,
            ttl: 3,
            minor_version: 0,
        };
        let pkt_data = make_sd_packet(&[find]);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &pkt_data,
        };

        for _ in 0..50 {
            mon.inspect_packet(&pkt, 1000);
        }

        // Tick resets the counter
        mon.sd_tick();

        // Should be able to send more without flood alert
        for _ in 0..50 {
            let alert = mon.inspect_packet(&pkt, 2000);
            assert!(
                alert.is_none(),
                "flood counter should have reset after tick"
            );
        }
    }

    #[test]
    fn sd_round_trip_parse_constructed_payload() {
        let entries_in = [
            SomeIpSdEntry {
                entry_type: SdEntryType::OfferService,
                service_id: 0x4567,
                instance_id: 0x0002,
                major_version: 3,
                ttl: 1000,
                minor_version: 42,
            },
            SomeIpSdEntry {
                entry_type: SdEntryType::FindService,
                service_id: 0x89AB,
                instance_id: 0xFFFF,
                major_version: 0xFF,
                ttl: 5,
                minor_version: 0,
            },
        ];
        let pkt_data = make_sd_packet(&entries_in);
        let sd_payload = &pkt_data[SOMEIP_HEADER_SIZE..];
        let (_, count, parsed) = parse_sd_entries(sd_payload);
        assert_eq!(count, 2);

        let p0 = parsed[0].unwrap();
        assert_eq!(p0.service_id, 0x4567);
        assert_eq!(p0.instance_id, 0x0002);
        assert_eq!(p0.major_version, 3);
        assert_eq!(p0.ttl, 1000);
        assert_eq!(p0.minor_version, 42);

        let p1 = parsed[1].unwrap();
        assert_eq!(p1.service_id, 0x89AB);
        assert_eq!(p1.entry_type, SdEntryType::FindService);
    }

    #[test]
    fn sd_flood_property_test() {
        // SD_FLOOD_THRESHOLD is 100
        let mut monitor =
            EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

        let mut pkt = EthPacket {
            src_mac: [1, 2, 3, 4, 5, 6],
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: super::ETHERTYPE_IPV4,
            dst_port: Some(SOMEIP_UDP_PORT),
            payload: &[0u8; 16],
        };

        // Handcrafted SOME/IP-SD header (16 bytes)
        let mut payload = [0u8; 24];
        payload[0..2].copy_from_slice(&super::SOMEIP_SD_SERVICE_ID.to_be_bytes());
        payload[2..4].copy_from_slice(&super::SOMEIP_SD_METHOD_ID.to_be_bytes());
        // set random length and stuff so it passes parse_someip_header

        pkt.payload = &payload;

        // Send 100 messages - should be OK (None) or SOME(alert) depending on parsing
        // We just care that after 100, the flood condition triggers.
        // If it triggers UnknownService first, it's fine, but SOMEIP_SD is matched before Unknown.

        for _ in 0..100 {
            let _ = monitor.inspect_packet(&pkt, 1000);
        }

        // The 101st should definitely trigger a flood alert
        let alert = monitor
            .inspect_packet(&pkt, 2000)
            .expect("Expected flood alert");
        assert_eq!(alert.id, super::ALERT_ID_SOMEIP_SD_FLOOD);
    }

    // -------------------------------------------------------------------
    // V6: ARP rate-limit alert tests
    // -------------------------------------------------------------------

    #[test]
    fn arp_rate_limit_emits_alert_once() {
        let mut mon = default_monitor();

        // Learn MAX_ARP_LEARNS_PER_TICK entries (should all succeed silently).
        for i in 0..MAX_ARP_LEARNS_PER_TICK {
            let mac = [i as u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
            let ip = [192, 168, 1, i as u8];
            let arp = make_arp_reply(mac, ip);
            let pkt = EthPacket {
                src_mac: mac,
                dst_mac: [0xFF; 6],
                vlan_id: None,
                ethertype: ETHERTYPE_ARP,
                dst_port: None,
                payload: &arp,
            };
            assert!(mon.inspect_packet(&pkt, 100 + u64::from(i)).is_none());
        }

        // The next ARP learn should trigger the rate-limit alert.
        let mac = [0xFE, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let ip = [192, 168, 1, 200];
        let arp = make_arp_reply(mac, ip);
        let pkt = EthPacket {
            src_mac: mac,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        let alert = mon.inspect_packet(&pkt, 200);
        assert!(alert.is_some(), "Expected ARP rate-limit alert");
        assert_eq!(alert.unwrap().id, ALERT_ID_ARP_RATE_LIMIT);

        // Subsequent rate-limited ARP should NOT emit another alert.
        let mac2 = [0xFD, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let ip2 = [192, 168, 1, 201];
        let arp2 = make_arp_reply(mac2, ip2);
        let pkt2 = EthPacket {
            src_mac: mac2,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp2,
        };
        assert!(mon.inspect_packet(&pkt2, 201).is_none());
    }

    #[test]
    fn arp_rate_limit_resets_on_tick() {
        let mut mon = default_monitor();

        // Exhaust rate limit.
        for i in 0..MAX_ARP_LEARNS_PER_TICK {
            let mac = [i as u8, 0x11, 0x22, 0x33, 0x44, 0x55];
            let ip = [10, 0, 0, i as u8];
            let arp = make_arp_reply(mac, ip);
            let pkt = EthPacket {
                src_mac: mac,
                dst_mac: [0xFF; 6],
                vlan_id: None,
                ethertype: ETHERTYPE_ARP,
                dst_port: None,
                payload: &arp,
            };
            mon.inspect_packet(&pkt, 100 + u64::from(i));
        }

        // Trigger rate limit alert.
        let mac = [0xAB, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = [10, 0, 0, 200];
        let arp = make_arp_reply(mac, ip);
        let pkt = EthPacket {
            src_mac: mac,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        assert!(mon.inspect_packet(&pkt, 200).is_some());

        // Tick resets the rate limit.
        mon.arp_tick();

        // Should be able to learn again without alert.
        let mac3 = [0xCD, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip3 = [10, 0, 1, 1];
        let arp3 = make_arp_reply(mac3, ip3);
        let pkt3 = EthPacket {
            src_mac: mac3,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp3,
        };
        assert!(mon.inspect_packet(&pkt3, 300).is_none());
    }

    #[test]
    fn reject_all_zero_siphash_keys() {
        let zero_keys = [(0u64, 0u64); 4];
        let result = EthMonitor::new(&EthMonitorConfig::default(), zero_keys);
        assert!(matches!(result, Err(VsError::InvalidConfig)));
    }

    // =======================================================================
    // Regression tests — security fixes
    // =======================================================================

    /// Regression: the allow-list lookup probe used to stop at 16 steps
    /// while the insertion probe walked the full 128-slot capacity, so an
    /// entry inserted past step 16 became a "ghost-deny" — present in the
    /// hash table but unreachable from queries, silently denying
    /// authorized traffic.
    ///
    /// This test fills the bucket starting at hash slot 0 with 60+ keys
    /// that all hash to the same slot, then asserts that the *last*
    /// inserted entry (the one furthest down the probe chain) is still
    /// found by `is_service_allowed`.
    ///
    /// To force a deep probe chain, we craft keys that share the first
    /// 14 bytes of input to `allow_list_hash` (`src_mac` + `dst_mac`)
    /// and vary only `service_id`. Since the hash mixes service_id last,
    /// many of these collide modulo 128.
    #[test]
    fn regression_allow_list_lookup_probe_matches_insert_probe() {
        let mut mon = default_monitor();
        // Pick (src_mac, dst_mac) and a set of service_ids that all
        // collide to the same bucket. Rather than try to compute
        // collisions by hand, fill the allow-list to capacity (64) with
        // entries that all share the same src_mac/dst_mac — they will
        // hash according to service_id and form long probe chains.
        let src = MAC_A;
        let dst = MAC_B;
        for i in 0..MAX_ALLOW_LIST {
            let entry = AllowListEntry {
                src_mac: src,
                dst_mac: dst,
                service_id: i as u16,
            };
            assert!(mon.add_allow_entry(entry).unwrap());
        }
        // Every inserted (src, dst, service_id) must be discoverable by
        // is_service_allowed. With a 64/128 occupancy and the original
        // 16-step lookup cap, late inserts on long probe chains would
        // be invisible; with the fix every entry resolves.
        for i in 0..MAX_ALLOW_LIST {
            let pkt = EthPacket {
                src_mac: src,
                dst_mac: dst,
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: Some(SOMEIP_UDP_PORT),
                payload: &make_someip_payload(i as u16, 0x0001, 8, 1, 1, 1, 1, 0, 0),
            };
            assert!(
                mon.inspect_packet(&pkt, 1000 + i as u64).is_none(),
                "service_id {i} inserted into allow-list but not found by lookup"
            );
        }
    }

    /// Regression: the ARP parser only validated `htype` and `ptype` and
    /// blindly indexed sender/target MAC/IP fields at fixed offsets,
    /// assuming `hlen=6`/`plen=4`. A crafted ARP frame with mismatched
    /// hlen/plen would still parse, letting an attacker spoof bindings
    /// (or evade detection) by aliasing different bytes into the sender
    /// fields. After the fix, hlen=6/plen=4 is required.
    #[test]
    fn regression_arp_rejects_nonstandard_hlen() {
        let mut mon = default_monitor();
        let mut arp = make_arp_reply(MAC_A, [10, 0, 0, 1]);
        // hlen != 6 — the rest of the frame is still otherwise valid.
        arp[4] = 8;
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        // Must be silently rejected — no learning, no alert.
        assert!(mon.inspect_packet(&pkt, 100).is_none());

        // Confirm the binding was *not* learned: a subsequent legitimate
        // ARP for the same IP with a different MAC must not be flagged
        // as a spoof (because nothing was learned from the malformed
        // frame).
        let legit = make_arp_reply(MAC_B, [10, 0, 0, 1]);
        let pkt2 = EthPacket {
            src_mac: MAC_B,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &legit,
        };
        assert!(mon.inspect_packet(&pkt2, 101).is_none());
    }

    #[test]
    fn regression_arp_rejects_nonstandard_plen() {
        let mut mon = default_monitor();
        let mut arp = make_arp_reply(MAC_A, [10, 0, 0, 2]);
        arp[5] = 16; // plen=16 (IPv6 address length) — still IPv4 EtherType in ptype.
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: ETHERTYPE_ARP,
            dst_port: None,
            payload: &arp,
        };
        assert!(mon.inspect_packet(&pkt, 200).is_none());
    }

    /// Regression: a `DoIP` routing-activation request sent to a
    /// broadcast or multicast `dst_mac` used to create a session whose
    /// `expected_responder` was the broadcast address. Any host on the
    /// segment could then forge a routing-activation response (its
    /// `src_mac` would never match the broadcast expected_responder via
    /// constant_time_eq, but the original logic accepted *any* responder
    /// for the matching session). After the fix, requests with
    /// broadcast/multicast destinations are dropped without creating a
    /// session.
    #[test]
    fn regression_doip_rejects_broadcast_dst_mac_at_request() {
        let mut mon = default_monitor();
        let bcast: [u8; 6] = [0xFF; 6];
        let req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: bcast,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &req,
        };
        // Request itself is silently dropped, no alert.
        assert!(mon.inspect_packet(&pkt_req, 100).is_none());

        // A subsequent diagnostic from the same src_mac must NOT be
        // authorised — no session was created.
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        let alert = mon.inspect_packet(&pkt_diag, 101);
        assert!(alert.is_some(), "broadcast dst_mac should not authorise");
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    #[test]
    fn regression_doip_rejects_multicast_dst_mac_at_request() {
        let mut mon = default_monitor();
        // Multicast: LSB of first byte is set, but not full broadcast.
        let mcast: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: mcast,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &req,
        };
        assert!(mon.inspect_packet(&pkt_req, 200).is_none());

        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        let alert = mon.inspect_packet(&pkt_diag, 201);
        assert!(alert.is_some(), "multicast dst_mac should not authorise");
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    /// Regression: `DoIP` session promotion used to be keyed on
    /// `pkt.dst_mac` alone. An attacker who activated a session against
    /// server port X (e.g. a non-DoIP service that happens to share the
    /// victim MAC) could then send diagnostics against server port
    /// `DOIP_TCP_PORT` (13400) on the same MAC and have them
    /// authorised. After the fix, the session is bound to the TCP tuple
    /// (`src_mac`, `dst_port`); a diagnostic on a different `dst_port`
    /// must NOT be authorised.
    #[test]
    fn regression_doip_diagnostic_on_different_dst_port_not_authorised() {
        let mut mon = default_monitor();

        // Activate against port X (not the canonical DOIP port).
        const OTHER_PORT: u16 = 13401;
        let req = make_doip_payload(0x02, DOIP_ROUTING_ACTIVATION_REQUEST, 0);
        let pkt_req = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(OTHER_PORT),
            payload: &req,
        };
        assert!(mon.inspect_packet(&pkt_req, 100).is_none());

        // Same src_mac sends a diagnostic, but on the canonical DoIP
        // port — different TCP tuple, must NOT be authorised.
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let pkt_diag = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(DOIP_TCP_PORT),
            payload: &diag,
        };
        let alert = mon.inspect_packet(&pkt_diag, 101);
        assert!(
            alert.is_some(),
            "diagnostic on a different dst_port must not inherit session state"
        );
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);

        // And on the original port, it remains authorised.
        let pkt_diag_same = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(OTHER_PORT),
            payload: &diag,
        };
        assert!(
            mon.inspect_packet(&pkt_diag_same, 102).is_none(),
            "diagnostic on the original dst_port must remain authorised"
        );
    }

    /// Wrap an 8-byte+ DoIP message in a minimal IPv4 + TCP frame so
    /// `inspect_packet` must derive the transport port via its internal
    /// L3/L4 parser (the `dst_port: None` path). `dst_port` selects the
    /// TCP destination port written into the frame.
    fn make_doip_over_ipv4_tcp(doip: &[u8], dst_port: u16) -> [u8; 64] {
        let mut pkt = [0u8; 64];
        // IPv4 header (20 bytes, IHL=5).
        pkt[0] = 0x45;
        let total_len = (40 + doip.len()) as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = 6; // protocol = TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP header (20 bytes, data offset = 5 words).
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 5 << 4; // data offset nibble
                          // DoIP payload at offset 40.
        pkt[40..40 + doip.len()].copy_from_slice(doip);
        pkt
    }

    /// Regression (H2): `inspect_packet` must wire the L3/L4 parsers into
    /// protocol dispatch. A real IPv4 + TCP frame carrying a DoIP
    /// diagnostic — presented with `dst_port: None` so the monitor must
    /// strip L3/L4 itself — must be routed to `check_doip` on the
    /// derived port and flagged `DOIP_UNAUTH` when no session exists.
    #[test]
    fn regression_inspect_packet_derives_doip_port_from_l3_l4() {
        let mut mon = default_monitor();
        let diag = make_doip_payload(0x02, DOIP_DIAGNOSTIC_MESSAGE, 0);
        let frame = make_doip_over_ipv4_tcp(&diag, DOIP_TCP_PORT);
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: ETHERTYPE_IPV4,
            dst_port: None, // monitor must derive port 13400 via parse_ip/parse_transport
            payload: &frame[..40 + diag.len()],
        };
        let alert = mon.inspect_packet(&pkt, 100);
        assert!(
            alert.is_some(),
            "DoIP diagnostic with no prior activation must be flagged"
        );
        assert_eq!(alert.unwrap().id, ALERT_ID_DOIP_UNAUTH);
    }

    /// Regression (H1): a plain large IPv4/TCP packet whose IP-header
    /// bytes 4..8 encode a value larger than `someip_max_length` must
    /// NOT raise a spurious `SOMEIP_OVERSIZE` alert. Before the fix,
    /// `check_someip` parsed the raw IP payload as a SOME/IP header.
    #[test]
    fn regression_raw_ipv4_not_misparsed_as_someip() {
        let config = EthMonitorConfig {
            someip_max_length: 64,
            ..EthMonitorConfig::default()
        };
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();
        // IPv4 + TCP frame to a non-SOME/IP port. IP-header bytes 2..4
        // (total length) are large; bytes 4..6 (identification) are set
        // so a SOME/IP misparse of bytes 4..8 would look oversize.
        let mut frame = make_doip_over_ipv4_tcp(&[0u8; 16], 8080);
        frame[4] = 0xFF;
        frame[5] = 0xFF; // identification — would be SOME/IP length high bytes
        let pkt = EthPacket {
            src_mac: MAC_A,
            dst_mac: MAC_B,
            vlan_id: None,
            ethertype: ETHERTYPE_IPV4,
            dst_port: None,
            payload: &frame,
        };
        assert!(
            mon.inspect_packet(&pkt, 100).is_none(),
            "raw IPv4 packet on a non-SOME/IP port must not raise a SOME/IP alert"
        );
    }
}
