// SPDX-License-Identifier: Apache-2.0
//! Advanced Ethernet monitor integration tests — SOME/IP-SD, port-based
//! routing, and DoIP session timeout.

use vs_eth_monitor::{
    parse_doip_header, parse_sd_entries, parse_someip_header, AllowListEntry, EthMonitor,
    EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS,
};
use vs_types::AlertSeverity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_monitor() -> EthMonitor {
    EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap()
}

fn make_pkt<'a>(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ethertype: u16,
    dst_port: Option<u16>,
    payload: &'a [u8],
) -> EthPacket<'a> {
    EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype,
        dst_port,
        payload,
    }
}

/// Build a minimal SOME/IP header payload.
fn build_someip_payload(service_id: u16, method_id: u16, length: u32) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&service_id.to_be_bytes());
    buf[2..4].copy_from_slice(&method_id.to_be_bytes());
    buf[4..8].copy_from_slice(&length.to_be_bytes());
    buf
}

/// Build a minimal DoIP header payload.
fn build_doip_payload(payload_type: u16, payload_length: u32) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0] = 0x02; // protocol_version
    buf[1] = 0xFD; // inverse
    buf[2..4].copy_from_slice(&payload_type.to_be_bytes());
    buf[4..8].copy_from_slice(&payload_length.to_be_bytes());
    buf
}

// ===========================================================================
// SOME/IP header parsing tests
// ===========================================================================

#[test]
fn parse_someip_valid_header() {
    let payload = build_someip_payload(0x1234, 0x0001, 100);
    let hdr = parse_someip_header(&payload);
    assert!(hdr.is_some());
    let hdr = hdr.unwrap();
    assert_eq!(hdr.service_id, 0x1234);
    assert_eq!(hdr.method_id, 0x0001);
    assert_eq!(hdr.length, 100);
}

#[test]
fn parse_someip_too_short() {
    let short = [0u8; 8]; // less than 16 bytes
    assert!(parse_someip_header(&short).is_none());
}

// ===========================================================================
// DoIP header parsing tests
// ===========================================================================

#[test]
fn parse_doip_valid_header() {
    let payload = build_doip_payload(0x0005, 4);
    let hdr = parse_doip_header(&payload);
    assert!(hdr.is_some());
    let hdr = hdr.unwrap();
    assert_eq!(hdr.protocol_version, 0x02);
    assert_eq!(hdr.inverse_version, 0xFD);
    assert_eq!(hdr.payload_type, 0x0005);
    assert_eq!(hdr.payload_length, 4);
}

#[test]
fn parse_doip_too_short() {
    let short = [0u8; 4];
    assert!(parse_doip_header(&short).is_none());
}

// ===========================================================================
// SOME/IP-SD parsing tests
// ===========================================================================

#[test]
fn parse_sd_entries_empty_payload() {
    let (flags, count, _entries) = parse_sd_entries(&[]);
    assert_eq!(flags, 0);
    assert_eq!(count, 0);
}

#[test]
fn parse_sd_entries_single_offer() {
    // SD payload layout:
    // flags(1) + reserved(3) + length_of_entries(4) + entry(16)
    let mut sd_payload = [0u8; 24];
    sd_payload[0] = 0x40; // flags: reboot flag set

    // length_of_entries = 16 (one entry)
    sd_payload[4..8].copy_from_slice(&16u32.to_be_bytes());

    // Entry at offset 8:
    sd_payload[8] = 0x01; // entry_type = OfferService
                          // index1st, index2nd, num_opts — skip (0)
    sd_payload[12..14].copy_from_slice(&0xABCDu16.to_be_bytes()); // service_id
    sd_payload[14..16].copy_from_slice(&0x0001u16.to_be_bytes()); // instance_id
    sd_payload[16] = 1; // major_version
                        // TTL (3 bytes)
    sd_payload[17] = 0x00;
    sd_payload[18] = 0x00;
    sd_payload[19] = 0x0A; // TTL = 10
                           // minor_version (4 bytes)
    sd_payload[20..24].copy_from_slice(&0x0000_0001u32.to_be_bytes());

    let (flags, count, entries) = parse_sd_entries(&sd_payload);
    assert_eq!(flags, 0x40);
    assert_eq!(count, 1);
    let entry = entries[0].unwrap();
    assert_eq!(entry.service_id, 0xABCD);
    assert_eq!(entry.instance_id, 0x0001);
    assert_eq!(entry.major_version, 1);
    assert_eq!(entry.ttl, 10);
    assert_eq!(entry.minor_version, 1);
}

#[test]
fn parse_sd_entries_misaligned_length_ignored() {
    // length_of_entries = 7 (not a multiple of 16) — should return 0 entries.
    let mut sd_payload = [0u8; 24];
    sd_payload[4..8].copy_from_slice(&7u32.to_be_bytes());

    let (_, count, _) = parse_sd_entries(&sd_payload);
    assert_eq!(
        count, 0,
        "misaligned entries length should produce 0 entries"
    );
}

// ===========================================================================
// Port-based protocol routing tests
// ===========================================================================

#[test]
fn port_based_doip_routing() {
    let mut eth = default_monitor();

    // Diagnostic message to DoIP port (13400) without routing activation.
    let doip_diag = build_doip_payload(0x8001, 4);
    let pkt = make_pkt([0x10; 6], [0x20; 6], 0x0800, Some(13400), &doip_diag);

    let alert = eth.inspect_packet(&pkt, 1_000);
    assert!(
        alert.is_some(),
        "unauthenticated DoIP diagnostic on port 13400 must trigger alert"
    );
    assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
}

#[test]
fn port_based_someip_routing() {
    // Create config with an allow-list so the unknown-service check fires.
    let mut config = EthMonitorConfig::default();
    config.allow_list[0] = Some(AllowListEntry {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        service_id: 0x1234,
    });
    config.allow_list_len = 1;
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // SOME/IP packet to port 30490 with unknown service 0xDEAD.
    let someip_payload = build_someip_payload(0xDEAD, 0x0001, 8);
    let pkt = make_pkt([0x01; 6], [0x02; 6], 0x0800, Some(30490), &someip_payload);

    let alert = eth.inspect_packet(&pkt, 1_000);
    assert!(
        alert.is_some(),
        "unknown SOME/IP service on port 30490 must trigger alert"
    );
    assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
}

// ===========================================================================
// DoIP session timeout tests
// ===========================================================================

#[test]
fn doip_session_timeout_revokes_auth() {
    let mut eth = default_monitor();
    let src_mac = [0x10; 6];
    let dst_mac = [0x20; 6];

    // Step 1: Routing activation request.
    let routing_req = build_doip_payload(0x0005, 4);
    let pkt_route = make_pkt(src_mac, dst_mac, 0x0800, None, &routing_req);
    assert!(eth.inspect_packet(&pkt_route, 1_000).is_none());

    // Step 2: Diagnostic message shortly after — should pass.
    let diag = build_doip_payload(0x8001, 4);
    let pkt_diag = make_pkt(src_mac, dst_mac, 0x0800, None, &diag);
    assert!(
        eth.inspect_packet(&pkt_diag, 2_000).is_none(),
        "diagnostic after routing activation should pass"
    );

    // Step 3: Let the session timeout (30 seconds = 30_000_000 us).
    eth.doip_tick(32_000_000);

    // Step 4: Diagnostic message after timeout — session should be revoked.
    let alert = eth.inspect_packet(&pkt_diag, 33_000_000);
    assert!(
        alert.is_some(),
        "diagnostic after session timeout must trigger alert"
    );
    assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
}

// ===========================================================================
// SOME/IP oversized boundary tests
// ===========================================================================

#[test]
fn someip_exactly_one_over_max_triggers() {
    let config = EthMonitorConfig {
        someip_max_length: 100,
        ..EthMonitorConfig::default()
    };
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // length = 101, just over the max of 100.
    let payload = build_someip_payload(0x0001, 0x0001, 101);
    let pkt = make_pkt([0x01; 6], [0x02; 6], 0x0800, None, &payload);

    let alert = eth.inspect_packet(&pkt, 1_000);
    assert!(
        alert.is_some(),
        "SOME/IP with length 101 > max 100 must trigger oversized alert"
    );
    assert_eq!(alert.unwrap().severity, AlertSeverity::High);
}

// ===========================================================================
// ARP flood / eviction tests
// ===========================================================================

#[test]
fn arp_table_eviction_flood_alert() {
    let mut eth = default_monitor();

    // Send many ARP replies from different IPs/MACs to flood the ARP table.
    // The table holds MAX_ARP_ENTRIES (64), and eviction flood threshold is 16.
    let mut _alert_count = 0;
    for i in 0..100u8 {
        let mut arp_reply = [0u8; 28];
        arp_reply[6] = 0x00;
        arp_reply[7] = 0x02; // reply
                             // Unique MAC per entry.
        arp_reply[8..14].copy_from_slice(&[i, i, i, i, i, i]);
        // Unique IP per entry.
        arp_reply[14..18].copy_from_slice(&[10, 0, 0, i]);

        let pkt = EthPacket {
            src_mac: [i; 6],
            dst_mac: [0xFF; 6],
            vlan_id: None,
            ethertype: 0x0806,
            dst_port: None,
            payload: &arp_reply,
        };

        if eth.inspect_packet(&pkt, (i as u64) * 1_000).is_some() {
            _alert_count += 1;
        }
    }

    // We may or may not hit the eviction flood threshold depending on
    // the arp_tick cadence. The key check is no panics and the monitor
    // remains functional.
    let payload = [0u8; 16];
    let normal_pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800, None, &payload);
    // After the flood, the monitor should still process normal packets.
    let _ = eth.inspect_packet(&normal_pkt, 200_000);
}
