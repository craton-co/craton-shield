// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_eth_monitor::{
    EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS,
    parse_someip_header, parse_sd_entries, parse_doip_header,
    parse_ip, parse_ipv4, parse_ipv6, parse_transport,
};

fuzz_target!(|data: &[u8]| {
    // Need at least 14 bytes for a minimal Ethernet-like header:
    // 6 src_mac + 6 dst_mac + 2 ethertype
    if data.len() < 14 {
        return;
    }

    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];
    src_mac.copy_from_slice(&data[0..6]);
    dst_mac.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let payload = &data[14..];

    // Determine VLAN ID from first byte of payload if available.
    let vlan_id = if payload.len() >= 2 {
        Some(u16::from_be_bytes([payload[0] & 0x0F, payload[1]]))
    } else {
        None
    };

    // Determine dst_port from payload bytes if available.
    let dst_port = if payload.len() >= 4 {
        Some(u16::from_be_bytes([payload[2], payload[3]]))
    } else {
        None
    };

    let pkt = EthPacket {
        src_mac,
        dst_mac,
        vlan_id,
        ethertype,
        dst_port,
        payload,
    };

    // --- Exercise EthMonitor::inspect_packet with default config ---
    let config = EthMonitorConfig::default();

    if let Ok(mut monitor) = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS) {
        let _ = monitor.inspect_packet(&pkt, 1_000_000);
        // Call again to exercise rate / state tracking paths
        let _ = monitor.inspect_packet(&pkt, 1_000_001);
    }

    // --- Exercise SOME/IP parsing ---
    // Length-field invariant: the `length` field inside the header (which
    // covers everything after the first 8 bytes of the SOME/IP header) must
    // not exceed the actual available payload bytes.
    if let Some(someip) = parse_someip_header(payload) {
        // SOME/IP `length` covers [message_id(4) + request_id(4) + ...] but
        // by convention must fit within the slice that was handed to us.
        // Specifically, the remaining payload after the full 16-byte header
        // is `payload.len() - 16`; `length - 8` is the body byte count.
        let body_len = (someip.length as usize).saturating_sub(8);
        assert!(
            body_len <= payload.len().saturating_sub(16),
            "SOME/IP length field must not exceed available payload bytes"
        );
    }

    // --- Exercise SOME/IP-SD entry parsing ---
    if payload.len() >= 4 {
        let _ = parse_sd_entries(&payload[4..]);
    }

    // --- Exercise DoIP parsing ---
    // Length-field invariant: the declared payload_length must not exceed
    // the number of bytes that follow the fixed 8-byte DoIP header.
    if let Some(doip) = parse_doip_header(payload) {
        let available = payload.len().saturating_sub(8);
        assert!(
            (doip.payload_length as usize) <= available,
            "DoIP payload_length must not exceed available payload bytes"
        );
    }

    // --- Exercise IP parsing (IPv4 / IPv6 / arbitrary ethertype) ---
    // Length-field invariant: ip_hdr.payload_len (transport-layer byte count)
    // must not exceed the bytes that remain after the IP header.
    if let Some((ip_hdr, offset)) = parse_ip(ethertype, payload) {
        let remaining_after_header = payload.len().saturating_sub(offset);
        assert!(
            (ip_hdr.payload_len as usize) <= remaining_after_header,
            "IP payload_len must not exceed bytes remaining after IP header"
        );
        let _ = parse_transport(ip_hdr.protocol, payload, offset);
    }

    // Explicitly try IPv4 (0x0800)
    let _ = parse_ipv4(payload);

    // Explicitly try IPv6 (0x86DD)
    let _ = parse_ipv6(payload);

    // --- Exercise ARP-like packets (ethertype 0x0806) ---
    let arp_pkt = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype: 0x0806,
        dst_port: None,
        payload,
    };
    if let Ok(mut monitor) = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS) {
        let _ = monitor.inspect_packet(&arp_pkt, 2_000_000);
    }
});
