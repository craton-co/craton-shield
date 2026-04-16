// SPDX-License-Identifier: Apache-2.0
//! Ethernet monitoring example.
//!
//! Demonstrates how to set up the Ethernet monitor for SOME/IP and
//! ARP anomaly detection, and inspect packets for security alerts.
//!
//! ```
//! cargo run --example eth_monitoring
//! ```

use vs_eth_monitor::{
    AllowListEntry, EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS,
};

fn main() {
    println!("Craton Shield — Ethernet Monitoring Example");
    println!("============================================\n");

    // 1. Create an Ethernet monitor with default configuration
    let config = EthMonitorConfig::default();
    let mut monitor = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // 2. Add a SOME/IP allowlist entry for service 0x1234
    let entry = AllowListEntry {
        src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        service_id: 0x1234,
    };
    let added = monitor.add_allow_entry(entry).expect("hash table not full");
    println!("Added SOME/IP allowlist entry: service=0x1234 (ok={added})");

    // 3. Add allowed VLAN IDs
    monitor.add_allowed_vlan(100);
    monitor.add_allowed_vlan(200);
    println!("Added allowed VLANs: 100, 200\n");

    // 4. Simulate an Ethernet packet with a SOME/IP payload
    // Build a minimal SOME/IP-over-UDP-over-IPv4 packet
    #[rustfmt::skip]
    let someip_payload: [u8; 46] = [
        // IPv4 header (20 bytes, minimal)
        0x45, 0x00, 0x00, 0x2E, // version/IHL, DSCP, total length = 46
        0x00, 0x01, 0x00, 0x00, // identification, flags/fragment
        0x40, 0x11, 0x00, 0x00, // TTL=64, protocol=UDP(17), checksum
        0xC0, 0xA8, 0x01, 0x0A, // src IP: 192.168.1.10
        0xC0, 0xA8, 0x01, 0x14, // dst IP: 192.168.1.20
        // UDP header (8 bytes)
        0x76, 0x54, 0x76, 0x54, // src/dst port: 30292 (SOME/IP default)
        0x00, 0x1A, 0x00, 0x00, // length, checksum
        // SOME/IP header (16 bytes)
        0x12, 0x34, 0x00, 0x01, // service ID: 0x1234, method ID: 0x0001
        0x00, 0x00, 0x00, 0x08, // length
        0x00, 0x01, 0x00, 0x00, // client ID, session ID
        0x01, 0x01, 0x00, 0x00, // protocol ver, interface ver, msg type, return code
        0x00, 0x00,             // padding
    ];

    let pkt = EthPacket {
        src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        vlan_id: None,
        ethertype: 0x0800, // IPv4
        dst_port: Some(30292),
        payload: &someip_payload,
    };

    println!("Inspecting Ethernet packet (SOME/IP service 0x1234)...");
    if let Some(alert) = monitor.inspect_packet(&pkt, 1_000) {
        println!(
            "  ALERT: severity={:?}, source_id=0x{:04X}",
            alert.severity, alert.source_id
        );
    } else {
        println!("  No alert — packet inspection passed.");
    }

    // 5. Simulate an ARP-like packet (ethertype 0x0806) to show ARP monitoring
    let arp_payload: [u8; 28] = [
        // ARP payload (28 bytes)
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, // hardware addr len
        0x04, // protocol addr len
        0x00, 0x01, // opcode: request
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // sender MAC
        0xC0, 0xA8, 0x01, 0x0A, // sender IP: 192.168.1.10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (unknown)
        0xC0, 0xA8, 0x01, 0x01, // target IP: 192.168.1.1
    ];

    let arp_pkt = EthPacket {
        src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        vlan_id: None,
        ethertype: 0x0806, // ARP
        dst_port: None,
        payload: &arp_payload,
    };

    println!("\nInspecting ARP request (192.168.1.10 -> 192.168.1.1)...");
    if let Some(alert) = monitor.inspect_packet(&arp_pkt, 2_000) {
        println!(
            "  ALERT: severity={:?}, source_id=0x{:04X}",
            alert.severity, alert.source_id
        );
    } else {
        println!("  No alert — ARP binding learned.");
    }

    // 6. Check capacity
    let (used, max) = monitor.capacity();
    println!("\nMonitor capacity: {used}/{max} allowlist entries used.");
    println!("Active SD services: {}", monitor.sd_active_service_count());

    println!("\nDone.");
}
