// SPDX-License-Identifier: Apache-2.0
//! Attack detection scenario integration tests.
//!
//! Creates CAN and Ethernet monitors (directly or via the IDS engine) and
//! simulates various attack patterns, verifying that each produces the
//! expected alert.

use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_eth_monitor::{
    AllowListEntry, EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS,
};
use vs_ids_engine::IdsEngine;
use vs_types::AlertSeverity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_can_frame(id: u32, dlc: u8, data: &[u8]) -> CanFrame {
    let mut frame = CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data: [0u8; 64],
    };
    let copy_len = data.len().min(64);
    frame.data[..copy_len].copy_from_slice(&data[..copy_len]);
    frame
}

/// Build a rule matching a single exact standard CAN ID.
fn exact_id_rule(id: u32, min_interval_us: u64, max_dlc: u8) -> CanRule {
    CanRule {
        id: 0,
        id_mask: 0x7FF,
        id_filter: id,
        min_interval_us,
        max_dlc,
        is_extended: false,
        severity: AlertSeverity::High,
    }
}

/// Build an IDS engine with a CAN rule for ID 0x100 and a default EthMonitor.
fn make_ids_engine() -> IdsEngine {
    let mut can = CanMonitor::default();
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("CAN rule addition should succeed");
    let eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    IdsEngine::new(can, eth, 100_000)
}

// ===========================================================================
// CAN attack scenarios
// ===========================================================================

#[test]
fn can_bus_flooding_detected() {
    let mut can = CanMonitor::default();
    // Minimum interval for ID 0x100 = 10 ms (10_000 us)
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("CAN rule addition should succeed");

    let frame = make_can_frame(0x100, 8, &[0x01; 8]);

    // First frame seeds the timestamp -- no alert.
    assert!(can.process_frame(&frame, 1_000_000).is_none());

    // Second frame only 1_000 us later -- flood detected.
    let alert = can.process_frame(&frame, 1_001_000);
    assert!(alert.is_some(), "flood must be detected");
    let alert = alert.expect("flood alert should be present");
    assert_eq!(alert.severity, AlertSeverity::High);
    assert_eq!(alert.source_id, 0x100);
}

#[test]
fn can_bus_flooding_many_frames() {
    let mut engine = make_ids_engine();

    let frame = make_can_frame(0x100, 8, &[0x01; 8]);

    // Send 100 frames at 100 us intervals (way below the 10_000 us minimum).
    let mut alert_count = 0u32;
    for i in 0..100u64 {
        if engine.submit_can_frame(&frame, i * 100).is_some() {
            alert_count += 1;
        }
    }
    // All but the first should trigger (first has no previous timestamp).
    assert!(
        alert_count >= 90,
        "expected at least 90 flood alerts, got {alert_count}"
    );
}

#[test]
fn can_dlc_anomaly_detected() {
    let mut can = CanMonitor::default();
    // Max DLC for ID 0x200 = 4 bytes
    can.add_rule(exact_id_rule(0x200, 0, 4))
        .expect("CAN rule addition should succeed");

    // Frame with DLC 6 -- exceeds max_dlc of 4.
    let frame = make_can_frame(0x200, 6, &[0x01; 6]);
    let alert = can.process_frame(&frame, 1_000_000);
    assert!(alert.is_some(), "DLC anomaly must be detected");
    assert_eq!(
        alert.expect("DLC anomaly alert should be present").severity,
        AlertSeverity::High
    );
}

#[test]
fn can_high_entropy_fuzzing_detected() {
    let mut can = CanMonitor::default();
    // Use a very low entropy threshold so the check triggers reliably.
    can.add_rule(exact_id_rule(0x300, 0, 8))
        .expect("CAN rule addition should succeed");
    let _ = can.set_entropy_threshold(1.0);

    // Each byte is unique -- high entropy.
    let frame = make_can_frame(0x300, 8, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    let alert = can.process_frame(&frame, 1_000_000);
    assert!(alert.is_some(), "high-entropy fuzzing must be detected");
}

#[test]
fn can_low_entropy_passes() {
    let mut can = CanMonitor::default();
    can.add_rule(exact_id_rule(0x300, 0, 8))
        .expect("CAN rule addition should succeed");
    let _ = can.set_entropy_threshold(1.0);

    // All identical bytes -- entropy is 0.
    let frame = make_can_frame(0x300, 8, &[0xAA; 8]);
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "constant payload should not trigger fuzzing alert"
    );
}

// ===========================================================================
// Ethernet attack scenarios
// ===========================================================================

#[test]
fn eth_vlan_hopping_detected() {
    // Default config has no allowed VLANs -- any VLAN-tagged frame is
    // suspicious.
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    let payload = [0u8; 16];
    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(999), // unexpected VLAN
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };

    let alert = eth.inspect_packet(&pkt, 1_000);
    assert!(alert.is_some(), "VLAN hopping must be detected");
    assert_eq!(
        alert
            .expect("VLAN hopping alert should be present")
            .severity,
        AlertSeverity::High
    );
}

#[test]
fn eth_allowed_vlan_passes() {
    let mut config = EthMonitorConfig::default();
    config.allowed_vlans[0] = Some(100);
    config.allowed_vlans_len = 1;
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    let payload = [0u8; 16];
    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(100), // allowed
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };

    assert!(
        eth.inspect_packet(&pkt, 1_000).is_none(),
        "allowed VLAN should not trigger"
    );
}

#[test]
fn eth_arp_spoofing_detected() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    // Build a minimal ARP reply payload (28 bytes for IPv4-over-Ethernet).
    // Layout: hw_type(2) | proto_type(2) | hw_len(1) | proto_len(1) |
    //         operation(2) | sender_mac(6) | sender_ip(4) | target_mac(6) |
    //         target_ip(4)
    let mut arp_reply_1 = [0u8; 28];
    // hw_type = 1 (Ethernet)
    arp_reply_1[0] = 0x00;
    arp_reply_1[1] = 0x01;
    // proto_type = 0x0800 (IPv4)
    arp_reply_1[2] = 0x08;
    arp_reply_1[3] = 0x00;
    // operation = reply (0x0002)
    arp_reply_1[6] = 0x00;
    arp_reply_1[7] = 0x02;
    // sender MAC = AA:AA:AA:AA:AA:AA
    arp_reply_1[8..14].copy_from_slice(&[0xAA; 6]);
    // sender IP = 192.168.1.100
    arp_reply_1[14..18].copy_from_slice(&[192, 168, 1, 100]);

    let pkt1 = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xFF; 6],
        vlan_id: None,
        ethertype: 0x0806, // ARP
        dst_port: None,
        payload: &arp_reply_1,
    };

    // First ARP reply -- learns the binding, no alert.
    assert!(eth.inspect_packet(&pkt1, 1_000).is_none());

    // Second ARP reply for same IP but different MAC -- spoof!
    let mut arp_reply_2 = arp_reply_1;
    arp_reply_2[8..14].copy_from_slice(&[0xBB; 6]); // different MAC

    let pkt2 = EthPacket {
        src_mac: [0xBB; 6],
        dst_mac: [0xFF; 6],
        vlan_id: None,
        ethertype: 0x0806,
        dst_port: None,
        payload: &arp_reply_2,
    };

    let alert = eth.inspect_packet(&pkt2, 2_000);
    assert!(alert.is_some(), "ARP spoofing must be detected");
    assert_eq!(
        alert
            .expect("ARP spoofing alert should be present")
            .severity,
        AlertSeverity::Critical
    );
}

#[test]
fn eth_unknown_someip_service_detected() {
    // Create a config with an allow-list containing one specific service.
    let mut config = EthMonitorConfig::default();
    config.allow_list[0] = Some(AllowListEntry {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        service_id: 0x1234,
    });
    config.allow_list_len = 1;
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // Build a SOME/IP payload with an unknown service_id (0xDEAD).
    let mut someip_payload = [0u8; 16];
    // service_id = 0xDEAD
    someip_payload[0] = 0xDE;
    someip_payload[1] = 0xAD;
    // method_id
    someip_payload[2] = 0x00;
    someip_payload[3] = 0x01;
    // length (8 bytes remaining -- fits within default max)
    someip_payload[4..8].copy_from_slice(&8u32.to_be_bytes());

    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &someip_payload,
    };

    let alert = eth.inspect_packet(&pkt, 3_000);
    assert!(alert.is_some(), "unknown SOME/IP service must be detected");
    assert_eq!(
        alert
            .expect("unknown SOME/IP service alert should be present")
            .severity,
        AlertSeverity::Medium
    );
}

#[test]
fn eth_oversized_someip_detected() {
    let config = EthMonitorConfig {
        // Set a small max to trigger oversized detection easily.
        someip_max_length: 100,
        ..EthMonitorConfig::default()
    };
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // Build a SOME/IP payload with length field exceeding the max.
    let mut someip_payload = [0u8; 16];
    someip_payload[0] = 0x00;
    someip_payload[1] = 0x01; // service_id
    someip_payload[2] = 0x00;
    someip_payload[3] = 0x01; // method_id
                              // length = 200 -- exceeds max of 100
    someip_payload[4..8].copy_from_slice(&200u32.to_be_bytes());

    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &someip_payload,
    };

    let alert = eth.inspect_packet(&pkt, 4_000);
    assert!(alert.is_some(), "oversized SOME/IP must be detected");
    assert_eq!(
        alert
            .expect("oversized SOME/IP alert should be present")
            .severity,
        AlertSeverity::High
    );
}

#[test]
fn eth_unauthenticated_doip_detected() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    // Build a DoIP diagnostic message header (8 bytes) without prior
    // routing activation.
    let mut doip_payload = [0u8; 16];
    // protocol_version = 0x02
    doip_payload[0] = 0x02;
    // inverse_version = !0x02 = 0xFD
    doip_payload[1] = 0xFD;
    // payload_type = diagnostic message (0x8001)
    doip_payload[2] = 0x80;
    doip_payload[3] = 0x01;
    // payload_length = 4
    doip_payload[4..8].copy_from_slice(&4u32.to_be_bytes());

    let pkt = EthPacket {
        src_mac: [0x10; 6],
        dst_mac: [0x20; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &doip_payload,
    };

    let alert = eth.inspect_packet(&pkt, 5_000);
    assert!(
        alert.is_some(),
        "unauthenticated DoIP diagnostic must be detected"
    );
    assert_eq!(
        alert
            .expect("unauthenticated DoIP alert should be present")
            .severity,
        AlertSeverity::Critical
    );
}

#[test]
fn eth_doip_after_routing_activation_passes() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    let src_mac = [0x10; 6];
    let dst_mac = [0x20; 6];

    // Step 1: Send routing activation request from the client.
    let mut doip_routing_req = [0u8; 16];
    doip_routing_req[0] = 0x02; // protocol_version
    doip_routing_req[1] = 0xFD; // inverse
                                // payload_type = routing activation request (0x0005)
    doip_routing_req[2] = 0x00;
    doip_routing_req[3] = 0x05;
    doip_routing_req[4..8].copy_from_slice(&4u32.to_be_bytes());

    let pkt_req = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &doip_routing_req,
    };
    // This should set state to RoutingActivated, no alert.
    assert!(eth.inspect_packet(&pkt_req, 1_000).is_none());

    // Step 2: Now send a diagnostic message from the same client.
    let mut doip_diag = [0u8; 16];
    doip_diag[0] = 0x02;
    doip_diag[1] = 0xFD;
    // payload_type = diagnostic message (0x8001)
    doip_diag[2] = 0x80;
    doip_diag[3] = 0x01;
    doip_diag[4..8].copy_from_slice(&4u32.to_be_bytes());

    let pkt_diag = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &doip_diag,
    };

    // Should pass because the session is routing-activated.
    assert!(
        eth.inspect_packet(&pkt_diag, 2_000).is_none(),
        "authenticated DoIP diagnostic should not trigger alert"
    );
}

// ===========================================================================
// IDS engine correlation test
// ===========================================================================

#[test]
fn ids_engine_correlates_can_and_eth_attacks() {
    let mut engine = make_ids_engine();

    // Trigger a CAN flood alert first.
    let frame = make_can_frame(0x100, 8, &[0x01; 8]);
    engine.submit_can_frame(&frame, 1_000); // seed
    let can_alert = engine.submit_can_frame(&frame, 1_001); // flood
    assert!(can_alert.is_some(), "CAN flood alert expected");

    // Now trigger an ETH alert (VLAN hopping) within the correlation window.
    let payload = [0u8; 16];
    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(999),
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };

    let eth_alert = engine.submit_eth_packet(&pkt, 1_050);
    assert!(eth_alert.is_some(), "ETH VLAN alert expected");

    // The ETH alert should be escalated due to CAN+ETH correlation.
    let eth_alert = eth_alert.expect("correlated ETH alert should be present");
    assert_eq!(
        eth_alert.severity,
        AlertSeverity::Critical,
        "ETH alert should be escalated to Critical when correlated with CAN alert"
    );
}

// ===========================================================================
// Additional CAN attack scenarios
// ===========================================================================

#[test]
fn can_flood_with_varying_intervals() {
    let mut can = CanMonitor::default();
    // min_interval = 10_000 us for ID 0x100
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("CAN rule addition should succeed");

    let frame = make_can_frame(0x100, 8, &[0x01; 8]);

    // First frame -- seeds timestamp.
    assert!(can.process_frame(&frame, 1_000_000).is_none());

    // Frame at 1_015_000 (15_000 us later -- above threshold, no flood).
    assert!(
        can.process_frame(&frame, 1_015_000).is_none(),
        "interval above threshold should not trigger flood"
    );

    // Frame at 1_020_000 (5_000 us later -- below threshold, flood).
    let alert = can.process_frame(&frame, 1_020_000);
    assert!(
        alert.is_some(),
        "interval below threshold must trigger flood"
    );

    // Frame at 1_035_000 (15_000 us later -- above threshold again, no flood).
    assert!(
        can.process_frame(&frame, 1_035_000).is_none(),
        "interval above threshold should not trigger flood"
    );

    // Frame at 1_037_000 (2_000 us later -- below threshold, flood again).
    let alert = can.process_frame(&frame, 1_037_000);
    assert!(alert.is_some(), "second flood occurrence must be detected");
}

#[test]
fn can_all_zero_payload_no_fuzzing() {
    let mut can = CanMonitor::default();
    can.add_rule(exact_id_rule(0x300, 0, 8))
        .expect("CAN rule addition should succeed");
    let _ = can.set_entropy_threshold(1.0);

    // All-zero payload -- entropy is 0, should not trigger fuzzing alert.
    let frame = make_can_frame(0x300, 8, &[0x00; 8]);
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "all-zero payload should not trigger fuzzing alert"
    );
}

#[test]
fn can_alternating_pattern_low_entropy() {
    let mut can = CanMonitor::default();
    can.add_rule(exact_id_rule(0x300, 0, 8))
        .expect("CAN rule addition should succeed");
    let _ = can.set_entropy_threshold(2.0); // threshold above the entropy of 2 distinct values

    // Alternating 0x55/0xAA -- only 2 distinct values, entropy = 1.0 bit.
    let frame = make_can_frame(0x300, 8, &[0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA]);
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "alternating pattern should not trigger with high threshold"
    );
}

#[test]
fn can_bus_off_at_error_count_255() {
    let mut can = CanMonitor::default();

    // Report 254 errors -- just below threshold (BUS_OFF_ERROR_THRESHOLD = 255).
    for t in 0..254u64 {
        assert!(
            can.report_error(t * 1_000).is_none(),
            "error #{t} should not trigger bus-off"
        );
    }

    // The 255th error hits the threshold and triggers bus-off.
    let alert = can.report_error(255_000);
    assert!(
        alert.is_some(),
        "error count 255 must trigger bus-off alert"
    );
    assert_eq!(
        alert.expect("bus-off alert should be present").severity,
        AlertSeverity::Critical
    );
}

#[test]
fn can_bus_off_below_threshold_no_alert() {
    let mut can = CanMonitor::default();

    // Report exactly 254 errors (one below threshold).
    for t in 0..254u64 {
        assert!(
            can.report_error(t * 1_000).is_none(),
            "error #{t} should not trigger bus-off"
        );
    }
    // No alert has been generated -- still below threshold.
}

#[test]
fn can_multiple_ids_do_not_cross_trigger_flood() {
    let mut can = CanMonitor::default();
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("CAN rule addition for ID 0x100 should succeed");
    can.add_rule(exact_id_rule(0x200, 10_000, 8))
        .expect("CAN rule addition for ID 0x200 should succeed");

    let frame_a = make_can_frame(0x100, 8, &[0x01; 8]);
    let frame_b = make_can_frame(0x200, 8, &[0x02; 8]);

    // Send frame_a, then frame_b quickly -- different IDs, no flood.
    assert!(can.process_frame(&frame_a, 1_000_000).is_none());
    assert!(
        can.process_frame(&frame_b, 1_000_100).is_none(),
        "different CAN IDs should not cross-trigger flood detection"
    );

    // Now send frame_a again after sufficient time -- no flood for ID 0x100.
    assert!(
        can.process_frame(&frame_a, 1_015_000).is_none(),
        "ID 0x100 interval is sufficient, should not flood"
    );
}

// ===========================================================================
// Additional Ethernet attack scenarios
// ===========================================================================

#[test]
fn eth_doip_routing_then_diagnostic_passes() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    let src_mac = [0x30; 6];
    let dst_mac = [0x40; 6];

    // Step 1: Send routing activation request.
    let mut doip_routing = [0u8; 16];
    doip_routing[0] = 0x02; // protocol_version
    doip_routing[1] = 0xFD; // inverse
    doip_routing[2] = 0x00; // routing activation request (0x0005)
    doip_routing[3] = 0x05;
    doip_routing[4..8].copy_from_slice(&4u32.to_be_bytes());

    let pkt_route = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &doip_routing,
    };
    assert!(eth.inspect_packet(&pkt_route, 1_000).is_none());

    // Step 2: Send diagnostic message -- should pass.
    let mut doip_diag = [0u8; 16];
    doip_diag[0] = 0x02;
    doip_diag[1] = 0xFD;
    doip_diag[2] = 0x80;
    doip_diag[3] = 0x01;
    doip_diag[4..8].copy_from_slice(&4u32.to_be_bytes());

    let pkt_diag = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &doip_diag,
    };
    assert!(
        eth.inspect_packet(&pkt_diag, 2_000).is_none(),
        "DoIP diagnostic after routing activation should pass"
    );
}

#[test]
fn eth_multiple_vlan_ids_only_disallowed_trigger() {
    let mut config = EthMonitorConfig::default();
    config.allowed_vlans[0] = Some(100);
    config.allowed_vlans[1] = Some(200);
    config.allowed_vlans_len = 2;
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    let payload = [0u8; 16];

    // VLAN 100 -- allowed, no alert.
    let pkt_ok1 = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(100),
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };
    assert!(eth.inspect_packet(&pkt_ok1, 1_000).is_none());

    // VLAN 200 -- allowed, no alert.
    let pkt_ok2 = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(200),
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };
    assert!(eth.inspect_packet(&pkt_ok2, 2_000).is_none());

    // VLAN 300 -- NOT allowed, alert.
    let pkt_bad = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(300),
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };
    let alert = eth.inspect_packet(&pkt_bad, 3_000);
    assert!(alert.is_some(), "disallowed VLAN 300 must trigger alert");
    assert_eq!(
        alert
            .expect("disallowed VLAN alert should be present")
            .severity,
        AlertSeverity::High
    );
}

#[test]
fn eth_arp_with_multiple_ips_learned() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    // ARP reply from MAC AA for IP 192.168.1.100
    let mut arp1 = [0u8; 28];
    arp1[6] = 0x00;
    arp1[7] = 0x02; // reply
    arp1[8..14].copy_from_slice(&[0xAA; 6]);
    arp1[14..18].copy_from_slice(&[192, 168, 1, 100]);

    let pkt1 = EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xFF; 6],
        vlan_id: None,
        ethertype: 0x0806,
        dst_port: None,
        payload: &arp1,
    };
    assert!(eth.inspect_packet(&pkt1, 1_000).is_none());

    // ARP reply from MAC BB for a DIFFERENT IP 192.168.1.200 -- no spoof.
    let mut arp2 = [0u8; 28];
    arp2[6] = 0x00;
    arp2[7] = 0x02;
    arp2[8..14].copy_from_slice(&[0xBB; 6]);
    arp2[14..18].copy_from_slice(&[192, 168, 1, 200]);

    let pkt2 = EthPacket {
        src_mac: [0xBB; 6],
        dst_mac: [0xFF; 6],
        vlan_id: None,
        ethertype: 0x0806,
        dst_port: None,
        payload: &arp2,
    };
    assert!(
        eth.inspect_packet(&pkt2, 2_000).is_none(),
        "different IPs from different MACs should not trigger ARP spoof"
    );
}

#[test]
fn eth_someip_exactly_max_length_no_alert() {
    let config = EthMonitorConfig {
        someip_max_length: 100,
        ..EthMonitorConfig::default()
    };
    let mut eth = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

    // Build a SOME/IP payload with length field == max (100) -- boundary.
    let mut someip_payload = [0u8; 16];
    someip_payload[0] = 0x00;
    someip_payload[1] = 0x01; // service_id
    someip_payload[2] = 0x00;
    someip_payload[3] = 0x01; // method_id
                              // length = exactly 100 (at boundary, should NOT trigger oversized).
    someip_payload[4..8].copy_from_slice(&100u32.to_be_bytes());

    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &someip_payload,
    };

    let alert = eth.inspect_packet(&pkt, 1_000);
    // At the exact boundary, should not trigger oversized (only > max triggers).
    assert!(
        alert.is_none(),
        "SOME/IP with length exactly at max should not trigger oversized alert"
    );
}

#[test]
fn eth_normal_ipv4_no_alerts() {
    let mut eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();

    // A normal IPv4 packet (ethertype 0x0800) with no VLAN, no DoIP, no SOME/IP.
    let payload = [0u8; 64];
    let pkt = EthPacket {
        src_mac: [0x11; 6],
        dst_mac: [0x22; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };

    assert!(
        eth.inspect_packet(&pkt, 1_000).is_none(),
        "normal IPv4 packet should not trigger any alerts"
    );
}

// ===========================================================================
// Additional IDS correlation scenarios
// ===========================================================================

#[test]
fn ids_correlation_only_can_alert_no_escalation() {
    let mut engine = make_ids_engine();

    // Trigger a CAN flood alert.
    let frame = make_can_frame(0x100, 8, &[0x01; 8]);
    engine.submit_can_frame(&frame, 1_000); // seed
    let can_alert = engine.submit_can_frame(&frame, 1_001); // flood
    assert!(can_alert.is_some(), "CAN flood alert expected");

    // Do NOT submit any ETH packet with an alert.
    // Send a normal ETH packet that should NOT trigger.
    let payload = [0u8; 64];
    let pkt = EthPacket {
        src_mac: [0x11; 6],
        dst_mac: [0x22; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };
    let eth_alert = engine.submit_eth_packet(&pkt, 1_050);
    // No ETH alert should be generated.
    assert!(
        eth_alert.is_none(),
        "normal ETH packet should not trigger alert even after CAN alert"
    );
}

#[test]
fn ids_correlation_only_eth_alert_no_escalation() {
    let mut engine = make_ids_engine();

    // Send a CAN frame that does NOT trigger (first frame seeds timestamp).
    let frame = make_can_frame(0x100, 8, &[0x01; 8]);
    assert!(engine.submit_can_frame(&frame, 1_000).is_none());

    // Now trigger an ETH VLAN hopping alert.
    let payload = [0u8; 16];
    let pkt = EthPacket {
        src_mac: [0x01; 6],
        dst_mac: [0x02; 6],
        vlan_id: Some(999),
        ethertype: 0x0800,
        dst_port: None,
        payload: &payload,
    };
    let eth_alert = engine.submit_eth_packet(&pkt, 1_050);
    assert!(eth_alert.is_some(), "ETH VLAN alert expected");

    // Without a prior CAN alert, the ETH alert should NOT be escalated.
    let eth_alert = eth_alert.expect("ETH VLAN alert should be present");
    assert_eq!(
        eth_alert.severity,
        AlertSeverity::High,
        "ETH alert should remain High without CAN correlation"
    );
}
