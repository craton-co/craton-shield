// SPDX-License-Identifier: Apache-2.0
//! Shared test/benchmark helpers for constructing CAN frames, firewall rules,
//! SOME/IP payloads, and other common structures.
//!
//! Used by both `cratonshield_benchmarks.rs` and `wcet_harness.rs` to avoid
//! divergence in fixture construction.

use vs_can_monitor::{CanFrame, CanRule};
use vs_netfw::{FirewallRule, RuleAction};
use vs_types::AlertSeverity;

pub fn make_can_frame(id: u32, dlc: u8, payload: &[u8]) -> CanFrame {
    assert!(
        payload.len() <= dlc as usize,
        "payload length ({}) must not exceed dlc ({})",
        payload.len(),
        dlc
    );
    let mut data = [0u8; 64];
    let len = payload.len().min(64);
    data[..len].copy_from_slice(&payload[..len]);
    CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data,
    }
}

pub fn can_rule(id_filter: u32, min_interval_us: u64) -> CanRule {
    CanRule {
        id: 0,
        id_mask: 0x7FF,
        id_filter,
        min_interval_us,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    }
}

pub fn firewall_rule(id: u32, priority: u8, action: RuleAction) -> FirewallRule {
    FirewallRule {
        id,
        priority,
        src_mac: None,
        dst_mac: None,
        vlan_id: None,
        ethertype: Some(0x0800),
        action,
        active: true,
        ..Default::default()
    }
}

#[allow(dead_code)]
/// Construct a minimal SOME/IP header (24 bytes):
/// service_id(2) + method_id(2) + length(4) + client_id(2) + session_id(2)
/// + protocol_ver(1) + iface_ver(1) + msg_type(1) + return_code(1) + padding(8)
pub fn make_someip_payload() -> [u8; 24] {
    let mut p = [0u8; 24];
    p[0] = 0x00;
    p[1] = 0x01; // service_id
    p[2] = 0x00;
    p[3] = 0x01; // method_id
    p[4] = 0x00;
    p[5] = 0x00;
    p[6] = 0x00;
    p[7] = 0x08; // length
    p[12] = 0x01; // protocol version
    p
}
