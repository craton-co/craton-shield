// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_eth_monitor::EthPacket;
use vs_netfw::{Firewall, FirewallRule, RuleAction};

fuzz_target!(|data: &[u8]| {
    // Fuzz firewall rule evaluation with arbitrary packet data.
    // The firewall must not panic on any input.
    if data.len() < 20 {
        return;
    }

    let mut fw = Firewall::new();

    // Build a rule from the first few fuzz bytes.
    let rule_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let ethertype_match = u16::from_le_bytes([data[4], data[5]]);
    let action = match data[6] & 0x03 {
        0 => RuleAction::Allow,
        1 => RuleAction::Drop,
        2 => RuleAction::Log,
        _ => RuleAction::RateLimit(u32::from_le_bytes([data[7], data[8], data[9], data[10]])),
    };

    let rule = FirewallRule {
        id: rule_id,
        priority: data[11],
        ethertype: Some(ethertype_match),
        action,
        active: true,
        ..FirewallRule::default()
    };
    let _ = fw.add_rule(rule);

    // Build a packet from remaining fuzz bytes.
    let src_mac = [data[12], data[13], data[14], data[15], data[16], data[17]];
    let dst_mac = [data[18], data[19], data[12], data[13], data[14], data[15]];
    let ethertype = u16::from_be_bytes([data[4], data[5]]);
    let payload = &data[20..];

    let pkt = EthPacket {
        src_mac,
        dst_mac,
        vlan_id: None,
        ethertype,
        dst_port: None,
        payload,
    };

    let timestamp_us = u64::from_le_bytes([
        data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]);

    let verdict1 = fw.evaluate(&pkt, timestamp_us);

    // Verify determinism: the same packet evaluated twice must produce the
    // same verdict (rate-limiter excluded — we use a fresh Firewall each run,
    // so state cannot diverge between the two calls here).
    let verdict2 = fw.evaluate(&pkt, timestamp_us);
    assert_eq!(verdict1, verdict2, "firewall evaluation must be deterministic");
});
