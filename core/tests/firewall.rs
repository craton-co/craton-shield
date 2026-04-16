// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the network firewall (`vs_netfw`).

use vs_eth_monitor::EthPacket;
use vs_netfw::{Firewall, FirewallRule, RuleAction, Verdict};

fn make_rule(id: u32, priority: u8, action: RuleAction) -> FirewallRule {
    FirewallRule {
        id,
        priority,
        src_mac: None,
        dst_mac: None,
        vlan_id: None,
        ethertype: None,
        src_ip: None,
        dst_ip: None,
        protocol: None,
        src_port: None,
        dst_port: None,
        action,
        active: true,
    }
}

fn make_packet_fields<'a>(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_id: Option<u16>,
    ethertype: u16,
    dst_port: Option<u16>,
    payload: &'a [u8],
) -> EthPacket<'a> {
    EthPacket {
        src_mac,
        dst_mac,
        vlan_id,
        ethertype,
        dst_port,
        payload,
    }
}

#[test]
fn firewall_default_deny_no_rules() {
    let mut fw = Firewall::new();
    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    // Default-deny: no rules means all traffic is dropped.
    let action = fw.evaluate(&pkt, 0);
    assert_eq!(action, Verdict::Drop);
}

#[test]
fn firewall_drop_rule_blocks_packet() {
    let mut fw = Firewall::new();

    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.ethertype = Some(0x0800);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];

    // Matching packet (ethertype 0x0800) should be dropped
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

    // Non-matching packet (ethertype 0x86DD) hits default-deny
    let pkt2 = make_packet_fields([0x11; 6], [0x22; 6], None, 0x86DD, None, &payload);
    assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);
}

#[test]
fn firewall_rule_priority_ordering() {
    let mut fw = Firewall::new();

    // Allow rule at priority 10 (lower priority)
    let mut allow_rule = make_rule(1, 10, RuleAction::Allow);
    allow_rule.ethertype = Some(0x0800);
    fw.add_rule(allow_rule).expect("add allow rule");

    // Drop rule at priority 5 (higher priority — lower number wins)
    let mut drop_rule = make_rule(2, 5, RuleAction::Drop);
    drop_rule.ethertype = Some(0x0800);
    fw.add_rule(drop_rule).expect("add drop rule");

    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
}

#[test]
fn firewall_rule_capacity() {
    let mut fw = Firewall::new();
    assert_eq!(fw.rule_capacity(), (0, 128));

    let rule = make_rule(1, 5, RuleAction::Drop);
    fw.add_rule(rule).expect("add rule");
    assert_eq!(fw.rule_capacity(), (1, 128));
}

#[test]
fn firewall_dynamic_rule_expiry() {
    let mut fw = Firewall::new();

    // Low-priority allow-all so we can distinguish "dynamic rule dropped"
    // from "default-deny dropped". Same pattern as mac/vlan filter tests.
    fw.add_rule(make_rule(99, 255, RuleAction::Allow))
        .expect("add allow-all");

    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.ethertype = Some(0x0800);
    fw.insert_dynamic_rule(rule, 1000)
        .expect("insert dynamic rule");

    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);

    // At ts=500 the dynamic drop rule (priority 5) wins over allow-all (priority 255)
    assert_eq!(fw.evaluate(&pkt, 500), Verdict::Drop);

    // Expire rules at ts=2000 — the dynamic rule (expiry_us=1000) should be gone
    fw.expire_rules(2000);

    // After expiry the dynamic rule is removed; only the allow-all remains → Allow.
    // This proves the dynamic rule was actually removed, not just masked by default-deny.
    assert_eq!(fw.evaluate(&pkt, 3000), Verdict::Allow);
}

#[test]
fn firewall_mac_filter() {
    let mut fw = Firewall::new();

    // Low-priority allow-all so non-matching packets are permitted.
    fw.add_rule(make_rule(99, 255, RuleAction::Allow))
        .expect("add allow-all");

    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.src_mac = Some([0xAA; 6]);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];

    // Packet from matching MAC should be dropped
    let pkt = make_packet_fields([0xAA; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

    // Packet from different MAC should be allowed (by allow-all rule)
    let pkt2 = make_packet_fields([0xBB; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Allow);
}

#[test]
fn firewall_vlan_filter() {
    let mut fw = Firewall::new();

    // Low-priority allow-all so non-matching packets are permitted.
    fw.add_rule(make_rule(99, 255, RuleAction::Allow))
        .expect("add allow-all");

    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.vlan_id = Some(999);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];

    // Packet with VLAN 999 should be dropped
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], Some(999), 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

    // Packet with no VLAN should be allowed (by allow-all rule)
    let pkt2 = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Allow);
}

#[test]
fn firewall_rate_limit_action() {
    let mut fw = Firewall::new();

    let mut rule = make_rule(1, 5, RuleAction::RateLimit(10));
    rule.ethertype = Some(0x0800);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(10));
}

#[test]
fn firewall_log_action() {
    let mut fw = Firewall::new();

    let mut rule = make_rule(1, 5, RuleAction::Log);
    rule.ethertype = Some(0x0800);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);
    assert_eq!(fw.evaluate(&pkt, 0), Verdict::Log);
}

#[test]
fn firewall_drop_counter_increments() {
    let mut fw = Firewall::new();

    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.ethertype = Some(0x0800);
    fw.add_rule(rule).expect("add rule");

    let payload = [0u8; 32];
    let pkt = make_packet_fields([0x11; 6], [0x22; 6], None, 0x0800, None, &payload);

    for _ in 0..5 {
        fw.evaluate(&pkt, 0);
    }

    assert_eq!(fw.drop_count(), 5);
}

// ---------------------------------------------------------------------------
// V9 audit fix tests
// ---------------------------------------------------------------------------

#[test]
fn firewall_rejects_duplicate_priority() {
    let mut fw = Firewall::new();

    // Add a rule at priority 5.
    let rule_a = make_rule(1, 5, RuleAction::Drop);
    fw.add_rule(rule_a).expect("add first rule");

    // Adding another rule with the same priority should fail.
    let rule_b = make_rule(2, 5, RuleAction::Allow);
    let result = fw.add_rule(rule_b);
    assert!(
        result.is_err(),
        "duplicate priority should be rejected: got {result:?}"
    );
}

#[test]
fn firewall_rejects_invalid_vlan_id() {
    let mut fw = Firewall::new();

    // VLAN ID > 4094 should be rejected per IEEE 802.1Q.
    let mut rule = make_rule(1, 5, RuleAction::Drop);
    rule.vlan_id = Some(4095);
    let result = fw.add_rule(rule);
    assert!(
        result.is_err(),
        "vlan_id > 4094 should be rejected: got {result:?}"
    );
}
