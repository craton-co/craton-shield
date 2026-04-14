// SPDX-License-Identifier: Apache-2.0
//! Firewall and policy engine example.
//!
//! Demonstrates how to configure the network firewall with rules and
//! the XACML-lite policy engine for security policy evaluation.
//!
//! ```
//! cargo run --example firewall_policy
//! ```

use vs_eth_monitor::EthPacket;
use vs_netfw::{Firewall, FirewallRule, RuleAction};
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, AuthenticationLevel, CombiningAlgorithm, Effect,
    Environment, PolicyEngine, PolicyRule, Resource, ResourceMatcher, Subject, SubjectMatcher,
};
use vs_types::IpProtocol;

fn main() {
    println!("Craton Shield — Firewall & Policy Engine Example");
    println!("=================================================\n");

    // -----------------------------------------------------------------------
    // Part 1: Network Firewall
    // -----------------------------------------------------------------------
    println!("--- Part 1: Network Firewall ---\n");

    let mut firewall = Firewall::new();
    println!(
        "Firewall capacity: {}/{}",
        firewall.rule_capacity().0,
        firewall.rule_capacity().1
    );

    // Add a rule: allow UDP traffic to port 30292 (SOME/IP)
    let allow_someip = FirewallRule {
        id: 1,
        priority: 10,
        dst_port: Some(30292),
        protocol: Some(IpProtocol::Udp),
        action: RuleAction::Allow,
        active: true,
        ..Default::default()
    };

    firewall
        .add_rule(allow_someip)
        .expect("failed to add SOME/IP allow rule");
    println!("Rule 1: ALLOW UDP to port 30292 (priority 10)");

    // Add a default-deny rule with lowest priority
    let deny_all = FirewallRule {
        id: 999,
        priority: 255,
        action: RuleAction::Drop,
        active: true,
        ..Default::default()
    };

    firewall
        .add_rule(deny_all)
        .expect("failed to add deny-all rule");
    println!("Rule 999: DROP all (default deny, priority 255)");

    // Simulate a packet evaluation
    let payload: [u8; 30] = [
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x1E, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00,
        0x00, // protocol = UDP (17)
        0xC0, 0xA8, 0x01, 0x0A, // src: 192.168.1.10
        0xC0, 0xA8, 0x02, 0x14, // dst: 192.168.2.20
        // UDP header (8 bytes)
        0xBB, 0x01, // src port
        0x76, 0x54, // dst port 30292
        0x00, 0x0A, 0x00, 0x00, // 2 bytes payload
        0xAA, 0xBB,
    ];

    let pkt = EthPacket {
        src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        vlan_id: None,
        ethertype: 0x0800, // IPv4
        dst_port: Some(30292),
        payload: &payload,
    };

    let verdict = firewall.evaluate(&pkt, 1_000);
    println!("\nPacket (UDP to port 30292): {:?}", verdict);

    // Check rule hit counters
    if let Some(hits) = firewall.rule_hits(1) {
        println!("Rule 1 hits: {hits}");
    }
    println!("Total drops: {}", firewall.drop_count());

    // -----------------------------------------------------------------------
    // Part 2: Policy Engine
    // -----------------------------------------------------------------------
    println!("\n--- Part 2: XACML-Lite Policy Engine ---\n");

    let mut engine = PolicyEngine::new();
    engine.set_combining_algorithm(CombiningAlgorithm::DenyOverrides);
    println!("Combining algorithm: DenyOverrides");

    // Rule: allow authenticated tester to write firmware regions
    let update_rule = PolicyRule {
        id: 1,
        subject: SubjectMatcher::AuthenticatedWithLevel(AuthenticationLevel::Extended),
        resource: ResourceMatcher::FirmwareRegion(0),
        action: ActionMatcher::Write,
        effect: Effect::Permit,
        priority: 10,
        valid_from: 0,
        valid_until: 0, // no expiry
    };
    engine
        .add_rule(update_rule)
        .expect("failed to add update rule");
    println!("Rule 1: PERMIT Extended-auth Write to firmware region 0");

    // Rule: deny all unauthenticated write attempts
    let deny_unauth = PolicyRule {
        id: 2,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Write,
        effect: Effect::Deny,
        priority: 100,
        valid_from: 0,
        valid_until: 0,
    };
    engine
        .add_rule(deny_unauth)
        .expect("failed to add deny rule");
    println!("Rule 2: DENY all Write to any resource (lower priority)");

    // Evaluate: authenticated firmware update
    let subject_auth = Subject {
        address: 0x0001,
        authenticated: true,
        ecu_role: 0,
        session_token: 0xDEAD_BEEF,
        auth_level: AuthenticationLevel::Extended,
    };
    let resource_fw = Resource {
        bus_type: None,
        bus_id: None,
        service_id: None,
        firmware_region: Some(0),
    };
    let action_write = Action {
        action_type: ActionType::Write,
    };
    let env = Environment {
        timestamp_us: 50_000,
    };

    let decision = engine.evaluate(&subject_auth, &resource_fw, &action_write, &env);
    println!(
        "\nAuthenticated Write to firmware region 0: effect={:?}, rule_id={:?}",
        decision.effect, decision.rule_id
    );

    // Evaluate: unauthenticated write attempt
    let subject_unauth = Subject {
        address: 0x00FF,
        authenticated: false,
        ecu_role: 0,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };

    let decision = engine.evaluate(&subject_unauth, &resource_fw, &action_write, &env);
    println!(
        "Unauthenticated Write to firmware region 0: effect={:?}, rule_id={:?}",
        decision.effect, decision.rule_id
    );

    println!(
        "\nPolicy engine: {}/{} rules loaded.",
        engine.rule_count(),
        engine.rule_capacity().1
    );
    println!("\nDone.");
}
