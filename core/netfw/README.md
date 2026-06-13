# vs-netfw

Automotive Ethernet firewall with token-bucket rate limiting and dynamic rules.

## Overview

This crate provides a stateful network firewall for automotive Ethernet with
L2/L3/L4 rule matching, token-bucket rate limiting, and connection tracking.
Rules are evaluated in priority order with a default-deny policy. Dynamic
rules can be added at runtime for adaptive threat response.

## Key Types

- `Firewall` — stateful firewall engine with rule table, rate limiters, and connection tracker
- `FirewallRule` — a single rule with L2-L4 match fields, priority, and action
- `RuleAction` — action on match (Allow, Drop, Log, RateLimit)

## Usage

```rust
use vs_netfw::{Firewall, FirewallRule, RuleAction, Verdict};
use vs_eth_monitor::EthPacket;

fn main() -> Result<(), vs_types::VsError> {
    let mut fw = Firewall::new();

    // Allow IPv4 traffic from a specific source MAC. Adding an L3/L4 field
    // such as `dst_port: Some(13400)` would additionally require the packet
    // payload to parse as that transport flow.
    fw.add_rule(FirewallRule {
        id: 1,
        priority: 10,
        action: RuleAction::Allow,
        src_mac: Some([0x02, 0, 0, 0, 0, 1]),
        ethertype: Some(0x0800),
        active: true,
        ..Default::default()
    })?;

    // Build a packet to evaluate (normally produced by the eth-monitor crate).
    let packet = EthPacket {
        src_mac: [0x02, 0, 0, 0, 0, 1],
        dst_mac: [0x02, 0, 0, 0, 0, 2],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &[],
    };

    let timestamp_us: u64 = 1_000_000;
    let verdict = fw.evaluate(&packet, timestamp_us);
    assert_eq!(verdict, Verdict::Allow);
    Ok(())
}
```

## Feature Flags

Compile-time capacity selection:

- Base (default): 128 rules
- `capacity-large`: 256 rules
- `capacity-xl`: 512 rules

See [docs/feature-flags.md](../docs/feature-flags.md) for the full reference.

## License

Apache-2.0
