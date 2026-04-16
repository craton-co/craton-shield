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
use vs_netfw::{Firewall, FirewallRule, RuleAction};

let mut fw = Firewall::new();
fw.add_rule(FirewallRule {
    id: 1, priority: 10, action: RuleAction::Allow,
    dst_port: Some(13400), active: true, ..Default::default()
})?;
let verdict = fw.evaluate(&packet, timestamp_us);
```

## Feature Flags

Compile-time capacity selection:

- Base (default): 128 rules
- `capacity-large`: 256 rules
- `capacity-xl`: 512 rules

See [docs/feature-flags.md](../docs/feature-flags.md) for the full reference.

## License

Apache-2.0
