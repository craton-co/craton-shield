# vs-mqtt-monitor

MQTT protocol intrusion detection for Craton Shield.

## Overview

Monitors MQTT traffic for security anomalies on constrained IoT gateways.
All state is stack-allocated with fixed-size arrays. No heap required.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **Topic allowlist/blocklist** | MQTT wildcard pattern matching (`+`, `#`). **First-match-wins** — rule ordering matters. | Allow all |
| **Connect storm** | Sliding window detection of excessive CONNECT packets. | 5 per 60s |
| **QoS enforcement** | Per-topic minimum or exact QoS policy. | Any QoS |
| **Rate limiting** | Per-topic token bucket with automatic refill. 32 buckets max. | Unlimited |

## Configuration

```rust
use vs_mqtt_monitor::{MqttMonitor, TopicAction, QosPolicy};
use vs_types_embedded::MqttQoS;

let mut monitor = MqttMonitor::new();           // allow-by-default
// let mut monitor = MqttMonitor::new_deny_default(); // deny-by-default

// Topic rules (supports MQTT wildcards: + and #).
monitor.add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 10).unwrap();
monitor.add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0).unwrap();
monitor.add_rule(
    b"critical/#",
    TopicAction::Allow,
    QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
    0,
).unwrap();

// Connect storm tuning.
monitor.set_connect_storm_params(5, 60_000_000); // 5 connects per 60 seconds
```

## Inspection

```rust
let result = monitor.inspect(&msg);
// result.allowed    — whether the message should be forwarded
// result.alert_count — number of alerts (0-4)
// result.alerts     — array of SecurityAlert structs
```

## Alert Source IDs

| ID | Meaning |
|:---|:---|
| 0 | Connect storm detected |
| 1 | Empty topic in Publish/Subscribe |
| 2 | Topic blocked by rule |
| 3 | QoS policy violation (advisory — does not block) |
| 4 | Rate limit exceeded |
| 5 | Rate-limit bucket capacity exhausted |
| 6 | Payload size anomaly (EWMA) |
| 7 | Timestamp anomaly |

## Limits

- 32 topic rules max
- 64-byte topic patterns max
- 32 rate-limit buckets
- 16 connect timestamps tracked

## Errors

- `VsError::InvalidInput` — empty or oversized pattern, malformed wildcard
- `VsError::ResourceExhausted` — rule capacity full

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
