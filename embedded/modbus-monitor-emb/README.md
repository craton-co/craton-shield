# vs-modbus-monitor-emb

Modbus RTU/TCP intrusion detection for embedded IoT gateways.

## Overview

Lightweight Modbus monitor for constrained IoT gateways and edge devices.
This crate shares detection mechanisms with `vs-modbus-monitor-ind` (industrial
variant) but integrates with the embedded runtime (`vs-runtime-embedded`) and
uses `vs-types-embedded` types. Use this crate for resource-constrained IoT
deployments; use `vs-modbus-monitor-ind` for SCADA/DCS/PLC environments with
IEC 62443 zone/conduit requirements.

All state is stack-allocated with fixed-size arrays. No heap required.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **Unit ID filtering** | Per-unit-ID allowlist/blocklist. **First-match-wins**. | Allow all |
| **Function code enforcement** | Per-unit policy: `Any`, `ReadOnly`, or `WriteOnly`. | Any |
| **Write protection** | Block write operations to specific units via `ReadOnly` policy. | Disabled |
| **Register range enforcement** | Per-unit minimum and maximum register address (inclusive). | Full range |
| **Rate limiting** | Per-unit token bucket with automatic refill. Buckets expire after 5 minutes of inactivity. | Unlimited |
| **Invalid unit ID detection** | Flags reserved Modbus unit IDs (248-255). | Enabled |
| **TCP source IP filtering** | Allow/block by source IP prefix (CIDR-style). TCP transport only. | Allow all |
| **Exception response tracking** | Per-unit exception count in a 60-second window. Alerts when threshold exceeded. | 10 per 60s |
| **Timestamp validation** | Detects clock manipulation via monotonicity and gap checks. | Enabled |

## Configuration

```rust
use vs_modbus_monitor::{ModbusMonitor, UnitAction, FunctionPolicy};
use vs_types_embedded::IpAction;

let mut monitor = ModbusMonitor::new();               // allow-by-default
// let mut monitor = ModbusMonitor::new_deny_default(); // deny-by-default

// Unit ID rules.
monitor.add_rule(
    1,                        // unit ID
    UnitAction::Allow,        // action
    FunctionPolicy::ReadOnly, // only reads allowed
    0,                        // register min
    999,                      // register max
    50,                       // 50 requests/sec
).unwrap();

monitor.add_rule(
    247,
    UnitAction::Block,
    FunctionPolicy::Any,
    0,
    u16::MAX,
    0,
).unwrap();

// TCP IP filters (CIDR prefix matching).
monitor.add_ip_filter([192, 168, 1, 0], 24, IpAction::Allow).unwrap();
monitor.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block).unwrap();
```

## Inspection

```rust
// RTU messages:
let result = monitor.inspect_rtu(&rtu_msg);
// result.allowed     — whether the message should be forwarded
// result.alert_count — number of alerts (0-4)
// result.alerts      — array of SecurityAlert structs

// TCP messages (includes IP filter checks):
let result = monitor.inspect_tcp(&tcp_msg);

// Exception tracking (call separately when a response contains an exception):
if let Some(alert) = monitor.record_exception(unit_id, exception, timestamp_us, source_type) {
    // exception flood alert
}
```

## Alert Source IDs

| ID | Meaning |
|:---|:---|
| 1 | Invalid / reserved unit ID (248-255) |
| 2 | Unknown function code |
| 3 | Unit ID blocked by rule |
| 4 | Function code policy violation |
| 5 | Register address out of range |
| 6 | Rate limit exceeded |
| 7 | TCP source IP blocked |
| 8 | Exception response flood |
| 9 | Timestamp anomaly |

## Limits

- 32 unit ID rules max
- 16 rate-limit buckets (5-minute expiry)
- 16 TCP IP filter entries
- 32 exception counters (per unit)

## Errors

- `VsError::ResourceExhausted` — rule, IP filter, or bucket capacity full
- `VsError::InvalidInput` — invalid index on removal

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
