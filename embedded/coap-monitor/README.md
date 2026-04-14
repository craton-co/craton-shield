# vs-coap-monitor

CoAP protocol intrusion detection for Craton Shield.

## Overview

Monitors CoAP (Constrained Application Protocol) traffic for security anomalies.
Uses longest-prefix matching for URI rules and token-bucket rate limiting.
All state is stack-allocated with fixed-size arrays.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **URI allowlist/blocklist** | **Longest-prefix-match** on URI paths — more specific rules override general ones. | Allow all |
| **Method enforcement** | Per-URI bitmask of allowed methods (GET/POST/PUT/DELETE). | All methods |
| **Rate limiting** | Per-URI token bucket with automatic refill. 16 buckets max. | Unlimited |
| **Amplification detection** | Tracks request sizes; alerts if response exceeds threshold ratio. | 10x ratio |

## Configuration

```rust
use vs_coap_monitor::{CoapMonitor, UriAction, AllowedMethods};

let mut monitor = CoapMonitor::new();           // allow-by-default
// let mut monitor = CoapMonitor::new_deny_default(); // deny-by-default

// URI rules (prefix matching).
monitor.add_rule(b"/sensors", UriAction::Allow, AllowedMethods::GET_ONLY, 10).unwrap();
monitor.add_rule(b"/admin", UriAction::Block, AllowedMethods::ALL, 0).unwrap();
monitor.add_rule(
    b"/data",
    UriAction::Allow,
    AllowedMethods::new(true, true, false, false), // GET + POST
    5,
).unwrap();

// Amplification threshold (response/request size ratio).
monitor.set_amplification_threshold(10);
```

## Inspection

```rust
let result = monitor.inspect(&msg);
// result.allowed     — whether the message should be forwarded
// result.alert_count — number of alerts (0-4)

// Check for amplification on response:
if let Some(alert) = monitor.check_amplification(msg_id, response_len, ts_us) {
    // handle amplification attack
}
```

## Alert Source IDs

| ID | Meaning |
|:---|:---|
| 1 | URI blocked by rule |
| 2 | Method not allowed |
| 3 | Rate limit exceeded |
| 4 | Rate-limit bucket capacity exhausted |
| 5 | Amplification attack detected |
| 6 | Timestamp anomaly |

## Limits

- 24 URI rules max
- 64-byte URI patterns max
- 16 rate-limit buckets
- 32 recent requests tracked for amplification

## Errors

- `VsError::InvalidInput` — empty or oversized URI prefix
- `VsError::ResourceExhausted` — rule capacity full

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
