# vs-zigbee-monitor

Zigbee / IEEE 802.15.4 intrusion detection for Craton Shield.

## Overview

Monitors Zigbee traffic for security anomalies on constrained IoT devices.
All state is stack-allocated with fixed-size arrays. No heap required.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **Address filtering** | Per-address allowlist/blocklist with optional PAN ID scoping (0xFFFF = any PAN). **First-match-wins**. | Allow all |
| **PAN ID enforcement** | Restrict which PAN IDs are accepted per address rule. | Any PAN |
| **Frame type filtering** | Bitmask control over allowed frame types (beacon, data, ack, command). | All types allowed |
| **Rate limiting** | Per-source-address token bucket with automatic refill. Buckets expire after 5 minutes of inactivity. | Unlimited |
| **Security frame counter / replay protection** | Tracks per-source frame counters. Detects replayed frames with non-increasing counters. | Enabled |
| **Timestamp validation** | Detects clock manipulation via monotonicity and gap checks. | Enabled |
| **Trust Center monitoring** | Sliding window detection of rapid key rotation events. | 3 rotations per 60s |

## Configuration

```rust
use vs_zigbee_monitor::{ZigbeeMonitor, AddrAction};

let mut monitor = ZigbeeMonitor::new();               // allow-by-default
// let mut monitor = ZigbeeMonitor::new_deny_default(); // deny-by-default

// Address rules (PAN ID 0xFFFF = match any PAN).
monitor.add_rule(0x0001, 0x1234, AddrAction::Allow, 10).unwrap(); // 10 frames/sec
monitor.add_rule(0x00FF, 0xFFFF, AddrAction::Block, 0).unwrap();

// Frame type filtering (bitmask: bit 0=beacon, 1=data, 2=ack, 3=command).
monitor.set_allowed_frame_types(0x0F); // all types
```

## Inspection

`inspect` runs address, PAN, frame-type, rate-limit and timestamp checks.
It does **not** run replay (security frame counter) detection — use
`inspect_with_counter` for that.

```rust
use vs_zigbee_monitor::ZigbeeMonitor;
use vs_types_embedded::{ZigbeeFrame, ZigbeeFrameType};

let mut monitor = ZigbeeMonitor::new();
let frame = ZigbeeFrame {
    src_pan_id: 0x1234,
    src_addr: 0x0001,
    dst_addr: 0x0000,
    cluster_id: 0,
    frame_type: ZigbeeFrameType::Data,
    payload_len: 20,
    timestamp_us: 1_000_000,
};

let result = monitor.inspect(&frame);
// result.allowed        — whether the frame should be forwarded
// result.alert_count    — number of alerts (0-4)
// result.alerts         — array of SecurityAlert structs
// result.alerts_dropped — alerts that overflowed the 4-slot array
```

### Replay protection — `inspect_with_counter`

Replay detection (alert ID 5) requires the per-frame security counter, so it
is only performed by `inspect_with_counter`. It runs every `inspect` check
plus a per-source sliding-window counter check.

```rust
# use vs_zigbee_monitor::ZigbeeMonitor;
# use vs_types_embedded::{ZigbeeFrame, ZigbeeFrameType};
# let mut monitor = ZigbeeMonitor::new();
# let frame = ZigbeeFrame {
#     src_pan_id: 0x1234, src_addr: 0x0001, dst_addr: 0x0000, cluster_id: 0,
#     frame_type: ZigbeeFrameType::Data, payload_len: 20, timestamp_us: 1_000_000,
# };
// `frame_counter` is the APS/NWK security frame counter for this frame.
let result = monitor.inspect_with_counter(&frame, /* frame_counter = */ 42);
```

By default a counter that appears to wrap from `0xFFFFFFFF` to `0` is rejected
as a stale frame. Call `set_allow_counter_rollover(true)` to accept a genuine
32-bit rollover; rollover acceptance is fail-closed and requires the device's
counter to have genuinely climbed into the top of the range first, so a
replayed low-counter frame cannot re-anchor the replay window.

### Trust Center monitoring — `record_trust_center_event`

Trust Center key-rotation detection (alert ID 6) is driven separately by
feeding Trust Center events as they occur:

```rust
# use vs_zigbee_monitor::ZigbeeMonitor;
use vs_types_embedded::TrustCenterEvent;

# let mut monitor = ZigbeeMonitor::new();
let result = monitor.record_trust_center_event(
    TrustCenterEvent::NetworkKeyUpdate,
    /* ts_us = */ 5_000_000,
);
// More than 3 NetworkKeyUpdate events within 60s raises a rapid-rotation alert.
```

## Alert Source IDs

| ID | Meaning |
|:---|:---|
| 1 | Unknown frame type |
| 2 | Blocked frame type |
| 3 | Address blocked by rule |
| 4 | Rate limit exceeded |
| 5 | Security frame counter replay detected |
| 6 | Trust Center rapid key rotation |
| 7 | Timestamp anomaly |
| 8 | Security counter table exhausted |
| 9 | Rate-limit table exhausted |

## Limits

Default-tier capacities (no capacity feature enabled):

- 32 address rules max
- 16 rate-limit buckets (5-minute expiry)
- 16 security frame counters tracked
- 16 Trust Center events in sliding window

Address-rule, rate-bucket, and security-counter capacities come from
`vs-types-embedded` constants and scale up with the `capacity-large` /
`capacity-xl` feature flags on this crate (which forward to the corresponding
features on `vs-types-embedded`). For the exact sizes at each capacity tier,
see the `MAX_ZIGBEE_*` constants in `vs-types-embedded`. The Trust Center
event window is fixed at 16 internally.

## Errors

- `VsError::ResourceExhausted` — rule capacity full
- `VsError::InvalidInput` — invalid rule index on removal

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
