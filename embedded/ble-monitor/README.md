# vs-ble-monitor

BLE connection intrusion detection for Craton Shield.

## Overview

Monitors Bluetooth Low Energy connections for security anomalies on IoT devices.
Tracks per-peer state for RSSI, pairing, and GATT operation monitoring.
All state is stack-allocated with fixed-size arrays.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **MAC filtering** | Exact MAC address allowlist/blocklist. | Allow all |
| **Connection storm** | Sliding window detection of excessive connections (any peer). | 10 per 30s |
| **RSSI anomaly** | Sudden RSSI jump between connections indicates relay/MITM attack. | 30 dBm threshold |
| **Pairing brute-force** | Consecutive pairing failures per peer. Resets on success. | 3 failures |
| **Global pairing storm** | Distributed pairing failures across many MACs in a window. | 10 per 60s |
| **Pairing request flood** | Per-peer pairing-request rate (separate from failures). | 100 per 60s |
| **Pairing-method downgrade** | LE Secure Connections to Legacy, or authenticated method to JustWorks. | Always on |
| **GATT abuse** | Per-peer read/write operation count in a 60-second window. | 100 ops/min |
| **GATT permission violation** | Read/write on a policy-protected handle without the required auth/authz flags. | Per registered policy |
| **MTU downgrade** | Negotiated ATT MTU shrinks below a previously observed baseline. | Always on |
| **Random address flood** | Surge of random BLE addresses (incl. random-private-non-resolvable detected via the IEEE 802 locally-administered bit). | 50 per 60s |
| **Advertisement flood** | Aggregate advertisement rate across all peers. | 1000 per 60s |
| **Advertisement replay** | Duplicate `(peer_addr, rssi, conn_handle)` digest within a short window. | 5s window |
| **Short connection** | Disconnect within 1 second of connect (probe behaviour). | 1s threshold |
| **Timestamp anomaly** | Non-monotonic or out-of-range event timestamps. | Always on |
| **Invalid MAC** | Zero or broadcast peer addresses. | Always on |

## Configuration

```rust
use vs_ble_monitor::{BleMonitor, MacAction};

let mut monitor = BleMonitor::new();             // allow-by-default
// let mut monitor = BleMonitor::new_deny_default(); // deny-by-default (allowlist only)

// MAC filters.
monitor.add_mac_filter([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03], MacAction::Allow).unwrap();
monitor.add_mac_filter([0xDD, 0xEE, 0xFF, 0x04, 0x05, 0x06], MacAction::Block).unwrap();

// Tuning.
monitor.set_conn_storm_params(10, 30_000_000);    // 10 connections per 30 seconds
monitor.set_pairing_fail_threshold(3);             // 3 failures triggers alert
monitor.set_gatt_rate_threshold(100);              // 100 ops per 60-second window
```

## Inspection

```rust
use vs_types_embedded::{BleEvent, BleEventType};

let result = monitor.inspect(&event);
// result.allowed     — whether the event should be processed
// result.alert_count — number of alerts (0-4)
```

## Alert Source IDs

| ID | Meaning | Severity |
|:---|:---|:---|
| 1 | MAC filter block | Medium |
| 2 | Connection storm | High |
| 3 | RSSI anomaly (relay attack) | High |
| 4 | Peer slot exhaustion | Low |
| 5 | Pairing failure lockout | High |
| 6 | Global pairing storm | High |
| 7 | GATT abuse | Medium |
| 8 | Timestamp anomaly | Medium |
| 9 | Random address flood | Medium |
| 10 | Pairing request flood | Medium |
| 11 | Short connection | Low |
| 12 | Advertisement flood | Medium |
| 13 | Unknown BLE event | Low |
| 14 | Invalid MAC (zero / broadcast) | High |
| 15 | ATT MTU downgrade | Medium |
| 16 | GATT permission violation | High |
| 17 | Pairing-method downgrade | High |
| 18 | Advertisement replay | Medium |

## Limits

- 16 MAC filter entries
- 16 tracked peers (RSSI, pairing, GATT)
- 32 connection timestamps for storm detection
- 32 GATT handle permission policies
- 16 advertisement-replay digest ring slots

Tracked-peer and MAC-filter capacities (`MAX_TRACKED_PEERS`,
`MAX_MAC_FILTERS`) are re-exported from `vs-types-embedded` and scale with the
crate's capacity feature flags:

- default — values shown above.
- `capacity-large` — larger fixed-size tables suited for gateway-class
  devices.
- `capacity-xl` — largest tables; intended for aggregator nodes.

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the
exact constants per profile.

## Errors

- `VsError::ResourceExhausted` — MAC filter capacity full

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
