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
| **GATT abuse** | Per-peer read/write operation count in a 60-second window. | 100 ops/min |

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

## Limits

- 16 MAC filter entries
- 16 tracked peers (RSSI, pairing, GATT)
- 32 connection timestamps for storm detection

## Errors

- `VsError::ResourceExhausted` — MAC filter capacity full

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
