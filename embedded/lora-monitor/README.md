# vs-lora-monitor

LoRa / LoRaWAN intrusion detection for Craton Shield.

## Overview

Monitors LoRaWAN traffic for security anomalies on constrained IoT devices.
All state is stack-allocated with fixed-size arrays. No heap required.

## Detection Mechanisms

| Mechanism | Description | Default |
|:---|:---|:---|
| **Device allowlist/blocklist** | Per-device-address filtering. **Exact address match**. | Allow all |
| **Replay detection** | Tracks per-device frame counters with session awareness. Session IDs increment on rejoin so counter resets are not false-positived. | Enabled |
| **Join flood detection** | Sliding window detection of excessive join requests (DoS / key extraction). | 10 per 60s |
| **ADR monitoring** | Detects anomalous adaptive data rate changes within a 60-second window. | 5 changes per 60s |
| **Duty cycle tracking** | Per-device airtime accumulation over a 1-hour window. Alerts when a device exceeds 1% duty cycle. | 1% / 1 hour |
| **Timestamp validation** | Detects clock manipulation via monotonicity and gap checks. | Enabled |

## Configuration

```rust
use vs_lora_monitor::{LoraMonitor, DeviceAction};

let mut monitor = LoraMonitor::new();               // allow-by-default
// let mut monitor = LoraMonitor::new_deny_default(); // deny-by-default

// Device address rules.
monitor.add_rule([0x01, 0x02, 0x03, 0x04], DeviceAction::Allow).unwrap();
monitor.add_rule([0xDE, 0xAD, 0xBE, 0xEF], DeviceAction::Block).unwrap();

// Join flood tuning.
monitor.set_join_flood_params(10, 60_000_000); // 10 joins per 60 seconds

// Session management (after a device rejoin).
monitor.start_new_session([0x01, 0x02, 0x03, 0x04]).unwrap();
```

## Inspection

```rust
let result = monitor.inspect(&msg);
// result.allowed     — whether the message should be forwarded
// result.alert_count — number of alerts (0-4)
// result.alerts      — array of SecurityAlert structs

// For downlink messages:
let result = monitor.inspect_downlink(&msg);
```

## Alert Source IDs

| ID | Meaning |
|:---|:---|
| 1 | Join flood detected |
| 2 | Device address blocked by rule |
| 3 | Frame counter replay detected |
| 4 | ADR anomaly (rapid data rate changes) |
| 5 | Duty cycle exceeded |
| 6 | Timestamp anomaly |
| 7 | Session table exhausted |
| 8 | ADR table exhausted |
| 9 | Duty cycle table exhausted |

## Join-Procedure Guard (`JoinGuard`)

The [`join`] module exposes a standalone `JoinGuard` for `LoRaWAN` OTAA
join-procedure replay protection and AES-CMAC MIC verification. It is
independent of `LoraMonitor`'s frame-counter pipeline and can be wired in
front of it or used on its own.

`JoinGuard` covers three lineages:

- **JoinRequest** — verifies the MIC under the device's `AppKey` /
  `NwkKey` and tracks recently-seen `DevNonce`s per `DevEUI` in a
  16-deep ring (`MAX_DEV_NONCE_DEVICES = 16`, depth
  `DEV_NONCE_RING_DEPTH = 32`). A replayed `DevNonce` is rejected
  **without** displacing the legitimate value from the ring.
- **JoinAccept** — verifies the MIC over the **plaintext** body and
  tracks `JoinNonce` per join-server EUI in an 8-deep table
  (`MAX_JOIN_NONCE_SERVERS = 8`, ring depth
  `JOIN_NONCE_RING_DEPTH = 32`). `LoRaWAN` 1.1 requires the
  `JoinNonce` to strictly increase; 1.0.x rejects only on repeat
  within the recent ring.
- **Data frame** — stateless AES-CMAC verification over the
  `LoRaWAN` B0 block. Frame-counter replay is handled by
  `LoraMonitor`.

Every call returns a `JoinVerdict`:

```rust
pub enum JoinVerdict {
    Allow,
    Replay { kind: ReplayKind, value: u32 },
    MicMismatch,
    Malformed { reason: MalformedReason },
}
```

### Example

```rust
use vs_lora_monitor::{FrameDir, JoinGuard, JoinVerdict, LoraWanVersion};

let mut guard = JoinGuard::new(LoraWanVersion::V1_1);
let app_key = [0u8; 16];
let phy_payload: &[u8] = &[/* on-air JoinRequest with trailing MIC */];

match guard.inspect_join_request(phy_payload, &app_key, 1_000_000) {
    JoinVerdict::Allow => { /* forward to network server */ }
    JoinVerdict::Replay { value, .. } => { /* DevNonce replay */ let _ = value; }
    JoinVerdict::MicMismatch => { /* drop */ }
    JoinVerdict::Malformed { .. } => { /* drop */ }
}
```

## Limits

- 32 device address rules max
- 16 tracked devices (replay / session detection)
- 16 join timestamps for flood detection
- 16 duty cycle trackers
- 16 `DevEUI`s tracked for `DevNonce` replay (32-deep ring each)
- 8 `JoinEUI`s tracked for `JoinNonce` replay (32-deep ring each)

## Errors

- `VsError::ResourceExhausted` — rule or session capacity full

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
