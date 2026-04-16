# vs-can-monitor

CAN bus intrusion detection for Craton Shield.

`#![no_std]`, zero heap allocations. Designed for bare-metal Cortex-M and
Linux automotive gateways.

## Detection Modes

| Detector | Description |
|:---------|:------------|
| Frame flood | Rate-limit enforcement per CAN ID |
| DLC anomaly | Flags frames whose DLC exceeds the rule maximum |
| ID allowlist | Rejects CAN IDs not in the configured allow-list |
| Payload entropy | Detects fuzzing via Shannon entropy analysis |
| Replay counter | Tracks per-ID monotonic counters to detect replays |

## Capacity

- Up to **256 rules**, **1024 tracked IDs**, **512 allowlist entries** (base tier).
- Higher limits available via `capacity-large` / `capacity-xl` feature flags.

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full reference.

## Usage

```rust
use vs_can_monitor::{CanMonitor, CanFrame, CanRule};
use vs_types::AlertSeverity;

// Supply a random SipHash key for replay detection.
// In production, source from `CryptoProvider::random_bytes()`.
let replay_key: [u8; 16] = [0xAB; 16];
let mut monitor = CanMonitor::try_new(replay_key).expect("non-zero key");
monitor.add_rule(CanRule {
    id: 0,
    id_mask: 0x7FF,
    id_filter: 0x100,
    min_interval_us: 10_000,
    max_dlc: 8,
    is_extended: false,
    severity: AlertSeverity::High,
}).unwrap();

let frame = CanFrame {
    id: 0x100, dlc: 8, data: [0u8; 64],
    is_extended: false, is_fd: false,
};
let alerts = monitor.process_frame(&frame, timestamp_us);
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
