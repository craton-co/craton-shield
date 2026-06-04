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

| Flag | Effect |
|:-----|:-------|
| _(default)_ | Base capacity tier: 256 rules, 1024 tracked IDs, 512 allowlist entries, 256 replay counters. |
| `capacity-large` | Doubles every capacity tier (512 / 2048 / 1024 / 512). |
| `capacity-xl` | Quadruples every capacity tier (1024 / 4096 / 2048 / 1024). Takes precedence over `capacity-large` if both are set. |
| `testing` | Exposes the internal entropy helpers via `testing_internals` for benches/integration tests. Not for production builds. |

`capacity-large` and `capacity-xl` are mutually exclusive by design; enabling
both selects the `capacity-xl` tier.

## Usage

```no_run
use vs_can_monitor::{CanMonitor, CanFrame, CanRule};
use vs_types::AlertSeverity;

// Supply a random SipHash key for replay detection.
// In production, source from `CryptoProvider::random_bytes()`.
let replay_key: [u8; 16] = [0xAB; 16];
let mut monitor = CanMonitor::try_new(replay_key).expect("non-zero key");

// `id` is a caller-assigned handle used by `remove_rule`; `id_filter`
// (masked by `id_mask`) is what the rule matches against incoming frames.
monitor.add_rule(CanRule {
    id: 1,
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
let timestamp_us: u64 = 0;
// `process_frame` returns `Option<SecurityAlert>` — at most one alert per frame.
let alert = monitor.process_frame(&frame, timestamp_us);
```

`CanMonitor` is single-threaded: every method takes `&mut self` and the type
has no interior mutability. Callers sharing one monitor between an ISR and a
thread context must provide external synchronization.

## License

Apache-2.0. See [LICENSE](LICENSE).
