# vs-profinet-monitor

PROFINET IO intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors PROFINET real-time traffic for anomalies in industrial control
systems. Designed for industrial communication processors and PROFINET
controllers.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

**Stack budget:** approximately 1.5 KB per `ProfinetMonitor` instance
(frame ID rules, cycle state table, alarm-flood window, rate buckets,
DCP policy, IRT timing rules).

## Features

- **Frame ID filtering** — allowlist/blocklist of permitted RT frame IDs (single or range)
- **DCP blocking** — block unauthorized Discovery and Configuration Protocol messages (enabled by default)
- **DCP service allowlist** — per-service policy (Get/Set/Identify/Hello) with a `commissioning` preset that permits discovery while blocking `Set`
- **Cycle counter validation** — detect missed or replayed cyclic RT frames (backward jumps surface as `ReplayDetected`)
- **IRT timing enforcement** — per-frame-ID isochronous real-time `cycle_us ± jitter_us` window
- **Provider state monitoring** — alert on provider Run-to-Stop transitions
- **Alarm flood detection** — rate-based detection of alarm frame floods
- **Rate limiting** — per-frame-ID token-bucket cap (`max_rate_per_sec`)
- **Strict mode** — block all unknown frame IDs by default

## Usage

```rust
use vs_profinet_monitor::{ProfinetMonitor, FrameAction};

let mut monitor = ProfinetMonitor::new_strict();

// Allow a specific frame ID range with no per-rule rate cap
// (signature: start, end, action, max_rate_per_sec; 0 = unlimited).
monitor
    .add_frame_range_rule(0x8000, 0x800F, FrameAction::Allow, 0)
    .unwrap();

let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
