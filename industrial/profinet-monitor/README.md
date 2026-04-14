# vs-profinet-monitor

PROFINET IO intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors PROFINET real-time traffic for anomalies in industrial control
systems. Designed for industrial communication processors and PROFINET
controllers.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

**Stack budget:** approximately 1.5 KB per `ProfinetMonitor` instance
(frame ID rules, cycle state table, alarm-flood window, rate buckets).

## Features

- **Frame ID filtering** — allowlist/blocklist of permitted RT frame IDs (single or range)
- **DCP blocking** — block unauthorized Discovery and Configuration Protocol messages (enabled by default)
- **Cycle counter validation** — detect missed or replayed cyclic RT frames
- **Provider state monitoring** — alert on provider Run-to-Stop transitions
- **Alarm flood detection** — rate-based detection of alarm frame floods
- **Strict mode** — block all unknown frame IDs by default

## Usage

```rust
use vs_profinet_monitor::{ProfinetMonitor, FrameAction};

let mut monitor = ProfinetMonitor::new_strict();

// Allow specific frame ID range
monitor.add_frame_range_rule(0x8000, 0x800F, FrameAction::Allow).unwrap();

let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
