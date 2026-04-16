# vs-iec60870-monitor

IEC 60870-5-104 telecontrol intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors IEC 60870-5-104 traffic for security anomalies in SCADA and
telecontrol systems. Designed for RTUs, gateways, and control centres.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **TypeID allowlist** -- 256-bit bitmask restricting permitted ASDU type identifiers
- **COT filtering** -- Cause of Transmission filtering rejects frames with unexpected COT values
- **Write protection** -- block command TypeIDs (45--51, 58--64) when rule is read-only
- **I-frame sequence tracking** -- forward-progress window detects replays and large gaps
- **Rate limiting** -- per-TypeID token bucket with LRU eviction

## Stack Budget

~2-3 KiB for the `Iec60870Monitor` itself (16 ASDU rules, 16 sequence-tracking
entries, 16 rate-limit buckets, plus the 256-bit TypeID allowlist and COT
filter bitmasks). No heap allocation.

## Usage

```rust
use vs_iec60870_monitor::{Iec60870Monitor, Iec60870Frame, Iec60870FrameFormat, Iec60870Cot};

let mut monitor = Iec60870Monitor::new_strict();
monitor.add_rule(1, true, 20).unwrap(); // ASDU addr 1, read-only, 20 req/s
// TypeID allowlist: `low` covers TypeIDs 0..=127, `high` covers 128..=255.
// Bit N of `low` = TypeID N allowed; here we permit only M_SP_NA_1 (TypeID 1).
monitor.set_type_id_allowlist(1u128 << 1, 0);

let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
