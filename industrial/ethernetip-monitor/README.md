# vs-ethernetip-monitor

EtherNet/IP intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors EtherNet/IP traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **Session handle tracking** — track and validate EtherNet/IP session handles
- **Command allowlist** — per-session allowlist of permitted EtherNet/IP commands
- **Rate limiting** — per-session request rate enforcement via token bucket
- **CIP service filter** — allowlist by CIP Message Router service code
- **LRU eviction** — when the rate-limit table is full, the oldest bucket is
  evicted and the new key is admitted. Use `EtherNetIpMonitor::new_strict()`
  for fail-closed semantics (unknown sessions / unmatched commands are denied).

## Stack Budget

~700 bytes

## Usage

```rust
use vs_ethernetip_monitor::EtherNetIpMonitor;
use vs_types_ind::EtherNetIpFrame;

let mut monitor = EtherNetIpMonitor::new();

// Allow command 0x0004 (ListServices) at max 10 req/s
monitor.add_command_rule(0x0004, 10).unwrap();

// Inspect a frame
let frame = EtherNetIpFrame::default();
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

### CIP service allowlist

`set_cip_service_filter` enables a bitmask filter over the embedded CIP
Message Router service code parsed from `SendRRData` (0x006F) and
`SendUnitData` (0x0070) commands. Each bit `N` of the `u128` mask
allows CIP service code `N` (0–127). Passing `0` disables filtering.

```rust
use vs_ethernetip_monitor::EtherNetIpMonitor;

let mut monitor = EtherNetIpMonitor::new();
monitor.add_command_rule(0x006F, 0).unwrap(); // permit SendRRData

// Allow only Get_Attribute_Single (0x0E) and Read_Tag (0x4C).
let mask = (1u128 << 0x0E) | (1u128 << 0x4C);
monitor.set_cip_service_filter(mask);

// Any SendRRData / SendUnitData frame carrying a CIP service other than
// 0x0E or 0x4C is now blocked with AlertCode::CipServiceBlocked.
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
