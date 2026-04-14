# vs-dnp3-monitor

DNP3 intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors DNP3 traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **Function code allowlist** — bitmask-based allowlist for FCs 0-31; FCs >= 32 are always blocked
- **Address validation** — source/destination address filtering with wildcard support
- **Write protection** — block write operations on read-only address rules

## Stack Budget

~500 bytes

## Usage

```rust
use vs_dnp3_monitor::Dnp3Monitor;
use vs_types_ind::Dnp3Frame;

let mut monitor = Dnp3Monitor::new();

// Allow src=1 -> dst=10, FCs 0-3 enabled (mask 0x0F), read-only
monitor.add_address_rule(1, 10, 0x0000_000F, true).unwrap();

// Inspect a frame
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
