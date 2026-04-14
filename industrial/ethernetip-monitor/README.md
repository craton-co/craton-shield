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
- **Fail-closed design** — deny traffic when rate buckets are exhausted

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
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
