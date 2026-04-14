# vs-bacnet-monitor

BACnet intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors BACnet traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **Service choice allowlist** — per-rule allowlist of permitted BACnet service choices with wildcard support
- **Write/dangerous operation protection** — block writeProperty, writePropertyMultiple, createObject, deleteObject, and reinitializeDevice services
- **Read-only enforcement** — restrict rules to read-only operations

## Stack Budget

~300 bytes

## Usage

```rust
use vs_bacnet_monitor::BacnetMonitor;
use vs_types_ind::BacnetFrame;

let mut monitor = BacnetMonitor::new();

// Allow service choice 12 (ReadProperty), read-only
monitor.add_service_rule(12, true).unwrap();

// Inspect a frame
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
