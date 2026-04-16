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
- **Object-level access control** — per-object read/write and full-deny rules matched against the `BACnetObjectIdentifier` parsed from `readProperty` / `writeProperty` / `writePropertyMultiple` APDU payloads
- **BVLC foreign-device abuse detection** — flag `REGISTER_FOREIGN_DEVICE` and `FORWARDED_NPDU` BVLC functions from sources outside the operator-supplied allowlist
- **NPDU forwarding-loop detection** — drop routed NPDUs whose hop count reaches zero with a non-local destination network number
- **Broadcast amplification rate limiting** — per-source token-bucket rate limit on broadcast NPDUs (Who-Is, I-Am, Who-Has, Time-Sync, ...)

## Stack Budget

~700 bytes

## Usage

```rust
use vs_bacnet_monitor::BacnetMonitor;
use vs_types_ind::BacnetFrame;

let mut monitor = BacnetMonitor::new();

// Allow service choice 12 (ReadProperty), read-only, no rate limit (0 = unlimited).
// Signature: add_service_rule(service_choice: u8, read_only: bool, max_rate_per_sec: u16)
monitor.add_service_rule(12, true, 0).unwrap();

// Inspect a frame
let frame = BacnetFrame::default();
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
