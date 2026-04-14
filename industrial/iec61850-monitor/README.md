# vs-iec61850-monitor

IEC 61850 MMS / GOOSE intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors IEC 61850 traffic (MMS and GOOSE protocols) for security anomalies
in substation automation systems. Designed for IEDs, gateways, and
merging units.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

### MMS (Manufacturing Message Specification)

- **Service-type allowlist** -- bitmask filter for MMS confirmed service types
- **Write protection** -- block Write, Define/Delete operations
- **Rate limiting** -- per-invoke-ID token buckets

### GOOSE (Generic Object Oriented Substation Event)

- **Publisher allowlist** -- restrict allowed (src_mac, GoCBRef) pairs
- **Replay detection** -- stNum/sqNum tracking
- **Test-flag blocking** -- optionally block test frames

## Stack Budget

~600 bytes

## Usage

```rust
use vs_iec61850_monitor::{Iec61850Monitor, MmsFrame, MmsServiceType, GooseFrame};

let mut monitor = Iec61850Monitor::new_strict();

// Configure MMS: read-only, allow Read and GetNameList
let mask = (1u16 << MmsServiceType::Read as u8) | (1u16 << MmsServiceType::GetNameList as u8);
monitor.set_mms_service_mask(mask);
monitor.set_mms_read_only(true);

// Configure GOOSE: allow a specific publisher
monitor.add_goose_publisher([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None).unwrap();

let result = monitor.inspect_mms(&mms_frame);
let result = monitor.inspect_goose(&goose_frame);
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
