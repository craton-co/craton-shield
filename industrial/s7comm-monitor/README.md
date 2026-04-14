# vs-s7comm-monitor

Siemens S7comm / S7comm-plus intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors S7comm traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **PDU-type allowlist** -- restrict allowed PDU types (JobRequest, AckData, UserData)
- **Function code filtering** -- per-rule bitmask of allowed S7comm function codes with wildcard support
- **Write protection** -- block write operations (WriteVar, RequestDownload, DownloadBlock, DownloadEnded, PlcControl, PlcStop)
- **SZL filtering** -- block UserData PDU type to prevent device capability enumeration
- **Rate limiting** -- per-function-code token bucket with LRU eviction

## Stack Budget

~500 bytes

## Usage

```rust
use vs_s7comm_monitor::{S7commMonitor, S7commFrame, S7commPduType, S7commFunction};

let mut monitor = S7commMonitor::new_strict();

// Allow ReadVar, read-only, max 50 req/sec
monitor.add_rule(0x04, true, false, 50).unwrap();

let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
