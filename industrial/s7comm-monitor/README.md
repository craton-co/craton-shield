# vs-s7comm-monitor

Siemens S7comm / S7comm-plus intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors S7comm traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **Variant awareness** -- classic S7comm (`0x32`) and S7comm-plus (`0x72`)
  are parsed and policed as distinct dialects.  A TCP connection is pinned
  to the first variant it presents; later frames whose variant differs are
  blocked as a high-severity MITM indicator.
- **Connection-keyed PDU-reference replay defense** -- per-`connection_id`
  session table with an 8-slot `(pdu_ref, timestamp)` ring.  Duplicates
  within the configurable replay window are blocked at `High` severity.
- **SF 0x29 (Security) session-type restriction** -- per-rule allowlist of
  session types (`PG` / `HMI` / `OP`) in which the `Security` function
  group may be issued.  Defaults to PG-only.
- **PDU-type allowlist** -- restrict allowed PDU types (JobRequest, AckData, UserData)
- **Function code filtering** -- per-rule bitmask of allowed S7comm function codes with wildcard support
- **Write protection** -- block write operations (WriteVar, RequestDownload, DownloadBlock, DownloadEnded, PlcControl, Security)
- **SZL filtering** -- block UserData PDU type to prevent device capability enumeration
- **Rate limiting** -- per-function-code token bucket with LRU eviction
- **PDU-reference replay defense** -- alert (High severity), block the frame when the same `pdu_ref` is seen twice within a 5 s window on JobRequest traffic on the same connection

## Layer assumptions

The monitor assumes COTP **class 0** (TPKT/ISO 8073 over TCP/102), which is
the only class used by S7 communication in practice. Frames in other COTP
classes must be rejected by the parser layer before being passed to
`inspect`.

The PDU-reference replay defense is **connection-keyed**: each TCP
connection (`connection_id`) gets its own per-session ring of recently
observed `(pdu_ref, timestamp)` values.  A duplicate `pdu_ref` observed
within the configured replay window on the same connection raises a
High-severity alert and blocks the frame.  Replay across distinct
connections is not flagged, because `pdu_ref` is legitimately per-session.

## Stack Budget

~3.5 KiB

## Usage

```rust
use vs_s7comm_monitor::{
    S7commMonitor, S7commFrame, S7commPduType, S7commFunction,
    S7CommVariant, S7SessionType,
};

let mut monitor = S7commMonitor::new_strict();

// Allow ReadVar (raw 0x04), fc_mask = any, read-only, do not block SZL,
// max 50 req/sec.
monitor.add_rule(0x04, 0xFFFF_FFFF, true, false, 50).unwrap();

let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
