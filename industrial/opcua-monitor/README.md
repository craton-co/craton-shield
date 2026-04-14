# vs-opcua-monitor

OPC UA security monitor for Craton Shield (IEC 62443).

## Overview

Monitors OPC UA traffic for security violations in industrial control
systems. Designed for SCADA gateways and industrial edge computers.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

**Stack budget:** approximately 2.0 KB per `OpcUaMonitor` instance
(endpoint rule table, session table, rate buckets).

## Features

- **Security mode enforcement** — require `SignAndEncrypt` for all channels (global or per-endpoint)
- **Session/channel tracking** — track active sessions with automatic eviction of stale entries
- **Replay detection** — sequence number validation to detect replayed messages
- **Endpoint allowlist** — restrict which OPC UA endpoints are reachable (prefix-based matching)
- **Message type permissions** — per-endpoint control over which operations (Read, Write, Call, Browse) are allowed
- **Read-only mode** — globally block all Write and Call operations
- **Rate limiting** — per-channel request rate enforcement via token bucket

## Usage

```rust
use vs_opcua_monitor::{OpcUaMonitor, EndpointAction, MessagePermissions, OpcUaInspectResult};
use vs_types_ind::OpcUaSecurityMode;

let mut monitor = OpcUaMonitor::new();
monitor.set_min_security_mode(OpcUaSecurityMode::SignAndEncrypt);

// Add an endpoint rule
monitor.add_rule(
    b"opc.tcp://plc1",
    EndpointAction::Allow,
    MessagePermissions::READ_ONLY,
    OpcUaSecurityMode::SignAndEncrypt,
    100, // max requests/sec
).unwrap();

let result = monitor.inspect(&msg);
if !result.allowed {
    // message was blocked
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
