# vs-types-ind

Industrial automation type extensions for Craton Shield (IEC 62443).

## Overview

Extends the base `vs-types` crate with types specific to industrial control
systems and operational technology.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

**Stack budget:** types only — no runtime state. Frame types are
`#[derive(Copy)]` with fixed-size payload buffers (256–292 bytes per
frame, see per-protocol `MAX_*_PAYLOAD_LEN` constants).

## Key Types

- `ModbusTcpFrame` / `ModbusRtuFrame` — Modbus protocol frames with function code, register address, and PDU data
- `ModbusFunctionCode` — Parsed Modbus function codes with `is_write()` / `is_diagnostic()` helpers
- `OpcUaMessage` — OPC UA message with security mode, channel ID, sequence number, and endpoint
- `OpcUaMessageType` / `OpcUaSecurityMode` — OPC UA enumerations
- `ProfinetFrame` — PROFINET IO frame with frame type, cycle counter, and data status
- `ProfinetFrameType` — PROFINET frame type enumeration (CyclicRT, AcyclicRT, DCP, Alarm)
- `Zone` / `Conduit` — IEC 62443 zone/conduit model with security level tracking
- `SecurityLevel` — IEC 62443 security levels (SL 0–4)
- Source-type constants (`SOURCE_MODBUS_RTU`, `SOURCE_OPCUA`, `SOURCE_PROFINET`, etc.)
- Protocol bitmask flags (`PROTO_MODBUS_TCP`, `PROTO_OPCUA`, `PROTO_PROFINET`, etc.)

## Usage

```rust
use vs_types_ind::{ModbusTcpFrame, ModbusFunctionCode, SecurityLevel, Zone};

let frame = ModbusTcpFrame::default();
assert!(!frame.function_code.is_write());

let mut zone = Zone::empty();
zone.target_sl = SecurityLevel::Sl3;
zone.achieved_sl = SecurityLevel::Sl3;
assert!(zone.meets_target());
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
