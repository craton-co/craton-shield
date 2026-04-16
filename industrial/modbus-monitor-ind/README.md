# vs-modbus-monitor-ind

Modbus RTU/TCP intrusion detection for industrial OT/ICS environments.

## Overview

`no_std`, no-heap Modbus monitor for the Craton Shield Industrial workspace.
Inspects Modbus TCP (MBAP + PDU) and Modbus RTU (PDU + CRC16) frames against
a fixed-size policy and returns a structured `Verdict` plus an
`InspectResult` carrying any alerts.

State is stack-allocated; rules live in a fixed-size array sized by
[`MAX_RULES`].

## Detection Mechanisms (0.7.0)

| Mechanism | Description | Default |
|:---|:---|:---|
| MBAP validation | `protocol_id == 0`; MBAP length consistent with the framed PDU. | Enabled |
| Function-code allowlist | 128-bit mask; presets `FC_PROFILE_READ_ONLY`, `FC_PROFILE_SAFETY`, `FC_PROFILE_PERMISSIVE`. | Permissive |
| Address-range rules | Up to `MAX_RULES` (= 16) per-FC allow/deny windows; the full request span is validated. | None |
| Diagnostics sub-function blocking | Optionally blocks FC 0x08 `RestartCommunications` / `ForceListenOnly` / `ClearCounters`. | Disabled |
| CRC-16/Modbus (RTU) | Table-driven CRC validation when `frame.crc_provided`. | Enabled when provided |
| Exception responses | Surfaced as `Suspicious` (allow-through, low-severity alert). | Enabled |

## Quick Start

```rust
use vs_modbus_monitor_ind::{
    AddressRule, ModbusMonitor, RuleAction, Verdict, FC_PROFILE_READ_ONLY,
};

let mut monitor = ModbusMonitor::new();
monitor.set_function_code_allowlist(FC_PROFILE_READ_ONLY);
monitor.allow_function_code(0x06);            // permit single-register writes
monitor.set_block_dangerous_diagnostics(true);

monitor.add_address_rule(AddressRule {
    function_code: 0x06,
    start: 0x1000,
    end: 0x10FF,
    action: RuleAction::Deny,
}).unwrap();

// Parse and inspect a raw MBAP+PDU buffer:
let bytes = [
    0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
    0x11, 0x03, 0x00, 0x10, 0x00, 0x04,
];
let frame = ModbusMonitor::parse_tcp(&bytes, 0).expect("valid MBAP");
let (verdict, _result) = monitor.inspect_tcp(&frame);
assert_eq!(verdict, Verdict::Allow);
```

The verdict is one of `Allow`, `Suspicious { reason }`, or
`Deny { reason }`. `reason` is an `AlertCode` from `vs-types-ind`.

## Alert Codes Emitted

| `AlertCode` | Source |
|:---|:---|
| `InvalidProtocol` | MBAP `protocol_id != 0`. |
| `PayloadOverflow` | PDU truncated, zero-length, or larger than `MAX_MODBUS_PDU_LEN`. |
| `UnknownFunctionCode` | FC is `0`, exception-bit set on a request, or not in the allowlist. |
| `DiagnosticBlocked` | FC 0x08 sub-function in the dangerous set. |
| `PolicyViolation` | Address-range rule violated; exception response surfaced as `Suspicious`. |
| `CrcFailure` | RTU CRC-16 mismatch. |

## Limits (0.7.0)

- `MAX_RULES = 16` address-range rules. Adding more returns `VsError::ResourceExhausted`.
- `start > end` in an `AddressRule` returns `VsError::InvalidInput`.

## Limitations

The following IDS controls are **not** implemented in 0.7.0 and are
deferred to 0.8.0 (see the workspace ROADMAP):

- No per-unit-id allowlist (broadcast/reserved unit ids are not auto-rejected).
- No source-IP allowlist / `inspect_tcp_with_ip` API.
- No per-source rate limiting.
- No exception-flood / repeated-failure detector.
- No transaction-id replay tracking.
- No timestamp-regression tracker.

Until those land, deploy the monitor behind a separate L3/L4 ACL and use
the existing function-code and address-range rules for application-layer
filtering.

## Errors

- `VsError::ResourceExhausted` — `MAX_RULES` already configured.
- `VsError::InvalidInput` — `AddressRule { start, end }` has `start > end`.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
