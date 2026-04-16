# vs-health

Shared subsystem health tracking for Craton Shield runtimes.

## Overview

This `no_std`, heap-free crate centralizes the per-subsystem health bookkeeping
used by the Craton Shield runtime crates. It fixes a small family of bugs
previously found in hand-rolled per-runtime trackers: `ts_us == 0` auto-recovery
deadlocks, shutdown paths that left `degraded_since_us` populated, and
health-attribution drift between status fields and the alert log. All status
mutation flows through a single `with_subsystem_alert` entry point that pairs
status changes with a clamped (non-zero) alert timestamp and a dirty bit.

## Quick Start

```rust
use vs_health::{HealthRegistry, SubsystemId};
use vs_types::AlertSeverity;

let mut registry = HealthRegistry::new();
registry.mark_initialized(SubsystemId::Can);

registry.with_subsystem_alert(
    SubsystemId::Can,
    1_000, // ts_us (monotonic microseconds)
    AlertSeverity::Medium,
    |handle| {
        handle.mark_degraded();
    },
);

assert!(registry.is_dirty());
```

## SubsystemId Variants

`Can`, `Eth`, `V2x`, `Diag`, `SignalIds`, `Mqtt`, `CoAp`, `Ble`, `Zigbee`,
`LoRa`, `ModbusEmb`, `ModbusInd`, `OpcUa`, `Profinet`, `EthernetIp`, `Dnp3`,
`BacNet`, `S7Comm`, `Iec60870`, `Iec61850`, `Mms`, `Goose`.

`SubsystemId::COUNT` and `SubsystemId::ALL` are exposed for fixed-size lookup
tables; the enum is `#[non_exhaustive]`.

## License

Apache-2.0. See [LICENSE](../../LICENSE). For workspace overview see
[../../README.md](../../README.md).
