# vs-runtime-ind

Industrial runtime extending Craton Shield with Modbus, OPC UA, and PROFINET monitors.

## Overview

Composes all industrial security monitors into a single `IndustrialShield` runtime
that wraps the base `CratonShield` from `vs-runtime`. Alerts from protocol monitors
are automatically routed to the core event log.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

**Stack budget:** approximately 10 KB per `IndustrialShield` instance
(sum of all embedded monitors plus zone/conduit tables and the recent
alerts ring buffer). Actual size depends on `capacity-large` /
`capacity-xl` feature flags forwarded to `vs-runtime`.

## Features

- Integrates `vs-modbus-monitor`, `vs-opcua-monitor`, and `vs-profinet-monitor`
- Alerts from all monitors routed to the core event log
- Health status reporting across all subsystems
- Zone and conduit management with `remove_zone()` and `remove_conduit()`
- Recent alerts buffer via `recent_alerts()`, `clear_recent_alerts()`, and `recent_alerts_dropped()`
- `reset_health()` returns `Result<(), VsError>` for explicit error handling
- Configurable capacity via feature flags: `capacity-large`, `capacity-xl`
- Full access to individual monitors for configuration

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## Usage

```rust
use vs_runtime_ind::IndustrialShield;
use vs_runtime_ind::vs_runtime::PlatformConfig;

// Initialize with your CryptoProvider implementation.
let config = PlatformConfig::default();
let mut shield = IndustrialShield::init(config, my_crypto).unwrap();

// Periodic tick
shield.tick(timestamp_us).unwrap();

// Submit protocol traffic
let result = shield.submit_modbus_tcp(&frame, timestamp_us);
let result = shield.submit_opcua_message(&msg, timestamp_us);
let result = shield.submit_profinet_frame(&pn_frame, timestamp_us);

// Configure individual monitors
shield.modbus_monitor_mut().add_unit_rule(/* ... */).unwrap();
shield.profinet_monitor_mut().set_block_dcp(true);

// Zone / conduit management
shield.add_zone(1, vs_runtime_ind::SecurityLevel::Sl3).unwrap();
shield.set_zone_achieved_sl(1, vs_runtime_ind::SecurityLevel::Sl2).unwrap();

// Remove a zone (cascades to conduits)
shield.remove_zone(1)?;

// Remove a specific conduit
shield.remove_conduit(0)?;

// Read and clear recent alerts
for alert in shield.recent_alerts() {
    // process alert...
}
shield.clear_recent_alerts();

// Health check and recovery (returns Result)
let health = shield.health_status();
shield.reset_health(vs_runtime_ind::vs_types_ind::SOURCE_MODBUS_TCP)?;
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
