# vs-runtime-auto

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

Automotive runtime extending Craton Shield with signal IDS, V2X, and UDS diagnostics.

## Overview

Orchestrates all automotive security modules into a unified runtime. Extends the
base `CratonShield` runtime with automotive-specific initialization, tick processing,
and health monitoring for signal-level IDS, V2X communication security, and UDS
diagnostic gateway protection.

## Key Types

- `AutomotiveShield<C>` — main automotive runtime wrapping `CratonShield` with automotive subsystems
- `AutomotiveConfig` — automotive-specific platform configuration (session timeout, lockout duration)
- `AutomotiveHealth` — extended health snapshot including signal IDS, V2X, and diagnostics status

## Features

- `capacity-large` — increases internal buffer sizes (forwarded to `vs-runtime`)
- `capacity-xl` — further increases internal buffer sizes (forwarded to `vs-runtime`)
- `heap-subsystems` — allocates subsystems (`SignalIdsEngine`, `V2xValidator`, `DiagGateway`)
  on the heap via `Box` instead of inline in `AutomotiveShield`. Requires `std`. Use this on
  Linux/QNX gateway ECUs to avoid the large default stack usage of `AutomotiveShield`
  (which requires 8 MiB stack threads on `no_std` targets).

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## Usage

```rust
use vs_runtime_auto::{AutomotiveShield, AutomotiveConfig};

let config = AutomotiveConfig::default();
let mut shield = AutomotiveShield::init(config, crypto)?;

// Periodic tick
shield.tick(timestamp_us)?;

// Submit CAN frames for IDS inspection (core + signal-level)
shield.submit_can_frame(&frame, timestamp_us)?;

// Check health
let health = shield.health_status();

// Access subsystems directly
let signal_ids = shield.signal_ids_mut();
let diag = shield.diag_gateway_mut();
let v2x = shield.v2x_validator_mut();
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
