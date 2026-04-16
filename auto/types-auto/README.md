# vs-types-auto

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

Automotive-specific types for Craton Shield.

## Overview

Extends the base `vs-types` crate with types specific to the automotive domain.
Re-exports all core types from `vs-types` and adds automotive domain types
for vehicle identification and bus classification.

**Relationship to `vs-types`:** This crate depends on and re-exports everything
from `vs-types` (the core type library shared across all domains). Automotive
crates should depend on `vs-types-auto` instead of `vs-types` directly to get
both the core types and the automotive-specific extensions in a single import.

## Key Types

- `VehicleId` — 17-character Vehicle Identification Number (VIN) with charset validation (excludes I, O, Q)
- `BusType` — automotive bus classification (`Can`, `CanFd`, `AutomotiveEthernet`, `Lin`, `FlexRay`)

## Source Type Constants

- `SOURCE_AUTOMOTIVE_ETHERNET` — Automotive Ethernet (SOME/IP, DoIP)
- `SOURCE_LIN` — LIN bus
- `SOURCE_FLEXRAY` — FlexRay bus

All core source constants (`SOURCE_CAN`, `SOURCE_CAN_FD`, `SOURCE_ETHERNET`) are
re-exported from `vs-types`.

## Usage

```rust
use vs_types_auto::{VehicleId, BusType};

let vin = VehicleId::try_from("1HGBH41JXMN109186")?;
println!("VIN: {vin}");

let source = BusType::CanFd.to_source_type();
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
