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

- `VehicleId` — re-exported from `vs-types`; the 17-character Vehicle
  Identification Number (VIN) with charset validation (excludes I, O, Q). This
  crate deliberately does **not** define its own `VehicleId`: re-introducing one
  would shadow the PII-redacting core type. Its `Display`/`Debug` impls redact
  the vehicle-unique suffix of the VIN.
- `BusType` — automotive bus classification (`Can`, `CanFd`,
  `AutomotiveEthernet`, `Lin`, `FlexRay`)

## VIN Helpers

This crate's main value-add is a pair of free functions that operate on the
core PII-redacting `vs_types::VehicleId`:

- `try_from_normalized(&str)` — parse a VIN from a (possibly lower/mixed-case)
  string, normalizing to uppercase and validating the ISO 3779 check digit.
- `validate_check_digit(&VehicleId)` — validate the ISO 3779 check digit at
  position 9 of an already-constructed VIN.

## Source Type Constants

- `SOURCE_AUTOMOTIVE_ETHERNET` — Automotive Ethernet (SOME/IP, DoIP); an alias
  of the core `SOURCE_ETHERNET`.

The bus source constants `SOURCE_CAN`, `SOURCE_CAN_FD`, `SOURCE_ETHERNET`,
`SOURCE_LIN`, and `SOURCE_FLEXRAY` are all re-exported unchanged from
`vs-types`, which is the single source of truth for their values. This crate
does not redefine them.

## Usage

```rust
use vs_types_auto::{try_from_normalized, BusType};

let vin = try_from_normalized("1hgbh41jxmn109186").unwrap();
// `Display` is PII-redacted — only the WMI prefix is shown, never the
// full VIN. Use `VehicleId::as_str_unredacted()` for audited access.
println!("VIN: {vin}");

let source = BusType::CanFd.to_source_type();
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
