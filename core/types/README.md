# vs-types

Core types, error enums, and vehicle identity for Craton Shield.

## Overview

This crate defines the foundational types shared across all Craton Shield crates.
It provides the unified error type, alert severity levels, security alert
representation, vehicle identification, and bus type enums. Everything is
`#![no_std]` and `#[repr(C)]` where needed for FFI compatibility.

## Key Types

- `VsError` — unified error enum used across all crates (crypto, bus, policy, integrity, etc.)
- `AlertSeverity` — five-level severity classification (Info through Critical)
- `SecurityAlert` — a security event with id, severity, source, payload hash, and timestamp
- `PayloadHash` — newtype wrapper for SHA-256 hashes (`[u8; 32]`)
- `KeyId` — newtype wrapper for cryptographic key slot identifiers (`u32`)
- `VehicleId` — 17-character VIN with ISO 3779 validation (excludes I, O, Q)
- `BusType` — vehicle communication bus variants (CAN, CAN-FD, Automotive Ethernet, LIN, FlexRay)
- `IpAddr` / `IpProtocol` / `IpHeader` / `TransportHeader` — L3/L4 network types
- `TcpState` — stateful TCP connection tracking with `advance()` state machine

## Usage

```rust
use vs_types::{VehicleId, VsError, SecurityAlert, AlertSeverity, PayloadHash, SOURCE_CAN};

// Validate a VIN
let vin = VehicleId::new(b"WBA3A5C55CF256789").unwrap();
assert_eq!(vin.vin.len(), 17);

// Create a security alert (rejects zero timestamps)
let alert = SecurityAlert::new(
    1,
    AlertSeverity::High,
    SOURCE_CAN,
    42,
    PayloadHash([0xAB; 32]),
    1_000_000,
).unwrap();
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
