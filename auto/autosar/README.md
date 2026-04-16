# vs-autosar

> Part of [Craton Shield](../../README.md) | [Architecture](../../core/docs/architecture.md)

Craton Shield AUTOSAR Classic/Adaptive platform integration.

## Overview

This crate provides adapters for integrating Craton Shield with AUTOSAR
platforms. It includes SecOC (Secure Onboard Communication) for MAC-based
CAN frame authentication, an IdsM reporter for mapping security alerts to
the AUTOSAR IDS Manager interface, MCAL driver adapter traits, and
Ara::com service discovery types for SOME/IP instance registration.

## Key Types

- `SecOcManager<C>` — manages SecOC PDU verification and MAC generation with freshness tracking
- `SecOcPduConfig` — per-PDU configuration (CAN ID, key slot, MAC/freshness lengths, direction)
- `SecOcVerifyResult` — verification outcome (`Pass`, `MacMismatch`, `FreshnessExpired`, etc.)
- `SecOcDirection` — PDU direction (`Tx` or `Rx`)
- `SecOcCrypto` — trait for the cryptographic backend used by SecOC
- `IdsmReporter` — maps `SecurityAlert` events to AUTOSAR IdsM security events
- `IdsmSecurityEvent` — AUTOSAR-compatible security event representation
- `McalCanAdapter<D>` — bridges Craton Shield `CanBus` trait to MCAL CAN drivers
- `McalEthAdapter<D>` — bridges Craton Shield `EthernetPhy` trait to MCAL Ethernet drivers
- `ServiceRegistry` — Ara::com SOME/IP service instance registry
- `DemManager` — Diagnostic Event Manager with debounce/healing logic
- `BswModeManager` — BSW mode transition management with rule-based gating
- `ComMManager` — Communication channel mode management

## Usage

```rust
use vs_autosar::{SecOcManager, SecOcPduConfig, SecOcDirection, IdsmReporter};

// SecOC: Secure Onboard Communication with MAC verification
let mut secoc = SecOcManager::new(my_crypto, 100_000 /* max freshness age us */);
// Note: `SecOcPduConfig::active` is set by `register_pdu` itself and is
// ignored on input — the field exists only so the same struct can be
// returned from accessors. Leave it at its `Default` value here.
secoc.register_pdu(SecOcPduConfig {
    can_id: 0x100, key_id: 1, data_id: 0x0100, mac_len: 4,
    freshness_len: 4, direction: SecOcDirection::Rx, active: false,
})?;
let result = secoc.verify_rx(&frame, now_us);

// IdsM: forward security alerts to the AUTOSAR IDS Manager
let mut idsm = IdsmReporter::new();
idsm.report_alert(&alert)?;
while let Some(event) = idsm.dequeue() {
    // forward event to AUTOSAR IdsM interface
}
```

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
