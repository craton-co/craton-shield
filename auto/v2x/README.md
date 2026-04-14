# vs-v2x

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

Craton Shield V2X communication security with IEEE 1609.2 validation.

## Overview

This crate validates Vehicle-to-Everything (V2X) messages per IEEE 1609.2.
The validator enforces a fail-closed policy, rejecting messages unless they
pass ECDSA P-256 signature verification, replay detection via generation-time
windows, and kinematic plausibility checks (speed, position bounds).

## Key Types

- `V2xValidator<C>` — validates V2X signed protocol data units (SPDUs)
- `V2xMessage` — incoming SPDU with signature, signer public key, and payload
- `V2xPayload` — BSM-like payload with latitude, longitude, speed, and heading
- `ValidatedV2xMessage` — type-safe wrapper guaranteeing validation has passed
- `PlausibilityLimits` — configurable bounds for speed and position plausibility checks
- `TrustStore` — certificate chain verification for root CA trust anchors
- `CertificateRevocationList` — revoked signer tracking
- `PsidPolicy` — PSID-based service-level message filtering
- `GeoRegion` — geographic region constraint (`Global`, `Circle`, `Rectangle`)
- `MisbehaviorDetector` — tracks sender rate limiting and impossible-acceleration detection

## Feature Flags

- **`stub`** — Replaces validation with a permissive stub that accepts all messages.
  A compile-time error prevents this feature from being enabled in release builds.

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## Usage

```rust
use vs_v2x::{V2xValidator, PlausibilityLimits};

// Default plausibility limits (250 km/h max speed, 5 s max age)
let mut validator = V2xValidator::new(crypto);

// Or with custom limits
let mut validator = V2xValidator::with_limits(crypto, PlausibilityLimits {
    max_speed_cm_s: 20_000, // 200 km/h
    ..PlausibilityLimits::default()
});

match validator.validate(&message, now_us) {
    Ok(validated) => { /* forward validated.payload() to application */ }
    Err(e) => { /* log rejection */ }
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
