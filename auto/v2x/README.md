# vs-v2x

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

Craton Shield V2X communication security: validation helpers for
IEEE 1609.2 / ETSI TS 103 097 message-flavoured payloads.

## Overview

This crate provides a policy validator for Vehicle-to-Everything (V2X)
messages in the style of IEEE 1609.2. The validator enforces a fail-closed
policy, rejecting messages unless they pass ECDSA P-256 signature
verification, replay detection via generation-time windows, and kinematic
plausibility checks (speed, position bounds).

## Scope and limitations

This crate implements a **subset** of IEEE 1609.2-2022 §5–6 SPDU validation.
The standards are referenced for context; this is **not** a conformant
implementation of either IEEE 1609.2 or ETSI TS 103 097. The following
gaps are intentional and should be understood before deployment:

- **No ASN.1 OER decoder.** Callers must supply already-parsed
  `V2xMessage` and `V2xCertificate` structs. Wire-format decoding from
  `Ieee1609Dot2Data` / `EtsiTs103097Data` byte streams is out of scope
  and must be performed by an upstream component.
- **Custom certificate TBS digest format.** The to-be-signed bytes
  hashed for certificate signature verification are a fixed-layout
  craton-shield encoding (little-endian, 119 bytes), **not** canonical
  IEEE/ETSI OER. As a result, certificates issued by, and signatures
  produced for, production SCMS PKIs (CAMP SCMS, ETSI C-ITS Trust List,
  etc.) **will not interoperate** with this crate. The signature
  primitives (ECDSA P-256 over SHA-256) are standard; only the TBS
  serialization is custom.
- **No SCMS lifecycle.** Pseudonym certificate rotation, butterfly-key
  expansion, linkage values, and the Enrollment/Authorization CA split
  from IEEE 1609.2.1 / SCMS are **not** implemented. Certificates are
  treated as opaque long-term identities.
- **Fixed-size replay window.** Replay detection uses a power-of-two
  LRU ring buffer with a bloom-filter fast path. An adversary capable
  of injecting signatures from a large number of distinct signers can
  evict legitimate digests; the validator fails closed once the
  eviction count exceeds `max_eviction_threshold`. The default sizing
  targets roughly 64 simultaneous signers at typical 10 Hz BSM rates
  and is not appropriate for high-cardinality fleets without
  reconfiguration.

Treat the public API here as a *policy validator* over pre-decoded V2X
structures rather than a drop-in 1609.2 stack.

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
