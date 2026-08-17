# vs-runtime-auto

> Part of the [Craton Shield workspace](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

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
- `heap-subsystems` — heap-allocates the `V2xValidator` and `DiagGateway` subsystems
  via `Box` instead of storing them inline in `AutomotiveShield` (the `SignalIdsEngine`
  remains inline). Requires `std`. Use this on Linux/QNX gateway ECUs to avoid the large
  default stack usage of `AutomotiveShield`.
- `mix-shift-xor` — uses shift-XOR alert-ID mixing instead of 64-bit multiplications,
  for targets without a hardware multiply (e.g. Cortex-M0/M0+).
- `pq` — pulls in the post-quantum crypto stack (ML-KEM-768 + ML-DSA-65) via
  `vs-crypto/pq` and `vs-runtime/pq`.
- `stub` — build-only convenience feature for stub/test configurations.

> Note: The crate's `cargo test` suite spawns helper threads with an 8 MiB stack to
> accommodate `AutomotiveShield`'s inline subsystems on the test runner; this is a
> test-harness convenience, **not** a runtime requirement. The runtime itself uses
> well under a kilobyte of stack per `tick`/`submit_*` call (subsystem state lives
> in the `AutomotiveShield` value, which callers typically place in a `static` or
> on a dedicated task stack).

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## Usage

```rust,ignore
use vs_runtime_auto::{AutomotiveShield, AutomotiveConfig};

fn run<C: vs_crypto::CryptoProvider + Clone>(
    crypto: C,
    timestamp_us: u64,
    frame: &vs_runtime::CanFrame,
) -> Result<(), vs_types::VsError> {
    let config = AutomotiveConfig::default();
    let mut shield = AutomotiveShield::init(config, crypto)?;

    // Periodic tick
    shield.tick(timestamp_us)?;

    // Submit CAN frames for IDS inspection (core + signal-level)
    shield.submit_can_frame(frame, timestamp_us)?;

    // Check health
    let _health = shield.health_status();

    // Access subsystems directly
    let _signal_ids = shield.signal_ids_mut();
    let _diag = shield.diag_gateway_mut();
    let _v2x = shield.v2x_validator_mut();
    Ok(())
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
