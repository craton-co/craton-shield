# vs-ffi

> **Warning — C ABI crate.** This crate exposes a stable C ABI. Cargo's
> semver only covers the Rust API. The C ABI is tracked **separately** via
> the packed `VS_ABI_VERSION` constant (see [`cratonshield.h`](../include/cratonshield.h)
> and [`ABI.md`](../../ABI.md) at the workspace root). A patch-level Rust
> release MAY bump `VS_ABI_VERSION` (e.g. fixing a field-layout bug);
> downstream C consumers MUST query `vs_abi_version()` at init and
> refuse to dispatch on a major-version mismatch.

C-compatible FFI bindings for Craton Shield platform integration.

## Overview

This crate exposes a C-compatible API for integrating the Craton Shield
runtime into non-Rust environments. It provides functions for platform
initialization, periodic tick processing, CAN frame and Ethernet packet
submission, health queries, and shutdown. All functions use panic-catching
wrappers and return C-compatible result codes.

## Key Functions

- `vs_platform_init` — initialize the Craton Shield runtime
- `vs_platform_tick` — advance the runtime clock and process pending events
- `vs_submit_can_frame` — submit a CAN frame for intrusion detection
- `vs_submit_eth_packet` — submit an Ethernet packet for inspection
- `vs_get_health` — query platform subsystem health status
- `vs_platform_shutdown` — shut down the runtime and release resources

## Usage

```c
#include "cratonshield.h"

VsResult rc = vs_platform_init();
if (rc != VS_OK) { /* handle error */ }

vs_platform_tick(timestamp_us);
vs_submit_can_frame(&frame);

VsHealth health;
vs_get_health(&health);

vs_platform_shutdown();
```

## Feature Flags

| Feature      | Default | Description |
|--------------|---------|-------------|
| `production` | off     | Excludes the stub `CryptoProvider`; required for release builds. A real `CryptoProvider` must be wired in or the crate fails to compile. |
| `mock-hsm`   | off     | Enables the mock HSM for non-production builds. Mutually exclusive with `production`. |
| `pqc`        | off     | Enables the real ML-KEM-768 / ML-DSA-65 post-quantum C ABI functions (`vs_pq_*`). |

The default feature set is empty; select `mock-hsm` (development) or
`production` (release) explicitly.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
