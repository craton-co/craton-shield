# vs-ffi

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

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
