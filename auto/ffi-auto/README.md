# vs-ffi-auto

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

Automotive C-compatible FFI bindings for Craton Shield.

## Overview

Provides a stable C ABI for integrating Craton Shield automotive modules into
existing ECU software written in C/C++. Designed for ISO 26262 compliant
integration with legacy automotive toolchains.

**Note:** This crate requires `std` (for `Mutex`, `catch_unwind`, and monotonic
timestamps). It targets Linux/QNX gateway ECUs, not bare-metal Cortex-M.

## Features

- C-compatible function exports with `catch_unwind` for panic safety
- Null pointer and alignment validation on all inputs
- CAN ID (11/29-bit) and DLC validation
- Token-bucket rate limiting for CAN frame ingestion
- Produces both `staticlib` and `cdylib` outputs
- `production` feature flag gates a real cryptographic backend via C callbacks

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## Building

```bash
# Development / testing (uses stub crypto — zero security)
cargo build -p vs-ffi-auto
cargo test -p vs-ffi-auto

# Production (requires caller-supplied crypto callbacks)
cargo build --release -p vs-ffi-auto --features production
```

## Production Integration

In production builds (`--features production`), the platform must be initialized
with a `VsCryptoCallbacks` struct that provides real cryptographic operations
(typically backed by an HSM driver):

```c
#include "vs_auto.h"

static VsCryptoCallbacks my_callbacks = {
    .context       = &my_hsm_driver,
    .sha256        = my_sha256,
    .hmac_sha256   = my_hmac_sha256,
    .random_bytes  = my_rng,
    // ... all other callbacks
};

VsResult r = vs_auto_platform_init_with_crypto(&my_callbacks);
```

In non-production builds, `vs_auto_platform_init()` (no arguments) uses a stub
provider suitable for testing only.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
