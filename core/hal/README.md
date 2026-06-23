# vs-hal

Hardware abstraction layer traits for CAN, Ethernet, Timer, and HSM.

## Overview

This crate defines the hardware abstraction traits that allow Craton Shield
core logic to remain platform-independent. Implementations target specific
automotive platforms (NXP S32G, Infineon AURIX, QEMU, etc.) while the
core crates program against these traits.

## Key Types

- `CanBus` — trait for CAN/CAN-FD hardware (receive, transmit, bus-off detection)
- `Timer` — trait for monotonic microsecond timestamps and cycle counting
- `HsmHardware` — trait for HSM operations (AES-GCM, ECDSA P-256, key management)
- `EthernetPhy` — trait for raw Ethernet frame send/receive
- `RawCanFrame` — CAN frame representation with ID, DLC, data, timestamp, and FD flag
- `RawEthFrame` — raw Ethernet frame buffer

## Usage

```rust
use vs_hal::{CanBus, Timer};

/// Drain one CAN frame (if any) and return its hardware ID paired with the
/// timestamp the application observed it.
fn process<B: CanBus, T: Timer>(bus: &mut B, timer: &T) -> Option<(u32, u64)> {
    let frame = bus.receive().ok()??;
    let now = timer.now_us();
    Some((frame.id, now))
}
```

## Feature Flags

All features are off by default.

- `test-stubs` — exposes security-neutral test doubles (`StubCanBus`,
  `StubEthernetPhy`, `StubTimer`, `StubWatchdog`, `StubSecureStorage`).
  Contains no cryptographic code and is safe to enable in any build,
  including release.
- `stub-hsm` — exposes `StubHsmHardware`, an **insecure** HSM stub with
  deterministic placeholder crypto. Implies `test-stubs`. A `compile_error!`
  fences this feature out of release builds; it must never be enabled in
  production.
- `tpm2-experimental` — surfaces the unfinished `Tpm2Transport` trait stub
  for prototyping. The API is not finalized; do not use in production.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
