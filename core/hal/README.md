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
use vs_hal::{CanBus, Timer, RawCanFrame};

fn process<B: CanBus, T: Timer>(bus: &mut B, timer: &T) {
    if let Ok(Some(frame)) = bus.receive() {
        let now = timer.now_us();
        // process frame at timestamp `now`
    }
}
```

## Feature Flags

See [docs/feature-flags.md](../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
