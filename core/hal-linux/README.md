# vs-hal-linux

Linux HAL implementation with SocketCAN and raw Ethernet support.

## Overview

This crate provides Linux userspace implementations of the Craton Shield HAL
traits. It targets NXP S32G3 and other Linux-based automotive platforms,
providing CAN access via SocketCAN, raw Ethernet via AF_PACKET sockets, and
monotonic timing via `clock_gettime`. On non-Linux targets the crate is empty.

## Key Types

- `LinuxCanBus` — SocketCAN-based `CanBus` implementation
- `LinuxEthernetPhy` — AF_PACKET raw socket `EthernetPhy` implementation
- `LinuxTimer` — `clock_gettime`-based `Timer` implementation

## Usage

```rust
use vs_hal_linux::{LinuxCanBus, LinuxTimer, LinuxEthernetPhy};

let mut can = LinuxCanBus::open("can0")?;
let timer = LinuxTimer::new();
let mut eth = LinuxEthernetPhy::open("eth0")?;
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
