# Hardware Compatibility Matrix

**Version**: 1.0.0 | **Date**: 2026-03-28

This document lists hardware platforms that have been tested or are known to be
compatible with Craton Shield Core.

---

## Supported Targets

### Tier 1 — CI Tested

These targets are tested on every push and pull request in CI.

| Target | Architecture | OS | CI Job | Notes |
|:---|:---|:---|:---|:---|
| `x86_64-unknown-linux-gnu` | x86_64 | Linux | `test` | Primary development target |
| `aarch64-unknown-linux-gnu` | AArch64 | Linux | `test` (cross) | Cross-compiled, QEMU user-mode |
| `x86_64-pc-windows-msvc` | x86_64 | Windows 11 | `test-windows` | Full test suite |
| `x86_64-apple-darwin` | x86_64 | macOS | `test-macos` | Full test suite |
| `thumbv7em-none-eabihf` | Cortex-M4F | Bare metal | `check-thumbv7em` | `cargo check` only (no test execution) |

### Tier 2 — Known Compatible

These targets have been manually tested or are expected to work based on
architecture compatibility. They are not tested in CI.

| Target | Architecture | SoC / Board | Notes |
|:---|:---|:---|:---|
| NXP S32G274A (S32G3 family) | Cortex-A53 + Cortex-M7 | S32G-VNP-RDB3 | Primary automotive reference platform |
| NXP S32K344 | Cortex-M7 | S32K3X4EVB | CAN-FD gateway evaluation |
| Infineon AURIX TC3xx | TriCore 1.6.2 | — | Requires custom HAL; no `vs-hal-linux` |
| Renesas R-Car S4 | Cortex-A76 + Cortex-R52 | Spider board | Linux HAL compatible on A76 cores |
| Qualcomm SA8155P | Cortex-A76 | Snapdragon Ride | Linux or QNX HAL |
| TI TDA4VM (Jacinto 7) | Cortex-A72 + Cortex-R5F | SK-TDA4VM | Linux HAL on A72; bare-metal on R5F |
| STM32H755 | Cortex-M7 + Cortex-M4 | NUCLEO-H755ZI | Bare-metal with custom HAL |

### Tier 3 — Community / Untested

These targets should work but have not been validated.

| Target | Notes |
|:---|:---|
| `aarch64-unknown-none` | Generic bare-metal AArch64 |
| `riscv32imac-unknown-none-elf` | RISC-V 32-bit (no FPU) |
| `riscv64gc-unknown-none-elf` | RISC-V 64-bit |
| Any Cortex-M3+ with 256 KB+ flash | Must implement `vs-hal` traits |

---

## HAL Implementations

| HAL Crate | Platforms | Repository |
|:---|:---|:---|
| `vs-hal-linux` | Linux (SocketCAN, raw sockets, `clock_gettime`) | This repo |
| `vs-hal-qnx` | QNX Neutrino 7.1+ | [auto/](../../auto/) |
| `vs-hal-autosar` | AUTOSAR Adaptive R22-11+ | [auto/](../../auto/) |

For other platforms, implement the traits defined in `vs-hal`:
- `CanBus` — CAN frame receive/transmit
- `EthernetPhy` — Raw Ethernet frame receive/transmit
- `Timer` — Monotonic microsecond clock
- `HsmHardware` — Hardware security module interface

See [docs/porting-guide.md](porting-guide.md) for step-by-step instructions.

---

## Memory Requirements

| Capacity Tier | Feature Flags | Flash | RAM (stack) | Max Rules | Max CAN IDs |
|:---|:---|---:|---:|---:|---:|
| Standard | (default) | ~180 KB | ~80 KB | 128 FW / 64 policy | 512 |
| Large | `capacity-large` | ~320 KB | ~120 KB | 256 FW / 128 policy | 512 |
| XL | `capacity-xl` | ~520 KB | ~200 KB | 512 FW / 256 policy | 512 |

See [docs/performance-results.md](performance-results.md) for detailed measurements.

---

## CAN Controller Requirements

- Classic CAN (ISO 11898-1) at 125 kbit/s – 1 Mbit/s
- CAN-FD (ISO 11898-1:2015) at up to 8 Mbit/s data phase (optional)
- Hardware timestamping recommended (≤1 us resolution)
- Receive FIFO with at least 16 entries recommended to avoid frame drops

## Ethernet Controller Requirements

- 100BASE-T1 or 1000BASE-T1 (automotive Ethernet)
- Raw frame access (promiscuous mode) for monitoring
- VLAN tag support (IEEE 802.1Q) for firewall rules
- Hardware timestamping recommended for SOME/IP latency tracking

## Clock Requirements

- Monotonic clock with ≤1 ms jitter (safety assumption A-01)
- Microsecond resolution (`u64` timestamp)
- `CLOCK_MONOTONIC_RAW` on Linux (not `CLOCK_MONOTONIC` which is NTP-adjusted)
