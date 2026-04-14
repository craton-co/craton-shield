# Hardware Porting Guide

> Craton Shield 0.7.0

This guide explains how to port Craton Shield to a new hardware platform (ECU, SoC, or RTOS).

## Overview

Craton Shield uses a HAL (Hardware Abstraction Layer) to isolate platform-specific code. Porting requires implementing four traits defined in `vs-hal`:

| Trait | Purpose | Example |
|-------|---------|---------|
| `CanBus` | CAN frame send/receive | SocketCAN, devctl, MCAL |
| `EthernetPhy` | Raw Ethernet frames | io-pkt, raw sockets, DMA |
| `Timer` | Monotonic microsecond clock | clock_gettime, CCNT, SysTick |
| `HsmHardware` | Hardware crypto offload | NXP HSE, Infineon SHE+, TPM |

## Step-by-Step

### 1. Create a HAL crate

```bash
mkdir crates/hal-<platform>
```

Add to workspace `Cargo.toml` members and create `src/lib.rs` with `#![no_std]`.

Depend on `vs-hal` and `vs-types`:

```toml
[dependencies]
vs-hal = { path = "../hal" }
vs-types = { path = "../types" }
```

### 2. Implement `Timer`

This is the simplest trait and the first one to bring up.

```rust
use vs_hal::Timer;

pub struct MyTimer;

impl Timer for MyTimer {
    fn now_us(&self) -> u64 {
        // Read the platform's monotonic timer and convert to microseconds.
        // Replace with your hardware's timer peripheral register access.
        let ticks = read_timer_counter();
        let us = ticks / (TIMER_FREQ_HZ / 1_000_000);
        us
    }

    fn cycle_count(&self) -> Option<u64> {
        // Optional: CPU cycle counter for WCET measurement.
        // Return None if not available.
        None
    }
}
```

**Verification**: `now_us()` must be monotonically increasing and survive sleep/idle.

### 3. Implement `CanBus`

```rust
use vs_hal::{CanBus, RawCanFrame};
use vs_types::VsError;

pub struct MyCan { /* platform-specific state */ }

impl CanBus for MyCan {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        // Poll the CAN peripheral's receive FIFO.
        // Replace with your hardware's CAN register access.
        if !can_rx_fifo_empty() {
            let frame = read_can_rx_fifo();
            Ok(Some(frame))
        } else {
            Ok(None)
        }
    }

    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        // Write frame to CAN peripheral's transmit mailbox.
        // Replace with your hardware's CAN register access.
        write_can_tx_mailbox(frame)?;
        Ok(())
    }

    fn bitrate(&self) -> u32 { 500_000 }
    fn is_bus_off(&self) -> bool { false }
}
```

**Key constraints**:
- `RawCanFrame::data` is 64 bytes (CAN-FD). Classic CAN uses only bytes 0..7.
- `timestamp_us` must come from the same clock as `Timer::now_us()`.
- `dlc` must reflect actual payload length, not the DLC field encoding.

### 4. Implement `EthernetPhy`

```rust
use vs_hal::{EthernetPhy, RawEthFrame};
use vs_types::VsError;

pub struct MyEth { /* platform-specific state */ }

impl EthernetPhy for MyEth {
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        // Poll the Ethernet MAC's receive DMA descriptor ring.
        // Replace with your hardware's Ethernet register access.
        if !eth_rx_descriptor_available() {
            return Ok(None);
        }
        let frame = read_eth_rx_descriptor();
        Ok(Some(frame))
    }

    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError> {
        // Write frame to the Ethernet MAC's transmit DMA descriptor ring.
        // Replace with your hardware's Ethernet register access.
        write_eth_tx_descriptor(data)?;
        Ok(())
    }

    fn link_speed_mbps(&self) -> u32 { 1000 }
    fn link_is_up(&self) -> bool { true }
}
```

**Key constraints**:
- `RawEthFrame::data` is 1522 bytes (MTU 1500 + L2 header + VLAN tag).
- `len` field must reflect actual frame length.

### 5. Implement `HsmHardware` (optional)

Only needed if your platform has a hardware security module. See `vs-hal::HsmHardware` for the full trait.

Priority order for HSM operations:
1. `hsm_sha256` — most commonly called
2. `hsm_aes_gcm_encrypt` / `hsm_aes_gcm_decrypt` — OTA payload protection
3. `hsm_sign_p256` / `hsm_verify_p256` — metadata verification
4. `hsm_random_bytes` — key generation, nonce generation
5. `hsm_hmac_sha256` — audit log chaining
6. `hsm_ecdh_derive` — secure channel establishment

### 6. Wire into vs-runtime

In your application's `main()`, construct the runtime with your HAL types:

```rust
let timer = MyTimer::new();
let can = MyCan::new(500_000);
let eth = MyEth::new(1000);
// Pass to CratonShieldRuntime::builder()
```

### 7. Test on host first

Use `#[cfg(not(target_os = "..."))]` stubs that return `VsError::NotInitialized` so the crate compiles and tests pass on x86_64. Then cross-compile for the target:

```bash
cargo build --target aarch64-unknown-linux-gnu  # Linux ARM64
cargo build --target aarch64-unknown-nto-qnx710 # QNX 7.1
cargo build --target thumbv7em-none-eabihf      # Cortex-M (compile-only)
```

## Existing Ports

| Platform | Crate | Status |
|----------|-------|--------|
| Linux (x86_64, aarch64) | `vs-hal-linux` | Production-ready |
| QNX Neutrino 7.1 | `vs-hal-qnx` (in [auto/](../../auto/)) | FFI bindings complete, needs SDP testing |
| Stub (testing) | `vs-hal` (StubCanBus, StubTimer) | Complete |

## Constraints

- All HAL crates must be `#![no_std]` — no `std` library
- Zero heap allocation — no `Vec`, `Box`, `String`
- All `unsafe` blocks require `// SAFETY:` comments
- Public types must use `#[repr(C)]` for FFI compatibility
- Receive methods must be non-blocking (return `Ok(None)` when no data)
