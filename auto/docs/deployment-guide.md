# Automotive Deployment Guide

> Craton Shield Auto 0.7.0

This guide covers deployment of the Craton Shield automotive runtime
(`vs-runtime-auto`) on vehicle ECUs and gateways. For core deployment concepts,
see the [Core Deployment Guide](../../core/docs/deployment.md).

---

## Target Platforms

| Platform | Architecture | HAL | Notes |
|:---------|:-------------|:----|:------|
| NXP S32G274A | Cortex-A53 + M7 | `vs-hal-linux` | Primary reference platform |
| NXP S32K344 | Cortex-M7 | Custom | CAN-FD gateway |
| Infineon AURIX TC3xx | TriCore | Custom | Requires AUTOSAR integration |
| Renesas R-Car S4 | Cortex-A76 + R52 | `vs-hal-linux` | Linux on A76 cores |
| TI TDA4VM | Cortex-A72 + R5F | `vs-hal-linux` | Linux on A72 |

See [Hardware Compatibility](../../core/docs/hardware-compatibility.md) for the
full matrix.

---

## Build Configuration

### Feature Selection

| Scenario | Features | Notes |
|:---------|:---------|:------|
| Gateway (Linux) | `std`, `capacity-large` | Full CAN + Ethernet + V2X |
| Gateway (bare-metal) | `capacity-large` | No filesystem storage |
| Zone controller | default | Base capacity sufficient |
| AUTOSAR Classic | `autosar-classic` | SecOC, IdsM integration |
| AUTOSAR Adaptive | `autosar-adaptive` | Ara::com service discovery |
| Testing / CI | `mock-hsm` | **Never in production** |

```bash
# Linux gateway build
cargo build --release -p vs-runtime-auto --features "std,capacity-large"

# Cortex-M bare-metal
cargo build --release --target thumbv7em-none-eabihf -p vs-runtime-auto
```

### Capacity Tiers

| Resource | Base | Large | XL |
|:---------|-----:|------:|---:|
| CAN rules | 256 | 512 | 1024 |
| Tracked CAN IDs | 1024 | 2048 | 4096 |
| Firewall rules | 128 | 256 | 512 |
| Signal IDS channels | 64 | 128 | 256 |
| V2X peer cache | 32 | 64 | 128 |

---

## Initialization

```rust
use vs_runtime_auto::{AutoShield, AutoConfig};
use vs_crypto::SoftwareCryptoProvider;  // Replace with HSM in production

let config = AutoConfig {
    watchdog_timeout_us: 1_000_000,
    ids_correlation_window_us: 100_000,
    diag_session_timeout_us: 5_000_000,
    diag_lockout_duration_us: 10_000_000,
    v2x_generation_time_tolerance_us: 2_000_000,
    ..Default::default()
};

let crypto = SoftwareCryptoProvider::default();
let mut shield = AutoShield::init(config, crypto)?;
```

---

## CAN Bus Integration

### SocketCAN (Linux)

```rust
use vs_hal_linux::LinuxCanBus;

let mut can0 = LinuxCanBus::open("can0")?;
loop {
    if let Ok(Some(frame)) = can0.receive() {
        shield.submit_can_frame(&frame, timer.now_us())?;
    }
    shield.tick(timer.now_us())?;
}
```

### Bare-Metal

Implement the `vs_hal::CanBus` trait for your MCU's CAN peripheral. See the
[Porting Guide](../../core/docs/porting-guide.md) for step-by-step instructions.

---

## AUTOSAR Integration

For AUTOSAR Classic (SecOC, IdsM) and Adaptive (Ara::com) integration patterns,
see the [AUTOSAR V2X Integration Guide](../../core/docs/autosar-v2x-integration-guide.md).

Key integration points:

- **SecOC:** `vs-autosar` provides MAC-based CAN frame authentication
- **IdsM:** Alert forwarding to the AUTOSAR Intrusion Detection System Manager
- **MCAL:** CAN/Ethernet driver adapters for AUTOSAR MCAL layer
- **DEM:** Diagnostic Event Manager integration for fault reporting

---

## V2X Configuration

```rust
use vs_v2x::{V2xValidator, V2xConfig};

let v2x_config = V2xConfig {
    generation_time_tolerance_us: 2_000_000,  // 2 seconds
    max_speed_mps: 80,                         // 80 m/s (~288 km/h)
    max_range_m: 1000,                         // 1 km plausibility check
    require_certificate: true,
    ..Default::default()
};
```

---

## UDS Diagnostic Gateway

The diagnostic gateway (`vs-diag-gateway`) provides SecurityAccess (0x27)
brute-force protection with configurable lockout:

- **Default lockout:** 3 failed attempts → 10-second lockout
- **Session timeout:** 5 seconds of inactivity
- **SID allowlisting:** Only explicitly permitted diagnostic services are forwarded

---

## Monitoring and Health

```rust
let health = shield.health_status();
// Check per-subsystem status:
// health.can_monitor, health.eth_monitor, health.v2x,
// health.signal_ids, health.diag_gateway, ...
```

---

## Standards Compliance

| Standard | Coverage | Notes |
|:---------|:---------|:------|
| ISO/SAE 21434 | TARA, threat catalog, risk assessment | See `vs-report-iso21434` |
| UN R155 / R156 | Technical controls | See [UN R155/R156 evidence](../../core/docs/certification/un-r155-r156-evidence.md) |
| ISO 26262 ASIL-B | Targeting (not certified) | See [Safety Manual](../../core/docs/safety-manual.md) |
| AUTOSAR AP R22-11 | SecOC, IdsM, Ara::com | See `vs-autosar` |

---

## Further Reading

- [Core Deployment Guide](../../core/docs/deployment.md) — build profiles, initialization, watchdog
- [Porting Guide](../../core/docs/porting-guide.md) — HAL trait implementation
- [AUTOSAR V2X Integration Guide](../../core/docs/autosar-v2x-integration-guide.md)
- [Performance Results](../../core/docs/performance-results.md) — CAN/Ethernet latency benchmarks
- [Threat Model](../../core/docs/threat-model.md) — automotive threat scenarios
