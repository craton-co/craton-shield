# Embedded IoT Deployment Guide

> Craton Shield Embedded 0.7.0

This guide covers deployment of the Craton Shield embedded runtime
(`vs-runtime-embedded`) on constrained IoT devices and gateways. For core
deployment concepts, see the [Core Deployment Guide](../../core/docs/deployment.md).

---

## Target Environments

| Environment | Typical Hardware | RAM | Flash | Protocols |
|:------------|:-----------------|----:|------:|:----------|
| IoT gateway | Cortex-A (Linux) | 64+ MB | 256+ MB | All |
| Smart sensor hub | Cortex-M7 | 512 KB | 2 MB | MQTT, CoAP, BLE |
| Edge controller | Cortex-M4F | 256 KB | 512 KB | MQTT, Modbus |
| Constrained node | Cortex-M3 | 128 KB | 256 KB | CoAP, BLE |

---

## Memory Budget

All Craton Shield embedded crates are `#![no_std]` with zero heap allocation.
Stack usage per monitor:

| Monitor | Stack Budget | Notes |
|:--------|:-------------|:------|
| `vs-mqtt-monitor` | ~400 bytes | 32 topic rules, 32 rate buckets |
| `vs-coap-monitor` | ~350 bytes | 24 URI rules, 16 rate buckets |
| `vs-ble-monitor` | ~300 bytes | 16 peer tracking slots |
| `vs-zigbee-monitor` | ~350 bytes | 32 address rules, frame counter tracking |
| `vs-lora-monitor` | ~400 bytes | 32 device rules, duty cycle tracking |
| `vs-modbus-monitor-emb` | ~350 bytes | 32 unit rules, 16 rate buckets |
| `vs-runtime-embedded` | ~3 KB | Composes all monitors |

Total stack for a full deployment: **~5 KB** (all monitors active).

### Binary Size

| Configuration | Flash (release, LTO) |
|:--------------|---------------------:|
| Runtime + MQTT + CoAP | ~45 KB |
| Runtime + BLE + Zigbee | ~40 KB |
| Runtime + all 6 monitors | ~80 KB |
| Core runtime only | ~280 KB |

---

## Build Configuration

### Feature Selection

| Scenario | Features | Notes |
|:---------|:---------|:------|
| Full gateway | all monitors enabled | Default |
| MQTT-only edge | disable unused monitors | Smaller binary |
| Testing / CI | `mock-hsm` | **Never in production** |

```bash
# Linux gateway (full)
cargo build --release -p vs-runtime-embedded

# Cortex-M4F bare-metal
cargo build --release --target thumbv7em-none-eabihf -p vs-runtime-embedded

# Single monitor only
cargo build --release --target thumbv7em-none-eabihf -p vs-mqtt-monitor
```

### Capacity Tiers

| Resource | Base | Large | XL |
|:---------|-----:|------:|---:|
| MQTT topic rules | 32 | 64 | 128 |
| CoAP URI rules | 24 | 48 | 96 |
| BLE peer slots | 16 | 32 | 64 |
| Zigbee address rules | 32 | 64 | 128 |
| LoRa device rules | 32 | 64 | 128 |
| Modbus unit rules | 32 | 64 | 128 |

---

## Initialization

```rust
use vs_runtime_embedded::{EmbeddedShield, EmbeddedConfig};
use vs_crypto::SoftwareCryptoProvider;

let config = EmbeddedConfig::default();
let crypto = SoftwareCryptoProvider::default();
let mut shield = EmbeddedShield::init(config, crypto)?;
```

---

## Protocol Integration

### MQTT

```rust
use vs_types_embedded::MqttMessage;

// From your MQTT client callback:
let msg = MqttMessage {
    topic: /* topic bytes */,
    topic_len: /* length */,
    payload: /* payload bytes */,
    payload_len: /* length */,
    qos: 1,
    // ...
};
let result = shield.inspect_mqtt(&msg, timestamp_us);
```

### CoAP

```rust
use vs_types_embedded::CoapMessage;

let msg = CoapMessage {
    uri_path: /* URI bytes */,
    uri_len: /* length */,
    method: 1,  // GET
    // ...
};
let result = shield.inspect_coap(&msg, timestamp_us);
```

### BLE

```rust
use vs_types_embedded::BleEvent;

let event = BleEvent {
    peer_mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
    rssi: -65,
    // ...
};
let result = shield.inspect_ble(&event, timestamp_us);
```

---

## Alert Handling

```rust
use vs_runtime_embedded::AlertCallback;

struct MyAlertHandler;

impl AlertCallback for MyAlertHandler {
    fn on_alert(&self, alert: &SecurityAlert) {
        // Forward to cloud, log to flash, trigger LED, etc.
    }
}

shield.set_alert_callback(MyAlertHandler);
```

---

## Constrained Device Sizing

For devices with very limited resources, consider:

1. **Enable only needed monitors.** Each unused monitor saves 5-15 KB flash.
2. **Use base capacity tier.** Large/XL tiers increase RAM usage.
3. **Disable unused detection modes.** E.g., skip entropy analysis if not needed.
4. **Use `release` profile with LTO.** Reduces binary by ~40% vs debug.
5. **Strip debug symbols.** Add `strip = true` to your release profile.

```toml
# Cargo.toml release profile for minimum size
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

---

## Over-the-Air Updates

For OTA firmware updates on IoT devices, integrate with `vs-ota-validator`:

- TUF/Uptane metadata validation
- Rollback protection via monotonic version counters
- Firmware hash verification before installation

See [Core Deployment Guide — OTA](../../core/docs/deployment.md) for details.

---

## Further Reading

- [Core Deployment Guide](../../core/docs/deployment.md) — build profiles, initialization, watchdog
- [Porting Guide](../../core/docs/porting-guide.md) — HAL trait implementation for new MCUs
- [Hardware Compatibility](../../core/docs/hardware-compatibility.md) — tested platforms
- [Feature Flags](../../core/docs/feature-flags.md) — all workspace features
- [Performance Results](../../core/docs/performance-results.md) — latency benchmarks
