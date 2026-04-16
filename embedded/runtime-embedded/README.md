# vs-runtime-embedded

IoT/embedded runtime extending Craton Shield with MQTT, CoAP, BLE, Zigbee, LoRa, and Modbus monitors.

## Overview

Orchestrates all embedded security modules into a lightweight runtime suitable
for constrained MCUs. Extends the base `CratonShield` core with IoT-specific
protocol monitors, unified health reporting, and alert routing.

## Features

- Integrates `vs-mqtt-monitor`, `vs-coap-monitor`, `vs-ble-monitor`, `vs-zigbee-monitor`, `vs-lora-monitor`, and `vs-modbus-monitor` into a single runtime
- Routes all monitor alerts through the core `CratonShield` event pipeline
- Provides `EmbeddedHealth` snapshot combining core and IoT subsystem status
- `AlertCallback` trait for synchronous alert notifications (LED, buzzer, radio shutdown)
- Configurable capacity via feature flags: `capacity-large`, `capacity-xl`

## Usage

```rust,ignore
use vs_runtime_embedded::EmbeddedShield;
use vs_runtime::PlatformConfig;
use vs_types::VsError;

# fn example<C: vs_crypto::CryptoProvider + Clone>(
#     crypto: C,
#     mqtt_msg: &mut vs_types_embedded::MqttMessage,
#     coap_msg: &mut vs_types_embedded::CoapMessage,
#     ble_event: &mut vs_types_embedded::BleEvent,
#     zigbee_frame: &mut vs_types_embedded::ZigbeeFrame,
#     lora_msg: &mut vs_types_embedded::LoraMessage,
#     rtu_msg: &mut vs_types_embedded::ModbusRtuMessage,
#     tcp_msg: &mut vs_types_embedded::ModbusTcpMessage,
#     timestamp_us: u64,
# ) -> Result<(), VsError> {
// Initialize with a crypto provider.
let mut shield = EmbeddedShield::init(PlatformConfig::default(), crypto)?;

// Configure monitors via configure_*() closures (primary API).
shield.configure_mqtt(|mqtt| {
    mqtt.add_rule(
        b"sensors/#",
        vs_mqtt_monitor::TopicAction::Allow,
        vs_mqtt_monitor::QosPolicy::Any,
        10,
    )?;
    Ok(())
})?;

// Submit protocol messages.  Each submit_* method takes `&mut` so it can
// stamp the validated `timestamp_us` onto the message after guard checks.
let mqtt_result = shield.submit_mqtt_message(mqtt_msg, timestamp_us);
let coap_result = shield.submit_coap_message(coap_msg, timestamp_us);
let ble_result  = shield.submit_ble_event(ble_event, timestamp_us);
let zigbee_result = shield.submit_zigbee_frame(zigbee_frame, timestamp_us);
let lora_result = shield.submit_lora_message(lora_msg, timestamp_us);
let modbus_rtu_result = shield.submit_modbus_rtu(rtu_msg, timestamp_us);
let modbus_tcp_result = shield.submit_modbus_tcp(tcp_msg, timestamp_us);

// Periodic tick and health check.
shield.tick(timestamp_us)?;
let health = shield.health_status();
# Ok(())
# }
```

## API

| Method | Description |
|:---|:---|
| `init(config, crypto)` | Initialize the embedded runtime |
| `init_with_callback(config, crypto, cb)` | Initialize with an `AlertCallback` |
| `submit_mqtt_message(msg, ts)` | Inspect MQTT message, route alerts |
| `submit_coap_message(msg, ts)` | Inspect CoAP message, route alerts |
| `submit_coap_message_with_peer(msg, peer, ts)` | Inspect CoAP message bound to a peer endpoint (required for amplification detection) |
| `check_coap_amplification_with_peer(id, token, peer, len, ts)` | Check response for amplification against a peer-scoped request |
| `submit_ble_event(event, ts)` | Inspect BLE event, route alerts |
| `submit_zigbee_frame(frame, ts)` | Inspect Zigbee frame, route alerts |
| `submit_lora_message(msg, ts)` | Inspect LoRa message, route alerts |
| `submit_modbus_rtu(msg, ts)` | Inspect Modbus RTU message, route alerts |
| `submit_modbus_tcp(msg, ts)` | Inspect Modbus TCP message, route alerts |
| `submit_can_frame(frame, ts)` | Pass-through to core CAN IDS |
| `submit_eth_packet(pkt, ts)` | Pass-through to core Ethernet IDS |
| `tick(ts)` | Periodic tick delegation |
| `health_status()` | Snapshot of core + IoT subsystem health |
| `drain_recent_alerts()` | Drain and clear the recent alerts buffer |
| `record_config_change(src, change, ts)` | Record a configuration change in audit log |
| `alert_callback()` | Access the installed alert callback |
| `shutdown()` | Graceful shutdown |
| `configure_mqtt(\|m\| ...)` | Configure MQTT monitor (primary API) |
| `configure_coap(\|m\| ...)` | Configure CoAP monitor (primary API) |
| `configure_ble(\|m\| ...)` | Configure BLE monitor (primary API) |
| `configure_zigbee(\|m\| ...)` | Configure Zigbee monitor (primary API) |
| `configure_lora(\|m\| ...)` | Configure LoRa monitor (primary API) |
| `configure_modbus(\|m\| ...)` | Configure Modbus monitor (primary API) |
| `mqtt_monitor()` | Read-only access to MQTT monitor |
| `coap_monitor()` | Read-only access to CoAP monitor |
| `ble_monitor()` | Read-only access to BLE monitor |
| `zigbee_monitor()` | Read-only access to Zigbee monitor |
| `lora_monitor()` | Read-only access to LoRa monitor |
| `modbus_monitor()` | Read-only access to Modbus monitor |

## Feature Flags

| Flag | Description |
|:---|:---|
| `capacity-large` | Enhanced buffer capacity (delegates to core) |
| `capacity-xl` | Maximum capacity (delegates to core) |

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
