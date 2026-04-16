# vs-types-embedded

IoT/embedded type extensions for Craton Shield.

## Overview

Extends the base `vs-types` crate with types specific to IoT and embedded
security monitoring. All types are `#![no_std]` compatible, use fixed-size
arrays (no heap), and are designed for efficient use on constrained MCUs.
Note: as of v0.7, `MqttMessage` and `CoapMessage` no longer implement `Copy`
due to their large size (656 and 408 bytes respectively). Use references
(`&MqttMessage`, `&CoapMessage`) instead. Other types remain `Copy`.

## Key Types

- `DeviceId` — Fixed-size (32 bytes max) device identifier for IoT endpoints. Supports construction from MAC addresses, UUIDs, or raw bytes.
- `MqttMessage` — MQTT message representation with topic (128 bytes), payload (512 bytes), QoS, retain flag, and timestamp.
- `MqttPacketType` — MQTT control packet types (Connect, Publish, Subscribe, etc.).
- `MqttQoS` — MQTT QoS levels (AtMostOnce, AtLeastOnce, ExactlyOnce).
- `CoapMessage` — CoAP message with URI (128 bytes), payload (256 bytes), method, message type, and message ID.
- `CoapMethod` — CoAP methods (Get, Post, Put, Delete).
- `CoapMessageType` — CoAP message types (Confirmable, NonConfirmable, Acknowledgement, Reset).
- `BleEvent` — BLE event with peer MAC address, RSSI, connection handle, and event type.
- `BleEventType` — BLE event types (Connected, Disconnected, PairingRequest, GattRead, GattWrite, etc.).
- `ZigbeeFrame` — IEEE 802.15.4 frame with source/destination addresses, PAN IDs, frame type, and security counter.
- `ZigbeeFrameType` — Zigbee frame types (Beacon, Data, Ack, Command).
- `LoraMessage` — LoRaWAN message with device address, frame counter, message type, data rate, and airtime.
- `LoraMessageType` — LoRa message types (JoinRequest, JoinAccept, UnconfirmedDataUp, ConfirmedDataUp, etc.).
- `ModbusRtuMessage` — Modbus RTU message with unit ID, function code, register address, and quantity.
- `ModbusTcpMessage` — Modbus TCP message wrapping RTU with source IP address.
- `ModbusIpFilter` — IP prefix filter for Modbus TCP source address filtering.
- `IpAction` — Allow/Block action for IP filters.
- `ModbusException` — Modbus exception response codes.

## Source Constants

Source-type constants for the embedded/IoT range (20-29):

| Constant | Value | Protocol |
|:---|:---|:---|
| `SOURCE_MQTT` | 20 | MQTT broker traffic |
| `SOURCE_COAP` | 21 | CoAP traffic |
| `SOURCE_BLE` | 22 | Bluetooth Low Energy |
| `SOURCE_ZIGBEE` | 23 | Zigbee / IEEE 802.15.4 |
| `SOURCE_LORA` | 24 | LoRa / LoRaWAN |
| `SOURCE_MODBUS_RTU` | 25 | Modbus RTU (serial) |
| `SOURCE_MODBUS_TCP` | 26 | Modbus TCP |

## Usage

```rust
use vs_types_embedded::{DeviceId, MqttMessage, MqttPacketType, MqttQoS};
use vs_types_embedded::{CoapMessage, CoapMethod, BleEvent, BleEventType};

// Create a device ID from a MAC address.
let device = DeviceId::from_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
assert_eq!(device.len(), 6);

// Create a default MQTT message.
let msg = MqttMessage::default();
```

## Changelog

See the [workspace CHANGELOG](../../CHANGELOG.md) for version history.

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
