# vs-signal-ids

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

CAN signal-level intrusion detection using per-signal EWMA anomaly ensemble.

## Overview

This crate extracts physical signals from raw CAN frame payloads based on
user-defined signal definitions (similar to DBC/ARXML descriptions) and
monitors each signal independently using an EWMA-based anomaly detector.
It supports both little-endian (Intel) and big-endian (Motorola) byte orders
with configurable linear scaling (`physical = raw * scale + offset`).

## Key Types

- `SignalIdsEngine` — manages signal definitions and per-signal EWMA anomaly detectors
- `SignalDefinition` — defines a CAN signal's bit position, length, byte order, and scaling
- `ByteOrder` — signal byte order (`LittleEndian` / `BigEndian`)
- `SignalAnomaly` — a single detected anomaly with signal index, z-score, and physical value
- `SignalIdsResult` — result of processing a frame (anomaly count + details)

## Usage

```rust
use vs_signal_ids::{SignalIdsEngine, SignalDefinition, ByteOrder};

let mut engine = SignalIdsEngine::new(0.1, 3.0)?; // alpha=0.1, z_threshold=3.0
engine.define_signal(SignalDefinition {
    can_id: 0x100, start_bit: 0, bit_length: 16,
    byte_order: ByteOrder::LittleEndian,
    scale: 0.1, offset: -40.0, name_hash: 0xDEAD,
    ..Default::default()
})?;

let result = engine.process_frame(&frame);
if result.anomaly_count > 0 {
    // signal anomaly detected — raise alert
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
