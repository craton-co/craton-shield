# vs-ids-engine

Alert correlation engine combining CAN and Ethernet IDS subsystems.

## Overview

This crate provides the central IDS orchestrator that combines CAN and Ethernet
intrusion detection monitors into a unified alert pipeline. It maintains a
correlation window of recent alerts to detect multi-vector attack patterns
and maps alert severity to response actions via configurable policy entries.

## Key Types

- `IdsEngine` — central orchestrator combining `CanMonitor` and `EthMonitor`
- `IdsResponse` — response actions (Log, Block, Isolate, Alert, Shutdown)
- `DispatchAction` — dispatch targets for alerts (Log, Block, Telemetry)
- `PolicyEntry` — maps an `AlertSeverity` to an `IdsResponse`

## Usage

```rust
use vs_ids_engine::IdsEngine;

let mut engine = IdsEngine::new(can_config, eth_config);
engine.process_can_frame(&frame, timestamp_us);
engine.process_eth_packet(&packet, timestamp_us);
let correlated = engine.correlate();
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
