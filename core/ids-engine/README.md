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

```rust,no_run
use vs_can_monitor::CanMonitor;
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, DEFAULT_SIPHASH_KEYS};
use vs_ids_engine::IdsEngine;

let can = CanMonitor::default();
let eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
let mut ids = IdsEngine::new(can, eth, 100_000); // 100ms correlation window

// Submit CAN frames and Ethernet packets; the engine correlates alerts
// and applies policy-based response actions automatically.
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
