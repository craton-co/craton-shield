# vs-eth-monitor

Automotive Ethernet intrusion detection with SOME/IP, DoIP, and ARP monitoring.

## Overview

This crate provides an Ethernet-level intrusion detection monitor for
automotive networks. It inspects traffic for SOME/IP service anomalies, DoIP
session violations, ARP spoofing attempts, VLAN hopping, and service discovery
flooding, raising `SecurityAlert` events for each detected threat.

## Key Types

- `EthMonitor` — central Ethernet IDS engine with configurable allow-lists
- `EthMonitorConfig` — configuration for VLAN, SOME/IP, DoIP, and ARP policies
- `EthPacket` — zero-copy Ethernet packet representation
- `SomeIpHeader` — parsed SOME/IP header (service ID, method ID, length, etc.)

## Usage

```rust
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket};

let mut monitor = EthMonitor::new(EthMonitorConfig::default());
let alerts = monitor.inspect(&packet, timestamp_us);
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
