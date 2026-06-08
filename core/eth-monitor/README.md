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

```rust,no_run
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket};

let config = EthMonitorConfig::default();
// Example keys only — production deployments MUST source these from the
// platform TRNG. The runtime wires this up automatically via
// `CratonShield::init`.
let siphash_keys: [(u64, u64); 4] = [
    (0xCAFE_BABE_DEAD_BEEF, 0xFEED_FACE_C0DE_F00D),
    (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
    (0xA5A5_A5A5_5A5A_5A5A, 0x5A5A_5A5A_A5A5_A5A5),
    (0xDEAD_C0DE_BAAD_F00D, 0xBADD_CAFE_BAAD_BEEF),
];
let mut monitor = EthMonitor::new(&config, siphash_keys).unwrap();

let packet = EthPacket {
    src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    vlan_id: None,
    ethertype: 0x0800,
    dst_port: None,
    payload: &[],
};
let alert = monitor.inspect_packet(&packet, /* ts_us = */ 0);
let _ = alert;
```

## License

Apache-2.0. See [LICENSE](LICENSE).
