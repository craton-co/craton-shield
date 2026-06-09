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

`inspect_packet` either takes a raw IP frame (leave `dst_port` as `None`
and the monitor strips the L3/L4 headers itself via `parse_ip` /
`parse_transport`), or an already-stripped L4 payload paired with an
explicit `dst_port`. SOME/IP and DoIP checks only run once the transport
port is positively identified — an unidentified packet is never
re-interpreted as a protocol header.

```rust,no_run
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS};

let config = EthMonitorConfig::default();
// `DEFAULT_SIPHASH_KEYS` is for examples/tests ONLY. Production
// deployments MUST source these from the platform TRNG; the runtime
// wires this up automatically via `CratonShield::init`.
let mut monitor = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();

// An already-stripped SOME/IP message: pair the L4 payload with the
// SOME/IP UDP port (30490) so the monitor dispatches it correctly.
let someip_payload: [u8; 16] = [0u8; 16];
let packet = EthPacket {
    src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    vlan_id: None,
    ethertype: 0x0800,
    dst_port: Some(30490),
    payload: &someip_payload,
};
let alert = monitor.inspect_packet(&packet, /* ts_us = */ 0);
let _ = alert;
```

## License

Apache-2.0. See [LICENSE](LICENSE).
