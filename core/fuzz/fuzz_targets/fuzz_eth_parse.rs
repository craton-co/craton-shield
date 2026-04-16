// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_eth_monitor::{parse_ip, parse_transport};

fuzz_target!(|data: &[u8]| {
    // Fuzz the Ethernet/IP/transport parsing path with arbitrary bytes.
    // The parser must not panic, allocate, or loop infinitely.
    if data.len() < 2 {
        return;
    }

    let ethertype = u16::from_be_bytes([data[0], data[1]]);
    let payload = &data[2..];

    // Exercise the IP header parser with various ethertypes
    if let Some((ip_hdr, offset)) = parse_ip(ethertype, payload) {
        // If we got an IP header, try parsing the transport layer
        let _ = parse_transport(ip_hdr.protocol, payload, offset);
    }

    // Also try IPv4 (0x0800) and IPv6 (0x86DD) explicitly
    let _ = parse_ip(0x0800, payload);
    let _ = parse_ip(0x86DD, payload);
});
