// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone BLE monitor example.
//!
//! Demonstrates configuring and using `BleMonitor` directly, without the
//! full `EmbeddedShield` runtime (which requires a `CryptoProvider`).
//!
//! Run with:
//! ```bash
//! cargo run -p vs-ble-monitor --example ble_scanner
//! ```

use vs_ble_monitor::{BleMonitor, MacAction};
use vs_types_embedded::{BleEvent, BleEventType};

fn main() {
    let mut monitor = BleMonitor::new();

    // Allow a known sensor.
    monitor
        .add_mac_filter([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03], MacAction::Allow)
        .expect("add MAC filter");

    // Block a known rogue device.
    monitor
        .add_mac_filter([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01], MacAction::Block)
        .expect("block rogue MAC");

    // Tune detection thresholds.
    monitor.set_conn_storm_params(10, 30_000_000); // 10 connections per 30s
    monitor.set_pairing_fail_threshold(3);
    monitor.set_gatt_rate_threshold(100); // 100 ops per minute

    // --- Simulate BLE events ---
    let events: &[([u8; 6], BleEventType, i8)] = &[
        // Known sensor connects.
        (
            [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
            BleEventType::Connected,
            -45,
        ),
        // Known sensor GATT read.
        (
            [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
            BleEventType::GattRead,
            -45,
        ),
        // Rogue device attempts connection.
        (
            [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            BleEventType::Connected,
            -60,
        ),
        // Unknown device connects (no filter rule).
        (
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            BleEventType::Connected,
            -70,
        ),
        // Same unknown device with sudden RSSI change (relay attack?).
        (
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            BleEventType::Connected,
            -20,
        ),
        // Pairing failure from unknown device.
        (
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            BleEventType::PairingFailed,
            -20,
        ),
    ];

    for (i, (mac, event_type, rssi)) in events.iter().enumerate() {
        let mut event = BleEvent::default();
        event.event_type = *event_type;
        event.peer_addr = *mac;
        event.rssi = *rssi;
        event.timestamp_us = (i as u64 + 1) * 1_000_000;

        let result = monitor.inspect(&event);
        let mac_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        println!(
            "[{}] mac={} event={:?} rssi={:>4} => allowed={}, alerts={}",
            i + 1,
            mac_str,
            event_type,
            rssi,
            result.allowed,
            result.alert_count,
        );
    }

    println!("\nTotal inspected: {}", monitor.total_inspected());
    println!("Total alerts:    {}", monitor.total_alerts());
}
