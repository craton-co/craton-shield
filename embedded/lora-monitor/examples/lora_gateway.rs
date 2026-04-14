// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone example demonstrating `LoraMonitor` directly.
//!
//! This example creates a `LoRa` monitor with device-level access rules and
//! join flood detection, then simulates several `LoRa` messages to show how
//! the monitor filters traffic and detects anomalies such as replay attacks.
//!
//! Run with:
//! ```sh
//! cargo run -p vs-lora-monitor --example lora_gateway
//! ```

use vs_lora_monitor::{DeviceAction, LoraMonitor};
use vs_types_embedded::{LoraMessage, LoraMessageType};

fn make_lora_msg(
    dev_addr: [u8; 4],
    msg_type: LoraMessageType,
    frame_counter: u32,
    ts_us: u64,
) -> LoraMessage {
    LoraMessage {
        dev_addr,
        frame_counter,
        frame_port: 1,
        msg_type,
        payload_len: 8,
        rssi: -80,
        snr: 7,
        data_rate: 5,
        airtime_us: 50_000,
        timestamp_us: ts_us,
    }
}

fn main() {
    println!("=== Craton Shield - LoRa Gateway Monitor Example ===\n");

    // ── Create and configure the monitor ──────────────────────────────
    let mut monitor = LoraMonitor::new();

    // Device rules
    let _ = monitor.add_rule([0x01, 0x02, 0x03, 0x04], DeviceAction::Allow);
    let _ = monitor.add_rule([0xDE, 0xAD, 0x00, 0x01], DeviceAction::Block);

    // Alert if more than 10 join requests within a 60-second window
    monitor.set_join_flood_params(10, 60_000_000);

    println!("Monitor configured:");
    println!("  Device [01:02:03:04] -> allow");
    println!("  Device [DE:AD:00:01] -> block");
    println!("  Join flood threshold : 10 in 60s");
    println!();

    // ── Build simulated messages ──────────────────────────────────────
    let allowed_dev = [0x01, 0x02, 0x03, 0x04];
    let blocked_dev = [0xDE, 0xAD, 0x00, 0x01];
    let unknown_dev = [0xAA, 0xBB, 0xCC, 0xDD];

    let messages: Vec<(&str, LoraMessage)> = vec![
        (
            "Uplink from allowed device [01:02:03:04] (should be allowed)",
            make_lora_msg(allowed_dev, LoraMessageType::UnconfirmedUp, 1, 1_000_000),
        ),
        (
            "Join request from unknown device [AA:BB:CC:DD] (no rule - default allow)",
            make_lora_msg(unknown_dev, LoraMessageType::JoinRequest, 0, 2_000_000),
        ),
        (
            "Data from blocked device [DE:AD:00:01] (should be blocked)",
            make_lora_msg(blocked_dev, LoraMessageType::UnconfirmedUp, 5, 3_000_000),
        ),
        (
            "Replay attempt - same counter from allowed device (should alert)",
            make_lora_msg(allowed_dev, LoraMessageType::UnconfirmedUp, 1, 4_000_000),
        ),
        (
            "Confirmed uplink from allowed device (should be allowed)",
            make_lora_msg(allowed_dev, LoraMessageType::ConfirmedUp, 2, 5_000_000),
        ),
        (
            "Another uplink from allowed device (should be allowed)",
            make_lora_msg(allowed_dev, LoraMessageType::UnconfirmedUp, 3, 6_000_000),
        ),
    ];

    // ── Inspect each message ──────────────────────────────────────────
    println!("--- Inspecting LoRa messages ---\n");

    let mut total_alerts = 0u32;
    for (description, msg) in &messages {
        let result = monitor.inspect(msg);
        let status = if result.alert_count == 0 {
            "ALLOWED"
        } else {
            "ALERT"
        };
        println!("[{status}] {description}");
        for i in 0..result.alert_count as usize {
            println!("         -> {:?}", result.alerts[i]);
        }
        total_alerts += result.alert_count as u32;
    }

    // ── Summary ───────────────────────────────────────────────────────
    println!();
    println!("--- Summary ---");
    println!("Total inspected : {}", messages.len());
    println!("Total alerts    : {total_alerts}");
    println!();
    println!("=== Done ===");
}
