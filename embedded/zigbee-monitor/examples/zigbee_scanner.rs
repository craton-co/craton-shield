// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone example demonstrating `ZigbeeMonitor` directly.
//!
//! This example creates a Zigbee monitor with PAN-ID-aware address rules
//! and frame type filtering, then simulates several Zigbee frames to show
//! how the monitor detects unauthorized devices and anomalous traffic.
//!
//! Run with:
//! ```sh
//! cargo run -p vs-zigbee-monitor --example zigbee_scanner
//! ```

use vs_types_embedded::{ZigbeeFrame, ZigbeeFrameType};
use vs_zigbee_monitor::{AddrAction, ZigbeeMonitor};

fn make_frame(
    src_addr: u16,
    dst_addr: u16,
    pan_id: u16,
    frame_type: ZigbeeFrameType,
    ts_us: u64,
) -> ZigbeeFrame {
    ZigbeeFrame {
        src_pan_id: pan_id,
        src_addr,
        dst_addr,
        cluster_id: 0x0006, // On/Off cluster
        frame_type,
        payload_len: 4,
        timestamp_us: ts_us,
    }
}

fn main() {
    println!("=== Craton Shield - Zigbee Scanner Monitor Example ===\n");

    // ── Create and configure the monitor ──────────────────────────────
    let mut monitor = ZigbeeMonitor::new();

    // Address rules: (address, PAN ID, action, max_rate_per_sec)
    let _ = monitor.add_rule(0x0001, 0x1234, AddrAction::Allow, 100); // coordinator
    let _ = monitor.add_rule(0x0002, 0x1234, AddrAction::Allow, 100); // sensor node
    let _ = monitor.add_rule(0xFFFF, 0x1234, AddrAction::Block, 0); // broadcast

    // Allow all frame types (bitmask: beacon=1, data=2, ack=4, command=8 => 0x0F)
    monitor.set_allowed_frame_types(0x0F);

    println!("Monitor configured:");
    println!("  PAN 0x1234, 0x0001 (coord)  -> allow, 100/s");
    println!("  PAN 0x1234, 0x0002 (sensor) -> allow, 100/s");
    println!("  PAN 0x1234, 0xFFFF (bcast)  -> block");
    println!("  Frame types: all allowed");
    println!();

    // ── Build simulated frames ────────────────────────────────────────
    let frames: Vec<(&str, ZigbeeFrame)> = vec![
        (
            "Data from coordinator 0x0001, PAN 0x1234 (should be allowed)",
            make_frame(0x0001, 0x0002, 0x1234, ZigbeeFrameType::Data, 1_000_000),
        ),
        (
            "Beacon from sensor 0x0002, PAN 0x1234 (should be allowed)",
            make_frame(0x0002, 0xFFFF, 0x1234, ZigbeeFrameType::Beacon, 2_000_000),
        ),
        (
            "Data from broadcast 0xFFFF, PAN 0x1234 (should be blocked)",
            make_frame(0xFFFF, 0x0001, 0x1234, ZigbeeFrameType::Data, 3_000_000),
        ),
        (
            "Data from unknown 0x00AA, PAN 0x1234 (no rule - default allow)",
            make_frame(0x00AA, 0x0001, 0x1234, ZigbeeFrameType::Data, 4_000_000),
        ),
        (
            "Data from coord 0x0001, wrong PAN 0x5678 (should alert)",
            make_frame(0x0001, 0x0002, 0x5678, ZigbeeFrameType::Data, 5_000_000),
        ),
        (
            "Command from coordinator 0x0001, PAN 0x1234 (should be allowed)",
            make_frame(0x0001, 0x0002, 0x1234, ZigbeeFrameType::Command, 6_000_000),
        ),
    ];

    // ── Inspect each frame ────────────────────────────────────────────
    println!("--- Inspecting Zigbee frames ---\n");

    let mut total_alerts = 0u32;
    for (description, frame) in &frames {
        let result = monitor.inspect(frame);
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
    println!("Total inspected : {}", frames.len());
    println!("Total alerts    : {total_alerts}");
    println!();
    println!("=== Done ===");
}
