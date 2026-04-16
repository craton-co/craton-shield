// SPDX-License-Identifier: Apache-2.0
//! Basic IDS integration example.
//!
//! Demonstrates how to set up a CAN monitor with rules, process frames,
//! and route alerts through the IDS engine.
//!
//! ```
//! cargo run --example basic_ids
//! ```

use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, DEFAULT_SIPHASH_KEYS};
use vs_ids_engine::IdsEngine;
use vs_types::AlertSeverity;

fn main() {
    println!("Craton Shield — Basic IDS Example");
    println!("==================================\n");

    // 1. Create a CAN monitor and add detection rules
    let mut monitor = CanMonitor::default();

    // Rule: alert on CAN ID 0x100 if frames arrive faster than every 10ms
    let rule = CanRule {
        id: 0,
        id_mask: 0x7FF,
        id_filter: 0x100,
        min_interval_us: 10_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    };
    monitor
        .add_rule(rule)
        .expect("failed to add CAN rule for ID 0x100: duplicate or invalid filter");

    // 2. Create an IDS engine for alert correlation
    let eth_monitor = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    let mut ids = IdsEngine::new(monitor, eth_monitor, 100_000);

    // 3. Simulate incoming CAN frames
    let frame = CanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 8,
        data: [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };

    println!("Processing 20 CAN frames on ID 0x100...\n");

    let mut alert_count = 0u64;
    for i in 0..20u64 {
        // Simulate frames arriving every 1ms (faster than the 10ms rule threshold)
        let timestamp_us = i * 1_000;
        if let Some(alert) = ids.submit_can_frame(&frame, timestamp_us) {
            println!(
                "  [t={:>6}us] ALERT: severity={:?}, source_id=0x{:03X}",
                timestamp_us, alert.severity, alert.source_id
            );
            alert_count += 1;
        }
    }

    println!(
        "\nDone. IDS engine processed {} correlated alerts.",
        alert_count
    );
}
