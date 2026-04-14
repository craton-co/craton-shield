// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone Modbus monitor example.
//!
//! Demonstrates configuring and using `ModbusMonitor` directly, without the
//! full `EmbeddedShield` runtime (which requires a `CryptoProvider`).
//!
//! Run with:
//! ```bash
//! cargo run -p vs-modbus-monitor --example modbus_gateway
//! ```

use vs_modbus_monitor_emb::{FunctionPolicy, ModbusMonitor, UnitAction};
use vs_types_embedded::{IpAction, IpAddress, ModbusFunction, ModbusRtuMessage, ModbusTcpMessage};

fn main() {
    let mut monitor = ModbusMonitor::new();

    // Allow unit ID 1 with read-only access to registers 0-999, rate limit 50 msg/s.
    monitor
        .add_rule(1, UnitAction::Allow, FunctionPolicy::ReadOnly, 0, 999, 50)
        .expect("add unit 1 rule");

    // Allow unit ID 2 with full access.
    monitor
        .add_rule(2, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 100)
        .expect("add unit 2 rule");

    // Block unit ID 247 (broadcast/reserved).
    monitor
        .add_rule(247, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
        .expect("block unit 247");

    // IP filter: only allow 192.168.1.0/24 subnet.
    monitor
        .add_ip_filter([192, 168, 1, 0], 24, IpAction::Allow)
        .expect("add IP filter");

    // --- Simulate Modbus RTU messages ---
    println!("=== Modbus RTU ===");
    let rtu_messages: &[(u8, ModbusFunction, u16, u16)] = &[
        (1, ModbusFunction::ReadHoldingRegisters, 0, 10), // allowed
        (1, ModbusFunction::WriteSingleRegister, 100, 1), // blocked: read-only
        (2, ModbusFunction::WriteSingleRegister, 100, 1), // allowed: full access
        (247, ModbusFunction::ReadHoldingRegisters, 0, 10), // blocked: unit blocked
    ];

    for (i, (unit_id, function, register, quantity)) in rtu_messages.iter().enumerate() {
        let mut msg = ModbusRtuMessage::default();
        msg.unit_id = *unit_id;
        msg.function = *function;
        msg.register_addr = *register;
        msg.quantity = *quantity;
        msg.timestamp_us = (i as u64 + 1) * 1_000_000;

        let result = monitor.inspect_rtu(&msg);
        println!(
            "[{}] unit={:<3} fn={:<28?} reg={:<5} qty={:<3} => allowed={}, alerts={}",
            i + 1,
            unit_id,
            function,
            register,
            quantity,
            result.allowed,
            result.alert_count,
        );
    }

    // --- Simulate Modbus TCP messages ---
    println!("\n=== Modbus TCP ===");
    let tcp_messages: &[(u8, ModbusFunction, [u8; 4])] = &[
        (1, ModbusFunction::ReadHoldingRegisters, [192, 168, 1, 100]), // allowed
        (1, ModbusFunction::ReadHoldingRegisters, [10, 0, 0, 1]),      // blocked: IP
    ];

    for (i, (unit_id, function, src_ip)) in tcp_messages.iter().enumerate() {
        let mut msg = ModbusTcpMessage::default();
        msg.rtu.unit_id = *unit_id;
        msg.rtu.function = *function;
        msg.rtu.register_addr = 0;
        msg.rtu.quantity = 10;
        msg.rtu.timestamp_us = (i as u64 + 10) * 1_000_000;
        msg.src_ip = IpAddress::V4(*src_ip);
        msg.src_port = 502;

        let result = monitor.inspect_tcp(&msg);
        let ip_str = format!("{}.{}.{}.{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        println!(
            "[{}] unit={:<3} fn={:<28?} ip={:<15} => allowed={}, alerts={}",
            i + 1,
            unit_id,
            function,
            ip_str,
            result.allowed,
            result.alert_count,
        );
    }

    println!("\nTotal inspected: {}", monitor.total_inspected());
    println!("Total alerts:    {}", monitor.total_alerts());
}
