// SPDX-License-Identifier: Apache-2.0
//! Industrial protocol boundary and edge-case tests.
//!
//! Covers parsing and inspection behaviour at the boundaries of the protocol
//! monitors: maximum-length PDUs, zero-length payloads, overflow sentinel
//! values, unknown/reserved function codes, and write-protection enforcement.
//! These tests complement the high-level integration tests in `full_stack.rs`
//! and the attack simulations in `attack_scenarios.rs`.

use vs_bacnet_monitor::{BacnetMonitor, BACNET_OBJECT_TYPE_ANY, BACNET_INSTANCE_ANY};
use vs_modbus_monitor_ind::ModbusMonitor;
use vs_s7comm_monitor::{S7commFrame, S7commFunction, S7commMonitor, S7commPduType};
use vs_types_ind::{BacnetFrame, ModbusTcpFrame, ModbusRtuFrame};

// ---------------------------------------------------------------------------
// Modbus TCP boundary tests
// ---------------------------------------------------------------------------

/// A Modbus TCP frame with maximum PDU length must be inspected without panic
/// and produce a consistent result.
#[test]
fn modbus_tcp_max_pdu_length_no_panic() {
    let mut mon = ModbusMonitor::new();
    let frame = ModbusTcpFrame {
        pdu_len: 253, // Modbus maximum PDU length
        ..ModbusTcpFrame::default()
    };
    let result = mon.inspect_tcp(&frame);
    // Permissive monitor — should allow by default.
    assert!(result.allowed, "max PDU length frame should be allowed in permissive mode");
}

/// A Modbus TCP frame with pdu_len exceeding the buffer size must be handled
/// safely — `pdu_len_overflow()` must return true and the monitor must not panic.
#[test]
fn modbus_tcp_pdu_len_overflow_handled_safely() {
    let frame = ModbusTcpFrame {
        pdu_len: 255, // Exceeds MAX_MODBUS_PDU_LEN (253)
        ..ModbusTcpFrame::default()
    };
    assert!(
        frame.pdu_len_overflow(),
        "pdu_len 255 should report overflow"
    );
    // valid_pdu_len() must clamp to the buffer maximum, not 255.
    assert!(
        frame.valid_pdu_len() <= 253,
        "valid_pdu_len() must clamp to MAX_MODBUS_PDU_LEN"
    );
    // Monitor must not panic inspecting an overflow frame.
    let mut mon = ModbusMonitor::new();
    let _ = mon.inspect_tcp(&frame);
}

/// A Modbus TCP frame with zero PDU length must be handled without panic.
#[test]
fn modbus_tcp_zero_pdu_length_no_panic() {
    let mut mon = ModbusMonitor::new();
    let frame = ModbusTcpFrame {
        pdu_len: 0,
        ..ModbusTcpFrame::default()
    };
    let _ = mon.inspect_tcp(&frame);
}

/// Strict mode must reject all TCP frames with an alert.
#[test]
fn modbus_tcp_strict_mode_rejects_all() {
    let mut mon = ModbusMonitor::new_strict();
    let frame = ModbusTcpFrame::default();
    let result = mon.inspect_tcp(&frame);
    assert!(!result.allowed, "strict mode must deny all frames");
    assert!(result.alert_count > 0, "strict mode must emit an alert");
}

// ---------------------------------------------------------------------------
// Modbus RTU boundary tests
// ---------------------------------------------------------------------------

/// A Modbus RTU frame with maximum PDU length must be inspected without panic.
#[test]
fn modbus_rtu_max_pdu_length_no_panic() {
    let mut mon = ModbusMonitor::new();
    let frame = ModbusRtuFrame {
        pdu_len: 253,
        ..ModbusRtuFrame::default()
    };
    let _ = mon.inspect_rtu(&frame);
}

/// A Modbus RTU frame with pdu_len exceeding buffer size is safe via clamping.
#[test]
fn modbus_rtu_pdu_len_overflow_handled_safely() {
    let frame = ModbusRtuFrame {
        pdu_len: 255,
        ..ModbusRtuFrame::default()
    };
    assert!(frame.pdu_len_overflow());
    assert!(frame.valid_pdu_len() <= 253);

    let mut mon = ModbusMonitor::new();
    let _ = mon.inspect_rtu(&frame);
}

// ---------------------------------------------------------------------------
// BACnet boundary tests
// ---------------------------------------------------------------------------

/// BACnet frame with payload_len exceeding the buffer size must be rejected
/// with an alert (overflow is a security concern — could indicate a crafted frame).
#[test]
fn bacnet_payload_len_overflow_rejected_with_alert() {
    let mut mon = BacnetMonitor::new();
    let mut frame = BacnetFrame::default();
    // Set payload_len beyond MAX_BACNET_PAYLOAD_LEN.
    // BacnetFrame::payload_len is u16; force overflow.
    frame.payload_len = 0xFFFF;

    let result = mon.inspect(&frame);
    assert!(
        !result.allowed,
        "BACnet frame with payload_len overflow must be rejected"
    );
    assert!(
        result.alert_count > 0,
        "BACnet overflow must emit at least one alert"
    );
}

/// BACnet frame with zero payload length must be handled without panic.
#[test]
fn bacnet_zero_payload_no_panic() {
    let mut mon = BacnetMonitor::new();
    let frame = BacnetFrame {
        service_choice: 12, // readProperty
        payload_len: 0,
        ..BacnetFrame::default()
    };
    let _ = mon.inspect(&frame);
}

/// A write operation (writeProperty = 15) to a read-only service rule must
/// be rejected with an alert.
#[test]
fn bacnet_write_to_read_only_rule_rejected() {
    let mut mon = BacnetMonitor::new();
    // Add a wildcard rule that is read-only.
    mon.add_service_rule(0xFF, true, 0)
        .expect("add wildcard read-only rule");

    let write_frame = BacnetFrame {
        service_choice: 15, // BACNET_WRITE_PROPERTY
        payload_len: 0,
        timestamp_us: 1000,
        ..BacnetFrame::default()
    };
    let result = mon.inspect(&write_frame);
    assert!(!result.allowed, "write to read-only rule must be rejected");
    assert!(result.alert_count > 0, "must emit a write-protection alert");
}

/// A read operation (readProperty = 12) to a read-only service rule must
/// be allowed.
#[test]
fn bacnet_read_to_read_only_rule_allowed() {
    let mut mon = BacnetMonitor::new();
    mon.add_service_rule(0xFF, true, 0)
        .expect("add wildcard read-only rule");

    let read_frame = BacnetFrame {
        service_choice: 12, // BACNET_READ_PROPERTY
        payload_len: 0,
        timestamp_us: 1000,
        ..BacnetFrame::default()
    };
    let result = mon.inspect(&read_frame);
    assert!(
        result.allowed,
        "read to read-only rule must be allowed; result: {:?}",
        result.allowed
    );
}

/// BACnet object-level deny rule must block access regardless of service rule.
#[test]
fn bacnet_object_deny_rule_blocks_read() {
    let mut mon = BacnetMonitor::new();
    // Deny all access to object type 5 (any instance).
    mon.add_object_rule(5, BACNET_INSTANCE_ANY, false, true)
        .expect("add deny rule for object type 5");

    // Build a readProperty frame with BACnetObjectIdentifier for type=5, instance=1.
    // BACnetObjectIdentifier encoding: 0x0C tag, 4 bytes = (type << 22) | instance.
    let oid_raw = (5u32 << 22) | 1u32;
    let oid_bytes = oid_raw.to_be_bytes();
    let mut frame = BacnetFrame {
        service_choice: 12, // readProperty
        payload_len: 5,
        timestamp_us: 500,
        ..BacnetFrame::default()
    };
    frame.payload[0] = 0x0C; // context tag 0, length 4
    frame.payload[1] = oid_bytes[0];
    frame.payload[2] = oid_bytes[1];
    frame.payload[3] = oid_bytes[2];
    frame.payload[4] = oid_bytes[3];

    let result = mon.inspect(&frame);
    assert!(!result.allowed, "deny rule must block read of object type 5");
    assert!(result.alert_count > 0, "must emit an alert for deny rule");
}

/// BACnet object-level wildcard rule (BACNET_OBJECT_TYPE_ANY) matches all types.
#[test]
fn bacnet_object_wildcard_type_matches_any() {
    let mut mon = BacnetMonitor::new();
    // Read-only rule for all object types.
    mon.add_object_rule(BACNET_OBJECT_TYPE_ANY, BACNET_INSTANCE_ANY, true, false)
        .expect("add wildcard read-only object rule");

    // writeProperty to any object should be blocked.
    let oid_raw = (7u32 << 22) | 42u32; // type=7, instance=42
    let oid_bytes = oid_raw.to_be_bytes();
    let mut frame = BacnetFrame {
        service_choice: 15, // writeProperty
        payload_len: 5,
        timestamp_us: 1000,
        ..BacnetFrame::default()
    };
    frame.payload[0] = 0x0C;
    frame.payload[1] = oid_bytes[0];
    frame.payload[2] = oid_bytes[1];
    frame.payload[3] = oid_bytes[2];
    frame.payload[4] = oid_bytes[3];

    let result = mon.inspect(&frame);
    assert!(
        !result.allowed,
        "wildcard read-only object rule must block write to any object type"
    );
}

/// Adding duplicate service choice rules must be rejected.
#[test]
fn bacnet_duplicate_service_rule_rejected() {
    let mut mon = BacnetMonitor::new();
    mon.add_service_rule(12, false, 0).expect("first add");
    let result = mon.add_service_rule(12, true, 0);
    assert!(
        result.is_err(),
        "duplicate service rule for same service_choice must be rejected"
    );
}

/// Filling service rule table to capacity must return ResourceExhausted on next add.
#[test]
fn bacnet_service_rule_table_full_returns_resource_exhausted() {
    use vs_types::VsError;
    let mut mon = BacnetMonitor::new();
    // MAX_SERVICE_RULES = 16; add 16 unique rules.
    for i in 0u8..16 {
        mon.add_service_rule(i, false, 0)
            .expect("should succeed for first 16 rules");
    }
    // The 17th rule must fail.
    let result = mon.add_service_rule(0xEE, false, 0);
    assert_eq!(
        result,
        Err(VsError::ResourceExhausted),
        "adding beyond MAX_SERVICE_RULES must return ResourceExhausted"
    );
}

// ---------------------------------------------------------------------------
// S7comm boundary tests
// ---------------------------------------------------------------------------

/// S7comm frames with unknown PDU type must be inspected without panic.
#[test]
fn s7comm_unknown_pdu_type_no_panic() {
    let mut mon = S7commMonitor::new();
    let frame = S7commFrame {
        pdu_type: S7commPduType::Unknown,
        raw_pdu_type: 0xFE,
        function: S7commFunction::ReadVar,
        raw_function: 0x04,
        pdu_ref: 0,
        timestamp_us: 0,
    };
    let result = mon.inspect(&frame);
    // Permissive mode — unknown type should still be allowed.
    assert!(
        result.allowed || result.alert_count > 0,
        "unknown PDU type must either be allowed or raise an alert — must not panic"
    );
}

/// S7comm strict mode must reject all frames.
#[test]
fn s7comm_strict_mode_rejects_all() {
    let mut mon = S7commMonitor::new_strict();
    let frame = S7commFrame::default();
    let result = mon.inspect(&frame);
    assert!(!result.allowed, "strict mode must deny all frames");
    assert!(result.alert_count > 0, "strict mode must emit an alert");
}

/// S7comm write operation (WriteVar) under a read-only rule must be rejected.
#[test]
fn s7comm_write_blocked_by_read_only_rule() {
    let mut mon = S7commMonitor::new();
    // Add a wildcard rule (0xFF) with read_only=true.
    mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0)
        .expect("add read-only wildcard rule");

    let write_frame = S7commFrame {
        pdu_type: S7commPduType::JobRequest,
        raw_pdu_type: 0x01,
        function: S7commFunction::WriteVar,
        raw_function: 0x05,
        pdu_ref: 1,
        timestamp_us: 1000,
    };
    let result = mon.inspect(&write_frame);
    assert!(!result.allowed, "WriteVar must be blocked by read-only rule");
    assert!(result.alert_count > 0, "must emit write-protection alert");
}

/// S7comm read operation (ReadVar) under a read-only rule must be allowed.
#[test]
fn s7comm_read_allowed_under_read_only_rule() {
    let mut mon = S7commMonitor::new();
    mon.add_rule(0xFF, 0xFFFF_FFFF, true, false, 0)
        .expect("add read-only wildcard rule");

    let read_frame = S7commFrame {
        pdu_type: S7commPduType::JobRequest,
        raw_pdu_type: 0x01,
        function: S7commFunction::ReadVar,
        raw_function: 0x04,
        pdu_ref: 2,
        timestamp_us: 2000,
    };
    let result = mon.inspect(&read_frame);
    assert!(result.allowed, "ReadVar must be allowed under read-only rule");
}

/// S7comm UserData PDU type blocked by block_szl rule.
#[test]
fn s7comm_userdata_blocked_by_szl_rule() {
    let mut mon = S7commMonitor::new();
    // block_szl=true blocks UserData PDU type.
    mon.add_rule(0xFF, 0xFFFF_FFFF, false, true, 0)
        .expect("add szl-blocking rule");

    let ud_frame = S7commFrame {
        pdu_type: S7commPduType::UserData,
        raw_pdu_type: 0x07,
        function: S7commFunction::ReadVar,
        raw_function: 0x04,
        pdu_ref: 0,
        timestamp_us: 500,
    };
    let result = mon.inspect(&ud_frame);
    assert!(!result.allowed, "UserData must be blocked by block_szl rule");
    assert!(result.alert_count > 0, "must emit SZL-block alert");
}

// ---------------------------------------------------------------------------
// Cross-protocol: alert ID monotonicity
// ---------------------------------------------------------------------------

/// Alert IDs must strictly increase across consecutive Modbus TCP inspections.
#[test]
fn modbus_tcp_alert_ids_strictly_increasing() {
    let mut mon = ModbusMonitor::new_strict();
    let frame = ModbusTcpFrame::default();

    let mut prev_id = 0u64;
    for ts in 1u64..=10 {
        let mut f = frame;
        f.timestamp_us = ts * 1000;
        let result = mon.inspect_tcp(&f);
        if result.alert_count > 0 {
            let id = result.alerts[0].id;
            assert!(
                id > prev_id,
                "alert ID must be strictly increasing: prev={prev_id}, got={id}"
            );
            prev_id = id;
        }
    }
    assert!(prev_id > 0, "at least one alert must have been generated");
}

/// Alert IDs must strictly increase across consecutive BACnet inspections.
#[test]
fn bacnet_alert_ids_strictly_increasing() {
    let mut mon = BacnetMonitor::new_strict();

    let mut prev_id = 0u64;
    for ts in 1u64..=10 {
        let frame = BacnetFrame {
            service_choice: 15, // writeProperty
            timestamp_us: ts * 1000,
            ..BacnetFrame::default()
        };
        let result = mon.inspect(&frame);
        if result.alert_count > 0 {
            let id = result.alerts[0].id;
            assert!(
                id > prev_id,
                "BACnet alert ID must be strictly increasing: prev={prev_id}, got={id}"
            );
            prev_id = id;
        }
    }
    assert!(prev_id > 0, "at least one BACnet alert must have been generated");
}
