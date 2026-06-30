// SPDX-License-Identifier: Apache-2.0
//! Offline (no-hardware) validation of the codec + monitor wiring.
//!
//! Builds the same ADUs the replayer transmits, parses them exactly as the
//! monitor tap would after capturing them off the wire, and runs them through
//! the strict `ModbusMonitor` profile. This proves the glue is correct before
//! any physical RS485 link is involved, and documents the expected verdicts.

use modbus_rs485_harness::{build_adu, build_request, crc16_modbus, parse_adu};
use vs_modbus_monitor_ind::{ModbusMonitor, Verdict};

fn verdict_of(monitor: &mut ModbusMonitor, adu: &[u8]) -> Verdict {
    let frame = parse_adu(adu, 0).expect("parse");
    monitor.inspect_rtu(&frame).0
}

#[test]
fn crc_roundtrips_through_build_and_parse() {
    let adu = build_request(1, 0x03, 0x0000, 10);
    // Recomputing CRC over slave+pdu must match the trailing CRC bytes.
    let body = &adu[..adu.len() - 2];
    let crc = crc16_modbus(body);
    assert_eq!(adu[adu.len() - 2], (crc & 0xFF) as u8);
    assert_eq!(adu[adu.len() - 1], (crc >> 8) as u8);
    let frame = parse_adu(&adu, 0).expect("parse");
    assert_eq!(frame.slave_addr, 1);
    assert_eq!(frame.raw_function_code, 0x03);
    assert_eq!(frame.start_address, 0);
    assert_eq!(frame.quantity, 10);
}

#[test]
fn legit_reads_are_allowed() {
    let mut m = ModbusMonitor::new_strict();
    assert!(matches!(
        verdict_of(&mut m, &build_request(1, 0x03, 0x0000, 10)),
        Verdict::Allow
    ));
    assert!(matches!(
        verdict_of(&mut m, &build_request(2, 0x01, 0x0000, 8)),
        Verdict::Allow
    ));
}

#[test]
fn illegal_writes_are_denied() {
    let mut m = ModbusMonitor::new_strict();
    assert!(matches!(
        verdict_of(&mut m, &build_request(1, 0x06, 0x0064, 0x00FF)),
        Verdict::Deny { .. }
    ));
    assert!(matches!(
        verdict_of(&mut m, &build_request(1, 0x10, 0x0000, 5)),
        Verdict::Deny { .. }
    ));
}

#[test]
fn dangerous_diagnostics_denied() {
    let mut m = ModbusMonitor::new_strict();
    assert!(matches!(
        verdict_of(&mut m, &build_adu(1, &[0x08, 0x00, 0x01, 0x00, 0x00])),
        Verdict::Deny { .. }
    ));
}

#[test]
fn corrupted_crc_denied() {
    let mut m = ModbusMonitor::new_strict();
    let mut bad = build_request(1, 0x03, 0x0000, 10);
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    assert!(matches!(
        verdict_of(&mut m, &bad),
        Verdict::Deny { .. }
    ));
}

/// Prints the full scripted battery and its verdicts — run with
/// `cargo test -- --nocapture` to see the table the hardware run should match.
#[test]
fn print_expected_verdict_table() {
    let cases: &[(&str, Vec<u8>)] = &[
        ("legit ReadHoldingRegisters", build_request(1, 0x03, 0x0000, 10)),
        ("legit ReadInputRegisters", build_request(1, 0x04, 0x0014, 4)),
        ("legit ReadCoils", build_request(2, 0x01, 0x0000, 8)),
        ("attack WriteSingleRegister 0x06", build_request(1, 0x06, 0x0064, 0x00FF)),
        ("attack WriteMultipleRegisters 0x10", build_request(1, 0x10, 0x0000, 5)),
        ("attack Diagnostics Restart 0x08", build_adu(1, &[0x08, 0x00, 0x01, 0x00, 0x00])),
        ("attack unknown FC 0x41", build_request(1, 0x41, 0x0000, 1)),
        ("attack corrupted CRC", {
            let mut b = build_request(1, 0x03, 0x0000, 10);
            let l = b.len() - 1;
            b[l] ^= 0xFF;
            b
        }),
    ];
    let mut m = ModbusMonitor::new_strict();
    println!("\n=== expected verdict table (strict profile) ===");
    for (label, adu) in cases {
        let frame = parse_adu(adu, 0).expect("parse");
        let (v, r) = m.inspect_rtu(&frame);
        println!("  {label:<38} => {v:?}  (alerts={})", r.alert_count);
    }
    println!("===============================================\n");
}
