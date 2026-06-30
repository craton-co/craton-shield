// SPDX-License-Identifier: Apache-2.0
//! Shared Modbus RTU codec for the RS485 hardware test bench.
//!
//! The bench wires two USB-RS485 adapters together (A-A, B-B). One adapter
//! transmits raw Modbus RTU ADUs (the `vs-modbus-replay` binary); the other
//! captures the same bytes off the wire and feeds them into
//! [`vs_modbus_monitor_ind::ModbusMonitor`] (the `vs-modbus-monitor` binary).
//!
//! This module is the small amount of glue that the certified `#![no_std]`
//! monitor crate deliberately does not provide: turning a raw byte stream from
//! a serial port into the typed [`ModbusRtuFrame`] the monitor inspects.

use vs_types_ind::{ModbusFunctionCode, ModbusRtuFrame};

/// Standard Modbus RTU CRC-16 (poly 0xA001, init 0xFFFF), transmitted
/// low-byte-first on the wire.
#[must_use]
pub fn crc16_modbus(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in bytes {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Build a complete Modbus RTU ADU (`slave | pdu | crc_lo | crc_hi`) from a
/// slave address and PDU (function code + data). Used by the replayer to put
/// well-formed frames on the wire.
#[must_use]
pub fn build_adu(slave: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = Vec::with_capacity(pdu.len() + 3);
    adu.push(slave);
    adu.extend_from_slice(pdu);
    let crc = crc16_modbus(&adu);
    adu.push((crc & 0xFF) as u8); // CRC low byte first
    adu.push((crc >> 8) as u8);
    adu
}

/// Convenience: build a read/write-style request ADU
/// (`slave | fc | addr_hi | addr_lo | qty_hi | qty_lo`).
#[must_use]
pub fn build_request(slave: u8, fc: u8, addr: u16, qty: u16) -> Vec<u8> {
    let pdu = [
        fc,
        (addr >> 8) as u8,
        (addr & 0xFF) as u8,
        (qty >> 8) as u8,
        (qty & 0xFF) as u8,
    ];
    build_adu(slave, &pdu)
}

/// Errors that can occur while parsing a raw ADU captured off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than the minimum 4 bytes (slave + fc + 2 CRC) were captured.
    TooShort,
}

/// Parse a raw RTU ADU captured off the wire into a typed [`ModbusRtuFrame`].
///
/// The CRC is taken verbatim from the last two bytes (low-byte-first) and
/// `crc_provided` is set, so the monitor validates it against the recomputed
/// value — corrupted frames are detected, not silently fixed.
///
/// `start_address` and `quantity` are parsed from the first four data bytes
/// when present; for short PDUs they default to zero (the monitor's
/// function-code and address-rule checks treat them accordingly).
pub fn parse_adu(adu: &[u8], timestamp_us: u64) -> Result<ModbusRtuFrame, ParseError> {
    if adu.len() < 4 {
        return Err(ParseError::TooShort);
    }
    let slave = adu[0];
    let raw_fc = adu[1];
    let crc_lo = adu[adu.len() - 2];
    let crc_hi = adu[adu.len() - 1];
    let crc = u16::from(crc_lo) | (u16::from(crc_hi) << 8);

    // PDU = everything between the slave address and the 2-byte CRC.
    let pdu = &adu[1..adu.len() - 2];

    let data = &pdu[1..];
    let start_address = if data.len() >= 2 {
        (u16::from(data[0]) << 8) | u16::from(data[1])
    } else {
        0
    };
    let quantity = if data.len() >= 4 {
        (u16::from(data[2]) << 8) | u16::from(data[3])
    } else {
        0
    };

    Ok(ModbusRtuFrame::with_pdu(
        slave,
        ModbusFunctionCode::from_u8(raw_fc),
        raw_fc,
        start_address,
        quantity,
        pdu,
        crc,
        true,
        timestamp_us,
    ))
}
