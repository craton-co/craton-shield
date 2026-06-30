// SPDX-License-Identifier: Apache-2.0
//! Minimal MCP2515 CAN-controller driver implementing [`vs_hal::CanBus`].
//!
//! Targets the common "MCP2515 + TJA1050" breakout modules over SPI (mode 0,
//! up to 10 MHz). Classic CAN, 11-bit IDs, receive-all filter. This is the
//! bare-metal counterpart to the Linux SocketCAN HAL in `core/hal-linux`: it
//! lets the certified `vs-can-monitor` ingest frames straight off a physical
//! CAN bus on a Cortex-M target.
//!
//! Scope: enough of the MCP2515 to bring up a real bus and move classic CAN
//! frames in both directions. CAN-FD, hardware filters/masks, and interrupt
//! pins are intentionally out of scope (we poll `CANINTF`).
//!
//! This is a reusable driver module: it exposes more API (alternate crystal
//! timings, an error-poll helper) than any single firmware binary exercises.
#![allow(dead_code)]

use embedded_hal::blocking::spi::{Transfer, Write};
use embedded_hal::digital::v2::OutputPin;
use vs_hal::{CanBus, CanError, RawCanFrame};
use vs_types::VsError;

// ---- SPI instruction set (MCP2515 datasheet §12) ----
const CMD_RESET: u8 = 0xC0;
const CMD_READ: u8 = 0x03;
const CMD_WRITE: u8 = 0x02;
const CMD_BIT_MODIFY: u8 = 0x05;
const CMD_READ_STATUS: u8 = 0xA0;
const CMD_RTS_TXB0: u8 = 0x81; // request-to-send, TXB0

// ---- Registers ----
const REG_CANCTRL: u8 = 0x0F;
const REG_CANSTAT: u8 = 0x0E;
const REG_CNF3: u8 = 0x28;
const REG_CNF2: u8 = 0x29;
const REG_CNF1: u8 = 0x2A;
const REG_CANINTE: u8 = 0x2B;
const REG_CANINTF: u8 = 0x2C;
const REG_EFLG: u8 = 0x2D;
const REG_RXB0CTRL: u8 = 0x60;
const REG_TXB0CTRL: u8 = 0x30;
const REG_TXB0SIDH: u8 = 0x31;
const REG_RXB0SIDH: u8 = 0x61;

// ---- CANCTRL operation modes (REQOP bits 7:5) ----
const MODE_NORMAL: u8 = 0x00;
const MODE_CONFIG: u8 = 0x80;
const MODE_MASK: u8 = 0xE0;

// ---- CANINTF bits ----
const INTF_RX0IF: u8 = 0x01;

// ---- EFLG bits ----
const EFLG_TXBO: u8 = 0x20; // bus-off
const EFLG_TXEP: u8 = 0x10; // tx error-passive
const EFLG_RXEP: u8 = 0x08; // rx error-passive

/// CNF1/CNF2/CNF3 bit-timing triple for a given crystal + bitrate.
///
/// **The crystal frequency must match your module.** Most blue MCP2515
/// breakouts use an 8 MHz crystal; some use 16 MHz. Picking the wrong triple
/// yields no communication (every frame errors / nothing is received).
#[derive(Clone, Copy)]
pub struct BitTiming {
    pub cnf1: u8,
    pub cnf2: u8,
    pub cnf3: u8,
    pub bitrate: u32,
}

impl BitTiming {
    /// 500 kbit/s with an **8 MHz** crystal (MCP_8MHz_500kBPS).
    pub const KBPS500_XTAL8: Self = Self {
        cnf1: 0x00,
        cnf2: 0x90,
        cnf3: 0x02,
        bitrate: 500_000,
    };
    /// 500 kbit/s with a **16 MHz** crystal (MCP_16MHz_500kBPS).
    pub const KBPS500_XTAL16: Self = Self {
        cnf1: 0x00,
        cnf2: 0xF0,
        cnf3: 0x86,
        bitrate: 500_000,
    };
}

/// MCP2515 driver owning its SPI peripheral and chip-select line.
pub struct Mcp2515<SPI, CS> {
    spi: SPI,
    cs: CS,
    bitrate: u32,
    /// Bus-off state cached from the most recent `receive()` poll, so the
    /// `&self` [`CanBus::is_bus_off`] accessor can report it without a register
    /// read (which would require `&mut`).
    bus_off: bool,
}

impl<SPI, CS, E> Mcp2515<SPI, CS>
where
    SPI: Transfer<u8, Error = E> + Write<u8, Error = E>,
    CS: OutputPin,
{
    /// Wrap a configured SPI bus and CS pin. Call [`Self::init`] before use.
    pub fn new(spi: SPI, cs: CS) -> Self {
        Self {
            spi,
            cs,
            bitrate: 0,
            bus_off: false,
        }
    }

    fn select(&mut self) {
        let _ = self.cs.set_low();
    }
    fn deselect(&mut self) {
        let _ = self.cs.set_high();
    }

    fn write_reg(&mut self, addr: u8, val: u8) -> Result<(), VsError> {
        self.select();
        let r = self.spi.write(&[CMD_WRITE, addr, val]);
        self.deselect();
        r.map_err(|_| VsError::BusError)
    }

    fn read_reg(&mut self, addr: u8) -> Result<u8, VsError> {
        let mut buf = [CMD_READ, addr, 0x00];
        self.select();
        let r = self.spi.transfer(&mut buf);
        self.deselect();
        r.map_err(|_| VsError::BusError)?;
        Ok(buf[2])
    }

    fn bit_modify(&mut self, addr: u8, mask: u8, val: u8) -> Result<(), VsError> {
        self.select();
        let r = self.spi.write(&[CMD_BIT_MODIFY, addr, mask, val]);
        self.deselect();
        r.map_err(|_| VsError::BusError)
    }

    fn read_status(&mut self) -> Result<u8, VsError> {
        let mut buf = [CMD_READ_STATUS, 0x00];
        self.select();
        let r = self.spi.transfer(&mut buf);
        self.deselect();
        r.map_err(|_| VsError::BusError)?;
        Ok(buf[1])
    }

    fn reset(&mut self) -> Result<(), VsError> {
        self.select();
        let r = self.spi.write(&[CMD_RESET]);
        self.deselect();
        r.map_err(|_| VsError::BusError)
    }

    fn set_mode(&mut self, mode: u8) -> Result<(), VsError> {
        self.bit_modify(REG_CANCTRL, MODE_MASK, mode)?;
        // Verify the controller actually entered the requested mode.
        for _ in 0..1000 {
            if (self.read_reg(REG_CANSTAT)? & MODE_MASK) == mode {
                return Ok(());
            }
        }
        Err(VsError::Timeout)
    }

    /// Reset, program bit timing, accept-all receive, and enter normal mode.
    pub fn init(&mut self, timing: BitTiming) -> Result<(), VsError> {
        self.reset()?;
        // After reset the device is in configuration mode; confirm.
        self.set_mode(MODE_CONFIG)?;

        self.write_reg(REG_CNF1, timing.cnf1)?;
        self.write_reg(REG_CNF2, timing.cnf2)?;
        self.write_reg(REG_CNF3, timing.cnf3)?;

        // RXB0: receive any message (RXM bits 6:5 = 0b11 = filters off).
        self.write_reg(REG_RXB0CTRL, 0x60)?;
        // Enable the RX0 full interrupt flag (polled, not wired).
        self.write_reg(REG_CANINTE, INTF_RX0IF)?;
        self.bit_modify(REG_CANINTF, INTF_RX0IF, 0x00)?;

        self.bitrate = timing.bitrate;
        self.set_mode(MODE_NORMAL)?;
        Ok(())
    }
}

impl<SPI, CS, E> CanBus for Mcp2515<SPI, CS>
where
    SPI: Transfer<u8, Error = E> + Write<u8, Error = E>,
    CS: OutputPin,
{
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        // Refresh cached bus-off state for the &self is_bus_off() accessor.
        self.bus_off = self.read_reg(REG_EFLG)? & EFLG_TXBO != 0;

        // Poll the read-status bit for RXB0.
        if self.read_status()? & 0x01 == 0 {
            return Ok(None);
        }

        // Read SIDH, SIDL, EID8, EID0, DLC starting at RXB0SIDH (5 header bytes).
        let mut hdr = [CMD_READ, REG_RXB0SIDH, 0, 0, 0, 0, 0];
        self.select();
        let r = self.spi.transfer(&mut hdr);
        self.deselect();
        r.map_err(|_| VsError::BusError)?;

        let sidh = hdr[2];
        let sidl = hdr[3];
        let dlc = hdr[6] & 0x0F;
        let id = (u32::from(sidh) << 3) | (u32::from(sidl) >> 5);

        let mut frame = RawCanFrame::zeroed();
        frame.id = id;
        frame.dlc = dlc;
        frame.is_extended = false;
        frame.is_fd = false;

        let n = (dlc as usize).min(8);
        if n > 0 {
            // Data registers begin at RXB0D0 = RXB0SIDH + 5 = 0x66.
            let mut req = [0u8; 10];
            req[0] = CMD_READ;
            req[1] = REG_RXB0SIDH + 5;
            self.select();
            let r = self.spi.transfer(&mut req[..2 + n]);
            self.deselect();
            r.map_err(|_| VsError::BusError)?;
            frame.data[..n].copy_from_slice(&req[2..2 + n]);
        }

        // Clear RX0IF so the next frame can be detected.
        self.bit_modify(REG_CANINTF, INTF_RX0IF, 0x00)?;
        Ok(Some(frame))
    }

    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        let id = frame.id & 0x7FF; // classic 11-bit
        let sidh = (id >> 3) as u8;
        let sidl = ((id << 5) & 0xE0) as u8;
        let dlc = frame.dlc.min(8);

        // Load TXB0 header.
        self.write_reg(REG_TXB0SIDH, sidh)?;
        self.write_reg(REG_TXB0SIDH + 1, sidl)?; // SIDL
        self.write_reg(REG_TXB0SIDH + 2, 0)?; // EID8
        self.write_reg(REG_TXB0SIDH + 3, 0)?; // EID0
        self.write_reg(REG_TXB0SIDH + 4, dlc)?; // DLC

        // Load data bytes (TXB0D0 = TXB0SIDH + 5 = 0x36).
        for i in 0..dlc as usize {
            self.write_reg(REG_TXB0SIDH + 5 + i as u8, frame.data[i])?;
        }

        // Request to send TXB0.
        self.select();
        let r = self.spi.write(&[CMD_RTS_TXB0]);
        self.deselect();
        r.map_err(|_| VsError::BusError)?;

        // Best-effort wait for TXREQ to clear (TXB0CTRL bit 3).
        for _ in 0..2000 {
            if self.read_reg(REG_TXB0CTRL)? & 0x08 == 0 {
                return Ok(());
            }
        }
        Err(VsError::Timeout)
    }

    fn bitrate(&self) -> u32 {
        self.bitrate
    }

    fn is_bus_off(&self) -> bool {
        // Cached from the most recent receive() poll (see the `bus_off` field).
        self.bus_off
    }

    fn last_error(&self) -> CanError {
        // Register reads need &mut SPI, so the &self accessor returns the
        // conservative default; use [`poll_error`] for a live read.
        if self.bus_off {
            CanError::BusOff
        } else {
            CanError::None
        }
    }
}

/// Read EFLG and map it to a [`CanError`] for diagnostics (needs &mut).
pub fn poll_error<SPI, CS, E>(dev: &mut Mcp2515<SPI, CS>) -> Result<CanError, VsError>
where
    SPI: Transfer<u8, Error = E> + Write<u8, Error = E>,
    CS: OutputPin,
{
    let eflg = dev.read_reg(REG_EFLG)?;
    Ok(if eflg & EFLG_TXBO != 0 {
        CanError::BusOff
    } else if eflg & (EFLG_TXEP | EFLG_RXEP) != 0 {
        CanError::ErrorPassive
    } else {
        CanError::None
    })
}
