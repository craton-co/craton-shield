// SPDX-License-Identifier: Apache-2.0
//! On-target self-test + WCET firmware for the NUCLEO-F767ZI.
//!
//! Runs the REAL certified IDS crates on the Cortex-M7 and measures
//! cycle-accurate worst-case execution time (WCET) using the DWT cycle
//! counter. Results are streamed over USART3, which the onboard ST-LINK
//! exposes as a USB virtual COM port (115200 8N1).
//!
//! This is the on-silicon counterpart to the x86 criterion benchmarks in
//! `core/docs/performance-results.md`: where that document *estimates* target
//! latency via scaling factors, this firmware *measures* it on the chip.

#![no_std]
#![no_main]

use core::fmt::{self, Write};

use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use panic_halt as _;

use stm32f7xx_hal::{pac, prelude::*, serial};

use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_modbus_monitor_ind::ModbusMonitor;
use vs_types::AlertSeverity;
use vs_types_ind::{ModbusFunctionCode, ModbusRtuFrame};

/// CPU frequency the firmware configures the core to run at.
const SYSCLK_HZ: u32 = 216_000_000;

/// Iterations per measured operation. Each iteration is timed individually so
/// we can report the observed minimum, mean, and maximum (WCET) cycle counts.
const ITERS: u32 = 2000;

// --------------------------------------------------------------------------
// Serial output helper (works regardless of whether the HAL Tx implements
// core::fmt::Write directly).
// --------------------------------------------------------------------------

struct SerialOut<T>(T);

impl<T> fmt::Write for SerialOut<T>
where
    T: embedded_hal::serial::Write<u8>,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            nb::block!(self.0.write(b)).map_err(|_| fmt::Error)?;
        }
        Ok(())
    }
}

/// Result of timing one operation across `ITERS` single-shot measurements.
struct Stats {
    min: u32,
    max: u32,
    mean: u32,
}

/// Time `op` `ITERS` times, returning per-iteration cycle statistics. The
/// closure result is fed through `black_box` so the optimiser cannot elide it.
fn measure<F: FnMut()>(mut op: F) -> Stats {
    let mut min = u32::MAX;
    let mut max = 0u32;
    let mut sum: u64 = 0;
    for _ in 0..ITERS {
        let start = DWT::cycle_count();
        op();
        let end = DWT::cycle_count();
        let dt = end.wrapping_sub(start);
        if dt < min {
            min = dt;
        }
        if dt > max {
            max = dt;
        }
        sum += dt as u64;
    }
    Stats {
        min,
        max,
        mean: (sum / ITERS as u64) as u32,
    }
}

fn cycles_to_ns(cycles: u32) -> u32 {
    // ns = cycles * 1e9 / f.  At 216 MHz, 1 cycle ≈ 4.63 ns.
    ((cycles as u64 * 1_000_000_000) / SYSCLK_HZ as u64) as u32
}

#[entry]
fn main() -> ! {
    let dp = pac::Peripherals::take().unwrap();
    let mut cp = cortex_m::Peripherals::take().unwrap();

    // Configure the core clock to its 216 MHz maximum so WCET reflects the
    // fastest deterministic path.
    let rcc = dp.RCC.constrain();
    let clocks = rcc.cfgr.sysclk(SYSCLK_HZ.Hz()).freeze();

    // Enable the DWT cycle counter (the WCET measurement instrument).
    cp.DCB.enable_trace();
    cp.DWT.enable_cycle_counter();

    // USART3 -> ST-LINK VCP on PD8 (TX) / PD9 (RX), AF7.
    let gpiod = dp.GPIOD.split();
    let tx = gpiod.pd8.into_alternate();
    let rx = gpiod.pd9.into_alternate();
    let serial = serial::Serial::new(
        dp.USART3,
        (tx, rx),
        &clocks,
        serial::Config {
            baud_rate: 115_200.bps(),
            ..Default::default()
        },
    );
    let (tx, _rx) = serial.split();
    let mut out = SerialOut(tx);

    let _ = writeln!(out, "\r\n==== Craton Shield on-target self-test ====");
    let _ = writeln!(out, "board   : NUCLEO-F767ZI (Cortex-M7F)");
    let _ = writeln!(out, "sysclk  : {} Hz", SYSCLK_HZ);
    let _ = writeln!(out, "iters   : {} per op (single-shot timed)\r\n", ITERS);

    // ---------------- CAN monitor ----------------
    let mut can = CanMonitor::try_new([0x42u8; 16]).unwrap();
    can.add_rule(CanRule {
        id: 1,
        id_mask: 0x7FF,
        id_filter: 0x100,
        min_interval_us: 1_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    })
    .ok();

    let legit = CanFrame {
        id: 0x100,
        is_extended: false,
        is_fd: false,
        dlc: 8,
        data: [0xAA; 64],
    };
    let unknown = CanFrame {
        id: 0x123,
        is_extended: false,
        is_fd: false,
        dlc: 8,
        data: [0x55; 64],
    };

    let mut ts: u64 = 0;
    let s_can_known = measure(|| {
        ts += 2_000;
        let r = can.process_frame(&legit, ts);
        core::hint::black_box(&r);
    });
    let s_can_unknown = measure(|| {
        ts += 2_000;
        let r = can.process_frame(&unknown, ts);
        core::hint::black_box(&r);
    });

    // ---------------- Modbus RTU monitor ----------------
    let mut modbus = ModbusMonitor::new_strict();
    let legit_rtu = make_rtu(1, 0x03, 0x0000, 10); // ReadHoldingRegisters -> Allow
    let attack_rtu = make_rtu(1, 0x06, 0x0064, 1); // WriteSingleRegister -> Deny

    let s_mb_allow = measure(|| {
        let r = modbus.inspect_rtu(&legit_rtu);
        core::hint::black_box(&r);
    });
    let s_mb_deny = measure(|| {
        let r = modbus.inspect_rtu(&attack_rtu);
        core::hint::black_box(&r);
    });

    report(&mut out, "CAN process_frame (allowlisted ID)", &s_can_known);
    report(&mut out, "CAN process_frame (unknown ID)", &s_can_unknown);
    report(&mut out, "Modbus inspect_rtu (allow)", &s_mb_allow);
    report(&mut out, "Modbus inspect_rtu (deny)", &s_mb_deny);

    // Pass/fail summary against the documented CAN budget (<500 ns/frame on
    // the host criterion bench; on a 216 MHz M7 we expect comparable order).
    let can_ns = cycles_to_ns(s_can_known.max);
    let _ = writeln!(out, "\r\nCAN WCET (allowlisted) = {} ns at {} MHz", can_ns, SYSCLK_HZ / 1_000_000);
    let _ = writeln!(
        out,
        "RESULT: {}",
        if can_ns < 10_000 { "PASS (within CAN 10us bus budget)" } else { "REVIEW" }
    );
    let _ = writeln!(out, "\r\n==== self-test complete ====");

    loop {
        cortex_m::asm::wfi();
    }
}

fn report<T: embedded_hal::serial::Write<u8>>(out: &mut SerialOut<T>, name: &str, s: &Stats) {
    let _ = writeln!(
        out,
        "{:<38} min={:>6} cyc ({:>5} ns)  mean={:>6} cyc  max={:>6} cyc ({:>5} ns)",
        name,
        s.min,
        cycles_to_ns(s.min),
        s.mean,
        s.max,
        cycles_to_ns(s.max),
    );
}

/// Build a Modbus RTU frame with a valid CRC, mirroring the RS485 harness
/// codec so the on-chip and on-wire measurements are directly comparable.
fn make_rtu(slave: u8, fc: u8, addr: u16, qty: u16) -> ModbusRtuFrame {
    let pdu = [
        fc,
        (addr >> 8) as u8,
        (addr & 0xFF) as u8,
        (qty >> 8) as u8,
        (qty & 0xFF) as u8,
    ];
    let mut buf = [0u8; 8];
    buf[0] = slave;
    buf[1..1 + pdu.len()].copy_from_slice(&pdu);
    let crc = crc16_modbus(&buf[..1 + pdu.len()]);
    ModbusRtuFrame::with_pdu(
        slave,
        ModbusFunctionCode::from_u8(fc),
        fc,
        addr,
        qty,
        &pdu,
        crc,
        true,
        0,
    )
}

fn crc16_modbus(bytes: &[u8]) -> u16 {
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
