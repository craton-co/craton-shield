// SPDX-License-Identifier: Apache-2.0
//! Tier 2: real CAN hardware-in-the-loop on the NUCLEO-F767ZI.
//!
//! Two MCP2515 + TJA1050 modules sit on one physical CAN bus:
//!   * Node A (SPI1) is the IDS interface — its frames feed the certified
//!     `vs-can-monitor` running on the Cortex-M7 via the `vs_hal::CanBus` impl.
//!   * Node B (SPI2) is a traffic generator that injects benign and attack
//!     frames onto the wire.
//!
//! The firmware drives a scripted scenario (baseline traffic then a flood),
//! processes every received frame through the IDS, and reports over the
//! ST-LINK virtual COM port (115200 8N1) how many frames crossed the real bus
//! and which raised alerts.

#![no_std]
#![no_main]

mod mcp2515;

use core::fmt::{self, Write};

use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use panic_halt as _;

use embedded_hal::spi::MODE_0;
use stm32f7xx_hal::{pac, prelude::*, spi::Spi};

use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_hal::{CanBus, RawCanFrame};
use vs_types::AlertSeverity;

use mcp2515::{BitTiming, Mcp2515};

const SYSCLK_HZ: u32 = 216_000_000;
const CYC_PER_US: u32 = SYSCLK_HZ / 1_000_000;

// >>> Set this to match YOUR module's crystal (8 MHz is the common default). <<<
const TIMING: BitTiming = BitTiming::KBPS500_XTAL8;

// --------------------------------------------------------------------------
// Serial output helper
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

fn delay_us(us: u32) {
    cortex_m::asm::delay(us.saturating_mul(CYC_PER_US));
}

/// Coarse monotonic microsecond clock built on the DWT cycle counter. Must be
/// `tick()`ed often enough that the 32-bit cycle counter does not wrap twice
/// between calls (~19 s at 216 MHz); the firmware calls it every iteration.
struct MonoClock {
    last: u32,
    acc_us: u64,
}
impl MonoClock {
    fn new() -> Self {
        Self {
            last: DWT::cycle_count(),
            acc_us: 0,
        }
    }
    fn tick(&mut self) -> u64 {
        let now = DWT::cycle_count();
        let d = now.wrapping_sub(self.last);
        self.last = now;
        self.acc_us += (d / CYC_PER_US) as u64;
        self.acc_us
    }
}

fn to_can_frame(raw: &RawCanFrame) -> CanFrame {
    CanFrame {
        id: raw.id,
        is_extended: raw.is_extended,
        is_fd: raw.is_fd,
        dlc: raw.dlc,
        data: raw.data,
    }
}

#[entry]
fn main() -> ! {
    let dp = pac::Peripherals::take().unwrap();
    let mut cp = cortex_m::Peripherals::take().unwrap();

    let mut rcc = dp.RCC.constrain();
    let clocks = rcc.cfgr.sysclk(SYSCLK_HZ.Hz()).freeze();

    cp.DCB.enable_trace();
    cp.DWT.enable_cycle_counter();

    let gpioa = dp.GPIOA.split();
    let gpiob = dp.GPIOB.split();
    let gpiod = dp.GPIOD.split();

    // USART3 -> ST-LINK VCP (PD8 TX / PD9 RX, AF7).
    let serial = stm32f7xx_hal::serial::Serial::new(
        dp.USART3,
        (gpiod.pd8.into_alternate(), gpiod.pd9.into_alternate()),
        &clocks,
        stm32f7xx_hal::serial::Config {
            baud_rate: 115_200.bps(),
            ..Default::default()
        },
    );
    let (tx, _rx) = serial.split();
    let mut out = SerialOut(tx);

    let _ = writeln!(out, "\r\n==== Craton Shield CAN HIL (Tier 2) ====");
    let _ = writeln!(out, "board : NUCLEO-F767ZI, two MCP2515 on one CAN bus");
    let _ = writeln!(out, "bitrate: {} bit/s (crystal-dependent timing)", TIMING.bitrate);

    // SPI1 for node A: SCK PA5, MISO PA6, MOSI PA7.
    let spi1 = Spi::new(
        dp.SPI1,
        (
            gpioa.pa5.into_alternate(),
            gpioa.pa6.into_alternate(),
            gpioa.pa7.into_alternate(),
        ),
    )
    .enable::<u8>(MODE_0, 1_000_000.Hz(), &clocks, &mut rcc.apb2);
    let cs_a = gpiod.pd14.into_push_pull_output();

    // SPI2 for node B: SCK PB13, MISO PB14, MOSI PB15.
    let spi2 = Spi::new(
        dp.SPI2,
        (
            gpiob.pb13.into_alternate(),
            gpiob.pb14.into_alternate(),
            gpiob.pb15.into_alternate(),
        ),
    )
    .enable::<u8>(MODE_0, 1_000_000.Hz(), &clocks, &mut rcc.apb1);
    let cs_b = gpiob.pb12.into_push_pull_output();

    let mut node_a = Mcp2515::new(spi1, cs_a);
    let mut node_b = Mcp2515::new(spi2, cs_b);

    if node_a.init(TIMING).is_err() {
        fail(&mut out, "node A (IDS) MCP2515 init failed");
    }
    if node_b.init(TIMING).is_err() {
        fail(&mut out, "node B (traffic) MCP2515 init failed");
    }
    let _ = writeln!(out, "both MCP2515 controllers initialised OK\r\n");

    // IDS: monitor ID 0x100, flood threshold 2 ms, max DLC 8.
    let mut ids = CanMonitor::try_new([0x42u8; 16]).unwrap();
    ids.add_rule(CanRule {
        id: 1,
        id_mask: 0x7FF,
        id_filter: 0x100,
        min_interval_us: 2_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    })
    .ok();

    let mut clock = MonoClock::new();
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut alerts = 0u32;

    // Helper closure-like inline: send from B, then drain A into the IDS.
    macro_rules! send_and_inspect {
        ($id:expr, $dlc:expr, $gap_us:expr, $label:expr) => {{
            let mut f = RawCanFrame::zeroed();
            f.id = $id;
            f.dlc = $dlc;
            for i in 0..$dlc as usize {
                f.data[i] = 0xA0 | (i as u8);
            }
            if node_b.transmit(&f).is_ok() {
                sent += 1;
            }
            // Give the frame time to land in node A's RX buffer.
            delay_us(500);
            let ts = clock.tick();
            match node_a.receive() {
                Ok(Some(rx)) => {
                    received += 1;
                    let cf = to_can_frame(&rx);
                    if let Some(alert) = ids.process_frame(&cf, ts) {
                        alerts += 1;
                        let _ = writeln!(
                            out,
                            "  ALERT {:<18} id=0x{:03X} sev={:?} src=0x{:03X}",
                            $label, rx.id, alert.severity, alert.source_id
                        );
                    } else {
                        let _ = writeln!(out, "  ok    {:<18} id=0x{:03X} dlc={}", $label, rx.id, rx.dlc);
                    }
                }
                Ok(None) => {
                    let _ = writeln!(out, "  MISS  {:<18} (no frame received from bus)", $label);
                }
                Err(_) => {
                    let _ = writeln!(out, "  ERR   {:<18} (bus/SPI error on receive)", $label);
                }
            }
            delay_us($gap_us);
        }};
    }

    // Phase 1 — baseline: frames spaced 10 ms apart (above the 2 ms threshold).
    let _ = writeln!(out, "Phase 1: baseline traffic on ID 0x100 (10 ms spacing)");
    for _ in 0..5 {
        send_and_inspect!(0x100, 8, 10_000, "baseline");
    }

    // Phase 2 — flood: frames spaced ~300 us apart (below the threshold).
    let _ = writeln!(out, "\r\nPhase 2: flood on ID 0x100 (~0.3 ms spacing)");
    for _ in 0..12 {
        send_and_inspect!(0x100, 8, 300, "flood");
    }

    // Phase 3 — an unmonitored ID, just to show non-0x100 traffic flows too.
    let _ = writeln!(out, "\r\nPhase 3: traffic on unmonitored ID 0x200");
    for _ in 0..3 {
        send_and_inspect!(0x200, 8, 5_000, "other-id");
    }

    let _ = writeln!(out, "\r\n──────────── SUMMARY ────────────");
    let _ = writeln!(out, "frames sent (node B)     : {}", sent);
    let _ = writeln!(out, "frames received (node A) : {}", received);
    let _ = writeln!(out, "IDS alerts raised        : {}", alerts);
    if received == 0 {
        let _ = writeln!(out, "RESULT: NO BUS TRAFFIC — check wiring/termination/crystal timing");
    } else if alerts > 0 {
        let _ = writeln!(out, "RESULT: PASS — real CAN frames inspected on-chip, flood detected");
    } else {
        let _ = writeln!(out, "RESULT: frames flowed but no alert — check flood threshold vs timing");
    }
    let _ = writeln!(out, "==== complete ====");

    loop {
        cortex_m::asm::wfi();
    }
}

fn fail<T: embedded_hal::serial::Write<u8>>(out: &mut SerialOut<T>, msg: &str) -> ! {
    let _ = writeln!(out, "FATAL: {}", msg);
    let _ = writeln!(out, "(check 3V3/GND to both modules, SPI wiring, and CS pins)");
    loop {
        cortex_m::asm::wfi();
    }
}
