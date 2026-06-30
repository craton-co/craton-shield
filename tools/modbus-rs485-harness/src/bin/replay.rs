// SPDX-License-Identifier: Apache-2.0
//! RS485 Modbus RTU traffic replayer.
//!
//! Transmits a scripted battery of Modbus RTU ADUs over a USB-RS485 adapter:
//! a baseline of legitimate read traffic interleaved with the attack patterns
//! the strict monitor profile is designed to catch (illegal writes, dangerous
//! diagnostics, CRC corruption, unknown function codes). Each frame is sent
//! with an inter-frame gap so the monitor can delimit it by silence.
//!
//! Usage:
//!   vs-modbus-replay <PORT> [BAUD] [REPEATS]
//! Example:
//!   vs-modbus-replay COM6 19200 1

use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

use modbus_rs485_harness::{build_adu, build_request};

struct Frame {
    label: &'static str,
    expect: &'static str,
    bytes: Vec<u8>,
}

fn script() -> Vec<Frame> {
    let mut f = Vec::new();

    // --- Baseline: legitimate read traffic (strict profile allows reads) ---
    f.push(Frame {
        label: "legit ReadHoldingRegisters unit=1 addr=0 qty=10",
        expect: "ALLOW",
        bytes: build_request(1, 0x03, 0x0000, 10),
    });
    f.push(Frame {
        label: "legit ReadInputRegisters unit=1 addr=20 qty=4",
        expect: "ALLOW",
        bytes: build_request(1, 0x04, 0x0014, 4),
    });
    f.push(Frame {
        label: "legit ReadCoils unit=2 addr=0 qty=8",
        expect: "ALLOW",
        bytes: build_request(2, 0x01, 0x0000, 8),
    });

    // --- Attack: illegal write under a read-only policy ---
    f.push(Frame {
        label: "attack WriteSingleRegister (FC 0x06) unit=1 addr=100",
        expect: "DENY (UnknownFunctionCode)",
        bytes: build_request(1, 0x06, 0x0064, 0x00FF),
    });
    f.push(Frame {
        label: "attack WriteMultipleRegisters (FC 0x10) unit=1 addr=0 qty=5",
        expect: "DENY (UnknownFunctionCode)",
        bytes: build_request(1, 0x10, 0x0000, 5),
    });

    // --- Attack: dangerous diagnostic sub-function (Restart Comms 0x0001) ---
    // Under the read-only allowlist FC 0x08 is simply not permitted, so this is
    // denied as UnknownFunctionCode before the diagnostic sub-function path.
    f.push(Frame {
        label: "attack Diagnostics RestartCommunications (FC 0x08 sub 0x0001)",
        expect: "DENY (UnknownFunctionCode)",
        bytes: build_adu(1, &[0x08, 0x00, 0x01, 0x00, 0x00]),
    });

    // --- Attack: unknown / non-standard function code ---
    f.push(Frame {
        label: "attack unknown function code 0x41",
        expect: "DENY (UnknownFunctionCode)",
        bytes: build_request(1, 0x41, 0x0000, 1),
    });

    // --- Attack: corrupted CRC (well-formed read with last byte flipped) ---
    let mut bad_crc = build_request(1, 0x03, 0x0000, 10);
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0xFF; // corrupt the high CRC byte
    f.push(Frame {
        label: "attack corrupted CRC (bit-flip on the wire)",
        expect: "DENY (CrcFailure)",
        bytes: bad_crc,
    });

    f
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: vs-modbus-replay <PORT> [BAUD] [REPEATS]");
        eprintln!("example: vs-modbus-replay COM6 19200 1");
        std::process::exit(2);
    }
    let port_name = &args[1];
    let baud: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(19200);
    let repeats: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    let mut port = serialport::new(port_name, baud)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(200))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("error: could not open {port_name} @ {baud}: {e}");
            std::process::exit(1);
        });

    let frames = script();
    println!("vs-modbus-replay: sending on {port_name} @ {baud} 8N1, {repeats} pass(es)");
    println!("{} frames per pass\n", frames.len());

    let mut sent = 0u32;
    for pass in 1..=repeats {
        if repeats > 1 {
            println!("--- pass {pass}/{repeats} ---");
        }
        for fr in &frames {
            port.write_all(&fr.bytes).expect("serial write");
            port.flush().expect("serial flush");
            sent += 1;
            println!(
                "  -> {:<55} expect {:<28} raw={:02X?}",
                fr.label, fr.expect, fr.bytes
            );
            // Inter-frame gap >> Modbus t3.5 so the monitor delimits frames.
            sleep(Duration::from_millis(50));
        }
    }
    println!("\ndone: {sent} frames transmitted");
}
