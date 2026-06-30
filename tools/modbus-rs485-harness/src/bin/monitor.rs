// SPDX-License-Identifier: Apache-2.0
//! RS485 Modbus RTU monitor tap.
//!
//! Captures raw bytes from a USB-RS485 adapter, frames them into Modbus RTU
//! ADUs (by inter-frame silence), feeds each frame to the certified
//! `vs-modbus-monitor-ind` inspector, and prints the verdict. A per-frame
//! inspection-latency histogram is printed on exit (Ctrl-C).
//!
//! Usage:
//!   vs-modbus-monitor <PORT> [BAUD] [--permissive]
//! Example:
//!   vs-modbus-monitor COM5 19200

use std::io::Read;
use std::time::{Duration, Instant};

use modbus_rs485_harness::parse_adu;
use vs_modbus_monitor_ind::{ModbusMonitor, Verdict};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: vs-modbus-monitor <PORT> [BAUD] [--permissive]");
        eprintln!("example: vs-modbus-monitor COM5 19200");
        std::process::exit(2);
    }
    let port_name = &args[1];
    let baud: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(19200);
    let permissive = args.iter().any(|a| a == "--permissive");

    let mut monitor = if permissive {
        ModbusMonitor::new()
    } else {
        // Strict profile: read-only function codes, dangerous diagnostics
        // blocked, exception responses surfaced as Suspicious.
        ModbusMonitor::new_strict()
    };

    let mut port = serialport::new(port_name, baud)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(8))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("error: could not open {port_name} @ {baud}: {e}");
            std::process::exit(1);
        });

    // Exit automatically after this much silence *following* the first frame,
    // so the run ends on its own once the bounded replayer finishes.
    let idle_exit = Duration::from_secs(4);

    println!(
        "vs-modbus-monitor: listening on {port_name} @ {baud} 8N1 ({} profile)",
        if permissive { "permissive" } else { "strict" }
    );
    println!("waiting for traffic; exits {idle_exit:?} after the last frame (Ctrl-C also works)\n");

    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    // Counters for the end-of-run summary.
    let mut n_frames = 0u64;
    let mut n_allow = 0u64;
    let mut n_deny = 0u64;
    let mut n_suspicious = 0u64;
    let mut n_parse_err = 0u64;
    let mut latencies_ns: Vec<u128> = Vec::new();

    let mut last_frame_at: Option<Instant> = None;

    loop {
        // Auto-exit once traffic has been seen and the bus has gone quiet.
        if buf.is_empty() {
            if let Some(t) = last_frame_at {
                if t.elapsed() >= idle_exit {
                    break;
                }
            }
        }
        match port.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => buf.push(byte[0]),
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Inter-frame gap: a non-empty buffer is a complete ADU.
                if !buf.is_empty() {
                    last_frame_at = Some(Instant::now());
                    let ts = start.elapsed().as_micros() as u64;
                    match parse_adu(&buf, ts) {
                        Ok(frame) => {
                            let t0 = Instant::now();
                            let (verdict, result) = monitor.inspect_rtu(&frame);
                            latencies_ns.push(t0.elapsed().as_nanos());
                            n_frames += 1;
                            print_verdict(&buf, &verdict, result.alert_count);
                            match verdict {
                                Verdict::Allow => n_allow += 1,
                                Verdict::Deny { .. } => n_deny += 1,
                                Verdict::Suspicious { .. } => n_suspicious += 1,
                            }
                        }
                        Err(e) => {
                            n_parse_err += 1;
                            println!("  RAW {:02X?}  => PARSE ERROR: {e:?}", &buf[..]);
                        }
                    }
                    buf.clear();
                }
            }
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }

    print_summary(
        n_frames,
        n_allow,
        n_deny,
        n_suspicious,
        n_parse_err,
        &mut latencies_ns,
        monitor.total_inspected(),
        monitor.total_alerts(),
    );
}

fn print_verdict(raw: &[u8], verdict: &Verdict, alert_count: u8) {
    let tag = match verdict {
        Verdict::Allow => "ALLOW     ".to_string(),
        Verdict::Deny { reason } => format!("DENY [{reason:?}]"),
        Verdict::Suspicious { reason } => format!("SUSPECT [{reason:?}]"),
    };
    let slave = raw.first().copied().unwrap_or(0);
    let fc = raw.get(1).copied().unwrap_or(0);
    println!(
        "  {tag:<28} slave={slave:<3} fc=0x{fc:02X} alerts={alert_count}  raw={:02X?}",
        raw
    );
}

#[allow(clippy::too_many_arguments)]
fn print_summary(
    frames: u64,
    allow: u64,
    deny: u64,
    suspicious: u64,
    parse_err: u64,
    latencies_ns: &mut [u128],
    total_inspected: u64,
    total_alerts: u64,
) {
    println!("\n──────────── SUMMARY ────────────");
    println!("frames captured : {frames}");
    println!("  allow         : {allow}");
    println!("  deny          : {deny}");
    println!("  suspicious    : {suspicious}");
    println!("  parse errors  : {parse_err}");
    println!("monitor totals  : inspected={total_inspected} alerts={total_alerts}");

    if !latencies_ns.is_empty() {
        latencies_ns.sort_unstable();
        let n = latencies_ns.len();
        let sum: u128 = latencies_ns.iter().sum();
        let mean = sum / n as u128;
        let p50 = latencies_ns[n / 2];
        let p99 = latencies_ns[(n * 99 / 100).min(n - 1)];
        let max = latencies_ns[n - 1];
        println!(
            "inspect latency : mean={mean} ns  p50={p50} ns  p99={p99} ns  max={max} ns  (n={n})"
        );
    }
}
