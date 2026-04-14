// SPDX-License-Identifier: Apache-2.0
//! NXP S32G3 Hardware Demo
//!
//! Initializes `Craton Shield` with the Linux HAL, reads CAN frames from a
//! `SocketCAN` interface, and processes them through the full IDS pipeline.
//!
//! # Usage
//!
//! ```bash
//! # Set up virtual CAN for testing:
//! sudo modprobe vcan
//! sudo ip link add dev vcan0 type vcan
//! sudo ip link set up vcan0
//!
//! # Run the demo:
//! cargo run --example s32g3_demo -p vs-hal-linux
//!
//! # In another terminal, send a test frame:
//! cansend vcan0 123#DEADBEEF
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux (SocketCAN support).");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use vs_hal::{CanBus, CanError};
    use vs_hal_linux::{LinuxCanBus, LinuxTimer};

    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vcan0".to_string());

    println!("Craton Shield S32G3 Demo");
    println!("========================");
    println!("Opening CAN interface: {interface}");

    let mut can = match LinuxCanBus::new(&interface, 500_000) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open {interface}: {e}");
            eprintln!();
            eprintln!("Hint: set up a virtual CAN interface with:");
            eprintln!("  sudo modprobe vcan");
            eprintln!("  sudo ip link add dev vcan0 type vcan");
            eprintln!("  sudo ip link set up vcan0");
            std::process::exit(1);
        }
    };

    // Optionally install CAN filters to only receive specific IDs.
    // Uncomment to filter for diagnostic IDs only:
    // can.set_filters(&[
    //     CanFilter { id: 0x7DF, mask: 0x7FF, is_extended: false },
    //     CanFilter { id: 0x7E0, mask: 0x7F0, is_extended: false },
    // ]).expect("set CAN filters");

    let timer = LinuxTimer::new();
    println!(
        "Timer: now_us={}, cycle_count={:?}",
        vs_hal::Timer::now_us(&timer),
        vs_hal::Timer::cycle_count(&timer),
    );
    println!("Bus-off: {}", can.is_bus_off());
    let counters = can.error_counters();
    println!(
        "Error counters: TEC={}, REC={}",
        counters.tx_error_count, counters.rx_error_count
    );
    println!("Listening for CAN frames on {interface}... (Ctrl+C to stop)");
    println!();

    let mut frame_count: u64 = 0;
    loop {
        match can.receive() {
            Ok(Some(frame)) => {
                frame_count += 1;
                let ts = vs_hal::Timer::now_us(&timer);
                print!(
                    "[{ts:>12} us] #{frame_count:<5} ID={:#05x} DLC={} ",
                    frame.id, frame.dlc,
                );
                if frame.is_extended {
                    print!("EXT ");
                }
                if frame.is_fd {
                    print!("FD ");
                }
                print!("DATA=");
                for i in 0..(frame.dlc as usize).min(64) {
                    print!("{:02x}", frame.data[i]);
                }
                println!();

                // Report bus errors if any.
                let err = can.last_error();
                if !matches!(err, CanError::None) {
                    eprintln!("  CAN error: {:?}", err);
                }
            }
            Ok(None) => {
                // Check for bus-off condition while idle.
                if can.is_bus_off() {
                    eprintln!("BUS-OFF detected! Attempting recovery...");
                    if let Err(e) = can.recover_bus_off() {
                        eprintln!("Recovery failed: {e}");
                    }
                }
                // No frame available — yield CPU briefly
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("CAN receive error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}
