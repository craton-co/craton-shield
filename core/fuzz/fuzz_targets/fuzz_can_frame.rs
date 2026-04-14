// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_can_monitor::{CanFrame, CanMonitor};

fuzz_target!(|data: &[u8]| {
    // Fuzz CAN frame ingestion with arbitrary bytes.
    if data.len() < 12 {
        return;
    }

    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let dlc = data[4];
    let is_extended = data[5] != 0;
    let is_fd = data[6] != 0;
    let timestamp_us = u32::from_le_bytes([data[7], data[8], data[9], data[10]]) as u64;

    let mut frame_data = [0u8; 64];
    let copy_len = (data.len() - 11).min(64);
    frame_data[..copy_len].copy_from_slice(&data[11..11 + copy_len]);

    let frame = CanFrame {
        id,
        is_extended,
        is_fd,
        dlc,
        data: frame_data,
    };

    let mut monitor = CanMonitor::default();

    // The monitor must not panic on any input.
    let _ = monitor.process_frame(&frame, timestamp_us);
});
