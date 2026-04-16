// SPDX-License-Identifier: Apache-2.0
//! Microbench for the `BatchReceive` per-frame translation cost
//! (perf review 2026-05 item 2).
//!
//! Cannot bench the `recvmmsg(2)` syscall itself without a real
//! `SocketCAN` interface, but we can measure the per-frame translation
//! that the batch path performs after the syscall returns — this is the
//! cost that scales with batch size on top of the fixed syscall overhead.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use vs_hal::RawCanFrame;

/// Standalone copy of the kernel CAN-FD layout that `recv_batch_impl`
/// reads from. Mirrors `KernelCanFdFrame` in `core/hal-linux/src/can.rs`
/// but is reproduced here so the bench does not need to dip into the
/// crate's private surface.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelCanFdFrame {
    can_id: u32,
    len: u8,
    flags: u8,
    res0: u8,
    res1: u8,
    data: [u8; 64],
}

const CAN_EFF_FLAG: u32 = 0x8000_0000;
const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;
const CAN_SFF_MASK: u32 = 0x0000_07FF;

fn translate(kf: &KernelCanFdFrame) -> RawCanFrame {
    let is_extended = kf.can_id & CAN_EFF_FLAG != 0;
    let id = if is_extended {
        kf.can_id & CAN_EFF_MASK
    } else {
        kf.can_id & CAN_SFF_MASK
    };
    let mut frame = RawCanFrame::zeroed();
    frame.id = id;
    frame.dlc = kf.len;
    frame.is_extended = is_extended;
    frame.is_fd = true;
    let copy_len = (kf.len as usize).min(64);
    frame.data[..copy_len].copy_from_slice(&kf.data[..copy_len]);
    frame
}

fn bench_batch_translation(c: &mut Criterion) {
    let mut batch: [KernelCanFdFrame; 16] = [KernelCanFdFrame {
        can_id: 0,
        len: 0,
        flags: 0,
        res0: 0,
        res1: 0,
        data: [0u8; 64],
    }; 16];
    for (i, k) in batch.iter_mut().enumerate() {
        k.can_id = 0x100 + i as u32;
        k.len = 64;
        for (j, b) in k.data.iter_mut().enumerate() {
            *b = ((i * 31 + j) & 0xFF) as u8;
        }
    }

    let mut group = c.benchmark_group("hal_linux::batch_receive");
    group.throughput(Throughput::Elements(16));
    group.bench_function("translate_x16_fd", |b| {
        b.iter(|| {
            let mut out: [RawCanFrame; 16] = [RawCanFrame::zeroed(); 16];
            for i in 0..16 {
                out[i] = translate(black_box(&batch[i]));
            }
            black_box(out);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_batch_translation);
criterion_main!(benches);
