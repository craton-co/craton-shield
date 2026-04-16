// SPDX-License-Identifier: Apache-2.0
//! Microbench for the CAN-FD Shannon entropy fast-path
//! (perf review 2026-05 item 6).
//!
//! Compares the cost of computing entropy for a representative
//! 64-byte CAN-FD payload via:
//!
//!   * the new small-payload routing (`shannon_entropy` for `n ≤ 64`),
//!   * the dense `[u32; 256]` fallback used for `n > 64`.
//!
//! The fast path avoids zeroing a 1 KB frequency table per frame.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use vs_can_monitor::testing_internals::{shannon_entropy, shannon_entropy_small};

/// Build a CAN-FD-sized random-looking payload of `n` bytes.
fn payload(n: usize) -> [u8; 64] {
    let mut data = [0u8; 64];
    // Deterministic LCG so re-runs are stable.
    let mut x: u32 = 0x1234_5678;
    for i in 0..n.min(64) {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data[i] = (x >> 24) as u8;
    }
    data
}

fn bench_entropy_can_fd_64(c: &mut Criterion) {
    let data = payload(64);
    let mut group = c.benchmark_group("can_monitor::shannon_entropy");
    group.throughput(Throughput::Bytes(64));
    group.bench_function("can_fd_64_fastpath", |b| {
        b.iter(|| black_box(shannon_entropy(black_box(&data[..64]))));
    });
    group.bench_function("can_fd_64_small_direct", |b| {
        b.iter(|| black_box(shannon_entropy_small(black_box(&data[..64]))));
    });
    group.finish();
}

fn bench_entropy_classic_8(c: &mut Criterion) {
    let data = payload(8);
    let mut group = c.benchmark_group("can_monitor::shannon_entropy");
    group.throughput(Throughput::Bytes(8));
    group.bench_function("classic_can_8", |b| {
        b.iter(|| black_box(shannon_entropy(black_box(&data[..8]))));
    });
    group.finish();
}

criterion_group!(benches, bench_entropy_can_fd_64, bench_entropy_classic_8);
criterion_main!(benches);
