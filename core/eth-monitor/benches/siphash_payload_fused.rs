// SPDX-License-Identifier: Apache-2.0
//! Criterion bench for the fused 4-lane SipHash-2-4 payload hash.
//!
//! Compares:
//! - `vs_eth_monitor::bench_compute_payload_hash` — the fused single-pass
//!   implementation that walks the payload once and feeds each 8-byte block
//!   to all four lanes.
//! - `vs_types::siphash_payload_hash` — the naive 4× implementation that
//!   walks the payload four separate times.
//!
//! For Ethernet payloads in the 64..1500 byte range, the fused version should
//! be measurably faster on cold-cache inputs because it reads each payload
//! byte once instead of four times.
//!
//! Run with:  `cargo bench -p vs-eth-monitor --features bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vs_eth_monitor::{bench_compute_payload_hash, DEFAULT_SIPHASH_KEYS};

fn make_payload(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    for (i, b) in v.iter_mut().enumerate() {
        *b = ((i as u8).wrapping_mul(31)).wrapping_add(7);
    }
    v
}

fn bench_fused_vs_naive(c: &mut Criterion) {
    let payloads = [
        ("eth_64", make_payload(64)),
        ("eth_512", make_payload(512)),
        ("eth_1500", make_payload(1500)),
    ];

    let mut group = c.benchmark_group("eth_siphash_payload");
    for (label, p) in &payloads {
        let bytes = p.as_slice();
        group.bench_function(format!("{label}_fused"), |b| {
            b.iter(|| {
                let h =
                    bench_compute_payload_hash(black_box(bytes), black_box(&DEFAULT_SIPHASH_KEYS));
                black_box(h);
            });
        });
        group.bench_function(format!("{label}_naive_x4"), |b| {
            b.iter(|| {
                let h = vs_types::siphash_payload_hash(
                    black_box(bytes),
                    black_box(&DEFAULT_SIPHASH_KEYS),
                );
                black_box(h);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fused_vs_naive);
criterion_main!(benches);
