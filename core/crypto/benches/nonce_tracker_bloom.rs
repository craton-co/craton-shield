// SPDX-License-Identifier: Apache-2.0
//! Criterion bench for the NonceTracker Bloom-rebuild fast path.
//!
//! Validates that the periodic Bloom rebuild on eviction keeps the fast path
//! viable across high-churn workloads. Baseline (pre-fix) would have shown
//! Bloom saturation after ~256 unique nonces and a constant-time scan on
//! every subsequent insert.
//!
//! Run with:  `cargo bench -p vs-crypto --features bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vs_crypto::NonceTracker;

/// Number of unique nonces to insert in the high-churn workload. Sized well
/// past `NONCE_TRACKER_CAPACITY` to exercise repeated evictions.
const CHURN_N: u64 = 2_048;

fn nonce(i: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&i.to_le_bytes());
    n
}

fn bench_churn(c: &mut Criterion) {
    c.bench_function("nonce_tracker_unique_churn_2048", |b| {
        b.iter(|| {
            let mut t = NonceTracker::new();
            for i in 0..CHURN_N {
                // black_box prevents the compiler from hoisting the loop.
                let _ = t.check_and_record(black_box(&nonce(i)));
            }
            black_box(&t);
        });
    });
}

criterion_group!(benches, bench_churn);
criterion_main!(benches);
