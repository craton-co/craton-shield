// SPDX-License-Identifier: Apache-2.0
//! Microbench for the runtime-auto digest threading
//! (perf review 2026-05 item 10).
//!
//! Compares the per-alert cost of:
//!
//!   * the **old** path: SHA-256 over a 64-byte CAN-FD payload via the
//!     platform `CryptoProvider`,
//!   * the **new** path: reuse the SipHash-based digest computed by
//!     `vs_can_monitor::compute_can_payload_hash` (passed through
//!     `Option<PayloadHash>` to the alert builder).
//!
//! With the threaded digest the hot path skips the SHA-256 compression
//! function entirely.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use vs_can_monitor::compute_can_payload_hash;
use vs_crypto::{CryptoProvider, KeyId, KeyType, SoftwareCryptoProvider};
use vs_types::{PayloadHash, VsError};

/// Re-implementation of the old hashing pattern (`let mut hash_bytes = …; sha256(..)`)
/// for comparison purposes. Mirrors the boilerplate that was deduplicated
/// by `hash_or_degrade`.
#[inline(never)]
fn sha256_path(crypto: &SoftwareCryptoProvider, data: &[u8]) -> PayloadHash {
    let mut hash_bytes = [0u8; 32];
    let _ = crypto.sha256(data, &mut hash_bytes);
    PayloadHash(hash_bytes)
}

/// New path: caller already has the SipHash digest in hand.
#[inline(never)]
fn threaded_path(provided: &PayloadHash) -> PayloadHash {
    *provided
}

fn bench_digest_paths(c: &mut Criterion) {
    let crypto = SoftwareCryptoProvider::default();
    // CAN-FD-sized payload.
    let mut data = [0u8; 64];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x9D).wrapping_add(0x37);
    }
    let precomputed = compute_can_payload_hash(&data, 64);

    let mut group = c.benchmark_group("runtime_auto::digest");
    group.throughput(Throughput::Bytes(64));
    group.bench_function("sha256_old", |b| {
        b.iter(|| black_box(sha256_path(black_box(&crypto), black_box(&data[..64]))));
    });
    group.bench_function("threaded_new", |b| {
        b.iter(|| black_box(threaded_path(black_box(&precomputed))));
    });
    // Standalone SipHash cost (what the threaded path pays elsewhere).
    group.bench_function("siphash_precompute", |b| {
        b.iter(|| black_box(compute_can_payload_hash(black_box(&data), 64)));
    });
    group.finish();
}

criterion_group!(benches, bench_digest_paths);
criterion_main!(benches);

// Keep the `KeyId`/`KeyType` imports referenced so future bench
// expansions can reach for them without re-adding to the dev-deps line.
#[allow(dead_code)]
fn _unused_imports(_: KeyId, _: KeyType, _: VsError) {}
