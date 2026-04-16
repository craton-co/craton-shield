// SPDX-License-Identifier: Apache-2.0
//! Microbench for the `valid_count` short-circuit in `IdsEngine`
//! (perf review 2026-05 item 5).
//!
//! Measures the cost of `tick()` on a quiet engine (no live correlation
//! entries) — the common case for ECUs that are not currently under
//! attack. With the short-circuit in place this becomes a single integer
//! load + a small constant tail instead of a 32-slot linear scan.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use vs_can_monitor::CanMonitor;
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, DEFAULT_SIPHASH_KEYS};
use vs_ids_engine::IdsEngine;

fn make_engine() -> IdsEngine {
    let can = CanMonitor::default();
    let eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    IdsEngine::new(can, eth, 100_000)
}

fn bench_tick_quiet(c: &mut Criterion) {
    let mut engine = make_engine();
    let mut ts: u64 = 1_000_000;

    c.bench_function("ids_engine::tick_quiet_ring", |b| {
        b.iter(|| {
            ts = ts.wrapping_add(1_000);
            engine.tick(black_box(ts));
        });
    });
}

criterion_group!(benches, bench_tick_quiet);
criterion_main!(benches);
