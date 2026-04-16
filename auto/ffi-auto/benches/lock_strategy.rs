// SPDX-License-Identifier: Apache-2.0
//! Microbench for the `vs_auto_set_lock_strategy()` opt-in
//! (perf review 2026-05 item 4).
//!
//! The set/get pair is implemented over a relaxed-loaded `AtomicU32`
//! so that every `submit_*` entry point can branch on the strategy
//! without paying lock or syscall costs. This bench measures the
//! observed overhead of:
//!
//!   * a single `vs_auto_get_lock_strategy()` call,
//!   * a `vs_auto_set_lock_strategy()` toggle.
//!
//! Both must complete in well under a microsecond — if they regress
//! the per-frame cost balloons even on the "global" strategy.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use vs_ffi_auto::{
    vs_auto_get_lock_strategy, vs_auto_set_lock_strategy, VS_LOCK_STRATEGY_GLOBAL,
    VS_LOCK_STRATEGY_PER_SUBSYSTEM,
};

fn bench_lock_strategy_atomic(c: &mut Criterion) {
    let mut group = c.benchmark_group("ffi_auto::lock_strategy");
    group.bench_function("get", |b| {
        b.iter(|| black_box(vs_auto_get_lock_strategy()));
    });
    group.bench_function("set_toggle", |b| {
        let mut flip = false;
        b.iter(|| {
            flip = !flip;
            let s = if flip {
                VS_LOCK_STRATEGY_PER_SUBSYSTEM
            } else {
                VS_LOCK_STRATEGY_GLOBAL
            };
            black_box(vs_auto_set_lock_strategy(black_box(s)));
        });
    });
    // Restore default.
    let _ = vs_auto_set_lock_strategy(VS_LOCK_STRATEGY_GLOBAL);
    group.finish();
}

criterion_group!(benches, bench_lock_strategy_atomic);
criterion_main!(benches);
