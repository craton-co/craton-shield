// SPDX-License-Identifier: Apache-2.0
//! Tests for the WCET statistics computation logic.
//!
//! These tests validate the `compute_stats` function that the WCET harness
//! relies on for min/max/mean/median/p99/p99.9/WCET calculations.

/// Mirrored from `benches/wcet_harness.rs` so we can unit-test independently.
/// Keep in sync with wcet_harness.rs — any changes here must be reflected there.
#[derive(Debug)]
struct WcetResult {
    operation: &'static str,
    min: u64,
    max: u64,
    mean: f64,
    median: u64,
    p99: u64,
    p999: u64,
    wcet: u64,
    budget_us: f64,
}

/// Safety margin added on top of observed max to estimate WCET.
/// Must match the constant in `benches/wcet_harness.rs`.
const WCET_MARGIN_PERCENT: u64 = 20;

fn compute_stats(name: &'static str, samples: &mut [u64], budget_us: f64) -> WcetResult {
    samples.sort_unstable();
    let n = samples.len();
    let min = samples[0];
    let max = samples[n - 1];
    // Use u128 to prevent overflow when summing large cycle counts.
    let sum: u128 = samples.iter().map(|&s| s as u128).sum();
    let mean = sum as f64 / n as f64;
    let median = samples[n / 2];
    let p99 = samples[(n as f64 * 0.99) as usize];
    let p999 = samples[((n as f64 * 0.999) as usize).min(n - 1)];
    let wcet = max + max / (100 / WCET_MARGIN_PERCENT);

    WcetResult {
        operation: name,
        min,
        max,
        mean,
        median,
        p99,
        p999,
        wcet,
        budget_us,
    }
}

#[test]
fn stats_min_max_on_sorted_input() {
    let mut samples = vec![10, 20, 30, 40, 50];
    let r = compute_stats("test", &mut samples, 10.0);
    assert_eq!(r.min, 10);
    assert_eq!(r.max, 50);
}

#[test]
fn stats_min_max_on_unsorted_input() {
    let mut samples = vec![50, 10, 40, 20, 30];
    let r = compute_stats("test", &mut samples, 10.0);
    assert_eq!(r.min, 10);
    assert_eq!(r.max, 50);
}

#[test]
fn stats_mean_computation() {
    let mut samples = vec![10, 20, 30, 40, 50];
    let r = compute_stats("test", &mut samples, 10.0);
    assert!((r.mean - 30.0).abs() < f64::EPSILON);
}

#[test]
fn stats_median_odd_count() {
    let mut samples = vec![5, 1, 3, 2, 4];
    let r = compute_stats("test", &mut samples, 5.0);
    // Sorted: [1,2,3,4,5], median at index 2 = 3
    assert_eq!(r.median, 3);
}

#[test]
fn stats_median_even_count() {
    let mut samples = vec![10, 40, 20, 30];
    let r = compute_stats("test", &mut samples, 5.0);
    // Sorted: [10,20,30,40], median at index 2 = 30
    assert_eq!(r.median, 30);
}

#[test]
fn stats_p99_on_100_elements() {
    // 100 elements: 1..=100
    let mut samples: Vec<u64> = (1..=100).collect();
    let r = compute_stats("test", &mut samples, 5.0);
    // p99 index = (100 * 0.99) as usize = 99, value = 100
    assert_eq!(r.p99, 100);
}

#[test]
fn stats_p999_on_1000_elements() {
    let mut samples: Vec<u64> = (1..=1000).collect();
    let r = compute_stats("test", &mut samples, 5.0);
    // p999 index = (1000 * 0.999) as usize = 999, value = 1000
    assert_eq!(r.p999, 1000);
}

#[test]
fn stats_wcet_is_max_plus_20_percent() {
    let mut samples = vec![100, 200, 300, 400, 500];
    let r = compute_stats("test", &mut samples, 10.0);
    // WCET = 500 + 500/5 = 600
    assert_eq!(r.wcet, 600);
}

#[test]
fn stats_wcet_margin_rounding() {
    // max = 7, wcet = 7 + 7/5 = 7 + 1 = 8 (integer division)
    let mut samples = vec![1, 3, 5, 7];
    let r = compute_stats("test", &mut samples, 5.0);
    assert_eq!(r.max, 7);
    assert_eq!(r.wcet, 8);
}

#[test]
fn stats_operation_name_preserved() {
    let mut samples = vec![1, 2, 3];
    let r = compute_stats("can_frame_test", &mut samples, 10.0);
    assert_eq!(r.operation, "can_frame_test");
}

#[test]
fn stats_budget_preserved() {
    let mut samples = vec![1, 2, 3];
    let r = compute_stats("test", &mut samples, 42.5);
    assert!((r.budget_us - 42.5).abs() < f64::EPSILON);
}

#[test]
fn stats_single_element() {
    let mut samples = vec![100];
    let r = compute_stats("single", &mut samples, 5.0);
    assert_eq!(r.min, 100);
    assert_eq!(r.max, 100);
    assert_eq!(r.median, 100);
    assert_eq!(r.p99, 100);
    assert_eq!(r.p999, 100);
    assert_eq!(r.wcet, 120);
    assert!((r.mean - 100.0).abs() < f64::EPSILON);
}

#[test]
fn stats_all_same_values() {
    let mut samples = vec![42; 100];
    let r = compute_stats("constant", &mut samples, 5.0);
    assert_eq!(r.min, 42);
    assert_eq!(r.max, 42);
    assert_eq!(r.median, 42);
    assert!((r.mean - 42.0).abs() < f64::EPSILON);
    assert_eq!(r.wcet, 50); // 42 + 42/5 = 42 + 8 = 50
}
