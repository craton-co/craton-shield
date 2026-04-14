// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

/// Anomaly score returned by detectors.
#[derive(Debug, Clone, Copy, PartialEq)]
#[must_use]
pub struct AnomalyScore {
    pub z_score: f32,
    pub is_anomalous: bool,
}

/// Exponential Weighted Moving Average detector.
#[derive(Debug, Clone, Copy)]
pub struct EwmaDetector {
    mean: f32,
    variance: f32,
    alpha: f32,
    z_threshold: f32,
    count: u32,
    frozen: bool,
    freeze_remaining: u32,
    freeze_duration: u32,
    warmup_count: u32,
}

impl EwmaDetector {
    /// Create a new EWMA detector.
    ///
    /// Returns `None` if `alpha` is not in `(0.0, 1.0]` or `z_threshold` is
    /// negative or non-finite.
    pub fn new(alpha: f32, z_threshold: f32) -> Option<Self> {
        Self::with_options(alpha, z_threshold, 10, 5)
    }

    /// Create a new EWMA detector with configurable freeze duration and
    /// warm-up count.
    ///
    /// `freeze_duration` controls how many samples the baseline stays frozen
    /// after an anomaly is detected.  `warmup_count` is the minimum number of
    /// samples before the freeze mechanism activates (default 5).
    ///
    /// Returns `None` if `alpha` is not in `(0.0, 1.0]` or `z_threshold` is
    /// negative or non-finite.
    pub fn with_options(
        alpha: f32,
        z_threshold: f32,
        freeze_duration: u32,
        warmup_count: u32,
    ) -> Option<Self> {
        if !alpha.is_finite()
            || alpha <= 0.0
            || alpha > 1.0
            || !z_threshold.is_finite()
            || z_threshold < 0.0
        {
            return None;
        }
        Some(Self {
            mean: 0.0,
            variance: 0.0,
            alpha,
            z_threshold,
            count: 0,
            frozen: false,
            freeze_remaining: 0,
            freeze_duration,
            warmup_count,
        })
    }

    /// Feed a new sample into the detector and return its anomaly score.
    ///
    /// Returns `None` for the very first sample (baseline) or if `value` is
    /// non-finite (NaN / Inf are silently rejected to prevent detector
    /// poisoning).
    #[must_use]
    pub fn update(&mut self, value: f32) -> Option<AnomalyScore> {
        if !value.is_finite() {
            return None;
        }

        if self.count == 0 {
            self.mean = value;
            self.variance = 0.0;
            self.count = 1;
            return None;
        }

        // Compute z-score against the OLD mean/variance before updating.
        let diff = value - self.mean;
        let diff_abs = if diff < 0.0 { -diff } else { diff };

        let score = if self.variance > f32::EPSILON {
            let std_dev = sqrt_approx(self.variance);
            if std_dev > f32::EPSILON {
                let z_abs = diff_abs / std_dev;
                Some(AnomalyScore {
                    z_score: z_abs,
                    is_anomalous: z_abs > self.z_threshold,
                })
            } else {
                // Variance is positive but std_dev rounds to zero — any
                // measurable deviation is anomalous.
                let is_anom = diff_abs > f32::EPSILON;
                Some(AnomalyScore {
                    z_score: if is_anom { f32::MAX } else { 0.0 },
                    is_anomalous: is_anom,
                })
            }
        } else {
            // Zero variance (stationary signal). Any non-trivial deviation
            // from the mean is infinitely many standard deviations away.
            let is_anom = diff_abs > f32::EPSILON;
            Some(AnomalyScore {
                z_score: if is_anom { f32::MAX } else { 0.0 },
                is_anomalous: is_anom,
            })
        };

        // Check if this sample is anomalous and trigger freeze if so.
        // Only activate freeze after a warm-up period (count >= 5) so the
        // baseline has enough samples to be meaningful.
        if let Some(ref s) = score {
            if s.is_anomalous && !self.frozen && self.count >= self.warmup_count {
                self.frozen = true;
                self.freeze_remaining = self.freeze_duration;
            }
        }

        if self.frozen {
            // Do NOT update mean/variance while frozen.
            self.freeze_remaining = self.freeze_remaining.saturating_sub(1);
            if self.freeze_remaining == 0 {
                self.frozen = false;
            }
        } else {
            // Now update the statistics using the diff already computed above.
            self.count = self.count.saturating_add(1);
            self.mean += self.alpha * diff;
            let new_var = (1.0 - self.alpha) * (self.variance + self.alpha * diff * diff);
            // Clamp variance to prevent floating-point drift accumulation over
            // very long uptimes (millions of samples on always-on automotive ECUs).
            // A non-finite or negative variance would poison all future scores.
            self.variance = if new_var.is_finite() && new_var >= 0.0 {
                new_var
            } else {
                0.0
            };
        }

        score
    }

    pub fn mean(&self) -> f32 {
        self.mean
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    /// Set the number of samples the baseline stays frozen after an anomaly.
    pub fn set_freeze_duration(&mut self, duration: u32) {
        self.freeze_duration = duration;
    }

    /// Re-calibrate the detector baseline to the given value.
    ///
    /// On long-running systems (millions of samples), floating-point
    /// rounding errors can accumulate in the EWMA mean and variance.
    /// Calling this method periodically (e.g., every 1 million samples
    /// during a known-good steady-state window) resets the statistics to
    /// a fresh baseline, eliminating accumulated drift.
    ///
    /// The sample count is preserved so that freeze/warm-up logic is not
    /// affected.
    pub fn recalibrate(&mut self, baseline_value: f32) {
        if !baseline_value.is_finite() {
            return;
        }
        self.mean = baseline_value;
        self.variance = 0.0;
        self.frozen = false;
        self.freeze_remaining = 0;
    }

    /// Return the current variance estimate.
    pub fn variance(&self) -> f32 {
        self.variance
    }
}

/// Histogram-based frequency detector.
///
/// Values are mapped to bins via `(value as usize) % BINS`. When `BINS < 256`,
/// multiple byte values will collide into the same bin (e.g. with `BINS = 16`,
/// values `0`, `16`, `32`, … `240` all map to bin 0). Use `BINS = 256` for
/// per-byte-value resolution with no collisions.
#[derive(Debug, Clone)]
pub struct HistogramDetector<const BINS: usize> {
    counts: [u32; BINS],
    total: u32,
}

impl<const BINS: usize> HistogramDetector<BINS> {
    pub fn new() -> Self {
        const { assert!(BINS > 0, "BINS must be > 0") };
        Self {
            counts: [0u32; BINS],
            total: 0,
        }
    }

    /// Map a value to a bin index. Uses bit-mask when BINS is a power of two
    /// (single AND instruction) and falls back to modulo otherwise.
    #[inline]
    fn bin_index(value: u8) -> usize {
        if BINS.is_power_of_two() {
            (value as usize) & (BINS - 1)
        } else {
            (value as usize) % BINS
        }
    }

    pub fn observe(&mut self, value: u8) {
        let idx = Self::bin_index(value);
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }

    pub fn probability(&self, value: u8) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        let idx = Self::bin_index(value);
        self.counts[idx] as f32 / self.total as f32
    }

    pub fn is_anomalous(&self, value: u8, threshold: f32) -> bool {
        self.total > 0 && self.probability(value) < threshold
    }
}

impl<const BINS: usize> Default for HistogramDetector<BINS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Markov chain transition detector.
#[derive(Debug, Clone)]
pub struct MarkovDetector<const N: usize> {
    transition: [[u32; N]; N],
    row_totals: [u32; N],
}

impl<const N: usize> MarkovDetector<N> {
    pub fn new() -> Self {
        const { assert!(N > 0, "N must be > 0") };
        Self {
            transition: [[0u32; N]; N],
            row_totals: [0u32; N],
        }
    }

    /// Map a state index. Uses bit-mask when N is a power of two.
    #[inline]
    fn state_index(value: u8) -> usize {
        if N.is_power_of_two() {
            (value as usize) & (N - 1)
        } else {
            (value as usize) % N
        }
    }

    pub fn observe_transition(&mut self, from: u8, to: u8) {
        let f = Self::state_index(from);
        let t = Self::state_index(to);
        self.transition[f][t] = self.transition[f][t].saturating_add(1);
        self.row_totals[f] = self.row_totals[f].saturating_add(1);
    }

    pub fn score_transition(&self, from: u8, to: u8) -> f32 {
        let f = Self::state_index(from);
        let t = Self::state_index(to);
        let total = self.row_totals[f];
        if total == 0 {
            return 0.0;
        }
        self.transition[f][t] as f32 / total as f32
    }
}

impl<const N: usize> Default for MarkovDetector<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Approximate square root using Newton's method (no std required).
///
/// Uses a bit-manipulation trick to seed Newton's method with a good initial
/// guess, giving accurate results across the full f32 range in few iterations.
fn sqrt_approx(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    // Seed via IEEE-754 bit hack: halve the exponent for a ~1-bit-accurate guess.
    let mut guess = f32::from_bits((x.to_bits() >> 1) + 0x1FC0_0000);
    // 4 Newton iterations refine to full f32 precision from this seed.
    for _ in 0..4 {
        guess = 0.5 * (guess + x / guess);
    }
    guess
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;

    #[test]
    fn ewma_converges_stationary() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..100 {
            det.update(50.0);
        }
        let diff = (det.mean() - 50.0).abs();
        assert!(
            diff < 0.01,
            "mean should converge to 50.0, got {}",
            det.mean()
        );
    }

    #[test]
    fn ewma_detects_outlier() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..100 {
            det.update(10.0);
        }
        // Inject a large outlier
        let score = det.update(1000.0);
        assert!(score.is_some());
        let score = score.as_ref();
        assert!(
            score.is_some_and(|s| s.is_anomalous),
            "5-sigma outlier should be flagged"
        );
    }

    #[test]
    fn ewma_first_sample_returns_none() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        assert!(det.update(42.0).is_none());
    }

    // ---- Input validation tests ----

    #[test]
    fn ewma_rejects_zero_alpha() {
        assert!(EwmaDetector::new(0.0, 3.0).is_none());
    }

    #[test]
    fn ewma_rejects_negative_alpha() {
        assert!(EwmaDetector::new(-0.5, 3.0).is_none());
    }

    #[test]
    fn ewma_rejects_alpha_above_one() {
        assert!(EwmaDetector::new(1.1, 3.0).is_none());
    }

    #[test]
    fn ewma_rejects_nan_alpha() {
        assert!(EwmaDetector::new(f32::NAN, 3.0).is_none());
    }

    #[test]
    fn ewma_rejects_inf_threshold() {
        assert!(EwmaDetector::new(0.1, f32::INFINITY).is_none());
    }

    #[test]
    fn ewma_rejects_negative_threshold() {
        assert!(EwmaDetector::new(0.1, -1.0).is_none());
    }

    #[test]
    fn ewma_accepts_alpha_one() {
        assert!(EwmaDetector::new(1.0, 3.0).is_some());
    }

    #[test]
    fn ewma_accepts_threshold_zero() {
        assert!(EwmaDetector::new(0.1, 0.0).is_some());
    }

    #[test]
    fn ewma_nan_input_rejected() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        det.update(10.0);
        // NaN should be silently rejected, not poison the detector.
        assert!(det.update(f32::NAN).is_none());
        // Detector should still work after the NaN.
        let score = det.update(10.0);
        assert!(score.is_some());
    }

    #[test]
    fn ewma_inf_input_rejected() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        det.update(10.0);
        assert!(det.update(f32::INFINITY).is_none());
        assert!(det.update(f32::NEG_INFINITY).is_none());
        // Detector still healthy.
        let score = det.update(10.0);
        assert!(score.is_some());
    }

    // ---- Histogram tests ----

    #[test]
    fn histogram_new_value_is_anomalous() {
        let mut hist = HistogramDetector::<256>::new();
        // Observe byte 0x00 many times
        for _ in 0..100 {
            hist.observe(0x00);
        }
        // Never-seen byte should have probability 0
        assert!(hist.is_anomalous(0xFF, 0.01));
    }

    #[test]
    fn histogram_known_value_not_anomalous() {
        let mut hist = HistogramDetector::<256>::new();
        for _ in 0..100 {
            hist.observe(0x42);
        }
        assert!(!hist.is_anomalous(0x42, 0.01));
    }

    #[test]
    fn histogram_empty_probability_zero() {
        let hist = HistogramDetector::<256>::new();
        assert!((hist.probability(0) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn markov_score_untrained_is_zero() {
        let det = MarkovDetector::<16>::new();
        assert!((det.score_transition(0, 1) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn markov_learns_transitions() {
        let mut det = MarkovDetector::<16>::new();
        for _ in 0..10 {
            det.observe_transition(0, 1);
        }
        det.observe_transition(0, 2);

        let score_0_1 = det.score_transition(0, 1);
        let score_0_2 = det.score_transition(0, 2);
        assert!(
            score_0_1 > score_0_2,
            "0->1 should be more likely than 0->2"
        );
    }

    #[test]
    fn sqrt_approx_accuracy() {
        let result = sqrt_approx(4.0);
        assert!((result - 2.0).abs() < 0.001);

        let result = sqrt_approx(9.0);
        assert!((result - 3.0).abs() < 0.001);

        let result = sqrt_approx(0.0);
        assert!((result - 0.0).abs() < f32::EPSILON);
    }

    // ---- New tests below ----

    #[test]
    fn ewma_alpha_one_instant_tracking() {
        let mut det = EwmaDetector::new(1.0, 3.0).unwrap();
        det.update(10.0);
        det.update(20.0);
        // With alpha=1.0, mean should jump immediately to the latest value
        let diff = (det.mean() - 20.0).abs();
        assert!(
            diff < 0.01,
            "alpha=1.0 should track instantly, got mean={}",
            det.mean()
        );
    }

    #[test]
    fn ewma_alpha_very_small_slow_adaptation() {
        let mut det = EwmaDetector::new(0.01, 3.0).unwrap();
        det.update(0.0); // initial
        det.update(100.0);
        // With alpha=0.01, after one update from 0, mean should be close to 0 still
        let diff = det.mean().abs();
        assert!(
            diff < 5.0,
            "alpha=0.01 should adapt slowly, got mean={}",
            det.mean()
        );
    }

    #[test]
    fn ewma_z_threshold_zero_flags_everything() {
        let mut det = EwmaDetector::new(0.1, 0.0).unwrap();
        det.update(10.0); // initial, returns None
                          // Second sample identical to first - with zero variance, any diff > EPSILON is anomalous
                          // but same value means diff_abs ~ 0, so it won't be anomalous
                          // Let's feed a slightly different value
        let score = det.update(10.001);
        assert!(score.is_some());
        // z_threshold=0 means any z_score > 0 is anomalous
        assert!(
            score.unwrap().is_anomalous,
            "z_threshold=0 should flag deviations"
        );
    }

    #[test]
    fn ewma_negative_values_handled() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..50 {
            det.update(-100.0);
        }
        let diff = (det.mean() - (-100.0)).abs();
        assert!(
            diff < 1.0,
            "mean should converge to -100.0, got {}",
            det.mean()
        );
    }

    #[test]
    fn ewma_large_values_no_panic() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        let large = f32::MAX / 2.0;
        det.update(large);
        let score = det.update(large);
        // Should not panic; score may or may not be anomalous
        assert!(score.is_some());
    }

    #[test]
    fn histogram_one_bin() {
        let mut hist = HistogramDetector::<1>::new();
        // All values map to bin 0
        hist.observe(0);
        hist.observe(100);
        hist.observe(255);
        // All values have probability 1.0 (all in same bin)
        let prob = hist.probability(42);
        assert!((prob - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn histogram_256_bins() {
        let mut hist = HistogramDetector::<256>::new();
        // Observe each byte value once
        for i in 0..=255u8 {
            hist.observe(i);
        }
        // Each value should have probability 1/256
        let expected = 1.0 / 256.0;
        let prob = hist.probability(128);
        assert!((prob - expected).abs() < 0.001);
    }

    #[test]
    fn histogram_same_value_many_times_high_probability() {
        let mut hist = HistogramDetector::<256>::new();
        for _ in 0..1000 {
            hist.observe(0x42);
        }
        // 0x42 should have probability 1.0 (only value observed)
        let prob = hist.probability(0x42);
        assert!((prob - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn histogram_new_instance_clears_state() {
        let mut hist = HistogramDetector::<256>::new();
        for _ in 0..100 {
            hist.observe(0xAA);
        }
        // Create a new histogram - should have clean state
        let hist2 = HistogramDetector::<256>::new();
        assert!((hist2.probability(0xAA) - 0.0).abs() < f32::EPSILON);
        // Original should still have data
        assert!(hist.probability(0xAA) > 0.5);
    }

    #[test]
    fn markov_transition_a_to_b_and_back() {
        let mut det = MarkovDetector::<16>::new();
        det.observe_transition(0, 1);
        det.observe_transition(1, 0);

        let score_0_1 = det.score_transition(0, 1);
        let score_1_0 = det.score_transition(1, 0);

        // Both should be 1.0 (only transition from each state)
        assert!((score_0_1 - 1.0).abs() < f32::EPSILON);
        assert!((score_1_0 - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn markov_all_transitions_to_same_state() {
        let mut det = MarkovDetector::<4>::new();
        // All states transition to state 2
        for from in 0..4u8 {
            det.observe_transition(from, 2);
        }
        // From any state, transition to 2 should have score 1.0
        for from in 0..4u8 {
            let score = det.score_transition(from, 2);
            assert!(
                (score - 1.0).abs() < f32::EPSILON,
                "transition from {from} to 2 should be 1.0, got {score}"
            );
        }
        // Transition to any other state should be 0.0
        for from in 0..4u8 {
            let score = det.score_transition(from, 0);
            if from != 2 {
                // state 2 -> 0 is also 0.0 since we only observed 2 -> nothing
                assert!((score - 0.0).abs() < f32::EPSILON);
            }
        }
    }

    #[test]
    fn markov_score_for_trained_transition_is_high() {
        let mut det = MarkovDetector::<16>::new();
        // Train heavily on 3->5 transition
        for _ in 0..100 {
            det.observe_transition(3, 5);
        }
        // One rare transition 3->7
        det.observe_transition(3, 7);

        let score_3_5 = det.score_transition(3, 5);
        let score_3_7 = det.score_transition(3, 7);

        assert!(
            score_3_5 > 0.9,
            "heavily trained transition should have high score"
        );
        assert!(score_3_7 < 0.1, "rare transition should have low score");
    }

    #[test]
    fn sqrt_approx_of_zero_returns_zero() {
        let result = sqrt_approx(0.0);
        assert!((result - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn sqrt_approx_of_one_returns_one() {
        let result = sqrt_approx(1.0);
        assert!(
            (result - 1.0).abs() < 0.001,
            "sqrt(1.0) should be ~1.0, got {result}"
        );
    }

    #[test]
    fn sqrt_approx_large_number_no_panic() {
        let large = 1.0e30_f32;
        let result = sqrt_approx(large);
        // Should not panic and should return a positive, finite value
        assert!(result > 0.0, "sqrt of large number should be positive");
        assert!(result.is_finite(), "sqrt of large number should be finite");
    }

    #[test]
    fn ewma_mean_converges_to_constant_input() {
        let mut det = EwmaDetector::new(0.3, 3.0).unwrap();
        for _ in 0..200 {
            det.update(42.0);
        }
        let diff = (det.mean() - 42.0).abs();
        assert!(
            diff < 0.001,
            "mean should converge to 42.0, got {}",
            det.mean()
        );
    }

    #[test]
    fn ewma_variance_approaches_zero_for_constant_input() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..200 {
            det.update(5.0);
        }
        // After many constant updates, the score for the same value should
        // be non-anomalous (z_score ~ 0)
        let score = det.update(5.0);
        assert!(score.is_some());
        let score = score.unwrap();
        assert!(
            !score.is_anomalous,
            "constant input should not be anomalous"
        );
    }

    // ----- Soft-float accuracy tests -----

    #[test]
    fn sqrt_approx_accuracy_bounds() {
        // With the bit-manipulation seed, accuracy is excellent across the
        // full range. All values should converge to < 0.001 relative error.
        let precise_range: &[(f32, f64)] = &[
            (0.01, 0.001),
            (0.1, 0.001),
            (0.5, 0.001),
            (1.0, 0.001),
            (2.0, 0.001),
            (4.0, 0.001),
            (9.0, 0.001),
            (16.0, 0.001),
            (25.0, 0.001),
            (100.0, 0.001),
            (256.0, 0.001),
            (1000.0, 0.001),
        ];
        for &(x, max_error) in precise_range {
            let approx = sqrt_approx(x);
            // Reference: Newton's method with f64 precision
            let mut ref_val = x as f64;
            for _ in 0..20 {
                ref_val = 0.5 * (ref_val + x as f64 / ref_val);
            }
            let relative_error = ((approx as f64 - ref_val) / ref_val).abs();
            assert!(
                relative_error < max_error,
                "sqrt_approx({x}) = {approx}, expected ~{ref_val}, relative error = {relative_error}"
            );
        }
    }

    #[test]
    fn ewma_known_sequence_accuracy() {
        // alpha=0.5, z_threshold=3.0
        // Update with sequence [10, 20, 30, 40, 50]
        // After first: mean=10
        // After second: mean = 0.5*20 + 0.5*10 = 15
        // After third: mean = 0.5*30 + 0.5*15 = 22.5
        // After fourth: mean = 0.5*40 + 0.5*22.5 = 31.25
        // After fifth: mean = 0.5*50 + 0.5*31.25 = 40.625
        let mut det = EwmaDetector::new(0.5, 3.0).unwrap();
        det.update(10.0);
        det.update(20.0);
        det.update(30.0);
        det.update(40.0);
        det.update(50.0);
        assert!((det.mean() - 40.625).abs() < 0.01);
    }

    #[test]
    fn ewma_accumulation_drift_bounded() {
        // After 10000 updates of the same value, mean should be very close
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..10_000 {
            det.update(42.0);
        }
        let drift = (det.mean() - 42.0).abs();
        assert!(drift < 0.001, "drift after 10000 constant updates: {drift}");
    }

    #[test]
    fn histogram_probabilities_sum_to_one() {
        let mut hist = HistogramDetector::<256>::new();
        // Feed diverse values
        for i in 0..200u8 {
            hist.observe(i);
        }
        // Observe some extras
        for _ in 0..50 {
            hist.observe(0);
            hist.observe(100);
        }

        let mut total_prob: f32 = 0.0;
        for v in 0..=255u8 {
            total_prob += hist.probability(v);
        }
        assert!(
            (total_prob - 1.0).abs() < 0.001,
            "probabilities sum to {total_prob}, expected ~1.0"
        );
    }

    #[test]
    fn markov_row_sums_to_one() {
        let mut det = MarkovDetector::<4>::new();
        // Train with sequence: 0->1->2->3->0->1->2->3
        let sequence = [0u8, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        for i in 0..sequence.len() - 1 {
            det.observe_transition(sequence[i], sequence[i + 1]);
        }

        // For each trained from-state, row should sum to ~1.0
        for from in 0..4u8 {
            let mut row_sum: f32 = 0.0;
            for to in 0..4u8 {
                row_sum += det.score_transition(from, to);
            }
            // Row sum should be 1.0 (each row represents conditional probs)
            assert!((row_sum - 1.0).abs() < 0.01, "row {from} sums to {row_sum}");
        }
    }

    #[test]
    fn histogram_total_count_increments() {
        let mut hist = HistogramDetector::<256>::new();
        assert!((hist.probability(0) - 0.0).abs() < f32::EPSILON);

        hist.observe(10);
        hist.observe(20);
        hist.observe(30);
        hist.observe(10);

        // 10 was observed twice out of 4 total
        let prob_10 = hist.probability(10);
        assert!((prob_10 - 0.5).abs() < f32::EPSILON);

        // 20 was observed once out of 4 total
        let prob_20 = hist.probability(20);
        assert!((prob_20 - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn ewma_freeze_prevents_baseline_drift() {
        let mut det = EwmaDetector::new(0.3, 2.0).unwrap();
        // Train on normal values
        for _ in 0..50 {
            det.update(100.0);
        }
        let mean_before = det.mean;
        // Inject anomalous values - baseline should freeze
        for _ in 0..20 {
            det.update(10000.0);
        }
        // Mean should not have drifted significantly because of freeze
        assert!(
            (det.mean - mean_before).abs() < 500.0,
            "Mean drifted too far: {} vs {}",
            det.mean,
            mean_before
        );
    }

    #[test]
    fn histogram_16_bin_collision() {
        let mut hist = HistogramDetector::<16>::new();
        // With BINS=16, values 0, 16, 32, 48 all map to bin 0
        // since (value as usize) & (16 - 1) == 0 for these values.
        hist.observe(0);
        hist.observe(16);
        hist.observe(32);
        hist.observe(48);
        assert_eq!(hist.total, 4);
        assert_eq!(hist.counts[0], 4);
    }

    #[test]
    fn histogram_empty_input() {
        let hist = HistogramDetector::<256>::new();
        // Calling probability on an empty histogram should not panic.
        let prob = hist.probability(0);
        assert!((prob - 0.0).abs() < f32::EPSILON);
        // is_anomalous on empty histogram should return false (total == 0).
        assert!(!hist.is_anomalous(0, 0.01));
    }

    #[test]
    fn histogram_single_byte() {
        let mut hist = HistogramDetector::<256>::new();
        hist.observe(42);
        assert_eq!(hist.total, 1);
        assert_eq!(hist.counts[42], 1);
    }

    #[test]
    fn ewma_with_custom_warmup_and_freeze() {
        let mut det = EwmaDetector::with_options(0.3, 3.0, 5, 3).unwrap();
        // Feed 3 samples for warmup (warmup_count = 3)
        det.update(10.0);
        det.update(10.0);
        det.update(10.0);
        // Now an anomaly should trigger freeze of duration 5
        let score = det.update(100.0);
        assert!(score.is_some());
        assert!(score.unwrap().is_anomalous);
        // During freeze, model should not update (5 ticks)
        for _ in 0..5 {
            det.update(100.0); // anomalous values during freeze
        }
        // After freeze ends, model resumes updating
        let score = det.update(10.0);
        assert!(score.is_some());
    }

    // ---- Recalibration tests ----

    #[test]
    fn ewma_recalibrate_resets_baseline() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..100 {
            det.update(50.0);
        }
        // After convergence, recalibrate to a new baseline.
        det.recalibrate(100.0);
        assert!((det.mean() - 100.0).abs() < f32::EPSILON);
        assert!((det.variance() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn ewma_recalibrate_preserves_count() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        for _ in 0..50 {
            det.update(10.0);
        }
        let count_before = det.count();
        det.recalibrate(20.0);
        assert_eq!(det.count(), count_before, "count must be preserved");
    }

    #[test]
    fn ewma_recalibrate_rejects_nan() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        det.update(10.0);
        det.recalibrate(f32::NAN);
        // Mean should be unchanged.
        assert!((det.mean() - 10.0).abs() < f32::EPSILON);
    }

    #[test]
    fn ewma_recalibrate_rejects_inf() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        det.update(10.0);
        det.recalibrate(f32::INFINITY);
        assert!((det.mean() - 10.0).abs() < f32::EPSILON);
    }

    #[test]
    fn ewma_recalibrate_unfreezes() {
        let mut det = EwmaDetector::with_options(0.1, 3.0, 100, 3).unwrap();
        // Warm up
        for _ in 0..5 {
            det.update(10.0);
        }
        // Trigger anomaly (long freeze of 100 samples)
        det.update(1000.0);
        assert!(det.frozen, "should be frozen after anomaly");
        // Recalibrate should unfreeze.
        det.recalibrate(10.0);
        assert!(!det.frozen, "recalibrate should clear frozen state");
    }

    #[test]
    fn ewma_variance_accessor() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        assert!((det.variance() - 0.0).abs() < f32::EPSILON);
        det.update(10.0);
        det.update(20.0);
        // After two different values, variance should be non-zero.
        assert!(det.variance() > 0.0);
    }
}
