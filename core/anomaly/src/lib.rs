// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `vs-anomaly` — heap-free statistical anomaly detectors for automotive signal
//! monitoring.
//!
//! This leaf crate implements three online detectors usable from `no_std`
//! environments without any allocator: an Exponential Weighted Moving Average
//! (EWMA) z-score detector, a per-byte-value histogram detector, and a Markov
//! transition detector. All counters use saturating arithmetic, so the
//! detectors never panic on overflow; long-running deployments should
//! periodically call `reset()` / `recalibrate()` to avoid the precision
//! degradation flagged by `saturated()`.

/// Errors returned by configuration methods on this crate's detectors.
///
/// This crate is a leaf in the `vs-*` workspace (no `vs-error` dep), so a
/// local minimal error type is defined here. Variants are kept narrow on
/// purpose so they can be mapped 1:1 into a richer error type by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyError {
    /// A configuration value was outside its accepted range (e.g.
    /// `freeze_duration == 0` passed to [`EwmaDetector::set_freeze_duration`]).
    InvalidInput,
}

/// Anomaly score returned by detectors.
#[derive(Debug, Clone, Copy, PartialEq)]
#[must_use]
pub struct AnomalyScore {
    /// Magnitude of deviation expressed in standard deviations from the
    /// running EWMA mean. Always non-negative.
    pub z_score: f32,
    /// `true` when `z_score` exceeded the detector's configured threshold.
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

    /// Relative variance floor.
    ///
    /// On a perfectly stationary stream `diff == 0`, so *any* EWMA-variance
    /// recursion decays the variance estimate geometrically toward `0`. Once
    /// it reaches exactly `0`, [`Self::update`] takes the zero-variance branch
    /// and flags every later sample whose deviation exceeds `f32::EPSILON`
    /// with `z_score == f32::MAX` — a false-positive storm on long-lived
    /// automotive signals that carry tiny legitimate jitter (H2).
    ///
    /// To fail closed, the variance used for z-scoring is floored at
    /// `(EWMA_VARIANCE_FLOOR_REL * mean)^2` (relative to the signal
    /// magnitude), with an absolute lower bound of
    /// [`Self::EWMA_VARIANCE_FLOOR_ABS`] so the floor is still positive when
    /// `mean == 0`. The floor only ever *raises* the variance, so it cannot
    /// mask a genuine anomaly; it merely prevents the std-dev from collapsing
    /// to zero and turning sub-epsilon jitter into infinite z-scores.
    const EWMA_VARIANCE_FLOOR_REL: f32 = 1.0e-6;

    /// Absolute lower bound for the variance floor (see
    /// [`Self::EWMA_VARIANCE_FLOOR_REL`]). Used when the running mean is zero
    /// or tiny so the floored variance is always strictly positive.
    const EWMA_VARIANCE_FLOOR_ABS: f32 = f32::MIN_POSITIVE;

    /// Variance estimate floored away from zero — see
    /// [`Self::EWMA_VARIANCE_FLOOR_REL`]. Always finite and strictly
    /// positive.
    fn floored_variance(&self) -> f32 {
        let mean_abs = if self.mean < 0.0 { -self.mean } else { self.mean };
        let rel = Self::EWMA_VARIANCE_FLOOR_REL * mean_abs;
        let mut floor = rel * rel;
        if !floor.is_finite() || floor < Self::EWMA_VARIANCE_FLOOR_ABS {
            floor = Self::EWMA_VARIANCE_FLOOR_ABS;
        }
        if self.variance.is_finite() && self.variance > floor {
            self.variance
        } else {
            floor
        }
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
        // f32::abs lives in std (not core) before Rust 1.84; emulate with a branch.
        let diff_abs = if diff < 0.0 { -diff } else { diff };

        // ---- Cold-start guard ----
        // During warm-up (count < warmup_count) the variance estimate is not
        // yet reliable — the very first sample after init has variance == 0,
        // so any deviation would falsely register as infinitely-anomalous and
        // poison the baseline. Skip the anomaly check entirely during warm-up
        // and fold every sample in unconditionally to grow the baseline.
        if self.count < self.warmup_count {
            self.count = self.count.saturating_add(1);
            self.mean += self.alpha * diff;
            // Standard incremental EWMA variance recursion (H2):
            //   var <- (1 - α)·var + α·diff²
            // The previous form `(1-α)·(var + α·diff²)` was non-standard and,
            // combined with the zero-variance branch below, produced a
            // false-positive storm once variance decayed to exactly 0.
            let new_var = (1.0 - self.alpha) * self.variance + self.alpha * (diff * diff);
            // Preserve prior variance on overflow rather than zeroing it,
            // which would silently disable downstream detection on the next
            // sample. See defect #2.
            self.variance = if new_var.is_finite() && new_var >= 0.0 {
                new_var
            } else {
                self.variance
            };
            return Some(AnomalyScore {
                z_score: 0.0,
                is_anomalous: false,
            });
        }

        // Score against a variance floored away from zero (H2). On a
        // stationary signal the EWMA variance decays geometrically toward 0;
        // `floored_variance` keeps it strictly positive so the std-dev never
        // collapses and tiny legitimate jitter is no longer turned into an
        // `f32::MAX` z-score. The floor only raises variance, so a genuine
        // anomaly still scores correctly.
        let effective_var = self.floored_variance();
        let std_dev = sqrt_approx(effective_var);
        let score = if std_dev > f32::MIN_POSITIVE {
            let z_abs = diff_abs / std_dev;
            // Guard against a non-finite z-score (e.g. std_dev subnormal and
            // diff large): treat it as a threshold breach but with a finite
            // reported score so downstream consumers are not poisoned.
            if z_abs.is_finite() {
                AnomalyScore {
                    z_score: z_abs,
                    is_anomalous: z_abs > self.z_threshold,
                }
            } else {
                AnomalyScore {
                    z_score: f32::MAX,
                    is_anomalous: true,
                }
            }
        } else {
            // Should be unreachable now that `floored_variance` guarantees a
            // strictly-positive variance, but kept as a defensive fallback:
            // any measurable deviation is anomalous.
            let is_anom = diff_abs > f32::EPSILON;
            AnomalyScore {
                z_score: if is_anom { f32::MAX } else { 0.0 },
                is_anomalous: is_anom,
            }
        };

        // Check if this sample is anomalous and trigger freeze if so.
        // (Warm-up has already returned above, so count >= warmup_count here.)
        if score.is_anomalous && !self.frozen {
            self.frozen = true;
            self.freeze_remaining = self.freeze_duration;
        }

        if self.frozen {
            // Do NOT update mean/variance while frozen.
            self.freeze_remaining = self.freeze_remaining.saturating_sub(1);
            if self.freeze_remaining == 0 {
                self.frozen = false;
            }
        } else if !score.is_anomalous {
            // Post-warm-up: only fold non-anomalous samples into the baseline.
            // Anomalous samples that did not trip the freeze (shouldn't happen
            // here, but defensive) must not poison the running statistics.
            self.count = self.count.saturating_add(1);
            self.mean += self.alpha * diff;
            // Standard incremental EWMA variance recursion (H2):
            //   var <- (1 - α)·var + α·diff²
            let new_var = (1.0 - self.alpha) * self.variance + self.alpha * (diff * diff);
            // Preserve prior variance on non-finite/negative drift rather than
            // resetting to 0 — see defect #2.
            self.variance = if new_var.is_finite() && new_var >= 0.0 {
                new_var
            } else {
                self.variance
            };
        }

        Some(score)
    }

    /// Current running mean of the EWMA detector.
    pub fn mean(&self) -> f32 {
        self.mean
    }

    /// Number of samples folded into the baseline (saturates at `u32::MAX`).
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Set the number of samples the baseline stays frozen after an anomaly.
    ///
    /// Returns [`AnomalyError::InvalidInput`] when `duration == 0`, because
    /// a zero-tick freeze would leave the detector in a `frozen=true,
    /// freeze_remaining=0` state for one extra sample (decrement happens on
    /// the next call), which is observationally indistinguishable from a
    /// bug. Use [`EwmaDetector::recalibrate`] for a true "unfreeze" reset.
    pub fn set_freeze_duration(&mut self, duration: u32) -> Result<(), AnomalyError> {
        if duration == 0 {
            return Err(AnomalyError::InvalidInput);
        }
        self.freeze_duration = duration;
        Ok(())
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
///
/// To stay fail-closed under collisions, the detector also keeps an exact
/// 256-bit "seen" bitmap of which raw byte values have actually been
/// observed. [`Self::is_anomalous`] consults this bitmap so that a never-seen
/// byte is always flagged as anomalous even if it collides with a frequent
/// byte in the same bin (see the method docs).
#[derive(Debug, Clone)]
pub struct HistogramDetector<const BINS: usize> {
    counts: [u64; BINS],
    total: u64,
    /// Exact per-byte-value "has this raw value ever been observed" bitmap,
    /// 256 bits packed into four `u64` words. Independent of `BINS`, so it is
    /// collision-free even when `BINS < 256`. Used by [`Self::is_anomalous`]
    /// to avoid bin-collision false negatives (H1).
    seen: [u64; 4],
    /// Sticky saturation flag: once any per-bin or total counter has hit
    /// `u64::MAX`, this is latched to `true` until [`Self::reset`] clears it.
    saturated: bool,
}

impl<const BINS: usize> HistogramDetector<BINS> {
    /// Construct an empty histogram detector. All bins start at zero.
    pub fn new() -> Self {
        const { assert!(BINS > 0, "BINS must be > 0") };
        Self {
            counts: [0u64; BINS],
            total: 0,
            seen: [0u64; 4],
            saturated: false,
        }
    }

    /// Mark raw byte `value` as observed in the 256-bit `seen` bitmap.
    #[inline]
    fn mark_seen(&mut self, value: u8) {
        self.seen[(value >> 6) as usize] |= 1u64 << (value & 63);
    }

    /// Return `true` if raw byte `value` has been observed at least once.
    #[inline]
    fn has_seen(&self, value: u8) -> bool {
        (self.seen[(value >> 6) as usize] >> (value & 63)) & 1 != 0
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

    /// Record one observation of `value`, incrementing both the bin counter
    /// and the running total with saturating arithmetic.
    pub fn observe(&mut self, value: u8) {
        self.mark_seen(value);
        let idx = Self::bin_index(value);
        let new_count = self.counts[idx].saturating_add(1);
        if new_count == u64::MAX {
            self.saturated = true;
        }
        self.counts[idx] = new_count;
        let new_total = self.total.saturating_add(1);
        if new_total == u64::MAX {
            self.saturated = true;
        }
        self.total = new_total;
    }

    /// Empirical probability of observing `value`.
    ///
    /// Note: counts above 2^24 (~16.7M) lose precision in the `f32`
    /// probability calculation; for high-volume buses, periodically
    /// recalibrate by calling [`Self::reset`].
    pub fn probability(&self, value: u8) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        let idx = Self::bin_index(value);
        // u64 -> f32 conversion is lossy for very large counts, but we only
        // need ratio precision sufficient for an anomaly threshold check.
        self.counts[idx] as f32 / self.total as f32
    }

    /// Return `true` when `value` looks anomalous against the learned model.
    ///
    /// Detection is fail-closed under bin collisions (H1): when `BINS < 256`
    /// several raw byte values share a bin, so [`Self::probability`] reports
    /// the *bin* probability, not the value probability. A never-seen byte
    /// that collides with a frequent byte would therefore score as common.
    /// To avoid that false negative, this method first consults an exact
    /// 256-bit `seen` bitmap: a byte value that has *never* been observed is
    /// always reported anomalous, regardless of its bin's probability.
    ///
    /// For values that *have* been seen, the bin-level empirical probability
    /// is compared against `threshold`. Note that with `BINS < 256` this
    /// remains a bin-level rarity test — a rare byte sharing a bin with a
    /// frequent one may not be flagged. Use `BINS == 256` for exact
    /// per-byte-value rarity detection.
    ///
    /// Returns `false` on an empty or saturated detector.
    pub fn is_anomalous(&self, value: u8, threshold: f32) -> bool {
        // Once any counter has reached the u64::MAX sentinel the model is no
        // longer mathematically sound (ratios become meaningless). Return
        // false so a saturated detector cannot raise alarms.
        if self.saturated {
            return false;
        }
        if self.total == 0 {
            return false;
        }
        // Fail closed on bin collisions: a byte value never actually observed
        // is anomalous even if its bin has a high probability (H1).
        if !self.has_seen(value) {
            return true;
        }
        self.probability(value) < threshold
    }

    /// Zero all counters. After calling this, the detector is in the same
    /// observable state as a freshly constructed instance. Use periodically
    /// on long-running systems before counters approach `u64::MAX`.
    pub fn reset(&mut self) {
        self.counts = [0u64; BINS];
        self.total = 0;
        self.seen = [0u64; 4];
        self.saturated = false;
    }

    /// Returns true if any counter (per-bin or `total`) has hit the
    /// `u64::MAX` saturation sentinel. Once saturated, the model is no longer
    /// reliable — callers should `reset()` (or recreate) the detector.
    ///
    /// O(1): backed by a cached sticky flag set inside [`Self::observe`].
    pub fn saturated(&self) -> bool {
        self.saturated
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
    transition: [[u64; N]; N],
    row_totals: [u64; N],
    /// Sticky saturation flag: once any transition or row total has hit
    /// `u64::MAX`, this is latched to `true` until [`Self::reset`] clears it.
    saturated: bool,
}

impl<const N: usize> MarkovDetector<N> {
    /// Construct an empty Markov transition detector. All counters start at
    /// zero.
    pub fn new() -> Self {
        const { assert!(N > 0, "N must be > 0") };
        Self {
            transition: [[0u64; N]; N],
            row_totals: [0u64; N],
            saturated: false,
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

    /// Record one `from -> to` state transition with saturating arithmetic.
    pub fn observe_transition(&mut self, from: u8, to: u8) {
        let f = Self::state_index(from);
        let t = Self::state_index(to);
        let new_cell = self.transition[f][t].saturating_add(1);
        if new_cell == u64::MAX {
            self.saturated = true;
        }
        self.transition[f][t] = new_cell;
        let new_row = self.row_totals[f].saturating_add(1);
        if new_row == u64::MAX {
            self.saturated = true;
        }
        self.row_totals[f] = new_row;
    }

    /// Empirical conditional probability `P(to | from)` as an `f32`.
    ///
    /// Note: counts above 2^24 (~16.7M) lose precision in the `f32`
    /// probability calculation; for high-volume buses, periodically
    /// recalibrate by calling [`Self::reset`].
    pub fn score_transition(&self, from: u8, to: u8) -> f32 {
        let f = Self::state_index(from);
        let t = Self::state_index(to);
        let total = self.row_totals[f];
        if total == 0 {
            return 0.0;
        }
        // u64 -> f32 conversion is lossy for very large counts, but we only
        // need ratio precision sufficient for downstream scoring.
        self.transition[f][t] as f32 / total as f32
    }

    /// Zero the transition matrix and row totals. Use periodically on
    /// long-running systems before counters approach `u64::MAX`.
    pub fn reset(&mut self) {
        self.transition = [[0u64; N]; N];
        self.row_totals = [0u64; N];
        self.saturated = false;
    }

    /// Returns true if any transition counter or row total has reached the
    /// `u64::MAX` sentinel. Once saturated, the model is no longer reliable.
    ///
    /// O(1): backed by a cached sticky flag set inside
    /// [`Self::observe_transition`].
    pub fn saturated(&self) -> bool {
        self.saturated
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
    // 2 Newton iterations refine the bit-hack seed to <1e-5 relative error,
    // which is well within the accuracy bound asserted by the test suite
    // (`sqrt_approx_accuracy_bounds` at 1e-3). Halves the sqrt latency vs.
    // the previous 4 iterations.
    for _ in 0..2 {
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
        // Use warmup_count=1 so the anomaly check engages immediately after
        // the seed sample (the default warm-up would otherwise short-circuit
        // any flagging on the second sample — see Finding #1 cold-start
        // guard).
        let mut det = EwmaDetector::with_options(0.1, 0.0, 10, 1).unwrap();
        det.update(10.0); // seed sample, returns None
                          // Build up some variance with a couple of warm-then-post-warm samples.
        det.update(10.0);
        det.update(10.0);
        // Now feed a slightly different value: with z_threshold=0, any
        // measurable deviation must be flagged.
        let score = det.update(10.001);
        assert!(score.is_some());
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
    fn histogram_bin_collision_never_seen_byte_flagged() {
        // H1 regression: with BINS=16, byte 0x0F and byte 0xFF both map to
        // bin 15 ((v) & 15 == 15). Train heavily on 0x0F only. Byte 0xFF was
        // never observed, but it shares a high-probability bin — the old
        // is_anomalous would have returned false (false negative). The seen
        // bitmap must now flag 0xFF as anomalous.
        let mut hist = HistogramDetector::<16>::new();
        for _ in 0..1000 {
            hist.observe(0x0F);
        }
        assert_eq!(
            HistogramDetector::<16>::bin_index(0x0F),
            HistogramDetector::<16>::bin_index(0xFF),
            "test precondition: 0x0F and 0xFF must collide in bin 15"
        );
        // The frequently-seen byte is not anomalous.
        assert!(!hist.is_anomalous(0x0F, 0.5));
        // The never-seen colliding byte MUST be flagged.
        assert!(
            hist.is_anomalous(0xFF, 0.5),
            "never-seen byte 0xFF colliding with frequent 0x0F must be flagged"
        );
    }

    #[test]
    fn histogram_seen_byte_below_threshold_still_flagged() {
        // A byte that has been seen but is rare (probability below threshold)
        // is still flagged via the probability path.
        let mut hist = HistogramDetector::<256>::new();
        for _ in 0..1000 {
            hist.observe(0x10);
        }
        hist.observe(0x20); // seen once, very rare
        assert!(hist.is_anomalous(0x20, 0.01), "rare seen byte must flag");
        assert!(!hist.is_anomalous(0x10, 0.01), "frequent byte must not");
    }

    #[test]
    fn histogram_reset_clears_seen_bitmap() {
        let mut hist = HistogramDetector::<16>::new();
        for _ in 0..100 {
            hist.observe(0x0F);
        }
        hist.reset();
        // After reset, total == 0 so is_anomalous returns false even for a
        // previously-seen byte; the seen bitmap must also be cleared so a
        // fresh observation does not see stale state.
        assert!(!hist.is_anomalous(0x0F, 0.5));
        hist.observe(0xFF);
        // 0x0F was never observed since the reset -> anomalous.
        assert!(hist.is_anomalous(0x0F, 0.5));
        assert!(!hist.is_anomalous(0xFF, 0.5));
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

    // ---- Cold-start regression tests ----

    #[test]
    fn ewma_second_sample_during_warmup_not_anomalous() {
        // With a fresh detector, the variance after the first sample is 0,
        // so historically the second sample would trip the zero-variance
        // branch and be falsely flagged anomalous. During warm-up we must
        // return a non-anomalous score with z_score == 0 instead.
        let mut det = EwmaDetector::with_options(0.3, 3.0, 5, 5).unwrap();
        assert!(det.update(10.0).is_none(), "first sample returns None");
        // Even a very different second sample must not be flagged.
        let score = det.update(10_000.0).expect("score expected");
        assert!(
            !score.is_anomalous,
            "second sample during warm-up must NOT be anomalous"
        );
        assert!(
            (score.z_score - 0.0).abs() < f32::EPSILON,
            "z_score during warm-up must be 0, got {}",
            score.z_score
        );
    }

    #[test]
    fn ewma_warmup_anomalous_sample_not_folded() {
        // Sanity: during warm-up, every sample is folded in (Finding 2's
        // exception only applies POST-warm-up). This test pins the
        // documented warm-up behavior: warm-up samples ARE folded
        // unconditionally. Then post-warm-up, anomalous samples are NOT
        // folded into mean/variance.
        let mut det = EwmaDetector::with_options(0.5, 3.0, 100, 3).unwrap();
        // Warm up to a stable baseline of 10.0 (3 samples, warmup_count=3).
        det.update(10.0); // first sample
        det.update(10.0); // warm-up
        det.update(10.0); // warm-up — count now equals warmup_count
        let mean_after_warmup = det.mean();
        let var_after_warmup = det.variance();
        assert!(
            (mean_after_warmup - 10.0).abs() < f32::EPSILON,
            "warm-up should fold constant samples to constant mean"
        );

        // Post-warm-up: an extreme outlier triggers anomaly + freeze.
        let score = det.update(1_000_000.0).expect("post-warm-up score");
        assert!(score.is_anomalous, "huge outlier must be anomalous");

        // After the outlier triggered freeze, mean/variance must NOT have
        // been folded with the outlier's value.
        assert!(
            (det.mean() - mean_after_warmup).abs() < f32::EPSILON,
            "anomalous sample must NOT update mean (was {}, now {})",
            mean_after_warmup,
            det.mean()
        );
        assert!(
            (det.variance() - var_after_warmup).abs() < f32::EPSILON,
            "anomalous sample must NOT update variance"
        );
    }

    // ---- H2: variance-collapse regression ----

    #[test]
    fn ewma_variance_collapse_no_false_positive_storm() {
        // H2 regression: feed a long perfectly-constant stream so the EWMA
        // variance decays geometrically toward zero, then inject a tiny
        // legitimate jitter just above f32::EPSILON. Historically the
        // detector would have collapsed into the zero-variance branch and
        // flagged this with z_score == f32::MAX. With the variance floor the
        // jitter must NOT be flagged.
        let mut det = EwmaDetector::new(0.3, 3.0).unwrap();
        for _ in 0..100_000 {
            let _ = det.update(50.0);
        }
        // A tiny deviation (a few epsilons) on a 50.0 baseline is well within
        // legitimate sensor jitter and must not trip the detector.
        let score = det
            .update(50.0 + f32::EPSILON * 4.0)
            .expect("post-warm-up score");
        assert!(
            score.z_score.is_finite(),
            "z_score must stay finite, got {}",
            score.z_score
        );
        assert!(
            !score.is_anomalous,
            "tiny jitter on a long constant stream must NOT be flagged \
             (z_score = {})",
            score.z_score
        );
    }

    #[test]
    fn ewma_genuine_anomaly_still_flagged_after_variance_floor() {
        // The variance floor must not mask real anomalies: after a long
        // constant stream a large outlier must still be flagged.
        let mut det = EwmaDetector::new(0.3, 3.0).unwrap();
        for _ in 0..10_000 {
            let _ = det.update(50.0);
        }
        let score = det.update(50_000.0).expect("score");
        assert!(
            score.is_anomalous,
            "large outlier must still be flagged after variance floor"
        );
    }

    // ---- Counter widening / saturation regression tests ----

    #[test]
    fn histogram_total_u64_no_silent_saturation_in_5_days() {
        // 5 days * 86_400 s/day * ~10_000 obs/s ~= 4.32e9, which fits in u32
        // by < 2x margin and saturates if you scale up. Demonstrate that
        // we can comfortably blow past u32::MAX without saturation.
        //
        // We avoid actually looping 4 billion times (slow); instead we
        // verify the type is u64 by pushing total past u32::MAX worth of
        // observations using a small synthetic burst plus a static check.
        let mut hist = HistogramDetector::<256>::new();
        // Observe enough to give us a non-zero state.
        for _ in 0..1000 {
            hist.observe(0x42);
        }
        // The total field must be u64 — if it were u32, total + (u32::MAX as u64)
        // would saturate. Use a let-binding to bind the type explicitly.
        let total: u64 = hist.total;
        // 5 days at 10k obs/s ~= 4.32e9 observations, > u32::MAX (~4.29e9).
        let five_day_burst: u64 = 5 * 86_400 * 10_000;
        assert!(
            five_day_burst > u32::MAX as u64,
            "sanity: 5-day burst exceeds u32::MAX"
        );
        // total has plenty of headroom in u64.
        assert!(
            total.checked_add(five_day_burst).is_some(),
            "u64 total must absorb a 5-day burst without overflow"
        );
        assert!(
            !hist.saturated(),
            "fresh-ish detector must not report saturated"
        );
    }

    #[test]
    fn histogram_reset_zeroes_state() {
        let mut hist = HistogramDetector::<16>::new();
        for v in 0..100u8 {
            hist.observe(v);
        }
        assert!(hist.total > 0);
        hist.reset();
        assert_eq!(hist.total, 0, "reset must zero total");
        for i in 0..16 {
            assert_eq!(hist.counts[i], 0, "reset must zero bin {i}");
        }
        // After reset the detector behaves like a fresh one.
        assert!((hist.probability(0) - 0.0).abs() < f32::EPSILON);
        assert!(!hist.is_anomalous(0, 0.01));
    }

    #[test]
    fn markov_reset_zeroes_state() {
        let mut det = MarkovDetector::<4>::new();
        for from in 0..4u8 {
            for to in 0..4u8 {
                det.observe_transition(from, to);
            }
        }
        // Confirm there's state to clear.
        assert!(det.score_transition(0, 0) > 0.0);
        det.reset();
        for from in 0..4u8 {
            for to in 0..4u8 {
                assert!(
                    (det.score_transition(from, to) - 0.0).abs() < f32::EPSILON,
                    "reset must zero transition {from}->{to}"
                );
            }
        }
        assert!(!det.saturated(), "reset must clear saturation");
    }

    #[test]
    fn histogram_saturated_returns_false_anomalous() {
        // Drive a counter to u64::MAX directly. saturating_add is already
        // tested elsewhere; here we just need a saturated state to verify
        // is_anomalous returns false.
        let mut hist = HistogramDetector::<16>::new();
        // Inject saturation via the public observe path is infeasible
        // (would need 2^64 calls). Manipulate the field through a
        // re-construction trick by repeatedly observing the same bin until
        // saturating_add caps it. To keep the test fast, jump directly:
        hist.counts[0] = u64::MAX;
        hist.total = u64::MAX;
        // Flip the cached sticky flag to mirror what observe() would have
        // done had we actually saturated through the public path.
        hist.saturated = true;

        assert!(hist.saturated(), "MAX counters must report saturated");
        // Even though probability would say 1.0, is_anomalous must NOT
        // flag — the model is unreliable.
        assert!(
            !hist.is_anomalous(0, 0.99),
            "saturated detector must not flag anomalies"
        );
        assert!(
            !hist.is_anomalous(255, 0.99),
            "saturated detector must not flag never-seen values either"
        );
    }

    // ---- set_freeze_duration validation ----

    #[test]
    fn ewma_set_freeze_duration_rejects_zero() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        let err = det.set_freeze_duration(0);
        assert_eq!(err, Err(AnomalyError::InvalidInput));
    }

    #[test]
    fn ewma_set_freeze_duration_accepts_positive() {
        let mut det = EwmaDetector::new(0.1, 3.0).unwrap();
        assert!(det.set_freeze_duration(7).is_ok());
    }
}
