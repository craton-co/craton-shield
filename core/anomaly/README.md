# vs-anomaly

EWMA-based statistical anomaly detection for automotive signal monitoring.

## Overview

This crate implements an Exponential Weighted Moving Average (EWMA) detector
for real-time anomaly detection on automotive signal streams. It tracks a
running mean and variance, computing z-scores against each new observation
to flag statistical outliers without heap allocation.

## Key Types

- `EwmaDetector` — stateful EWMA detector with configurable alpha and z-threshold
- `HistogramDetector<BINS>` — frequency-based anomaly detection using byte-value histograms
- `MarkovDetector<N>` — Markov chain transition probability detector
- `AnomalyScore` — detection result containing the z-score and anomalous flag

## Usage

```rust
use vs_anomaly::{EwmaDetector, AnomalyScore};

let mut detector = EwmaDetector::new(0.3, 3.0).expect("valid params");
if let Some(score) = detector.update(42.0) {
    if score.is_anomalous {
        // handle anomaly
    }
}
```

## Detector lifecycle helpers

- `EwmaDetector::with_options(alpha, z_threshold, freeze_duration, warmup_count)` —
  construct a detector with a custom freeze duration and warm-up sample count.
- `EwmaDetector::recalibrate(baseline_value)` — reset the running mean and
  variance to a fresh known-good baseline (preserves `count`, unfreezes the
  detector). Use periodically on long-running systems to eliminate
  accumulated drift.
- `HistogramDetector::reset()` / `MarkovDetector::reset()` — zero all counters
  back to a freshly-constructed state. Use before counters approach
  `u64::MAX`.
- `HistogramDetector::saturated()` / `MarkovDetector::saturated()` — `true`
  once any internal counter has hit the `u64::MAX` saturation sentinel.
  `is_anomalous` returns `false` on a saturated detector; the model is no
  longer reliable and the caller should `reset()` it.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
