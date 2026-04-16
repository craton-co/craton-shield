# vs-crypto benches

Criterion micro-benchmarks for performance-sensitive paths in `vs-crypto`.

## Convention

- Each bench file is a standalone criterion harness (`harness = false`).
- Compiled only when the `bench` feature is enabled — keeps the default
  build path free of criterion + std deps. Run with:

  ```
  cargo bench -p vs-crypto --features bench
  ```

- File name describes the subject under measurement, not the implementation
  strategy. Example: `nonce_tracker_bloom.rs` measures `NonceTracker` Bloom
  fast-path effectiveness regardless of whether the rebuild cadence changes.

## Benches

| File                       | Measures                                                                  |
| -------------------------- | ------------------------------------------------------------------------- |
| `nonce_tracker_bloom.rs`   | High-churn `check_and_record` throughput; sensitive to Bloom saturation.  |

## Adding a new bench

1. Add `benches/<name>.rs` with `criterion_main!`.
2. Add a `[[bench]]` stanza in `Cargo.toml` with
   `harness = false` and `required-features = ["bench"]`.
3. Document the bench in the table above.
