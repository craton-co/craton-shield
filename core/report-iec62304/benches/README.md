# vs-report-iec62304 benches

Criterion micro-benchmarks for performance-sensitive paths in `vs-report-iec62304`.

## Convention

- Each bench file is a standalone criterion harness (`harness = false`).
- Compiled only when the `bench` feature is enabled — keeps the default
  build path free of criterion + std deps. Run with:

  ```
  cargo bench -p vs-report-iec62304 --features bench
  ```

- File name describes the subject under measurement, not the implementation
  strategy.

## Benches

| File              | Measures                                                                                 |
| ----------------- | ---------------------------------------------------------------------------------------- |
| `trace_index.rs`  | Full `generate_traceability` cost at maximum input sizes (R = 64, T = 128).              |

## Adding a new bench

1. Add `benches/<name>.rs` with `criterion_main!`.
2. Add a `[[bench]]` stanza in `Cargo.toml` with
   `harness = false` and `required-features = ["bench"]`.
3. Document the bench in the table above.
