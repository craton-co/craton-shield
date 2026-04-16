# vs-key-manager benches

Criterion micro-benchmarks for performance-sensitive paths in `vs-key-manager`.

## Convention

- Each bench file is a standalone criterion harness (`harness = false`).
- Compiled only when the `bench` feature is enabled — keeps the default
  build path free of criterion + std deps. Run with:

  ```
  cargo bench -p vs-key-manager --features bench
  ```

- File name describes the subject under measurement, not the implementation
  strategy.

## Benches

| File                            | Measures                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| `audit_append_after_wrap.rs`    | Cost of `rotate_key` once the audit ring has wrapped (per-entry chain-hash fast path).|

## Adding a new bench

1. Add `benches/<name>.rs` with `criterion_main!`.
2. Add a `[[bench]]` stanza in `Cargo.toml` with
   `harness = false` and `required-features = ["bench"]`.
3. Document the bench in the table above.
