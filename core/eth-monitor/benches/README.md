# vs-eth-monitor benches

Criterion micro-benchmarks for performance-sensitive paths in `vs-eth-monitor`.

## Convention

- Each bench file is a standalone criterion harness (`harness = false`).
- Compiled only when the `bench` feature is enabled — keeps the default
  build path free of criterion + std deps. Run with:

  ```
  cargo bench -p vs-eth-monitor --features bench
  ```

- File name describes the subject under measurement, not the implementation
  strategy.

## Benches

| File                          | Measures                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------ |
| `siphash_payload_fused.rs`    | Fused 4-lane SipHash-2-4 vs naive 4× SipHash for payload-fingerprint hashing.  |

## Adding a new bench

1. Add `benches/<name>.rs` with `criterion_main!`.
2. Add a `[[bench]]` stanza in `Cargo.toml` with
   `harness = false` and `required-features = ["bench"]`.
3. Document the bench in the table above.
