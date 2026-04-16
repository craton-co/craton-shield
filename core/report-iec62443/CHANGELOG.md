# Changelog

All notable changes to `vs-report-iec62443` are documented in this file.

## [0.7.0]

- Adapted to the `Evidence::with_metadata(payload, standard, metadata)` API
  in `vs-evidence-envelope`: `Standard::Iec62443` is now passed explicitly.
- Documented 0.7.0 coverage scope; full IEC 62443-4-2 coverage targeted
  for 1.0.0 (missing CRs listed in the `Scope` section).
- Added `Iec62443Assessment::iter_gaps()` for O(n) gap iteration.
- Deprecated `Iec62443Assessment::gap_at()` in favour of `iter_gaps`.
- Added `assess_into()` for callers that want to reuse a single
  `Iec62443Assessment` buffer and avoid the per-call 40-entry zero-init.
- `TOOL_VERSION` is pinned to `iec62443-0.7`; bump on every minor release.
- `bool_sl` is now `const fn` (parity with `crypto_sl`).
