# Performance Budget

> **Scope:** v1.0.x supported lines.
> **Authority:** This file is the source of truth for the performance budget
> that CI watches. Benchmark code in `core/benches/` and the bench workflow in
> `.github/workflows/bench.yml` cite the numbers here.

Craton Shield is a safety-critical embedded runtime. Performance regressions on
the hot path can quietly erode the timing margin a downstream integrator relies
on to meet their ECU's worst-case execution-time budget. To prevent that, we
publish a per-operation budget and enforce it in CI.

## How budgets are set

For each tracked operation:

1. The published **target** is the v0.7.0 measured mean from
   [`core/docs/performance-results.md`](core/docs/performance-results.md),
   collected on a Linux x86_64 host with the criterion harness (warmup 3 s,
   measurement 5 s, performance governor pinned to an isolated core).
2. The **CI budget** is the target plus ~10-15 % headroom. The headroom
   absorbs noise from shared GitHub-hosted runners (which are noisier than the
   reference workstation) without hiding a real regression.
3. Hitting the budget is **necessary but not sufficient** -- a PR that lands
   within budget but doubles a previously fast operation should still be flagged
   in review. Budgets are a floor on what CI catches automatically, not a
   ceiling on what reviewers should pay attention to.

## Tracked operations (top 10)

These are the operations covered by the dedicated criterion benches in
`core/benches/cratonshield_benchmarks.rs` and watched by the
`criterion-bench` job in `.github/workflows/bench.yml`. Sorted by criticality
to the CAN gateway use case.

| #  | Operation                                | v0.7.0 mean | CI budget | Source bench / scenario                                |
|---:|------------------------------------------|------------:|----------:|--------------------------------------------------------|
|  1 | `runtime::submit_can_frame`              |     ~265 ns |    300 ns | Full pipeline through monitor, IDS, and tick           |
|  2 | `can_monitor::process_frame`             |     ~265 ns |    300 ns | 5 detectors, standard 8-byte frame                     |
|  3 | `eth_monitor::inspect_packet`            |      ~28 ns |     40 ns | SOME/IP allow-listed, hash-indexed lookup              |
|  4 | `eth_monitor::inspect_packet_rejected`   |     ~158 ns |    200 ns | Allow-list miss (worst-case scan)                      |
|  5 | `firewall::evaluate/128_rules_first`     |       ~9 ns |     15 ns | Sorted-priority early exit                             |
|  6 | `firewall::evaluate/128_rules_last`      |     ~166 ns |    200 ns | Full scan, worst-case                                  |
|  7 | `policy_engine::evaluate/64_rules`       |     ~199 ns |    250 ns | First-match miss, full scan to default deny            |
|  8 | `event_logger::append/hmac_chained`      |     ~108 ns |    130 ns | HMAC-chained, cached prev-entry serialization          |
|  9 | `runtime::tick`                          |      ~73 ns |    100 ns | Idle tick, all subsystems polled                       |
| 10 | `crypto::aes_gcm_encrypt/256`            |     ~907 ns |   1100 ns | Software AES-128-GCM, 256-byte plaintext               |

Scaling sweeps and crypto-suite numbers are tracked separately in
`core/benches/competitive_benchmarks.rs`; their budgets are listed in the
module-level rustdoc on that file.

## CI enforcement

The `criterion-bench` job in `.github/workflows/bench.yml`:

- Runs `cargo bench --workspace --all-features` on every push to `main` and
  on PRs touching `core/`, `auto/`, `embedded/`, `industrial/`, or any of the
  workspace `Cargo.toml` files.
- Uploads the full criterion artifact (HTML reports, raw JSON, bencher-format
  log) under the artifact name `criterion-<sha>` with 30-day retention.
- Emits a manual-review notice on PRs reminding the reviewer to compare the
  PR artifact against `main` using `critcmp`. We do not auto-fail on
  regression today: the noise floor on shared runners makes a strict
  threshold counterproductive. Once a self-hosted runner is wired in, the
  step will switch to an automatic fail.

The job is **not** a required check on `main`. Branch protection requires the
faster `Bench summary` step instead, which always succeeds and exists solely so
that the bench workflow contributes a green tick.

## Reviewing a bench run

When a PR touches latency-sensitive code (anything reachable from
`runtime::tick` or `runtime::submit_can_frame`):

1. Wait for the `criterion-bench` job on the PR to finish.
2. Download the `criterion-<sha>` artifact from the PR run.
3. Download the same artifact from the run on the PR's merge-base commit on
   `main`.
4. Compare with `critcmp` (or by eye, opening `target/criterion/report/index.html`):
   ```bash
   critcmp baseline/estimates.json pr/estimates.json
   ```
5. Treat any **> 5 % regression** on a budgeted operation as blocking unless
   the PR description explains and justifies it (e.g. accepting +10 ns on
   `inspect_packet` to add a documented defense-in-depth check).
6. Investigate any **> 15 % regression on an unbudgeted operation** -- it's
   often a leading indicator of a hot-path data-structure change worth
   discussing.

## What is *not* a regression

- Variance under ~5 % on shared GitHub runners. The noise floor on
  `ubuntu-latest` is real and the budget already accounts for it.
- An operation getting *faster*. Celebrate, then update `performance-results.md`
  and the budget table in this file on the next release.
- A new bench being added. New code without a baseline should land with a
  proposed budget in this file, set conservatively (the first measured mean
  plus the same ~15 % headroom).

## Updating budgets

Budgets are changed in two situations:

1. **A planned optimization lands.** Update the *target* and the *CI budget*
   together. Cite the commit and the optimization technique in
   `core/docs/performance-results.md` so the history is auditable.
2. **A deliberate trade-off lands** (e.g. constant-time path replaces a faster
   data-dependent one). Update the *target* to the new measured mean, the
   *CI budget* to target + 15 %, and document the rationale in the PR
   description and `core/docs/performance-results.md`.

Tightening a budget below the v0.7.0 baseline without a corresponding code
change is **not** allowed: an over-tight budget produces flaky CI without
catching real regressions.
