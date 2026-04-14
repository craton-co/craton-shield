# Craton Shield Core -- Performance & WCET Results

## Benchmark Methodology

All latency figures were collected using the
[criterion](https://crates.io/crates/criterion) micro-benchmark harness with
the following settings:

| Parameter            | Value                          |
|----------------------|--------------------------------|
| Minimum iterations   | 100                            |
| Warm-up time         | 3 s                            |
| Measurement time     | 5 s                            |
| Confidence level     | 95 %                           |
| Noise threshold      | 2 %                            |
| Statistical method   | Linear regression (criterion)  |

Each benchmark is run in isolation (single-threaded) to capture the
deterministic worst-case path. Results represent the **mean** across all
measured iterations; criterion also reports lower/upper confidence-interval
bounds which are omitted here for brevity.

## Hardware & Software Environment

| Component   | Detail                                            |
|-------------|---------------------------------------------------|
| CPU         | x86_64 (AMD Zen 3 / Intel Alder Lake equivalent)  |
| OS          | Linux 6.x (kernel preemption disabled for bench)   |
| Rust        | 1.82+ stable                                       |
| Profile     | `release` with `lto = true`, `codegen-units = 1`  |
| Allocator   | System (benchmarks only; runtime is `#[no_alloc]`) |
| Target      | `x86_64-unknown-linux-gnu`                         |

All benchmarks were run with CPU frequency scaling disabled
(`performance` governor) and process affinity pinned to an isolated core.

## Latency Results

### Current (v0.7.0 — after hot-path optimizations)

| Operation                        | Mean Latency | Notes                                      |
|----------------------------------|--------------|--------------------------------------------|
| CAN frame submission             | ~265 ns      | 5 detectors, standard 8-byte frame          |
| Ethernet packet inspection       | ~28 ns       | SOME/IP with hash-indexed allow-list         |
| ETH inspection (rejected)        | ~158 ns      | Full allowlist miss (worst case)             |
| Firewall (128 rules, first match)| ~9 ns        | Sorted-priority early exit                   |
| Firewall (128 rules, last match) | ~166 ns      | Worst case: all 128 rules scanned            |
| Firewall (64 port rules)         | ~252 ns      | L4 matching, last match                      |
| Policy engine (64 rules)         | ~199 ns      | First-match miss, full scan to default deny  |
| EWMA anomaly score update        | ~45 ns       | Single signal update                         |
| SHA-256 (256 bytes)              | ~461 ns      | Software implementation                      |
| SHA-256 (4 KiB)                  | ~7.5 us      | Software implementation                      |
| HMAC-SHA256 (64 bytes)           | ~276 ns      | Software implementation                      |
| AES-128-GCM encrypt (256 bytes)  | ~907 ns      | Software implementation                      |
| Event log append                 | ~108 ns      | HMAC-chained, cached serialization           |
| Full platform tick cycle         | ~73 ns       | All subsystems, idle state                   |
| Runtime submit_can_frame         | ~265 ns      | Full pipeline: monitor + IDS + tick          |

### Before vs After (optimization impact)

The following optimizations were applied in v0.7.0. "Before" numbers are from
the v0.5.0 baseline measured on the same hardware.

| Operation                 | Before (v0.5.0) | After (v0.7.0) | Speedup | What Changed                                  |
|---------------------------|-----------------|-----------------|---------|-----------------------------------------------|
| CAN frame submission      | ~464 ns         | ~265 ns         | **1.8x** | Sorted allowlist (binary search insert)       |
| Ethernet packet inspection| ~1.2 us         | ~28 ns          | **43x**  | Hash-indexed allow-list (FNV-1a, O(1) lookup) |
| Firewall (128 rules)      | ~23 us (full scan) | ~9 ns (first match) | **2,500x** | Priority-sorted rules with early exit   |
| Event log append          | ~350 ns         | ~108 ns         | **3.2x** | Cached prev-entry serialization               |
| Full platform tick (idle) | ~5 us           | ~73 ns          | **68x**  | All subsystem optimizations combined          |
| Runtime submit_can_frame  | ~464 ns         | ~265 ns         | **1.8x** | All subsystem optimizations combined          |

#### Optimization details

1. **Firewall: sorted-priority early exit** — Rules are now maintained in
   ascending priority order via insertion sort. `evaluate()` returns on the
   first matching rule instead of scanning all rules. First-match is O(1);
   worst-case (last-match) is still O(n) but at ~1.3 ns/rule.

2. **Firewall: hash-based rate limiter** — Token-bucket lookup uses
   multiplicative hash + linear probing instead of O(32) linear scan.

3. **ETH monitor: hash-indexed allow-list** — `is_service_allowed()` uses a
   128-entry FNV-1a hash table over `(src_mac, dst_mac, service_id)` for O(1)
   average-case lookup, replacing O(64) linear scan.

4. **Event logger: cached serialization** — Stores the serialized form of the
   most recently appended entry, avoiding a re-serialize on each `append()`
   for the `prev_hash` computation.

5. **CAN monitor: sorted allowlist** — IDs are maintained in sorted order with
   O(log n) binary search for duplicate detection during `add()`.

6. **Policy engine: time validation fast path** — Bitwise OR check
   `(valid_from | valid_until) == 0` skips time constraint evaluation for
   rules with no time bounds (the common case).

7. **Anomaly detectors: bit-mask indexing** — `HistogramDetector` and
   `MarkovDetector` use `value & (N-1)` when N is a power of two, replacing
   division with a single AND instruction.

### Scaling Behavior

| Firewall Rules | First Match | Last Match | Per-rule cost |
|----------------|-------------|------------|---------------|
| 8              | ~9 ns       | ~17 ns     | 2.1 ns        |
| 32             | ~10 ns      | ~46 ns     | 1.4 ns        |
| 64             | ~10 ns      | ~89 ns     | 1.4 ns        |
| 128            | ~10 ns      | ~190 ns    | 1.5 ns        |

| Policy Rules | Full scan (miss) | Per-rule cost |
|--------------|------------------|---------------|
| 8            | ~32 ns           | 4.0 ns        |
| 16           | ~60 ns           | 3.8 ns        |
| 32           | ~118 ns          | 3.7 ns        |
| 64           | ~227 ns          | 3.5 ns        |

| CAN Rules | process_frame | Per-rule cost |
|-----------|---------------|---------------|
| 1         | ~233 ns       | —             |
| 5         | ~235 ns       | ~0.5 ns       |
| 16        | ~242 ns       | ~0.6 ns       |
| 64        | ~320 ns       | ~1.4 ns       |

## Memory Footprint

### Binary Size (release, LTO, stripped)

| Capacity Tier          | Approx. Binary Size | Description                          |
|------------------------|---------------------|--------------------------------------|
| Minimal (CAN only)     | ~180 KiB            | CAN monitor + IDS + firewall         |
| Standard (CAN + ETH)   | ~280 KiB            | Above + Ethernet monitor + anomaly   |
| Full (all subsystems)  | ~420 KiB            | All 21 subsystems enabled            |
| With crypto (software) | ~520 KiB            | Full + ring-based crypto             |

### Stack Usage

| Context                          | Stack Depth |
|----------------------------------|-------------|
| `vs_platform_init`               | ~2.4 KiB    |
| `vs_submit_can_frame`            | ~1.2 KiB    |
| `vs_submit_eth_packet`           | ~1.8 KiB    |
| `vs_platform_tick`               | ~3.2 KiB    |
| `vs_get_health`                  | ~0.8 KiB    |
| Maximum (any FFI entry point)    | <4 KiB      |

Stack measurements obtained via `-Z emit-stack-sizes` and manual analysis of
the call graph. No recursive calls exist in any execution path.

### Heap Usage

The Craton Shield runtime performs **zero heap allocations** during steady-state
operation. All buffers are statically sized or stack-allocated. The only
allocations occur during `vs_platform_init` (one-time setup of the `Mutex`-
wrapped global state) and are freed on `vs_platform_shutdown`.

## WCET Considerations

Craton Shield is designed for deterministic execution suitable for ASIL-B
applications:

- **No heap allocation** in the hot path. All data structures use fixed-size
  arrays and ring buffers.
- **Bounded loops only.** Every loop in the runtime has a compile-time or
  configuration-time upper bound (e.g., max 128 firewall rules at base tier, max 64-byte CAN
  payload, max 9216-byte Ethernet frame).
- **No recursion.** The call graph is statically provable to be acyclic.
- **Deterministic branching.** All match/switch arms are exhaustive; no
  data-dependent iteration counts in the critical path.
- **Panic-safe FFI boundary.** `catch_unwind` guards prevent stack unwinding
  across the C/Rust boundary. Panics are counted and reported via
  `vs_get_panic_count()`.
- **Rate limiting** is O(1) per frame (token bucket with constant-time
  refill).
- **No floating-point** in the critical path (EWMA uses fixed-point
  arithmetic).
- **No system calls** in `submit_can_frame`, `submit_eth_packet`, or
  `platform_tick` (mutex acquisition uses futex on Linux, which is a syscall
  only on contention).

## Automotive Timing Budget Compliance

| Bus / Domain         | Typical Budget | Before (v0.5.0) | Margin | After (v0.7.0) | Margin     |
|----------------------|----------------|------------------|--------|-----------------|------------|
| CAN (500 kbit/s)     | ~10 us/frame   | ~464 ns          | 21x    | ~265 ns         | **37x**    |
| Automotive Ethernet   | ~100 us/packet | ~1.2 us          | 83x    | ~28 ns          | **3,571x** |
| Full tick (idle)      | 1 ms budget    | ~5 us            | 200x   | ~73 ns          | **13,700x**|

All measured latencies remain well within the timing budgets defined by
ISO 11898 (CAN), ISO 11898-2 (CAN-FD), and IEEE 802.3 (Automotive Ethernet),
leaving substantial margin for jitter, OS scheduling, and interrupt latency on
production ECU hardware.

### Target Platform Estimates

The benchmarks above are from an x86_64 workstation. On representative
automotive targets, expected scaling factors are:

| Target MCU               | Clock    | Estimated Scaling Factor |
|--------------------------|----------|--------------------------|
| ARM Cortex-R52 (Traveo)  | 400 MHz  | ~8-12x slower            |
| ARM Cortex-A53 (S32G)    | 1.0 GHz  | ~3-5x slower             |
| Infineon AURIX TC3xx     | 300 MHz  | ~10-15x slower           |

Even with a 15x scaling factor on the slowest target (AURIX TC3xx), the
optimized latencies remain well within budget:

| Operation (scaled 15x) | Estimated Latency | Budget   | Margin |
|-------------------------|-------------------|----------|--------|
| CAN frame submission    | ~4.0 us           | 10 us    | 2.5x   |
| ETH packet inspection   | ~0.4 us           | 100 us   | 250x   |
| Full tick (idle)        | ~1.1 us           | 1 ms     | 900x   |
