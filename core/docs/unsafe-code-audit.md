# Unsafe Code Audit

**Version**: 1.0.0 | **Date**: 2026-03-28 | **Auditor**: Automated

## Summary

37 `unsafe` items in production code (6 in `vs-ffi`, 29 in `vs-hal-linux`, 2 in `vs-storage`), plus 4 in benchmarks/examples. See the tables below for a line-by-line audit of each item.

## Policy

- Workspace-level `unsafe_code = "deny"` lint
- Only `vs-ffi` and `vs-hal-linux` use `#![allow(unsafe_code)]`
- `vs-storage` has 2 targeted `#[allow(unsafe_code)]` for mlock/munlock
- All other crates use `#![forbid(unsafe_code)]`
- Every unsafe block requires a `// SAFETY:` comment
- CI runs `cargo-geiger` to track unsafe usage

## vs-ffi (C ABI Boundary)

The FFI crate exposes `extern "C"` functions to C callers. Each function uses `#[allow(unsafe_code)]` because `extern "C"` is inherently unsafe at the ABI boundary. Functions accepting pointers are declared `unsafe extern "C"` and contain inner `unsafe` blocks for pointer dereference/write operations.

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 1 | `crates/ffi/src/lib.rs` | 342 | `extern "C" fn vs_get_poisoned_mutex_count()` | Atomic load of `POISONED_MUTEX_COUNT`; no pointer dereference. Pure read-only query. | Required for `extern "C"` ABI export to C callers. |
| 2 | `crates/ffi/src/lib.rs` | 506 | `extern "C" fn vs_get_panic_count()` | Atomic load of `PANIC_COUNT`; no pointer dereference. Pure read-only query. | Required for `extern "C"` ABI export to C callers. |
| 3 | `crates/ffi/src/lib.rs` | 517 | `extern "C" fn vs_is_degraded()` | Atomic load of `DEGRADED` flag; no pointer dereference. Pure read-only query. | Required for `extern "C"` ABI export to C callers. |
| 4 | `crates/ffi/src/lib.rs` | 536 | `extern "C" fn vs_platform_init()` | Acquires mutex, initializes platform. No raw pointer operations. Wrapped in `ffi_guard` (`catch_unwind`). | Required for `extern "C"` ABI export. Initializes the global `CratonShield` instance. |
| 5 | `crates/ffi/src/lib.rs` | — | ~~`extern "C" fn vs_platform_init_permissive()`~~ | **Removed (C1 / C2 audit fix).** The fail-open initialisation path no longer exists; `policy_fail_open` was deleted from `PlatformConfig`. All paths are fail-closed. | — |
| 6 | `crates/ffi/src/lib.rs` | 637 | `extern "C" fn vs_platform_tick(timestamp_us: u64)` | Acquires mutex, calls `platform.tick()`. No raw pointer operations. Wrapped in `ffi_guard`. | Required for `extern "C"` ABI export. Periodic tick entry point. |
| 7 | `crates/ffi/src/lib.rs` | 664 | `unsafe extern "C" fn vs_submit_can_frame(frame: *const VsCanFrame)` | Function-level `unsafe` because caller must provide a valid, aligned `VsCanFrame` pointer. Validates non-null, alignment, CAN ID range, and DLC before use. | Required for C ABI. Accepts a raw pointer to a CAN frame from C callers. |
| 8 | `crates/ffi/src/lib.rs` | 681 | `unsafe { &*frame }` (inside `vs_submit_can_frame`) | SAFETY: `frame` is verified non-null and properly aligned on lines 669-676. Caller guarantees validity per function contract. | Dereferences the raw pointer to read the CAN frame fields. |
| 9 | `crates/ffi/src/lib.rs` | 770 | `unsafe extern "C" fn vs_submit_eth_packet(data: *const u8, len: usize)` | Function-level `unsafe` because caller must provide a valid pointer to `len` readable bytes. Validates non-null, length bounds (14..9216). | Required for C ABI. Accepts a raw byte pointer to an Ethernet packet. |
| 10 | `crates/ffi/src/lib.rs` | 795 | `unsafe { core::slice::from_raw_parts(data, len) }` (inside `vs_submit_eth_packet`) | SAFETY: `data` is verified non-null on line 777, `len` is verified in range [14, 9216] on lines 782-789. Caller guarantees at least `len` readable bytes. | Constructs a Rust slice from the C caller's raw byte buffer. |
| 11 | `crates/ffi/src/lib.rs` | 996 | `unsafe extern "C" fn vs_get_health(out: *mut VsHealth)` | Function-level `unsafe` because caller must provide a valid, aligned, writable `VsHealth` pointer. Validates non-null and alignment. | Required for C ABI. Writes health status to caller-provided buffer. |
| 12 | `crates/ffi/src/lib.rs` | 1019 | `unsafe { core::ptr::write(out, health) }` (inside `vs_get_health`) | SAFETY: `out` is verified non-null and aligned on lines 1001-1008. Caller guarantees the pointer is writable and valid for the call duration. | Writes the `VsHealth` struct to the C caller's output pointer. |
| 13 | `crates/ffi/src/lib.rs` | 1036 | `extern "C" fn vs_platform_shutdown()` | Acquires mutex (or clears poisoned state), drops the platform. No raw pointer operations. Wrapped in `ffi_guard`. | Required for `extern "C"` ABI export. Shutdown and resource cleanup entry point. |

## vs-hal-linux (Linux System Calls)

All unsafe blocks in `vs-hal-linux` wrap Linux system calls (`libc` FFI). The crate uses `#![allow(unsafe_code)]` at the module level.

### lib.rs

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 14 | `crates/hal-linux/src/lib.rs` | 31 | `unsafe { *libc::__errno_location() }` | SAFETY: reading errno via the thread-local `__errno_location` pointer. Always valid on Linux. | Required to translate libc error codes into `VsError` variants. |

### can.rs

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 15 | `crates/hal-linux/src/can.rs` | 158 | `unsafe impl Send for LinuxCanBus {}` | SAFETY: fd used exclusively through `&mut self`; read-only queries access kernel state via sysfs or immutable cached values. No concurrent fd access possible. | `LinuxCanBus` owns a raw fd which is not auto-`Send`. Manual impl needed for cross-thread use. |
| 16 | `crates/hal-linux/src/can.rs` | 187-194 | `unsafe { libc::setsockopt(..., null(), 0) }` (in `set_filters`, empty case) | SAFETY: passing null pointer with len 0 clears the CAN filter list. fd is valid. | Required to remove all CAN acceptance filters via `setsockopt`. |
| 17 | `crates/hal-linux/src/can.rs` | 218-226 | `unsafe { libc::setsockopt(..., kfilters...) }` (in `set_filters`, non-empty case) | SAFETY: `kfilters` is valid stack memory, `optlen` is bounded by `MAX_CAN_FILTERS`. | Required to install CAN acceptance filters via `setsockopt`. |
| 18 | `crates/hal-linux/src/can.rs` | 270-352 | `unsafe { ... }` (in `open`) | SAFETY: creating a raw CAN socket. All pointers are to valid stack-allocated structures. Return values are checked. fd is closed on error paths. | Required to create and bind a SocketCAN socket, resolve interface index, enable CAN-FD and error frames. |
| 19 | `crates/hal-linux/src/can.rs` | 396-420 | `unsafe { libc::open/read/close }` (in `read_can_state_sysfs`) | SAFETY: `path` is a valid null-terminated C string on the stack. fd is closed after read. | Required to read CAN interface operational state from sysfs. |
| 20 | `crates/hal-linux/src/can.rs` | 467-489 | `unsafe { libc::open/read/close }` (in `read_sysfs_u64`) | SAFETY: `path` is a null-terminated stack buffer. fd is closed after read. | Required to read error counters and other numeric values from sysfs. |
| 21 | `crates/hal-linux/src/can.rs` | 503 | `unsafe { libc::clock_gettime(CLOCK_MONOTONIC_RAW, &mut ts) }` | SAFETY: `ts` is a valid stack-allocated `timespec`. | Required to obtain monotonic timestamps for CAN frame timestamping. |
| 22 | `crates/hal-linux/src/can.rs` | 548 | `unsafe { libc::close(self.fd) }` (in `Drop`) | SAFETY: closing a valid file descriptor exactly once. Drop runs once per value. | Required to release the socket fd when `LinuxCanBus` is dropped. |
| 23 | `crates/hal-linux/src/can.rs` | 642-649 | `unsafe { libc::open/write/close }` (in `recover_bus_off`) | SAFETY: `path` is a valid null-terminated string on the stack. Writes "1" to sysfs restart node. | Required to trigger CAN bus-off recovery via sysfs. |
| 24 | `crates/hal-linux/src/can.rs` | 659 | `unsafe { core::mem::zeroed::<KernelCanFrame>() }` (in `receive_classic`) | SAFETY: `KernelCanFrame` is `#[repr(C)]` with all-integer fields; zero is a valid bit pattern. | Required to initialize a kernel CAN frame buffer before `read()`. |
| 25 | `crates/hal-linux/src/can.rs` | 661-667 | `unsafe { libc::read(self.fd, ...) }` (in `receive_classic`) | SAFETY: reading into a valid, stack-allocated kernel CAN frame. fd is valid. | Required to receive a classic CAN frame from the SocketCAN socket. |
| 26 | `crates/hal-linux/src/can.rs` | 694 | `unsafe { core::mem::zeroed::<KernelCanFdFrame>() }` (in `receive_fd`) | SAFETY: `KernelCanFdFrame` is `#[repr(C)]` with all-integer fields; zero is a valid bit pattern. | Required to initialize a kernel CAN-FD frame buffer before `read()`. |
| 27 | `crates/hal-linux/src/can.rs` | 695-701 | `unsafe { libc::read(self.fd, ...) }` (in `receive_fd`) | SAFETY: reading into a valid, stack-allocated kernel CAN-FD frame. fd is valid. | Required to receive a CAN-FD frame from the SocketCAN socket. |
| 28 | `crates/hal-linux/src/can.rs` | 720 | `unsafe { core::ptr::from_ref(&kf).cast::<KernelCanFrame>().read() }` (in `receive_fd`) | SAFETY: `KernelCanFdFrame` and `KernelCanFrame` share the initial 4-byte `can_id` field at the same offset. Both are `#[repr(C)]`. The kernel wrote at least `sizeof(KernelCanFrame)` bytes. | Required to reinterpret a short read (classic-sized frame received on FD socket) as a classic frame for error frame detection. |
| 29 | `crates/hal-linux/src/can.rs` | 744-749 | `unsafe { libc::write(self.fd, ...) }` (in `transmit_classic`) | SAFETY: writing a valid, stack-allocated kernel CAN frame to the socket fd. | Required to transmit a classic CAN frame via SocketCAN. |
| 30 | `crates/hal-linux/src/can.rs` | 759-764 | `unsafe { libc::write(self.fd, ...) }` (in `transmit_fd`) | SAFETY: writing a valid, stack-allocated kernel CAN-FD frame to the socket fd. | Required to transmit a CAN-FD frame via SocketCAN. |

### ethernet.rs

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 31 | `crates/hal-linux/src/ethernet.rs` | 98 | `unsafe impl Send for LinuxEthernetPhy {}` | SAFETY: fd used exclusively through `&mut self` methods. Read-only queries use ioctl on a copy of the socket fd. No concurrent mutation possible. Does not implement `Clone` or `Sync`. | `LinuxEthernetPhy` owns a raw fd; manual `Send` impl needed for cross-thread use. |
| 32 | `crates/hal-linux/src/ethernet.rs` | 143-190 | `unsafe { ... }` (in `open`) | SAFETY: creating a raw `AF_PACKET` socket. All pointers are to valid stack-allocated structures. Return values are checked. fd is closed on error paths. | Required to create, configure, and bind a raw Ethernet socket. |
| 33 | `crates/hal-linux/src/ethernet.rs` | 205 | `unsafe { libc::clock_gettime(CLOCK_MONOTONIC_RAW, &mut ts) }` | SAFETY: `ts` is a valid, stack-allocated `timespec`. | Required to obtain monotonic timestamps for Ethernet frame timestamping. |
| 34 | `crates/hal-linux/src/ethernet.rs` | 216-237 | `unsafe { ... }` (in `ethtool_speed`) | SAFETY: `ecmd` and `ifr` are valid stack-allocated structures. ioctl is called with valid fd. Return value is checked. | Required to query link speed via the legacy `ETHTOOL_GSET` ioctl. |
| 35 | `crates/hal-linux/src/ethernet.rs` | 242-244 | `unsafe { libc::close(self.fd) }` (in `Drop`) | SAFETY: closing a valid file descriptor exactly once. Drop runs once per value. | Required to release the socket fd when `LinuxEthernetPhy` is dropped. |
| 36 | `crates/hal-linux/src/ethernet.rs` | 252 | `unsafe { libc::read(self.fd, ...) }` (in `receive`) | SAFETY: reading into a valid, stack-allocated buffer (`frame.data`). fd is valid. | Required to receive raw Ethernet frames from the `AF_PACKET` socket. |
| 37 | `crates/hal-linux/src/ethernet.rs` | 280 | `unsafe { libc::write(self.fd, padded...) }` (in `transmit`, short frame path) | SAFETY: writing from a valid stack-allocated padded buffer to the socket fd. | Required to transmit short Ethernet frames (padded to 60 bytes minimum). |
| 38 | `crates/hal-linux/src/ethernet.rs` | 287 | `unsafe { libc::write(self.fd, data...) }` (in `transmit`, normal path) | SAFETY: writing from a valid slice to the socket fd. | Required to transmit Ethernet frames via the raw socket. |
| 39 | `crates/hal-linux/src/ethernet.rs` | 302-315 | `unsafe { ... }` (in `link_is_up`) | SAFETY: ioctl with a valid fd and stack-allocated `ifreq`. Return values are checked. | Required to query interface flags (`IFF_UP | IFF_RUNNING`) via ioctl. |

### timer.rs

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 40 | `crates/hal-linux/src/timer.rs` | 40 | `unsafe { libc::clock_gettime(CLOCK_MONOTONIC_RAW, &mut ts) }` | SAFETY: `ts` is a valid, stack-allocated `timespec`. | Required to read the monotonic clock for timer implementation. |
| 41 | `crates/hal-linux/src/timer.rs` | 61-63 | `unsafe { core::arch::asm!("mrs {}, pmccntr_el0", ...) }` (aarch64 `cycle_count`) | SAFETY: reading `PMCCNTR_EL0` is a read-only operation. Requires `PMUSERENR_EL0.EN` set by kernel. | Required to read the ARM performance monitor cycle counter for WCET measurement. |
| 42 | `crates/hal-linux/src/timer.rs` | 71-73 | `unsafe { core::arch::asm!("rdtsc", ...) }` (x86_64 `cycle_count`) | SAFETY: `RDTSC` is a read-only, always-available instruction on x86_64. | Required to read the x86_64 timestamp counter for WCET measurement. |

## vs-storage (Memory Locking)

These two functions use targeted `#[allow(unsafe_code)]` annotations to call `mlock`/`munlock` for preventing sensitive data from being swapped to disk.

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 43 | `crates/storage/src/file_storage.rs` | 391 | `unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) }` | SAFETY: `mlock` is safe to call on any valid memory range. It is a no-op if memory is already locked. | Required to prevent key material and HMACs from being paged out to disk. |
| 44 | `crates/storage/src/file_storage.rs` | 411 | `unsafe { libc::munlock(buf.as_ptr().cast(), buf.len()) }` | SAFETY: `munlock` is safe to call on any valid memory range. | Required to unlock previously mlocked memory when buffers are released. |

## Benchmarks & Examples

These unsafe blocks appear in non-production code (benchmarks and examples).

| # | File | Line | Code | Safety Justification | Necessity |
|---|------|------|------|---------------------|-----------|
| 45 | `benches/wcet_harness.rs` | 54-56 | `unsafe { core::arch::asm!("mrs {}, pmccntr_el0", ...) }` (aarch64 in `read_cycles`) | SAFETY: reads the aarch64 performance monitor cycle counter register. Read-only, no side effects. | Required for hardware cycle counting in WCET measurement on ARM. |
| 46 | `benches/wcet_harness.rs` | 67-69 | `unsafe { core::arch::asm!("lfence", "rdtsc", ...) }` (x86_64 in `read_cycles`) | SAFETY: `lfence` + `rdtsc` is a standard serializing timestamp read on x86_64. Both instructions are read-only. | Required for hardware cycle counting in WCET measurement on x86_64. |
| 47 | `benches/wcet_harness.rs` | 97-100 | `unsafe { core::arch::asm!("dsb sy"); core::arch::asm!("isb"); }` (aarch64 in `memory_barrier`) | SAFETY: `dsb sy` + `isb` are memory/instruction barriers with no side effects beyond ensuring prior memory operations are visible. | Required to ensure memory ordering before WCET measurement on ARM. |
| 48 | `examples/s32g3_integration.rs` | 39-42 | `unsafe { COUNTER += 1_000; COUNTER }` (in `simulated_timer_us`) | Uses `static mut` for a simple simulated timer counter. Only safe in single-threaded example code. | Simulates S32G3 STM timer ticks in the integration example. Not production code. |

## Risk Assessment

### High Scrutiny Areas

1. **FFI pointer dereference** (items 8, 10, 12): These are the most dangerous unsafe blocks. Mitigated by null checks, alignment checks, and length validation before dereference.

2. **`unsafe impl Send`** (items 15, 31): Incorrect `Send` implementations could cause data races. Mitigated by the borrow checker requiring `&mut self` for all mutating operations.

3. **`mem::zeroed` + pointer cast** (item 28): Reinterpret-casting `KernelCanFdFrame` as `KernelCanFrame`. Mitigated by both being `#[repr(C)]` with identical initial layout and the kernel guaranteeing at least `sizeof(KernelCanFrame)` bytes were written.

### Low Risk Areas

4. **System call wrappers** (items 14, 16-27, 29-42): Standard libc FFI calls with stack-allocated buffers. Risk is limited to incorrect buffer sizes or fd lifetime bugs, both mitigated by Rust ownership.

5. **`mlock`/`munlock`** (items 43-44): Safe to call on any valid memory range per POSIX specification.

6. **Inline assembly** (items 41-42, 45-47): Read-only hardware register reads and memory barriers. No side effects beyond their documented purpose.

## Recommendations

1. Consider replacing the `static mut COUNTER` in the S32G3 example (item 48) with an `AtomicU64` to eliminate the unsafe block entirely.
2. Monitor `cargo-geiger` output in CI to detect any new unsafe usage in crates that should remain unsafe-free.
3. Re-audit after any changes to the `vs-ffi` or `vs-hal-linux` crates.
