// SPDX-License-Identifier: Apache-2.0
//! Linux timer implementation using `clock_gettime(CLOCK_MONOTONIC_RAW)`.

use core::sync::atomic::{AtomicU64, Ordering};

use vs_hal::Timer;

/// Linux monotonic timer backed by `CLOCK_MONOTONIC_RAW`.
///
/// On aarch64, [`cycle_count`](Timer::cycle_count) reads `PMCCNTR_EL0`
/// (requires kernel to enable userspace access via `PMUSERENR_EL0`).
/// On x86_64 it reads the TSC via `RDTSC`.
pub struct LinuxTimer {
    /// Last known good timestamp for fallback on `clock_gettime` failure.
    last_us: AtomicU64,
}

impl LinuxTimer {
    /// Create a new Linux timer.
    pub fn new() -> Self {
        Self {
            last_us: AtomicU64::new(0),
        }
    }
}

impl Default for LinuxTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for LinuxTimer {
    fn now_us(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, stack-allocated `timespec`.
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut ts) };
        // clock_gettime with CLOCK_MONOTONIC_RAW should never fail on a
        // running Linux kernel, but if it does we return the last known
        // timestamp to maintain monotonicity guarantees.
        // Use an unconditional check (not debug_assert) so that the failure
        // is handled identically in release builds — returning the last
        // known-good value preserves monotonicity.
        #[cfg(debug_assertions)]
        debug_assert!(ret == 0, "clock_gettime(CLOCK_MONOTONIC_RAW) failed");
        if ret != 0 {
            // Returning 0 could reset time-based security checks.
            // Return last known good value instead.
            return self.last_us.load(Ordering::Relaxed);
        }
        let result = (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000;
        self.last_us.store(result, Ordering::Relaxed);
        result
    }

    fn cycle_count(&self) -> Option<u64> {
        #[cfg(target_arch = "aarch64")]
        {
            let count: u64;
            // SAFETY: reading PMCCNTR_EL0 is a read-only operation.
            // Requires PMUSERENR_EL0.EN to be set by the kernel.
            unsafe {
                core::arch::asm!("mrs {}, pmccntr_el0", out(reg) count);
            }
            Some(count)
        }
        #[cfg(target_arch = "x86_64")]
        {
            let lo: u64;
            let hi: u64;
            // SAFETY: RDTSC is a read-only, always-available instruction.
            unsafe {
                core::arch::asm!("rdtsc", out("rax") lo, out("rdx") hi);
            }
            Some((hi << 32) | lo)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_now_us_returns_nonzero() {
        let timer = LinuxTimer::new();
        assert!(timer.now_us() > 0);
    }

    #[test]
    fn timer_now_us_is_monotonic() {
        let timer = LinuxTimer::new();
        let t1 = timer.now_us();
        let t2 = timer.now_us();
        assert!(t2 >= t1);
    }

    #[test]
    fn timer_default_works() {
        let timer = LinuxTimer::default();
        assert!(timer.now_us() > 0);
    }

    #[test]
    fn timer_cycle_count_available_on_this_platform() {
        let timer = LinuxTimer::new();
        let count = timer.cycle_count();
        // On x86_64 and aarch64, cycle_count should return Some.
        // On other platforms, it returns None.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert!(count.is_some());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        assert!(count.is_none());
    }

    #[test]
    fn timer_cycle_count_monotonic() {
        let timer = LinuxTimer::new();
        if let (Some(c1), Some(c2)) = (timer.cycle_count(), timer.cycle_count()) {
            assert!(c2 >= c1);
        }
    }

    #[test]
    fn timer_microsecond_resolution() {
        let timer = LinuxTimer::new();
        let t1 = timer.now_us();
        // Busy-wait briefly to ensure the clock advances.
        for _ in 0..100_000 {
            core::hint::black_box(());
        }
        let t2 = timer.now_us();
        assert!(t2 > t1, "timer should advance after busy-wait");
    }

    #[test]
    fn timer_last_us_updated_after_read() {
        let timer = LinuxTimer::new();
        assert_eq!(timer.last_us.load(Ordering::Relaxed), 0);
        let t = timer.now_us();
        assert!(t > 0);
        assert_eq!(timer.last_us.load(Ordering::Relaxed), t);
    }

    #[test]
    fn timer_multiple_reads_all_monotonic() {
        let timer = LinuxTimer::new();
        let mut prev = timer.now_us();
        for _ in 0..1000 {
            let t = timer.now_us();
            assert!(t >= prev, "timer must be monotonic");
            prev = t;
        }
    }

    #[test]
    fn timer_cycle_count_nonzero_on_supported_platforms() {
        let timer = LinuxTimer::new();
        if let Some(c) = timer.cycle_count() {
            assert!(
                c > 0,
                "cycle count should be nonzero on supported platforms"
            );
        }
    }
}
