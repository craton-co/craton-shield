// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::SoftwareCryptoProvider;
use vs_integrity::{IntegrityMonitor, IntegrityResult, IntegrityStatus};

/// Deterministic no-op RNG for fuzzing (not cryptographically secure).
fn fuzz_rng(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
}

fuzz_target!(|data: &[u8]| {
    // Fuzz the integrity monitor with arbitrary region data.
    // The monitor must not panic on any input.
    if data.len() < 16 {
        return;
    }

    let crypto = SoftwareCryptoProvider::new(fuzz_rng);
    let mut monitor = IntegrityMonitor::new(crypto);

    // Register a region with the first chunk of fuzzed data as the baseline.
    let region_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let base_addr = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let region_data = &data[8..];

    if region_data.is_empty() {
        return;
    }

    // Cap region data length to avoid excessive hashing.
    let len = region_data.len().min(256);
    let baseline = &region_data[..len];

    if monitor.register_region(region_id, base_addr, baseline).is_ok() {
        // Verify with the same data — must succeed and report Ok.
        if let Ok(result) = monitor.verify_region(region_id, base_addr, baseline) {
            assert_eq!(
                result.status,
                IntegrityStatus::Ok,
                "unmodified region must verify as Ok"
            );
        }

        // Corrupt a single byte of the baseline and verify tamper is detected.
        // Only possible when the region has at least one byte.
        if len >= 1 {
            let mut corrupted = [0u8; 256];
            corrupted[..len].copy_from_slice(baseline);
            corrupted[0] ^= 0xFF;
            if let Ok(result) = monitor.verify_region(region_id, base_addr, &corrupted[..len]) {
                assert_eq!(
                    result.status,
                    IntegrityStatus::Tampered,
                    "single-byte corruption must be detected as Tampered"
                );
            }
        }

        // Verify with arbitrary fuzz-mutated data (may detect tamper or differ in length).
        if data.len() > 8 + len {
            let mutated_len = (data.len() - 8 - len).min(len);
            let mutated = &data[8 + len..8 + len + mutated_len];
            let _ = monitor.verify_region(region_id, base_addr, mutated);
        }

        // Exercise verify_all with a data provider closure.
        let mut results = [IntegrityResult {
            region_id: 0,
            status: IntegrityStatus::Unavailable,
        }; 64];

        let _ = monitor.verify_all(
            |_id, _addr, length| {
                if length <= len {
                    Some(&baseline[..length])
                } else {
                    None
                }
            },
            &mut results,
        );

        // Unregister the region.
        let _ = monitor.unregister_region(region_id);
    }
});
