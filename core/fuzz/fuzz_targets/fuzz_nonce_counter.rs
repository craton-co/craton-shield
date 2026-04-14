// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::NonceCounter;

fuzz_target!(|data: &[u8]| {
    // Fuzz the NonceCounter with arbitrary prefix and iteration counts.
    if data.len() < 10 {
        return;
    }

    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&data[..8]);
    let iterations = u16::from_le_bytes([data[8], data[9]]) as usize;

    if let Ok(mut nc) = NonceCounter::new(prefix) {
        let mut prev: Option<[u8; 12]> = None;

        for _ in 0..iterations.min(1000) {
            match nc.next() {
                Ok(nonce) => {
                    // Verify monotonicity: each nonce must differ from the previous.
                    if let Some(p) = prev {
                        assert_ne!(p, nonce, "nonce collision detected");
                    }
                    // Verify prefix is preserved.
                    assert_eq!(&nonce[..8], &prefix);
                    prev = Some(nonce);
                }
                Err(_) => break, // ResourceExhausted is expected at u32::MAX
            }
        }
    }
});
