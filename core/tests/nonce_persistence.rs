// SPDX-License-Identifier: Apache-2.0
//! Tests for NonceCounter persistence and reboot safety (V6 fix).

use vs_crypto::NonceCounter;

#[test]
fn nonce_counter_basic_increment() {
    let mut nc = NonceCounter::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap();
    let n1 = nc.next().unwrap();
    let n2 = nc.next().unwrap();

    // 8-byte prefix should be preserved.
    assert_eq!(&n1[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&n2[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    // Counter portion should differ.
    assert_ne!(n1, n2);

    // Counter should be monotonically increasing.
    assert_eq!(nc.count(), 2);
}

#[test]
fn nonce_counter_persisted_skips_margin() {
    let persisted_value = 1000u32;
    let nc = NonceCounter::new_persisted(
        [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44],
        persisted_value,
    )
    .unwrap();

    // Should have skipped past persisted_value + safety margin (1024).
    assert!(nc.count() > persisted_value);
    assert_eq!(nc.count(), persisted_value + 1024);
}

#[test]
fn nonce_counter_persisted_then_generate_no_overlap() {
    // Simulate: session 1 generates 500 nonces, persists counter.
    let mut nc1 = NonceCounter::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap();
    let mut session1_nonces = Vec::new();
    for _ in 0..500 {
        session1_nonces.push(nc1.next().unwrap());
    }
    let persisted = nc1.counter_for_persistence();
    assert_eq!(persisted, 500);

    // Session 2 restores from persisted counter.
    let mut nc2 =
        NonceCounter::new_persisted([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], persisted)
            .unwrap();
    let mut session2_nonces = Vec::new();
    for _ in 0..500 {
        session2_nonces.push(nc2.next().unwrap());
    }

    // No nonce from session 2 should overlap with session 1.
    for n2 in &session2_nonces {
        assert!(
            !session1_nonces.contains(n2),
            "Nonce collision detected across reboot!"
        );
    }
}

#[test]
fn nonce_counter_random_prefix_different_each_boot() {
    let mut nc1 =
        NonceCounter::new_random_prefix([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]).unwrap();
    let mut nc2 =
        NonceCounter::new_random_prefix([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]).unwrap();

    let n1 = nc1.next().unwrap();
    let n2 = nc2.next().unwrap();

    // Different prefixes ensure different nonces even at the same counter.
    assert_ne!(n1, n2);
}

#[test]
fn nonce_counter_persisted_saturating_at_max() {
    // All-zero prefix is now rejected — verify it returns an error.
    assert!(NonceCounter::new_persisted([0; 8], u32::MAX - 100).is_err());
}

#[test]
fn nonce_counter_for_persistence_roundtrip() {
    let mut nc = NonceCounter::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]).unwrap();
    for _ in 0..42 {
        nc.next().unwrap();
    }
    assert_eq!(nc.counter_for_persistence(), 42);
}

#[test]
fn nonce_counter_8byte_prefix_provides_larger_birthday_bound() {
    // Verify that with 8-byte prefix, each nonce is a full 12 bytes
    let mut nc = NonceCounter::new([0xFF; 8]).unwrap();
    let nonce = nc.next().unwrap();
    assert_eq!(nonce.len(), 12);
    assert_eq!(&nonce[..8], &[0xFF; 8]);
    // Counter part is last 4 bytes, value should be 1
    assert_eq!(&nonce[8..], &1u32.to_be_bytes());
}

#[test]
fn test_nonce_counter_custom_margin() {
    let prefix = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let persisted_value = 500u32;
    let custom_margin = 5000u32;

    let mut nc =
        NonceCounter::new_persisted_with_margin(prefix, persisted_value, custom_margin).unwrap();

    // Counter should have skipped past persisted_value + custom_margin.
    assert_eq!(
        nc.count(),
        persisted_value + custom_margin,
        "counter should start at persisted + custom margin"
    );

    // Generate a nonce and verify prefix is preserved.
    let nonce = nc.next().unwrap();
    assert_eq!(&nonce[..8], &prefix, "prefix should be preserved");

    // Counter should now be one past the starting point.
    assert_eq!(nc.count(), persisted_value + custom_margin + 1);

    // Verify counter_for_persistence reflects the current state.
    assert_eq!(
        nc.counter_for_persistence(),
        persisted_value + custom_margin + 1
    );
}
