// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the `vs_event_logger` crate.

mod common;

use common::make_crypto;
use vs_crypto::SoftwareCryptoProvider;
use vs_event_logger::{ChainIntegrity, EventLog, EventType, LogEntry};
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a blank `LogEntry` suitable for pre-filling output buffers.
fn blank_entry() -> LogEntry {
    LogEntry {
        sequence: 0,
        timestamp_us: 0,
        event_type: EventType::SystemEvent,
        payload: [0u8; 128],
        payload_len: 0,
        prev_hash: [0u8; 32],
        entry_hmac: [0u8; 32],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn event_log_append_and_count() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    log.append(EventType::SecurityAlert, b"alert-one", 1000, &crypto)
        .expect("append 1");
    log.append(EventType::SecurityAlert, b"alert-two", 2000, &crypto)
        .expect("append 2");
    log.append(EventType::SecurityAlert, b"alert-three", 3000, &crypto)
        .expect("append 3");

    assert_eq!(log.entry_count(), 3);
}

#[test]
fn event_log_verify_chain_intact() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    for i in 0..5u64 {
        log.append(EventType::SecurityAlert, &[i as u8; 8], i * 1000, &crypto)
            .expect("append");
    }

    let integrity = log.verify_chain(&crypto).expect("verify_chain");
    assert_eq!(
        integrity,
        ChainIntegrity {
            entries_verified: 5,
            first_tampered_seq: None,
        }
    );
}

#[test]
fn event_log_export_entries() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    log.append(EventType::SecurityAlert, b"payload-0", 1000, &crypto)
        .expect("append 0");
    log.append(EventType::SecurityAlert, b"payload-1", 2000, &crypto)
        .expect("append 1");
    log.append(EventType::SecurityAlert, b"payload-2", 3000, &crypto)
        .expect("append 2");

    let mut out = [blank_entry(); 10];
    let n = log.export_entries(0, 2, &mut out);
    assert_eq!(n, 3);

    // Verify sequential sequence numbers.
    assert_eq!(out[0].sequence, 0);
    assert_eq!(out[1].sequence, 1);
    assert_eq!(out[2].sequence, 2);
}

#[test]
fn event_log_different_event_types() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    log.append(EventType::SecurityAlert, b"sec", 100, &crypto)
        .expect("SecurityAlert");
    log.append(EventType::KeyOperation, b"key", 200, &crypto)
        .expect("KeyOperation");
    log.append(EventType::BootEvent, b"boot", 300, &crypto)
        .expect("BootEvent");
    log.append(EventType::OtaUpdate, b"ota", 400, &crypto)
        .expect("OtaUpdate");
    log.append(EventType::SystemEvent, b"sys", 500, &crypto)
        .expect("SystemEvent");
    log.append(EventType::PolicyChange, b"pol", 600, &crypto)
        .expect("PolicyChange");

    let integrity = log.verify_chain(&crypto).expect("verify_chain");
    assert_eq!(integrity.entries_verified, 6);
    assert_eq!(integrity.first_tampered_seq, None);
}

#[test]
fn event_log_overflow_ring_buffer() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 8>::new(KeyId(0), &crypto).unwrap();

    for i in 0..12u64 {
        log.append(EventType::SecurityAlert, &[i as u8; 4], i * 100, &crypto)
            .expect("append");
    }

    // entry_count is monotonic and counts all appends, not just stored entries.
    assert_eq!(log.entry_count(), 12);

    // Chain verification should pass for the entries still in the buffer.
    let integrity = log.verify_chain(&crypto).expect("verify_chain");
    assert_eq!(integrity.entries_verified, 8);
    assert_eq!(integrity.first_tampered_seq, None);
}

#[test]
fn event_log_empty_log_verifies() {
    let crypto = make_crypto();
    let log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    let integrity = log.verify_chain(&crypto).expect("verify_chain");
    assert_eq!(integrity.entries_verified, 0);
    assert_eq!(integrity.first_tampered_seq, None);
}

#[test]
fn event_log_payload_truncation() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    // Exactly 128 bytes.
    let full_payload = [0xAB; 128];
    log.append(EventType::SecurityAlert, &full_payload, 1000, &crypto)
        .expect("append full payload");

    // Shorter payload.
    log.append(EventType::SecurityAlert, b"short", 2000, &crypto)
        .expect("append short payload");

    let integrity = log.verify_chain(&crypto).expect("verify_chain");
    assert_eq!(integrity.entries_verified, 2);
    assert_eq!(integrity.first_tampered_seq, None);
}

#[test]
fn event_log_sequence_numbers_monotonic() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 64>::new(KeyId(0), &crypto).unwrap();

    for i in 0..5u64 {
        let seq = log
            .append(EventType::SecurityAlert, &[i as u8], i * 100, &crypto)
            .expect("append");
        assert_eq!(seq, i);
    }

    // Export all 5 entries and verify sequence numbers.
    let mut out = [blank_entry(); 5];
    let n = log.export_entries(0, 4, &mut out);
    assert_eq!(n, 5);

    for i in 0..5u64 {
        assert_eq!(out[i as usize].sequence, i);
    }
}

// ---------------------------------------------------------------------------
// V9 audit fix tests
// ---------------------------------------------------------------------------

#[test]
fn event_log_near_overflow_detection() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 10>::new(KeyId(0), &crypto).unwrap();

    // Fill to 90% (9 out of 10 slots).
    for i in 0..9u64 {
        log.append(EventType::SystemEvent, &[i as u8], i * 100, &crypto)
            .expect("append");
    }

    // At 9/10 capacity (90%), should report near-overflow.
    assert!(
        log.is_near_overflow(),
        "log should report near-overflow at 90% capacity"
    );
}

#[test]
fn event_log_not_near_overflow_when_half_full() {
    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 10>::new(KeyId(0), &crypto).unwrap();

    // Fill to 50% (5 out of 10 slots).
    for i in 0..5u64 {
        log.append(EventType::SystemEvent, &[i as u8], i * 100, &crypto)
            .expect("append");
    }

    // At 5/10 capacity (50%), should NOT report near-overflow.
    assert!(
        !log.is_near_overflow(),
        "log should not report near-overflow at 50% capacity"
    );
}

#[test]
fn event_log_overflow_callback_invoked() {
    use core::sync::atomic::{AtomicU64, Ordering};

    static OVERFLOW_SEQ: AtomicU64 = AtomicU64::new(u64::MAX);
    static OVERFLOW_TS: AtomicU64 = AtomicU64::new(0);

    fn on_overflow(seq: u64, timestamp_us: u64) {
        OVERFLOW_SEQ.store(seq, Ordering::SeqCst);
        OVERFLOW_TS.store(timestamp_us, Ordering::SeqCst);
    }

    let crypto = make_crypto();
    let mut log = EventLog::<SoftwareCryptoProvider, 4>::new(KeyId(0), &crypto).unwrap();
    log.set_overflow_callback(on_overflow);

    // Reset sentinel values.
    OVERFLOW_SEQ.store(u64::MAX, Ordering::SeqCst);
    OVERFLOW_TS.store(0, Ordering::SeqCst);

    // Fill the buffer completely (4 entries).
    for i in 0..4u64 {
        log.append(EventType::SecurityAlert, &[i as u8], (i + 1) * 100, &crypto)
            .expect("append");
    }

    // No overflow yet — callback should not have fired.
    assert_eq!(
        OVERFLOW_SEQ.load(Ordering::SeqCst),
        u64::MAX,
        "callback should not fire before overflow"
    );

    // 5th entry triggers overflow (evicts entry 0).
    log.append(EventType::SecurityAlert, &[0xFF], 500, &crypto)
        .expect("append overflow");

    // Callback should have been invoked with the evicted entry's data.
    assert_ne!(
        OVERFLOW_SEQ.load(Ordering::SeqCst),
        u64::MAX,
        "overflow callback must have been invoked"
    );
}
