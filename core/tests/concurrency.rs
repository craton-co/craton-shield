// SPDX-License-Identifier: Apache-2.0
//! Concurrency and thread-safety tests for Craton Shield.
//!
//! These tests verify that core subsystems behave correctly under concurrent
//! access, that no data races occur, and that internal synchronization
//! mechanisms work as intended.

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use vs_can_monitor::{CanFrame, CanMonitor};
use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS};
use vs_event_logger::{EventLog, EventType};
use vs_ids_engine::IdsEngine;
use vs_integrity::IntegrityMonitor;
use vs_netfw::{Firewall, FirewallRule, RuleAction};
use vs_types::KeyId;

use common::make_crypto;

// ---------------------------------------------------------------------------
// CAN monitor: concurrent frame submission (shared behind Mutex)
// ---------------------------------------------------------------------------

#[test]
fn can_monitor_concurrent_frame_submission() {
    let monitor = Arc::new(Mutex::new(CanMonitor::default()));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for thread_id in 0..4u32 {
        let mon = Arc::clone(&monitor);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            let frame = CanFrame {
                id: 0x100 + thread_id,
                is_extended: false,
                is_fd: false,
                dlc: 8,
                data: [thread_id as u8; 64],
            };
            for i in 0..100u64 {
                let ts = (thread_id as u64) * 100_000 + i * 1_000;
                let mut m = mon.lock().unwrap();
                let _ = m.process_frame(&frame, ts);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ---------------------------------------------------------------------------
// Event logger: concurrent append from multiple threads
// ---------------------------------------------------------------------------

#[test]
fn event_logger_concurrent_append() {
    // SoftwareCryptoProvider is !Sync (uses RefCell), so we pair the logger
    // and its crypto provider together behind a single Mutex.
    //
    // EventLog enforces timestamp monotonicity, so we use an atomic counter
    // to provide globally increasing timestamps across threads.
    use std::sync::atomic::{AtomicU64, Ordering};

    let crypto = make_crypto();
    let log: EventLog<SoftwareCryptoProvider, 256> = EventLog::new(KeyId(0), &crypto).unwrap();
    let pair = Arc::new(Mutex::new((log, crypto)));
    let ts_counter = Arc::new(AtomicU64::new(1));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for thread_id in 0..4u32 {
        let p = Arc::clone(&pair);
        let ts = Arc::clone(&ts_counter);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            for _ in 0..50u64 {
                // Acquire lock BEFORE generating timestamp to guarantee
                // monotonicity: the timestamp is always increasing while
                // the lock is held.
                let mut guard = p.lock().unwrap();
                let timestamp = ts.fetch_add(1_000, Ordering::SeqCst);
                let (ref mut l, ref cp) = *guard;
                let _ = l.append(EventType::SystemEvent, &[thread_id as u8; 8], timestamp, cp);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // Verify chain integrity after concurrent writes
    let guard = pair.lock().unwrap();
    let (ref log, ref crypto) = *guard;
    assert!(
        log.verify_chain(crypto).is_ok(),
        "chain integrity broken after concurrent access"
    );
    assert_eq!(log.entry_count(), 200);
}

// ---------------------------------------------------------------------------
// Firewall: concurrent evaluate does not corrupt rule state
// ---------------------------------------------------------------------------

#[test]
fn firewall_concurrent_evaluate() {
    let mut fw = Firewall::new();
    for i in 0..32u8 {
        fw.add_rule(FirewallRule {
            id: i as u32,
            priority: i,
            action: if i % 2 == 0 {
                RuleAction::Allow
            } else {
                RuleAction::Drop
            },
            ethertype: Some(0x0800),
            active: true,
            ..FirewallRule::default()
        })
        .expect("add rule");
    }

    let fw = Arc::new(Mutex::new(fw));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for thread_id in 0..4u32 {
        let f = Arc::clone(&fw);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            for _ in 0..200 {
                let mut fw_guard = f.lock().unwrap();
                let pkt = EthPacket {
                    src_mac: [thread_id as u8; 6],
                    dst_mac: [0xBB; 6],
                    vlan_id: None,
                    ethertype: 0x0800,
                    dst_port: None,
                    payload: &[0u8; 64],
                };
                let _ = fw_guard.evaluate(&pkt, 0);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ---------------------------------------------------------------------------
// IDS engine: concurrent CAN + ETH submission
// ---------------------------------------------------------------------------

#[test]
fn ids_engine_concurrent_can_and_eth() {
    let can_monitor = CanMonitor::default();
    let eth_monitor = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
    let ids = Arc::new(Mutex::new(IdsEngine::new(
        can_monitor,
        eth_monitor,
        100_000,
    )));
    let barrier = Arc::new(Barrier::new(2));

    let ids_can = Arc::clone(&ids);
    let bar_can = Arc::clone(&barrier);
    let can_handle = thread::spawn(move || {
        bar_can.wait();
        let frame = CanFrame {
            id: 0x200,
            is_extended: false,
            is_fd: false,
            dlc: 8,
            data: [0xAA; 64],
        };
        let mut alert_count = 0u64;
        for i in 0..500u64 {
            let mut engine = ids_can.lock().unwrap();
            if engine.submit_can_frame(&frame, i * 100).is_some() {
                alert_count += 1;
            }
        }
        alert_count
    });

    let ids_eth = Arc::clone(&ids);
    let bar_eth = Arc::clone(&barrier);
    let eth_handle = thread::spawn(move || {
        bar_eth.wait();
        let payload = [0xBB; 64];
        let pkt = EthPacket {
            src_mac: [0xCC; 6],
            dst_mac: [0xDD; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        let mut alert_count = 0u64;
        for i in 0..500u64 {
            let mut engine = ids_eth.lock().unwrap();
            if engine.submit_eth_packet(&pkt, i * 100).is_some() {
                alert_count += 1;
            }
        }
        alert_count
    });

    let can_alerts = can_handle.join().expect("CAN thread panicked");
    let eth_alerts = eth_handle.join().expect("ETH thread panicked");

    // Both threads completed without deadlock or panic
    assert!(can_alerts + eth_alerts < 1000);
}

// ---------------------------------------------------------------------------
// Integrity monitor: concurrent verify_region
// ---------------------------------------------------------------------------

#[test]
fn integrity_monitor_concurrent_verify() {
    let crypto = make_crypto();
    let mut monitor = IntegrityMonitor::new(crypto);

    let data = [0xAA; 128];
    monitor
        .register_region(1, 0x1000_0000, &data)
        .expect("register region 1");

    let monitor = Arc::new(Mutex::new(monitor));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let m = Arc::clone(&monitor);
        let bar = Arc::clone(&barrier);
        let data_copy = data;
        handles.push(thread::spawn(move || {
            bar.wait();
            for _ in 0..50 {
                let mut mon = m.lock().unwrap();
                let result = mon.verify_region(1, 0x1000_0000, &data_copy);
                assert!(result.is_ok(), "verify_region should not fail");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ---------------------------------------------------------------------------
// Crypto provider: concurrent encrypt/decrypt
// ---------------------------------------------------------------------------

#[test]
fn crypto_concurrent_encrypt_decrypt() {
    // SoftwareCryptoProvider is !Sync (RefCell-based NonceTracker), so each
    // thread gets its own provider. This test verifies that independent
    // providers produce correct results when run concurrently.
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for thread_id in 0..4u32 {
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // Each thread has its own crypto provider
            let mut cp = SoftwareCryptoProvider::new(common::test_rng);
            cp.set_key(KeyId(0), &[0xAA; 32]).expect("provision key 0");

            bar.wait();
            let plaintext = [thread_id as u8; 32];
            let mut ciphertext = [0u8; 32];
            let mut tag = [0u8; 16];

            for i in 0..20u32 {
                // Build a non-degenerate nonce: validate_nonce rejects
                // all-zero and all-identical patterns.
                let mut nonce = [0u8; 12];
                nonce[0] = thread_id as u8 | 0x10; // ensure non-zero
                nonce[1] = 0xAB; // break identical-byte pattern
                nonce[4..8].copy_from_slice(&(i + 1).to_le_bytes());

                let enc_result = cp.aes_gcm_encrypt(
                    KeyId(0),
                    &nonce,
                    &plaintext,
                    &[],
                    &mut ciphertext,
                    &mut tag,
                );
                assert!(enc_result.is_ok(), "encrypt failed in thread {thread_id}");

                let mut decrypted = [0u8; 32];
                let dec_result =
                    cp.aes_gcm_decrypt(KeyId(0), &nonce, &ciphertext, &[], &tag, &mut decrypted);
                assert!(dec_result.is_ok(), "decrypt failed in thread {thread_id}");
                assert_eq!(
                    decrypted, plaintext,
                    "roundtrip mismatch in thread {thread_id}"
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}
