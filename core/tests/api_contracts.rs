// SPDX-License-Identifier: Apache-2.0
//! API contract tests — verify that security-critical return values behave
//! exactly as documented, and that capacity-overflow paths are handled safely.
//!
//! These tests document and enforce contracts that are easy to misuse:
//!
//! 1. `verify_p256` returns `Ok(false)` — not `Err` — for an invalid
//!    signature.  Code that only checks `.is_ok()` silently accepts forgeries.
//! 2. `hmac_verify` has the same `Ok(false)` contract.
//! 3. `validate_nonce` rejects repeated nonces (cross-invocation reuse)
//!    via the `NonceTracker`.
//! 4. The CAN replay-tracker eviction counter increments when the table is
//!    full, confirming the overflow is observable rather than silent.
//! 5. The `KeyManager` audit ring iterator yields correct results after the
//!    ring wraps more than once.

mod common;

use vs_can_monitor::{CanFrame, CanMonitor};
use vs_crypto::{CryptoProvider, KeyId, RustCryptoProvider};
use vs_key_manager::{AuditEventType, KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_rng(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x42);
    }
}

/// Build a `RustCryptoProvider` with a 32-byte key in slot 0.
fn make_provider() -> RustCryptoProvider {
    let mut p = RustCryptoProvider::new(test_rng);
    let key: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    p.set_key(KeyId(0), &key).expect("set key");
    p
}

// F-12: These constants are KNOWN-PUBLIC TEST VECTORS from RFC 6979 §A.2.5
// (ECDSA, 256 bits, SHA-256).  They are intentionally published by the IETF
// for interoperability testing and carry no confidentiality.  Secrets scanners
// (GitLeaks, truffleHog, etc.) may flag the private key constant; this comment
// suppresses false positives:
//
//   gitleaks:allow
//   nosec G101 (gosec)
//   pragma: allowlist secret
//
// Source: https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
// These keys MUST NOT be used in any production system.

/// RFC 6979 / NIST P-256 test key pair (Appendix A.2.5) — PUBLIC TEST VECTOR.
///
/// Private key scalar:
///   C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
/// Public key (SEC1 uncompressed — 0x04 || x || y):
///   x: 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
///   y: 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
// gitleaks:allow
const RFC6979_PRIV_KEY: [u8; 32] = [
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1,
    0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B,
    0x12, 0x0F, 0x67, 0x21,
];
const RFC6979_PUB_KEY: [u8; 65] = {
    let mut k = [0u8; 65];
    k[0] = 0x04;
    // x
    k[1]  = 0x60; k[2]  = 0xFE; k[3]  = 0xD4; k[4]  = 0xBA;
    k[5]  = 0x25; k[6]  = 0x5A; k[7]  = 0x9D; k[8]  = 0x31;
    k[9]  = 0xC9; k[10] = 0x61; k[11] = 0xEB; k[12] = 0x74;
    k[13] = 0xC6; k[14] = 0x35; k[15] = 0x6D; k[16] = 0x68;
    k[17] = 0xC0; k[18] = 0x49; k[19] = 0xB8; k[20] = 0x92;
    k[21] = 0x3B; k[22] = 0x61; k[23] = 0xFA; k[24] = 0x6C;
    k[25] = 0xE6; k[26] = 0x69; k[27] = 0x62; k[28] = 0x2E;
    k[29] = 0x60; k[30] = 0xF2; k[31] = 0x9F; k[32] = 0xB6;
    // y
    k[33] = 0x79; k[34] = 0x03; k[35] = 0xFE; k[36] = 0x10;
    k[37] = 0x08; k[38] = 0xB8; k[39] = 0xBC; k[40] = 0x99;
    k[41] = 0xA4; k[42] = 0x1A; k[43] = 0xE9; k[44] = 0xE9;
    k[45] = 0x56; k[46] = 0x28; k[47] = 0xBC; k[48] = 0x64;
    k[49] = 0xF2; k[50] = 0xF1; k[51] = 0xB2; k[52] = 0x0C;
    k[53] = 0x2D; k[54] = 0x7E; k[55] = 0x9F; k[56] = 0x51;
    k[57] = 0x77; k[58] = 0xA3; k[59] = 0xC2; k[60] = 0x94;
    k[61] = 0xD4; k[62] = 0x46; k[63] = 0x22; k[64] = 0x99;
    k
};

/// Sign `digest` using the RFC 6979 P-256 test key, returning `(sig, pub_key)`.
fn sign_digest(digest: &[u8; 32]) -> ([u8; 64], [u8; 65]) {
    let mut p = RustCryptoProvider::new(test_rng);
    p.set_key(KeyId(1), &RFC6979_PRIV_KEY).expect("set signing key");

    let mut sig = [0u8; 64];
    p.sign_p256(KeyId(1), digest, &mut sig).expect("sign");

    (sig, RFC6979_PUB_KEY)
}

// ---------------------------------------------------------------------------
// verify_p256 API contract
// ---------------------------------------------------------------------------

/// A valid signature must return `Ok(true)`.
#[test]
fn verify_p256_valid_signature_returns_ok_true() {
    let provider = make_provider();
    let digest = [0x5Au8; 32];
    let (sig, pub_key) = sign_digest(&digest);

    let result = provider.verify_p256(&pub_key, &digest, &sig);
    assert_eq!(result, Ok(true), "valid signature must return Ok(true)");
}

/// An invalid (tampered) signature must return `Ok(false)`, **not** `Err`.
///
/// This is the critical contract: callers that only check `.is_ok()` would
/// silently accept a forged signature.  The `#[must_use]` attribute on the
/// trait method ensures the compiler warns when the bool is discarded.
#[test]
fn verify_p256_tampered_signature_returns_ok_false_not_err() {
    let provider = make_provider();
    let digest = [0x5Au8; 32];
    let (mut sig, pub_key) = sign_digest(&digest);

    // Flip one bit in the signature to invalidate it.
    sig[0] ^= 0x01;

    let result = provider.verify_p256(&pub_key, &digest, &sig);
    assert_eq!(
        result,
        Ok(false),
        "tampered signature must return Ok(false), not Err"
    );
    // Explicitly demonstrate the footgun: `.is_ok()` is true for both cases.
    assert!(
        result.is_ok(),
        "Ok(false) is still Ok — callers must check the bool, not just is_ok()"
    );
}

/// A mismatched digest (right key, right sig, wrong message) returns `Ok(false)`.
#[test]
fn verify_p256_wrong_digest_returns_ok_false() {
    let provider = make_provider();
    let digest = [0x5Au8; 32];
    let (sig, pub_key) = sign_digest(&digest);

    // Different digest — signature is for a different message.
    let wrong_digest = [0xFFu8; 32];
    let result = provider.verify_p256(&pub_key, &wrong_digest, &sig);
    assert_eq!(
        result,
        Ok(false),
        "wrong digest must return Ok(false), not Err"
    );
}

/// A malformed public key (not a valid SEC1 point) returns `Err`, not `Ok(false)`.
/// This distinguishes operational failures from invalid-signature results.
#[test]
fn verify_p256_malformed_pubkey_returns_err() {
    let provider = make_provider();
    let digest = [0x5Au8; 32];
    let (sig, _) = sign_digest(&digest);

    // All-zero public key is not a valid SEC1 point.
    let bad_pub_key = [0u8; 65];
    let result = provider.verify_p256(&bad_pub_key, &digest, &sig);
    assert!(
        result.is_err(),
        "malformed public key must return Err, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// hmac_verify API contract
// ---------------------------------------------------------------------------

/// Correct MAC must return `Ok(true)`.
#[test]
fn hmac_verify_correct_mac_returns_ok_true() {
    let provider = make_provider();
    let data = b"craton-shield-test-data";
    let mut mac = [0u8; 32];
    provider
        .hmac_sha256(KeyId(0), data, &mut mac)
        .expect("hmac");

    let result = provider.hmac_verify(KeyId(0), data, &mac);
    assert_eq!(result, Ok(true), "correct MAC must return Ok(true)");
}

/// Wrong MAC (one bit flipped) must return `Ok(false)`, not `Err`.
#[test]
fn hmac_verify_wrong_mac_returns_ok_false_not_err() {
    let provider = make_provider();
    let data = b"craton-shield-test-data";
    let mut mac = [0u8; 32];
    provider
        .hmac_sha256(KeyId(0), data, &mut mac)
        .expect("hmac");

    mac[15] ^= 0xFF; // Corrupt the MAC.

    let result = provider.hmac_verify(KeyId(0), data, &mac);
    assert_eq!(
        result,
        Ok(false),
        "wrong MAC must return Ok(false), not Err"
    );
    // Demonstrate the footgun.
    assert!(
        result.is_ok(),
        "Ok(false) is still Ok — callers must check the bool"
    );
}

/// Wrong data (MAC is for different content) must return `Ok(false)`.
#[test]
fn hmac_verify_wrong_data_returns_ok_false() {
    let provider = make_provider();
    let data = b"craton-shield-test-data";
    let mut mac = [0u8; 32];
    provider
        .hmac_sha256(KeyId(0), data, &mut mac)
        .expect("hmac");

    let result = provider.hmac_verify(KeyId(0), b"different-data", &mac);
    assert_eq!(result, Ok(false), "wrong data must return Ok(false)");
}

// ---------------------------------------------------------------------------
// Nonce reuse detection
// ---------------------------------------------------------------------------

/// Using the same nonce twice for AES-GCM encryption must be rejected by the
/// `NonceTracker` inside `RustCryptoProvider`.
#[test]
fn nonce_reuse_detected_by_aes_gcm_encrypt() {
    let provider = make_provider();
    let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    let plaintext = b"sensitive data";
    let mut ct = [0u8; 14];
    let mut tag = [0u8; 16];

    // First use: must succeed.
    let first = provider.aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ct, &mut tag);
    assert!(first.is_ok(), "first encryption with nonce should succeed");

    // Second use of the same nonce: must be rejected.
    let second = provider.aes_gcm_encrypt(KeyId(0), &nonce, plaintext, &[], &mut ct, &mut tag);
    assert_eq!(
        second,
        Err(VsError::InvalidInput),
        "second encryption with the same nonce must fail — nonce reuse is catastrophic for AES-GCM"
    );
}

/// All-zero nonce must be rejected regardless of prior use.
#[test]
fn nonce_all_zero_rejected() {
    let provider = make_provider();
    let nonce = [0u8; 12];
    let mut ct = [0u8; 4];
    let mut tag = [0u8; 16];
    let result = provider.aes_gcm_encrypt(KeyId(0), &nonce, b"test", &[], &mut ct, &mut tag);
    assert_eq!(
        result,
        Err(VsError::InvalidInput),
        "all-zero nonce must be rejected"
    );
}

/// All-identical nonce (e.g., [0xAA; 12]) must be rejected.
#[test]
fn nonce_all_identical_bytes_rejected() {
    let provider = make_provider();
    let nonce = [0xAA; 12];
    let mut ct = [0u8; 4];
    let mut tag = [0u8; 16];
    let result = provider.aes_gcm_encrypt(KeyId(0), &nonce, b"test", &[], &mut ct, &mut tag);
    assert_eq!(
        result,
        Err(VsError::InvalidInput),
        "constant-fill nonce must be rejected"
    );
}

// ---------------------------------------------------------------------------
// CAN replay tracker eviction counter
// ---------------------------------------------------------------------------

/// When more than REPLAY_CAPACITY (256) distinct CAN IDs are seen, the replay
/// tracker must evict old entries rather than silently stopping detection.
/// The eviction counter must be non-zero after the table overflows.
#[test]
fn can_replay_tracker_eviction_count_increments_when_table_full() {
    // Use a fixed SipHash key so the test is deterministic.
    let key = [0x12u8; 16];
    let mut mon = CanMonitor::new(key);

    // Send 300 distinct IDs (one unique frame per ID) to overflow the 256-slot
    // replay tracker.
    for id in 0u32..300 {
        let frame = CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc: 4,
            data: {
                let mut d = [0u8; 64];
                // Each ID gets a unique payload so this is not a replay.
                d[0] = (id & 0xFF) as u8;
                d[1] = ((id >> 8) & 0xFF) as u8;
                d[2] = 0xAB;
                d[3] = 0xCD;
                d
            },
        };
        let _ = mon.process_frame(&frame, id as u64 * 1000);
    }

    let evictions = mon.replay_eviction_count();
    assert!(
        evictions > 0,
        "replay tracker eviction counter must be > 0 after overflowing the table with 300 unique IDs; got {evictions}"
    );
}

/// Even after overflow, replay detection still works for the IDs that remain
/// in the tracker — it does not silently disable itself.
#[test]
fn can_replay_detection_still_works_after_table_overflow() {
    let key = [0x34u8; 16];
    let mut mon = CanMonitor::new(key);

    // Fill the tracker with 300 unique IDs.
    for id in 0u32..300 {
        let frame = CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc: 2,
            data: {
                let mut d = [0u8; 64];
                d[0] = (id & 0xFF) as u8;
                d[1] = ((id >> 8) & 0xFF) as u8;
                d
            },
        };
        let _ = mon.process_frame(&frame, id as u64 * 500);
    }

    // Now send the same frame 10 times on ID 1 — should eventually trigger replay.
    let replay_frame = CanFrame {
        id: 1,
        is_extended: false,
        is_fd: false,
        dlc: 2,
        data: {
            let mut d = [0u8; 64];
            // Identical payload — should be detected as replay.
            d[0] = 0xDE;
            d[1] = 0xAD;
            d
        },
    };

    let mut replay_detected = false;
    let base_ts = 300_000u64;
    for i in 0u64..20 {
        if mon.process_frame(&replay_frame, base_ts + i * 1000).is_some() {
            replay_detected = true;
            break;
        }
    }
    assert!(
        replay_detected,
        "replay detection must still work after table overflow"
    );
}

// ---------------------------------------------------------------------------
// KeyManager audit ring wraparound
// ---------------------------------------------------------------------------

/// After more than AUDIT_CAPACITY (256) audit entries, the ring wraps and the
/// iterator must still yield exactly AUDIT_CAPACITY entries in sequence-number
/// order without panicking or skipping.
#[test]
fn key_manager_audit_ring_wraparound_yields_correct_entries() {
    use common::make_crypto;
    let mut km = KeyManager::new(make_crypto());

    // Generate 300 key provisions to force the ring to wrap (capacity = 256).
    // We use different key IDs cycling through slots 0..63.
    for i in 0u32..300 {
        let slot = (i % 64) as u8;
        let meta = KeyMetadata {
            key_id: KeyId(slot as u32),
            algorithm: KeyAlgorithm::HmacSha256,
            purpose: KeyPurpose::BusAuthentication,
            created_at: i as u64 * 1000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        let key: [u8; 32] = core::array::from_fn(|j| (i as u8).wrapping_add(j as u8 + 1));
        // Provision (overwriting existing slot is fine for this test).
        let _ = km.provision_key(KeyId(slot as u32), meta, &key);
    }

    // The ring holds at most AUDIT_CAPACITY = 256 entries.
    let entries: alloc::vec::Vec<_> = km.audit_iter().collect();
    assert_eq!(
        entries.len(),
        256,
        "audit ring must yield exactly 256 entries after wrap"
    );

    // All yielded entries must have non-zero sequence numbers.
    for entry in &entries {
        assert_ne!(entry.sequence, 0, "sequence numbers must be non-zero");
    }

    // Entries must be in ascending sequence order (oldest first).
    for window in entries.windows(2) {
        assert!(
            window[0].sequence < window[1].sequence,
            "audit entries must be in ascending sequence order: {} >= {}",
            window[0].sequence,
            window[1].sequence,
        );
    }

    // All entries must be KeyProvisioned events.
    for entry in &entries {
        assert_eq!(
            entry.event_type,
            AuditEventType::KeyProvisioned,
            "expected KeyProvisioned, got {:?}",
            entry.event_type
        );
    }

    // Overflow counter must reflect the wrapped entries (300 - 256 = 44 minimum).
    assert!(
        km.audit_overflow_count() >= 44,
        "overflow counter must reflect wrapped entries; got {}",
        km.audit_overflow_count()
    );
}

/// The audit ring overflow count must be exactly zero before any overflow.
#[test]
fn key_manager_audit_no_overflow_initially() {
    use common::make_crypto;
    let km = KeyManager::new(make_crypto());
    assert_eq!(km.audit_overflow_count(), 0);
}
