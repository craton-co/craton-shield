// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

use subtle::ConstantTimeEq;
use vs_crypto::{CryptoProvider, KeyId};
use vs_types::VsError;

/// Serialized size of a single [`LogEntry`] in bytes.
///
/// Layout: sequence(8) + timestamp(8) + `event_type`(1) + payload(128)
///       + `payload_len`(1) + `prev_hash`(32) + `entry_hmac`(32) = 210
const ENTRY_SERIALIZED_SIZE: usize = 8 + 8 + 1 + 128 + 1 + 32 + 32;

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

/// Category of a logged security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    SecurityAlert = 0,
    KeyOperation = 1,
    BootEvent = 2,
    DiagnosticSession = 3,
    OtaUpdate = 4,
    SystemEvent = 5,
    PolicyChange = 6,
}

impl EventType {
    /// Convert the variant to a single discriminant byte.
    const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for EventType {
    type Error = VsError;

    fn try_from(value: u8) -> Result<Self, VsError> {
        match value {
            0 => Ok(Self::SecurityAlert),
            1 => Ok(Self::KeyOperation),
            2 => Ok(Self::BootEvent),
            3 => Ok(Self::DiagnosticSession),
            4 => Ok(Self::OtaUpdate),
            5 => Ok(Self::SystemEvent),
            6 => Ok(Self::PolicyChange),
            _ => Err(VsError::InvalidInput),
        }
    }
}

// ---------------------------------------------------------------------------
// LogEntry
// ---------------------------------------------------------------------------

/// A single entry in the tamper-evident event log.
#[derive(Debug, Clone, Copy)]
pub struct LogEntry {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub event_type: EventType,
    pub payload: [u8; 128],
    pub payload_len: u8,
    pub prev_hash: [u8; 32],
    pub entry_hmac: [u8; 32],
}

impl LogEntry {
    /// Serialize the entry into a fixed-size byte buffer.
    ///
    /// Field order: sequence (8 LE) | timestamp (8 LE) | `event_type` (1)
    ///            | payload (128) | `payload_len` (1) | `prev_hash` (32) | `entry_hmac` (32)
    fn serialize(&self, buf: &mut [u8; ENTRY_SERIALIZED_SIZE]) {
        let mut offset = 0usize;

        buf[offset..offset + 8].copy_from_slice(&self.sequence.to_le_bytes());
        offset += 8;

        buf[offset..offset + 8].copy_from_slice(&self.timestamp_us.to_le_bytes());
        offset += 8;

        buf[offset] = self.event_type.as_byte();
        offset += 1;

        buf[offset..offset + 128].copy_from_slice(&self.payload);
        offset += 128;

        buf[offset] = self.payload_len;
        offset += 1;

        buf[offset..offset + 32].copy_from_slice(&self.prev_hash);
        offset += 32;

        buf[offset..offset + 32].copy_from_slice(&self.entry_hmac);
    }

    /// Build the byte blob that is fed into the HMAC for this entry.
    ///
    /// Layout: sequence (8 LE) | timestamp (8 LE) | `event_type` (1)
    ///       | payload (128) | `payload_len` (1) | `prev_hash` (32) = 178 bytes
    fn hmac_message(&self, buf: &mut [u8; 178]) {
        let mut offset = 0usize;

        buf[offset..offset + 8].copy_from_slice(&self.sequence.to_le_bytes());
        offset += 8;

        buf[offset..offset + 8].copy_from_slice(&self.timestamp_us.to_le_bytes());
        offset += 8;

        buf[offset] = self.event_type.as_byte();
        offset += 1;

        buf[offset..offset + 128].copy_from_slice(&self.payload);
        offset += 128;

        buf[offset] = self.payload_len;
        offset += 1;

        buf[offset..offset + 32].copy_from_slice(&self.prev_hash);
    }
}

// ---------------------------------------------------------------------------
// ChainIntegrity
// ---------------------------------------------------------------------------

/// Result of a chain-integrity verification pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIntegrity {
    /// Number of entries that were successfully verified.
    pub entries_verified: u64,
    /// Sequence number of the first entry that failed verification, if any.
    pub first_tampered_seq: Option<u64>,
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// Domain separator used to compute the crypto provider fingerprint.
const CRYPTO_BINDING_DOMAIN: &[u8] = b"vs-event-log-crypto-binding-v1";

/// Tamper-evident security event log backed by a fixed-capacity ring buffer.
///
/// `C` is the cryptographic provider used for SHA-256 and HMAC-SHA256.
/// `CAPACITY` is the maximum number of entries held in memory (ring wraps).
///
/// The log is bound to a specific `CryptoProvider` instance at construction
/// time via a fingerprint.  Passing a different provider to [`Self::append`] or
/// [`Self::verify_chain`] returns [`VsError::InvalidConfig`].
pub struct EventLog<C: CryptoProvider, const CAPACITY: usize> {
    entries: [Option<LogEntry>; CAPACITY],
    /// Ring-buffer write position (next slot to write).
    head: usize,
    /// Total number of entries ever appended (monotonic counter).
    count: u64,
    /// Number of entries lost due to ring buffer overflow.
    overflow_count: u64,
    /// Most recent timestamp seen, for monotonicity enforcement.
    last_timestamp_us: u64,
    /// Key slot used for HMAC signing.
    hmac_key_id: KeyId,
    /// SHA-256 fingerprint of the crypto provider, computed at construction.
    /// Used to detect accidental provider swaps between calls.
    crypto_fingerprint: [u8; 32],
    /// Cached serialization of the most recently appended entry, used to
    /// compute `prev_hash` for the next append without re-serializing.
    last_serialized: Option<[u8; ENTRY_SERIALIZED_SIZE]>,
    /// Optional callback invoked when an entry is about to be overwritten
    /// due to ring buffer overflow. Receives the sequence number and
    /// timestamp of the entry being evicted.
    overflow_callback: Option<fn(seq: u64, timestamp_us: u64)>,
    /// Number of entries currently in the ring buffer (up to CAPACITY).
    entry_count: usize,
    /// The overflow count that was last incorporated into the HMAC chain.
    /// When `overflow_count` exceeds this value the delta is mixed into the
    /// next HMAC computation so that the tamper chain captures every overflow.
    last_reported_overflow_count: u64,
    /// Marker for the crypto provider type.
    _crypto: core::marker::PhantomData<C>,
}

impl<C: CryptoProvider, const CAPACITY: usize> EventLog<C, CAPACITY> {
    /// Create a new, empty event log bound to `crypto`.
    ///
    /// `hmac_key_id` identifies the key slot used for HMAC-SHA256 signing and
    /// verification of log entries.  The `crypto` provider is fingerprinted
    /// so that subsequent [`append`](Self::append) and
    /// [`verify_chain`](Self::verify_chain) calls can detect accidental
    /// provider swaps.
    pub fn new(hmac_key_id: KeyId, crypto: &C) -> Result<Self, VsError> {
        const { assert!(CAPACITY > 0, "EventLog CAPACITY must be greater than zero") };
        let mut fingerprint = [0u8; 32];
        crypto.sha256(CRYPTO_BINDING_DOMAIN, &mut fingerprint)?;
        Ok(Self {
            entries: core::array::from_fn(|_| None),
            head: 0,
            count: 0,
            overflow_count: 0,
            last_timestamp_us: 0,
            hmac_key_id,
            crypto_fingerprint: fingerprint,
            last_serialized: None,
            overflow_callback: None,
            entry_count: 0,
            last_reported_overflow_count: 0,
            _crypto: core::marker::PhantomData,
        })
    }

    /// Verify that `crypto` matches the provider used at construction time.
    fn verify_crypto_binding(&self, crypto: &C) -> Result<(), VsError> {
        let mut fp = [0u8; 32];
        crypto.sha256(CRYPTO_BINDING_DOMAIN, &mut fp)?;
        // Constant-time comparison via `subtle` to avoid timing leaks.
        if !bool::from(fp.ct_eq(&self.crypto_fingerprint)) {
            return Err(VsError::InvalidConfig);
        }
        Ok(())
    }

    /// Append a new event to the log.
    ///
    /// Returns the sequence number assigned to the entry.  If the ring buffer
    /// is full the oldest entry is overwritten.
    pub fn append(
        &mut self,
        event_type: EventType,
        payload: &[u8],
        ts_us: u64,
        crypto: &C,
    ) -> Result<u64, VsError> {
        // --- crypto provider binding check -------------------------------
        self.verify_crypto_binding(crypto)?;

        // --- timestamp monotonicity check --------------------------------
        if self.count > 0 && ts_us < self.last_timestamp_us {
            return Err(VsError::InvalidInput);
        }

        let sequence = self.count;

        // --- prev_hash ---------------------------------------------------
        let prev_hash = if sequence == 0 {
            [0u8; 32]
        } else {
            // Use the cached serialization of the previous entry if available,
            // avoiding a re-serialization (saves ~210 bytes of memcpy).
            let ser = if let Some(cached) = &self.last_serialized {
                *cached
            } else {
                // Fallback: re-serialize from the ring buffer (cold path on
                // first append after construction or after verify_chain).
                let prev_idx = if self.head == 0 {
                    CAPACITY - 1
                } else {
                    self.head - 1
                };
                let prev_entry = self.entries[prev_idx]
                    .as_ref()
                    .ok_or(VsError::IntegrityFailure)?;
                let mut buf = [0u8; ENTRY_SERIALIZED_SIZE];
                prev_entry.serialize(&mut buf);
                buf
            };

            let mut hash = [0u8; 32];
            crypto.sha256(&ser, &mut hash)?;
            hash
        };

        // --- build payload array (zero-padded) ---------------------------
        if payload.len() > 128 {
            return Err(VsError::InvalidInput);
        }
        let mut payload_buf = [0u8; 128];
        payload_buf[..payload.len()].copy_from_slice(payload);
        let payload_len = payload.len() as u8;

        // --- compute HMAC ------------------------------------------------
        let mut entry = LogEntry {
            sequence,
            timestamp_us: ts_us,
            event_type,
            payload: payload_buf,
            payload_len,
            prev_hash,
            entry_hmac: [0u8; 32],
        };

        // Build the HMAC input: 178 bytes for the entry fields + 8 bytes
        // for the current overflow count, so that ring-buffer overflows are
        // captured in the tamper chain without a separate log entry.
        let mut hmac_entry = [0u8; 178];
        entry.hmac_message(&mut hmac_entry);
        let mut hmac_buf = [0u8; 186];
        hmac_buf[..178].copy_from_slice(&hmac_entry);
        hmac_buf[178..186].copy_from_slice(&self.overflow_count.to_le_bytes());
        crypto.hmac_sha256(self.hmac_key_id, &hmac_buf, &mut entry.entry_hmac)?;
        self.last_reported_overflow_count = self.overflow_count;

        // --- store -------------------------------------------------------
        if self.count >= CAPACITY as u64 {
            // Invoke the overflow callback before overwriting the entry.
            if let Some(cb) = self.overflow_callback {
                if let Some(ref evicted) = self.entries[self.head] {
                    cb(evicted.sequence, evicted.timestamp_us);
                }
            }
            self.overflow_count = self.overflow_count.saturating_add(1);
        } else {
            self.entry_count = self.entry_count.saturating_add(1);
        }
        // Cache the serialized form of this entry so the next append
        // can compute prev_hash without re-serializing.
        let mut cached_ser = [0u8; ENTRY_SERIALIZED_SIZE];
        entry.serialize(&mut cached_ser);
        self.last_serialized = Some(cached_ser);

        self.entries[self.head] = Some(entry);
        self.head = (self.head + 1) % CAPACITY;
        self.count = self.count.saturating_add(1);
        self.last_timestamp_us = ts_us;

        Ok(sequence)
    }

    /// Walk all stored entries in sequence order and verify the HMAC /
    /// `prev_hash` chain.
    pub fn verify_chain(&self, crypto: &C) -> Result<ChainIntegrity, VsError> {
        self.verify_crypto_binding(crypto)?;

        if self.count == 0 {
            return Ok(ChainIntegrity {
                entries_verified: 0,
                first_tampered_seq: None,
            });
        }

        // Determine the range of entries available in the ring buffer.
        let stored = if self.count < CAPACITY as u64 {
            self.count as usize
        } else {
            CAPACITY
        };

        // Index of the oldest entry in the ring buffer.
        let oldest_idx = if self.count <= CAPACITY as u64 {
            0
        } else {
            self.head // head points one past newest, which wraps to oldest
        };

        let mut entries_verified: u64 = 0;
        let mut first_tampered_seq: Option<u64> = None;
        let mut prev_serialized: Option<[u8; ENTRY_SERIALIZED_SIZE]> = None;

        for i in 0..stored {
            let ring_idx = (oldest_idx + i) % CAPACITY;
            let Some(entry) = &self.entries[ring_idx] else {
                break;
            };

            // -- Verify prev_hash ------------------------------------------
            let expected_prev_hash = if let Some(ref prev_ser) = prev_serialized {
                let mut hash = [0u8; 32];
                crypto.sha256(prev_ser, &mut hash)?;
                Some(hash)
            } else {
                None
            };

            if let Some(ref expected) = expected_prev_hash {
                if !bool::from(entry.prev_hash.ct_eq(expected)) {
                    if first_tampered_seq.is_none() {
                        first_tampered_seq = Some(entry.sequence);
                    }
                    // Serialize this entry so subsequent checks can continue.
                    let mut ser = [0u8; ENTRY_SERIALIZED_SIZE];
                    entry.serialize(&mut ser);
                    prev_serialized = Some(ser);
                    entries_verified = entries_verified.saturating_add(1);
                    continue;
                }
            }

            // -- Verify HMAC -----------------------------------------------
            // Reconstruct the overflow count that was used when this entry's
            // HMAC was computed.  The HMAC is computed *before* the overflow
            // counter is incremented, so: overflow = max(0, seq - CAP).
            let overflow_at_entry = entry.sequence.saturating_sub(CAPACITY as u64);
            let mut hmac_entry = [0u8; 178];
            entry.hmac_message(&mut hmac_entry);
            let mut hmac_buf = [0u8; 186];
            hmac_buf[..178].copy_from_slice(&hmac_entry);
            hmac_buf[178..186].copy_from_slice(&overflow_at_entry.to_le_bytes());
            let mut expected_hmac = [0u8; 32];
            crypto.hmac_sha256(self.hmac_key_id, &hmac_buf, &mut expected_hmac)?;

            if !bool::from(entry.entry_hmac.ct_eq(&expected_hmac)) && first_tampered_seq.is_none() {
                first_tampered_seq = Some(entry.sequence);
            }

            // Serialize this entry for the next iteration's prev_hash check.
            let mut ser = [0u8; ENTRY_SERIALIZED_SIZE];
            entry.serialize(&mut ser);
            prev_serialized = Some(ser);

            entries_verified = entries_verified.saturating_add(1);
        }

        Ok(ChainIntegrity {
            entries_verified,
            first_tampered_seq,
        })
    }

    /// Copy entries whose sequence numbers fall within `[from_seq, to_seq]`
    /// into `out`, returning the number of entries actually copied.
    pub fn export_entries(&self, from_seq: u64, to_seq: u64, out: &mut [LogEntry]) -> usize {
        if self.count == 0 || from_seq > to_seq || out.is_empty() {
            return 0;
        }

        let stored = if self.count < CAPACITY as u64 {
            self.count as usize
        } else {
            CAPACITY
        };

        let oldest_idx = if self.count <= CAPACITY as u64 {
            0
        } else {
            self.head
        };

        let mut copied = 0usize;
        for i in 0..stored {
            let ring_idx = (oldest_idx + i) % CAPACITY;
            if let Some(entry) = &self.entries[ring_idx] {
                if entry.sequence >= from_seq && entry.sequence <= to_seq {
                    if copied >= out.len() {
                        break;
                    }
                    out[copied] = *entry;
                    copied += 1;
                }
            }
        }
        copied
    }

    /// Total number of entries ever appended (monotonic, not affected by
    /// ring-buffer wrapping).
    pub fn entry_count(&self) -> u64 {
        self.count
    }

    /// Number of entries lost due to ring buffer overflow.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Registers a callback invoked when an entry is about to be evicted
    /// from the ring buffer due to overflow. The callback receives the
    /// sequence number and timestamp of the entry being overwritten.
    pub fn set_overflow_callback(&mut self, cb: fn(seq: u64, timestamp_us: u64)) {
        self.overflow_callback = Some(cb);
    }

    /// Returns `true` when the ring buffer is more than 90% full.
    ///
    /// This can be used as an early warning to trigger log export or
    /// rotation before entries start being overwritten.
    pub fn is_near_overflow(&self) -> bool {
        let threshold = CAPACITY - CAPACITY / 10; // 90%
        self.entry_count >= threshold
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test capacity for the ring buffer.
    const TEST_CAP: usize = 8;

    // -- TestCrypto mock ---------------------------------------------------

    /// Minimal mock implementing `CryptoProvider` with simple deterministic
    /// hashing so that chain verification can be exercised without pulling
    /// in a real crypto library.
    struct TestCrypto;

    impl TestCrypto {
        /// Simple non-cryptographic mixing function used by both `sha256` and
        /// `hmac_sha256`.
        fn simple_hash(data: &[u8], out: &mut [u8; 32]) {
            *out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                let idx = i % 32;
                out[idx] = out[idx]
                    .wrapping_add(b)
                    .wrapping_add((i as u8).wrapping_mul(31));
            }
        }
    }

    impl CryptoProvider for TestCrypto {
        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            TestCrypto::simple_hash(data, hash_out);
            Ok(())
        }

        fn hmac_sha256(
            &self,
            key_id: KeyId,
            data: &[u8],
            mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            // Compute the basic hash, then XOR the key byte into every
            // position to make the result key-dependent.
            TestCrypto::simple_hash(data, mac_out);
            let key_byte = key_id.0 as u8;
            for b in mac_out.iter_mut() {
                *b ^= key_byte;
            }
            Ok(())
        }

        // Required by `CryptoProvider` trait but not used by `EventLog`,
        // which only needs `sha256` and `hmac_sha256`. These return
        // `NotInitialized` to surface accidental misuse immediately.

        fn aes_gcm_encrypt(
            &self,
            _: KeyId,
            _: &[u8; 12],
            _: &[u8],
            _: &[u8],
            _: &mut [u8],
            _: &mut [u8; 16],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn aes_gcm_decrypt(
            &self,
            _: KeyId,
            _: &[u8; 12],
            _: &[u8],
            _: &[u8],
            _: &[u8; 16],
            _: &mut [u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn ecdh_derive_shared(
            &self,
            _: KeyId,
            _: &[u8; 65],
            _: &mut [u8; 32],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
            Err(VsError::NotInitialized)
        }

        fn random_bytes(&self, _: &mut [u8]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }

        fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
    }

    // -- Helper ------------------------------------------------------------

    fn make_log() -> EventLog<TestCrypto, TEST_CAP> {
        EventLog::new(KeyId(42), &crypto()).unwrap()
    }

    fn crypto() -> TestCrypto {
        TestCrypto
    }

    // -- Tests -------------------------------------------------------------

    #[test]
    fn chain_verification_passes_on_unmodified_log() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..5u64 {
            log.append(EventType::SecurityAlert, &[i as u8; 4], i * 1000, &c)
                .expect("append");
        }

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.entries_verified, 5);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn tamper_hmac_detected() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..4u64 {
            log.append(EventType::BootEvent, &[0xAA; 8], i * 100, &c)
                .expect("append");
        }

        // Tamper with the HMAC of the second entry (sequence 1).
        if let Some(ref mut entry) = log.entries[1] {
            entry.entry_hmac[0] ^= 0xFF;
        }

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.first_tampered_seq, Some(1));
    }

    #[test]
    fn tamper_payload_detected() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..4u64 {
            log.append(EventType::KeyOperation, &[0xBB; 16], i * 200, &c)
                .expect("append");
        }

        // Tamper with payload[0] of the third entry (sequence 2).
        if let Some(ref mut entry) = log.entries[2] {
            entry.payload[0] ^= 0xFF;
        }

        let integrity = log.verify_chain(&c).expect("verify");
        // The tampered entry itself should be detected (HMAC mismatch),
        // and/or the *next* entry's prev_hash won't match.
        assert!(integrity.first_tampered_seq.is_some());
        // The tampered entry is sequence 2.
        assert_eq!(integrity.first_tampered_seq, Some(2));
    }

    #[test]
    fn ring_wrap_verify_chain() {
        let mut log = make_log();
        let c = crypto();

        // Append CAPACITY + 10 entries so the ring wraps.
        let total = (TEST_CAP + 10) as u64;
        for i in 0..total {
            log.append(EventType::OtaUpdate, &[i as u8; 6], i * 50, &c)
                .expect("append");
        }

        assert_eq!(log.entry_count(), total);

        let integrity = log.verify_chain(&c).expect("verify");
        // All entries currently stored should verify cleanly.
        assert_eq!(integrity.entries_verified, TEST_CAP as u64);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn export_entries_copies_correct_range() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..6u64 {
            log.append(EventType::DiagnosticSession, &[i as u8], i * 100, &c)
                .expect("append");
        }

        // Export sequences 2..=4
        let mut out = [log.entries[0].unwrap(); 4]; // pre-fill with junk
        let n = log.export_entries(2, 4, &mut out);
        assert_eq!(n, 3);
        assert_eq!(out[0].sequence, 2);
        assert_eq!(out[1].sequence, 3);
        assert_eq!(out[2].sequence, 4);
    }

    #[test]
    fn export_respects_output_buffer_limit() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..6u64 {
            log.append(EventType::SystemEvent, &[i as u8], i * 100, &c)
                .expect("append");
        }

        // Only room for 2 entries but range covers 4.
        let mut out = [log.entries[0].unwrap(); 2];
        let n = log.export_entries(1, 4, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].sequence, 1);
        assert_eq!(out[1].sequence, 2);
    }

    #[test]
    fn entry_count_increments() {
        let mut log = make_log();
        let c = crypto();

        assert_eq!(log.entry_count(), 0);

        log.append(EventType::PolicyChange, &[1], 100, &c)
            .expect("append");
        assert_eq!(log.entry_count(), 1);

        log.append(EventType::PolicyChange, &[2], 200, &c)
            .expect("append");
        assert_eq!(log.entry_count(), 2);

        log.append(EventType::SecurityAlert, &[3], 300, &c)
            .expect("append");
        assert_eq!(log.entry_count(), 3);
    }

    #[test]
    fn empty_log_verify_chain() {
        let log = make_log();
        let c = crypto();

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.entries_verified, 0);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn single_entry_verifies() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::BootEvent, &[0xDE, 0xAD], 42, &c)
            .expect("append");

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.entries_verified, 1);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn payload_over_128_returns_error() {
        let mut log = make_log();
        let c = crypto();

        let big_payload = [0xCC; 200];
        let result = log.append(EventType::SystemEvent, &big_payload, 999, &c);
        assert_eq!(result, Err(VsError::InvalidInput));
        assert_eq!(log.entry_count(), 0);
    }

    #[test]
    fn export_empty_range_returns_zero() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::SecurityAlert, &[1], 100, &c)
            .expect("append");

        let mut out = [log.entries[0].unwrap(); 4];
        // from_seq > to_seq
        assert_eq!(log.export_entries(5, 3, &mut out), 0);
        // range outside stored
        assert_eq!(log.export_entries(100, 200, &mut out), 0);
    }

    #[test]
    fn append_returns_sequential_ids() {
        let mut log = make_log();
        let c = crypto();

        for expected in 0..5u64 {
            let seq = log
                .append(EventType::SecurityAlert, &[], expected * 10, &c)
                .expect("append");
            assert_eq!(seq, expected);
        }
    }

    // ---- New tests below ----

    #[test]
    fn append_with_empty_payload() {
        let mut log = make_log();
        let c = crypto();

        let seq = log
            .append(EventType::SecurityAlert, &[], 1000, &c)
            .expect("append");
        assert_eq!(seq, 0);

        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.payload_len, 0);
        assert!(entry.payload.iter().all(|&b| b == 0));
    }

    #[test]
    fn append_with_max_payload_128_bytes() {
        let mut log = make_log();
        let c = crypto();

        let payload = [0xAB; 128];
        let seq = log
            .append(EventType::BootEvent, &payload, 2000, &c)
            .expect("append");
        assert_eq!(seq, 0);

        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.payload_len, 128);
        assert!(entry.payload.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn append_with_payload_over_128_returns_error() {
        let mut log = make_log();
        let c = crypto();

        let payload = [0xCD; 256];
        let result = log.append(EventType::SystemEvent, &payload, 3000, &c);
        assert_eq!(result, Err(VsError::InvalidInput));
        assert_eq!(log.entry_count(), 0);
    }

    #[test]
    fn event_type_security_alert() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::SecurityAlert, &[1], 100, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::SecurityAlert);
    }

    #[test]
    fn event_type_key_operation() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::KeyOperation, &[2], 200, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::KeyOperation);
    }

    #[test]
    fn event_type_boot_event() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::BootEvent, &[3], 300, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::BootEvent);
    }

    #[test]
    fn event_type_diagnostic_session() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::DiagnosticSession, &[4], 400, &c)
            .unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::DiagnosticSession);
    }

    #[test]
    fn event_type_ota_update() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::OtaUpdate, &[5], 500, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::OtaUpdate);
    }

    #[test]
    fn event_type_system_event_variant() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::SystemEvent, &[6], 600, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::SystemEvent);
    }

    #[test]
    fn event_type_policy_change() {
        let mut log = make_log();
        let c = crypto();
        log.append(EventType::PolicyChange, &[7], 700, &c).unwrap();
        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.event_type, EventType::PolicyChange);
    }

    #[test]
    fn sequence_numbers_strictly_monotonic() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..TEST_CAP as u64 {
            let seq = log
                .append(EventType::SecurityAlert, &[i as u8], i * 100, &c)
                .unwrap();
            assert_eq!(seq, i);
        }

        // Verify each stored entry has increasing sequence.
        for i in 0..TEST_CAP - 1 {
            let curr = log.entries[i].as_ref().unwrap();
            let next = log.entries[i + 1].as_ref().unwrap();
            assert!(next.sequence > curr.sequence);
        }
    }

    #[test]
    fn entry_count_matches_append_count() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..7u64 {
            log.append(EventType::SecurityAlert, &[i as u8], i * 100, &c)
                .unwrap();
            assert_eq!(log.entry_count(), i + 1);
        }
    }

    #[test]
    fn verify_chain_on_single_entry_succeeds() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::BootEvent, &[0xDE, 0xAD], 42, &c)
            .unwrap();

        let integrity = log.verify_chain(&c).unwrap();
        assert_eq!(integrity.entries_verified, 1);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn export_with_from_seq_greater_than_to_seq_returns_0() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::SecurityAlert, &[1], 100, &c).unwrap();
        log.append(EventType::SecurityAlert, &[2], 200, &c).unwrap();

        let mut out = [log.entries[0].unwrap(); 4];
        let n = log.export_entries(5, 2, &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn export_with_from_seq_equals_to_seq_returns_1_entry() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..5u64 {
            log.append(EventType::SecurityAlert, &[i as u8], i * 100, &c)
                .unwrap();
        }

        let mut out = [log.entries[0].unwrap(); 4];
        let n = log.export_entries(2, 2, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].sequence, 2);
    }

    #[test]
    fn ring_buffer_head_tail_after_exactly_capacity_appends() {
        let mut log = make_log();
        let c = crypto();

        // Append exactly TEST_CAP entries.
        for i in 0..TEST_CAP as u64 {
            log.append(EventType::SystemEvent, &[i as u8], i * 100, &c)
                .unwrap();
        }

        assert_eq!(log.entry_count(), TEST_CAP as u64);

        // The head should have wrapped to 0.
        // Verify chain should still pass.
        let integrity = log.verify_chain(&c).unwrap();
        assert_eq!(integrity.entries_verified, TEST_CAP as u64);
        assert_eq!(integrity.first_tampered_seq, None);
    }

    #[test]
    fn two_logs_with_same_data_produce_same_hmacs() {
        let mut log1 = make_log();
        let mut log2 = make_log();
        let c = crypto();

        let payload = [0xAA; 16];
        log1.append(EventType::SecurityAlert, &payload, 1000, &c)
            .unwrap();
        log2.append(EventType::SecurityAlert, &payload, 1000, &c)
            .unwrap();

        let entry1 = log1.entries[0].as_ref().unwrap();
        let entry2 = log2.entries[0].as_ref().unwrap();

        assert_eq!(entry1.entry_hmac, entry2.entry_hmac);
    }

    #[test]
    fn hmac_chain_modifying_sequence_breaks_verification() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..4u64 {
            log.append(EventType::SecurityAlert, &[i as u8; 4], i * 100, &c)
                .unwrap();
        }

        // Tamper with the sequence of the second entry.
        if let Some(ref mut entry) = log.entries[1] {
            entry.sequence = 999;
        }

        let integrity = log.verify_chain(&c).unwrap();
        // Tampering should be detected.
        assert!(integrity.first_tampered_seq.is_some());
    }

    #[test]
    fn timestamp_stored_correctly() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::SecurityAlert, &[1], 123_456_789, &c)
            .unwrap();

        let entry = log.entries[0].as_ref().unwrap();
        assert_eq!(entry.timestamp_us, 123_456_789);
    }

    #[test]
    fn timestamp_going_backward_returns_error() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::SecurityAlert, &[1], 1000, &c)
            .unwrap();
        let result = log.append(EventType::SecurityAlert, &[2], 500, &c);
        assert_eq!(result, Err(VsError::InvalidInput));
        assert_eq!(log.entry_count(), 1);
    }

    #[test]
    fn timestamp_equal_to_previous_is_allowed() {
        let mut log = make_log();
        let c = crypto();

        log.append(EventType::SecurityAlert, &[1], 1000, &c)
            .unwrap();
        log.append(EventType::SecurityAlert, &[2], 1000, &c)
            .unwrap();
        assert_eq!(log.entry_count(), 2);
    }

    #[test]
    fn overflow_count_tracks_overwrites() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..(TEST_CAP as u64 + 3) {
            log.append(EventType::SystemEvent, &[i as u8], i * 100, &c)
                .unwrap();
        }
        assert_eq!(log.overflow_count(), 3);
    }

    #[test]
    fn event_type_try_from_valid_values() {
        assert_eq!(EventType::try_from(0), Ok(EventType::SecurityAlert));
        assert_eq!(EventType::try_from(1), Ok(EventType::KeyOperation));
        assert_eq!(EventType::try_from(2), Ok(EventType::BootEvent));
        assert_eq!(EventType::try_from(3), Ok(EventType::DiagnosticSession));
        assert_eq!(EventType::try_from(4), Ok(EventType::OtaUpdate));
        assert_eq!(EventType::try_from(5), Ok(EventType::SystemEvent));
        assert_eq!(EventType::try_from(6), Ok(EventType::PolicyChange));
    }

    #[test]
    fn event_type_try_from_invalid_returns_error() {
        assert_eq!(EventType::try_from(7), Err(VsError::InvalidInput));
        assert_eq!(EventType::try_from(255), Err(VsError::InvalidInput));
    }

    #[test]
    fn tamper_payload_len_detected() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..4u64 {
            log.append(EventType::SecurityAlert, &[0xAA; 8], i * 100, &c)
                .unwrap();
        }

        // Tamper with payload_len of the second entry (sequence 1).
        if let Some(ref mut entry) = log.entries[1] {
            entry.payload_len = 127;
        }

        let integrity = log.verify_chain(&c).unwrap();
        assert!(integrity.first_tampered_seq.is_some());
    }

    #[test]
    fn overflow_count_tracked_correctly() {
        let mut log = make_log();
        let c = crypto();

        // Fill exactly to capacity — no overflow yet.
        for i in 0..TEST_CAP as u64 {
            log.append(EventType::SecurityAlert, &[i as u8], i * 100, &c)
                .expect("append");
        }
        assert_eq!(log.overflow_count(), 0);

        // One more entry triggers the first overflow.
        log.append(EventType::SecurityAlert, &[0xFF], TEST_CAP as u64 * 100, &c)
            .expect("append");
        assert_eq!(log.overflow_count(), 1);

        // A few more to accumulate overflows.
        for i in 1..4u64 {
            log.append(
                EventType::SecurityAlert,
                &[0xFE],
                (TEST_CAP as u64 + i) * 100,
                &c,
            )
            .expect("append");
        }
        assert_eq!(log.overflow_count(), 4);

        // Chain verification must still succeed because the HMAC includes
        // the overflow count.
        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.first_tampered_seq, None);
    }
}
