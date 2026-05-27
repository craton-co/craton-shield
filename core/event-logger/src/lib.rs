// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! HMAC-chained tamper-evident event log.
//!
//! # Public API (v1.0 stable)
//!
//! The `EventLog` type, its `append` / `verify_chain` methods, and the
//! `LogEntry` / `EventType` / `ChainIntegrity` types form the v1.0 stable
//! surface and are governed by `DEPRECATION.md`.
//!
//! # No-reboot-anchor limitation
//!
//! [`EventLog::verify_chain`] only detects tampering of entries currently held
//! in RAM. After a reboot the log resets to `sequence = 0` with no persistent
//! anchor. If you need cross-reboot tamper detection, persist the last
//! sequence number and last entry hash via `vs-storage` and re-anchor on boot.

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
    /// A security-relevant alert (e.g. IDS detection, policy violation).
    SecurityAlert = 0,
    /// A key-management operation (generation, rotation, deletion).
    KeyOperation = 1,
    /// A boot or reset event from the host platform.
    BootEvent = 2,
    /// A diagnostic session was opened or closed.
    DiagnosticSession = 3,
    /// An OTA firmware update event (start, progress, success, abort).
    OtaUpdate = 4,
    /// A generic system event that does not fit any other category.
    SystemEvent = 5,
    /// A policy / configuration change was applied.
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

/// Size in bytes of the HMAC input for a single entry (entry fields only,
/// not including the trailing overflow counter mixed in by [`EventLog`]).
const HMAC_MESSAGE_SIZE: usize = 8 + 8 + 1 + 128 + 1 + 32;

/// A single entry in the tamper-evident event log.
#[derive(Debug, Clone, Copy)]
pub struct LogEntry {
    /// Monotonic sequence number assigned at append time.
    pub sequence: u64,
    /// Wall-clock timestamp in microseconds since an arbitrary epoch.
    pub timestamp_us: u64,
    /// Category of the event.
    pub event_type: EventType,
    /// Fixed-size payload, zero-padded beyond `payload_len`.
    pub payload: [u8; 128],
    /// Number of meaningful bytes in `payload` (`0..=128`).
    pub payload_len: u8,
    /// SHA-256 of the previous entry's full serialization, or `[0u8; 32]`
    /// for the first entry.
    pub prev_hash: [u8; 32],
    /// HMAC-SHA256 over the entry fields and the in-RAM overflow count.
    pub entry_hmac: [u8; 32],
}

impl LogEntry {
    /// Write the HMAC-covered fields (the first `HMAC_MESSAGE_SIZE` bytes of
    /// the on-the-wire layout) into `buf`.
    ///
    /// `buf` must be at least `HMAC_MESSAGE_SIZE` bytes long. This is the
    /// single source of truth for the byte order of an entry; it is invoked
    /// by both [`Self::serialize`] (which then appends `entry_hmac`) and the
    /// in-place HMAC builder used by [`EventLog::append`]. Changing the order
    /// or padding here would silently corrupt the chain — keep this function
    /// bit-identical across releases.
    ///
    /// Field order: sequence (8 LE) | timestamp (8 LE) | `event_type` (1)
    ///            | payload (128) | `payload_len` (1) | `prev_hash` (32)
    ///            = `HMAC_MESSAGE_SIZE` = 178 bytes.
    fn write_fields(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= HMAC_MESSAGE_SIZE);
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

    /// Serialize the entry into a fixed-size byte buffer.
    ///
    /// Field order: sequence (8 LE) | timestamp (8 LE) | `event_type` (1)
    ///            | payload (128) | `payload_len` (1) | `prev_hash` (32) | `entry_hmac` (32)
    fn serialize(&self, buf: &mut [u8; ENTRY_SERIALIZED_SIZE]) {
        // ENTRY_SERIALIZED_SIZE == HMAC_MESSAGE_SIZE + 32, statically asserted.
        const _: () = assert!(ENTRY_SERIALIZED_SIZE == HMAC_MESSAGE_SIZE + 32);
        self.write_fields(&mut buf[..HMAC_MESSAGE_SIZE]);
        buf[HMAC_MESSAGE_SIZE..].copy_from_slice(&self.entry_hmac);
    }

    /// Build the byte blob that is fed into the HMAC for this entry.
    ///
    /// Layout: same as [`Self::write_fields`] — sequence (8 LE) | timestamp
    /// (8 LE) | `event_type` (1) | payload (128) | `payload_len` (1)
    /// | `prev_hash` (32) = `HMAC_MESSAGE_SIZE` bytes.
    #[cfg(test)]
    fn hmac_message(&self, buf: &mut [u8; HMAC_MESSAGE_SIZE]) {
        self.write_fields(buf);
    }
}

// ---------------------------------------------------------------------------
// ChainIntegrity
// ---------------------------------------------------------------------------

/// Result of a chain-integrity verification pass.
///
/// `verify_chain` walks every entry currently held in RAM and reports a
/// per-entry verdict via the aggregate counters below. A tamper is any of:
/// `prev_hash` mismatch (chain break), HMAC mismatch (entry-level forgery),
/// or both. Each tampered entry contributes once to [`Self::tampered_count`]
/// regardless of which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIntegrity {
    /// Number of entries that were walked (whether or not they verified
    /// cleanly). This equals the number of entries currently in the ring
    /// buffer when verification completed without an I/O error from the
    /// crypto provider.
    pub entries_verified: u64,
    /// Sequence number of the first entry that failed verification, if any.
    ///
    /// "First" means lowest sequence number — i.e. the earliest tamper site
    /// when entries are walked oldest-to-newest.
    pub first_tampered_seq: Option<u64>,
    /// Total count of entries that failed verification. Zero if the chain is
    /// fully intact. May be larger than `1` when multiple distinct entries
    /// have been tampered with.
    pub tampered_count: u32,
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// Domain separator HMAC'd under `hmac_key_id` to compute the crypto-provider
/// binding fingerprint. The fingerprint is key-specific: a different key slot
/// (or rotated key material) yields a different fingerprint, so a key swap is
/// detected rather than silently producing un-verifiable HMACs.
const CRYPTO_BINDING_DOMAIN: &[u8] = b"vs-event-log-crypto-binding-v1";

/// Threshold at which [`EventLog::is_near_overflow`] reports `true`. Computed
/// once per monomorphization as 90 % of `CAPACITY`.
const fn near_overflow_threshold(capacity: usize) -> usize {
    capacity - capacity / 10
}

/// Tamper-evident security event log backed by a fixed-capacity ring buffer.
///
/// `C` is the cryptographic provider used for SHA-256 and HMAC-SHA256.
/// `CAPACITY` is the maximum number of entries held in memory (ring wraps).
///
/// # Crypto-provider binding
///
/// The log is bound to a specific `CryptoProvider` *and HMAC key* at
/// construction time via a fingerprint computed as
/// `HMAC-SHA256(hmac_key_id, CRYPTO_BINDING_DOMAIN)`. Because the fingerprint
/// is an HMAC keyed by the same slot used to sign entries, it changes whenever
/// the underlying key material changes — not just when the provider *type*
/// changes. Passing a provider to [`Self::append`] or [`Self::verify_chain`]
/// whose key slot holds different material (a key swap or rotation) therefore
/// returns [`VsError::InvalidConfig`] instead of silently producing HMACs that
/// would never verify. The check is fail-closed: any binding mismatch aborts
/// the operation.
///
/// Note this binding still cannot distinguish two providers that hold
/// *identical* key material in the same slot — that is the intended behaviour,
/// since such providers are cryptographically interchangeable for this log.
///
/// # No persistent anchor across reboots
///
/// [`Self::verify_chain`] detects in-RAM tampering of entries currently held
/// in the ring buffer. It does **not** detect tampering that occurred before
/// the current process started: after a reboot the log resets to
/// `sequence = 0` with no persistent anchor, so an attacker who can write to
/// non-volatile storage can forge a fresh "clean" history that this type
/// alone cannot distinguish from a legitimate restart.
///
/// If you need cross-reboot tamper detection, persist the final
/// `(sequence, last_entry_hash)` tuple to `vs-storage` (or another integrity-
/// protected store) on shutdown and re-anchor on boot before the first
/// `append`. This crate intentionally keeps that responsibility outside its
/// surface so the storage backend can be chosen per-deployment.
///
/// # In-RAM truncation / replay
///
/// The per-entry HMAC mixes in the live `overflow_count`, but that counter is
/// a single scalar with no external anchor. An attacker who can rewrite the
/// in-RAM ring buffer can truncate the log and replace it with an earlier,
/// internally-consistent prefix carrying a correspondingly lower
/// `overflow_count`: every HMAC still verifies because the counter matches the
/// reconstruction formula. [`Self::verify_chain`] therefore proves *internal
/// consistency* of the entries present, not that no entries were dropped.
/// Detecting truncation requires the same persistent `(sequence, hash)` anchor
/// described above, compared against the highest sequence ever observed.
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
    /// Key-bound fingerprint of the crypto provider, computed at construction
    /// as `HMAC-SHA256(hmac_key_id, CRYPTO_BINDING_DOMAIN)`. Detects both
    /// provider-type swaps and key-material swaps/rotation on `hmac_key_id`.
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
    /// Marker for the crypto provider type.
    _crypto: core::marker::PhantomData<C>,
}

impl<C: CryptoProvider, const CAPACITY: usize> EventLog<C, CAPACITY> {
    /// Create a new, empty event log bound to `crypto`.
    ///
    /// `hmac_key_id` identifies the key slot used for HMAC-SHA256 signing and
    /// verification of log entries.  The `crypto` provider is fingerprinted
    /// under that key so that subsequent [`append`](Self::append) and
    /// [`verify_chain`](Self::verify_chain) calls can detect both provider
    /// swaps and key-material swaps/rotation on the bound slot.
    pub fn new(hmac_key_id: KeyId, crypto: &C) -> Result<Self, VsError> {
        const { assert!(CAPACITY > 0, "EventLog CAPACITY must be greater than zero") };
        // Bind the fingerprint to the actual HMAC key material: an HMAC of a
        // fixed domain under `hmac_key_id`. A different key (swap or rotation)
        // produces a different fingerprint, so `verify_crypto_binding` rejects
        // it instead of letting `append`/`verify_chain` compute HMACs that
        // would never verify.
        let mut fingerprint = [0u8; 32];
        crypto.hmac_sha256(hmac_key_id, CRYPTO_BINDING_DOMAIN, &mut fingerprint)?;
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
            _crypto: core::marker::PhantomData,
        })
    }

    /// Verify that `crypto` matches the provider *and key material* bound at
    /// construction time.
    ///
    /// Recomputes the key-bound fingerprint
    /// (`HMAC-SHA256(hmac_key_id, CRYPTO_BINDING_DOMAIN)`) and compares it in
    /// constant time. A mismatch — provider swap, key swap, or key rotation —
    /// is fail-closed: the caller's operation is aborted with
    /// [`VsError::InvalidConfig`].
    fn verify_crypto_binding(&self, crypto: &C) -> Result<(), VsError> {
        let mut fp = [0u8; 32];
        crypto.hmac_sha256(self.hmac_key_id, CRYPTO_BINDING_DOMAIN, &mut fp)?;
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

        // Build the HMAC input directly into a single 186-byte buffer: the
        // first 178 bytes are the entry fields (via the shared writer) and
        // the trailing 8 bytes are the current overflow count, so ring-buffer
        // overflows are captured in the tamper chain without a separate
        // entry. Avoids an intermediate 178-byte stack copy.
        //
        // CRITICAL hidden invariant: `verify_chain` cannot read the live
        // `overflow_count`, so it reconstructs the value used here as
        // `sequence.saturating_sub(CAPACITY)`. That identity only holds while
        // `overflow_count` is incremented exactly once per append after the
        // ring is full and never reset. The assertion below pins the producer
        // (here) to the verifier's reconstruction formula: any future change
        // to overflow accounting that breaks the identity fails fast in debug
        // builds instead of silently corrupting every stored HMAC.
        debug_assert_eq!(
            self.overflow_count,
            sequence.saturating_sub(CAPACITY as u64),
            "overflow_count must equal sequence.saturating_sub(CAPACITY); \
             verify_chain reconstructs it from this identity"
        );
        let mut hmac_buf = [0u8; HMAC_MESSAGE_SIZE + 8];
        entry.write_fields(&mut hmac_buf[..HMAC_MESSAGE_SIZE]);
        hmac_buf[HMAC_MESSAGE_SIZE..].copy_from_slice(&self.overflow_count.to_le_bytes());
        crypto.hmac_sha256(self.hmac_key_id, &hmac_buf, &mut entry.entry_hmac)?;

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
    ///
    /// Every entry currently in the ring buffer is checked independently:
    ///
    /// * `prev_hash` is compared against the SHA-256 of the **last known-good**
    ///   previous entry. A mismatch counts as a tamper.
    /// * `entry_hmac` is recomputed and compared regardless of the chain-link
    ///   verdict; an HMAC mismatch counts as a tamper.
    ///
    /// An entry that fails either check contributes once to
    /// [`ChainIntegrity::tampered_count`]. The anchor for the next iteration
    /// (`prev_serialized`) is **only advanced when the current entry verified
    /// cleanly on both checks**, so a tampered entry does not poison
    /// subsequent chain-link comparisons.
    #[must_use = "chain-integrity verification result must not be silently ignored"]
    pub fn verify_chain(&self, crypto: &C) -> Result<ChainIntegrity, VsError> {
        self.verify_crypto_binding(crypto)?;

        if self.count == 0 {
            return Ok(ChainIntegrity {
                entries_verified: 0,
                first_tampered_seq: None,
                tampered_count: 0,
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
        let mut tampered_count: u32 = 0;
        // Serialization of the most recent KNOWN-GOOD entry. We deliberately
        // do not advance this from a tampered entry so that a chain break
        // does not cascade through the rest of the log.
        let mut last_good_serialized: Option<[u8; ENTRY_SERIALIZED_SIZE]> = None;

        for i in 0..stored {
            let ring_idx = (oldest_idx + i) % CAPACITY;
            let Some(entry) = &self.entries[ring_idx] else {
                break;
            };

            let mut entry_tampered = false;

            // -- Verify prev_hash against the last known-good predecessor ---
            if let Some(ref prev_ser) = last_good_serialized {
                let mut expected_hash = [0u8; 32];
                crypto.sha256(prev_ser, &mut expected_hash)?;
                if !bool::from(entry.prev_hash.ct_eq(&expected_hash)) {
                    entry_tampered = true;
                }
            }

            // -- Verify HMAC independently (even if prev_hash failed) -------
            // Reconstruct the overflow count that was used when this entry's
            // HMAC was computed. The HMAC is computed *before* the overflow
            // counter is incremented, so: overflow = max(0, seq - CAP).
            //
            // This formula is the verifier half of the hidden invariant
            // asserted in `append` (see the `debug_assert_eq!` there): the two
            // sites must stay in lock-step or every stored HMAC is corrupted.
            let overflow_at_entry = entry.sequence.saturating_sub(CAPACITY as u64);
            let mut hmac_buf = [0u8; HMAC_MESSAGE_SIZE + 8];
            entry.write_fields(&mut hmac_buf[..HMAC_MESSAGE_SIZE]);
            hmac_buf[HMAC_MESSAGE_SIZE..].copy_from_slice(&overflow_at_entry.to_le_bytes());
            let mut expected_hmac = [0u8; 32];
            crypto.hmac_sha256(self.hmac_key_id, &hmac_buf, &mut expected_hmac)?;
            if !bool::from(entry.entry_hmac.ct_eq(&expected_hmac)) {
                entry_tampered = true;
            }

            if entry_tampered {
                tampered_count = tampered_count.saturating_add(1);
                if first_tampered_seq.is_none() {
                    first_tampered_seq = Some(entry.sequence);
                }
                // Do NOT advance last_good_serialized: keep anchoring on the
                // most recent clean entry.
            } else {
                // Entry verified cleanly on both checks — advance the anchor.
                let mut ser = [0u8; ENTRY_SERIALIZED_SIZE];
                entry.serialize(&mut ser);
                last_good_serialized = Some(ser);
            }

            entries_verified = entries_verified.saturating_add(1);
        }

        Ok(ChainIntegrity {
            entries_verified,
            first_tampered_seq,
            tampered_count,
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

        // Early-return when the requested range cannot intersect what is
        // currently stored: examine the oldest and newest entries and bail
        // out before the full O(N) scan.
        let newest_idx = if self.head == 0 {
            CAPACITY - 1
        } else {
            self.head - 1
        };
        if let (Some(oldest), Some(newest)) = (
            self.entries[oldest_idx].as_ref(),
            self.entries[newest_idx].as_ref(),
        ) {
            if to_seq < oldest.sequence || from_seq > newest.sequence {
                return 0;
            }
        }

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
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.count
    }

    /// Number of entries lost due to ring buffer overflow.
    #[must_use]
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Registers a callback invoked when an entry is about to be evicted
    /// from the ring buffer due to overflow. The callback receives the
    /// sequence number and timestamp of the entry being overwritten.
    pub fn set_overflow_callback(&mut self, cb: fn(seq: u64, timestamp_us: u64)) {
        self.overflow_callback = Some(cb);
    }

    /// Threshold (in entries) at which [`Self::is_near_overflow`] starts
    /// returning `true`. Equal to 90 % of `CAPACITY`, rounded down.
    pub const NEAR_OVERFLOW_THRESHOLD: usize = near_overflow_threshold(CAPACITY);

    /// Returns `true` when the ring buffer is more than 90 % full.
    ///
    /// This can be used as an early warning to trigger log export or
    /// rotation before entries start being overwritten. The exact threshold
    /// is available as [`Self::NEAR_OVERFLOW_THRESHOLD`].
    #[must_use]
    pub fn is_near_overflow(&self) -> bool {
        self.entry_count >= Self::NEAR_OVERFLOW_THRESHOLD
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
        assert_eq!(integrity.tampered_count, 0);
    }

    /// Regression test for the "cascade past first tamper" bug:
    /// two independent tampers at distinct sequence numbers must both be
    /// counted, and `first_tampered_seq` must point at the lower one.
    #[test]
    fn two_distinct_tampers_are_both_detected() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..6u64 {
            log.append(EventType::SecurityAlert, &[i as u8; 4], i * 100, &c)
                .expect("append");
        }

        // Tamper #1: flip a bit in payload of entry at sequence 1.
        if let Some(ref mut entry) = log.entries[1] {
            entry.payload[0] ^= 0xFF;
        }
        // Tamper #2: flip a bit in the HMAC of entry at sequence 4.
        if let Some(ref mut entry) = log.entries[4] {
            entry.entry_hmac[0] ^= 0x55;
        }

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.first_tampered_seq, Some(1));
        // Both tampers must be detected. Depending on whether the prev_hash
        // of entry 2 also fails (because entry 1's serialization changed),
        // the count may be 2 (both tampered entries themselves) when we
        // anchor on the last known-good predecessor — which is what we do
        // now. The minimum acceptable behavior is `>= 2`.
        let tc = integrity.tampered_count;
        assert!(tc >= 2, "tampered_count = {tc}");
        assert_eq!(integrity.entries_verified, 6);
    }

    /// Regression test for the original cascade bug: if entry 2 is tampered,
    /// the OLD verifier would (a) skip entry 2's own HMAC check and (b)
    /// anchor the rest of the walk on entry 2's tampered serialization,
    /// reporting entries 3..N as clean. With the fixed verifier:
    ///   * entry 2 must be flagged as tampered on its own HMAC, AND
    ///   * `first_tampered_seq` must point at entry 2,
    ///   * the walk does not stop or panic and produces a stable result.
    #[test]
    fn tamper_does_not_cascade_silently() {
        let mut log = make_log();
        let c = crypto();

        for i in 0..5u64 {
            log.append(EventType::BootEvent, &[i as u8; 4], i * 100, &c)
                .expect("append");
        }

        // Flip a bit in entry 2's HMAC. With the OLD code the HMAC check was
        // bypassed entirely when the chain link broke; with the new code we
        // verify HMACs independently of chain-link status.
        if let Some(ref mut entry) = log.entries[2] {
            entry.entry_hmac[0] ^= 0xFF;
        }

        let integrity = log.verify_chain(&c).expect("verify");
        assert_eq!(integrity.first_tampered_seq, Some(2));
        assert!(integrity.tampered_count >= 1);
        assert_eq!(integrity.entries_verified, 5);
    }

    /// `LogEntry::hmac_message` and the first `HMAC_MESSAGE_SIZE` bytes of
    /// `LogEntry::serialize` must produce identical bytes. Any drift would
    /// silently corrupt the HMAC chain.
    #[test]
    fn hmac_message_matches_serialize_prefix() {
        let entry = LogEntry {
            sequence: 0x1122_3344_5566_7788,
            timestamp_us: 0x99AA_BBCC_DDEE_FF00,
            event_type: EventType::PolicyChange,
            payload: [0xA5; 128],
            payload_len: 77,
            prev_hash: [0x5A; 32],
            entry_hmac: [0xC3; 32],
        };

        let mut hmac_buf = [0u8; HMAC_MESSAGE_SIZE];
        entry.hmac_message(&mut hmac_buf);

        let mut ser_buf = [0u8; ENTRY_SERIALIZED_SIZE];
        entry.serialize(&mut ser_buf);

        assert_eq!(&hmac_buf[..], &ser_buf[..HMAC_MESSAGE_SIZE]);
        // And the trailing 32 bytes of `serialize` are exactly `entry_hmac`.
        assert_eq!(&ser_buf[HMAC_MESSAGE_SIZE..], &entry.entry_hmac[..]);
    }

    /// H-1 regression: the crypto-provider binding is keyed by `hmac_key_id`,
    /// so a provider that effectively holds different key material (modelled
    /// here by signing the same log with a different `KeyId`) is rejected with
    /// `VsError::InvalidConfig` rather than silently producing un-verifiable
    /// HMACs. This exercises the previously-untested binding failure path.
    #[test]
    fn crypto_binding_rejects_key_swap() {
        // Log bound to key slot 42.
        let mut log = EventLog::<TestCrypto, TEST_CAP>::new(KeyId(42), &crypto()).unwrap();
        let c = crypto();
        log.append(EventType::SecurityAlert, &[1], 100, &c).unwrap();

        // Simulate a key swap: the same fingerprint slot now holds different
        // material. We model that by constructing a log bound to a different
        // key and copying its (mismatching) fingerprint into our log.
        let other = EventLog::<TestCrypto, TEST_CAP>::new(KeyId(99), &crypto()).unwrap();
        assert_ne!(
            log.crypto_fingerprint, other.crypto_fingerprint,
            "different key slots must yield different binding fingerprints"
        );
        log.crypto_fingerprint = other.crypto_fingerprint;

        // Both append and verify_chain must now fail-closed.
        assert_eq!(
            log.append(EventType::SecurityAlert, &[2], 200, &c),
            Err(VsError::InvalidConfig)
        );
        assert_eq!(log.verify_chain(&c), Err(VsError::InvalidConfig));
    }

    #[test]
    fn near_overflow_threshold_is_90_percent() {
        // For TEST_CAP == 8 -> threshold = 8 - 8/10 = 8 - 0 = 8.
        // So is_near_overflow becomes true only at capacity for very small caps.
        assert_eq!(
            <EventLog<TestCrypto, TEST_CAP>>::NEAR_OVERFLOW_THRESHOLD,
            TEST_CAP - TEST_CAP / 10,
        );

        // Larger capacity: 100 -> threshold = 100 - 10 = 90.
        assert_eq!(<EventLog<TestCrypto, 100>>::NEAR_OVERFLOW_THRESHOLD, 90,);
    }
}
