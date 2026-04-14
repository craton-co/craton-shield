// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

#![no_std]

//! CAN signal-level intrusion detection using per-signal EWMA anomaly ensemble.
//!
//! Extracts individual signals from CAN frame payloads (supporting both Intel/LE and
//! Motorola/BE byte orders) and monitors them for statistical anomalies using exponentially
//! weighted moving average (EWMA) with configurable z-score thresholds.

use vs_anomaly::EwmaDetector;
use vs_can_monitor::CanFrame;
use vs_types::VsError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of signal definitions the engine can track.
const MAX_SIGNALS: usize = 64;

const _: () = assert!(MAX_SIGNALS <= u16::MAX as usize);

/// Maximum number of anomalies reported per single frame processing call.
const MAX_ANOMALIES_PER_FRAME: usize = 8;

/// Maximum supported bit length for a single signal.
const MAX_BIT_LENGTH: u8 = 64;

// ---------------------------------------------------------------------------
// ByteOrder
// ---------------------------------------------------------------------------

/// Byte order for CAN signal extraction.
///
/// Matches DBC conventions: Little-Endian = Intel, Big-Endian = Motorola.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Intel byte order — LSB at `start_bit`, bits grow toward MSB.
    LittleEndian,
    /// Motorola byte order — MSB at `start_bit`, bits grow toward LSB.
    BigEndian,
}

// ---------------------------------------------------------------------------
// SignalDefinition
// ---------------------------------------------------------------------------

/// Definition of a single CAN signal within a frame payload.
///
/// Maps a contiguous bit range in a CAN frame to a physical value using:
/// `physical = raw_value * scale + offset`
#[derive(Debug, Clone, Copy)]
pub struct SignalDefinition {
    /// CAN arbitration ID this signal belongs to.
    pub can_id: u32,
    /// Start bit position within the frame payload (0-indexed from byte 0, bit 0).
    pub start_bit: u16,
    /// Number of bits in this signal (1..=64).
    pub bit_length: u8,
    /// Byte order for multi-byte signals.
    pub byte_order: ByteOrder,
    /// Linear scaling factor: `physical = raw * scale + offset`.
    pub scale: f32,
    /// Offset for linear scaling.
    pub offset: f32,
    /// Hash of the signal name (for identification without heap allocation).
    pub name_hash: u32,
    /// Whether this signal uses two's complement (signed) representation.
    /// When `true`, the extracted raw value is sign-extended before conversion
    /// to `f32` physical value.
    pub signed: bool,
    /// Whether this signal is a multiplexor (selector) signal.
    /// Multiplexor signals determine which set of multiplexed signals
    /// to decode in the frame.
    pub is_multiplexor: bool,
    /// Optional multiplexor value for multiplexed signals.
    /// When `Some(mux_val)`, this signal definition only applies when
    /// the multiplexor signal in the same frame equals `mux_val`.
    /// When `None`, this signal applies to all frames with this CAN ID.
    pub multiplexor_value: Option<u16>,
}

impl Default for SignalDefinition {
    /// Returns an unsigned, non-multiplexed, 8-bit little-endian signal
    /// with scale=1.0 and offset=0.0 on CAN ID 0 at bit 0.
    ///
    /// Useful as a base for struct-update syntax:
    /// ```ignore
    /// SignalDefinition { can_id: 0x100, bit_length: 16, ..Default::default() }
    /// ```
    fn default() -> Self {
        Self {
            can_id: 0,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Signal extraction
// ---------------------------------------------------------------------------

/// Extract a raw integer value from CAN frame data based on a signal definition.
///
/// Returns `None` if the signal's bit range extends beyond the available data.
fn extract_raw_bits(frame_data: &[u8], data_len: usize, def: &SignalDefinition) -> Option<u64> {
    extract_signal_raw(frame_data, data_len, def)
}

/// Extract a raw integer value from CAN frame data based on a signal definition.
///
/// This is the public version of raw bit extraction. For signals with
/// `bit_length > 24`, the raw `u64` preserves full precision that would
/// otherwise be lost when casting to `f32` in [`extract_signal`].
///
/// Returns `None` if `bit_length` is 0 or exceeds 64, or if the signal's
/// bit range extends beyond the available data.
pub fn extract_signal_raw(
    frame_data: &[u8],
    data_len: usize,
    def: &SignalDefinition,
) -> Option<u64> {
    if def.bit_length == 0 || def.bit_length > MAX_BIT_LENGTH {
        return None;
    }

    match def.byte_order {
        ByteOrder::LittleEndian => extract_raw_le(frame_data, data_len, def),
        ByteOrder::BigEndian => extract_raw_be(frame_data, data_len, def),
    }
}

/// Extract raw bits in little-endian (Intel) byte order.
///
/// In Intel byte order, `start_bit` points to the LSB. Bits are numbered
/// sequentially across bytes: byte 0 bits 0-7, byte 1 bits 8-15, etc.
///
/// Includes a fast path for byte-aligned signals (`start_bit` and `bit_length`
/// are both multiples of 8), which is the common case in many CAN databases.
/// The fast path reads whole bytes directly, avoiding the per-bit loop.
fn extract_raw_le(frame_data: &[u8], data_len: usize, def: &SignalDefinition) -> Option<u64> {
    let start = def.start_bit as usize;
    let length = def.bit_length as usize;

    // Check that all bits are within the available data.
    let end_bit = start + length;
    let required_bytes = end_bit.div_ceil(8);
    if required_bytes > data_len {
        return None;
    }

    // Fast path: byte-aligned signals (very common in CAN databases).
    // Reads whole bytes directly instead of iterating per-bit, reducing
    // loop iterations by up to 8x for the hot path in CAN IDS processing.
    if start % 8 == 0 && length % 8 == 0 {
        let start_byte = start / 8;
        let num_bytes = length / 8;
        let mut value: u64 = 0;
        let mut i = 0;
        while i < num_bytes {
            value |= (frame_data[start_byte + i] as u64) << (i * 8);
            i += 1;
        }
        return Some(value);
    }

    // General path: bit-by-bit extraction for non-aligned signals.
    //
    // Optimization note: for typical CAN databases, most signals are
    // byte-aligned (covered by the fast path above). Non-aligned signals
    // are uncommon enough that the per-bit loop's simplicity is preferred
    // over a more complex multi-byte read with mask/shift logic.
    // If profiling shows this is a bottleneck for a specific database,
    // consider pre-computing byte boundaries and reading 1–8 bytes at once.
    let mut value: u64 = 0;
    for i in 0..length {
        let bit_pos = start + i;
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8;
        if byte_idx >= data_len {
            return None;
        }
        if (frame_data[byte_idx] >> bit_idx) & 1 == 1 {
            value |= 1u64 << i;
        }
    }

    Some(value)
}

/// Extract raw bits in big-endian (Motorola) byte order.
///
/// In Motorola byte order, `start_bit` points to the MSB. Bits are laid out
/// such that within each byte the MSB is the highest-numbered bit position,
/// and the signal continues to the next byte in big-endian fashion.
fn extract_raw_be(frame_data: &[u8], data_len: usize, def: &SignalDefinition) -> Option<u64> {
    let start = def.start_bit as usize;
    let length = def.bit_length as usize;

    // General path: bit-by-bit extraction for non-aligned signals.
    //
    // Optimization note: for typical CAN databases, most signals are
    // byte-aligned (covered by the fast path above). Non-aligned signals
    // are uncommon enough that the per-bit loop's simplicity is preferred
    // over a more complex multi-byte read with mask/shift logic.
    // If profiling shows this is a bottleneck for a specific database,
    // consider pre-computing byte boundaries and reading 1–8 bytes at once.
    let mut value: u64 = 0;
    let mut bit_pos = start;

    for i in 0..length {
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8;
        if byte_idx >= data_len {
            return None;
        }
        if (frame_data[byte_idx] >> bit_idx) & 1 == 1 {
            // MSB first: bit i=0 is the most significant bit of the result
            value |= 1u64 << (length - 1 - i);
        }

        // Navigate to next bit in Motorola order:
        // Within a byte, go from higher bit to lower. At bit 0 of a byte,
        // wrap to bit 7 of the next byte.
        if bit_idx == 0 {
            bit_pos += 15; // jump to bit 7 of next byte
        } else {
            bit_pos -= 1;
        }
    }

    Some(value)
}

/// Extract a physical signal value from CAN frame data.
///
/// Returns `None` if the signal's bit range exceeds the frame payload length
/// or if the computed physical value is not finite (NaN or infinity from
/// extreme `scale`/`offset` combinations).
///
/// When `scale` is zero the formula `raw * 0.0 + offset` evaluates to
/// `offset` for any finite raw value, which is well-defined.
///
/// # Precision note
///
/// The raw integer value is cast to `f32` before applying the linear
/// transformation. An `f32` has only 24 bits of mantissa, so for signals
/// with `bit_length > 24` the conversion loses precision — distinct raw
/// integer values may map to the same `f32`. If your application requires
/// exact representation of 32-bit or wider signals, use [`extract_signal_raw`]
/// directly and work with the raw `u64` value instead of the `f32` result.
pub fn extract_signal(frame_data: &[u8], data_len: usize, def: &SignalDefinition) -> Option<f32> {
    // Clamp data_len to the actual slice length to prevent out-of-bounds
    // access if the caller provides a data_len larger than the slice.
    let data_len = data_len.min(frame_data.len());
    let raw = extract_raw_bits(frame_data, data_len, def)?;
    let raw = if def.signed && def.bit_length < 64 {
        // Sign-extend: if the MSB of the raw value is set, fill upper bits with 1s
        let sign_bit = 1u64 << (def.bit_length as u32 - 1);
        if raw & sign_bit != 0 {
            raw | !((1u64 << def.bit_length as u32) - 1)
        } else {
            raw
        }
    } else {
        raw
    };
    #[allow(clippy::cast_possible_wrap)]
    let value = if def.signed {
        (raw as i64) as f32 * def.scale + def.offset
    } else {
        raw as f32 * def.scale + def.offset
    };
    if value.is_finite() {
        Some(value)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// SignalAnomaly
// ---------------------------------------------------------------------------

/// A single signal anomaly detected during frame processing.
#[derive(Debug, Clone, Copy)]
pub struct SignalAnomaly {
    /// Index of the signal definition that triggered the anomaly.
    pub signal_index: u16,
    /// Z-score of the anomalous value.
    pub z_score: f32,
    /// Physical value that triggered the anomaly.
    pub physical_value: f32,
}

impl SignalAnomaly {
    const fn empty() -> Self {
        Self {
            signal_index: 0,
            z_score: 0.0,
            physical_value: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// SignalIdsResult
// ---------------------------------------------------------------------------

/// Result of processing a single CAN frame through the signal IDS engine.
#[derive(Debug, Clone, Copy)]
#[must_use = "anomaly results should be inspected — discarding them silently ignores detected intrusions"]
pub struct SignalIdsResult {
    /// Number of anomalies detected (0..=`MAX_ANOMALIES_PER_FRAME`).
    pub anomaly_count: u8,
    /// Anomaly details (only first `anomaly_count` entries are valid).
    pub anomalies: [SignalAnomaly; MAX_ANOMALIES_PER_FRAME],
}

impl SignalIdsResult {
    const fn empty() -> Self {
        Self {
            anomaly_count: 0,
            anomalies: [SignalAnomaly::empty(); MAX_ANOMALIES_PER_FRAME],
        }
    }
}

// ---------------------------------------------------------------------------
// SignalIdsEngine
// ---------------------------------------------------------------------------

/// CAN signal-level intrusion detection engine.
///
/// Maintains a set of signal definitions and a per-signal EWMA anomaly
/// detector. When a CAN frame is processed, all matching signals are
/// extracted and scored against their learned statistical profile.
///
/// Definitions are stored contiguously (packed at the front of the array)
/// and sorted by `can_id` so that signals for the same CAN ID are contiguous.
/// `process_frame` uses binary search to find matching definitions in O(log n).
/// A parallel index map records the original insertion slot for stable
/// `signal_index` values in anomaly reports.
/// Maximum number of distinct CAN IDs in the fast-path index.
/// Equal to `MAX_SIGNALS` because each signal could belong to a unique CAN ID.
const MAX_CAN_ID_INDEX: usize = MAX_SIGNALS;

pub struct SignalIdsEngine {
    /// Signal definitions (contiguously packed, first `signal_count` are valid).
    /// Sorted by CAN ID so that signals for the same CAN ID are contiguous.
    definitions: [SignalDefinition; MAX_SIGNALS],
    /// Per-signal EWMA detector (struct-of-arrays for cache-friendly access).
    detectors: [EwmaDetector; MAX_SIGNALS],
    /// Maps packed index → original slot index for stable anomaly reporting.
    slot_map: [u16; MAX_SIGNALS],
    /// Number of defined signals.
    signal_count: usize,
    /// Default EWMA parameters for new detectors.
    alpha: f32,
    z_threshold: f32,
    /// Next slot index to assign (monotonically increasing).
    ///
    /// Uses `saturating_add` so it caps at `u16::MAX` (65 535). After that
    /// many cumulative define calls (regardless of removals), new signals
    /// will receive duplicate slot indices. In practice automotive signal
    /// sets are defined once at ECU startup, so this limit is not
    /// reachable in normal operation.
    pub(crate) next_slot: u16,
    /// Fast-path CAN ID set: CAN IDs with at least one monitored signal.
    /// Rebuilt on `define_signal` and `remove_signal`. Enables O(k) lookup
    /// (where k = number of distinct monitored CAN IDs) instead of O(n)
    /// scan through all signal definitions.
    can_id_set: [u32; MAX_CAN_ID_INDEX],
    /// Number of valid entries in `can_id_set`.
    can_id_count: usize,
}

impl SignalIdsEngine {
    /// Create a new signal IDS engine with the given EWMA parameters.
    ///
    /// Returns `VsError::InvalidInput` if `alpha` or `z_threshold` are not
    /// valid for `EwmaDetector` construction (e.g. NaN, negative, or
    /// out of range).
    /// Zero-initialized placeholder definition (never read beyond `signal_count`).
    const ZERO_DEF: SignalDefinition = SignalDefinition {
        can_id: 0,
        start_bit: 0,
        bit_length: 1,
        byte_order: ByteOrder::LittleEndian,
        scale: 0.0,
        offset: 0.0,
        name_hash: 0,
        signed: false,
        is_multiplexor: false,
        multiplexor_value: None,
    };

    pub fn new(alpha: f32, z_threshold: f32) -> Result<Self, VsError> {
        // Validate EWMA parameters upfront rather than panicking inside
        // the array initializer.
        let probe = EwmaDetector::new(alpha, z_threshold).ok_or(VsError::InvalidInput)?;
        Ok(Self {
            definitions: [Self::ZERO_DEF; MAX_SIGNALS],
            detectors: [probe; MAX_SIGNALS],
            slot_map: [0; MAX_SIGNALS],
            signal_count: 0,
            alpha,
            z_threshold,
            next_slot: 0,
            can_id_set: [0; MAX_CAN_ID_INDEX],
            can_id_count: 0,
        })
    }

    /// Returns the next slot index that will be assigned.
    pub fn next_slot(&self) -> u16 {
        self.next_slot
    }

    /// Rebuild the CAN ID fast-path set from the current packed definitions.
    ///
    /// Collects distinct CAN IDs so that `process_frame` can reject
    /// unmonitored CAN IDs without scanning the full definitions array.
    fn rebuild_can_id_index(&mut self) {
        self.can_id_count = 0;
        let count = self.signal_count;
        for i in 0..count {
            let cid = self.definitions[i].can_id;
            let mut found = false;
            for j in 0..self.can_id_count {
                if self.can_id_set[j] == cid {
                    found = true;
                    break;
                }
            }
            if !found && self.can_id_count < MAX_CAN_ID_INDEX {
                self.can_id_set[self.can_id_count] = cid;
                self.can_id_count += 1;
            }
        }
        self.can_id_set[..self.can_id_count].sort_unstable();
    }

    /// Check if a CAN ID has any monitored signals (fast-path reject).
    fn has_can_id(&self, can_id: u32) -> bool {
        let count = self.can_id_count;
        if count == 0 {
            return false;
        }
        self.can_id_set[..count].binary_search(&can_id).is_ok()
    }

    /// Find the insertion position to keep definitions sorted by `can_id`.
    /// Returns the index where a definition with the given `can_id` should
    /// be inserted so that the array remains sorted.
    fn sorted_insert_pos(&self, can_id: u32) -> usize {
        // Binary search for the first position where can_id <= definitions[pos].can_id.
        let mut lo = 0usize;
        let mut hi = self.signal_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.definitions[mid].can_id < can_id {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Binary search for the first definition index with the given `can_id`.
    /// Returns `None` if no definition matches.
    fn binary_search_can_id(&self, can_id: u32) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.signal_count;
        let mut result = None;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.definitions[mid].can_id < can_id {
                lo = mid + 1;
            } else {
                if self.definitions[mid].can_id == can_id {
                    result = Some(mid);
                }
                hi = mid;
            }
        }
        result
    }

    /// Insert a definition at position `pos`, shifting later elements right.
    fn insert_at(&mut self, pos: usize, def: SignalDefinition, detector: EwmaDetector, slot: u16) {
        // Shift elements from signal_count-1 down to pos, moving right.
        let mut i = self.signal_count;
        while i > pos {
            self.definitions[i] = self.definitions[i - 1];
            self.detectors[i] = self.detectors[i - 1];
            self.slot_map[i] = self.slot_map[i - 1];
            i -= 1;
        }
        self.definitions[pos] = def;
        self.detectors[pos] = detector;
        self.slot_map[pos] = slot;
        self.signal_count += 1;
    }

    /// Define a new signal to monitor. Returns the slot index on success.
    ///
    /// Returns `VsError::ResourceExhausted` if all slots are full.
    /// Returns `VsError::BusError` if `bit_length` is 0 or > 64.
    pub fn define_signal(&mut self, def: SignalDefinition) -> Result<usize, VsError> {
        if def.bit_length == 0 || def.bit_length > MAX_BIT_LENGTH {
            return Err(VsError::BusError);
        }

        // Warn during development if a signal is wider than the f32 mantissa
        // (24 bits). The IDS engine uses `extract_signal` internally, which
        // casts the raw integer to f32 — signals with bit_length > 24 may
        // lose precision, causing distinct raw values to map to the same
        // physical value and potentially masking anomalies. If exact
        // representation matters, use `extract_signal_raw()` directly.
        debug_assert!(
            def.bit_length <= 24,
            "define_signal: bit_length {} exceeds f32 mantissa precision (24 bits). \
             The IDS engine may lose precision for wider signals.",
            def.bit_length
        );

        if self.signal_count >= MAX_SIGNALS {
            return Err(VsError::ResourceExhausted);
        }

        // Reject new signals if the slot counter has saturated. After 65,535
        // cumulative define_signal calls, next_slot wraps to u16::MAX and
        // cannot produce unique indices. In practice, automotive signal sets
        // are defined once at ECU startup, so this limit is unreachable.
        if self.next_slot == u16::MAX {
            return Err(VsError::ResourceExhausted);
        }

        let slot = self.next_slot;
        let detector =
            EwmaDetector::new(self.alpha, self.z_threshold).ok_or(VsError::InvalidInput)?;

        // Find sorted insertion position by can_id.
        let pos = self.sorted_insert_pos(def.can_id);
        self.insert_at(pos, def, detector, slot);

        self.next_slot = self.next_slot.saturating_add(1);
        self.rebuild_can_id_index();
        Ok(slot as usize)
    }

    /// Define multiple signals in batch. Returns `Ok(())` on success.
    ///
    /// This is more efficient than calling `define_signal` repeatedly because
    /// it only rebuilds the CAN ID index once at the end.
    ///
    /// Returns `VsError::ResourceExhausted` if adding all signals would exceed capacity.
    /// Returns `VsError::BusError` if any definition has `bit_length` 0 or > 64.
    pub fn define_signals_batch(&mut self, defs: &[SignalDefinition]) -> Result<(), VsError> {
        // Pre-validate all definitions before modifying state.
        if self.signal_count + defs.len() > MAX_SIGNALS {
            return Err(VsError::ResourceExhausted);
        }
        for def in defs {
            if def.bit_length == 0 || def.bit_length > MAX_BIT_LENGTH {
                return Err(VsError::BusError);
            }
            debug_assert!(
                def.bit_length <= 24,
                "define_signals_batch: bit_length {} exceeds f32 mantissa precision (24 bits). \
                 The IDS engine may lose precision for wider signals.",
                def.bit_length
            );
        }
        if !defs.is_empty() && self.next_slot == u16::MAX {
            return Err(VsError::ResourceExhausted);
        }
        // Check that we have enough slot headroom for all definitions.
        // next_slot uses saturating_add, so we need to verify we won't
        // run out of unique slots.
        if defs.len() > 1 {
            let slots_remaining = (u16::MAX as usize).saturating_sub(self.next_slot as usize);
            if defs.len() > slots_remaining + 1 {
                return Err(VsError::ResourceExhausted);
            }
        }

        // Append all definitions to the end of the array (O(n) instead of O(n^2)
        // sorted insertion), then sort once.
        for def in defs {
            let slot = self.next_slot;
            let detector =
                EwmaDetector::new(self.alpha, self.z_threshold).ok_or(VsError::InvalidInput)?;
            let pos = self.signal_count;
            self.definitions[pos] = *def;
            self.detectors[pos] = detector;
            self.slot_map[pos] = slot;
            self.signal_count += 1;
            self.next_slot = self.next_slot.saturating_add(1);
        }

        // Sort all definitions by can_id to restore the sorted invariant.
        // We need to sort definitions, detectors, and slot_map in parallel.
        // Use a simple insertion sort (signal count is bounded by MAX_SIGNALS=64).
        let n = self.signal_count;
        for i in 1..n {
            let mut j = i;
            while j > 0 && self.definitions[j - 1].can_id > self.definitions[j].can_id {
                // Swap all parallel arrays.
                self.definitions.swap(j - 1, j);
                self.detectors.swap(j - 1, j);
                self.slot_map.swap(j - 1, j);

                j -= 1;
            }
        }

        self.rebuild_can_id_index();
        Ok(())
    }

    /// Process a CAN frame: extract all matching signals, feed to EWMA
    /// detectors, and return anomaly results.
    ///
    /// Uses binary search to find the first definition matching the CAN ID,
    /// then iterates only the contiguous run of matching definitions.
    #[allow(clippy::cast_possible_truncation)] // signal_index is bounds-checked above
    pub fn process_frame(&mut self, frame: &CanFrame) -> SignalIdsResult {
        let mut result = SignalIdsResult::empty();

        // Fast-path: skip entirely if no signals are defined for this CAN ID.
        if !self.has_can_id(frame.id) {
            return result;
        }

        let data_len = frame.payload_len();

        // Binary search for the first definition matching this CAN ID.
        let Some(start) = self.binary_search_can_id(frame.id) else {
            return result;
        };

        // First pass: find and extract the multiplexor signal value (if any).
        let mut mux_value: Option<u16> = None;
        {
            let mut i = start;
            while i < self.signal_count && self.definitions[i].can_id == frame.id {
                if self.definitions[i].is_multiplexor {
                    if let Some(raw) = extract_raw_bits(&frame.data, data_len, &self.definitions[i])
                    {
                        mux_value = Some(raw as u16);
                    }
                    break;
                }
                i += 1;
            }
        }

        // Second pass: extract and score all applicable signals.
        let mut i = start;
        while i < self.signal_count && self.definitions[i].can_id == frame.id {
            let def = &self.definitions[i];

            // Skip multiplexed signals whose multiplexor value doesn't match.
            if let Some(mux_val) = def.multiplexor_value {
                match mux_value {
                    Some(current_mux) if current_mux == mux_val => {}
                    _ => {
                        i += 1;
                        continue;
                    }
                }
            }

            // Extract the physical value.
            let Some(value) = extract_signal(&frame.data, data_len, def) else {
                i += 1;
                continue;
            };

            // Defense-in-depth: skip non-finite values even though
            // extract_signal already filters them.
            if !value.is_finite() {
                i += 1;
                continue;
            }

            // Feed to EWMA detector.
            if let Some(score) = self.detectors[i].update(value) {
                if score.is_anomalous && (result.anomaly_count as usize) < MAX_ANOMALIES_PER_FRAME {
                    let idx = result.anomaly_count as usize;
                    result.anomalies[idx] = SignalAnomaly {
                        signal_index: self.slot_map[i],
                        z_score: score.z_score,
                        physical_value: value,
                    };
                    result.anomaly_count += 1;
                }
            }

            i += 1;
        }

        result
    }

    /// Process a raw frame identified by an arbitrary ID and data buffer.
    ///
    /// Unlike [`Self::process_frame`], this method does not require a [`CanFrame`]
    /// struct, making it suitable for LIN, `FlexRay`, or other bus types where
    /// signals are defined with the same bit-packing conventions as CAN.
    ///
    /// The `frame_id` is matched against `SignalDefinition::can_id` (which
    /// serves as a generic bus-independent message identifier despite its name).
    ///
    /// # Arguments
    /// * `frame_id` - Message identifier (CAN ID, LIN frame ID, `FlexRay` slot).
    /// * `data` - Raw payload bytes.
    /// * `data_len` - Number of valid bytes in `data`.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process_raw_frame(
        &mut self,
        frame_id: u32,
        data: &[u8],
        data_len: usize,
    ) -> SignalIdsResult {
        let mut result = SignalIdsResult::empty();

        if !self.has_can_id(frame_id) {
            return result;
        }

        let data_len = data_len.min(data.len());

        // Binary search for the first definition matching this frame ID.
        let Some(start) = self.binary_search_can_id(frame_id) else {
            return result;
        };

        // First pass: find and extract the multiplexor signal value (if any).
        let mut mux_value: Option<u16> = None;
        {
            let mut i = start;
            while i < self.signal_count && self.definitions[i].can_id == frame_id {
                if self.definitions[i].is_multiplexor {
                    if let Some(raw) = extract_raw_bits(data, data_len, &self.definitions[i]) {
                        mux_value = Some(raw as u16);
                    }
                    break;
                }
                i += 1;
            }
        }

        // Second pass: extract and score all applicable signals.
        let mut i = start;
        while i < self.signal_count && self.definitions[i].can_id == frame_id {
            let def = &self.definitions[i];

            // Skip multiplexed signals whose multiplexor value doesn't match.
            if let Some(mux_val) = def.multiplexor_value {
                match mux_value {
                    Some(current_mux) if current_mux == mux_val => {}
                    _ => {
                        i += 1;
                        continue;
                    }
                }
            }

            let Some(value) = extract_signal(data, data_len, def) else {
                i += 1;
                continue;
            };

            if !value.is_finite() {
                i += 1;
                continue;
            }

            if let Some(score) = self.detectors[i].update(value) {
                if score.is_anomalous && (result.anomaly_count as usize) < MAX_ANOMALIES_PER_FRAME {
                    let idx = result.anomaly_count as usize;
                    result.anomalies[idx] = SignalAnomaly {
                        signal_index: self.slot_map[i],
                        z_score: score.z_score,
                        physical_value: value,
                    };
                    result.anomaly_count += 1;
                }
            }

            i += 1;
        }

        result
    }

    /// Remove a signal definition by its slot index.
    ///
    /// Finds the signal with the given slot index in the slot map, removes it,
    /// and compacts the remaining definitions to maintain contiguous packing.
    /// Returns `Err(VsError::InvalidInput)` if the slot index is not found.
    pub fn remove_signal(&mut self, slot_index: u16) -> Result<(), VsError> {
        // Find the packed index for this slot.
        let mut packed_idx = None;
        for i in 0..self.signal_count {
            if self.slot_map[i] == slot_index {
                packed_idx = Some(i);
                break;
            }
        }
        let idx = packed_idx.ok_or(VsError::InvalidInput)?;

        // Compact by shifting later entries down.
        for i in idx..self.signal_count - 1 {
            self.definitions[i] = self.definitions[i + 1];
            self.detectors[i] = self.detectors[i + 1];
            self.slot_map[i] = self.slot_map[i + 1];
        }
        self.signal_count -= 1;

        // Clear the last slot to avoid stale data.
        self.definitions[self.signal_count] = Self::ZERO_DEF;
        self.slot_map[self.signal_count] = 0;

        self.rebuild_can_id_index();
        Ok(())
    }

    /// Returns the number of defined signals.
    pub fn signal_count(&self) -> usize {
        self.signal_count
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn make_frame(id: u32, data: &[u8]) -> CanFrame {
        let mut frame = CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc: data.len() as u8,
            data: [0u8; 64],
        };
        let len = data.len().min(64);
        frame.data[..len].copy_from_slice(&data[..len]);
        frame
    }

    fn default_engine() -> SignalIdsEngine {
        SignalIdsEngine::new(0.1, 3.0).expect("test EWMA parameters are valid")
    }

    // -----------------------------------------------------------------------
    // Signal extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_le_8bit_signal() {
        // Byte 0 = 0xAB = 171
        let data = [0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        assert!((val - 171.0).abs() < 0.01);
    }

    #[test]
    fn extract_le_16bit_signal() {
        // Bytes 0-1 = 0x0102 in LE = 0x0201 = 513
        let data = [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 16,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        // LE: byte 0 = LSB (0x01), byte 1 = MSB (0x02) => 0x0201 = 513
        assert!((val - 513.0).abs() < 0.01);
    }

    #[test]
    fn extract_be_8bit_signal() {
        // Byte 0, bit 7 = MSB. Signal starts at bit 7 (MSB of byte 0).
        let data = [0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 7, // MSB of byte 0
            bit_length: 8,
            byte_order: ByteOrder::BigEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        assert!((val - 171.0).abs() < 0.01);
    }

    #[test]
    fn extract_be_16bit_signal() {
        // BE 16-bit signal starting at bit 7 (MSB of byte 0).
        // Data: [0x01, 0x02] → BE value = 0x0102 = 258
        let data = [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 7, // MSB of byte 0
            bit_length: 16,
            byte_order: ByteOrder::BigEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        assert!((val - 258.0).abs() < 0.01);
    }

    #[test]
    fn extract_signal_spanning_byte_boundary() {
        // 12-bit LE signal starting at bit 4 (spans bytes 0 and 1).
        // Byte 0 = 0xF0: bits 4-7 = 0xF (all 1s), bits 0-3 = 0x0
        // Byte 1 = 0x0A: bits 0-3 = 0xA, bits 4-7 = 0x0
        // Signal bits [4..16): byte0 bits 4-7 = 0b1111, byte1 bits 0-7 = 0b00001010
        // LE value: 0b0000_1010_1111 = 0x0AF = 175
        let data = [0xF0, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 4,
            bit_length: 12,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        assert!((val - 175.0).abs() < 0.01, "got {val}");
    }

    #[test]
    fn scale_and_offset_applied_correctly() {
        let data = [100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 0.5,
            offset: -40.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        // 100 * 0.5 + (-40.0) = 10.0
        assert!((val - 10.0).abs() < 0.01);
    }

    #[test]
    fn signal_outside_frame_length_returns_none() {
        // Signal needs 2 bytes but frame has only 1.
        let data = [0xFF];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 16,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        assert!(extract_signal(&data, 1, &def).is_none());
    }

    // -----------------------------------------------------------------------
    // Engine tests
    // -----------------------------------------------------------------------

    #[test]
    fn define_signal_returns_slot_index() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let idx = engine.define_signal(def).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(engine.signal_count(), 1);

        let idx2 = engine
            .define_signal(SignalDefinition {
                name_hash: 2,
                ..def
            })
            .unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(engine.signal_count(), 2);
    }

    #[test]
    fn process_frame_extracts_and_scores() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).unwrap();

        // First frame: EWMA returns None (initialization)
        let frame = make_frame(0x100, &[50, 0, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert_eq!(result.anomaly_count, 0);
    }

    #[test]
    fn ewma_detects_outlier_signal_value() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x200,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).unwrap();

        // Train with stable value
        for _ in 0..100 {
            let frame = make_frame(0x200, &[50, 0, 0, 0, 0, 0, 0, 0]);
            let _ = engine.process_frame(&frame);
        }

        // Inject an outlier
        let frame = make_frame(0x200, &[255, 0, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert!(
            result.anomaly_count > 0,
            "large outlier should be detected as anomalous"
        );
        assert!(result.anomalies[0].z_score > 3.0);
    }

    #[test]
    fn multiple_signals_from_same_can_id() {
        let mut engine = default_engine();
        // Signal 1: byte 0
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 1,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();
        // Signal 2: byte 1
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 8,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 2,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();

        let frame = make_frame(0x100, &[10, 20, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        // Both signals processed (first frame returns None from EWMA)
        assert_eq!(result.anomaly_count, 0);
    }

    #[test]
    fn signals_from_different_can_ids() {
        let mut engine = default_engine();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 1,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x200,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 2,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();

        // Frame for CAN ID 0x100 should only process signal 1
        let frame = make_frame(0x100, &[50, 0, 0, 0, 0, 0, 0, 0]);
        let _ = engine.process_frame(&frame);
        // No crash, signals for 0x200 are skipped
    }

    #[test]
    fn frame_with_no_matching_signals() {
        let mut engine = default_engine();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 1,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();

        // Frame for unrelated CAN ID
        let frame = make_frame(0x999, &[50, 0, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert_eq!(result.anomaly_count, 0);
    }

    #[test]
    fn signal_definition_capacity_limit() {
        let mut engine = default_engine();
        for i in 0..MAX_SIGNALS {
            let def = SignalDefinition {
                can_id: i as u32,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: i as u32,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            };
            assert!(engine.define_signal(def).is_ok());
        }
        // One more should fail
        let def = SignalDefinition {
            can_id: 0xFFFF,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0xFFFF,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        assert_eq!(engine.define_signal(def), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn bit_length_1_boolean_signal() {
        let data = [0b0000_0100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 2, // bit 2 of byte 0
            bit_length: 1,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        assert!((val - 1.0).abs() < 0.01);

        // Bit 3 should be 0
        let def_zero = SignalDefinition {
            start_bit: 3,
            ..def
        };
        let val = extract_signal(&data, 8, &def_zero).unwrap();
        assert!((val - 0.0).abs() < 0.01);
    }

    #[test]
    fn bit_length_32_full_word() {
        // 32-bit LE signal at start_bit 0
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 32,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        // LE: 0x12345678
        assert!((val - 305_419_896.0).abs() < 1.0, "got {val}");
    }

    #[test]
    fn zero_scale_returns_offset() {
        let data = [100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 0.0,
            offset: 42.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let val = extract_signal(&data, 8, &def).unwrap();
        // 100 * 0.0 + 42.0 = 42.0
        assert!((val - 42.0).abs() < 0.01);
    }

    #[test]
    fn engine_new_initializes_empty() {
        let engine = SignalIdsEngine::new(0.2, 4.0).expect("test EWMA parameters are valid");
        assert_eq!(engine.signal_count(), 0);
    }

    #[test]
    fn anomaly_result_capped_at_max() {
        let mut engine = SignalIdsEngine::new(0.1, 0.0).expect("test EWMA parameters are valid"); // z_threshold=0 → everything is anomalous

        // Define 10 signals (more than MAX_ANOMALIES_PER_FRAME=8) on same CAN ID
        for i in 0..10u16 {
            engine
                .define_signal(SignalDefinition {
                    can_id: 0x100,
                    start_bit: i * 8,
                    bit_length: 8,
                    byte_order: ByteOrder::LittleEndian,
                    scale: 1.0,
                    offset: 0.0,
                    name_hash: i as u32,
                    signed: false,
                    is_multiplexor: false,
                    multiplexor_value: None,
                })
                .unwrap();
        }

        // First frame initializes (EWMA returns None)
        let frame = make_frame(0x100, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let _ = engine.process_frame(&frame);

        // Second frame with different values — all should be anomalous with z_threshold=0
        let frame2 = make_frame(0x100, &[10, 20, 30, 40, 50, 60, 70, 80]);
        let result = engine.process_frame(&frame2);
        // Should be capped at MAX_ANOMALIES_PER_FRAME
        assert!(
            result.anomaly_count <= MAX_ANOMALIES_PER_FRAME as u8,
            "anomaly count {} should be capped at {MAX_ANOMALIES_PER_FRAME}",
            result.anomaly_count
        );
    }

    #[test]
    fn process_frame_after_training_detects_injection() {
        let mut engine = default_engine();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x300,
                start_bit: 0,
                bit_length: 16,
                byte_order: ByteOrder::LittleEndian,
                scale: 0.1,
                offset: 0.0,
                name_hash: 1,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();

        // Train with RPM-like signal: ~3000 RPM (raw=30000, physical=3000.0)
        let rpm_bytes = 30000u16.to_le_bytes();
        for _ in 0..200 {
            let frame = make_frame(0x300, &[rpm_bytes[0], rpm_bytes[1], 0, 0, 0, 0, 0, 0]);
            let _ = engine.process_frame(&frame);
        }

        // Inject: RPM jumps to 9000 (raw=90000 > u16::MAX, use 60000 → 6000 RPM)
        let injected = 60000u16.to_le_bytes();
        let frame = make_frame(0x300, &[injected[0], injected[1], 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert!(
            result.anomaly_count > 0,
            "injected RPM value should be detected"
        );
    }

    #[test]
    fn bit_length_zero_rejected() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 0,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        assert_eq!(engine.define_signal(def), Err(VsError::BusError));
    }

    #[test]
    fn remove_signal_compacts_array() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let _slot0 = engine.define_signal(def).unwrap();
        let slot1 = engine
            .define_signal(SignalDefinition {
                name_hash: 2,
                can_id: 0x200,
                ..def
            })
            .unwrap();
        let _slot2 = engine
            .define_signal(SignalDefinition {
                name_hash: 3,
                can_id: 0x300,
                ..def
            })
            .unwrap();
        assert_eq!(engine.signal_count(), 3);

        // Remove the middle signal.
        engine.remove_signal(slot1 as u16).unwrap();
        assert_eq!(engine.signal_count(), 2);

        // Remaining signals should still work.
        let frame = make_frame(0x100, &[50, 0, 0, 0, 0, 0, 0, 0]);
        let _ = engine.process_frame(&frame);
        let frame = make_frame(0x300, &[50, 0, 0, 0, 0, 0, 0, 0]);
        let _ = engine.process_frame(&frame);
    }

    #[test]
    fn remove_signal_invalid_slot_returns_error() {
        let mut engine = default_engine();
        assert_eq!(engine.remove_signal(99), Err(VsError::InvalidInput));
    }

    #[test]
    fn remove_and_redefine_signal() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let slot = engine.define_signal(def).unwrap();
        engine.remove_signal(slot as u16).unwrap();
        assert_eq!(engine.signal_count(), 0);

        // Can add a new signal after removal.
        let new_slot = engine
            .define_signal(SignalDefinition {
                name_hash: 2,
                ..def
            })
            .unwrap();
        assert_eq!(engine.signal_count(), 1);
        // New slot should have a different index.
        assert_ne!(slot, new_slot);
    }

    // --- S5: data_len exceeds slice length ---

    #[test]
    fn extract_signal_data_len_exceeds_slice_no_panic() {
        let data = [0xFF, 0xAB];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        // data_len (10) exceeds data.len() (2) — must not panic.
        let result = extract_signal(&data, 10, &def);
        // Signal only needs 1 byte (bit 0..7), so it should succeed.
        assert!(result.is_some());
    }

    // --- Q3: NaN / Infinity guard ---

    #[test]
    fn nan_infinity_signal_values_return_none() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 32,
            byte_order: ByteOrder::LittleEndian,
            scale: f32::MAX,
            offset: f32::MAX,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        // raw * f32::MAX + f32::MAX overflows to Infinity.
        let result = extract_signal(&data, 8, &def);
        assert!(result.is_none(), "infinite result must return None");
    }

    #[test]
    fn slot_saturation_returns_error() {
        // We can't easily call define_signal 65535 times, but we can test
        // the boundary condition by manipulating next_slot directly.
        let mut engine = default_engine();
        // Define one signal to make signal_count > 0
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).expect("first define");
        // Artificially set next_slot to MAX
        engine.next_slot = u16::MAX;
        // Next define should fail
        let result = engine.define_signal(def);
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn process_raw_frame_matches_process_frame() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x200,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 42,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).expect("define");

        let data = [100u8, 0, 0, 0, 0, 0, 0, 0];
        let result = engine.process_raw_frame(0x200, &data, 8);
        // First observation is never anomalous (EWMA needs warmup)
        assert_eq!(result.anomaly_count, 0);
    }

    #[test]
    fn process_raw_frame_no_match_returns_empty() {
        let mut engine = default_engine();
        let def = SignalDefinition {
            can_id: 0x200,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 42,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).expect("define");

        let data = [100u8, 0, 0, 0, 0, 0, 0, 0];
        // Different frame ID — should not match
        let result = engine.process_raw_frame(0x300, &data, 8);
        assert_eq!(result.anomaly_count, 0);
    }

    // -----------------------------------------------------------------------
    // New tests: binary search sorted insertion, batch define, extract_signal_raw, next_slot getter
    // -----------------------------------------------------------------------

    #[test]
    fn binary_search_finds_signals_after_sorted_insertion() {
        let mut engine = default_engine();
        // Insert signals with CAN IDs in reverse order to verify sorted insertion.
        engine
            .define_signal(SignalDefinition {
                can_id: 0x300,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 3,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 1,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();
        engine
            .define_signal(SignalDefinition {
                can_id: 0x200,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 2,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();
        // Add a second signal for 0x100 to test contiguous grouping.
        engine
            .define_signal(SignalDefinition {
                can_id: 0x100,
                start_bit: 8,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 4,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            })
            .unwrap();

        assert_eq!(engine.signal_count(), 4);

        // Verify definitions are sorted by can_id.
        for i in 1..engine.signal_count {
            assert!(
                engine.definitions[i - 1].can_id <= engine.definitions[i].can_id,
                "definitions not sorted at index {}: {} > {}",
                i,
                engine.definitions[i - 1].can_id,
                engine.definitions[i].can_id,
            );
        }

        // Binary search should find the first 0x100 entry.
        let idx = engine.binary_search_can_id(0x100).unwrap();
        assert_eq!(engine.definitions[idx].can_id, 0x100);
        // The next entry should also be 0x100 (contiguous).
        assert_eq!(engine.definitions[idx + 1].can_id, 0x100);

        // Processing a frame for 0x100 should work (both signals extracted).
        let frame = make_frame(0x100, &[10, 20, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert_eq!(result.anomaly_count, 0); // first observation, no anomaly

        // Processing a frame for 0x200 should also work.
        let frame = make_frame(0x200, &[30, 0, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert_eq!(result.anomaly_count, 0);

        // A non-existent CAN ID should return None from binary search.
        assert!(engine.binary_search_can_id(0x999).is_none());
    }

    #[test]
    fn define_signals_batch_inserts_all_and_sorts() {
        let mut engine = default_engine();
        let defs = [
            SignalDefinition {
                can_id: 0x300,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 30,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            },
            SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 10,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            },
            SignalDefinition {
                can_id: 0x200,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: 20,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            },
        ];

        engine.define_signals_batch(&defs).unwrap();
        assert_eq!(engine.signal_count(), 3);

        // Verify sorted order.
        assert_eq!(engine.definitions[0].can_id, 0x100);
        assert_eq!(engine.definitions[1].can_id, 0x200);
        assert_eq!(engine.definitions[2].can_id, 0x300);

        // All CAN IDs should be findable via process_frame.
        let frame = make_frame(0x200, &[42, 0, 0, 0, 0, 0, 0, 0]);
        let result = engine.process_frame(&frame);
        assert_eq!(result.anomaly_count, 0);
    }

    #[test]
    fn define_signals_batch_rejects_overflow() {
        let mut engine = default_engine();
        // Fill up all slots first.
        let mut defs = [SignalDefinition {
            can_id: 0,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        }; MAX_SIGNALS];
        for (i, d) in defs.iter_mut().enumerate() {
            d.can_id = i as u32;
            d.name_hash = i as u32;
        }
        engine.define_signals_batch(&defs).unwrap();
        assert_eq!(engine.signal_count(), MAX_SIGNALS);

        // One more should fail.
        let extra = [SignalDefinition {
            can_id: 0xFFFF,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0xFFFF,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        }];
        assert_eq!(
            engine.define_signals_batch(&extra),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn define_signals_batch_rejects_invalid_bit_length() {
        let mut engine = default_engine();
        let defs = [SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 0, // invalid
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        }];
        assert_eq!(engine.define_signals_batch(&defs), Err(VsError::BusError));
    }

    #[test]
    fn extract_signal_raw_returns_exact_u64() {
        // 32-bit LE signal: raw value = 0x12345678 = 305419896
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 32,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        let raw = extract_signal_raw(&data, 8, &def).unwrap();
        assert_eq!(raw, 0x1234_5678);
    }

    #[test]
    fn extract_signal_raw_preserves_precision_beyond_24_bits() {
        // Two consecutive 32-bit values that would collapse to the same f32.
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 32,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };

        let val_a: u32 = 0x01_00_00_00; // 16777216
        let val_b: u32 = 0x01_00_00_01; // 16777217 — differs by 1 but f32 cannot distinguish
        let data_a = val_a.to_le_bytes();
        let data_b = val_b.to_le_bytes();

        let mut buf_a = [0u8; 8];
        let mut buf_b = [0u8; 8];
        buf_a[..4].copy_from_slice(&data_a);
        buf_b[..4].copy_from_slice(&data_b);

        let raw_a = extract_signal_raw(&buf_a, 8, &def).unwrap();
        let raw_b = extract_signal_raw(&buf_b, 8, &def).unwrap();
        // Raw u64 values are distinct.
        assert_ne!(raw_a, raw_b);
        assert_eq!(raw_a, 0x01_00_00_00);
        assert_eq!(raw_b, 0x01_00_00_01);

        // But f32 versions would be the same.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(raw_a as f32, raw_b as f32);
        }
    }

    #[test]
    fn extract_signal_raw_returns_none_for_invalid() {
        let data = [0xFF; 8];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 0, // invalid
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        assert!(extract_signal_raw(&data, 8, &def).is_none());
    }

    #[test]
    fn next_slot_getter_returns_current_value() {
        let mut engine = default_engine();
        assert_eq!(engine.next_slot(), 0);

        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 1,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).unwrap();
        assert_eq!(engine.next_slot(), 1);

        engine
            .define_signal(SignalDefinition {
                name_hash: 2,
                ..def
            })
            .unwrap();
        assert_eq!(engine.next_slot(), 2);
    }

    #[test]
    fn capacity_exhaustion_returns_resource_exhausted() {
        let mut engine = default_engine();
        // Fill all MAX_SIGNALS (64) slots.
        for i in 0..MAX_SIGNALS {
            let def = SignalDefinition {
                can_id: 0x100,
                start_bit: 0,
                bit_length: 8,
                byte_order: ByteOrder::LittleEndian,
                scale: 1.0,
                offset: 0.0,
                name_hash: i as u32,
                signed: false,
                is_multiplexor: false,
                multiplexor_value: None,
            };
            engine.define_signal(def).unwrap();
        }
        assert_eq!(engine.signal_count(), MAX_SIGNALS);

        // The 65th signal should fail with ResourceExhausted.
        let extra = SignalDefinition {
            can_id: 0x100,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 999,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        assert_eq!(engine.define_signal(extra), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn remove_signal_with_invalid_slot_returns_error() {
        let mut engine = default_engine();
        // Define one signal to get slot 0.
        let def = SignalDefinition {
            can_id: 0x200,
            start_bit: 0,
            bit_length: 8,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };
        engine.define_signal(def).unwrap();

        // Removing a slot index that was never assigned should fail.
        assert_eq!(engine.remove_signal(100), Err(VsError::InvalidInput));
    }

    #[test]
    fn extract_non_byte_aligned_le_signal() {
        // Signal: start_bit=3, bit_length=12, little-endian.
        // Frame data: [0xF8, 0x1A, 0x00, ...]
        //
        // LE extraction: bits 3..14 (inclusive of bit 3, 12 bits total).
        // Byte 0 = 0xF8 = 1111_1000 => bits 3..7 = 11111 (5 bits)
        // Byte 1 = 0x1A = 0001_1010 => bits 8..14 = 0001_101 (7 bits)
        // But we only need 12 bits total, so bits 8..14 = bits 0..6 of byte 1.
        //
        // raw value bits (LSB first from start_bit):
        //   bit3=1, bit4=1, bit5=1, bit6=1, bit7=1, bit8=0, bit9=1, bit10=0, bit11=1, bit12=1, bit13=0, bit14=0
        // Wait, let's compute manually:
        //   Byte 0 = 0xF8 = bits [0]=0,[1]=0,[2]=0,[3]=1,[4]=1,[5]=1,[6]=1,[7]=1
        //   Byte 1 = 0x1A = bits [0]=0,[1]=1,[2]=0,[3]=1,[4]=1,[5]=0,[6]=0,[7]=0
        // LE bits 3..14:
        //   result bit 0 = frame bit 3 = 1
        //   result bit 1 = frame bit 4 = 1
        //   result bit 2 = frame bit 5 = 1
        //   result bit 3 = frame bit 6 = 1
        //   result bit 4 = frame bit 7 = 1
        //   result bit 5 = frame bit 8 = byte1 bit0 = 0
        //   result bit 6 = frame bit 9 = byte1 bit1 = 1
        //   result bit 7 = frame bit 10 = byte1 bit2 = 0
        //   result bit 8 = frame bit 11 = byte1 bit3 = 1
        //   result bit 9 = frame bit 12 = byte1 bit4 = 1
        //   result bit 10 = frame bit 13 = byte1 bit5 = 0
        //   result bit 11 = frame bit 14 = byte1 bit6 = 0
        // raw = 0b_0000_0110_1010_1111 ... wait, let me reorder MSB first:
        //   bits [11..0] = 0,0,1,1,0,1,0,1,1,1,1,1
        //   = 0b_0011_0101_1111 = 0x35F = 863
        let data = [0xF8, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let def = SignalDefinition {
            can_id: 0x100,
            start_bit: 3,
            bit_length: 12,
            byte_order: ByteOrder::LittleEndian,
            scale: 1.0,
            offset: 0.0,
            name_hash: 0,
            signed: false,
            is_multiplexor: false,
            multiplexor_value: None,
        };

        let raw = extract_signal_raw(&data, 8, &def).unwrap();
        assert_eq!(
            raw, 0x35F,
            "non-byte-aligned 12-bit LE signal should be 0x35F (863)"
        );

        let physical = extract_signal(&data, 8, &def).unwrap();
        assert!((physical - 863.0).abs() < 0.01);
    }
}
