// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! CAN-bus intrusion detection monitor.
//!
//! # Public API
//!
//! Pre-1.0 (workspace version 0.7.1); API may change before 1.0. The
//! `CanMonitor` type, its `try_new` / `add_rule` / `process_frame`
//! methods, and the `CanFrame` / `CanRule` types form the in-progress
//! public surface and are governed by the workspace-root `DEPRECATION.md`
//! policy document. The `new_with_replay_key` alias was removed in an
//! earlier pre-1.0 breaking pass.

use vs_types::{AlertSeverity, SecurityAlert, VsError, SOURCE_CAN};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Test-only access shim for the private entropy helpers.
///
/// Gated behind the `testing` feature so that benches and integration tests
/// can measure the fast-path optimization (perf review item 6) without
/// expanding the public API surface in production builds.
#[cfg(feature = "testing")]
pub mod testing_internals {
    /// Compute Shannon entropy via the production routing logic
    /// (small-payload fast path for `data.len() <= 64`).
    #[must_use]
    pub fn shannon_entropy(data: &[u8]) -> f32 {
        super::CanMonitor::shannon_entropy(data)
    }

    /// Compute Shannon entropy via the small-payload helper directly.
    #[must_use]
    pub fn shannon_entropy_small(data: &[u8]) -> f32 {
        super::CanMonitor::shannon_entropy_small(data)
    }
}

/// Maximum number of rules a `CanMonitor` can hold (base tier).
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const MAX_RULES: usize = 256;

/// Maximum number of rules a `CanMonitor` can hold (`capacity-large` tier).
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const MAX_RULES: usize = 512;

/// Maximum number of rules a `CanMonitor` can hold (`capacity-xl` tier).
#[cfg(feature = "capacity-xl")]
const MAX_RULES: usize = 1024;

/// Capacity of the per-ID statistics hash map (must be a power of two) (base tier).
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const STATS_CAPACITY: usize = 1024;

/// Capacity of the per-ID statistics hash map (`capacity-large` tier).
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const STATS_CAPACITY: usize = 2048;

/// Capacity of the per-ID statistics hash map (`capacity-xl` tier).
#[cfg(feature = "capacity-xl")]
const STATS_CAPACITY: usize = 4096;

/// Default *normalized* Shannon-entropy threshold above which a frame payload
/// is flagged as potential fuzzing.
///
/// The detector compares `H / log2(n)` — a 0.0..=1.0 ratio of measured
/// entropy to the maximum entropy attainable for an `n`-byte payload — rather
/// than raw bits. A raw-bit threshold is meaningless across DLC sizes: a
/// fully random 8-byte classic frame caps at `log2(8) = 3.0` bits while a
/// random 64-byte CAN-FD frame reaches `log2(64) = 6.0` bits, so any single
/// bit threshold either misses classic-CAN fuzzing or false-positives on FD.
/// Normalizing makes the threshold uniform: `0.95` means "within 5% of the
/// maximum entropy for this payload's length", which fires for both classic
/// and FD fuzzing while leaving structured signals (far lower ratio) clear.
const ENTROPY_THRESHOLD: f32 = 0.95;

/// CAN bus error count above which we declare a bus-off condition.
const BUS_OFF_ERROR_THRESHOLD: u32 = 255;

/// Maximum number of IDs in the allowlist (base tier).
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const ALLOWLIST_CAPACITY: usize = 512;

/// Maximum number of IDs in the allowlist (`capacity-large` tier).
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const ALLOWLIST_CAPACITY: usize = 1024;

/// Maximum number of IDs in the allowlist (`capacity-xl` tier).
#[cfg(feature = "capacity-xl")]
const ALLOWLIST_CAPACITY: usize = 2048;

/// Maximum number of tracked replay counters (per-ID sequence counters) (base tier).
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const REPLAY_CAPACITY: usize = 256;

/// Maximum number of tracked replay counters (`capacity-large` tier).
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const REPLAY_CAPACITY: usize = 512;

/// Maximum number of tracked replay counters (`capacity-xl` tier).
#[cfg(feature = "capacity-xl")]
const REPLAY_CAPACITY: usize = 1024;

/// Maximum valid standard (11-bit) CAN ID.
const CAN_ID_STANDARD_MAX: u32 = 0x7FF;

/// Maximum valid extended (29-bit) CAN ID.
const CAN_ID_EXTENDED_MAX: u32 = 0x1FFF_FFFF;

/// Maximum value of the normalized entropy ratio (`H / log2(n)`).
///
/// The ratio is bounded by 1.0 (a payload with all-distinct bytes reaches
/// its per-length maximum entropy), so the configurable threshold is also
/// capped at 1.0.
const ENTROPY_MAX: f32 = 1.0;

/// Number of identical-payload repeats before a replay alert fires, and the
/// interval at which subsequent re-alerts are emitted.
const REPLAY_ALERT_INTERVAL: u8 = 3;

// ---------------------------------------------------------------------------
// CanFrame
// ---------------------------------------------------------------------------

/// A raw CAN / CAN-FD frame.
///
/// The `data` buffer is 64 bytes to accommodate CAN-FD.  For classic CAN
/// frames only the first `dlc` bytes (max 8) are meaningful.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CanFrame {
    /// Raw arbitration ID as received from the CAN peripheral.
    /// Will be masked to the 11- or 29-bit valid range by the monitor
    /// based on `is_extended`.
    pub id: u32,
    /// `true` for 29-bit extended frames, `false` for 11-bit standard.
    pub is_extended: bool,
    /// `true` for CAN-FD frames (variable-length payload up to 64 bytes).
    pub is_fd: bool,
    /// Data length code as transmitted on the wire. For classic CAN the
    /// payload length is `min(dlc, 8)`; for CAN-FD the ISO 11898-1
    /// mapping in [`CanFrame::payload_len`] applies.
    pub dlc: u8,
    /// Payload bytes. Only the first [`CanFrame::payload_len`] bytes are
    /// meaningful; trailing bytes are zero-padded.
    pub data: [u8; 64],
}

/// CAN-FD DLC-to-length mapping per ISO 11898-1.
/// DLC values 0..8 map 1:1; 9→12, 10→16, 11→20, 12→24, 13→32, 14→48, 15→64.
const CAN_FD_DLC_TO_LEN: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

impl CanFrame {
    /// Number of payload bytes that are valid for this frame.
    ///
    /// For classic CAN the length is `min(dlc, 8)`. For CAN-FD the non-linear
    /// ISO 11898-1 mapping is applied (DLC 9→12, 10→16, …, 15→64).
    #[inline]
    pub fn payload_len(&self) -> usize {
        if self.is_fd {
            let idx = (self.dlc as usize).min(15);
            CAN_FD_DLC_TO_LEN[idx]
        } else {
            (self.dlc as usize).min(8)
        }
    }

    /// Returns the frame ID masked to the valid range for its type
    /// (11-bit for standard, 29-bit for extended).
    #[inline]
    fn effective_id(&self) -> u32 {
        if self.is_extended {
            self.id & CAN_ID_EXTENDED_MAX
        } else {
            self.id & CAN_ID_STANDARD_MAX
        }
    }
}

// ---------------------------------------------------------------------------
// CanRule
// ---------------------------------------------------------------------------

/// A single CAN-bus monitoring rule.
///
/// A frame matches this rule when `(frame.id & id_mask) == id_filter` **and**
/// `frame.is_extended == is_extended`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CanRule {
    /// Identifier used to look up / remove this rule via
    /// [`CanMonitor::remove_rule`]. Not used for frame matching — that is
    /// driven by [`CanRule::id_filter`] / [`CanRule::id_mask`].
    pub id: u32,
    /// Bitmask applied to the incoming frame ID before comparison with
    /// [`CanRule::id_filter`].
    pub id_mask: u32,
    /// Expected value of `frame.id & id_mask`. A frame matches when this
    /// equality holds and `is_extended` agrees.
    pub id_filter: u32,
    /// Minimum allowed inter-frame interval (in microseconds) for this
    /// rule's matching ID. Frames arriving faster than this raise a flood
    /// alert.
    pub min_interval_us: u64,
    /// Maximum allowed payload length in bytes. Frames exceeding this
    /// raise a DLC-anomaly alert.
    pub max_dlc: u8,
    /// `true` if this rule applies only to 29-bit extended frames,
    /// `false` for 11-bit standard frames. Must match the incoming
    /// frame's [`CanFrame::is_extended`] flag for the rule to fire.
    pub is_extended: bool,
    /// Severity of alerts raised by this rule.
    pub severity: AlertSeverity,
}

impl CanRule {
    /// Returns `true` if the frame matches this rule's bitmask filter and
    /// extended-ID flag.
    #[inline]
    fn matches(&self, frame: &CanFrame) -> bool {
        self.is_extended == frame.is_extended
            && (frame.effective_id() & self.id_mask) == self.id_filter
    }
}

// ---------------------------------------------------------------------------
// Per-ID statistics (fixed hash map with linear probing)
// ---------------------------------------------------------------------------

/// Tracks per-CAN-ID timing/counting statistics.
#[derive(Clone, Copy, Debug)]
struct IdStats {
    last_timestamp_us: u64,
    message_count: u64,
    id: u32,
    occupied: bool,
}

impl IdStats {
    const EMPTY: Self = Self {
        last_timestamp_us: 0,
        message_count: 0,
        id: 0,
        occupied: false,
    };
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Number of bytes needed to cover all standard (11-bit) CAN IDs as a bitset.
/// 2048 IDs / 8 bits = 256 bytes.
const STD_BITSET_BYTES: usize = (CAN_ID_STANDARD_MAX as usize + 1).div_ceil(8);

/// Fixed-capacity set of allowed CAN arbitration IDs.
///
/// IDs are maintained in sorted order to allow O(log n) duplicate checks
/// during insertion. For standard (11-bit) IDs, a 256-byte bitset provides
/// O(1) lookup in [`is_allowed`](Self::is_allowed). Extended IDs fall back
/// to the constant-time full scan.
struct Allowlist {
    ids: [u32; ALLOWLIST_CAPACITY],
    count: usize,
    enabled: bool,
    /// Bitset covering standard CAN IDs (0..=0x7FF) for O(1) lookup.
    std_bitset: [u8; STD_BITSET_BYTES],
    /// `true` if any extended (29-bit) IDs are in the allowlist, which
    /// forces the full constant-time scan for extended frames.
    has_extended: bool,
}

impl Allowlist {
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self {
        Self {
            ids: [0u32; ALLOWLIST_CAPACITY],
            count: 0,
            enabled: false,
            std_bitset: [0u8; STD_BITSET_BYTES],
            has_extended: false,
        }
    }

    /// Binary search for `id` in the sorted portion of the array.
    /// Returns `Ok(index)` if found, `Err(insert_pos)` if not.
    fn binary_search(&self, id: u32) -> Result<usize, usize> {
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.ids[mid] < id {
                lo = mid + 1;
            } else if self.ids[mid] > id {
                hi = mid;
            } else {
                return Ok(mid);
            }
        }
        Err(lo)
    }

    /// Add an ID to the allowlist in sorted order.  Returns `Err` if full.
    fn add(&mut self, id: u32) -> Result<(), VsError> {
        // O(log n) duplicate + insertion point check.
        match self.binary_search(id) {
            Ok(_) => return Ok(()), // Already present.
            Err(insert_pos) => {
                if self.count >= ALLOWLIST_CAPACITY {
                    return Err(VsError::ResourceExhausted);
                }
                // Shift elements right to maintain sorted order.
                let mut j = self.count;
                while j > insert_pos {
                    self.ids[j] = self.ids[j - 1];
                    j -= 1;
                }
                self.ids[insert_pos] = id;
                self.count += 1;
                if !self.enabled {
                    self.enabled = true;
                }
                // Maintain bitset for O(1) standard-ID lookups.
                if id <= CAN_ID_STANDARD_MAX {
                    let idx = id as usize;
                    self.std_bitset[idx / 8] |= 1 << (idx % 8);
                } else {
                    self.has_extended = true;
                }
                Ok(())
            }
        }
    }

    /// Remove an ID from the allowlist. Returns `true` if it was present.
    fn remove(&mut self, id: u32) -> bool {
        if self.count == 0 {
            return false;
        }
        match self.binary_search(id) {
            Ok(pos) => {
                // Shift left to compact.
                let mut j = pos;
                while j < self.count - 1 {
                    self.ids[j] = self.ids[j + 1];
                    j += 1;
                }
                self.ids[self.count - 1] = 0;
                self.count -= 1;
                if self.count == 0 {
                    self.enabled = false;
                }
                // Clear bitset bit for standard IDs.
                if id <= CAN_ID_STANDARD_MAX {
                    let idx = id as usize;
                    self.std_bitset[idx / 8] &= !(1 << (idx % 8));
                } else {
                    // We just removed an extended ID; re-derive `has_extended`
                    // so the fast-path bitset lookup can resume once the last
                    // extended ID is gone (otherwise it stays permanently on
                    // the constant-time slow path).
                    self.has_extended = self.ids[..self.count]
                        .iter()
                        .any(|entry| *entry > CAN_ID_STANDARD_MAX);
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Returns `true` if the ID is in the allowlist or if the allowlist is
    /// disabled (empty).
    ///
    /// For standard (11-bit) CAN IDs when no extended IDs are present, a
    /// 256-byte bitset provides O(1) lookup.  Otherwise falls back to a
    /// constant-time full scan via [`subtle::ConstantTimeEq`] to prevent
    /// timing side-channels that could reveal which CAN IDs are allowed.
    #[inline]
    fn is_allowed(&self, id: u32) -> bool {
        use subtle::ConstantTimeEq;
        if !self.enabled {
            return true;
        }
        // Fast path: standard-only allowlist — O(1) bitset lookup.
        // NOTE: This early return introduces a timing difference between
        // standard-only and mixed (standard + extended) allowlists.  This is
        // an intentional optimisation: the frame format (standard 11-bit vs
        // extended 29-bit) is already visible on the physical CAN bus, so the
        // timing difference does not leak information an attacker could not
        // already observe.
        if !self.has_extended && id <= CAN_ID_STANDARD_MAX {
            let idx = id as usize;
            return (self.std_bitset[idx / 8] >> (idx % 8)) & 1 != 0;
        }
        // Slow path: constant-time scan for extended IDs or mixed lists.
        let id_bytes = id.to_le_bytes();
        let mut found: u8 = 0;
        // Scan the full capacity (not just `self.count`) so iteration count
        // is constant regardless of how many entries are populated, preventing
        // timing side-channels that could leak the allowlist size.
        for i in 0..ALLOWLIST_CAPACITY {
            let entry_bytes = self.ids[i].to_le_bytes();
            let in_range = u8::from(i < self.count);
            found |= entry_bytes.ct_eq(&id_bytes).unwrap_u8() & in_range;
        }
        found != 0
    }
}

// ---------------------------------------------------------------------------
// Replay tracker
// ---------------------------------------------------------------------------

/// Per-ID replay detection using a payload-hash monotonicity check.
///
/// Tracks the last payload hash per-ID.  If an identical payload hash is seen
/// `REPLAY_ALERT_INTERVAL` times consecutively from the same ID, a replay
/// alert fires.  Subsequent re-alerts fire every `REPLAY_ALERT_INTERVAL`
/// additional repeats so that sustained replay attacks remain visible.
///
/// When the table is full, the oldest entry is evicted so that replay
/// detection is never silently disabled.
struct ReplayTracker {
    entries: [ReplayEntry; REPLAY_CAPACITY],
    count: usize,
    insert_seq: u32,
    siphash_key: [u64; 2],
    eviction_count: u32,
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    last_hash: u64,
    id: u32,
    repeat_count: u16,
    insert_order: u32,
    occupied: bool,
}

impl ReplayEntry {
    const EMPTY: Self = Self {
        last_hash: 0,
        id: 0,
        repeat_count: 0,
        insert_order: 0,
        occupied: false,
    };
}

impl ReplayTracker {
    /// Create a replay tracker with a caller-supplied SipHash key.
    ///
    /// Use this in production to supply a randomized key from
    /// `CryptoProvider::random_bytes`, preventing attackers from
    /// crafting hash-colliding payloads that bypass replay detection.
    #[allow(clippy::large_stack_arrays)]
    const fn with_key(key: [u64; 2]) -> Self {
        Self {
            entries: [ReplayEntry::EMPTY; REPLAY_CAPACITY],
            count: 0,
            insert_seq: 0,
            siphash_key: key,
            eviction_count: 0,
        }
    }

    /// Check a frame for replay.  Returns `true` if replay is detected.
    fn check(&mut self, id: u32, payload: &[u8]) -> bool {
        let hash = vs_types::siphash_2_4(payload, self.siphash_key[0], self.siphash_key[1]);

        // Hash-based O(1) lookup for this CAN ID.
        let start = self.id_hash(id);
        for probe in 0..REPLAY_CAPACITY {
            let idx = (start + probe) & (REPLAY_CAPACITY - 1);
            if self.entries[idx].occupied && self.entries[idx].id == id {
                if self.entries[idx].last_hash == hash {
                    self.entries[idx].repeat_count =
                        self.entries[idx].repeat_count.saturating_add(1);
                    let interval = REPLAY_ALERT_INTERVAL as u16;
                    return self.entries[idx].repeat_count >= interval
                        && self.entries[idx].repeat_count % interval == 0;
                }
                self.entries[idx].last_hash = hash;
                self.entries[idx].repeat_count = 1;
                return false;
            }
            if !self.entries[idx].occupied {
                // Not found — insert new entry here.
                self.insert_seq = self.insert_seq.wrapping_add(1);
                self.entries[idx] = ReplayEntry {
                    last_hash: hash,
                    id,
                    repeat_count: 1,
                    insert_order: self.insert_seq,
                    occupied: true,
                };
                self.count += 1;
                return false;
            }
        }

        // Table full — evict oldest entry in probe chain and insert.
        self.insert_seq = self.insert_seq.wrapping_add(1);
        self.eviction_count = self.eviction_count.saturating_add(1);
        let victim_idx = self.find_oldest_in_probe(start);
        self.entries[victim_idx] = ReplayEntry {
            last_hash: hash,
            id,
            repeat_count: 1,
            insert_order: self.insert_seq,
            occupied: true,
        };
        false
    }

    /// Hash a CAN ID to an initial slot index using keyed SipHash-2-4.
    ///
    /// The key is the same TRNG-seeded SipHash key used for payload hashing,
    /// so an attacker without access to the key cannot pre-compute CAN IDs
    /// that all collide into the same probe chain (hash-flooding /
    /// replay-table evasion via crafted IDs).
    #[inline]
    fn id_hash(&self, id: u32) -> usize {
        let h = vs_types::siphash_2_4(&id.to_le_bytes(), self.siphash_key[0], self.siphash_key[1]);
        (h as usize) & (REPLAY_CAPACITY - 1)
    }

    /// Find the oldest entry within a limited probe window from `start`.
    fn find_oldest_in_probe(&self, start: usize) -> usize {
        let mut oldest_idx = start & (REPLAY_CAPACITY - 1);
        let mut oldest_order = u32::MAX;
        // Scan a limited window (32 slots) for CLOCK-style approximation.
        // Widened from 8 to 32 to reduce eviction bias against entries that
        // share a long collision chain under adversarial ID flooding.
        let window = 32.min(REPLAY_CAPACITY);
        for i in 0..window {
            let idx = (start + i) & (REPLAY_CAPACITY - 1);
            if self.entries[idx].occupied
                && (self.entries[idx].insert_order < oldest_order
                    || (self.entries[idx].insert_order == oldest_order && idx < oldest_idx))
            {
                oldest_order = self.entries[idx].insert_order;
                oldest_idx = idx;
            }
        }
        oldest_idx
    }

    /// Returns the number of evictions since last reset.
    pub fn eviction_count(&self) -> u32 {
        self.eviction_count
    }

    /// Reset the eviction counter.
    pub fn reset_eviction_count(&mut self) {
        self.eviction_count = 0;
    }
}

/// Fixed-capacity hash map keyed on CAN ID, using linear probing.
struct StatsMap {
    slots: [IdStats; STATS_CAPACITY],
    /// SipHash key for keyed CAN-ID hashing (prevents collision-flood attacks).
    siphash_key: [u64; 2],
    /// Number of LFU evictions performed. Saturates at `u64::MAX`.
    /// A rising counter indicates adversarial flooding with many distinct
    /// CAN IDs, evicting legitimate-traffic entries.
    stats_evictions: u64,
    /// Number of currently occupied slots, maintained incrementally on
    /// insert / clear so that capacity queries do not have to scan the
    /// whole slot array (O(1) instead of O(`STATS_CAPACITY`)).
    stats_active: u32,
}

impl StatsMap {
    #[allow(clippy::large_stack_arrays)]
    const fn with_key(siphash_key: [u64; 2]) -> Self {
        Self {
            slots: [IdStats::EMPTY; STATS_CAPACITY],
            siphash_key,
            stats_evictions: 0,
            stats_active: 0,
        }
    }

    /// Test-only constructor that uses a deterministic zero key.
    ///
    /// Production code must call [`StatsMap::with_key`] with a key sourced from
    /// `CryptoProvider::random_bytes`.  An all-zero key produces predictable
    /// SipHash output and would let an attacker craft colliding CAN IDs.
    #[cfg(test)]
    #[allow(clippy::large_stack_arrays)]
    fn for_test() -> Self {
        Self::with_key([0u64; 2])
    }

    /// Total number of evictions performed since construction (or last reset).
    pub fn stats_evictions(&self) -> u64 {
        self.stats_evictions
    }

    /// Reset the eviction counter to zero.
    pub fn reset_stats_evictions(&mut self) {
        self.stats_evictions = 0;
    }

    /// Hash a CAN ID to an initial slot index.
    #[inline]
    fn hash(&self, id: u32) -> usize {
        let h = vs_types::siphash_2_4(&id.to_le_bytes(), self.siphash_key[0], self.siphash_key[1]);
        (h as usize) & (STATS_CAPACITY - 1)
    }

    /// Look up or insert a stats entry for `id`.
    ///
    /// If the table is full, evicts the entry with the lowest
    /// `message_count` in the probe chain (LFU-style eviction) to prevent
    /// a permanent denial-of-service when an attacker floods with many
    /// distinct CAN IDs.
    fn get_or_insert(&mut self, id: u32) -> Option<&mut IdStats> {
        let start = self.hash(id);
        // First pass: find existing entry or free slot.
        let mut target_idx = None;
        for i in 0..STATS_CAPACITY {
            let idx = (start + i) & (STATS_CAPACITY - 1);
            if self.slots[idx].occupied && self.slots[idx].id == id {
                target_idx = Some(idx);
                break;
            }
            if !self.slots[idx].occupied {
                self.slots[idx].occupied = true;
                self.slots[idx].id = id;
                // Newly occupied slot — keep the O(1) live counter in sync
                // with the array so `stats_capacity()` does not have to scan.
                self.stats_active = self.stats_active.saturating_add(1);
                target_idx = Some(idx);
                break;
            }
        }

        // Table full — evict the least-used entry in a limited probe window
        // (CLOCK-style approximation) to avoid O(n) full-table scan.
        // Window widened from 8 to 32 to reduce LFU bias under adversarial
        // ID flooding that exhausts long collision chains.
        if target_idx.is_none() {
            let window = 32;
            let mut victim_idx = start & (STATS_CAPACITY - 1);
            let mut min_count = self.slots[victim_idx].message_count;
            for i in 1..window {
                let idx = (start + i) & (STATS_CAPACITY - 1);
                if self.slots[idx].message_count < min_count {
                    min_count = self.slots[idx].message_count;
                    victim_idx = idx;
                }
            }
            self.slots[victim_idx] = IdStats {
                last_timestamp_us: 0,
                message_count: 0,
                id,
                occupied: true,
            };
            self.stats_evictions = self.stats_evictions.saturating_add(1);
            target_idx = Some(victim_idx);
        }

        target_idx.map(|idx| &mut self.slots[idx])
    }

    fn clear(&mut self) {
        for entry in &mut self.slots {
            *entry = IdStats::EMPTY;
        }
        self.stats_evictions = 0;
        self.stats_active = 0;
    }

    /// Number of currently occupied slots (O(1)).
    #[inline]
    fn active_count(&self) -> usize {
        self.stats_active as usize
    }
}

// ---------------------------------------------------------------------------
// Payload hash helper
// ---------------------------------------------------------------------------

/// Default SipHash keys for CAN payload forensic hashing.
/// Each lane uses a different key pair for independent 64-bit outputs.
const PAYLOAD_HASH_KEYS: [(u64, u64); 4] = [
    (0xcbf2_9ce4_8422_2325, 0xd228_cb69_6f1a_8caf),
    (0x8b1a_7cef_0312_5647, 0x63c4_cb16_83c3_44e5),
    (0xa171_de3a_024f_1b27, 0xb492_5f78_1de0_8c9c),
    (0x9ae1_6a3b_2f90_404f, 0xe74b_5d10_3a89_c26d),
];

/// Compute a SipHash-based fingerprint of CAN payload data for forensic
/// correlation. Uses 4 independent SipHash-2-4 lanes with different keys,
/// producing a full 256-bit output with genuine independence between lanes.
///
/// `len` is clamped to `data.len()`: if a caller passes a `len` larger than
/// the supplied slice, only the available bytes are hashed rather than
/// panicking. This keeps the function total — under the workspace
/// `panic = "abort"` profile an out-of-bounds slice would otherwise abort
/// the whole process on an automotive gateway.
///
/// Exposed publicly so that the automotive runtime can thread the same
/// digest through to its own alert builders, avoiding a duplicate SHA-256
/// computation on the CAN frame hot path (see `vs-runtime-auto::hash_or_degrade`).
#[must_use]
pub fn compute_can_payload_hash(data: &[u8], len: usize) -> vs_types::PayloadHash {
    let len = len.min(data.len());
    vs_types::siphash_payload_hash(&data[..len], &PAYLOAD_HASH_KEYS)
}

// ---------------------------------------------------------------------------
// CanMonitor
// ---------------------------------------------------------------------------

/// Stateful CAN bus monitor that applies a fixed set of [`CanRule`]s to
/// incoming [`CanFrame`]s, emitting [`SecurityAlert`]s on anomalies.
pub struct CanMonitor {
    rules: [Option<CanRule>; MAX_RULES],
    rule_count: usize,
    stats: StatsMap,
    error_count: u32,
    alert_counter: u64,
    entropy_threshold: f32,
    allowlist: Allowlist,
    replay_tracker: ReplayTracker,
    /// Whether we have already emitted a bus-off alert for the current error
    /// run.  Reset when `reset_error_count` is called.
    bus_off_alerted: bool,
}

#[cfg(any(test, feature = "testing"))]
impl Default for CanMonitor {
    /// Create a monitor with a deterministic key — **for testing only**.
    ///
    /// Production code must use [`CanMonitor::try_new`] with a random key.
    #[allow(deprecated)]
    fn default() -> Self {
        Self::new([
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ])
    }
}

impl CanMonitor {
    /// Create a new monitor with no rules loaded.
    ///
    /// Requires a random SipHash key for replay detection to prevent
    /// attackers from crafting hash-colliding payloads. Obtain the key
    /// from `CryptoProvider::random_bytes`.
    ///
    /// # Panics
    ///
    /// Panics if `replay_key` is all zeros. A zero key produces trivially
    /// predictable SipHash output and would silently disable replay
    /// detection's collision resistance, so it is rejected at construction.
    /// Use [`CanMonitor::try_new`] for fallible construction that returns
    /// a [`VsError`] instead of panicking — this is the canonical path
    /// for any code that ingests an untrusted configuration source.
    #[allow(clippy::large_stack_arrays)]
    #[deprecated(since = "0.7.0", note = "use try_new")]
    pub fn new(replay_key: [u8; 16]) -> Self {
        assert!(
            !replay_key.iter().all(|&b| b == 0),
            "replay_key must not be all-zero"
        );
        let k0 = u64::from_le_bytes([
            replay_key[0],
            replay_key[1],
            replay_key[2],
            replay_key[3],
            replay_key[4],
            replay_key[5],
            replay_key[6],
            replay_key[7],
        ]);
        let k1 = u64::from_le_bytes([
            replay_key[8],
            replay_key[9],
            replay_key[10],
            replay_key[11],
            replay_key[12],
            replay_key[13],
            replay_key[14],
            replay_key[15],
        ]);
        Self {
            rules: [None; MAX_RULES],
            rule_count: 0,
            stats: StatsMap::with_key([k0, k1]),
            error_count: 0,
            alert_counter: 0,
            entropy_threshold: ENTROPY_THRESHOLD,
            allowlist: Allowlist::new(),
            replay_tracker: ReplayTracker::with_key([k0, k1]),
            bus_off_alerted: false,
        }
    }

    /// Fallible variant of [`new`](Self::new) that rejects all-zero keys.
    ///
    /// Returns [`VsError::InvalidInput`] if `replay_key` is all zeros
    /// instead of panicking. Use this in production paths where construction
    /// failure must be handled gracefully — this is the canonical
    /// constructor; the panicking [`new`](Self::new) is retained only for
    /// backward compatibility.
    ///
    /// # Examples
    ///
    /// ```
    /// use vs_can_monitor::CanMonitor;
    ///
    /// // All-zero keys are rejected — a zero key produces predictable
    /// // SipHash output and would silently disable replay-collision
    /// // resistance.
    /// let bad: [u8; 16] = [0; 16];
    /// assert!(CanMonitor::try_new(bad).is_err());
    ///
    /// // In production, source from `CryptoProvider::random_bytes`.
    /// let replay_key: [u8; 16] = [0xAB; 16];
    /// let _monitor = CanMonitor::try_new(replay_key).expect("non-zero key");
    /// ```
    #[allow(clippy::large_stack_arrays)]
    #[allow(deprecated)]
    pub fn try_new(replay_key: [u8; 16]) -> Result<Self, VsError> {
        if replay_key.iter().all(|&b| b == 0) {
            return Err(VsError::InvalidInput);
        }
        Ok(Self::new(replay_key))
    }

    // `new_with_replay_key` was removed earlier in the pre-1.0 series;
    // use `CanMonitor::try_new(replay_key)` directly.

    /// Override the default entropy threshold used for fuzzing detection.
    ///
    /// The threshold is a *normalized* entropy ratio and must be in the
    /// range `0.0..=1.0`. The detector flags a frame when `H / log2(n)`
    /// (measured Shannon entropy over the maximum attainable for an
    /// `n`-byte payload) exceeds the threshold. `1.0` disables the detector
    /// in practice (only an all-distinct payload reaches the maximum).
    ///
    /// Returns `Err(VsError::InvalidInput)` for out-of-range, `NaN`, or
    /// infinite values.
    pub fn set_entropy_threshold(&mut self, threshold: f32) -> Result<(), VsError> {
        if threshold.is_nan()
            || threshold.is_infinite()
            || threshold < 0.0
            || threshold > ENTROPY_MAX
        {
            return Err(VsError::InvalidInput);
        }
        self.entropy_threshold = threshold;
        Ok(())
    }

    /// Add an ID to the allowlist.  Once any ID is added, all frames with
    /// IDs not in the allowlist will generate a `High` severity alert.
    ///
    /// Returns `Err(VsError::ResourceExhausted)` if the allowlist is full.
    pub fn allow_id(&mut self, id: u32) -> Result<(), VsError> {
        self.allowlist.add(id)
    }

    /// Returns `true` if the allowlist is enabled (at least one ID added).
    pub fn allowlist_enabled(&self) -> bool {
        self.allowlist.enabled
    }

    /// Add a rule.  Returns `Err(VsError::ResourceExhausted)` if the rule
    /// table is full.
    pub fn add_rule(&mut self, rule: CanRule) -> Result<(), VsError> {
        if self.rule_count >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }
        self.rules[self.rule_count] = Some(rule);
        self.rule_count += 1;
        Ok(())
    }

    /// Remove a rule by its `id` field.  Returns `Err(VsError::NotFound)` if
    /// no rule with that id exists.
    pub fn remove_rule(&mut self, id: u32) -> Result<(), VsError> {
        let mut found = None;
        for i in 0..self.rule_count {
            if let Some(ref rule) = self.rules[i] {
                if rule.id == id {
                    found = Some(i);
                    break;
                }
            }
        }
        let idx = found.ok_or(VsError::NotFound)?;
        for i in idx..self.rule_count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[self.rule_count - 1] = None;
        self.rule_count -= 1;
        Ok(())
    }

    /// Remove an ID from the allowlist.  Returns `true` if it was present.
    pub fn remove_from_allowlist(&mut self, id: u32) -> bool {
        self.allowlist.remove(id)
    }

    /// Reset all per-ID statistics, clearing the stats map.
    pub fn reset_stats(&mut self) {
        self.stats.clear();
    }

    /// Report a CAN bus error (e.g. from the peripheral interrupt handler).
    /// When the internal error counter reaches the bus-off threshold a
    /// single `Critical` alert is returned.  Subsequent calls do not produce
    /// additional alerts until the counter is reset with `reset_error_count`.
    pub fn report_error(&mut self, timestamp_us: u64) -> Option<SecurityAlert> {
        self.error_count = self.error_count.saturating_add(1);
        if self.error_count >= BUS_OFF_ERROR_THRESHOLD && !self.bus_off_alerted {
            self.bus_off_alerted = true;
            return Some(self.make_alert(AlertSeverity::Critical, 0, timestamp_us));
        }
        None
    }

    /// Reset the bus error counter (e.g. after recovery).
    pub fn reset_error_count(&mut self) {
        self.error_count = 0;
        self.bus_off_alerted = false;
    }

    /// Returns `(current_rules, max_rules)` for capacity monitoring.
    pub fn rule_capacity(&self) -> (usize, usize) {
        (self.rule_count, MAX_RULES)
    }

    /// Returns `(current_entries, max_entries)` for stats map capacity.
    ///
    /// Uses an incrementally-maintained live counter, so this is O(1) and
    /// safe to call on the hot path (e.g. for telemetry export every frame)
    /// without scanning the 1 KiB slot table.
    pub fn stats_capacity(&self) -> (usize, usize) {
        (self.stats.active_count(), STATS_CAPACITY)
    }

    /// Number of replay-tracker evictions since the monitor was created.
    ///
    /// A high eviction count may indicate an attacker flooding many distinct
    /// CAN IDs to exhaust the replay tracker, degrading replay detection.
    pub fn replay_eviction_count(&self) -> u32 {
        self.replay_tracker.eviction_count()
    }

    /// Reset the replay-tracker eviction counter.
    pub fn reset_replay_eviction_count(&mut self) {
        self.replay_tracker.reset_eviction_count();
    }

    /// Number of stats-map evictions since the monitor was created.
    ///
    /// A high eviction count may indicate an attacker flooding many distinct
    /// CAN IDs to exhaust the per-ID stats map, degrading flood detection.
    pub fn stats_evictions(&self) -> u64 {
        self.stats.stats_evictions()
    }

    /// Reset the stats-map eviction counter.
    pub fn reset_stats_evictions(&mut self) {
        self.stats.reset_stats_evictions();
    }

    /// Process an incoming CAN frame and return an alert if any anomaly is
    /// detected.
    ///
    /// Detection order (first match wins):
    /// 1. **Allowlist** – frame ID not in the permitted set
    /// 2. **Flooding** – same ID arriving faster than `rule.min_interval_us`
    /// 3. **DLC anomaly** – `frame.dlc > rule.max_dlc`
    /// 4. **Fuzzing** – payload Shannon entropy above threshold
    /// 5. **Replay** – identical payload repeated 3+ times from the same ID
    pub fn process_frame(&mut self, frame: &CanFrame, timestamp_us: u64) -> Option<SecurityAlert> {
        let eid = frame.effective_id();

        let plen = frame.payload_len();

        // 1) Allowlist check (runs before any other detector).
        if !self.allowlist.is_allowed(eid) {
            return Some(self.make_alert_with_payload(
                AlertSeverity::High,
                eid,
                timestamp_us,
                &frame.data,
                plen,
            ));
        }

        // Update per-ID stats.
        let interval_since_last = if let Some(stats) = self.stats.get_or_insert(eid) {
            let delta = timestamp_us.saturating_sub(stats.last_timestamp_us);
            let is_first = stats.message_count == 0;
            stats.last_timestamp_us = timestamp_us;
            stats.message_count = stats.message_count.saturating_add(1);
            if is_first {
                None
            } else {
                Some(delta)
            }
        } else {
            None
        };

        // Entropy is a function of the payload alone — hoist it out of the
        // rule loop so it is computed at most once per frame, not once per
        // matching rule.  Same for the payload length, which feeds both the
        // DLC-anomaly comparison and the entropy slice.
        //
        // The fuzzing detector compares a *normalized* ratio (H / log2(n))
        // so that the threshold is uniform across DLC sizes; see
        // `shannon_entropy_ratio`.
        let entropy_ratio = Self::shannon_entropy_ratio(&frame.data[..plen]);
        let plen_u8 = plen as u8;

        // Evaluate every active rule (flood, DLC, entropy).
        // If any fires, we reset replay state for this ID before returning.
        let mut rule_alert: Option<SecurityAlert> = None;
        for i in 0..self.rule_count {
            let Some(rule) = self.rules[i] else { continue };

            if !rule.matches(frame) {
                continue;
            }

            // 2) Flood detection
            if let Some(delta) = interval_since_last {
                if delta < rule.min_interval_us {
                    rule_alert = Some(self.make_alert_with_payload(
                        rule.severity,
                        eid,
                        timestamp_us,
                        &frame.data,
                        plen,
                    ));
                    break;
                }
            }

            // 3) DLC anomaly — compare the clamped payload length (not the
            //    raw `dlc` field) against the rule limit so that physically
            //    impossible DLC values do not cause false positives.
            if plen_u8 > rule.max_dlc {
                rule_alert = Some(self.make_alert_with_payload(
                    rule.severity,
                    eid,
                    timestamp_us,
                    &frame.data,
                    plen,
                ));
                break;
            }

            // 4) Fuzzing (entropy) — normalized ratio precomputed above.
            if entropy_ratio > self.entropy_threshold {
                rule_alert = Some(self.make_alert_with_payload(
                    rule.severity,
                    eid,
                    timestamp_us,
                    &frame.data,
                    plen,
                ));
                break;
            }
        }

        // If another detector fired, return that alert but leave replay
        // state untouched. Resetting the replay counter here would let an
        // attacker suppress the sustained-replay detector entirely by
        // interleaving a single flood/DLC/entropy-anomalous frame between
        // replayed frames — a distinct detector must never be defeatable
        // by deliberately tripping another one. Replay state is therefore
        // kept independent of the other detectors.
        if let Some(alert) = rule_alert {
            return Some(alert);
        }

        // 5) Replay detection — only checked for frames that pass all other
        //    detectors.
        let payload_slice = &frame.data[..plen];
        if self.replay_tracker.check(eid, payload_slice) {
            return Some(self.make_alert_with_payload(
                AlertSeverity::Medium,
                eid,
                timestamp_us,
                &frame.data,
                plen,
            ));
        }

        None
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a `SecurityAlert` with a monotonically increasing local id.
    /// The counter saturates at `u64::MAX` rather than wrapping, so alert
    /// IDs are always unique.
    fn make_alert(
        &mut self,
        severity: AlertSeverity,
        source_id: u32,
        timestamp_us: u64,
    ) -> SecurityAlert {
        self.alert_counter = self.alert_counter.saturating_add(1);
        SecurityAlert {
            id: self.alert_counter,
            severity,
            source_type: SOURCE_CAN,
            source_id,
            payload_hash: vs_types::PayloadHash([0u8; 32]),
            timestamp_us,
        }
    }

    fn make_alert_with_payload(
        &mut self,
        severity: AlertSeverity,
        source_id: u32,
        timestamp_us: u64,
        data: &[u8],
        len: usize,
    ) -> SecurityAlert {
        self.alert_counter = self.alert_counter.saturating_add(1);
        SecurityAlert {
            id: self.alert_counter,
            severity,
            source_type: SOURCE_CAN,
            source_id,
            payload_hash: compute_can_payload_hash(data, len),
            timestamp_us,
        }
    }

    /// Compute Shannon entropy (in bits) of `data` without any heap allocation.
    ///
    /// Uses the identity `H = log2(n) - (1/n) * Σ c_i·log2(c_i)` to avoid
    /// per-bucket division.  `c·log2(c)` values for c=1..64 are served from
    /// a precomputed lookup table (`C_LOG2_C_TABLE`), making the hot loop
    /// multiplication-free for CAN / CAN-FD payloads (≤64 bytes).
    ///
    /// # Fast paths
    ///
    /// * `n ≤ 64`  → reuse [`Self::shannon_entropy_small`] with `vals/freqs`
    ///   arrays sized to 64.  A CAN-FD frame has at most 64 distinct byte
    ///   values (≪ 256), so the 1 KB `[u32; 256]` frequency table is wasted
    ///   work — the compact O(n²) scan touches only 64·4 B of stack and
    ///   typically completes in a few hundred cycles.
    /// * `n  > 64` → fall back to the dense 256-bucket table (used by
    ///   non-CAN callers that supply payloads beyond CAN-FD's 64-byte cap).
    fn shannon_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        // Fast path for CAN / CAN-FD (≤ 64 bytes): use a compact O(n²)
        // distinct-value scan instead of zeroing a 1 KB frequency table on
        // every frame. Payloads of ≤ 64 bytes have at most 64 distinct byte
        // values, which is ¼ of the dense table's 256 slots.
        if data.len() <= 64 {
            return Self::shannon_entropy_small(data);
        }

        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let n = data.len();
        let mut sum_c_log2_c: f32 = 0.0;
        for &c in &counts {
            if c == 0 {
                continue;
            }
            let cu = c as usize;
            if cu < C_LOG2_C_TABLE.len() {
                sum_c_log2_c += C_LOG2_C_TABLE[cu];
            } else {
                // Fallback for payloads > 64 bytes (shouldn't happen for CAN).
                sum_c_log2_c += c as f32 * log2_approx_positive(c as f32);
            }
        }

        log2_approx_positive(n as f32) - sum_c_log2_c / n as f32
    }

    /// Shannon entropy for short payloads (≤ 64 bytes — covers classic CAN
    /// *and* CAN-FD) using an O(n²) distinct-value scan with only
    /// `64·(1 + 4) = 320 B` of stack instead of the 1 KB dense table.
    ///
    /// For `n = 64` this is at most `64·64 / 2 = 2048` byte comparisons,
    /// which is still well below the cost of zeroing 256 `u32` slots plus
    /// the indexed counter increments of the dense path.
    fn shannon_entropy_small(data: &[u8]) -> f32 {
        let n = data.len();
        if n == 0 {
            return 0.0;
        }
        // Sized to 64 so that a full CAN-FD frame stays on this fast path.
        // The lookup-table indexing in the sum loop is bounded by
        // `C_LOG2_C_TABLE.len()` (65) which already covers `c ≤ 64`.
        let mut vals = [0u8; 64];
        let mut freqs = [0u32; 64];
        let mut distinct = 0usize;
        for &b in data {
            let mut found = false;
            for j in 0..distinct {
                if vals[j] == b {
                    freqs[j] += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                // n ≤ 64, so `distinct` cannot exceed the array length.
                vals[distinct] = b;
                freqs[distinct] = 1;
                distinct += 1;
            }
        }
        let mut sum_c_log2_c: f32 = 0.0;
        for i in 0..distinct {
            let c = freqs[i] as usize;
            if c > 0 && c < C_LOG2_C_TABLE.len() {
                sum_c_log2_c += C_LOG2_C_TABLE[c];
            }
        }
        // Use the exact `log2(n)` table for the CAN/CAN-FD range (n ≤ 64)
        // instead of the IEEE-754 bit-trick approximation, which carries up
        // to ~0.09 bits of error — too coarse to feed a security threshold.
        log2_exact_small(n) - sum_c_log2_c / n as f32
    }

    /// Shannon entropy of `data` *normalized* to a 0.0..=1.0 ratio.
    ///
    /// Returns `H / log2(n)` where `H` is the raw Shannon entropy in bits
    /// and `log2(n)` is the maximum entropy attainable for an `n`-byte
    /// payload. This makes the fuzzing threshold uniform across DLC sizes:
    /// a fully random 8-byte classic frame and a fully random 64-byte
    /// CAN-FD frame both yield a ratio near 1.0, whereas a raw-bits
    /// comparison would only ever flag the latter.
    ///
    /// Payloads of length 0 or 1 carry no entropy and return `0.0` (there
    /// is no `log2(n)` to normalize against — fail-closed: never flag).
    fn shannon_entropy_ratio(data: &[u8]) -> f32 {
        let n = data.len();
        if n <= 1 {
            return 0.0;
        }
        let max_entropy = if n <= 64 {
            log2_exact_small(n)
        } else {
            log2_approx_positive(n as f32)
        };
        // `n >= 2` guarantees `max_entropy > 0`, so the division is safe.
        Self::shannon_entropy_small(data) / max_entropy
    }
}

/// Exact `log2(n)` for `n` in `0..=64`, served from a precomputed table.
///
/// Used on the CAN/CAN-FD entropy hot path so that the `log2(n)` term of
/// the Shannon-entropy formula carries no approximation error. `n == 0`
/// returns `0.0` (callers guard against empty payloads independently).
fn log2_exact_small(n: usize) -> f32 {
    debug_assert!(n <= 64, "log2_exact_small only covers n <= 64");
    LOG2_TABLE[n.min(64)]
}

/// Approximate `log2(x)` for any positive `x` using the IEEE 754 bit trick.
///
/// Good enough for entropy classification; not intended for cryptographic use.
/// Max error < 0.09 bits over the range 1..64.
fn log2_approx_positive(x: f32) -> f32 {
    let bits = x.to_bits();
    (bits as f32) * (1.0 / (1_u32 << 23) as f32) - 127.0
}

/// Precomputed `c · log2(c)` for c = 0..64.
///
/// Entry 0 is 0.0 (unused; zero-count buckets are skipped).
/// Used by [`CanMonitor::shannon_entropy`] to avoid per-bucket floating-point
/// division and logarithm calls.
#[allow(clippy::excessive_precision)]
const C_LOG2_C_TABLE: [f32; 65] = {
    // We cannot call `log2_approx_positive` in const context (no const
    // f32 → bits yet), so the table is hand-computed from exact values.
    // c * log2(c) for c in 0..=64, computed from f64 and rounded:
    [
        0.0,        //  0 (sentinel)
        0.0,        //  1
        2.0,        //  2
        4.754_89,   //  3
        8.0,        //  4
        11.609_64,  //  5
        15.509_78,  //  6
        19.651_48,  //  7
        24.0,       //  8
        28.529_33,  //  9
        33.219_28,  // 10
        38.053_75,  // 11
        43.019_55,  // 12
        48.105_72,  // 13
        53.302_97,  // 14
        58.603_36,  // 15
        64.0,       // 16
        69.486_87,  // 17
        75.058_65,  // 18
        80.710_62,  // 19
        86.438_56,  // 20
        92.238_67,  // 21
        98.107_50,  // 22
        104.041_92, // 23
        110.039_10, // 24
        116.096_40, // 25
        122.211_43, // 26
        128.381_96, // 27
        134.605_94, // 28
        140.881_45, // 29
        147.206_72, // 30
        153.580_09, // 31
        160.0,      // 32
        166.465_01, // 33
        172.973_74, // 34
        179.524_91, // 35
        186.117_30, // 36
        192.749_77, // 37
        199.421_25, // 38
        206.130_69, // 39
        212.877_12, // 40
        219.659_63, // 41
        226.477_33, // 42
        233.329_38, // 43
        240.214_99, // 44
        247.133_39, // 45
        254.083_85, // 46
        261.065_68, // 47
        268.078_20, // 48
        275.120_78, // 49
        282.192_81, // 50
        289.293_69, // 51
        296.422_87, // 52
        303.579_78, // 53
        310.763_93, // 54
        317.974_78, // 55
        325.211_88, // 56
        332.474_73, // 57
        339.762_90, // 58
        347.075_94, // 59
        354.413_44, // 60
        361.774_98, // 61
        369.160_17, // 62
        376.568_64, // 63
        384.0,      // 64
    ]
};

/// Precomputed exact `log2(n)` for `n = 0..=64` (rounded to `f32`).
///
/// Entry 0 is `0.0` (a sentinel — `log2(0)` is undefined and callers never
/// index it for a real entropy computation). Used by [`log2_exact_small`]
/// to give the entropy formula's `log2(n)` term an exact value on the
/// CAN/CAN-FD hot path, replacing the lower-accuracy bit-trick approximation
/// for that term so the security threshold is not subject to ~0.09-bit drift.
// `clippy::approx_constant` fires on entry 10 (`log2(10)`), which here is a
// genuine lookup-table value, not an attempt to spell a named constant.
#[allow(clippy::excessive_precision, clippy::approx_constant)]
const LOG2_TABLE: [f32; 65] = [
    0.000_000_00, // 0
    0.000_000_00, // 1
    1.000_000_00, // 2
    1.584_962_50, // 3
    2.000_000_00, // 4
    2.321_928_09, // 5
    2.584_962_50, // 6
    2.807_354_92, // 7
    3.000_000_00, // 8
    3.169_925_00, // 9
    3.321_928_09, // 10
    3.459_431_62, // 11
    3.584_962_50, // 12
    3.700_439_72, // 13
    3.807_354_92, // 14
    3.906_890_60, // 15
    4.000_000_00, // 16
    4.087_462_84, // 17
    4.169_925_00, // 18
    4.247_927_51, // 19
    4.321_928_09, // 20
    4.392_317_42, // 21
    4.459_431_62, // 22
    4.523_561_96, // 23
    4.584_962_50, // 24
    4.643_856_19, // 25
    4.700_439_72, // 26
    4.754_887_50, // 27
    4.807_354_92, // 28
    4.857_981_00, // 29
    4.906_890_60, // 30
    4.954_196_31, // 31
    5.000_000_00, // 32
    5.044_394_12, // 33
    5.087_462_84, // 34
    5.129_283_02, // 35
    5.169_925_00, // 36
    5.209_453_37, // 37
    5.247_927_51, // 38
    5.285_402_22, // 39
    5.321_928_09, // 40
    5.357_552_00, // 41
    5.392_317_42, // 42
    5.426_264_75, // 43
    5.459_431_62, // 44
    5.491_853_10, // 45
    5.523_561_96, // 46
    5.554_588_85, // 47
    5.584_962_50, // 48
    5.614_709_84, // 49
    5.643_856_19, // 50
    5.672_425_34, // 51
    5.700_439_72, // 52
    5.727_920_45, // 53
    5.754_887_50, // 54
    5.781_359_71, // 55
    5.807_354_92, // 56
    5.832_890_01, // 57
    5.857_981_00, // 58
    5.882_643_05, // 59
    5.906_890_60, // 60
    5.930_737_34, // 61
    5.954_196_31, // 62
    5.977_279_92, // 63
    6.000_000_00, // 64
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// Helper: build a simple CAN frame.
    fn make_frame(id: u32, dlc: u8, data: &[u8]) -> CanFrame {
        let mut frame = CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc,
            data: [0u8; 64],
        };
        let copy_len = data.len().min(64);
        frame.data[..copy_len].copy_from_slice(&data[..copy_len]);
        frame
    }

    /// Helper: build a rule matching a single exact standard-frame ID.
    fn exact_id_rule(id: u32, min_interval_us: u64, max_dlc: u8) -> CanRule {
        CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: id,
            min_interval_us,
            max_dlc,
            is_extended: false,
            severity: AlertSeverity::High,
        }
    }

    // --- Rule matching ---

    #[test]
    fn rule_matches_exact_id() {
        let rule = exact_id_rule(0x100, 1000, 8);
        assert!(rule.matches(&make_frame(0x100, 0, &[])));
        assert!(!rule.matches(&make_frame(0x101, 0, &[])));
    }

    #[test]
    fn rule_matches_masked_id() {
        let rule = CanRule {
            id: 0,
            id_mask: 0x7F0,
            id_filter: 0x100,
            min_interval_us: 1000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Medium,
        };
        // IDs 0x100..0x10F all match
        assert!(rule.matches(&make_frame(0x100, 0, &[])));
        assert!(rule.matches(&make_frame(0x10F, 0, &[])));
        // 0x110 does not
        assert!(!rule.matches(&make_frame(0x110, 0, &[])));
    }

    #[test]
    fn add_rule_within_capacity() {
        let mut mon = CanMonitor::default();
        for i in 0..MAX_RULES {
            let r = exact_id_rule(i as u32, 1000, 8);
            assert!(mon.add_rule(r).is_ok());
        }
    }

    #[test]
    fn add_rule_exceeds_capacity() {
        let mut mon = CanMonitor::default();
        for i in 0..MAX_RULES {
            mon.add_rule(exact_id_rule(i as u32, 1000, 8)).ok();
        }
        let result = mon.add_rule(exact_id_rule(0xFFF, 1000, 8));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    // --- No alert on clean traffic ---

    #[test]
    fn no_alert_for_normal_traffic() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 1_000, 8)).ok();

        // Structured low-entropy payload — representative of a real signal
        // frame (a few repeated byte values), well below the fuzzing ratio.
        let frame = make_frame(0x100, 8, &[0x00, 0x00, 0x01, 0x00, 0xFF, 0x00, 0x00, 0x00]);
        // First frame – no previous timestamp to compare
        assert!(mon.process_frame(&frame, 0).is_none());
        // Second frame at safe interval
        assert!(mon.process_frame(&frame, 10_000).is_none());
    }

    #[test]
    fn no_alert_when_no_rule_matches() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 1_000, 8)).ok();

        let frame = make_frame(0x200, 8, &[0xFF; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    // --- Flood detection ---

    #[test]
    fn flood_detection_triggers() {
        let mut mon = CanMonitor::default();
        // Minimum interval 10 ms (10_000 us)
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 1_000_000).is_none()); // first
                                                                 // Only 5_000 us later → too fast
        let alert = mon.process_frame(&frame, 1_005_000);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.source_id, 0x100);
        assert_eq!(alert.source_type, SOURCE_CAN);
    }

    #[test]
    fn flood_detection_does_not_trigger_at_boundary() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
        // Exactly at the minimum interval – should be fine
        assert!(mon.process_frame(&frame, 10_000).is_none());
    }

    // --- DLC anomaly detection ---

    #[test]
    fn dlc_anomaly_triggers() {
        let mut mon = CanMonitor::default();
        // max_dlc = 4 for this ID
        mon.add_rule(exact_id_rule(0x200, 1_000, 4)).ok();

        let frame = make_frame(0x200, 6, &[0x01; 6]);
        let alert = mon.process_frame(&frame, 1_000_000);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.source_id, 0x200);
    }

    #[test]
    fn dlc_at_max_is_ok() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x200, 1_000, 8)).ok();

        let frame = make_frame(0x200, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    // --- Entropy-based fuzzing detection ---

    #[test]
    fn high_entropy_triggers_fuzzing_alert() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x300, 0, 8)).ok();
        // Low normalized-entropy ratio threshold so our payload triggers it.
        mon.set_entropy_threshold(0.5).ok();

        // Each byte is unique → maximum entropy for the length → ratio 1.0.
        let frame = make_frame(0x300, 8, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let alert = mon.process_frame(&frame, 0);
        assert!(alert.is_some());
    }

    #[test]
    fn low_entropy_does_not_trigger() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x300, 0, 8)).ok();
        // Ratio threshold well above what a constant payload can produce.
        mon.set_entropy_threshold(0.5).ok();

        // All identical bytes → entropy ratio = 0.
        let frame = make_frame(0x300, 8, &[0xAA; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn entropy_empty_payload_is_zero() {
        assert!((CanMonitor::shannon_entropy(&[]) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn entropy_uniform_byte_is_zero() {
        // All same byte → probability 1.0 → entropy 0.0
        let data = [0x42u8; 8];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            e.abs() < 0.01,
            "entropy of constant data should be ~0, got {e}"
        );
    }

    #[test]
    fn entropy_two_symbols_is_one() {
        // Two equally frequent symbols → entropy = 1.0 bit
        let data = [0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.15,
            "entropy of two equiprobable symbols should be ~1.0, got {e}"
        );
    }

    #[test]
    fn entropy_all_distinct_bytes() {
        // 8 distinct bytes → entropy = log2(8) = 3.0
        let data = [0, 1, 2, 3, 4, 5, 6, 7];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 3.0).abs() < 0.15,
            "entropy of 8 distinct bytes should be ~3.0, got {e}"
        );
    }

    // --- Bus-off detection ---

    #[test]
    fn bus_off_triggers_critical_alert() {
        let mut mon = CanMonitor::default();
        for t in 0..BUS_OFF_ERROR_THRESHOLD - 1 {
            assert!(mon.report_error(t as u64).is_none());
        }
        let alert = mon.report_error(1_000_000);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.source_id, 0);
    }

    #[test]
    fn error_count_reset() {
        let mut mon = CanMonitor::default();
        for t in 0..100 {
            mon.report_error(t);
        }
        mon.reset_error_count();
        // After reset, need another full run to trigger
        for t in 0..BUS_OFF_ERROR_THRESHOLD - 1 {
            assert!(mon.report_error(100 + t as u64).is_none());
        }
        assert!(mon.report_error(999_999).is_some());
    }

    // --- Alert counter & payload hash ---

    #[test]
    fn alert_ids_are_sequential() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        // Generate two flood alerts
        mon.process_frame(&frame, 0);
        let a1 = mon.process_frame(&frame, 1).unwrap();
        let a2 = mon.process_frame(&frame, 2).unwrap();
        assert_eq!(a2.id, a1.id + 1);
    }

    #[test]
    fn payload_hash_is_computed() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0);
        let alert = mon.process_frame(&frame, 1).unwrap();
        // Hash should be non-zero since we now compute a SipHash-2-4 fingerprint
        assert_ne!(alert.payload_hash, vs_types::PayloadHash([0u8; 32]));
        // Same payload should produce the same hash
        let alert2 = mon.process_frame(&frame, 2).unwrap();
        assert_eq!(alert.payload_hash, alert2.payload_hash);
    }

    // --- CAN-FD payload length ---

    #[test]
    fn canfd_frame_uses_full_64_bytes() {
        let mut fd = CanFrame {
            id: 0x400,
            is_extended: false,
            is_fd: true,
            dlc: 64,
            data: [0u8; 64],
        };
        // Fill all 64 bytes with distinct values
        for (i, b) in fd.data.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(fd.payload_len(), 64);
    }

    #[test]
    fn classic_can_frame_clamped_to_8() {
        let frame = CanFrame {
            id: 0x400,
            is_extended: false,
            is_fd: false,
            dlc: 12, // invalid for classic CAN, but we clamp gracefully
            data: [0u8; 64],
        };
        assert_eq!(frame.payload_len(), 8);
    }

    // --- Stats map ---

    #[test]
    fn stats_map_insert_and_retrieve() {
        let mut map = StatsMap::for_test();
        let entry = map.get_or_insert(0x100);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.id, 0x100);
        entry.message_count = 5;

        // Retrieve again
        let entry2 = map.get_or_insert(0x100).unwrap();
        assert_eq!(entry2.message_count, 5);
    }

    #[test]
    fn stats_map_distinct_ids() {
        let mut map = StatsMap::for_test();
        map.get_or_insert(0x100).unwrap().message_count = 10;
        map.get_or_insert(0x200).unwrap().message_count = 20;

        assert_eq!(map.get_or_insert(0x100).unwrap().message_count, 10);
        assert_eq!(map.get_or_insert(0x200).unwrap().message_count, 20);
    }

    // --- Integration / multi-rule ---

    #[test]
    fn multiple_rules_first_match_wins() {
        let mut mon = CanMonitor::default();
        // Rule 0: ID 0x100, severity Medium, very tight interval
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x100,
            min_interval_us: 50_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Medium,
        })
        .ok();
        // Rule 1: catches all IDs, severity Low
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x000,
            id_filter: 0x000,
            min_interval_us: 100_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Low,
        })
        .ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0); // seed first timestamp
                                      // Flood detected by rule 0 (Medium) before rule 1 (Low) is checked
        let alert = mon.process_frame(&frame, 100).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
    }

    #[test]
    fn extended_id_frame_processed() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x1FFF_FFFF,
            id_filter: 0x18DA_00F1,
            min_interval_us: 0,
            max_dlc: 4, // intentionally low
            is_extended: true,
            severity: AlertSeverity::High,
        })
        .ok();

        let frame = CanFrame {
            id: 0x18DA_00F1,
            is_extended: true,
            is_fd: false,
            dlc: 8,
            data: [0x02; 64],
        };
        // DLC 8 > max_dlc 4 → alert
        let alert = mon.process_frame(&frame, 0);
        assert!(alert.is_some());
    }

    // ---- New tests ----

    #[test]
    fn multiple_rules_different_priorities() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x100,
            min_interval_us: 1_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Low,
        })
        .ok();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x200,
            min_interval_us: 1_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Critical,
        })
        .ok();

        // Flood on 0x200 should get Critical
        let frame = make_frame(0x200, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0);
        let alert = mon.process_frame(&frame, 1).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.source_id, 0x200);
    }

    #[test]
    fn rule_mask_all_ones_matches_exactly_one_extended_id() {
        let rule = CanRule {
            id: 0,
            id_mask: 0x1FFF_FFFF,
            id_filter: 0x1234_5678,
            min_interval_us: 1000,
            max_dlc: 8,
            is_extended: true,
            severity: AlertSeverity::High,
        };
        let make_ext = |id| {
            let mut f = make_frame(id, 0, &[]);
            f.is_extended = true;
            f
        };
        assert!(rule.matches(&make_ext(0x1234_5678)));
        assert!(!rule.matches(&make_ext(0x1234_5679)));
        assert!(!rule.matches(&make_ext(0x1234_5677)));
        assert!(!rule.matches(&make_ext(0x0000_0000)));
        // Standard frame with same numeric ID should NOT match.
        assert!(!rule.matches(&make_frame(0x678, 0, &[])));
    }

    #[test]
    fn rule_mask_all_zeros_matches_all_ids() {
        let rule = CanRule {
            id: 0,
            id_mask: 0x0000_0000,
            id_filter: 0x0000_0000,
            min_interval_us: 1000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Low,
        };
        assert!(rule.matches(&make_frame(0x000, 0, &[])));
        assert!(rule.matches(&make_frame(0x100, 0, &[])));
        assert!(rule.matches(&make_frame(0x7FF, 0, &[])));
        // Extended frames do NOT match a standard rule.
        let mut ext = make_frame(0x100, 0, &[]);
        ext.is_extended = true;
        assert!(!rule.matches(&ext));
    }

    #[test]
    fn frame_with_max_extended_can_id() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x1FFF_FFFF,
            id_filter: 0x1FFF_FFFF,
            min_interval_us: 0,
            max_dlc: 8,
            is_extended: true,
            severity: AlertSeverity::Medium,
        })
        .ok();

        let frame = CanFrame {
            id: 0x1FFF_FFFF,
            is_extended: true,
            is_fd: false,
            dlc: 4,
            data: [0x01; 64],
        };
        // Should match and not panic
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn frame_with_id_zero_processed_correctly() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x000,
            min_interval_us: 1_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::Medium,
        })
        .ok();

        let frame = make_frame(0x000, 4, &[0x01; 4]);
        assert!(mon.process_frame(&frame, 0).is_none());
        // At safe interval, no alert
        assert!(mon.process_frame(&frame, 10_000).is_none());
    }

    #[test]
    fn flood_detection_at_exactly_min_interval_boundary() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 5_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
        // Exactly at min_interval_us boundary — should NOT trigger (delta == min_interval)
        assert!(mon.process_frame(&frame, 5_000).is_none());
        // One microsecond below boundary — should trigger
        assert!(mon.process_frame(&frame, 9_999).is_some());
    }

    #[test]
    fn dlc_anomaly_with_dlc_zero() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 0, 4)).ok();

        let frame = make_frame(0x100, 0, &[]);
        // DLC 0 <= max_dlc 4, no alert
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn dlc_anomaly_with_dlc_64_can_fd() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x300,
            min_interval_us: 0,
            max_dlc: 8, // Classic CAN max
            is_extended: false,
            severity: AlertSeverity::High,
        })
        .ok();

        let mut frame = CanFrame {
            id: 0x300,
            is_extended: false,
            is_fd: true,
            dlc: 64,
            data: [0x01; 64],
        };
        for (i, b) in frame.data.iter_mut().enumerate() {
            *b = (i & 0x03) as u8; // Low entropy repeated pattern
        }
        // DLC 64 > max_dlc 8 → alert
        let alert = mon.process_frame(&frame, 0);
        assert!(alert.is_some());
    }

    #[test]
    fn entropy_of_1_byte_payload() {
        // Single byte: only one symbol, entropy = 0.0
        let e = CanMonitor::shannon_entropy(&[0x42]);
        assert!(
            e.abs() < 0.01,
            "entropy of 1-byte payload should be ~0, got {e}"
        );
    }

    #[test]
    fn entropy_of_2_byte_identical_payload() {
        // Two identical bytes: one symbol, entropy = 0.0
        let e = CanMonitor::shannon_entropy(&[0xAB, 0xAB]);
        assert!(
            e.abs() < 0.01,
            "entropy of 2 identical bytes should be ~0, got {e}"
        );
    }

    #[test]
    fn entropy_of_2_byte_different_payload() {
        // Two different bytes: two symbols each with p=0.5, entropy = 1.0
        let e = CanMonitor::shannon_entropy(&[0x00, 0x01]);
        assert!(
            (e - 1.0).abs() < 0.15,
            "entropy of 2 different bytes should be ~1.0, got {e}"
        );
    }

    #[test]
    fn stats_map_full_capacity() {
        let mut map = StatsMap::for_test();
        // Insert STATS_CAPACITY entries
        for i in 0..STATS_CAPACITY as u32 {
            let entry = map.get_or_insert(i);
            assert!(entry.is_some(), "failed to insert entry {i}");
        }
    }

    #[test]
    fn stats_map_collision_handling() {
        let mut map = StatsMap::for_test();
        // Insert two IDs that hash to the same slot via linear probing
        // The hash function uses multiplicative hashing, but any two different IDs
        // should still be retrievable
        let id_a = 0x100u32;
        let id_b = 0x100u32 + STATS_CAPACITY as u32; // likely same bucket modulo capacity
        map.get_or_insert(id_a).unwrap().message_count = 42;
        map.get_or_insert(id_b).unwrap().message_count = 99;

        assert_eq!(map.get_or_insert(id_a).unwrap().message_count, 42);
        assert_eq!(map.get_or_insert(id_b).unwrap().message_count, 99);
    }

    #[test]
    fn multiple_sequential_alerts_have_incrementing_ids() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0); // seed
        let a1 = mon.process_frame(&frame, 1).unwrap();
        let a2 = mon.process_frame(&frame, 2).unwrap();
        let a3 = mon.process_frame(&frame, 3).unwrap();
        assert_eq!(a1.id, 1);
        assert_eq!(a2.id, 2);
        assert_eq!(a3.id, 3);
    }

    #[test]
    fn process_frame_no_rules_returns_none() {
        let mut mon = CanMonitor::default();
        // No rules added
        let frame = make_frame(0x100, 8, &[0xFF; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
        assert!(mon.process_frame(&frame, 1).is_none());
    }

    #[test]
    fn error_counter_increments_correctly() {
        let mut mon = CanMonitor::default();
        // Report several errors
        for i in 0..10u64 {
            mon.report_error(i);
        }
        // After 10 errors (below threshold 255), no alert
        assert!(mon.report_error(10).is_none());
    }

    #[test]
    fn error_counter_at_exactly_254() {
        let mut mon = CanMonitor::default();
        // Report 254 errors (threshold is 255)
        for i in 0..254u64 {
            mon.report_error(i);
        }
        // 254th error is index 253 (0-based), error_count is now 254
        // The threshold is >= 255, so 254 should NOT trigger
        assert_eq!(mon.error_count, 254);
        // One more would be 255, which triggers
    }

    #[test]
    fn error_counter_at_exactly_255() {
        let mut mon = CanMonitor::default();
        // Report 254 errors — no trigger yet
        for i in 0..254u64 {
            assert!(mon.report_error(i).is_none());
        }
        // 255th error triggers bus-off
        let alert = mon.report_error(254);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    #[test]
    fn shannon_entropy_all_zeros_returns_zero() {
        let data = [0u8; 16];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            e.abs() < 0.01,
            "entropy of all-zero data should be ~0, got {e}"
        );
    }

    #[test]
    fn shannon_entropy_precision_check() {
        // 4 equally frequent symbols in 8 bytes → entropy = log2(4) = 2.0
        let data = [0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 2.0).abs() < 0.15,
            "entropy of 4 equiprobable symbols should be ~2.0, got {e}"
        );
    }

    #[test]
    fn bus_off_alert_has_critical_severity() {
        let mut mon = CanMonitor::default();
        for t in 0..BUS_OFF_ERROR_THRESHOLD {
            let result = mon.report_error(t as u64);
            if t < BUS_OFF_ERROR_THRESHOLD - 1 {
                assert!(result.is_none());
            } else {
                let alert = result.unwrap();
                assert_eq!(alert.severity, AlertSeverity::Critical);
                assert_eq!(alert.source_type, SOURCE_CAN);
            }
        }
    }

    #[test]
    fn frame_processing_updates_stats_message_count() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 0, 8)).ok();

        let frame = make_frame(0x100, 4, &[0x01; 4]);
        mon.process_frame(&frame, 0);
        mon.process_frame(&frame, 1_000_000);
        mon.process_frame(&frame, 2_000_000);

        // Verify stats are tracked by inserting and checking
        let stats = mon.stats.get_or_insert(0x100).unwrap();
        assert_eq!(stats.message_count, 3);
    }

    #[test]
    fn large_frame_data_64_bytes_all_filled() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x400,
            min_interval_us: 0,
            max_dlc: 64,
            is_extended: false,
            severity: AlertSeverity::Low,
        })
        .ok();
        // Max ratio threshold so entropy doesn't trigger.
        mon.set_entropy_threshold(1.0).ok();

        let mut frame = CanFrame {
            id: 0x400,
            is_extended: false,
            is_fd: true,
            dlc: 64,
            data: [0u8; 64],
        };
        for (i, b) in frame.data.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(frame.payload_len(), 64);
        // Should not crash with 64 bytes
        let _ = mon.process_frame(&frame, 0);
    }

    #[test]
    fn flood_detection_resets_after_long_gap() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0);
        // Flood
        assert!(mon.process_frame(&frame, 1).is_some());
        // Long gap resets effective timing
        assert!(mon.process_frame(&frame, 1_000_000).is_none());
    }

    #[test]
    fn second_rule_matches_when_first_does_not() {
        let mut mon = CanMonitor::default();
        // Rule 0: only matches 0x100
        mon.add_rule(exact_id_rule(0x100, 1_000, 8)).ok();
        // Rule 1: matches 0x200
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x200,
            min_interval_us: 1_000,
            max_dlc: 4,
            is_extended: false,
            severity: AlertSeverity::Critical,
        })
        .ok();

        // Frame with ID 0x200 should match rule 1, not rule 0
        let frame = make_frame(0x200, 6, &[0x01; 6]);
        let alert = mon.process_frame(&frame, 0);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    #[test]
    fn rule_active_flag_inactive_rule_skipped() {
        let mut mon = CanMonitor::default();
        // Add a rule, then manually set it to None to simulate deactivation
        mon.add_rule(exact_id_rule(0x100, 1_000, 4)).ok();
        // Deactivate by clearing
        mon.rules[0] = None;

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        // No active rules match → no alert even though DLC > 4
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn default_entropy_threshold() {
        let mon = CanMonitor::default();
        assert!((mon.entropy_threshold - ENTROPY_THRESHOLD).abs() < f32::EPSILON);
    }

    #[test]
    fn monitor_default_trait() {
        let mon = CanMonitor::default();
        assert_eq!(mon.rule_count, 0);
        assert_eq!(mon.error_count, 0);
        assert_eq!(mon.alert_counter, 0);
    }

    #[test]
    fn canfd_dlc_clamped_to_64() {
        let frame = CanFrame {
            id: 0x100,
            is_extended: false,
            is_fd: true,
            dlc: 100, // exceeds 64
            data: [0u8; 64],
        };
        assert_eq!(frame.payload_len(), 64);
    }

    #[test]
    fn classic_can_dlc_zero() {
        let frame = CanFrame {
            id: 0x100,
            is_extended: false,
            is_fd: false,
            dlc: 0,
            data: [0u8; 64],
        };
        assert_eq!(frame.payload_len(), 0);
    }

    // --- Allowlist detection (Sprint 3) ---

    #[test]
    fn allowlist_disabled_by_default() {
        let mon = CanMonitor::default();
        assert!(!mon.allowlist_enabled());
    }

    #[test]
    fn allowlist_blocks_unknown_id() {
        let mut mon = CanMonitor::default();
        mon.allow_id(0x100).ok();
        mon.allow_id(0x200).ok();

        // Allowed ID — no alert.
        let frame = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());

        // Unknown ID — alert.
        let frame_bad = make_frame(0x300, 8, &[0x01; 8]);
        let alert = mon.process_frame(&frame_bad, 1000).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.source_id, 0x300);
    }

    #[test]
    fn allowlist_allows_known_id() {
        let mut mon = CanMonitor::default();
        mon.allow_id(0x100).ok();

        let frame = make_frame(0x100, 4, &[0x01; 4]);
        assert!(mon.process_frame(&frame, 0).is_none());
        assert!(mon.process_frame(&frame, 10_000).is_none());
    }

    #[test]
    fn allowlist_not_enabled_allows_all() {
        let mut mon = CanMonitor::default();
        // No IDs added — allowlist is disabled, all pass.
        let frame = make_frame(0x999, 4, &[0x01; 4]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn allowlist_duplicate_id_ok() {
        let mut mon = CanMonitor::default();
        assert!(mon.allow_id(0x100).is_ok());
        assert!(mon.allow_id(0x100).is_ok()); // duplicate is fine
    }

    #[test]
    fn allowlist_capacity_exhausted() {
        let mut mon = CanMonitor::default();
        for i in 0..ALLOWLIST_CAPACITY as u32 {
            assert!(mon.allow_id(i).is_ok());
        }
        // One more should fail.
        assert_eq!(mon.allow_id(0xFFFF), Err(VsError::ResourceExhausted));
    }

    // --- Replay detection (Sprint 3) ---

    #[test]
    fn replay_not_triggered_by_varying_payloads() {
        let mut mon = CanMonitor::default();

        for i in 0..10u64 {
            let frame = make_frame(0x100, 4, &[i as u8; 4]);
            assert!(
                mon.process_frame(&frame, i * 10_000).is_none(),
                "varying payload should not trigger replay at i={i}"
            );
        }
    }

    #[test]
    fn replay_triggered_after_3_identical_payloads() {
        let mut mon = CanMonitor::default();
        let frame = make_frame(0x100, 4, &[0xAA; 4]);

        // 1st frame — no replay (first seen).
        assert!(mon.process_frame(&frame, 0).is_none());
        // 2nd — repeat_count=2, not yet 3.
        assert!(mon.process_frame(&frame, 10_000).is_none());
        // 3rd — repeat_count=3, triggers replay alert.
        let alert = mon.process_frame(&frame, 20_000);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
    }

    #[test]
    fn replay_not_suppressed_by_interleaved_alert() {
        // Regression for H4: an attacker must not be able to defeat the
        // sustained-replay detector by interleaving a frame that trips
        // another detector. Replay state is independent and persists
        // across frames that raise flood/DLC/entropy alerts.
        let mut mon = CanMonitor::default();
        // Rule: no flood limit, DLC capped at 4.
        mon.add_rule(exact_id_rule(0x100, 0, 4)).ok();

        let replay = make_frame(0x100, 4, &[0xAA; 4]);
        // Same ID, oversized DLC -> always raises a DLC-anomaly alert.
        let dlc_anomaly = make_frame(0x100, 8, &[0xAA; 8]);

        // replay #1 -> repeat_count = 1
        assert!(mon.process_frame(&replay, 0).is_none());
        // interleaved DLC alert (would previously reset replay state)
        assert!(mon.process_frame(&dlc_anomaly, 10_000).is_some());
        // replay #2 -> repeat_count = 2
        assert!(mon.process_frame(&replay, 20_000).is_none());
        // another interleaved DLC alert
        assert!(mon.process_frame(&dlc_anomaly, 30_000).is_some());
        // replay #3 -> repeat_count = 3 -> sustained-replay alert MUST fire
        let alert = mon.process_frame(&replay, 40_000);
        assert!(
            alert.is_some(),
            "interleaved alerts must not suppress replay detection"
        );
        assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
    }

    #[test]
    fn replay_resets_on_different_payload() {
        let mut mon = CanMonitor::default();

        let frame_a = make_frame(0x100, 4, &[0xAA; 4]);
        let frame_b = make_frame(0x100, 4, &[0xBB; 4]);

        // Two identical, then different, then two more identical.
        assert!(mon.process_frame(&frame_a, 0).is_none());
        assert!(mon.process_frame(&frame_a, 10_000).is_none());
        // Different payload resets counter.
        assert!(mon.process_frame(&frame_b, 20_000).is_none());
        assert!(mon.process_frame(&frame_b, 30_000).is_none());
        // Third identical triggers.
        let alert = mon.process_frame(&frame_b, 40_000);
        assert!(alert.is_some());
    }

    #[test]
    fn replay_different_ids_tracked_separately() {
        let mut mon = CanMonitor::default();
        let frame_a = make_frame(0x100, 4, &[0xAA; 4]);
        let frame_b = make_frame(0x200, 4, &[0xAA; 4]);

        // Two identical for each ID — neither should trigger yet.
        assert!(mon.process_frame(&frame_a, 0).is_none());
        assert!(mon.process_frame(&frame_b, 1000).is_none());
        assert!(mon.process_frame(&frame_a, 2000).is_none());
        assert!(mon.process_frame(&frame_b, 3000).is_none());
        // Third identical for 0x100 triggers.
        let alert = mon.process_frame(&frame_a, 4000);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().source_id, 0x100);
    }

    #[test]
    fn process_frame_runs_all_5_detectors() {
        // Verify the 5 detection stages run without panicking.
        let mut mon = CanMonitor::default();
        mon.allow_id(0x100).ok();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();
        mon.set_entropy_threshold(0.95).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        // First frame — no alert from any detector.
        assert!(mon.process_frame(&frame, 0).is_none());
        // Normal interval — still OK.
        assert!(mon.process_frame(&frame, 100_000).is_none());
    }

    // ----- Soft-float accuracy tests -----

    #[test]
    fn entropy_uniform_8_bytes() {
        // 8 distinct bytes → entropy = log2(8) = 3.0
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 3.0).abs() < 0.15,
            "entropy of 8 distinct bytes = {e}, expected ~3.0"
        );
    }

    #[test]
    fn entropy_single_byte_is_zero() {
        let data = [0xAAu8; 8];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            e.abs() < 0.001,
            "entropy of constant bytes = {e}, expected 0.0"
        );
    }

    #[test]
    fn entropy_two_equal_halves_is_one() {
        // Half 0x00, half 0xFF → p=0.5 each → entropy = 1.0
        let data = [0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.15,
            "entropy of two-symbol equal split = {e}, expected ~1.0"
        );
    }

    #[test]
    fn log2_approx_accuracy_range() {
        // Test log2_approx_positive over both <1 and >=1 ranges.
        let test_values: &[f32] = &[
            1.0 / 256.0,
            1.0 / 128.0,
            1.0 / 64.0,
            1.0 / 32.0,
            1.0 / 16.0,
            1.0 / 8.0,
            0.25,
            0.5,
            1.0,
            2.0,
            8.0,
            32.0,
            64.0,
        ];
        for &x in test_values {
            let approx = log2_approx_positive(x);
            let exact = (x as f64).log2() as f32;
            let error = (approx - exact).abs();
            assert!(
                error < 0.1,
                "log2_approx_positive({x}) = {approx}, exact = {exact}, error = {error}"
            );
        }
    }

    #[test]
    fn entropy_max_64_byte_fd_payload() {
        // 64 distinct bytes → entropy = log2(64) = 6.0
        let mut data = [0u8; 64];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let e = CanMonitor::shannon_entropy(&data);
        assert!(
            (e - 6.0).abs() < 0.15,
            "entropy of 64 distinct bytes = {e}, expected ~6.0"
        );
    }

    // -----------------------------------------------------------------------
    // Security property assertion tests
    // -----------------------------------------------------------------------

    #[test]
    fn security_flood_detector_threshold_triggers() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);

        // First frame establishes baseline — no alert.
        assert!(mon.process_frame(&frame, 0).is_none());

        // Second frame too soon (interval < min_interval_us) should trigger.
        let alert = mon.process_frame(&frame, 100);
        assert!(
            alert.is_some(),
            "flood detection must trigger on rapid frames"
        );
    }

    #[test]
    fn security_dlc_anomaly_is_flagged() {
        let mut mon = CanMonitor::default();
        // Rule expects max_dlc = 4.
        mon.add_rule(exact_id_rule(0x200, 0, 4)).ok();

        // Frame with payload_len > max_dlc should be flagged.
        let frame = make_frame(0x200, 6, &[0xAA; 6]);
        let alert = mon.process_frame(&frame, 0);
        assert!(alert.is_some(), "DLC exceeding max_dlc must generate alert");
    }

    #[test]
    fn security_unknown_can_id_blocked_by_allowlist() {
        let mut mon = CanMonitor::default();
        // Adding an ID enables the allowlist automatically.
        mon.allow_id(0x100).ok();
        assert!(mon.allowlist_enabled());

        // Known ID — no alert.
        let frame_ok = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame_ok, 0).is_none());

        // Unknown ID — should alert.
        let frame_unknown = make_frame(0x999, 8, &[0x01; 8]);
        let alert = mon.process_frame(&frame_unknown, 1000);
        assert!(
            alert.is_some(),
            "unknown CAN ID must be flagged by allowlist"
        );
    }

    #[test]
    fn security_entropy_threshold_constant() {
        // Security property: the fuzzing detector compares a *normalized*
        // entropy ratio (H / log2(n)), not raw bits. The default threshold
        // is a 0.0..=1.0 ratio.
        assert!(ENTROPY_THRESHOLD > 0.0 && ENTROPY_THRESHOLD <= 1.0);

        // Regression for the old dead-detector bug: a fully random 8-byte
        // *classic* CAN payload caps at log2(8)=3.0 raw bits — below the
        // old 3.5-bit threshold, so classic-CAN fuzzing was never flagged.
        // The normalized ratio reaches 1.0 and MUST exceed the threshold.
        let classic_random = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let classic_ratio = CanMonitor::shannon_entropy_ratio(&classic_random);
        assert!(
            classic_ratio > ENTROPY_THRESHOLD,
            "max-entropy classic CAN payload (ratio {classic_ratio}) must exceed threshold ({ENTROPY_THRESHOLD})"
        );

        // A fully random 64-byte CAN-FD payload also reaches ratio ~1.0.
        let fd_random: [u8; 64] = core::array::from_fn(|i| i as u8);
        let fd_ratio = CanMonitor::shannon_entropy_ratio(&fd_random);
        assert!(
            fd_ratio > ENTROPY_THRESHOLD,
            "max-entropy CAN-FD payload (ratio {fd_ratio}) must exceed threshold ({ENTROPY_THRESHOLD})"
        );

        // Structured low-entropy traffic stays well below the threshold.
        let structured = [0xAAu8, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB];
        let structured_ratio = CanMonitor::shannon_entropy_ratio(&structured);
        assert!(
            structured_ratio < ENTROPY_THRESHOLD,
            "structured payload (ratio {structured_ratio}) must stay below threshold"
        );
    }

    #[test]
    fn classic_can_fuzzing_is_detected_end_to_end() {
        // End-to-end regression for H2: an 8-byte classic CAN frame with
        // all-distinct bytes is the worst-case fuzzing payload and must
        // raise an alert at the default threshold.
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x123, 0, 8)).ok();
        let frame = make_frame(0x123, 8, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(
            mon.process_frame(&frame, 0).is_some(),
            "classic-CAN fuzzing must be flagged by the entropy detector"
        );
    }

    #[test]
    fn security_bus_off_error_threshold_constant() {
        // Security assertion: bus-off threshold must be 255 (CAN standard).
        assert_eq!(BUS_OFF_ERROR_THRESHOLD, 255);
    }

    // -----------------------------------------------------------------------
    // New tests for security fixes
    // -----------------------------------------------------------------------

    #[test]
    fn effective_id_masks_standard_frame() {
        let frame = make_frame(0xFFFF_FFFF, 0, &[]);
        assert_eq!(frame.effective_id(), 0x7FF);
    }

    #[test]
    fn effective_id_masks_extended_frame() {
        let mut frame = make_frame(0xFFFF_FFFF, 0, &[]);
        frame.is_extended = true;
        assert_eq!(frame.effective_id(), 0x1FFF_FFFF);
    }

    #[test]
    fn out_of_range_id_masked_before_allowlist() {
        let mut mon = CanMonitor::default();
        // Allow only 0x7FF (the masked value of 0xFFFF_FFFF for standard).
        mon.allow_id(0x7FF).ok();

        // A frame with raw id 0xFFFF_FFFF should be masked to 0x7FF and pass.
        let frame = make_frame(0xFFFF_FFFF, 4, &[0x01; 4]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn entropy_threshold_rejects_nan() {
        let mut mon = CanMonitor::default();
        assert_eq!(
            mon.set_entropy_threshold(f32::NAN),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn entropy_threshold_rejects_infinity() {
        let mut mon = CanMonitor::default();
        assert_eq!(
            mon.set_entropy_threshold(f32::INFINITY),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn entropy_threshold_rejects_negative() {
        let mut mon = CanMonitor::default();
        assert_eq!(mon.set_entropy_threshold(-0.1), Err(VsError::InvalidInput));
    }

    #[test]
    fn entropy_threshold_accepts_valid_range() {
        // The threshold is a normalized 0.0..=1.0 ratio.
        let mut mon = CanMonitor::default();
        assert!(mon.set_entropy_threshold(0.0).is_ok());
        assert!(mon.set_entropy_threshold(0.5).is_ok());
        assert!(mon.set_entropy_threshold(1.0).is_ok());
    }

    #[test]
    fn entropy_threshold_rejects_above_max() {
        // Ratios above 1.0 are not attainable and must be rejected.
        let mut mon = CanMonitor::default();
        assert_eq!(mon.set_entropy_threshold(1.1), Err(VsError::InvalidInput));
        assert_eq!(mon.set_entropy_threshold(3.5), Err(VsError::InvalidInput));
    }

    #[test]
    fn bus_off_alert_fires_only_once() {
        let mut mon = CanMonitor::default();
        // Reach threshold.
        for t in 0..BUS_OFF_ERROR_THRESHOLD - 1 {
            mon.report_error(t as u64);
        }
        // First crossing — alert.
        assert!(mon.report_error(9999).is_some());
        // Subsequent errors — no more alerts.
        assert!(mon.report_error(10000).is_none());
        assert!(mon.report_error(10001).is_none());
    }

    #[test]
    fn bus_off_alert_re_fires_after_reset() {
        let mut mon = CanMonitor::default();
        for t in 0..BUS_OFF_ERROR_THRESHOLD {
            mon.report_error(t as u64);
        }
        mon.reset_error_count();
        // Need full count again.
        for t in 0..BUS_OFF_ERROR_THRESHOLD - 1 {
            assert!(mon.report_error(1000 + t as u64).is_none());
        }
        assert!(mon.report_error(9999).is_some());
    }

    #[test]
    fn extended_rule_does_not_match_standard_frame() {
        let mut mon = CanMonitor::default();
        mon.add_rule(CanRule {
            id: 0,
            id_mask: 0x1FFF_FFFF,
            id_filter: 0x100,
            min_interval_us: 0,
            max_dlc: 4,
            is_extended: true,
            severity: AlertSeverity::High,
        })
        .ok();

        // Standard frame with same numeric ID should NOT match the extended rule.
        let frame = make_frame(0x100, 8, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn replay_tracker_evicts_oldest_when_full() {
        let mut tracker = ReplayTracker::with_key([0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF]);

        // Fill the tracker with REPLAY_CAPACITY distinct IDs.  Insertion order
        // is monotonic; this test verifies that adding *more* than capacity
        // does not silently drop replay detection — the tracker must continue
        // to function for newly-observed IDs even after eviction kicks in.
        for i in 0..REPLAY_CAPACITY as u32 {
            tracker.check(i, &[0x01; 4]);
        }
        let pre_evictions = tracker.eviction_count();

        // Insert one more — must succeed via eviction of some entry in the
        // probe chain.  Under a keyed hash we cannot predict which ID will
        // be evicted, but the eviction counter must advance.
        let new_id = REPLAY_CAPACITY as u32;
        tracker.check(new_id, &[0xAA; 4]);
        assert!(
            tracker.eviction_count() > pre_evictions,
            "expected at least one eviction after exceeding capacity"
        );

        // The new ID must be tracked and produce a replay alert after the
        // configured number of repeats — proving the tracker still works
        // post-eviction.
        assert!(!tracker.check(new_id, &[0xAA; 4])); // 2nd identical
        assert!(tracker.check(new_id, &[0xAA; 4])); // 3rd → triggers
    }

    #[test]
    fn replay_re_alerts_on_sustained_attack() {
        let mut mon = CanMonitor::default();
        let frame = make_frame(0x100, 4, &[0xAA; 4]);

        // 1st and 2nd — no alert.
        assert!(mon.process_frame(&frame, 0).is_none());
        assert!(mon.process_frame(&frame, 10_000).is_none());
        // 3rd — first replay alert.
        assert!(mon.process_frame(&frame, 20_000).is_some());
        // 4th, 5th — no alert.
        assert!(mon.process_frame(&frame, 30_000).is_none());
        assert!(mon.process_frame(&frame, 40_000).is_none());
        // 6th — second replay alert (every 3 repeats).
        assert!(mon.process_frame(&frame, 50_000).is_some());
    }

    #[test]
    fn dlc_check_uses_clamped_length() {
        let mut mon = CanMonitor::default();
        mon.add_rule(exact_id_rule(0x100, 0, 8)).ok();

        // Classic CAN frame with raw dlc=12 — payload_len() clamps to 8.
        // Since 8 <= max_dlc(8), this should NOT trigger a DLC alert.
        let frame = make_frame(0x100, 12, &[0x01; 8]);
        assert!(mon.process_frame(&frame, 0).is_none());
    }

    #[test]
    fn compute_can_payload_hash_clamps_len() {
        let data = [0xAAu8; 8];

        // len == data.len(): hashes the whole slice.
        let exact = compute_can_payload_hash(&data, 8);

        // len > data.len(): must NOT panic; clamps to data.len() so the
        // result equals the exact-length hash.
        let over = compute_can_payload_hash(&data, 999);
        assert_eq!(exact.0, over.0, "oversized len must clamp, not panic");

        // len < data.len(): hashes only the requested prefix.
        let short = compute_can_payload_hash(&data, 4);
        assert_ne!(short.0, exact.0);

        // Empty slice with non-zero len must also be safe.
        let _ = compute_can_payload_hash(&[], 16);
    }

    #[test]
    fn alert_counter_saturates() {
        let mut mon = CanMonitor::default();
        mon.alert_counter = u64::MAX - 1;
        mon.add_rule(exact_id_rule(0x100, 10_000, 8)).ok();

        let frame = make_frame(0x100, 8, &[0x01; 8]);
        mon.process_frame(&frame, 0);

        // First alert: counter goes to MAX.
        let a1 = mon.process_frame(&frame, 1).unwrap();
        assert_eq!(a1.id, u64::MAX);

        // Second alert: counter stays at MAX (saturated, not wrapped).
        let a2 = mon.process_frame(&frame, 2).unwrap();
        assert_eq!(a2.id, u64::MAX);
    }

    #[test]
    fn siphash_different_payloads_different_hashes() {
        let k0 = 0xDEAD_BEEF_CAFE_BABE_u64;
        let k1 = 0x0123_4567_89AB_CDEF_u64;
        let h1 = vs_types::siphash_2_4(&[1, 2, 3], k0, k1);
        let h2 = vs_types::siphash_2_4(&[1, 2, 4], k0, k1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn eviction_counter_increments() {
        let mut tracker = ReplayTracker::with_key([0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF]);
        // Fill every replay slot (capacity varies by `capacity-*` feature).
        for i in 0..REPLAY_CAPACITY as u32 {
            tracker.check(i, &[i as u8]);
        }
        tracker.reset_eviction_count();
        // Next insert (a fresh ID beyond capacity) must evict.
        tracker.check(REPLAY_CAPACITY as u32 + 1, &[0xFF]);
        assert!(tracker.eviction_count() > 0);
    }

    // `new_with_replay_key_creates_functional_monitor` was removed in an
    // earlier pre-1.0 breaking pass along with the deprecated
    // `new_with_replay_key` alias. `CanMonitor::try_new(replay_key)` covers
    // the same construction path.

    #[test]
    fn different_replay_keys_produce_different_hashes() {
        let mut mon1 = CanMonitor::new([0x11; 16]);
        let mut mon2 = CanMonitor::new([0x22; 16]);

        let frame = CanFrame {
            id: 0x100,
            is_extended: false,
            is_fd: false,
            dlc: 4,
            data: {
                let mut d = [0u8; 64];
                d[0] = 0xDE;
                d[1] = 0xAD;
                d
            },
        };

        // Both monitors should handle the frame without panic.
        // The internal hash paths differ due to different keys.
        let _ = mon1.process_frame(&frame, 1000);
        let _ = mon2.process_frame(&frame, 1000);
    }

    // -- Allowlist capacity tests --------------------------------------------

    #[test]
    fn allowlist_full_capacity() {
        let mut mon = CanMonitor::default();
        // Capacity varies by `capacity-*` feature — use the constant.
        for i in 0..ALLOWLIST_CAPACITY as u32 {
            assert!(mon.allow_id(i).is_ok());
        }
        // One past capacity must fail.
        assert_eq!(
            mon.allow_id(ALLOWLIST_CAPACITY as u32),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn allowlist_duplicate_is_idempotent() {
        let mut mon = CanMonitor::default();
        assert!(mon.allow_id(0x100).is_ok());
        assert!(mon.allow_id(0x100).is_ok()); // duplicate, no error
    }

    #[test]
    fn allowlist_remove() {
        let mut al = Allowlist::new();
        al.add(100).unwrap();
        al.add(200).unwrap();
        al.add(300).unwrap();
        assert!(al.remove(200));
        assert_eq!(al.count, 2);
        assert!(al.is_allowed(100));
        assert!(!al.is_allowed(200));
        assert!(al.is_allowed(300));
    }

    #[test]
    fn allowlist_remove_nonexistent() {
        let mut al = Allowlist::new();
        al.add(100).unwrap();
        assert!(!al.remove(999));
        assert_eq!(al.count, 1);
    }

    #[test]
    fn allowlist_remove_last_disables() {
        let mut al = Allowlist::new();
        al.add(42).unwrap();
        assert!(al.enabled);
        assert!(al.remove(42));
        assert!(!al.enabled);
        assert_eq!(al.count, 0);
    }

    #[test]
    fn stats_map_clear() {
        let mut map = StatsMap::for_test();
        map.get_or_insert(0x100).unwrap().message_count = 1;
        map.get_or_insert(0x200).unwrap().message_count = 1;
        // Verify entries exist before clearing.
        assert!(map.get_or_insert(0x100).unwrap().message_count > 0);
        map.clear();
        // After clear, a fresh lookup should return a zeroed entry.
        let entry = map.get_or_insert(0x100).unwrap();
        assert_eq!(entry.message_count, 0);
    }

    // -------------------------------------------------------------------
    // P1/P2: Bitset-based allowlist tests
    // -------------------------------------------------------------------

    #[test]
    fn allowlist_bitset_standard_ids_o1() {
        let mut al = Allowlist::new();
        al.add(0x100).unwrap();
        al.add(0x200).unwrap();
        al.add(0x7FF).unwrap(); // max standard ID

        assert!(al.is_allowed(0x100));
        assert!(al.is_allowed(0x200));
        assert!(al.is_allowed(0x7FF));
        assert!(!al.is_allowed(0x300));
        assert!(!al.is_allowed(0));
    }

    #[test]
    fn allowlist_bitset_remove_clears_bit() {
        let mut al = Allowlist::new();
        al.add(0x100).unwrap();
        al.add(0x200).unwrap();
        assert!(al.is_allowed(0x100));

        al.remove(0x100);
        // 0x100 removed but allowlist is still enabled (0x200 remains).
        assert!(!al.is_allowed(0x100));
        assert!(al.is_allowed(0x200));
    }

    #[test]
    fn allowlist_extended_ids_fall_back_to_ct_scan() {
        let mut al = Allowlist::new();
        // Add one extended ID — forces constant-time fallback for all lookups
        let ext_id = 0x1000_0000;
        al.add(ext_id).unwrap();
        al.add(0x100).unwrap(); // standard ID too

        assert!(al.has_extended);
        assert!(al.is_allowed(ext_id));
        assert!(al.is_allowed(0x100));
        assert!(!al.is_allowed(0x200));
    }

    #[test]
    fn allowlist_standard_only_uses_fast_path() {
        let mut al = Allowlist::new();
        al.add(0x050).unwrap();
        al.add(0x051).unwrap();

        // No extended IDs — fast bitset path should be used.
        assert!(!al.has_extended);
        assert!(al.is_allowed(0x050));
        assert!(al.is_allowed(0x051));
        assert!(!al.is_allowed(0x052));
    }

    // -------------------------------------------------------------------
    // P4: Entropy lookup table accuracy
    // -------------------------------------------------------------------

    #[test]
    fn c_log2_c_table_accuracy() {
        for c in 1..=64u32 {
            let table_val = C_LOG2_C_TABLE[c as usize];
            let exact = (c as f64) * (c as f64).log2();
            let error = (table_val as f64 - exact).abs();
            assert!(
                error < 0.01,
                "C_LOG2_C_TABLE[{c}] = {table_val}, exact = {exact}, err = {error}"
            );
        }
    }

    #[test]
    fn entropy_consistent_with_lookup_optimization() {
        // All-same bytes → entropy = 0
        let data = [0xAA; 8];
        let e = CanMonitor::shannon_entropy(&data);
        assert!(e.abs() < 0.01, "expected ~0.0, got {e}");

        // Two distinct byte values, evenly split → entropy = 1.0
        let data2 = [0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01];
        let e2 = CanMonitor::shannon_entropy(&data2);
        assert!((e2 - 1.0).abs() < 0.15, "expected ~1.0, got {e2}");

        // All unique bytes (8 distinct in 8 bytes) → entropy = 3.0
        let data3 = [0, 1, 2, 3, 4, 5, 6, 7];
        let e3 = CanMonitor::shannon_entropy(&data3);
        assert!((e3 - 3.0).abs() < 0.15, "expected ~3.0, got {e3}");
    }

    // -------------------------------------------------------------------
    // Regression: reject all-zero replay key in `new`
    // -------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "replay_key must not be all-zero")]
    fn new_panics_on_zero_replay_key() {
        let _ = CanMonitor::new([0u8; 16]);
    }

    // -------------------------------------------------------------------
    // Regression: stats-map eviction counter increments under flood
    // -------------------------------------------------------------------

    #[test]
    fn stats_map_evictions_counter_increments_under_flood() {
        let mut mon = CanMonitor::default();
        // Counter starts at zero.
        assert_eq!(mon.stats_evictions(), 0);

        // Add a rule that matches every extended ID so process_frame() will
        // exercise the stats-map insert path for each frame.
        let rule = CanRule {
            id: 0,
            id_mask: 0,
            id_filter: 0,
            min_interval_us: 0,
            max_dlc: 64,
            is_extended: true,
            severity: AlertSeverity::Low,
        };
        mon.add_rule(rule).unwrap();

        // Flood with far more distinct extended CAN IDs than STATS_CAPACITY
        // (capacity varies by `capacity-*` feature). 2x capacity guarantees
        // the table fills and the LFU-eviction path is exercised many times.
        for i in 0..(STATS_CAPACITY as u32 * 2) {
            let frame = CanFrame {
                id: i,
                is_extended: true,
                is_fd: false,
                dlc: 1,
                data: {
                    let mut d = [0u8; 64];
                    d[0] = (i & 0xFF) as u8;
                    d
                },
            };
            let _ = mon.process_frame(&frame, u64::from(i) * 1000);
        }

        assert!(
            mon.stats_evictions() > 0,
            "expected stats_evictions > 0 after flood, got {}",
            mon.stats_evictions()
        );
    }
}
