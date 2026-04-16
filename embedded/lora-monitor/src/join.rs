// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! `LoRaWAN` join-procedure replay protection and MIC verification.
//!
//! Implements the cryptographic and replay-window checks defined in the
//! `LoRaWAN` 1.0.x and 1.1 specifications:
//!
//! * **DevNonce tracking** -- `JoinRequest` frames carry a 16-bit `DevNonce`
//!   chosen by the end device. The network server must reject any
//!   `JoinRequest` whose `DevNonce` was already seen for that `DevEUI` in a
//!   bounded recent-history window.
//! * **JoinNonce tracking** -- in 1.1 the server's `JoinNonce` is monotonic
//!   per device (strictly increasing); in 1.0.x it is random and must not
//!   repeat within a recent window.
//! * **MIC verification** -- the trailing 4-byte Message Integrity Code on
//!   `JoinRequest`, `JoinAccept`, and data frames is recomputed via
//!   AES-CMAC and compared in constant time.
//!
//! All state is held in fixed-size arrays so the monitor is safe to embed
//! in `no_std` / heap-less targets.
//!
//! The verdict surface is intentionally narrow:
//!
//! ```ignore
//! Allow
//! Replay { kind, value }
//! MicMismatch
//! Malformed { reason }
//! ```
//!
//! This module is independent of [`super::LoraMonitor`] and the frame-counter
//! pipeline -- it can be used standalone or wired into a larger inspector.

use aes::cipher::KeyInit;
use aes::Aes128;
use cmac::{Cmac, Mac};

// ---------------------------------------------------------------------------
// Capacity constants
// ---------------------------------------------------------------------------

/// Maximum number of distinct devices (per `DevEUI`) tracked for DevNonce
/// replay detection.
pub const MAX_DEV_NONCE_DEVICES: usize = 16;

/// Recent-DevNonce ring-buffer depth per device.
///
/// `LoRaWAN` 1.1 §6.2.4 recommends keeping at least 20 recent DevNonces. We
/// use 32 to give a small safety margin while staying small on the stack.
pub const DEV_NONCE_RING_DEPTH: usize = 32;

/// Maximum number of distinct join servers (per `JoinEUI`) tracked for
/// JoinNonce monitoring.
pub const MAX_JOIN_NONCE_SERVERS: usize = 8;

/// Recent-JoinNonce ring-buffer depth per join server (used in 1.0.x mode).
pub const JOIN_NONCE_RING_DEPTH: usize = 32;

/// Length of an AES-128 key in bytes.
pub const KEY_LEN: usize = 16;

/// Length of the MIC trailer on every `LoRaWAN` PHY payload, in bytes.
pub const MIC_LEN: usize = 4;

/// Minimum legal `JoinRequest` PHYPayload length (MHDR + AppEUI + DevEUI +
/// DevNonce + MIC = 1 + 8 + 8 + 2 + 4).
pub const MIN_JOIN_REQUEST_LEN: usize = 23;

/// Minimum legal `JoinAccept` PHYPayload length **after** decryption
/// (MHDR + JoinNonce + NetID + DevAddr + DLSettings + RxDelay + MIC =
/// 1 + 3 + 3 + 4 + 1 + 1 + 4 = 17). Optional CFList adds 16 more.
pub const MIN_JOIN_ACCEPT_LEN: usize = 17;

/// Minimum legal data-frame PHYPayload length
/// (MHDR + DevAddr + FCtrl + FCnt + MIC = 1 + 4 + 1 + 2 + 4).
pub const MIN_DATA_FRAME_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Verdict surface
// ---------------------------------------------------------------------------

/// What kind of replayed nonce was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayKind {
    /// A `DevNonce` from a `JoinRequest` that we have already seen for this
    /// `DevEUI` within the recent-history window.
    DevNonce,
    /// A `JoinNonce` from a `JoinAccept` that has already been seen
    /// (1.0.x) or that did not strictly increase (1.1).
    JoinNonce,
}

/// Why a frame was rejected as malformed (independent of cryptography).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// PHYPayload was shorter than the minimum length for the declared
    /// frame type.
    TooShort,
    /// MHDR major version field was something other than 0
    /// (`LoRaWAN R1`).
    BadMajor,
    /// MHDR message type byte did not match the frame kind the caller
    /// asserted (e.g. caller said `JoinRequest` but MHDR said `Data`).
    MTypeMismatch,
}

/// Outcome of inspecting a single LoRaWAN frame.
#[must_use = "join verdicts carry security-relevant decisions"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinVerdict {
    /// Frame passed all replay and MIC checks.
    Allow,
    /// A nonce previously seen on this lineage was reused.
    Replay {
        /// Which nonce field replayed.
        kind: ReplayKind,
        /// The offending nonce value.
        value: u32,
    },
    /// Computed MIC did not match the trailing 4 bytes of the frame.
    MicMismatch,
    /// Frame failed parsing before any cryptographic check could run.
    Malformed {
        /// Concrete reason for parse failure.
        reason: MalformedReason,
    },
}

// ---------------------------------------------------------------------------
// LoRaWAN protocol version
// ---------------------------------------------------------------------------

/// `LoRaWAN` major-version selector for JoinNonce policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoraWanVersion {
    /// 1.0.x: `JoinNonce` is random; reject only if it repeats inside the
    /// recent ring buffer.
    V1_0,
    /// 1.1: `JoinNonce` must strictly increase per device.
    V1_1,
}

// ---------------------------------------------------------------------------
// Direction constant for data-frame MIC
// ---------------------------------------------------------------------------

/// MIC direction byte used by `LoRaWAN` data-frame B0 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDir {
    /// Uplink (device -> server). Direction byte = 0x00.
    Up,
    /// Downlink (server -> device). Direction byte = 0x01.
    Down,
}

impl FrameDir {
    #[inline]
    const fn byte(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Down => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// AES-CMAC helpers
// ---------------------------------------------------------------------------

/// Compute AES-CMAC over `data` using `key` and return the first 4 bytes.
fn cmac4(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; MIC_LEN] {
    // `Cmac::<Aes128>::new_from_slice` only fails if the key length is wrong;
    // we feed it a fixed 16-byte array, so this cannot fail at runtime.
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key)
        .expect("AES-128 CMAC key length is fixed at 16 bytes");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MIC_LEN];
    out.copy_from_slice(&tag[..MIC_LEN]);
    out
}

/// Constant-time comparison of two 4-byte MIC tags.
#[inline]
fn ct_mic_eq(a: &[u8; MIC_LEN], b: &[u8; MIC_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..MIC_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time equality for 8-byte EUIs.
#[inline]
fn ct_eui_eq(a: &[u8; 8], b: &[u8; 8]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..8 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Per-DevEUI DevNonce ring buffer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct DevNonceEntry {
    dev_eui: [u8; 8],
    /// Ring of recent DevNonces. `0xFFFF_FFFF` (sentinel) marks unused.
    ring: [u32; DEV_NONCE_RING_DEPTH],
    write_idx: u16,
    fill: u16,
    active: bool,
    last_seen_us: u64,
}

impl DevNonceEntry {
    const fn empty() -> Self {
        Self {
            dev_eui: [0; 8],
            ring: [u32::MAX; DEV_NONCE_RING_DEPTH],
            write_idx: 0,
            fill: 0,
            active: false,
            last_seen_us: 0,
        }
    }

    fn contains(&self, nonce: u32) -> bool {
        // O(DEV_NONCE_RING_DEPTH) linear scan. Acceptable at the current
        // depth of 32 (well under one cache line of comparisons), but if
        // the ring depth grows substantially consider a sorted-set or
        // small bloom-filter representation keyed on the low bits.
        // TODO(perf): replace with sorted u32 set or 64-bit bloom hash
        //             once DEV_NONCE_RING_DEPTH > 64.
        for i in 0..self.fill as usize {
            if self.ring[i] == nonce {
                return true;
            }
        }
        false
    }

    fn push(&mut self, nonce: u32) {
        self.ring[self.write_idx as usize] = nonce;
        self.write_idx = (self.write_idx + 1) % DEV_NONCE_RING_DEPTH as u16;
        if (self.fill as usize) < DEV_NONCE_RING_DEPTH {
            self.fill += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Per-JoinEUI JoinNonce state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct JoinNonceEntry {
    join_eui: [u8; 8],
    /// Strictly-monotonic last seen value (used in 1.1).
    last_seen: u32,
    has_last: bool,
    /// Ring of recent values (used in 1.0.x). Sentinel `0xFFFF_FFFF` =
    /// unused.
    ring: [u32; JOIN_NONCE_RING_DEPTH],
    write_idx: u16,
    fill: u16,
    active: bool,
    last_seen_us: u64,
}

impl JoinNonceEntry {
    const fn empty() -> Self {
        Self {
            join_eui: [0; 8],
            last_seen: 0,
            has_last: false,
            ring: [u32::MAX; JOIN_NONCE_RING_DEPTH],
            write_idx: 0,
            fill: 0,
            active: false,
            last_seen_us: 0,
        }
    }

    fn contains(&self, nonce: u32) -> bool {
        // O(JOIN_NONCE_RING_DEPTH) linear scan. Same trade-off as
        // `DevNonceEntry::contains` -- fine at depth 32, revisit if grown.
        // TODO(perf): replace with sorted u32 set or 64-bit bloom hash
        //             once JOIN_NONCE_RING_DEPTH > 64.
        for i in 0..self.fill as usize {
            if self.ring[i] == nonce {
                return true;
            }
        }
        false
    }

    fn push(&mut self, nonce: u32) {
        self.ring[self.write_idx as usize] = nonce;
        self.write_idx = (self.write_idx + 1) % JOIN_NONCE_RING_DEPTH as u16;
        if (self.fill as usize) < JOIN_NONCE_RING_DEPTH {
            self.fill += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// JoinGuard — public API
// ---------------------------------------------------------------------------

/// Tracks join-procedure replay state and verifies MICs on `LoRaWAN`
/// frames.
///
/// Holds bounded per-`DevEUI` DevNonce ring buffers, per-`JoinEUI`
/// JoinNonce state, and acts as a stateless oracle for AES-CMAC MICs on
/// data frames (which carry no replay state of their own here -- frame
/// counters are handled separately by [`super::LoraMonitor`]).
pub struct JoinGuard {
    dev_nonces: [DevNonceEntry; MAX_DEV_NONCE_DEVICES],
    join_nonces: [JoinNonceEntry; MAX_JOIN_NONCE_SERVERS],
    version: LoraWanVersion,
}

impl JoinGuard {
    /// Create a new guard for the given protocol version.
    pub fn new(version: LoraWanVersion) -> Self {
        Self {
            dev_nonces: [DevNonceEntry::empty(); MAX_DEV_NONCE_DEVICES],
            join_nonces: [JoinNonceEntry::empty(); MAX_JOIN_NONCE_SERVERS],
            version,
        }
    }

    /// Forget all tracked DevNonces and JoinNonces. Keys are not stored
    /// in this struct, so this is a complete reset.
    pub fn reset(&mut self) {
        self.dev_nonces = [DevNonceEntry::empty(); MAX_DEV_NONCE_DEVICES];
        self.join_nonces = [JoinNonceEntry::empty(); MAX_JOIN_NONCE_SERVERS];
    }

    /// Number of distinct `DevEUI`s currently tracked.
    pub fn tracked_devices(&self) -> usize {
        self.dev_nonces.iter().filter(|e| e.active).count()
    }

    /// Number of distinct `JoinEUI`s currently tracked.
    pub fn tracked_servers(&self) -> usize {
        self.join_nonces.iter().filter(|e| e.active).count()
    }

    // -----------------------------------------------------------------------
    // JoinRequest
    // -----------------------------------------------------------------------

    /// Inspect a `JoinRequest` PHYPayload.
    ///
    /// `phy` is the raw on-air payload, including the 4-byte MIC trailer.
    /// `app_key` is the device's `AppKey` (1.0.x) or `NwkKey` (1.1) used
    /// to derive the MIC.
    ///
    /// On success returns [`JoinVerdict::Allow`] and records the
    /// `DevNonce` in the per-`DevEUI` ring. On replay returns
    /// [`JoinVerdict::Replay`] **without** recording (so the legitimate
    /// nonce is not displaced by the attack).
    pub fn inspect_join_request(
        &mut self,
        phy: &[u8],
        app_key: &[u8; KEY_LEN],
        timestamp_us: u64,
    ) -> JoinVerdict {
        if phy.len() < MIN_JOIN_REQUEST_LEN {
            return JoinVerdict::Malformed {
                reason: MalformedReason::TooShort,
            };
        }
        // MHDR validation: MType in upper 3 bits = 0 (JoinRequest),
        // Major in lower 2 bits = 0 (R1).
        let mhdr = phy[0];
        if (mhdr & 0b0000_0011) != 0 {
            return JoinVerdict::Malformed {
                reason: MalformedReason::BadMajor,
            };
        }
        if (mhdr & 0b1110_0000) != 0 {
            return JoinVerdict::Malformed {
                reason: MalformedReason::MTypeMismatch,
            };
        }

        let mic_offset = phy.len() - MIC_LEN;
        let mac_input = &phy[..mic_offset];
        let mut frame_mic = [0u8; MIC_LEN];
        frame_mic.copy_from_slice(&phy[mic_offset..]);

        let computed = cmac4(app_key, mac_input);
        if !ct_mic_eq(&computed, &frame_mic) {
            return JoinVerdict::MicMismatch;
        }

        // Layout (after MHDR): JoinEUI[8] (LE) | DevEUI[8] (LE) | DevNonce[2] (LE)
        // (LoRaWAN 1.1 renames AppEUI -> JoinEUI; bytes are identical.)
        let mut dev_eui = [0u8; 8];
        dev_eui.copy_from_slice(&phy[9..17]);
        let dev_nonce = u16::from_le_bytes([phy[17], phy[18]]);

        let entry = self.dev_entry_for(&dev_eui, timestamp_us);
        let nonce_u32 = u32::from(dev_nonce);
        if entry.contains(nonce_u32) {
            return JoinVerdict::Replay {
                kind: ReplayKind::DevNonce,
                value: nonce_u32,
            };
        }
        entry.push(nonce_u32);
        entry.last_seen_us = timestamp_us;
        JoinVerdict::Allow
    }

    // -----------------------------------------------------------------------
    // JoinAccept
    // -----------------------------------------------------------------------

    /// Inspect a (decrypted) `JoinAccept` PHYPayload.
    ///
    /// Callers are responsible for AES-decrypting the JoinAccept body
    /// before invoking this method -- the MIC is computed over the
    /// **plaintext** per the spec. `join_eui` identifies the join server
    /// for JoinNonce tracking.
    pub fn inspect_join_accept(
        &mut self,
        phy: &[u8],
        app_key: &[u8; KEY_LEN],
        join_eui: &[u8; 8],
        timestamp_us: u64,
    ) -> JoinVerdict {
        if phy.len() < MIN_JOIN_ACCEPT_LEN {
            return JoinVerdict::Malformed {
                reason: MalformedReason::TooShort,
            };
        }
        let mhdr = phy[0];
        if (mhdr & 0b0000_0011) != 0 {
            return JoinVerdict::Malformed {
                reason: MalformedReason::BadMajor,
            };
        }
        // JoinAccept MType = 0b001
        if (mhdr & 0b1110_0000) != (1 << 5) {
            return JoinVerdict::Malformed {
                reason: MalformedReason::MTypeMismatch,
            };
        }

        let mic_offset = phy.len() - MIC_LEN;
        let mac_input = &phy[..mic_offset];
        let mut frame_mic = [0u8; MIC_LEN];
        frame_mic.copy_from_slice(&phy[mic_offset..]);

        let computed = cmac4(app_key, mac_input);
        if !ct_mic_eq(&computed, &frame_mic) {
            return JoinVerdict::MicMismatch;
        }

        // JoinNonce: 3 bytes, little-endian, immediately after MHDR.
        let join_nonce = u32::from(phy[1]) | (u32::from(phy[2]) << 8) | (u32::from(phy[3]) << 16);

        let version = self.version;
        let entry = self.server_entry_for(join_eui, timestamp_us);
        match version {
            LoraWanVersion::V1_1 => {
                if entry.has_last && join_nonce <= entry.last_seen {
                    return JoinVerdict::Replay {
                        kind: ReplayKind::JoinNonce,
                        value: join_nonce,
                    };
                }
                entry.last_seen = join_nonce;
                entry.has_last = true;
            }
            LoraWanVersion::V1_0 => {
                if entry.contains(join_nonce) {
                    return JoinVerdict::Replay {
                        kind: ReplayKind::JoinNonce,
                        value: join_nonce,
                    };
                }
                entry.push(join_nonce);
            }
        }
        entry.last_seen_us = timestamp_us;
        JoinVerdict::Allow
    }

    // -----------------------------------------------------------------------
    // Data frames (uplink / downlink)
    // -----------------------------------------------------------------------

    /// Verify the MIC on a `LoRaWAN` data frame (uplink or downlink).
    ///
    /// The MIC is computed over the B0 block || MHDR || FHDR || FPort ||
    /// FRMPayload, as defined in `LoRaWAN` 1.0.x §4.4. Frame-counter
    /// replay and rollover are **not** checked here -- that pipeline
    /// lives in [`super::LoraMonitor`].
    ///
    /// `nwk_skey` is the NwkSKey (1.0.x) or FNwkSIntKey (1.1).
    pub fn verify_data_frame(
        &self,
        phy: &[u8],
        nwk_skey: &[u8; KEY_LEN],
        dir: FrameDir,
        dev_addr: [u8; 4],
        full_fcnt: u32,
    ) -> JoinVerdict {
        if phy.len() < MIN_DATA_FRAME_LEN {
            return JoinVerdict::Malformed {
                reason: MalformedReason::TooShort,
            };
        }
        let mhdr = phy[0];
        if (mhdr & 0b0000_0011) != 0 {
            return JoinVerdict::Malformed {
                reason: MalformedReason::BadMajor,
            };
        }
        // Data MTypes: 010, 011, 100, 101 (top three bits).
        let mtype = (mhdr & 0b1110_0000) >> 5;
        let dir_byte = dir.byte();
        let is_uplink = matches!(mtype, 2 | 4);
        let is_downlink = matches!(mtype, 3 | 5);
        match (dir_byte, is_uplink, is_downlink) {
            (0, true, _) | (1, _, true) => {}
            _ => {
                return JoinVerdict::Malformed {
                    reason: MalformedReason::MTypeMismatch,
                };
            }
        }

        let mic_offset = phy.len() - MIC_LEN;
        let mac_input = &phy[..mic_offset];
        let mut frame_mic = [0u8; MIC_LEN];
        frame_mic.copy_from_slice(&phy[mic_offset..]);

        // B0 = 0x49 || 4*0x00 || Dir || DevAddr (LE) || FCnt32 (LE) ||
        //      0x00 || len(msg)
        let mut b0 = [0u8; 16];
        b0[0] = 0x49;
        b0[5] = dir_byte;
        b0[6..10].copy_from_slice(&dev_addr);
        b0[10..14].copy_from_slice(&full_fcnt.to_le_bytes());
        b0[14] = 0x00;
        // LoRaWAN MAC payload is bounded well below 255 bytes (e.g. ~242 at
        // SF7 in EU868), so this cast never truncates in practice. Assert in
        // debug builds to catch a misuse where an oversized buffer is fed in.
        debug_assert!(mac_input.len() <= 255);
        b0[15] = mac_input.len() as u8;

        // CMAC over B0 || mac_input
        let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(nwk_skey)
            .expect("AES-128 CMAC key length is fixed at 16 bytes");
        mac.update(&b0);
        mac.update(mac_input);
        let tag = mac.finalize().into_bytes();
        let mut computed = [0u8; MIC_LEN];
        computed.copy_from_slice(&tag[..MIC_LEN]);

        if ct_mic_eq(&computed, &frame_mic) {
            JoinVerdict::Allow
        } else {
            JoinVerdict::MicMismatch
        }
    }

    // -----------------------------------------------------------------------
    // Internal slot allocation
    // -----------------------------------------------------------------------

    /// Find or LRU-allocate the per-DevEUI ring entry. Eviction overwrites
    /// the least-recently-used active slot.
    //
    // TODO(refactor): `dev_entry_for` and `server_entry_for` share ~80 lines
    // of identical LRU logic differing only in the table, entry type, and
    // EUI accessor. Extract into a generic helper once a small `SlotEntry`
    // trait (or equivalent index-returning closure) is acceptable in this
    // `no_std` / `forbid(unsafe_code)` context. Left in place for now to
    // avoid widening the surface for a low-traffic codepath.
    fn dev_entry_for(&mut self, dev_eui: &[u8; 8], now_us: u64) -> &mut DevNonceEntry {
        let mut free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        let mut found: Option<usize> = None;
        for (i, e) in self.dev_nonces.iter().enumerate() {
            if e.active {
                if ct_eui_eq(&e.dev_eui, dev_eui) {
                    found = Some(i);
                    break;
                }
                if e.last_seen_us < lru_ts {
                    lru_ts = e.last_seen_us;
                    lru_idx = i;
                }
            } else if free.is_none() {
                free = Some(i);
            }
        }
        let idx = match found {
            Some(i) => i,
            None => {
                if let Some(i) = free {
                    self.dev_nonces[i] = DevNonceEntry::empty();
                    self.dev_nonces[i].active = true;
                    self.dev_nonces[i].dev_eui = *dev_eui;
                    self.dev_nonces[i].last_seen_us = now_us;
                    i
                } else {
                    self.dev_nonces[lru_idx] = DevNonceEntry::empty();
                    self.dev_nonces[lru_idx].active = true;
                    self.dev_nonces[lru_idx].dev_eui = *dev_eui;
                    self.dev_nonces[lru_idx].last_seen_us = now_us;
                    lru_idx
                }
            }
        };
        &mut self.dev_nonces[idx]
    }

    fn server_entry_for(&mut self, join_eui: &[u8; 8], now_us: u64) -> &mut JoinNonceEntry {
        let mut free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;
        let mut found: Option<usize> = None;
        for (i, e) in self.join_nonces.iter().enumerate() {
            if e.active {
                if ct_eui_eq(&e.join_eui, join_eui) {
                    found = Some(i);
                    break;
                }
                if e.last_seen_us < lru_ts {
                    lru_ts = e.last_seen_us;
                    lru_idx = i;
                }
            } else if free.is_none() {
                free = Some(i);
            }
        }
        let idx = match found {
            Some(i) => i,
            None => {
                if let Some(i) = free {
                    self.join_nonces[i] = JoinNonceEntry::empty();
                    self.join_nonces[i].active = true;
                    self.join_nonces[i].join_eui = *join_eui;
                    self.join_nonces[i].last_seen_us = now_us;
                    i
                } else {
                    self.join_nonces[lru_idx] = JoinNonceEntry::empty();
                    self.join_nonces[lru_idx].active = true;
                    self.join_nonces[lru_idx].join_eui = *join_eui;
                    self.join_nonces[lru_idx].last_seen_us = now_us;
                    lru_idx
                }
            }
        };
        &mut self.join_nonces[idx]
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed JoinRequest with a valid MIC.
    fn make_join_request(
        join_eui: [u8; 8],
        dev_eui: [u8; 8],
        dev_nonce: u16,
        key: &[u8; KEY_LEN],
    ) -> [u8; MIN_JOIN_REQUEST_LEN] {
        let mut buf = [0u8; MIN_JOIN_REQUEST_LEN];
        buf[0] = 0x00; // MType=000 (JoinRequest), Major=00
        buf[1..9].copy_from_slice(&join_eui);
        buf[9..17].copy_from_slice(&dev_eui);
        buf[17..19].copy_from_slice(&dev_nonce.to_le_bytes());
        let mic = cmac4(key, &buf[..19]);
        buf[19..23].copy_from_slice(&mic);
        buf
    }

    /// Build a well-formed JoinAccept (plaintext) with a valid MIC.
    fn make_join_accept(join_nonce: u32, key: &[u8; KEY_LEN]) -> [u8; MIN_JOIN_ACCEPT_LEN] {
        let mut buf = [0u8; MIN_JOIN_ACCEPT_LEN];
        buf[0] = 0b001 << 5; // MType = 001 (JoinAccept), Major = 00
        buf[1] = (join_nonce & 0xFF) as u8;
        buf[2] = ((join_nonce >> 8) & 0xFF) as u8;
        buf[3] = ((join_nonce >> 16) & 0xFF) as u8;
        // bytes 4..13 left zero (NetID, DevAddr, DLSettings, RxDelay)
        let mic = cmac4(key, &buf[..13]);
        buf[13..17].copy_from_slice(&mic);
        buf
    }

    /// Build a well-formed uplink data frame with valid MIC.
    fn make_uplink(nwk_skey: &[u8; KEY_LEN], dev_addr: [u8; 4], fcnt: u32) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = 0b010 << 5; // UnconfirmedDataUp, Major=0
        buf[1..5].copy_from_slice(&dev_addr);
        buf[5] = 0; // FCtrl
        buf[6..8].copy_from_slice(&((fcnt & 0xFFFF) as u16).to_le_bytes());

        let mut b0 = [0u8; 16];
        b0[0] = 0x49;
        b0[5] = 0; // uplink
        b0[6..10].copy_from_slice(&dev_addr);
        b0[10..14].copy_from_slice(&fcnt.to_le_bytes());
        b0[15] = 8; // MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2)

        let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(nwk_skey).unwrap();
        mac.update(&b0);
        mac.update(&buf[..8]);
        let tag = mac.finalize().into_bytes();
        buf[8..12].copy_from_slice(&tag[..4]);
        buf
    }

    const KEY: [u8; KEY_LEN] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    const JOIN_EUI: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const DEV_EUI: [u8; 8] = [9, 10, 11, 12, 13, 14, 15, 16];

    // -----------------------------------------------------------------------
    // JoinRequest / DevNonce
    // -----------------------------------------------------------------------

    #[test]
    fn join_request_valid_mic_allowed() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let frame = make_join_request(JOIN_EUI, DEV_EUI, 0x1234, &KEY);
        assert_eq!(
            g.inspect_join_request(&frame, &KEY, 1_000),
            JoinVerdict::Allow
        );
    }

    #[test]
    fn join_request_replayed_dev_nonce_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let frame = make_join_request(JOIN_EUI, DEV_EUI, 0x1234, &KEY);
        assert_eq!(
            g.inspect_join_request(&frame, &KEY, 1_000),
            JoinVerdict::Allow
        );
        // Same DevNonce again → replay.
        let frame2 = make_join_request(JOIN_EUI, DEV_EUI, 0x1234, &KEY);
        let v = g.inspect_join_request(&frame2, &KEY, 2_000);
        assert_eq!(
            v,
            JoinVerdict::Replay {
                kind: ReplayKind::DevNonce,
                value: 0x1234,
            }
        );
    }

    #[test]
    fn join_request_distinct_dev_nonces_allowed() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        for i in 0..10u16 {
            let frame = make_join_request(JOIN_EUI, DEV_EUI, i * 7 + 1, &KEY);
            let v = g.inspect_join_request(&frame, &KEY, u64::from(i));
            assert_eq!(v, JoinVerdict::Allow, "iter {} should pass", i);
        }
    }

    #[test]
    fn join_request_mic_corruption_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let mut frame = make_join_request(JOIN_EUI, DEV_EUI, 0x1234, &KEY);
        // Flip a bit in the MIC.
        frame[20] ^= 0x01;
        assert_eq!(
            g.inspect_join_request(&frame, &KEY, 1_000),
            JoinVerdict::MicMismatch
        );
    }

    #[test]
    fn join_request_mic_replay_does_not_record_dev_nonce() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let mut frame = make_join_request(JOIN_EUI, DEV_EUI, 0x4242, &KEY);
        frame[20] ^= 0xFF; // bad MIC
        assert_eq!(
            g.inspect_join_request(&frame, &KEY, 1_000),
            JoinVerdict::MicMismatch
        );
        // Now legitimate JoinRequest with same nonce should still pass — the
        // nonce was NOT recorded by the rejected MIC-mismatch frame.
        let good = make_join_request(JOIN_EUI, DEV_EUI, 0x4242, &KEY);
        assert_eq!(
            g.inspect_join_request(&good, &KEY, 2_000),
            JoinVerdict::Allow
        );
    }

    #[test]
    fn join_request_too_short_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let bad = [0u8; 8];
        assert_eq!(
            g.inspect_join_request(&bad, &KEY, 0),
            JoinVerdict::Malformed {
                reason: MalformedReason::TooShort
            }
        );
    }

    #[test]
    fn join_request_bad_mtype_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let mut frame = make_join_request(JOIN_EUI, DEV_EUI, 7, &KEY);
        frame[0] = 0b010 << 5; // pretend it's an UnconfirmedDataUp
                               // Recompute MIC so we actually exercise the MType check, not the MIC.
        let mic = cmac4(&KEY, &frame[..19]);
        frame[19..23].copy_from_slice(&mic);
        assert_eq!(
            g.inspect_join_request(&frame, &KEY, 0),
            JoinVerdict::Malformed {
                reason: MalformedReason::MTypeMismatch
            }
        );
    }

    #[test]
    fn dev_nonce_ring_buffer_eviction_works() {
        // After DEV_NONCE_RING_DEPTH unique nonces, the oldest must be
        // forgotten and re-acceptable. We use depth+1 distinct nonces.
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let depth = DEV_NONCE_RING_DEPTH as u16;
        // First nonce = 0; we want to push >depth distinct nonces to evict it.
        for i in 0..depth {
            let f = make_join_request(JOIN_EUI, DEV_EUI, i, &KEY);
            assert_eq!(
                g.inspect_join_request(&f, &KEY, u64::from(i)),
                JoinVerdict::Allow,
                "nonce {} should pass",
                i
            );
        }
        // Ring is full. Push one more distinct nonce — this overwrites
        // slot 0 (which held nonce 0).
        let f_evict = make_join_request(JOIN_EUI, DEV_EUI, depth, &KEY);
        assert_eq!(
            g.inspect_join_request(&f_evict, &KEY, 9_999),
            JoinVerdict::Allow
        );
        // Nonce 0 is now forgotten — replay-of-0 should pass again.
        let f_zero = make_join_request(JOIN_EUI, DEV_EUI, 0, &KEY);
        assert_eq!(
            g.inspect_join_request(&f_zero, &KEY, 10_000),
            JoinVerdict::Allow,
            "nonce 0 should be re-accepted after eviction"
        );
        // But the most recent nonce (depth) should still be tracked.
        let f_recent = make_join_request(JOIN_EUI, DEV_EUI, depth, &KEY);
        assert_eq!(
            g.inspect_join_request(&f_recent, &KEY, 10_001),
            JoinVerdict::Replay {
                kind: ReplayKind::DevNonce,
                value: u32::from(depth),
            }
        );
    }

    #[test]
    fn dev_nonce_isolated_per_dev_eui() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let other_dev = [99u8; 8];
        let f1 = make_join_request(JOIN_EUI, DEV_EUI, 7, &KEY);
        let f2 = make_join_request(JOIN_EUI, other_dev, 7, &KEY);
        assert_eq!(g.inspect_join_request(&f1, &KEY, 1), JoinVerdict::Allow);
        // Same DevNonce, different DevEUI → not a replay.
        assert_eq!(g.inspect_join_request(&f2, &KEY, 2), JoinVerdict::Allow);
    }

    // -----------------------------------------------------------------------
    // JoinAccept / JoinNonce
    // -----------------------------------------------------------------------

    #[test]
    fn join_accept_v1_1_monotonic_violation_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let f1 = make_join_accept(10, &KEY);
        let f2 = make_join_accept(11, &KEY);
        let f3 = make_join_accept(11, &KEY); // not strictly increasing
        let f4 = make_join_accept(5, &KEY); // decreasing
        assert_eq!(
            g.inspect_join_accept(&f1, &KEY, &JOIN_EUI, 1),
            JoinVerdict::Allow
        );
        assert_eq!(
            g.inspect_join_accept(&f2, &KEY, &JOIN_EUI, 2),
            JoinVerdict::Allow
        );
        assert_eq!(
            g.inspect_join_accept(&f3, &KEY, &JOIN_EUI, 3),
            JoinVerdict::Replay {
                kind: ReplayKind::JoinNonce,
                value: 11
            }
        );
        assert_eq!(
            g.inspect_join_accept(&f4, &KEY, &JOIN_EUI, 4),
            JoinVerdict::Replay {
                kind: ReplayKind::JoinNonce,
                value: 5
            }
        );
    }

    #[test]
    fn join_accept_v1_0_random_repeat_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_0);
        let f_a = make_join_accept(0x00AA_AAAA, &KEY);
        let f_b = make_join_accept(0x0011_1111, &KEY); // smaller is fine in 1.0.x
        let f_a2 = make_join_accept(0x00AA_AAAA, &KEY);
        assert_eq!(
            g.inspect_join_accept(&f_a, &KEY, &JOIN_EUI, 1),
            JoinVerdict::Allow
        );
        assert_eq!(
            g.inspect_join_accept(&f_b, &KEY, &JOIN_EUI, 2),
            JoinVerdict::Allow
        );
        assert_eq!(
            g.inspect_join_accept(&f_a2, &KEY, &JOIN_EUI, 3),
            JoinVerdict::Replay {
                kind: ReplayKind::JoinNonce,
                value: 0x00AA_AAAA
            }
        );
    }

    #[test]
    fn join_accept_mic_mismatch_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let mut f = make_join_accept(7, &KEY);
        f[14] ^= 0x80; // flip a bit in MIC
        assert_eq!(
            g.inspect_join_accept(&f, &KEY, &JOIN_EUI, 1),
            JoinVerdict::MicMismatch
        );
    }

    #[test]
    fn join_accept_too_short_rejected() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        assert_eq!(
            g.inspect_join_accept(&[0u8; 5], &KEY, &JOIN_EUI, 0),
            JoinVerdict::Malformed {
                reason: MalformedReason::TooShort
            }
        );
    }

    // -----------------------------------------------------------------------
    // Data-frame MIC
    // -----------------------------------------------------------------------

    #[test]
    fn data_frame_valid_mic_allowed() {
        let g = JoinGuard::new(LoraWanVersion::V1_1);
        let frame = make_uplink(&KEY, [1, 2, 3, 4], 7);
        assert_eq!(
            g.verify_data_frame(&frame, &KEY, FrameDir::Up, [1, 2, 3, 4], 7),
            JoinVerdict::Allow
        );
    }

    #[test]
    fn data_frame_mic_corruption_rejected() {
        let g = JoinGuard::new(LoraWanVersion::V1_1);
        let mut frame = make_uplink(&KEY, [1, 2, 3, 4], 7);
        frame[10] ^= 0x01; // flip MIC bit
        assert_eq!(
            g.verify_data_frame(&frame, &KEY, FrameDir::Up, [1, 2, 3, 4], 7),
            JoinVerdict::MicMismatch
        );
    }

    #[test]
    fn data_frame_dir_mismatch_rejected() {
        let g = JoinGuard::new(LoraWanVersion::V1_1);
        let frame = make_uplink(&KEY, [1, 2, 3, 4], 7);
        // Frame is uplink but caller asserts downlink → MType/dir mismatch.
        assert_eq!(
            g.verify_data_frame(&frame, &KEY, FrameDir::Down, [1, 2, 3, 4], 7),
            JoinVerdict::Malformed {
                reason: MalformedReason::MTypeMismatch
            }
        );
    }

    #[test]
    fn data_frame_too_short_rejected() {
        let g = JoinGuard::new(LoraWanVersion::V1_1);
        assert_eq!(
            g.verify_data_frame(&[0u8; 4], &KEY, FrameDir::Up, [0; 4], 0),
            JoinVerdict::Malformed {
                reason: MalformedReason::TooShort
            }
        );
    }

    #[test]
    fn data_frame_wrong_fcnt_breaks_mic() {
        // Caller's full_fcnt feeds the B0 block. If wrong, MIC differs.
        let g = JoinGuard::new(LoraWanVersion::V1_1);
        let frame = make_uplink(&KEY, [1, 2, 3, 4], 7);
        assert_eq!(
            g.verify_data_frame(&frame, &KEY, FrameDir::Up, [1, 2, 3, 4], 8),
            JoinVerdict::MicMismatch
        );
    }

    // -----------------------------------------------------------------------
    // Reset / capacity
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_all_tracking() {
        let mut g = JoinGuard::new(LoraWanVersion::V1_1);
        let f = make_join_request(JOIN_EUI, DEV_EUI, 1, &KEY);
        assert_eq!(g.inspect_join_request(&f, &KEY, 0), JoinVerdict::Allow);
        assert_eq!(g.tracked_devices(), 1);
        g.reset();
        assert_eq!(g.tracked_devices(), 0);
        // Same nonce now allowed again.
        let f2 = make_join_request(JOIN_EUI, DEV_EUI, 1, &KEY);
        assert_eq!(g.inspect_join_request(&f2, &KEY, 0), JoinVerdict::Allow);
    }
}
