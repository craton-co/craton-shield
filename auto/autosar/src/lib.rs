// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! AUTOSAR Classic and Adaptive platform integration for Craton Shield.
//!
//! Provides `SecOC` (Secure Onboard Communication), `IdsM` (Intrusion Detection System Manager),
//! MCAL CAN/Ethernet adapter traits, `Ara::com` service discovery, DEM event management,
//! `BswM` mode management, and `ComM` communication management.
//! - **`Ara::com` service discovery** — Lightweight types for AUTOSAR Adaptive
//!   SOME/IP service instance registration and lookup.
//!
//! # Public API
//!
//! Pre-1.0 (workspace version 0.7.0); see ROADMAP for 1.0 stability
//! commitment. The `SecOc`, `IdsM`, `Dem`, `BswM`, `ComM`, and `AraCom`
//! types and their associated traits (`McalCanDriver`, `McalEthernetDriver`,
//! `SomeIpAuthProvider`) form the public surface and are governed by
//! `DEPRECATION.md`. The deprecated `NoOpSomeIpAuth` stub was removed.

#![no_std]
// `deny` (not `forbid`) so that security-critical zeroization can use
// `write_volatile` via a scoped `#[allow(unsafe_code)]`, matching the
// approach in `vs-diag-gateway`. All other unsafe usage remains denied.
#![deny(unsafe_code)]
#![deny(missing_docs)]

// Prevent the stub feature from being compiled into release binaries.
// Uses both `not(debug_assertions)` AND explicit release profile detection
// to guard against optimized debug builds where debug_assertions is off.
#[cfg(all(feature = "stub", not(debug_assertions), not(test)))]
compile_error!(
    "The `stub` feature must not be enabled in release builds. \
     Stub MCAL drivers provide no security. Remove the `stub` feature \
     for production builds."
);

#[cfg(test)]
extern crate alloc;

use vs_hal::{CanBus, EthernetPhy, RawCanFrame, RawEthFrame};
#[cfg(test)]
use vs_types::PayloadHash;
use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_auto::BusType;

/// Convert a generic `source_type` back to a [`BusType`] for AUTOSAR reporting.
///
/// Returns `None` for unrecognized source types instead of silently
/// defaulting, which could mask bugs when new bus types are added.
fn source_type_to_bus(source_type: u8) -> Option<BusType> {
    match source_type {
        vs_types::SOURCE_CAN => Some(BusType::Can),
        vs_types::SOURCE_CAN_FD => Some(BusType::CanFd),
        vs_types::SOURCE_ETHERNET => Some(BusType::AutomotiveEthernet),
        vs_types_auto::SOURCE_LIN => Some(BusType::Lin),
        vs_types_auto::SOURCE_FLEXRAY => Some(BusType::FlexRay),
        _ => None,
    }
}

// ============================================================================
// SecOC — Secure Onboard Communication
// ============================================================================

/// Maximum number of `SecOC`-protected PDU definitions.
pub const MAX_SECOC_PDUS: usize = 64;

/// Maximum freshness value size in bytes (up to 64-bit counters).
pub const MAX_FRESHNESS_LEN: usize = 8;

/// Maximum MAC truncation length in bytes.
pub const MAX_MAC_LEN: usize = 16;

/// Minimum MAC truncation length in bytes per the `SecOC` specification.
///
/// AUTOSAR `SecOC` allows MAC truncation, but the truncated MAC must be at
/// least 32 bits (4 bytes) wide. Anything shorter has too few bits of
/// integrity to provide meaningful authentication — a 24-bit tag, for
/// example, can be brute-forced in roughly 2^23 attempts.
///
/// This is enforced both at PDU registration time (config-load) and at
/// Tx/Rx time as a belt-and-suspenders defense in case a config is bypassed
/// or mutated after registration.
pub const MAC_LEN_4: u8 = 4;

/// Result of `SecOC` verification on an incoming PDU.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SecOcVerifyResult {
    /// MAC verification passed; freshness value is current.
    Pass,
    /// MAC verification failed (corrupted or tampered payload).
    MacMismatch,
    /// Freshness value is stale (potential replay attack).
    FreshnessExpired,
    /// The PDU ID is not configured for `SecOC` protection.
    UnknownPdu,
    /// Underlying crypto operation failed.
    CryptoFailure,
    /// The frame structure is invalid (e.g. DLC exceeds maximum or frame is
    /// too short to contain the expected trailer).
    InvalidFrame,
}

/// Direction of a `SecOC`-protected PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SecOcDirection {
    /// Outbound: we generate the MAC + freshness before transmission.
    Tx,
    /// Inbound: we verify the MAC + freshness on reception.
    Rx,
}

/// Configuration for a single `SecOC`-protected PDU.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SecOcPduConfig {
    /// CAN arbitration ID this config applies to.
    pub can_id: u32,
    /// Key slot identifier used for HMAC computation.
    pub key_id: u32,
    /// AUTOSAR `SecOC` Data ID (per `SWS_SecOC` §7.5).
    ///
    /// Bound to every MAC computation as a domain-separation tag so that a
    /// MAC computed for one PDU cannot be replayed against another PDU that
    /// happens to share the same `key_id`. Frames whose `data_id` does not
    /// match the registered PDU fail MAC verification regardless of whether
    /// the underlying authenticated payload and freshness are valid.
    pub data_id: u16,
    /// Truncated MAC length in bytes (1..=16).
    pub mac_len: u8,
    /// Freshness value length in bytes (1..=8).
    pub freshness_len: u8,
    /// Direction (Tx or Rx).
    pub direction: SecOcDirection,
    /// Whether this slot is active.
    pub active: bool,
}

impl SecOcPduConfig {
    const fn empty() -> Self {
        Self {
            can_id: 0,
            key_id: 0,
            data_id: 0,
            mac_len: 0,
            freshness_len: 0,
            direction: SecOcDirection::Rx,
            active: false,
        }
    }
}

/// Freshness value state for a single PDU.
#[derive(Debug, Clone, Copy)]
struct FreshnessState {
    /// Current freshness counter value (big-endian in the low bytes).
    counter: u64,
    /// Timestamp (microseconds) of the last successful verification or transmission.
    last_seen_us: u64,
    /// Maximum allowed age in microseconds before freshness is considered stale.
    max_age_us: u64,
}

impl FreshnessState {
    const fn new(max_age_us: u64) -> Self {
        Self {
            counter: 0,
            last_seen_us: 0,
            max_age_us,
        }
    }
}

/// Trait for the cryptographic backend used by `SecOC`.
///
/// `SecOC` delegates MAC computation and verification to an external provider
/// (typically backed by the HSM via `vs_hal::HsmHardware` or the software
/// `CryptoProvider`).
pub trait SecOcCrypto {
    /// Compute a truncated HMAC over `data` using the given `key_id`.
    ///
    /// Writes exactly `mac_len` bytes into `mac_out`.
    fn compute_mac(
        &self,
        key_id: u32,
        data: &[u8],
        mac_out: &mut [u8],
        mac_len: usize,
    ) -> Result<(), VsError>;

    /// Verify a truncated HMAC. Returns `true` if the MAC matches.
    ///
    /// The default implementation computes the MAC and performs a
    /// constant-time comparison (byte-by-byte XOR accumulator) to prevent
    /// timing side-channel attacks. Implementors may override this, but
    /// **must** use constant-time comparison.
    fn verify_mac(
        &self,
        key_id: u32,
        data: &[u8],
        expected_mac: &[u8],
        mac_len: usize,
    ) -> Result<bool, VsError> {
        let mut computed = [0u8; MAX_MAC_LEN];
        self.compute_mac(key_id, data, &mut computed, mac_len)?;
        if expected_mac.len() < mac_len || computed.len() < mac_len {
            return Ok(false);
        }
        // Constant-time comparison: XOR accumulator avoids short-circuit.
        let mut acc: u8 = 0;
        for i in 0..mac_len {
            acc |= computed[i] ^ expected_mac[i];
        }
        // Prevent the compiler from optimizing away the constant-time
        // XOR accumulation loop above. Without this barrier, an aggressive
        // optimizer could short-circuit the comparison, leaking timing
        // information about which byte position differs first.
        let acc = core::hint::black_box(acc);
        // Zeroize the computed MAC to prevent extraction from memory dumps.
        // Uses `write_volatile` to prevent the compiler from eliding the
        // zeroization, matching the approach in `vs-diag-gateway`.
        #[allow(unsafe_code)]
        for byte in computed.iter_mut().take(MAX_MAC_LEN) {
            // SAFETY: `byte` is a valid, aligned, dereferenceable pointer
            // derived from a live mutable reference to a stack-local array.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::hint::black_box(computed.as_ptr());
        Ok(acc == 0)
    }
}

/// Maximum PDU ID value supported by the fast O(1) index.
///
/// CAN IDs above this value fall back to linear scan. 2048 covers the
/// entire standard (11-bit) CAN ID space with a modest memory cost
/// (2 × 2048 bytes ≈ 4 KiB, using `u8` slots with `0xFF` as sentinel).
pub const MAX_PDU_ID_INDEX: usize = 2048;

// Compile-time guarantee that every valid slot index fits in a u8 and
// 0xFF remains available as a sentinel ("no mapping").
const _: () = assert!(
    MAX_SECOC_PDUS < 255,
    "MAX_SECOC_PDUS must be < 255 for u8 sentinel"
);

/// Buffer length for the `SecOC` MAC input.
///
/// The MAC is computed over `data_id (2 B) || auth_data (<= 64 B) ||
/// full_freshness_value (8 B)`. Sized to comfortably fit a CAN-FD payload
/// plus the data ID and full freshness counter — the upper bound is
/// `2 + 64 + 8 = 74` bytes, but rounding up to 80 keeps the arithmetic
/// clean without measurable cost.
const MAC_INPUT_BUF_LEN: usize = 80;

/// Decode a big-endian byte slice (1..=8 bytes) into a `u64`.
///
/// Used to interpret the truncated freshness value carried on the wire.
/// Returns `0` for an empty slice (defensive — callers ensure `len >= 1`).
fn decode_be_bytes(bytes: &[u8]) -> u64 {
    match bytes.len() {
        8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(bytes);
            u64::from_be_bytes(buf)
        }
        4 => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(bytes);
            u64::from(u32::from_be_bytes(buf))
        }
        _ => {
            let mut v: u64 = 0;
            for &b in bytes {
                v = (v << 8) | u64::from(b);
            }
            v
        }
    }
}

/// Reconstruct the full 64-bit freshness value from the truncated wire bytes.
///
/// Per `SWS_SecOC` §7.5, only the low-order `fv_len` bytes of the full
/// freshness counter are transmitted; the receiver reassembles the full FV
/// using the high bytes of its stored counter and handles rollover.
///
/// Rules:
///   * `fv_len >= 8` — the full FV is on the wire, return as-is.
///   * `truncated_fv > stored_low` — same epoch as the stored counter; the
///     high bits come from the stored counter.
///   * `truncated_fv == stored_low` — exact replay (same low bits, no
///     forward progress). Return the stored counter unchanged so the
///     monotonicity check in `verify_rx` rejects with `FreshnessExpired`
///     rather than speculatively jumping a whole epoch (which would mask a
///     stale frame as `MacMismatch`).
///   * `truncated_fv < stored_low` — the low half wrapped at least once;
///     advance the high portion by one epoch and OR the wire bytes in.
fn reconstruct_full_fv(stored_counter: u64, truncated_fv: u64, fv_len: usize) -> u64 {
    if fv_len >= 8 {
        return truncated_fv;
    }
    let shift = fv_len * 8;
    // Width-1..=7 cannot overflow u64 when shifted (max shift = 56).
    let low_mask: u64 = (1u64 << shift) - 1;
    let stored_high = stored_counter & !low_mask;
    let stored_low = stored_counter & low_mask;
    if truncated_fv > stored_low {
        // Same epoch as the stored counter — high bits unchanged.
        stored_high | truncated_fv
    } else if truncated_fv == stored_low {
        // Exact replay of the last accepted FV. Surface this to the
        // monotonicity check unchanged so it returns `FreshnessExpired`.
        stored_counter
    } else {
        // Wire low bits wrapped: advance the high portion by one epoch.
        // saturating_add prevents wrap-around at the 64-bit boundary; if
        // the high half ever maxes out, the resulting full FV stays at
        // `u64::MAX` and the monotonicity check rejects further frames.
        let next_high = stored_high.saturating_add(1u64 << shift);
        next_high | truncated_fv
    }
}

/// `SecOC` manager — handles freshness tracking and MAC verification for
/// AUTOSAR Secure Onboard Communication.
///
/// Manages up to [`MAX_SECOC_PDUS`] protected PDU definitions with per-PDU
/// freshness counters and configurable MAC truncation lengths.
///
/// # Memory footprint
///
/// This struct is **approximately 6 KiB** in size. The bulk of that memory
/// is the two `[u8; MAX_PDU_ID_INDEX]` (≈ 4 KiB) lookup tables plus the
/// `[SecOcPduConfig; MAX_SECOC_PDUS]` and `[FreshnessState; MAX_SECOC_PDUS]`
/// arrays. Allocate on the stack of an isolated task or as a `static mut`
/// guarded by `critical-section` primitives — do **not** place it on a
/// shallow stack such as an interrupt handler.
///
/// `active_pdu_count` is cached and updated incrementally on
/// register/unregister to avoid an O(n) scan over the slot array.
pub struct SecOcManager<C: SecOcCrypto> {
    pdus: [SecOcPduConfig; MAX_SECOC_PDUS],
    freshness: [FreshnessState; MAX_SECOC_PDUS],
    crypto: C,
    default_max_age_us: u64,
    verify_count: u64,
    verify_fail_count: u64,
    /// Cached count of active PDU slots. Maintained by `register_pdu` /
    /// `unregister_pdu` so [`SecOcManager::active_pdu_count`] is O(1).
    /// Bounded by `MAX_SECOC_PDUS < 255` (asserted at compile time).
    active_pdu_count: u8,
    /// Fast O(1) lookup: `pdu_id_index[can_id]` stores the slot index for
    /// **Rx** PDUs whose `can_id < MAX_PDU_ID_INDEX`. Tx PDUs are indexed
    /// separately in `pdu_id_index_tx`. `0xFF` means "no mapping".
    pdu_id_index_rx: [u8; MAX_PDU_ID_INDEX],
    /// Fast O(1) lookup for **Tx** PDUs. `0xFF` means "no mapping".
    pdu_id_index_tx: [u8; MAX_PDU_ID_INDEX],
}

impl<C: SecOcCrypto> SecOcManager<C> {
    /// Create a new `SecOC` manager.
    ///
    /// `default_max_age_us` is the maximum freshness age applied to new PDU
    /// registrations (e.g. `100_000` for 100 ms).
    pub fn new(crypto: C, default_max_age_us: u64) -> Self {
        Self {
            pdus: [SecOcPduConfig::empty(); MAX_SECOC_PDUS],
            freshness: [FreshnessState::new(default_max_age_us); MAX_SECOC_PDUS],
            crypto,
            default_max_age_us,
            verify_count: 0,
            verify_fail_count: 0,
            active_pdu_count: 0,
            pdu_id_index_rx: [0xFF; MAX_PDU_ID_INDEX],
            pdu_id_index_tx: [0xFF; MAX_PDU_ID_INDEX],
        }
    }

    /// Register a `SecOC`-protected PDU. Returns the slot index on success.
    #[allow(clippy::cast_possible_truncation)] // i < MAX_SECOC_PDUS < 255 (compile-time asserted)
    pub fn register_pdu(&mut self, config: SecOcPduConfig) -> Result<usize, VsError> {
        if config.mac_len == 0 || config.mac_len as usize > MAX_MAC_LEN {
            return Err(VsError::PolicyViolation);
        }
        // SecOC spec: truncated MAC must be at least MAC_LEN_4 (32 bits) to
        // provide meaningful integrity. Anything shorter (e.g. 24 bits) is
        // rejected with `InvalidConfig` so callers can distinguish "I asked
        // for an unsupported length" from "I tried to disable MAC entirely".
        if config.mac_len < MAC_LEN_4 {
            return Err(VsError::InvalidConfig);
        }
        if config.freshness_len == 0 || config.freshness_len as usize > MAX_FRESHNESS_LEN {
            return Err(VsError::PolicyViolation);
        }
        // Single-pass scan: check for duplicates and find the first empty
        // slot simultaneously, halving the iteration count.
        //
        // We reject two flavours of conflict:
        //   1. Same (can_id, direction) — the obvious "PDU already registered"
        //      collision that breaks the O(1) index.
        //   2. Same (key_id, data_id, direction) — reusing a key without a
        //      distinct Data ID means two PDUs would share an entire MAC
        //      domain. A frame authenticated for one PDU could then be
        //      replayed against the other (the MAC validates because the
        //      Data ID prepended in `verify_rx` / `prepare_tx` is identical).
        //      Requiring callers to disambiguate via `data_id` enforces
        //      `SWS_SecOC` §7.5 domain separation at config-load time.
        let mut empty_slot: Option<usize> = None;
        for (i, pdu) in self.pdus.iter().enumerate() {
            if pdu.active {
                if pdu.can_id == config.can_id && pdu.direction == config.direction {
                    return Err(VsError::PolicyViolation);
                }
                if pdu.key_id == config.key_id
                    && pdu.data_id == config.data_id
                    && pdu.direction == config.direction
                {
                    return Err(VsError::PolicyViolation);
                }
            } else if empty_slot.is_none() {
                empty_slot = Some(i);
            }
        }
        let i = empty_slot.ok_or(VsError::ResourceExhausted)?;
        self.pdus[i] = SecOcPduConfig {
            active: true,
            ..config
        };
        self.freshness[i] = FreshnessState::new(self.default_max_age_us);

        // Populate the O(1) index for standard CAN IDs.
        if (config.can_id as usize) < MAX_PDU_ID_INDEX {
            let idx_table = match config.direction {
                SecOcDirection::Rx => &mut self.pdu_id_index_rx,
                SecOcDirection::Tx => &mut self.pdu_id_index_tx,
            };
            idx_table[config.can_id as usize] = i as u8;
        }

        // Maintain the cached active-slot counter. Bounded by MAX_SECOC_PDUS
        // (< 255, compile-time asserted), so saturating_add is defensive.
        self.active_pdu_count = self.active_pdu_count.saturating_add(1);

        Ok(i)
    }

    /// Unregister a `SecOC` PDU by slot index.
    pub fn unregister_pdu(&mut self, slot: usize) -> Result<(), VsError> {
        let pdu = self.pdus.get_mut(slot).ok_or(VsError::PolicyViolation)?;
        if !pdu.active {
            return Err(VsError::NotInitialized);
        }
        // Clear the O(1) index entry.
        if (pdu.can_id as usize) < MAX_PDU_ID_INDEX {
            let idx_table = match pdu.direction {
                SecOcDirection::Rx => &mut self.pdu_id_index_rx,
                SecOcDirection::Tx => &mut self.pdu_id_index_tx,
            };
            idx_table[pdu.can_id as usize] = 0xFF;
        }
        *pdu = SecOcPduConfig::empty();
        self.freshness[slot] = FreshnessState::new(self.default_max_age_us);
        self.active_pdu_count = self.active_pdu_count.saturating_sub(1);
        Ok(())
    }

    /// Look up the slot index for a given CAN ID and direction.
    ///
    /// Uses the O(1) index for standard CAN IDs (`< MAX_PDU_ID_INDEX`);
    /// falls back to linear scan for extended IDs.
    fn find_pdu(&self, can_id: u32, direction: SecOcDirection) -> Option<usize> {
        if (can_id as usize) < MAX_PDU_ID_INDEX {
            let idx_table = match direction {
                SecOcDirection::Rx => &self.pdu_id_index_rx,
                SecOcDirection::Tx => &self.pdu_id_index_tx,
            };
            let slot = idx_table[can_id as usize];
            if slot != 0xFF {
                let slot = slot as usize;
                // Verify the slot is still active (defensive).
                if self.pdus[slot].active {
                    return Some(slot);
                }
            }
            return None;
        }
        // Fallback: linear scan for extended / high CAN IDs.
        self.pdus
            .iter()
            .position(|p| p.active && p.can_id == can_id && p.direction == direction)
    }

    /// Verify an incoming `SecOC`-protected CAN frame.
    ///
    /// The frame payload is expected to contain:
    ///   `[authentic_data ... | freshness_value | truncated_mac]`
    ///
    /// The freshness value and MAC are extracted from the tail of the payload
    /// according to the PDU configuration.
    #[must_use = "SecOC verification outcome must drive the bus action"]
    pub fn verify_rx(&mut self, frame: &RawCanFrame, now_us: u64) -> SecOcVerifyResult {
        self.verify_count = self.verify_count.saturating_add(1);

        let Some(slot) = self.find_pdu(frame.id, SecOcDirection::Rx) else {
            return SecOcVerifyResult::UnknownPdu;
        };

        let pdu = &self.pdus[slot];
        let mac_len = pdu.mac_len as usize;
        let fv_len = pdu.freshness_len as usize;
        let trailer_len = fv_len + mac_len;
        let dlc = frame.dlc as usize;

        // Belt-and-suspenders: refuse to verify against a MAC shorter than
        // `MAC_LEN_4`. `register_pdu` already rejects this, but a stored
        // config could have been mutated by an out-of-tree adapter or
        // memory-corruption attack. Failing closed here turns that bypass
        // into a `MacMismatch` rather than silently accepting a 24-bit tag.
        if pdu.mac_len < MAC_LEN_4 {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::MacMismatch;
        }

        // Guard against DLC exceeding the RawCanFrame data array (64 bytes).
        if dlc > 64 {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::InvalidFrame;
        }

        // Frame must be large enough to hold freshness + MAC.
        if dlc < trailer_len {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::InvalidFrame;
        }

        let data = &frame.data[..dlc];
        let auth_data_len = dlc - trailer_len;
        let auth_data = &data[..auth_data_len];
        let fv_bytes = &data[auth_data_len..auth_data_len + fv_len];
        let received_mac = &data[auth_data_len + fv_len..dlc];

        // Decode the **truncated** freshness value on the wire (big-endian).
        // Per `SWS_SecOC` §7.5, only the low-order `freshness_len` bytes of
        // the full 32/64-bit freshness counter travel on the bus; the
        // receiver reconstructs the full FV from its local high bits with
        // rollover handling. This is the low-order portion only.
        let truncated_fv: u64 = decode_be_bytes(fv_bytes);

        // Reconstruct the full freshness value with rollover handling.
        // When `freshness_len == 8`, the full FV is on the wire and no
        // reconstruction is required. Otherwise, the high bits come from
        // the stored counter, and if the received low bits are less than
        // the stored low bits, the upper portion rolled over by one.
        let fs = &self.freshness[slot];
        let full_fv = reconstruct_full_fv(fs.counter, truncated_fv, fv_len);

        // Check freshness monotonicity against the reconstructed full FV.
        // The reconstructed value must strictly exceed the stored counter.
        // Without this, a stale wire FV that happens to equal a low-bit
        // value from an earlier rollover cycle could be replayed.
        if full_fv <= fs.counter {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::FreshnessExpired;
        }

        // Check time-based freshness. When last_seen_us == 0 (first frame),
        // we still verify that current_time_us is not zero to avoid accepting
        // frames at the epoch boundary.
        if fs.last_seen_us == 0 {
            if now_us == 0 {
                self.verify_fail_count = self.verify_fail_count.saturating_add(1);
                return SecOcVerifyResult::FreshnessExpired;
            }
        } else if now_us.saturating_sub(fs.last_seen_us) > fs.max_age_us {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::FreshnessExpired;
        }

        // Build verification input: data_id || auth_data || full_freshness_value.
        //
        // - `data_id` (2 bytes BE) provides domain separation per
        //   `SWS_SecOC` §7.5 so that a MAC for one PDU cannot be replayed
        //   against another PDU that shares the same `key_id`.
        // - `full_freshness_value` is the reconstructed 64-bit counter (not
        //   the truncated wire bytes), so an attacker cannot create
        //   ambiguity by replaying frames across rollover boundaries.
        //
        // CAN-FD max payload (64 B) + 2 B data_id + 8 B full FV = 74.
        let mut verify_buf = [0u8; MAC_INPUT_BUF_LEN];
        let data_id_bytes = pdu.data_id.to_be_bytes();
        let full_fv_bytes = full_fv.to_be_bytes();
        let mac_input_len = data_id_bytes.len() + auth_data_len + full_fv_bytes.len();
        if mac_input_len > verify_buf.len() {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::MacMismatch;
        }
        verify_buf[..data_id_bytes.len()].copy_from_slice(&data_id_bytes);
        verify_buf[data_id_bytes.len()..data_id_bytes.len() + auth_data_len]
            .copy_from_slice(auth_data);
        verify_buf[data_id_bytes.len() + auth_data_len..mac_input_len]
            .copy_from_slice(&full_fv_bytes);

        let mac_ok = match self.crypto.verify_mac(
            pdu.key_id,
            &verify_buf[..mac_input_len],
            received_mac,
            mac_len,
        ) {
            Ok(true) => true,
            Ok(false) => false,
            Err(_) => {
                self.verify_fail_count = self.verify_fail_count.saturating_add(1);
                return SecOcVerifyResult::CryptoFailure;
            }
        };

        if !mac_ok {
            self.verify_fail_count = self.verify_fail_count.saturating_add(1);
            return SecOcVerifyResult::MacMismatch;
        }

        // Update freshness state on success using the full reconstructed FV.
        self.freshness[slot].counter = full_fv;
        self.freshness[slot].last_seen_us = now_us;

        SecOcVerifyResult::Pass
    }

    /// Prepare a Tx frame by appending freshness value and MAC.
    ///
    /// Writes the freshness value and truncated MAC into the frame payload
    /// starting at offset `auth_data_len`. Updates `frame.dlc` accordingly.
    ///
    /// Returns the new DLC on success.
    #[allow(clippy::cast_possible_truncation)] // fv byte extraction and DLC bounded by 64
    pub fn prepare_tx(
        &mut self,
        frame: &mut RawCanFrame,
        auth_data_len: usize,
        now_us: u64,
    ) -> Result<usize, VsError> {
        let slot = self
            .find_pdu(frame.id, SecOcDirection::Tx)
            .ok_or(VsError::NotInitialized)?;

        let pdu = &self.pdus[slot];
        let mac_len = pdu.mac_len as usize;
        let fv_len = pdu.freshness_len as usize;
        let new_dlc = auth_data_len + fv_len + mac_len;

        // Belt-and-suspenders: refuse to emit a frame whose configured MAC
        // is shorter than `MAC_LEN_4`. Mirrors the guard in `verify_rx`.
        if pdu.mac_len < MAC_LEN_4 {
            return Err(VsError::InvalidConfig);
        }

        if new_dlc > 64 {
            return Err(VsError::ResourceExhausted);
        }

        // Increment freshness counter. The full 64-bit counter advances on
        // every Tx and is bound to the MAC, while only the low-order
        // `freshness_len` bytes travel on the wire per `SWS_SecOC` §7.5.
        self.freshness[slot].counter = self.freshness[slot]
            .counter
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.freshness[slot].last_seen_us = now_us;
        let full_fv = self.freshness[slot].counter;

        // Transmit only the low-order `freshness_len` bytes of the full FV
        // (big-endian). For `fv_len == 8` this is the entire counter; for
        // shorter widths the receiver reconstructs the high bytes via
        // rollover handling against its stored counter.
        let full_fv_bytes = full_fv.to_be_bytes();
        let skip = full_fv_bytes.len() - fv_len;
        frame.data[auth_data_len..auth_data_len + fv_len].copy_from_slice(&full_fv_bytes[skip..]);

        // Build MAC input: data_id || auth_data || full_freshness_value.
        //
        // `data_id` (2 bytes BE) is prepended for domain separation so the
        // MAC binds to the PDU identity (`SWS_SecOC` §7.5). The full 64-bit
        // FV — not the truncated wire bytes — is appended so an attacker
        // cannot collapse multiple rollover cycles into a single MAC input.
        let mut mac_input = [0u8; MAC_INPUT_BUF_LEN];
        let data_id_bytes = pdu.data_id.to_be_bytes();
        let input_len = data_id_bytes.len() + auth_data_len + full_fv_bytes.len();
        if input_len > mac_input.len() {
            return Err(VsError::ResourceExhausted);
        }
        mac_input[..data_id_bytes.len()].copy_from_slice(&data_id_bytes);
        mac_input[data_id_bytes.len()..data_id_bytes.len() + auth_data_len]
            .copy_from_slice(&frame.data[..auth_data_len]);
        mac_input[data_id_bytes.len() + auth_data_len..input_len].copy_from_slice(&full_fv_bytes);

        // Compute MAC into a temporary buffer, then copy truncated result.
        let mut mac_buf = [0u8; MAX_MAC_LEN];
        self.crypto
            .compute_mac(pdu.key_id, &mac_input[..input_len], &mut mac_buf, mac_len)?;

        frame.data[auth_data_len + fv_len..new_dlc].copy_from_slice(&mac_buf[..mac_len]);
        frame.dlc = new_dlc as u8;

        Ok(new_dlc)
    }

    /// Return `(total_verifications, failed_verifications)`.
    pub fn stats(&self) -> (u64, u64) {
        (self.verify_count, self.verify_fail_count)
    }

    /// Return the number of active PDU registrations.
    ///
    /// O(1) — backed by the cached `active_pdu_count` counter, which is
    /// maintained by `register_pdu` and `unregister_pdu`.
    pub fn active_pdu_count(&self) -> usize {
        self.active_pdu_count as usize
    }

    /// Get the current freshness counter for a slot.
    pub fn freshness_counter(&self, slot: usize) -> Option<u64> {
        if slot < MAX_SECOC_PDUS && self.pdus[slot].active {
            Some(self.freshness[slot].counter)
        } else {
            None
        }
    }
}

// ============================================================================
// IdsM — Intrusion Detection System Manager
// ============================================================================

/// Maximum number of queued `IdsM` security events.
pub const MAX_IDSM_EVENTS: usize = 32;

/// AUTOSAR `IdsM` security event type identifiers.
///
/// Maps to AUTOSAR `IdsM_SecurityEventType` with `Craton Shield`-specific
/// extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum IdsmEventType {
    /// Anomalous CAN frame detected (ID spoofing, abnormal rate, etc.).
    CanAnomaly,
    /// Anomalous Ethernet traffic detected.
    EthAnomaly,
    /// `SecOC` MAC verification failure.
    SecOcFailure,
    /// UDS brute-force or unauthorized diagnostic access attempt.
    DiagIntrusion,
    /// Firmware integrity violation.
    IntegrityViolation,
    /// Cross-bus correlated multi-vector attack.
    CorrelatedAttack,
    /// OTA update validation failure.
    OtaViolation,
    /// Generic policy violation.
    PolicyViolation,
}

/// AUTOSAR `IdsM` security event severity (maps to `IdsM` SEV levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum IdsmSeverity {
    /// Informational, no action required.
    Sev0,
    /// Low-priority event for post-mortem analysis.
    Sev1,
    /// Medium-priority, warrants investigation.
    Sev2,
    /// High-priority, active threat detected.
    Sev3,
    /// Critical, immediate response required (e.g. bus isolation).
    Sev4,
}

/// A single `IdsM` security event ready for reporting.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdsmSecurityEvent {
    /// Monotonic event sequence number.
    pub sequence: u64,
    /// Event type classification.
    pub event_type: IdsmEventType,
    /// Severity level.
    pub severity: IdsmSeverity,
    /// Source bus type.
    pub bus: BusType,
    /// Source identifier (CAN ID, IP, etc.).
    pub source_id: u32,
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
    /// Context-specific data (first 8 bytes of payload hash).
    pub context: [u8; 8],
}

/// `IdsM` reporter — converts `Craton Shield` [`SecurityAlert`]s into AUTOSAR
/// `IdsM` security events and queues them for the AUTOSAR Dem/`IdsM` stack.
///
/// Supports two overflow modes:
/// - **Drop** (default): new events are dropped when the queue is full.
/// - **Overwrite**: oldest events are overwritten when the queue is full,
///   ensuring the most recent events are always available. Preferred during
///   sustained attacks where recent events are more valuable.
pub struct IdsmReporter {
    events: [Option<IdsmSecurityEvent>; MAX_IDSM_EVENTS],
    head: usize,
    tail: usize,
    count: usize,
    sequence: u64,
    total_reported: u64,
    total_dropped: u64,
    /// When `true`, a full queue overwrites the oldest event instead of
    /// rejecting new events.
    overwrite_on_full: bool,
}

impl IdsmReporter {
    /// Create a new `IdsM` reporter with an empty event queue (drop mode).
    pub fn new() -> Self {
        Self {
            events: [None; MAX_IDSM_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
            sequence: 0,
            total_reported: 0,
            total_dropped: 0,
            overwrite_on_full: false,
        }
    }

    /// Create a new `IdsM` reporter that overwrites oldest events on overflow.
    ///
    /// Preferred for sustained attack scenarios where the most recent
    /// events are more valuable than preserving older entries.
    pub fn new_overwrite() -> Self {
        Self {
            overwrite_on_full: true,
            ..Self::new()
        }
    }

    /// Enqueue a pre-built [`IdsmSecurityEvent`] into the ring buffer.
    ///
    /// Handles overflow according to the configured mode: in drop mode,
    /// returns `Err(VsError::ResourceExhausted)` when the queue is full.
    /// In overwrite mode, the oldest event is discarded to make room.
    ///
    /// This is the single shared path for all `report_*` methods.
    fn enqueue_event(&mut self, event: IdsmSecurityEvent) -> Result<u64, VsError> {
        if self.count >= MAX_IDSM_EVENTS {
            if self.overwrite_on_full {
                // Overwrite the oldest event by advancing head.
                self.head = (self.head + 1) % MAX_IDSM_EVENTS;
                self.count -= 1;
                self.total_dropped = self.total_dropped.saturating_add(1);
            } else {
                self.total_dropped = self.total_dropped.saturating_add(1);
                return Err(VsError::ResourceExhausted);
            }
        }

        self.events[self.tail] = Some(event);
        self.tail = (self.tail + 1) % MAX_IDSM_EVENTS;
        self.count += 1;
        let seq = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        self.total_reported = self.total_reported.saturating_add(1);

        Ok(seq)
    }

    /// Convert a `Craton Shield` [`SecurityAlert`] into an `IdsM` event and enqueue it.
    ///
    /// Returns `Ok(sequence)` on success, `Err(VsError::ResourceExhausted)`
    /// if the queue is full and overwrite mode is disabled, or
    /// `Err(VsError::InvalidInput)` if the alert's `source_type` does not
    /// map to a known [`BusType`].
    pub fn report_alert(&mut self, alert: &SecurityAlert) -> Result<u64, VsError> {
        let event_type = Self::map_event_type(alert);
        let severity = Self::map_severity(alert.severity);
        let bus = source_type_to_bus(alert.source_type).ok_or(VsError::InvalidInput)?;

        let mut context = [0u8; 8];
        // Defensive: `PayloadHash::as_bytes()` is currently >= 8 bytes, but
        // future changes to that type must not panic this conversion path.
        // Fall back to all-zero context if the hash is shorter than 8 bytes.
        let hash_bytes = alert.payload_hash.as_bytes();
        context.copy_from_slice(hash_bytes.get(..8).unwrap_or(&[0u8; 8]));

        let event = IdsmSecurityEvent {
            sequence: self.sequence,
            event_type,
            severity,
            bus,
            source_id: alert.source_id,
            timestamp_us: alert.timestamp_us,
            context,
        };

        self.enqueue_event(event)
    }

    /// Report a `SecOC` verification failure as an `IdsM` event.
    pub fn report_secoc_failure(
        &mut self,
        can_id: u32,
        result: SecOcVerifyResult,
        timestamp_us: u64,
        bus: BusType,
    ) -> Result<u64, VsError> {
        let severity = match result {
            SecOcVerifyResult::MacMismatch => IdsmSeverity::Sev3,
            SecOcVerifyResult::FreshnessExpired => IdsmSeverity::Sev2,
            SecOcVerifyResult::CryptoFailure => IdsmSeverity::Sev4,
            _ => IdsmSeverity::Sev1,
        };

        let mut context = [0u8; 8];
        context[0] = result as u8;

        let event = IdsmSecurityEvent {
            sequence: self.sequence,
            event_type: IdsmEventType::SecOcFailure,
            severity,
            bus,
            source_id: can_id,
            timestamp_us,
            context,
        };

        self.enqueue_event(event)
    }

    /// Report an integrity violation (e.g. OTA manifest hash mismatch,
    /// firmware measurement failure) as an `IdsM` event with `Sev4` severity.
    pub fn report_integrity_violation(
        &mut self,
        source_id: u32,
        context_bytes: &[u8],
        timestamp_us: u64,
        bus: BusType,
    ) -> Result<u64, VsError> {
        let mut context = [0u8; 8];
        let copy_len = context_bytes.len().min(8);
        context[..copy_len].copy_from_slice(&context_bytes[..copy_len]);

        let event = IdsmSecurityEvent {
            sequence: self.sequence,
            event_type: IdsmEventType::IntegrityViolation,
            severity: IdsmSeverity::Sev4,
            bus,
            source_id,
            timestamp_us,
            context,
        };

        self.enqueue_event(event)
    }

    /// Report an OTA validation failure as an `IdsM` event.
    pub fn report_ota_violation(
        &mut self,
        context_bytes: &[u8],
        timestamp_us: u64,
        bus: BusType,
    ) -> Result<u64, VsError> {
        let mut context = [0u8; 8];
        let copy_len = context_bytes.len().min(8);
        context[..copy_len].copy_from_slice(&context_bytes[..copy_len]);

        let event = IdsmSecurityEvent {
            sequence: self.sequence,
            event_type: IdsmEventType::OtaViolation,
            severity: IdsmSeverity::Sev4,
            bus,
            source_id: vs_types_auto::SOURCE_ID_OTA_RESERVED, // Reserved OTA source ID
            timestamp_us,
            context,
        };

        self.enqueue_event(event)
    }

    /// Dequeue the next pending `IdsM` event for delivery to the AUTOSAR stack.
    pub fn dequeue(&mut self) -> Option<IdsmSecurityEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % MAX_IDSM_EVENTS;
        self.count = self.count.saturating_sub(1);
        event
    }

    /// Number of events currently in the queue.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Return `(total_reported, total_dropped)`.
    pub fn stats(&self) -> (u64, u64) {
        (self.total_reported, self.total_dropped)
    }

    /// Number of events dropped due to queue overflow.
    ///
    /// Monitor this metric to detect sustained attacks that exceed the
    /// `IdsM` queue capacity. A growing dropped count indicates that security
    /// events are being lost and the queue size or overflow mode should
    /// be reconsidered.
    pub fn dropped_count(&self) -> u64 {
        self.total_dropped
    }

    /// Map a [`SecurityAlert`] to the appropriate [`IdsmEventType`].
    fn map_event_type(alert: &SecurityAlert) -> IdsmEventType {
        // Check for reserved source IDs first (bus-independent events).
        if alert.source_id == vs_types_auto::SOURCE_ID_OTA_RESERVED {
            return if alert.severity >= AlertSeverity::Critical {
                IdsmEventType::OtaViolation
            } else {
                IdsmEventType::IntegrityViolation
            };
        }

        let Some(bus) = source_type_to_bus(alert.source_type) else {
            return IdsmEventType::PolicyViolation;
        };
        match bus {
            BusType::Can | BusType::CanFd => {
                if alert.severity >= AlertSeverity::High {
                    IdsmEventType::CorrelatedAttack
                } else {
                    IdsmEventType::CanAnomaly
                }
            }
            BusType::AutomotiveEthernet => IdsmEventType::EthAnomaly,
            // LIN and FlexRay anomalies use the same CAN-like reporting path.
            BusType::Lin | BusType::FlexRay => IdsmEventType::CanAnomaly,
        }
    }

    /// Map `Craton Shield` [`AlertSeverity`] to [`IdsmSeverity`].
    fn map_severity(severity: AlertSeverity) -> IdsmSeverity {
        match severity {
            AlertSeverity::Info => IdsmSeverity::Sev0,
            AlertSeverity::Low => IdsmSeverity::Sev1,
            AlertSeverity::Medium => IdsmSeverity::Sev2,
            AlertSeverity::High => IdsmSeverity::Sev3,
            AlertSeverity::Critical => IdsmSeverity::Sev4,
            // `AlertSeverity` is `#[non_exhaustive]`. Unknown future variants
            // map to the highest IDSM severity for fail-loud reporting.
            _ => IdsmSeverity::Sev4,
        }
    }
}

impl Default for IdsmReporter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MCAL Adapter — AUTOSAR Classic MCAL ↔ Craton Shield HAL bridge
// ============================================================================

/// AUTOSAR MCAL CAN driver status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum McalCanStatus {
    /// Driver has not been initialized.
    Uninit,
    /// Driver is ready for normal Tx/Rx operations.
    Ready,
    /// Controller has entered bus-off state due to TEC overflow.
    BusOff,
    /// Controller is in error-passive state (Rx still allowed, restricted Tx).
    ErrorPassive,
}

/// Trait for AUTOSAR Classic MCAL CAN driver abstraction.
///
/// An OEM-specific implementation bridges to the real MCAL `Can_Write` /
/// `Can_MainFunction_Read` calls. `Craton Shield` uses this via
/// [`McalCanAdapter`] to satisfy the [`CanBus`] HAL trait.
pub trait McalCanDriver {
    /// Read the next received CAN L-PDU from the MCAL driver.
    /// Returns `None` if no frame is pending.
    fn can_main_function_read(&mut self) -> Option<RawCanFrame>;

    /// Submit a CAN L-PDU for transmission via `Can_Write`.
    fn can_write(&mut self, frame: &RawCanFrame) -> Result<(), VsError>;

    /// Return the configured bus bitrate.
    fn can_get_bitrate(&self) -> u32;

    /// Query the current controller status.
    fn can_get_status(&self) -> McalCanStatus;
}

/// Adapter that wraps an AUTOSAR [`McalCanDriver`] into a `Craton Shield`
/// [`CanBus`] implementation.
pub struct McalCanAdapter<D: McalCanDriver> {
    driver: D,
}

impl<D: McalCanDriver> McalCanAdapter<D> {
    /// Wrap an existing [`McalCanDriver`] in the [`CanBus`] adapter.
    pub fn new(driver: D) -> Self {
        Self { driver }
    }

    /// Access the underlying MCAL driver.
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// Access the underlying MCAL driver mutably.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }
}

impl<D: McalCanDriver + Send> CanBus for McalCanAdapter<D> {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        match self.driver.can_get_status() {
            McalCanStatus::Uninit => Err(VsError::NotInitialized),
            McalCanStatus::BusOff => Err(VsError::BusError),
            McalCanStatus::Ready | McalCanStatus::ErrorPassive => {
                Ok(self.driver.can_main_function_read())
            }
        }
    }

    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        match self.driver.can_get_status() {
            McalCanStatus::Uninit => Err(VsError::NotInitialized),
            McalCanStatus::BusOff => Err(VsError::BusError),
            _ => self.driver.can_write(frame),
        }
    }

    fn bitrate(&self) -> u32 {
        self.driver.can_get_bitrate()
    }

    fn is_bus_off(&self) -> bool {
        self.driver.can_get_status() == McalCanStatus::BusOff
    }
}

/// Trait for AUTOSAR Classic MCAL Ethernet driver abstraction.
pub trait McalEthDriver {
    /// Read the next received Ethernet frame from the MCAL driver.
    fn eth_receive(&mut self) -> Option<RawEthFrame>;

    /// Transmit an Ethernet frame via the MCAL driver.
    fn eth_transmit(&mut self, data: &[u8]) -> Result<(), VsError>;

    /// Return the link speed in Mbit/s.
    fn eth_get_link_speed(&self) -> u32;

    /// Query whether the Ethernet link is up.
    fn eth_is_link_up(&self) -> bool;
}

/// Adapter that wraps an AUTOSAR [`McalEthDriver`] into a `Craton Shield`
/// [`EthernetPhy`] implementation.
pub struct McalEthAdapter<D: McalEthDriver> {
    driver: D,
}

impl<D: McalEthDriver> McalEthAdapter<D> {
    /// Wrap an existing [`McalEthDriver`] in the [`EthernetPhy`] adapter.
    pub fn new(driver: D) -> Self {
        Self { driver }
    }
}

impl<D: McalEthDriver + Send> EthernetPhy for McalEthAdapter<D> {
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        if !self.driver.eth_is_link_up() {
            return Err(VsError::NotInitialized);
        }
        Ok(self.driver.eth_receive())
    }

    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError> {
        if !self.driver.eth_is_link_up() {
            return Err(VsError::NotInitialized);
        }
        self.driver.eth_transmit(data)
    }

    fn link_speed_mbps(&self) -> u32 {
        self.driver.eth_get_link_speed()
    }

    fn link_is_up(&self) -> bool {
        self.driver.eth_is_link_up()
    }
}

// ============================================================================
// Stub MCAL Drivers — test / stub-feature concrete implementations
// ============================================================================

/// Concrete stub CAN MCAL driver for testing and integration bring-up.
///
/// Returns a single fixed [`RawCanFrame`] on the first read, then `None`.
/// All transmissions succeed silently. Gated behind `#[cfg(test)]` or the
/// `stub` feature so it is never compiled into production images.
#[cfg(any(test, feature = "stub"))]
pub struct StubMcalCanDriver {
    /// Pre-loaded frame returned by the first call to `can_main_function_read`.
    pending: Option<RawCanFrame>,
    /// Reported bus bitrate.
    pub bitrate: u32,
    /// Current controller status.
    pub status: McalCanStatus,
}

#[cfg(any(test, feature = "stub"))]
impl Default for StubMcalCanDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "stub"))]
impl StubMcalCanDriver {
    /// Create a new stub CAN driver in `Ready` state at 500 kbit/s with a
    /// default test frame (CAN ID `0x7FF`, DLC 8, all-`0xAA` payload).
    pub fn new() -> Self {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        let mut data = [0u8; 64];
        let mut i = 0;
        while i < 8 {
            data[i] = 0xAA;
            i += 1;
        }
        Self {
            pending: Some(RawCanFrame {
                id: 0x7FF,
                dlc: 8,
                data,
                timestamp_us: 1_000,
                is_fd: false,
                is_extended: false,
            }),
            bitrate: 500_000,
            status: McalCanStatus::Ready,
        }
    }

    /// Enqueue a frame to be returned by the next `can_main_function_read`.
    pub fn set_pending(&mut self, frame: RawCanFrame) {
        self.pending = Some(frame);
    }
}

#[cfg(any(test, feature = "stub"))]
impl McalCanDriver for StubMcalCanDriver {
    fn can_main_function_read(&mut self) -> Option<RawCanFrame> {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        self.pending.take()
    }
    fn can_write(&mut self, _frame: &RawCanFrame) -> Result<(), VsError> {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        Ok(())
    }
    fn can_get_bitrate(&self) -> u32 {
        self.bitrate
    }
    fn can_get_status(&self) -> McalCanStatus {
        self.status
    }
}

/// Concrete stub Ethernet MCAL driver for testing and integration bring-up.
///
/// Always reports link-up at 100 Mbit/s. Receives yield `None`; transmits
/// succeed silently. Gated behind `#[cfg(test)]` or the `stub` feature.
#[cfg(any(test, feature = "stub"))]
pub struct StubMcalEthDriver {
    /// Whether the Ethernet link is up.
    pub link_up: bool,
    /// Reported link speed in Mbit/s.
    pub link_speed: u32,
}

#[cfg(any(test, feature = "stub"))]
impl Default for StubMcalEthDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "stub"))]
impl StubMcalEthDriver {
    /// Create a new stub Ethernet driver with link up at 100 Mbit/s.
    pub fn new() -> Self {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        Self {
            link_up: true,
            link_speed: 100,
        }
    }
}

#[cfg(any(test, feature = "stub"))]
impl McalEthDriver for StubMcalEthDriver {
    fn eth_receive(&mut self) -> Option<RawEthFrame> {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        None
    }
    fn eth_transmit(&mut self, _data: &[u8]) -> Result<(), VsError> {
        debug_assert!(
            cfg!(any(test, debug_assertions)),
            "AUTOSAR stub must never execute in release builds"
        );
        Ok(())
    }
    fn eth_get_link_speed(&self) -> u32 {
        self.link_speed
    }
    fn eth_is_link_up(&self) -> bool {
        self.link_up
    }
}

// ============================================================================
// Ara::com — AUTOSAR Adaptive SOME/IP Service Discovery
// ============================================================================

/// Maximum number of registered `Ara::com` service instances.
pub const MAX_SERVICE_INSTANCES: usize = 16;

/// SOME/IP service identifier.
pub type ServiceId = u16;

/// SOME/IP instance identifier.
pub type InstanceId = u16;

/// State of a service instance in the `Ara::com` registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ServiceState {
    /// Instance is registered but not yet offered/available.
    Registered,
    /// Instance is offered and available for subscription.
    Offered,
    /// Instance was found via service discovery (client side).
    Available,
    /// Instance has been stopped or is unavailable.
    Stopped,
}

/// A registered SOME/IP service instance.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ServiceInstance {
    /// SOME/IP service identifier.
    pub service_id: ServiceId,
    /// SOME/IP instance identifier.
    pub instance_id: InstanceId,
    /// Major service version (interface-level compatibility).
    pub major_version: u8,
    /// Minor service version (additive compatibility).
    pub minor_version: u32,
    /// Lifecycle state of the registered instance.
    pub state: ServiceState,
    /// Whether this slot is occupied.
    active: bool,
}

impl ServiceInstance {
    const fn empty() -> Self {
        Self {
            service_id: 0,
            instance_id: 0,
            major_version: 0,
            minor_version: 0,
            state: ServiceState::Stopped,
            active: false,
        }
    }
}

/// Lightweight `Ara::com` service registry for SOME/IP service discovery.
///
/// Tracks service instances offered and found on the AUTOSAR Adaptive
/// platform. Used by `Craton Shield` to monitor the service landscape and
/// detect rogue or unauthorized service advertisements.
pub struct ServiceRegistry {
    instances: [ServiceInstance; MAX_SERVICE_INSTANCES],
}

impl ServiceRegistry {
    /// Create an empty service registry with no registered instances.
    pub fn new() -> Self {
        Self {
            instances: [ServiceInstance::empty(); MAX_SERVICE_INSTANCES],
        }
    }

    /// Register a new service instance. Returns the slot index.
    pub fn register(
        &mut self,
        service_id: ServiceId,
        instance_id: InstanceId,
        major_version: u8,
        minor_version: u32,
    ) -> Result<usize, VsError> {
        // Check for duplicates.
        for inst in &self.instances {
            if inst.active && inst.service_id == service_id && inst.instance_id == instance_id {
                return Err(VsError::PolicyViolation);
            }
        }
        for (i, slot) in self.instances.iter_mut().enumerate() {
            if !slot.active {
                *slot = ServiceInstance {
                    service_id,
                    instance_id,
                    major_version,
                    minor_version,
                    state: ServiceState::Registered,
                    active: true,
                };
                return Ok(i);
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Transition a service instance to the Offered state.
    ///
    /// The service must be in `Registered` state. Returns
    /// `Err(VsError::PolicyViolation)` for invalid state transitions.
    pub fn offer(&mut self, slot: usize) -> Result<(), VsError> {
        let inst = self
            .instances
            .get_mut(slot)
            .ok_or(VsError::PolicyViolation)?;
        if !inst.active {
            return Err(VsError::NotInitialized);
        }
        if inst.state != ServiceState::Registered {
            return Err(VsError::PolicyViolation);
        }
        inst.state = ServiceState::Offered;
        Ok(())
    }

    /// Mark a service instance as Available (client-side discovery result).
    ///
    /// The service must be in `Offered` state. Returns
    /// `Err(VsError::PolicyViolation)` for invalid state transitions.
    pub fn mark_available(&mut self, slot: usize) -> Result<(), VsError> {
        let inst = self
            .instances
            .get_mut(slot)
            .ok_or(VsError::PolicyViolation)?;
        if !inst.active {
            return Err(VsError::NotInitialized);
        }
        if inst.state != ServiceState::Offered {
            return Err(VsError::PolicyViolation);
        }
        inst.state = ServiceState::Available;
        Ok(())
    }

    /// Stop (unregister) a service instance.
    pub fn stop(&mut self, slot: usize) -> Result<(), VsError> {
        let inst = self
            .instances
            .get_mut(slot)
            .ok_or(VsError::PolicyViolation)?;
        if !inst.active {
            return Err(VsError::NotInitialized);
        }
        inst.state = ServiceState::Stopped;
        inst.active = false;
        Ok(())
    }

    /// Find a service instance by service ID and instance ID.
    pub fn find(
        &self,
        service_id: ServiceId,
        instance_id: InstanceId,
    ) -> Option<(usize, &ServiceInstance)> {
        self.instances.iter().enumerate().find(|(_, inst)| {
            inst.active && inst.service_id == service_id && inst.instance_id == instance_id
        })
    }

    /// Return the number of active service instances.
    pub fn active_count(&self) -> usize {
        self.instances.iter().filter(|i| i.active).count()
    }

    /// Iterate over all active service instances.
    pub fn iter_active(&self) -> impl Iterator<Item = (usize, &ServiceInstance)> {
        self.instances.iter().enumerate().filter(|(_, i)| i.active)
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SOME/IP Authentication — TLS/DTLS integration point
// ============================================================================

/// Trait for SOME/IP-SD (Service Discovery) transport-layer authentication.
///
/// AUTOSAR Adaptive Platform supports TLS/DTLS for securing SOME/IP
/// communication channels. This trait provides the integration point for
/// platform-specific TLS implementations.
///
/// There is no default implementation since v1.0.0 — production AUTOSAR
/// Adaptive deployments must provide a real implementation backed by the
/// platform's TLS stack
/// (e.g., OpenSSL, mbedTLS, wolfSSL).
///
/// # Security note
///
/// Without a real implementation, SOME/IP service discovery and method
/// calls are vulnerable to spoofing attacks on the vehicle Ethernet network.
/// See `THREAT_MODEL.md` § T5 for details.
pub trait SomeIpAuthProvider {
    /// Verify the authenticity of a SOME/IP-SD offer or find message.
    ///
    /// Returns `Ok(true)` if the message is authenticated, `Ok(false)` if
    /// authentication fails verifiably, or `Err` if no authentication
    /// backend is configured / an internal error occurred.
    ///
    /// Default: **fail-closed with explicit signalling** — every call
    /// returns `Err(VsError::NotInitialized)` so callers can distinguish
    /// "the peer's credentials are invalid" (`Ok(false)`) from "no auth
    /// backend is wired up at all" (`Err`). Previously the default
    /// silently returned `Ok(false)`, which masked misconfiguration as a
    /// run-of-the-mill verification failure.
    fn verify_sd_message(
        &self,
        _source_ip: u32,
        _service_id: u16,
        _instance_id: u16,
        _payload: &[u8],
    ) -> Result<bool, VsError> {
        Err(VsError::NotInitialized)
    }

    /// Verify a SOME/IP method call or event notification.
    ///
    /// Returns `Ok(true)` if the session is authenticated, `Ok(false)` if
    /// authentication fails verifiably, or `Err` if no authentication
    /// backend is configured / an internal error occurred.
    ///
    /// Default: **fail-closed with explicit signalling** — see
    /// [`Self::verify_sd_message`] for the rationale.
    fn verify_method_call(
        &self,
        _source_ip: u32,
        _service_id: u16,
        _method_id: u16,
        _session_id: u16,
        _payload: &[u8],
    ) -> Result<bool, VsError> {
        Err(VsError::NotInitialized)
    }

    /// Check if a TLS/DTLS session is established with the given peer.
    ///
    /// Default returns `false` — no session is ever established without a
    /// real backend.
    fn is_session_established(&self, _peer_ip: u32) -> bool {
        false
    }
}

// NoOpSomeIpAuth was removed in v0.7.0 (previously deprecated).
// Production AUTOSAR Adaptive deployments must provide a real
// `SomeIpAuthProvider` backed by TLS/DTLS. See `THREAT_MODEL.md` § T5
// for spoofing risks.

// ============================================================================
// Dem — Diagnostic Event Manager
// ============================================================================

/// Maximum number of monitored `Dem` events.
pub const MAX_DEM_EVENTS: usize = 64;

/// Status reported for a diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum DemEventStatus {
    /// Test completed — no fault detected.
    Passed,
    /// Test completed — fault detected.
    Failed,
    /// Test not yet completed — trending towards pass.
    Prepassed,
    /// Test not yet completed — trending towards fail.
    Prefailed,
}

/// Configuration for a single `Dem`-monitored event.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DemEventConfig {
    /// Unique event identifier.
    pub event_id: u16,
    /// Number of consecutive failures before the event is confirmed.
    pub debounce_threshold: u8,
    /// Number of consecutive passes before a confirmed event is healed.
    pub healing_threshold: u8,
    /// Whether this slot is active.
    pub active: bool,
}

impl DemEventConfig {
    const fn empty() -> Self {
        Self {
            event_id: 0,
            debounce_threshold: 0,
            healing_threshold: 0,
            active: false,
        }
    }
}

/// Runtime state for a single `Dem` event.
#[derive(Debug, Clone, Copy)]
struct DemEventState {
    status: DemEventStatus,
    fail_counter: u8,
    pass_counter: u8,
    occurrence_count: u64,
    last_failed_us: u64,
    last_passed_us: u64,
    confirmed: bool,
    /// Debounce counter for `Prepassed`/`Prefailed` transitions.
    /// Incremented on `Prefailed`, decremented on `Prepassed`.
    /// Clamped to the range -3..=3.
    /// Reaching -3 transitions to `Passed`; reaching 3 transitions to `Failed`.
    debounce_counter: i8,
}

impl DemEventState {
    const fn new() -> Self {
        Self {
            status: DemEventStatus::Passed,
            fail_counter: 0,
            pass_counter: 0,
            occurrence_count: 0,
            last_failed_us: 0,
            last_passed_us: 0,
            confirmed: false,
            debounce_counter: 0,
        }
    }
}

/// Maximum size of the data snapshot stored in a [`FreezeFrame`].
pub const FREEZE_FRAME_DATA_LEN: usize = 32;

/// A snapshot captured when a DEM event transitions to `Failed`.
///
/// Stores the timestamp, DTC number, and a fixed-size data array that can hold
/// environment data (e.g. ECU voltages, temperatures, bus state) at the time
/// the fault was detected.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FreezeFrame {
    /// Timestamp (microseconds) at which the freeze frame was captured.
    pub timestamp_us: u64,
    /// DTC (Diagnostic Trouble Code) number — typically derived from the
    /// event ID by the integrator's mapping table.
    pub dtc_number: u32,
    /// Raw environment data at the time of capture.
    pub data: [u8; FREEZE_FRAME_DATA_LEN],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

/// `Dem` manager — software-only fault memory that tracks diagnostic events
/// with debounce and healing logic.
///
/// When an event transitions to [`DemEventStatus::Failed`] and is confirmed,
/// a [`FreezeFrame`] is captured automatically. Retrieve it with
/// [`get_freeze_frame`](Self::get_freeze_frame).
pub struct DemManager {
    events: [(DemEventConfig, DemEventState); MAX_DEM_EVENTS],
    freeze_frames: [Option<FreezeFrame>; MAX_DEM_EVENTS],
    event_count: usize,
}

impl DemManager {
    /// Create a new `Dem` manager with no registered events.
    pub fn new() -> Self {
        Self {
            events: [(DemEventConfig::empty(), DemEventState::new()); MAX_DEM_EVENTS],
            freeze_frames: [None; MAX_DEM_EVENTS],
            event_count: 0,
        }
    }

    /// Register a monitored event. Returns the slot index on success.
    pub fn register_event(&mut self, config: DemEventConfig) -> Result<usize, VsError> {
        if config.debounce_threshold == 0 || config.healing_threshold == 0 {
            return Err(VsError::InvalidConfig);
        }
        // Check for duplicate event_id.
        for (cfg, _) in &self.events {
            if cfg.active && cfg.event_id == config.event_id {
                return Err(VsError::PolicyViolation);
            }
        }
        // Find an empty slot.
        for (i, (slot_cfg, slot_state)) in self.events.iter_mut().enumerate() {
            if !slot_cfg.active {
                *slot_cfg = DemEventConfig {
                    active: true,
                    ..config
                };
                *slot_state = DemEventState::new();
                self.event_count = self.event_count.saturating_add(1);
                return Ok(i);
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Report a pass or fail status for an event with debounce logic.
    ///
    /// On `Failed`: increment fail counter, reset pass counter.
    /// When `fail_counter >= debounce_threshold`, mark confirmed and capture
    /// a [`FreezeFrame`] (if one has not already been captured for this event).
    /// On `Passed`: increment pass counter, reset fail counter.
    /// When `pass_counter >= healing_threshold`, mark healed (unconfirmed).
    pub fn report_status(
        &mut self,
        event_id: u16,
        status: DemEventStatus,
        ts_us: u64,
    ) -> Result<(), VsError> {
        let slot_idx = self
            .find_event_index(event_id)
            .ok_or(VsError::InvalidInput)?;
        let (cfg, state) = &mut self.events[slot_idx];

        state.status = status;

        let was_confirmed = state.confirmed;

        match status {
            DemEventStatus::Failed => {
                state.debounce_counter = 0;
                state.fail_counter = state.fail_counter.saturating_add(1);
                state.pass_counter = 0;
                state.last_failed_us = ts_us;
                state.occurrence_count = state.occurrence_count.saturating_add(1);

                if state.fail_counter >= cfg.debounce_threshold {
                    state.confirmed = true;
                }
            }
            DemEventStatus::Prefailed => {
                state.debounce_counter = (state.debounce_counter + 1).min(3);
                state.fail_counter = state.fail_counter.saturating_add(1);
                state.pass_counter = 0;
                state.last_failed_us = ts_us;
                state.occurrence_count = state.occurrence_count.saturating_add(1);

                if state.debounce_counter >= 3 {
                    state.status = DemEventStatus::Failed;
                    state.confirmed = true;
                } else if state.fail_counter >= cfg.debounce_threshold {
                    state.confirmed = true;
                }
            }
            DemEventStatus::Passed => {
                state.debounce_counter = 0;
                state.pass_counter = state.pass_counter.saturating_add(1);
                state.fail_counter = 0;
                state.last_passed_us = ts_us;

                if state.pass_counter >= cfg.healing_threshold {
                    state.confirmed = false;
                }
            }
            DemEventStatus::Prepassed => {
                state.debounce_counter = (state.debounce_counter - 1).max(-3);
                state.pass_counter = state.pass_counter.saturating_add(1);
                state.fail_counter = 0;
                state.last_passed_us = ts_us;

                if state.debounce_counter <= -3 {
                    state.status = DemEventStatus::Passed;
                    state.confirmed = false;
                } else if state.pass_counter >= cfg.healing_threshold {
                    state.confirmed = false;
                }
            }
        }

        // Capture a freeze frame on the transition to confirmed-Failed.
        let (cfg, state) = &self.events[slot_idx];
        if state.confirmed && !was_confirmed {
            self.freeze_frames[slot_idx] = Some(FreezeFrame {
                timestamp_us: ts_us,
                dtc_number: cfg.event_id as u32,
                data: [0u8; FREEZE_FRAME_DATA_LEN],
                data_len: 0,
            });
        }

        Ok(())
    }

    /// Check if an event is confirmed failed.
    pub fn is_confirmed(&self, event_id: u16) -> bool {
        self.find_event(event_id)
            .is_some_and(|(_, state)| state.confirmed)
    }

    /// Retrieve the freeze frame captured for the event at the given slot
    /// index (as returned by [`register_event`](Self::register_event)).
    ///
    /// Returns `None` if the slot is out of range, inactive, or no freeze
    /// frame has been captured yet.
    pub fn get_freeze_frame(&self, event_index: usize) -> Option<&FreezeFrame> {
        if event_index >= MAX_DEM_EVENTS || !self.events[event_index].0.active {
            return None;
        }
        self.freeze_frames[event_index].as_ref()
    }

    /// Clear fault memory for a single event (including its freeze frame).
    pub fn clear_event(&mut self, event_id: u16) -> Result<(), VsError> {
        let idx = self
            .find_event_index(event_id)
            .ok_or(VsError::NotInitialized)?;
        self.events[idx].1 = DemEventState::new();
        self.freeze_frames[idx] = None;
        Ok(())
    }

    /// Unregister a monitored event, clearing its slot, freeze frame, and
    /// decrementing the event count.
    pub fn unregister_event(&mut self, event_id: u16) -> Result<(), VsError> {
        let idx = self
            .find_event_index(event_id)
            .ok_or(VsError::NotInitialized)?;
        self.events[idx].0 = DemEventConfig::empty();
        self.events[idx].1 = DemEventState::new();
        self.freeze_frames[idx] = None;
        self.event_count = self.event_count.saturating_sub(1);
        Ok(())
    }

    /// Clear all faults (reset all event states and freeze frames).
    pub fn clear_all(&mut self) {
        for i in 0..MAX_DEM_EVENTS {
            if self.events[i].0.active {
                self.events[i].1 = DemEventState::new();
                self.freeze_frames[i] = None;
            }
        }
    }

    /// Count confirmed faults.
    pub fn active_fault_count(&self) -> usize {
        self.events
            .iter()
            .filter(|(cfg, state)| cfg.active && state.confirmed)
            .count()
    }

    /// Iterate over confirmed faults, yielding `(slot, &DemEventConfig)`.
    pub fn iter_confirmed(&self) -> impl Iterator<Item = (usize, &DemEventConfig)> {
        self.events
            .iter()
            .enumerate()
            .filter(|(_, (cfg, state))| cfg.active && state.confirmed)
            .map(|(i, (cfg, _))| (i, cfg))
    }

    /// Return the number of registered events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Capture environment data into the freeze frame for a confirmed-Failed event.
    ///
    /// This should be called by the application layer when an event transitions
    /// to confirmed-Failed to record diagnostic environment data (ECU voltage,
    /// temperature, bus state, etc.) for later retrieval.
    ///
    /// Returns `Ok(())` on success, or `Err(VsError::NotFound)` if no freeze
    /// frame exists for the given event.
    #[allow(clippy::cast_possible_truncation)]
    pub fn capture_freeze_frame_data(&mut self, event_id: u32, data: &[u8]) -> Result<(), VsError> {
        let idx = self
            .find_event_index(event_id as u16)
            .ok_or(VsError::NotFound)?;
        if let Some(ref mut ff) = self.freeze_frames[idx] {
            let copy_len = data.len().min(FREEZE_FRAME_DATA_LEN);
            ff.data[..copy_len].copy_from_slice(&data[..copy_len]);
            ff.data_len = copy_len;
            Ok(())
        } else {
            Err(VsError::NotFound)
        }
    }

    /// Retrieve freeze frame data for a confirmed-Failed event.
    ///
    /// Returns the freeze frame if one has been captured for the given event.
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_freeze_frame_by_id(&self, event_id: u32) -> Option<&FreezeFrame> {
        let idx = self.find_event_index(event_id as u16)?;
        self.freeze_frames[idx].as_ref()
    }

    // TODO(perf): linear scan called from every `report_status` /
    // `is_confirmed` / `clear_event` path. For MAX_DEM_EVENTS = 64 the
    // observed cost is in the noise, but if profiling ever shows DEM as
    // hot we should mirror SecOcManager's index trick — though note the
    // u16 event-id space is too large for a dense `[u8; 65536]` table
    // (64 KiB), so a small sorted/secondary-hash structure is the right
    // approach rather than a direct-mapped array.
    fn find_event_index(&self, event_id: u16) -> Option<usize> {
        self.events
            .iter()
            .position(|(cfg, _)| cfg.active && cfg.event_id == event_id)
    }

    // TODO(perf): see `find_event_index` — same linear-scan caveat.
    fn find_event(&self, event_id: u16) -> Option<&(DemEventConfig, DemEventState)> {
        self.events
            .iter()
            .find(|(cfg, _)| cfg.active && cfg.event_id == event_id)
    }
}

impl Default for DemManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BswM — Basic Software Mode Manager
// ============================================================================

/// Maximum number of `BswM` mode transition rules.
pub const MAX_BSWM_RULES: usize = 16;

/// AUTOSAR BSW mode identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum BswModeId {
    /// Initial startup phase.
    Startup,
    /// Normal run mode.
    Run,
    /// Post-run phase (background tasks completing).
    PostRun,
    /// Low-power sleep mode.
    Sleep,
    /// Preparing for shutdown.
    PrepShutdown,
    /// Final shutdown.
    Shutdown,
}

/// A mode transition rule specifying an allowed `from → to` transition.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BswModeRule {
    /// Source mode.
    pub from: BswModeId,
    /// Target mode.
    pub to: BswModeId,
    /// Whether the transition condition is currently met.
    pub condition_met: bool,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl BswModeRule {
    const fn empty() -> Self {
        Self {
            from: BswModeId::Startup,
            to: BswModeId::Startup,
            condition_met: false,
            active: false,
        }
    }
}

/// `BswM` manager — manages BSW mode transitions with rule-based gating.
///
/// An optional [`transition_action`](Self::set_transition_action) callback is
/// invoked **after** every successful mode transition, receiving the previous
/// and new [`BswModeId`]. This allows integrators to trigger side-effects
/// (e.g. waking peripherals, notifying `EcuM`) without polling.
pub struct BswModeManager {
    current_mode: BswModeId,
    rules: [BswModeRule; MAX_BSWM_RULES],
    rule_count: usize,
    transition_count: u64,
    /// Optional callback invoked on every successful mode transition.
    /// Arguments: `(previous_mode, new_mode)`.
    transition_action: Option<fn(BswModeId, BswModeId)>,
}

impl BswModeManager {
    /// Create a new `BswM` manager starting in `Startup` mode.
    pub fn new() -> Self {
        Self {
            current_mode: BswModeId::Startup,
            rules: [BswModeRule::empty(); MAX_BSWM_RULES],
            rule_count: 0,
            transition_count: 0,
            transition_action: None,
        }
    }

    /// Register a callback that is invoked after every successful mode
    /// transition. The callback receives `(previous_mode, new_mode)`.
    ///
    /// Pass `None` to clear a previously registered callback.
    pub fn set_transition_action(&mut self, action: Option<fn(BswModeId, BswModeId)>) {
        self.transition_action = action;
    }

    /// Return the current BSW mode.
    pub fn current_mode(&self) -> BswModeId {
        self.current_mode
    }

    /// Register an allowed mode transition rule. Returns the rule slot index.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if a rule with the same
    /// `from` and `to` modes already exists.
    pub fn add_rule(&mut self, from: BswModeId, to: BswModeId) -> Result<usize, VsError> {
        // Reject duplicate rules to avoid wasting fixed-capacity slots.
        for slot in &self.rules {
            if slot.active && slot.from == from && slot.to == to {
                return Err(VsError::PolicyViolation);
            }
        }
        for (i, slot) in self.rules.iter_mut().enumerate() {
            if !slot.active {
                *slot = BswModeRule {
                    from,
                    to,
                    condition_met: true,
                    active: true,
                };
                self.rule_count = self.rule_count.saturating_add(1);
                return Ok(i);
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Remove a mode transition rule by slot index, clearing the slot and
    /// decrementing the rule count.
    pub fn remove_rule(&mut self, slot: usize) -> Result<(), VsError> {
        if slot >= MAX_BSWM_RULES || !self.rules[slot].active {
            return Err(VsError::InvalidInput);
        }
        self.rules[slot] = BswModeRule::empty();
        self.rule_count = self.rule_count.saturating_sub(1);
        Ok(())
    }

    /// Request a mode transition. Returns the new mode on success or
    /// `PolicyViolation` if no matching rule allows the transition.
    pub fn request_mode(&mut self, target: BswModeId) -> Result<BswModeId, VsError> {
        if target == self.current_mode {
            return Ok(self.current_mode);
        }

        // Check that an active rule allows this transition.
        let allowed = self
            .rules
            .iter()
            .any(|r| r.active && r.condition_met && r.from == self.current_mode && r.to == target);

        if !allowed {
            return Err(VsError::PolicyViolation);
        }

        let previous = self.current_mode;
        self.current_mode = target;
        self.transition_count = self.transition_count.saturating_add(1);

        if let Some(action) = self.transition_action {
            action(previous, target);
        }

        Ok(self.current_mode)
    }

    /// Return the total number of mode transitions performed.
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Return the number of registered mode transition rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Set or clear the condition flag on a transition rule by slot index.
    ///
    /// When a rule's condition is not met, [`request_mode`](Self::request_mode)
    /// will skip it even if the `from`/`to` modes match. This allows
    /// integrators to gate transitions on external conditions (e.g. ECU
    /// state, `NvM` readiness) without directly accessing the `rules` array.
    pub fn set_rule_condition(&mut self, slot: usize, met: bool) -> Result<(), VsError> {
        if slot >= MAX_BSWM_RULES || !self.rules[slot].active {
            return Err(VsError::InvalidInput);
        }
        self.rules[slot].condition_met = met;
        Ok(())
    }
}

impl Default for BswModeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ComM — Communication Manager
// ============================================================================

/// Maximum number of `ComM` communication channels.
pub const MAX_COMM_CHANNELS: usize = 8;

/// Communication mode for a `ComM` channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ComMMode {
    /// No communication — bus silent, transceiver may be off.
    NoCommunication,
    /// Silent communication — receive only, no transmission.
    SilentCommunication,
    /// Full communication — normal bidirectional bus access.
    FullCommunication,
}

/// A single `ComM` communication channel.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ComMChannel {
    /// Channel identifier.
    pub channel_id: u8,
    /// Current communication mode.
    pub mode: ComMMode,
    /// Underlying bus type.
    pub bus_type: BusType,
    /// Whether mode change inhibition is active.
    pub inhibit_active: bool,
    /// Number of active user requests for full communication.
    pub user_request_count: u8,
    /// Whether this slot is active. Kept non-`pub` so callers can only
    /// allocate/free slots via [`ComMManager::register_channel`].
    active: bool,
}

impl ComMChannel {
    const fn empty() -> Self {
        Self {
            channel_id: 0,
            mode: ComMMode::NoCommunication,
            bus_type: BusType::Can,
            inhibit_active: false,
            user_request_count: 0,
            active: false,
        }
    }
}

/// `ComM` manager — manages communication channel modes with inhibit support.
pub struct ComMManager {
    channels: [ComMChannel; MAX_COMM_CHANNELS],
    channel_count: usize,
}

impl ComMManager {
    /// Create a new `ComM` manager with no registered channels.
    pub fn new() -> Self {
        Self {
            channels: [ComMChannel::empty(); MAX_COMM_CHANNELS],
            channel_count: 0,
        }
    }

    /// Register a communication channel. Returns the slot index on success.
    pub fn register_channel(
        &mut self,
        channel_id: u8,
        bus_type: BusType,
    ) -> Result<usize, VsError> {
        // Check for duplicate channel_id.
        for ch in &self.channels {
            if ch.active && ch.channel_id == channel_id {
                return Err(VsError::PolicyViolation);
            }
        }
        // Find an empty slot.
        for (i, slot) in self.channels.iter_mut().enumerate() {
            if !slot.active {
                *slot = ComMChannel {
                    channel_id,
                    mode: ComMMode::NoCommunication,
                    bus_type,
                    inhibit_active: false,
                    user_request_count: 0,
                    active: true,
                };
                self.channel_count = self.channel_count.saturating_add(1);
                return Ok(i);
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Request full communication on a channel.
    pub fn request_full_com(&mut self, channel_id: u8) -> Result<(), VsError> {
        let ch = self
            .find_channel_mut(channel_id)
            .ok_or(VsError::NotInitialized)?;
        if ch.inhibit_active {
            return Err(VsError::PolicyViolation);
        }
        ch.mode = ComMMode::FullCommunication;
        ch.user_request_count = ch.user_request_count.saturating_add(1);
        Ok(())
    }

    /// Request silent communication on a channel (receive only, no transmission).
    ///
    /// The channel must currently be in `FullCommunication` mode. Transitioning
    /// from `NoCommunication` directly to `SilentCommunication` is not allowed.
    pub fn request_silent_com(&mut self, channel_id: u8) -> Result<(), VsError> {
        let ch = self
            .find_channel_mut(channel_id)
            .ok_or(VsError::NotInitialized)?;
        if ch.inhibit_active {
            return Err(VsError::PolicyViolation);
        }
        if ch.mode != ComMMode::FullCommunication {
            return Err(VsError::PolicyViolation);
        }
        ch.mode = ComMMode::SilentCommunication;
        Ok(())
    }

    /// Request no communication on a channel.
    pub fn request_no_com(&mut self, channel_id: u8) -> Result<(), VsError> {
        let ch = self
            .find_channel_mut(channel_id)
            .ok_or(VsError::NotInitialized)?;
        if ch.inhibit_active {
            return Err(VsError::PolicyViolation);
        }
        ch.mode = ComMMode::NoCommunication;
        ch.user_request_count = 0;
        Ok(())
    }

    /// Set or clear mode change inhibition on a channel.
    pub fn set_inhibit(&mut self, channel_id: u8, inhibit: bool) -> Result<(), VsError> {
        let ch = self
            .find_channel_mut(channel_id)
            .ok_or(VsError::NotInitialized)?;
        ch.inhibit_active = inhibit;
        Ok(())
    }

    /// Query the current communication mode of a channel.
    pub fn channel_mode(&self, channel_id: u8) -> Option<ComMMode> {
        self.find_channel(channel_id).map(|ch| ch.mode)
    }

    /// Count channels currently in `FullCommunication` mode.
    pub fn active_channel_count(&self) -> usize {
        self.channels
            .iter()
            .filter(|ch| ch.active && ch.mode == ComMMode::FullCommunication)
            .count()
    }

    /// Return the number of registered communication channels.
    pub fn channel_count(&self) -> usize {
        self.channel_count
    }

    /// Check whether communication is currently allowed on the given channel.
    ///
    /// Returns `true` only when the channel exists, is in
    /// [`FullCommunication`](ComMMode::FullCommunication) mode, **and** is not
    /// inhibited. The runtime should call this before transmitting on a bus
    /// to enforce the inhibit policy at the point of use.
    pub fn is_communication_allowed(&self, channel_id: u8) -> bool {
        self.find_channel(channel_id)
            .is_some_and(|ch| ch.mode == ComMMode::FullCommunication && !ch.inhibit_active)
    }

    fn find_channel(&self, channel_id: u8) -> Option<&ComMChannel> {
        self.channels
            .iter()
            .find(|ch| ch.active && ch.channel_id == channel_id)
    }

    fn find_channel_mut(&mut self, channel_id: u8) -> Option<&mut ComMChannel> {
        self.channels
            .iter_mut()
            .find(|ch| ch.active && ch.channel_id == channel_id)
    }
}

impl Default for ComMManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // -- Stub SecOcCrypto for testing --

    struct StubCrypto;

    impl SecOcCrypto for StubCrypto {
        fn compute_mac(
            &self,
            _key_id: u32,
            data: &[u8],
            mac_out: &mut [u8],
            mac_len: usize,
        ) -> Result<(), VsError> {
            // Simple XOR-fold "MAC" for testing (NOT cryptographically secure).
            let mut hash = 0u8;
            for &b in data {
                hash ^= b;
            }
            for byte in mac_out.iter_mut().take(mac_len) {
                *byte = hash;
            }
            Ok(())
        }

        fn verify_mac(
            &self,
            _key_id: u32,
            data: &[u8],
            expected_mac: &[u8],
            mac_len: usize,
        ) -> Result<bool, VsError> {
            let mut computed = [0u8; MAX_MAC_LEN];
            self.compute_mac(0, data, &mut computed, mac_len)?;
            Ok(computed[..mac_len] == expected_mac[..mac_len])
        }
    }

    /// Crypto that always fails, for error path testing.
    struct FailCrypto;

    impl SecOcCrypto for FailCrypto {
        fn compute_mac(
            &self,
            _key_id: u32,
            _data: &[u8],
            _mac_out: &mut [u8],
            _mac_len: usize,
        ) -> Result<(), VsError> {
            Err(VsError::CryptoError)
        }

        fn verify_mac(
            &self,
            _key_id: u32,
            _data: &[u8],
            _expected_mac: &[u8],
            _mac_len: usize,
        ) -> Result<bool, VsError> {
            Err(VsError::CryptoError)
        }
    }

    // -- Stub MCAL drivers --

    struct StubMcalCan {
        status: McalCanStatus,
        pending_frame: Option<RawCanFrame>,
        bitrate: u32,
    }

    impl McalCanDriver for StubMcalCan {
        fn can_main_function_read(&mut self) -> Option<RawCanFrame> {
            self.pending_frame.take()
        }
        fn can_write(&mut self, _frame: &RawCanFrame) -> Result<(), VsError> {
            Ok(())
        }
        fn can_get_bitrate(&self) -> u32 {
            self.bitrate
        }
        fn can_get_status(&self) -> McalCanStatus {
            self.status
        }
    }

    struct StubMcalEth {
        link_up: bool,
        speed: u32,
    }

    impl McalEthDriver for StubMcalEth {
        fn eth_receive(&mut self) -> Option<RawEthFrame> {
            None
        }
        fn eth_transmit(&mut self, _data: &[u8]) -> Result<(), VsError> {
            Ok(())
        }
        fn eth_get_link_speed(&self) -> u32 {
            self.speed
        }
        fn eth_is_link_up(&self) -> bool {
            self.link_up
        }
    }

    fn make_rx_config(can_id: u32) -> SecOcPduConfig {
        SecOcPduConfig {
            can_id,
            key_id: 1,
            // Default Data ID derived from `can_id` so each test PDU is
            // domain-separated; tests that need a specific Data ID set the
            // field explicitly after construction.
            data_id: can_id as u16,
            mac_len: 4,
            freshness_len: 2,
            direction: SecOcDirection::Rx,
            active: false,
        }
    }

    fn make_tx_config(can_id: u32) -> SecOcPduConfig {
        SecOcPduConfig {
            can_id,
            key_id: 1,
            data_id: can_id as u16,
            mac_len: 4,
            freshness_len: 2,
            direction: SecOcDirection::Tx,
            active: false,
        }
    }

    fn make_alert(severity: AlertSeverity, bus: BusType) -> SecurityAlert {
        SecurityAlert {
            id: 1,
            severity,
            source_type: bus.to_source_type(),
            source_id: 0x100,
            payload_hash: PayloadHash([0xAB; 32]),
            timestamp_us: 1_000_000,
        }
    }

    // ======================== SecOC Tests ========================

    #[test]
    fn secoc_register_and_count() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        assert_eq!(mgr.active_pdu_count(), 0);

        let slot = mgr.register_pdu(make_rx_config(0x100)).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(mgr.active_pdu_count(), 1);
    }

    #[test]
    fn secoc_reject_duplicate_can_id() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_rx_config(0x100)).unwrap();
        let result = mgr.register_pdu(make_rx_config(0x100));
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn secoc_same_id_different_direction_ok() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_rx_config(0x100)).unwrap();
        mgr.register_pdu(make_tx_config(0x100)).unwrap();
        assert_eq!(mgr.active_pdu_count(), 2);
    }

    #[test]
    fn secoc_unregister() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let slot = mgr.register_pdu(make_rx_config(0x100)).unwrap();
        mgr.unregister_pdu(slot).unwrap();
        assert_eq!(mgr.active_pdu_count(), 0);
    }

    #[test]
    fn secoc_unregister_inactive_fails() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        assert_eq!(mgr.unregister_pdu(0), Err(VsError::NotInitialized));
    }

    #[test]
    fn secoc_invalid_mac_len_rejected() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut cfg = make_rx_config(0x100);
        cfg.mac_len = 0;
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::PolicyViolation));
        cfg.mac_len = 17; // > MAX_MAC_LEN
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::PolicyViolation));
    }

    #[test]
    fn secoc_mac_len_below_min_rejected() {
        // Per the SecOC spec, a truncated MAC must be at least MAC_LEN_4.
        // mac_len = 3 is "non-zero but too short" and must be rejected with
        // InvalidConfig, distinct from the PolicyViolation that mac_len = 0
        // (disabled MAC) or mac_len > MAX_MAC_LEN (out of range) returns.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut cfg = make_rx_config(0x100);
        cfg.mac_len = 3;
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::InvalidConfig));
        cfg.mac_len = 1;
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::InvalidConfig));
        cfg.mac_len = 2;
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::InvalidConfig));
    }

    #[test]
    fn secoc_mac_len_4_accepted() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut cfg = make_rx_config(0x101);
        cfg.mac_len = MAC_LEN_4;
        assert!(mgr.register_pdu(cfg).is_ok());
    }

    #[test]
    fn secoc_mac_len_8_accepted() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut cfg = make_rx_config(0x102);
        cfg.mac_len = 8;
        assert!(mgr.register_pdu(cfg).is_ok());
    }

    #[test]
    fn secoc_verify_time_guard_rejects_short_mac() {
        // Belt-and-suspenders: even if a config is mutated post-load to set
        // mac_len below MAC_LEN_4 (simulating bypass of register_pdu), the
        // verify path must refuse to authenticate the frame and return
        // MacMismatch rather than silently accepting a too-short tag.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x500)).unwrap();
        let rx_slot = mgr.register_pdu(make_rx_config(0x500)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x500;
        frame.data[0] = 0x01;
        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();

        // Forge a config that bypassed register_pdu's check.
        mgr.pdus[rx_slot].mac_len = 3;

        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::MacMismatch,);
        assert!(mgr.verify_fail_count >= 1);
    }

    #[test]
    fn secoc_prepare_tx_guard_rejects_short_mac() {
        // Symmetric belt-and-suspenders for the Tx path.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let tx_slot = mgr.register_pdu(make_tx_config(0x501)).unwrap();
        mgr.pdus[tx_slot].mac_len = 2;

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x501;
        assert_eq!(
            mgr.prepare_tx(&mut frame, 1, 1000),
            Err(VsError::InvalidConfig),
        );
    }

    #[test]
    fn secoc_invalid_freshness_len_rejected() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut cfg = make_rx_config(0x100);
        cfg.freshness_len = 0;
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::PolicyViolation));
        cfg.freshness_len = 9; // > MAX_FRESHNESS_LEN
        assert_eq!(mgr.register_pdu(cfg), Err(VsError::PolicyViolation));
    }

    #[test]
    fn secoc_verify_unknown_pdu() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let frame = RawCanFrame::zeroed();
        assert_eq!(mgr.verify_rx(&frame, 0), SecOcVerifyResult::UnknownPdu);
    }

    #[test]
    fn secoc_tx_then_rx_roundtrip() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x200)).unwrap();
        mgr.register_pdu(make_rx_config(0x200)).unwrap();

        // Build a Tx frame with 4 bytes of auth data.
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x200;
        frame.data[0] = 0xDE;
        frame.data[1] = 0xAD;
        frame.data[2] = 0xBE;
        frame.data[3] = 0xEF;

        let new_dlc = mgr.prepare_tx(&mut frame, 4, 1000).unwrap();
        assert_eq!(new_dlc, 4 + 2 + 4); // auth_data + freshness + mac
        assert_eq!(frame.dlc, 10);

        // Verify on the Rx side.
        let result = mgr.verify_rx(&frame, 1000);
        assert_eq!(result, SecOcVerifyResult::Pass);
    }

    #[test]
    fn secoc_replay_detected() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x300)).unwrap();
        mgr.register_pdu(make_rx_config(0x300)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x300;
        frame.data[0] = 0x01;
        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();

        // First verify passes.
        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::Pass);

        // Replay the same frame — freshness counter hasn't advanced.
        assert_eq!(
            mgr.verify_rx(&frame, 1001),
            SecOcVerifyResult::FreshnessExpired
        );
    }

    #[test]
    fn secoc_tampered_mac_detected() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x400)).unwrap();
        mgr.register_pdu(make_rx_config(0x400)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x400;
        frame.data[0] = 0xAA;
        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();

        // Tamper with the MAC (last 4 bytes of the DLC region).
        let dlc = frame.dlc as usize;
        frame.data[dlc - 1] ^= 0xFF;

        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::MacMismatch);
    }

    #[test]
    fn secoc_crypto_failure_path() {
        let mut mgr = SecOcManager::new(FailCrypto, 100_000);
        mgr.register_pdu(make_rx_config(0x500)).unwrap();

        // Build a frame that matches the expected layout.
        // Layout for mac_len=4, freshness_len=2: [auth(2) | fv(2) | mac(4)]
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x500;
        frame.dlc = 8;
        frame.data[0] = 0x01; // auth data
        frame.data[1] = 0x02; // auth data
                              // Set freshness value > 0 so it passes the monotonicity check
                              // (fv must be > counter which starts at 0).
        frame.data[2] = 0x00; // freshness MSB
        frame.data[3] = 0x01; // freshness LSB = 1
                              // bytes 4-7: mac (zeros are fine — FailCrypto will error before comparison)

        assert_eq!(
            mgr.verify_rx(&frame, 1000),
            SecOcVerifyResult::CryptoFailure
        );
    }

    #[test]
    fn secoc_stats_tracking() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x600)).unwrap();
        mgr.register_pdu(make_rx_config(0x600)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x600;
        frame.data[0] = 0x01;
        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();

        let _ = mgr.verify_rx(&frame, 1000);

        // Replay triggers failure.
        let _ = mgr.verify_rx(&frame, 1001);

        let (total, failed) = mgr.stats();
        assert_eq!(total, 2);
        assert_eq!(failed, 1);
    }

    #[test]
    fn secoc_freshness_counter_advances() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let slot = mgr.register_pdu(make_tx_config(0x700)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x700;
        frame.data[0] = 0x01;

        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();
        assert_eq!(mgr.freshness_counter(slot), Some(1));

        mgr.prepare_tx(&mut frame, 1, 2000).unwrap();
        assert_eq!(mgr.freshness_counter(slot), Some(2));

        mgr.prepare_tx(&mut frame, 1, 3000).unwrap();
        assert_eq!(mgr.freshness_counter(slot), Some(3));
    }

    #[test]
    fn secoc_tx_unknown_pdu_fails() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x999;
        assert_eq!(
            mgr.prepare_tx(&mut frame, 1, 1000),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn secoc_capacity_exhaustion() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        for i in 0..MAX_SECOC_PDUS {
            mgr.register_pdu(make_rx_config(i as u32)).unwrap();
        }
        assert_eq!(
            mgr.register_pdu(make_rx_config(0xFFF)),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn secoc_frame_too_short_for_trailer() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_rx_config(0x800)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x800;
        frame.dlc = 3; // needs 2 (fv) + 4 (mac) = 6 minimum

        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::InvalidFrame);
    }

    // ====================== SecOC regression: Data ID binding ======================

    /// Two PDUs sharing the same `key_id` but registered with different
    /// `data_id`s must not accept each other's authenticated frames.
    ///
    /// Without the Data ID prepended to the MAC input, an attacker could
    /// take a frame authenticated for PDU A and replay it on the bus as if
    /// it were destined for PDU B (the MAC would still validate because
    /// the same key was used and the freshness counters could be coaxed
    /// into alignment). With Data-ID-binding, the MAC cryptographically
    /// commits to the PDU identity, so cross-PDU replay fails closed with
    /// `MacMismatch`.
    #[test]
    fn secoc_data_id_prevents_cross_pdu_replay() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);

        // PDU A: can_id 0xA00, data_id 0x1234.
        // PDU B: can_id 0xB00, same key_id, distinct data_id 0xABCD.
        //
        // Data IDs are chosen so that their byte XOR differs
        // (0x12 ^ 0x34 = 0x26, 0xAB ^ 0xCD = 0x66). The test stub crypto
        // is an XOR-fold of all input bytes, so for the MAC mismatch to
        // be observable the contribution of `data_id.to_be_bytes()` must
        // differ between the two PDUs.
        let mut tx_a = make_tx_config(0xA00);
        tx_a.data_id = 0x1234;
        let mut rx_a = make_rx_config(0xA00);
        rx_a.data_id = 0x1234;

        let mut tx_b = make_tx_config(0xB00);
        tx_b.data_id = 0xABCD;
        let mut rx_b = make_rx_config(0xB00);
        rx_b.data_id = 0xABCD;

        mgr.register_pdu(tx_a).unwrap();
        mgr.register_pdu(rx_a).unwrap();
        mgr.register_pdu(tx_b).unwrap();
        mgr.register_pdu(rx_b).unwrap();

        // Authenticate a frame for PDU A.
        let mut frame_a = RawCanFrame::zeroed();
        frame_a.id = 0xA00;
        frame_a.data[0] = 0x11;
        frame_a.data[1] = 0x22;
        mgr.prepare_tx(&mut frame_a, 2, 1000).unwrap();

        // Splice the authenticated payload + freshness + MAC into a frame
        // that claims to be PDU B. Same bytes, different can_id — without
        // Data ID binding the MAC would still validate.
        let mut spliced = frame_a;
        spliced.id = 0xB00;

        assert_eq!(
            mgr.verify_rx(&spliced, 1001),
            SecOcVerifyResult::MacMismatch,
            "cross-PDU replay must fail closed when Data IDs differ"
        );

        // Verify the original frame still validates against PDU A.
        assert_eq!(mgr.verify_rx(&frame_a, 1001), SecOcVerifyResult::Pass);
    }

    /// `register_pdu` must reject a second PDU that reuses the same
    /// `(key_id, data_id, direction)` triple. Without this guard, two PDUs
    /// would share a MAC domain and the Data-ID-binding defense above
    /// could be defeated at config-load time.
    #[test]
    fn secoc_register_rejects_duplicate_key_id_without_distinct_data_id() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);

        let mut first = make_rx_config(0xC00);
        first.key_id = 42;
        first.data_id = 0x1234;
        mgr.register_pdu(first).unwrap();

        // Different can_id but same (key_id, data_id, direction): reject.
        let mut conflict = make_rx_config(0xC01);
        conflict.key_id = 42;
        conflict.data_id = 0x1234;
        assert_eq!(
            mgr.register_pdu(conflict),
            Err(VsError::PolicyViolation),
            "reusing key_id without a distinct data_id must be rejected"
        );

        // Distinct data_id is permitted (still same key_id).
        let mut ok_cfg = make_rx_config(0xC02);
        ok_cfg.key_id = 42;
        ok_cfg.data_id = 0x5678;
        assert!(
            mgr.register_pdu(ok_cfg).is_ok(),
            "distinct data_id must allow key reuse"
        );
    }

    // ====================== SecOC regression: truncated FV roundtrip ======================

    /// Truncated freshness value with rollover handling: the full 64-bit
    /// counter is bound to the MAC, but only the low-order `freshness_len`
    /// bytes travel on the wire. A Tx/Rx roundtrip must survive many more
    /// frames than fit in `2^(freshness_len * 8)`.
    ///
    /// With `freshness_len = 2`, exercising 70 000 frames (past the 65 536
    /// boundary) confirms that the rollover reconstruction in
    /// `reconstruct_full_fv` correctly recombines the high bytes of the
    /// stored counter with the low bytes carried on the wire.
    #[test]
    fn secoc_truncated_freshness_value_roundtrip_with_rollover() {
        let mut mgr = SecOcManager::new(StubCrypto, 1_000_000_000);
        let mut tx = make_tx_config(0xD00);
        tx.freshness_len = 2;
        let mut rx = make_rx_config(0xD00);
        rx.freshness_len = 2;
        mgr.register_pdu(tx).unwrap();
        mgr.register_pdu(rx).unwrap();

        // Sanity-check the trailer width: 2 bytes FV + 4 bytes MAC = 6.
        // Verify that the wire payload is exactly `auth_data_len + 6` long.
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0xD00;
        frame.data[0] = 0xAB;
        let dlc = mgr.prepare_tx(&mut frame, 1, 1000).unwrap();
        assert_eq!(dlc, 1 + 2 + 4, "only freshness_len bytes on the wire");
        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::Pass);

        // Drive the counter past the 16-bit boundary to exercise rollover.
        // The wire bytes will cycle 2..=65535, 0, 1, 2, ..., but the full
        // counter and MAC must advance monotonically.
        let mut now = 2_000u64;
        for i in 0..70_000u32 {
            let mut f = RawCanFrame::zeroed();
            f.id = 0xD00;
            f.data[0] = (i & 0xFF) as u8;
            mgr.prepare_tx(&mut f, 1, now).unwrap();
            assert_eq!(
                mgr.verify_rx(&f, now),
                SecOcVerifyResult::Pass,
                "roundtrip failed at iteration {i}"
            );
            now += 1;
        }

        // The internal full counter is well past the 16-bit boundary while
        // only 2 wire bytes were transmitted each frame.
        let stored = mgr.freshness_counter(1).unwrap();
        assert!(
            stored > u64::from(u16::MAX),
            "internal counter should have rolled past 2^16 (got {stored})"
        );
    }

    /// An exact replay of the last accepted frame must surface as
    /// `FreshnessExpired`, not `MacMismatch`. The rollover reconstruction
    /// has to special-case `truncated_fv == stored_low` so it doesn't
    /// speculatively jump a full epoch.
    #[test]
    fn secoc_truncated_fv_exact_replay_is_freshness_expired() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let mut tx = make_tx_config(0xD10);
        tx.freshness_len = 2;
        let mut rx = make_rx_config(0xD10);
        rx.freshness_len = 2;
        mgr.register_pdu(tx).unwrap();
        mgr.register_pdu(rx).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0xD10;
        frame.data[0] = 0x77;
        mgr.prepare_tx(&mut frame, 1, 1000).unwrap();
        assert_eq!(mgr.verify_rx(&frame, 1000), SecOcVerifyResult::Pass);

        assert_eq!(
            mgr.verify_rx(&frame, 1001),
            SecOcVerifyResult::FreshnessExpired,
            "exact replay must be rejected as FreshnessExpired"
        );
    }

    // ======================== IdsM Tests ========================

    #[test]
    fn idsm_report_and_dequeue() {
        let mut reporter = IdsmReporter::new();
        let alert = make_alert(AlertSeverity::High, BusType::Can);

        let seq = reporter.report_alert(&alert).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(reporter.pending_count(), 1);

        let event = reporter.dequeue().unwrap();
        assert_eq!(event.sequence, 0);
        assert_eq!(event.event_type, IdsmEventType::CorrelatedAttack);
        assert_eq!(event.severity, IdsmSeverity::Sev3);
        assert_eq!(reporter.pending_count(), 0);
    }

    #[test]
    fn idsm_severity_mapping() {
        let mut reporter = IdsmReporter::new();

        let cases = [
            (AlertSeverity::Info, IdsmSeverity::Sev0),
            (AlertSeverity::Low, IdsmSeverity::Sev1),
            (AlertSeverity::Medium, IdsmSeverity::Sev2),
            (AlertSeverity::High, IdsmSeverity::Sev3),
            (AlertSeverity::Critical, IdsmSeverity::Sev4),
        ];

        for (alert_sev, expected_idsm_sev) in &cases {
            let alert = make_alert(*alert_sev, BusType::AutomotiveEthernet);
            reporter.report_alert(&alert).unwrap();
            let event = reporter.dequeue().unwrap();
            assert_eq!(event.severity, *expected_idsm_sev);
        }
    }

    #[test]
    fn idsm_bus_type_mapping() {
        let mut reporter = IdsmReporter::new();

        // CAN Low → CanAnomaly
        let alert = make_alert(AlertSeverity::Low, BusType::Can);
        reporter.report_alert(&alert).unwrap();
        assert_eq!(
            reporter.dequeue().unwrap().event_type,
            IdsmEventType::CanAnomaly
        );

        // CAN High → CorrelatedAttack
        let alert = make_alert(AlertSeverity::High, BusType::CanFd);
        reporter.report_alert(&alert).unwrap();
        assert_eq!(
            reporter.dequeue().unwrap().event_type,
            IdsmEventType::CorrelatedAttack
        );

        // Ethernet → EthAnomaly
        let alert = make_alert(AlertSeverity::Medium, BusType::AutomotiveEthernet);
        reporter.report_alert(&alert).unwrap();
        assert_eq!(
            reporter.dequeue().unwrap().event_type,
            IdsmEventType::EthAnomaly
        );

        // LIN → CanAnomaly (LIN anomalies use CAN-like reporting)
        let alert = make_alert(AlertSeverity::Low, BusType::Lin);
        reporter.report_alert(&alert).unwrap();
        assert_eq!(
            reporter.dequeue().unwrap().event_type,
            IdsmEventType::CanAnomaly
        );

        // FlexRay → CanAnomaly (FlexRay anomalies likewise)
        let alert = make_alert(AlertSeverity::Low, BusType::FlexRay);
        reporter.report_alert(&alert).unwrap();
        assert_eq!(
            reporter.dequeue().unwrap().event_type,
            IdsmEventType::CanAnomaly
        );
    }

    #[test]
    fn idsm_queue_full_drops() {
        let mut reporter = IdsmReporter::new();
        let alert = make_alert(AlertSeverity::Medium, BusType::Can);

        for _ in 0..MAX_IDSM_EVENTS {
            reporter.report_alert(&alert).unwrap();
        }

        // Queue is full — next report should fail.
        assert_eq!(
            reporter.report_alert(&alert),
            Err(VsError::ResourceExhausted)
        );

        let (report_count, dropped) = reporter.stats();
        assert_eq!(report_count, MAX_IDSM_EVENTS as u64);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn idsm_dequeue_empty() {
        let mut reporter = IdsmReporter::new();
        assert!(reporter.dequeue().is_none());
    }

    #[test]
    fn idsm_secoc_failure_report() {
        let mut reporter = IdsmReporter::new();
        let seq = reporter
            .report_secoc_failure(0x123, SecOcVerifyResult::MacMismatch, 5000, BusType::Can)
            .unwrap();
        assert_eq!(seq, 0);

        let event = reporter.dequeue().unwrap();
        assert_eq!(event.event_type, IdsmEventType::SecOcFailure);
        assert_eq!(event.severity, IdsmSeverity::Sev3);
        assert_eq!(event.source_id, 0x123);
        assert_eq!(event.context[0], SecOcVerifyResult::MacMismatch as u8);
    }

    #[test]
    fn idsm_secoc_failure_severity_levels() {
        let mut reporter = IdsmReporter::new();

        reporter
            .report_secoc_failure(0x1, SecOcVerifyResult::FreshnessExpired, 1000, BusType::Can)
            .unwrap();
        assert_eq!(reporter.dequeue().unwrap().severity, IdsmSeverity::Sev2);

        reporter
            .report_secoc_failure(0x2, SecOcVerifyResult::CryptoFailure, 2000, BusType::Can)
            .unwrap();
        assert_eq!(reporter.dequeue().unwrap().severity, IdsmSeverity::Sev4);

        reporter
            .report_secoc_failure(0x3, SecOcVerifyResult::UnknownPdu, 3000, BusType::Can)
            .unwrap();
        assert_eq!(reporter.dequeue().unwrap().severity, IdsmSeverity::Sev1);
    }

    #[test]
    fn idsm_fifo_ordering() {
        let mut reporter = IdsmReporter::new();

        for i in 0..5u64 {
            let alert = SecurityAlert {
                id: i,
                severity: AlertSeverity::Medium,
                source_type: BusType::Can.to_source_type(),
                source_id: i as u32,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: i * 1000,
            };
            reporter.report_alert(&alert).unwrap();
        }

        for i in 0..5u64 {
            let event = reporter.dequeue().unwrap();
            assert_eq!(event.sequence, i);
            assert_eq!(event.source_id, i as u32);
        }
    }

    #[test]
    fn idsm_context_contains_payload_hash_prefix() {
        let mut reporter = IdsmReporter::new();
        let mut alert = make_alert(AlertSeverity::Low, BusType::Can);
        alert.payload_hash.0[0] = 0xDE;
        alert.payload_hash.0[7] = 0xAD;

        reporter.report_alert(&alert).unwrap();
        let event = reporter.dequeue().unwrap();
        assert_eq!(event.context[0], 0xDE);
        assert_eq!(event.context[7], 0xAD);
    }

    // ======================== MCAL Adapter Tests ========================

    #[test]
    fn mcal_can_adapter_ready() {
        let mut adapter = McalCanAdapter::new(StubMcalCan {
            status: McalCanStatus::Ready,
            pending_frame: None,
            bitrate: 500_000,
        });

        assert_eq!(adapter.receive().unwrap(), None);
        assert_eq!(adapter.bitrate(), 500_000);
        assert!(!adapter.is_bus_off());
    }

    #[test]
    fn mcal_can_adapter_receives_frame() {
        let frame = RawCanFrame {
            id: 0x123,
            dlc: 8,
            data: {
                let mut d = [0u8; 64];
                d[0] = 0xAA;
                d
            },
            timestamp_us: 42_000,
            is_fd: false,
            is_extended: false,
        };

        let mut adapter = McalCanAdapter::new(StubMcalCan {
            status: McalCanStatus::Ready,
            pending_frame: Some(frame),
            bitrate: 500_000,
        });

        let received = adapter.receive().unwrap().unwrap();
        assert_eq!(received.id, 0x123);
        assert_eq!(received.data[0], 0xAA);
    }

    #[test]
    fn mcal_can_adapter_uninit_errors() {
        let mut adapter = McalCanAdapter::new(StubMcalCan {
            status: McalCanStatus::Uninit,
            pending_frame: None,
            bitrate: 0,
        });

        assert_eq!(adapter.receive(), Err(VsError::NotInitialized));
        let frame = RawCanFrame::zeroed();
        assert_eq!(adapter.transmit(&frame), Err(VsError::NotInitialized));
    }

    #[test]
    fn mcal_can_adapter_bus_off_errors() {
        let mut adapter = McalCanAdapter::new(StubMcalCan {
            status: McalCanStatus::BusOff,
            pending_frame: None,
            bitrate: 500_000,
        });

        assert_eq!(adapter.receive(), Err(VsError::BusError));
        assert!(adapter.is_bus_off());
    }

    #[test]
    fn mcal_can_adapter_error_passive_can_receive() {
        let mut adapter = McalCanAdapter::new(StubMcalCan {
            status: McalCanStatus::ErrorPassive,
            pending_frame: None,
            bitrate: 500_000,
        });

        assert_eq!(adapter.receive().unwrap(), None);
        assert!(!adapter.is_bus_off());
    }

    #[test]
    fn mcal_eth_adapter_basic() {
        let mut adapter = McalEthAdapter::new(StubMcalEth {
            link_up: true,
            speed: 1000,
        });

        assert!(adapter.receive().unwrap().is_none());
        assert!(adapter.link_is_up());
        assert_eq!(adapter.link_speed_mbps(), 1000);
        assert!(adapter.transmit(&[0xAA, 0xBB]).is_ok());
    }

    #[test]
    fn mcal_eth_adapter_link_down() {
        let adapter = McalEthAdapter::new(StubMcalEth {
            link_up: false,
            speed: 0,
        });

        assert!(!adapter.link_is_up());
        assert_eq!(adapter.link_speed_mbps(), 0);
    }

    // ======================== Service Registry Tests ========================

    #[test]
    fn service_registry_register_and_find() {
        let mut reg = ServiceRegistry::new();
        let slot = reg.register(0x1234, 0x0001, 1, 0).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(reg.active_count(), 1);

        let (found_slot, inst) = reg.find(0x1234, 0x0001).unwrap();
        assert_eq!(found_slot, 0);
        assert_eq!(inst.service_id, 0x1234);
        assert_eq!(inst.state, ServiceState::Registered);
    }

    #[test]
    fn service_registry_offer_lifecycle() {
        let mut reg = ServiceRegistry::new();
        let slot = reg.register(0x1000, 0x0001, 1, 0).unwrap();

        reg.offer(slot).unwrap();
        let (_, inst) = reg.find(0x1000, 0x0001).unwrap();
        assert_eq!(inst.state, ServiceState::Offered);

        reg.stop(slot).unwrap();
        assert!(reg.find(0x1000, 0x0001).is_none());
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn service_registry_mark_available() {
        let mut reg = ServiceRegistry::new();
        let slot = reg.register(0x2000, 0x0001, 2, 5).unwrap();
        reg.offer(slot).unwrap();
        reg.mark_available(slot).unwrap();

        let (_, inst) = reg.find(0x2000, 0x0001).unwrap();
        assert_eq!(inst.state, ServiceState::Available);
        assert_eq!(inst.major_version, 2);
        assert_eq!(inst.minor_version, 5);
    }

    #[test]
    fn service_registry_duplicate_rejected() {
        let mut reg = ServiceRegistry::new();
        reg.register(0x3000, 0x0001, 1, 0).unwrap();
        assert_eq!(
            reg.register(0x3000, 0x0001, 1, 0),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn service_registry_same_service_different_instance() {
        let mut reg = ServiceRegistry::new();
        reg.register(0x4000, 0x0001, 1, 0).unwrap();
        reg.register(0x4000, 0x0002, 1, 0).unwrap();
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn service_registry_capacity_exhaustion() {
        let mut reg = ServiceRegistry::new();
        for i in 0..MAX_SERVICE_INSTANCES {
            reg.register(i as u16, 0x0001, 1, 0).unwrap();
        }
        assert_eq!(
            reg.register(0xFFFF, 0x0001, 1, 0),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn service_registry_stop_inactive_fails() {
        let mut reg = ServiceRegistry::new();
        assert_eq!(reg.stop(0), Err(VsError::NotInitialized));
    }

    #[test]
    fn service_registry_iter_active() {
        let mut reg = ServiceRegistry::new();
        reg.register(0x1000, 0x0001, 1, 0).unwrap();
        reg.register(0x2000, 0x0001, 1, 0).unwrap();
        reg.register(0x3000, 0x0001, 1, 0).unwrap();

        let active: alloc::vec::Vec<_> = reg.iter_active().collect();
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn service_registry_slot_reuse_after_stop() {
        let mut reg = ServiceRegistry::new();
        let slot = reg.register(0x5000, 0x0001, 1, 0).unwrap();
        reg.stop(slot).unwrap();

        // Same slot should be reusable.
        let new_slot = reg.register(0x6000, 0x0001, 1, 0).unwrap();
        assert_eq!(new_slot, slot);
    }

    // ======================== Repr(C) Layout Tests ========================

    #[test]
    fn idsm_event_repr_c_size() {
        let size = core::mem::size_of::<IdsmSecurityEvent>();
        assert!(
            size <= 64,
            "IdsmSecurityEvent is {size} bytes, exceeds 64-byte budget"
        );
    }

    #[test]
    fn secoc_verify_result_repr_c_size() {
        assert!(core::mem::size_of::<SecOcVerifyResult>() <= 4);
    }

    #[test]
    fn idsm_severity_ordering() {
        assert!(IdsmSeverity::Sev4 > IdsmSeverity::Sev3);
        assert!(IdsmSeverity::Sev3 > IdsmSeverity::Sev2);
        assert!(IdsmSeverity::Sev2 > IdsmSeverity::Sev1);
        assert!(IdsmSeverity::Sev1 > IdsmSeverity::Sev0);
    }

    // ======================== Dem Tests ========================

    fn make_dem_config(event_id: u16) -> DemEventConfig {
        DemEventConfig {
            event_id,
            debounce_threshold: 3,
            healing_threshold: 2,
            active: false,
        }
    }

    #[test]
    fn dem_register_event() {
        let mut mgr = DemManager::new();
        let slot = mgr.register_event(make_dem_config(1)).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(mgr.active_fault_count(), 0);
    }

    #[test]
    fn dem_duplicate_event_id_rejected() {
        let mut mgr = DemManager::new();
        mgr.register_event(make_dem_config(1)).unwrap();
        assert_eq!(
            mgr.register_event(make_dem_config(1)),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn dem_invalid_config_rejected() {
        let mut mgr = DemManager::new();
        let mut cfg = make_dem_config(1);
        cfg.debounce_threshold = 0;
        assert_eq!(mgr.register_event(cfg), Err(VsError::InvalidConfig));

        let mut cfg2 = make_dem_config(2);
        cfg2.healing_threshold = 0;
        assert_eq!(mgr.register_event(cfg2), Err(VsError::InvalidConfig));
    }

    #[test]
    fn dem_debounce_confirms_after_threshold() {
        let mut mgr = DemManager::new();
        mgr.register_event(make_dem_config(10)).unwrap(); // threshold = 3

        // Two failures — not yet confirmed.
        mgr.report_status(10, DemEventStatus::Failed, 1000).unwrap();
        mgr.report_status(10, DemEventStatus::Failed, 2000).unwrap();
        assert!(!mgr.is_confirmed(10));

        // Third failure — confirmed.
        mgr.report_status(10, DemEventStatus::Failed, 3000).unwrap();
        assert!(mgr.is_confirmed(10));
        assert_eq!(mgr.active_fault_count(), 1);
    }

    #[test]
    fn dem_healing_clears_confirmed() {
        let mut mgr = DemManager::new();
        mgr.register_event(make_dem_config(20)).unwrap(); // heal threshold = 2

        // Confirm the fault.
        for i in 0..3 {
            mgr.report_status(20, DemEventStatus::Failed, i * 1000)
                .unwrap();
        }
        assert!(mgr.is_confirmed(20));

        // One pass — still confirmed.
        mgr.report_status(20, DemEventStatus::Passed, 4000).unwrap();
        assert!(mgr.is_confirmed(20));

        // Second pass — healed.
        mgr.report_status(20, DemEventStatus::Passed, 5000).unwrap();
        assert!(!mgr.is_confirmed(20));
        assert_eq!(mgr.active_fault_count(), 0);
    }

    #[test]
    fn dem_pass_resets_fail_counter() {
        let mut mgr = DemManager::new();
        mgr.register_event(make_dem_config(30)).unwrap(); // debounce = 3

        // Two failures, then a pass resets progress.
        mgr.report_status(30, DemEventStatus::Failed, 1000).unwrap();
        mgr.report_status(30, DemEventStatus::Failed, 2000).unwrap();
        mgr.report_status(30, DemEventStatus::Passed, 3000).unwrap();

        // Two more failures — only 2 consecutive, not 3.
        mgr.report_status(30, DemEventStatus::Failed, 4000).unwrap();
        mgr.report_status(30, DemEventStatus::Failed, 5000).unwrap();
        assert!(!mgr.is_confirmed(30));
    }

    #[test]
    fn dem_clear_event() {
        let mut mgr = DemManager::new();
        mgr.register_event(make_dem_config(40)).unwrap();

        for i in 0..3 {
            mgr.report_status(40, DemEventStatus::Failed, i * 1000)
                .unwrap();
        }
        assert!(mgr.is_confirmed(40));

        mgr.clear_event(40).unwrap();
        assert!(!mgr.is_confirmed(40));
    }

    #[test]
    fn dem_clear_all() {
        let mut mgr = DemManager::new();
        for id in 0..5u16 {
            let mut cfg = make_dem_config(id);
            cfg.debounce_threshold = 1;
            mgr.register_event(cfg).unwrap();
            mgr.report_status(id, DemEventStatus::Failed, 1000).unwrap();
        }
        assert_eq!(mgr.active_fault_count(), 5);

        mgr.clear_all();
        assert_eq!(mgr.active_fault_count(), 0);
    }

    #[test]
    fn dem_clear_unknown_event_fails() {
        let mut mgr = DemManager::new();
        assert_eq!(mgr.clear_event(99), Err(VsError::NotInitialized));
    }

    #[test]
    fn dem_capacity_exhaustion() {
        let mut mgr = DemManager::new();
        for i in 0..MAX_DEM_EVENTS as u16 {
            let mut cfg = make_dem_config(i);
            cfg.debounce_threshold = 1;
            cfg.healing_threshold = 1;
            mgr.register_event(cfg).unwrap();
        }
        assert_eq!(
            mgr.register_event(make_dem_config(0xFFFF)),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn dem_iter_confirmed() {
        let mut mgr = DemManager::new();
        for id in 0..4u16 {
            let mut cfg = make_dem_config(id);
            cfg.debounce_threshold = 1;
            mgr.register_event(cfg).unwrap();
        }
        // Confirm events 1 and 3.
        mgr.report_status(1, DemEventStatus::Failed, 1000).unwrap();
        mgr.report_status(3, DemEventStatus::Failed, 2000).unwrap();

        let confirmed: alloc::vec::Vec<_> = mgr.iter_confirmed().collect();
        assert_eq!(confirmed.len(), 2);
        assert_eq!(confirmed[0].1.event_id, 1);
        assert_eq!(confirmed[1].1.event_id, 3);
    }

    #[test]
    fn dem_prefailed_also_debounces() {
        let mut mgr = DemManager::new();
        let mut cfg = make_dem_config(50);
        cfg.debounce_threshold = 2;
        mgr.register_event(cfg).unwrap();

        mgr.report_status(50, DemEventStatus::Prefailed, 1000)
            .unwrap();
        mgr.report_status(50, DemEventStatus::Prefailed, 2000)
            .unwrap();
        assert!(mgr.is_confirmed(50));
    }

    // ======================== BswM Tests ========================

    #[test]
    fn bswm_starts_in_startup() {
        let mgr = BswModeManager::new();
        assert_eq!(mgr.current_mode(), BswModeId::Startup);
        assert_eq!(mgr.transition_count(), 0);
    }

    #[test]
    fn bswm_valid_transition() {
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();

        let mode = mgr.request_mode(BswModeId::Run).unwrap();
        assert_eq!(mode, BswModeId::Run);
        assert_eq!(mgr.transition_count(), 1);
    }

    #[test]
    fn bswm_invalid_transition_rejected() {
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();

        // Try to go directly to Shutdown — no rule for that.
        assert_eq!(
            mgr.request_mode(BswModeId::Shutdown),
            Err(VsError::PolicyViolation)
        );
        assert_eq!(mgr.current_mode(), BswModeId::Startup);
        assert_eq!(mgr.transition_count(), 0);
    }

    #[test]
    fn bswm_same_mode_noop() {
        let mgr = BswModeManager::new();
        // Requesting current mode is a no-op and succeeds even without rules.
        assert_eq!(mgr.current_mode(), BswModeId::Startup);
        let mut mgr = mgr;
        let mode = mgr.request_mode(BswModeId::Startup).unwrap();
        assert_eq!(mode, BswModeId::Startup);
        assert_eq!(mgr.transition_count(), 0);
    }

    #[test]
    fn bswm_multi_step_transition() {
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();
        mgr.add_rule(BswModeId::Run, BswModeId::PostRun).unwrap();
        mgr.add_rule(BswModeId::PostRun, BswModeId::PrepShutdown)
            .unwrap();
        mgr.add_rule(BswModeId::PrepShutdown, BswModeId::Shutdown)
            .unwrap();

        mgr.request_mode(BswModeId::Run).unwrap();
        mgr.request_mode(BswModeId::PostRun).unwrap();
        mgr.request_mode(BswModeId::PrepShutdown).unwrap();
        mgr.request_mode(BswModeId::Shutdown).unwrap();

        assert_eq!(mgr.current_mode(), BswModeId::Shutdown);
        assert_eq!(mgr.transition_count(), 4);
    }

    #[test]
    fn bswm_rule_condition_gating() {
        let mut mgr = BswModeManager::new();
        let slot = mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();

        // Disable the condition.
        mgr.rules[slot].condition_met = false;

        assert_eq!(
            mgr.request_mode(BswModeId::Run),
            Err(VsError::PolicyViolation)
        );

        // Re-enable the condition.
        mgr.rules[slot].condition_met = true;
        mgr.request_mode(BswModeId::Run).unwrap();
        assert_eq!(mgr.current_mode(), BswModeId::Run);
    }

    #[test]
    fn bswm_reverse_transition_needs_rule() {
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();
        mgr.request_mode(BswModeId::Run).unwrap();

        // No rule from Run → Startup.
        assert_eq!(
            mgr.request_mode(BswModeId::Startup),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn bswm_rule_capacity_exhaustion() {
        let mut mgr = BswModeManager::new();
        // Use unique (from, to) pairs to fill all 16 slots.
        let modes = [
            BswModeId::Startup,
            BswModeId::Run,
            BswModeId::PostRun,
            BswModeId::Sleep,
            BswModeId::PrepShutdown,
            BswModeId::Shutdown,
        ];
        let mut count = 0;
        'outer: for &from in &modes {
            for &to in &modes {
                if from == to {
                    continue;
                }
                if count >= MAX_BSWM_RULES {
                    break 'outer;
                }
                mgr.add_rule(from, to).unwrap();
                count += 1;
            }
        }
        assert_eq!(count, MAX_BSWM_RULES);
        // One more should fail — all slots occupied.
        assert_eq!(
            mgr.add_rule(BswModeId::Shutdown, BswModeId::Startup),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn bswm_default_impl() {
        let mgr = BswModeManager::default();
        assert_eq!(mgr.current_mode(), BswModeId::Startup);
    }

    #[test]
    fn bswm_skip_transition_blocked() {
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();
        mgr.add_rule(BswModeId::Run, BswModeId::PostRun).unwrap();

        // Skip from Startup directly to PostRun — no rule.
        assert_eq!(
            mgr.request_mode(BswModeId::PostRun),
            Err(VsError::PolicyViolation)
        );
    }

    // ======================== ComM Tests ========================

    #[test]
    fn comm_register_channel() {
        let mut mgr = ComMManager::new();
        let slot = mgr.register_channel(1, BusType::Can).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(mgr.channel_mode(1), Some(ComMMode::NoCommunication));
        assert_eq!(mgr.active_channel_count(), 0); // NoCommunication is not "active"
    }

    #[test]
    fn comm_duplicate_channel_rejected() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(1, BusType::Can).unwrap();
        assert_eq!(
            mgr.register_channel(1, BusType::CanFd),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn comm_request_full_com() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(5, BusType::AutomotiveEthernet)
            .unwrap();
        mgr.request_full_com(5).unwrap();

        assert_eq!(mgr.channel_mode(5), Some(ComMMode::FullCommunication));
        assert_eq!(mgr.active_channel_count(), 1);
    }

    #[test]
    fn comm_request_no_com() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(3, BusType::Can).unwrap();
        mgr.request_full_com(3).unwrap();
        mgr.request_no_com(3).unwrap();

        assert_eq!(mgr.channel_mode(3), Some(ComMMode::NoCommunication));
        assert_eq!(mgr.active_channel_count(), 0);
    }

    #[test]
    fn comm_inhibit_blocks_mode_change() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(7, BusType::Can).unwrap();
        mgr.set_inhibit(7, true).unwrap();

        assert_eq!(mgr.request_full_com(7), Err(VsError::PolicyViolation));
        assert_eq!(mgr.request_no_com(7), Err(VsError::PolicyViolation));
    }

    #[test]
    fn comm_inhibit_can_be_cleared() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(8, BusType::CanFd).unwrap();
        mgr.set_inhibit(8, true).unwrap();
        mgr.set_inhibit(8, false).unwrap();

        mgr.request_full_com(8).unwrap();
        assert_eq!(mgr.channel_mode(8), Some(ComMMode::FullCommunication));
    }

    #[test]
    fn comm_unknown_channel_returns_none() {
        let mgr = ComMManager::new();
        assert_eq!(mgr.channel_mode(99), None);
    }

    #[test]
    fn comm_unknown_channel_request_fails() {
        let mut mgr = ComMManager::new();
        assert_eq!(mgr.request_full_com(99), Err(VsError::NotInitialized));
        assert_eq!(mgr.request_no_com(99), Err(VsError::NotInitialized));
        assert_eq!(mgr.set_inhibit(99, true), Err(VsError::NotInitialized));
    }

    #[test]
    fn comm_capacity_exhaustion() {
        let mut mgr = ComMManager::new();
        for i in 0..MAX_COMM_CHANNELS as u8 {
            mgr.register_channel(i, BusType::Can).unwrap();
        }
        assert_eq!(
            mgr.register_channel(0xFF, BusType::Can),
            Err(VsError::ResourceExhausted)
        );
    }

    #[test]
    fn comm_multiple_channels_active() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(1, BusType::Can).unwrap();
        mgr.register_channel(2, BusType::AutomotiveEthernet)
            .unwrap();
        mgr.register_channel(3, BusType::CanFd).unwrap();

        mgr.request_full_com(1).unwrap();
        mgr.request_full_com(3).unwrap();

        assert_eq!(mgr.active_channel_count(), 2);
    }

    #[test]
    fn comm_default_impl() {
        let mgr = ComMManager::default();
        assert_eq!(mgr.active_channel_count(), 0);
    }

    // ======================== Repr(C) Layout Tests ========================

    #[test]
    fn dem_event_status_repr_c_size() {
        assert!(core::mem::size_of::<DemEventStatus>() <= 4);
    }

    #[test]
    fn bsw_mode_id_repr_c_size() {
        assert!(core::mem::size_of::<BswModeId>() <= 4);
    }

    #[test]
    fn comm_mode_repr_c_size() {
        assert!(core::mem::size_of::<ComMMode>() <= 4);
    }

    #[test]
    fn verify_rx_rejects_dlc_above_64() {
        let crypto = StubCrypto;
        let mut mgr = SecOcManager::new(crypto, 5_000_000);
        mgr.register_pdu(make_rx_config(0x100)).unwrap();

        let frame = RawCanFrame {
            id: 0x100,
            dlc: 200, // DLC > 64
            data: [0u8; 64],
            timestamp_us: 1_000,
            is_fd: false,
            is_extended: false,
        };
        let result = mgr.verify_rx(&frame, 1_000);
        assert_eq!(result, SecOcVerifyResult::InvalidFrame);
    }

    #[test]
    fn bswm_set_rule_condition_gates_transition() {
        let mut mgr = BswModeManager::new();
        let slot = mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();

        // Condition is met by default — transition should succeed.
        assert!(mgr.request_mode(BswModeId::Run).is_ok());
        assert_eq!(mgr.current_mode(), BswModeId::Run);

        // Go back to Startup.
        mgr.add_rule(BswModeId::Run, BswModeId::Startup).unwrap();
        mgr.request_mode(BswModeId::Startup).unwrap();

        // Clear condition on the Startup→Run rule.
        mgr.set_rule_condition(slot, false).unwrap();
        assert_eq!(
            mgr.request_mode(BswModeId::Run),
            Err(VsError::PolicyViolation)
        );

        // Re-set condition — should succeed again.
        mgr.set_rule_condition(slot, true).unwrap();
        assert!(mgr.request_mode(BswModeId::Run).is_ok());
    }

    #[test]
    fn bswm_set_rule_condition_invalid_slot() {
        let mut mgr = BswModeManager::new();
        // No rules added — slot 0 is inactive.
        assert_eq!(mgr.set_rule_condition(0, true), Err(VsError::InvalidInput));
        // Out-of-bounds slot.
        assert_eq!(
            mgr.set_rule_condition(999, true),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn idsm_overwrite_mode_unit_test() {
        let mut reporter = IdsmReporter::new_overwrite();
        // Fill the queue via report_secoc_failure.
        for i in 0..MAX_IDSM_EVENTS as u32 {
            reporter
                .report_secoc_failure(
                    i,
                    SecOcVerifyResult::MacMismatch,
                    i as u64 * 1000,
                    BusType::Can,
                )
                .expect("should accept");
        }
        assert_eq!(reporter.pending_count(), MAX_IDSM_EVENTS);

        // One more should succeed (overwrite oldest, source_id=0).
        reporter
            .report_secoc_failure(
                0xFFFF,
                SecOcVerifyResult::CryptoFailure,
                999_000,
                BusType::Can,
            )
            .expect("overwrite mode should accept");
        assert_eq!(reporter.pending_count(), MAX_IDSM_EVENTS);

        // First dequeued event should be source_id=1 (0 was evicted).
        let first = reporter.dequeue().unwrap();
        assert_eq!(first.source_id, 1);
    }

    // V6 — NoOpSomeIpAuth tests removed in v0.7.0; the stub was deleted.

    /// The `SomeIpAuthProvider` trait defaults must surface
    /// `Err(VsError::NotInitialized)` rather than silently returning
    /// `Ok(false)`. The previous defaults masked "no backend configured"
    /// as "authentication failed", which is indistinguishable on the wire
    /// from a legitimate spoofed-peer rejection and lets a misconfigured
    /// deployment ship without any TLS/DTLS coverage. The defaults must
    /// agree with `NoOpSomeIpAuth` so callers can rely on a single
    /// "fail-loud" contract regardless of which type they hold.
    #[test]
    fn someip_auth_provider_default_returns_not_initialized() {
        // A type that uses every default method on `SomeIpAuthProvider`.
        struct DefaultsProvider;
        impl SomeIpAuthProvider for DefaultsProvider {}

        let auth = DefaultsProvider;
        assert_eq!(
            auth.verify_sd_message(0x0A00_0001, 0x1234, 0x0001, &[]),
            Err(VsError::NotInitialized),
            "default verify_sd_message must signal NotInitialized"
        );
        assert_eq!(
            auth.verify_method_call(0x0A00_0001, 0x1234, 0x0001, 0x0001, &[]),
            Err(VsError::NotInitialized),
            "default verify_method_call must signal NotInitialized"
        );
        assert!(
            !auth.is_session_established(0x0A00_0001),
            "default is_session_established must report no session"
        );
    }

    // ======================== S5 — Stub MCAL Drivers ========================

    #[test]
    fn stub_mcal_can_driver_returns_default_frame() {
        let mut drv = StubMcalCanDriver::new();
        assert_eq!(drv.can_get_status(), McalCanStatus::Ready);
        assert_eq!(drv.can_get_bitrate(), 500_000);

        let frame = drv
            .can_main_function_read()
            .expect("should have a pending frame");
        assert_eq!(frame.id, 0x7FF);
        assert_eq!(frame.dlc, 8);
        assert_eq!(frame.data[0], 0xAA);

        // Second read returns None.
        assert!(drv.can_main_function_read().is_none());
    }

    #[test]
    fn stub_mcal_can_driver_write_succeeds() {
        let mut drv = StubMcalCanDriver::new();
        let frame = RawCanFrame::zeroed();
        assert!(drv.can_write(&frame).is_ok());
    }

    #[test]
    fn stub_mcal_can_driver_set_pending() {
        let mut drv = StubMcalCanDriver::new();
        // Consume default frame.
        let _ = drv.can_main_function_read();

        let mut custom = RawCanFrame::zeroed();
        custom.id = 0x42;
        custom.dlc = 2;
        drv.set_pending(custom);

        let f = drv.can_main_function_read().unwrap();
        assert_eq!(f.id, 0x42);
    }

    #[test]
    fn stub_mcal_eth_driver_defaults() {
        let mut drv = StubMcalEthDriver::new();
        assert!(drv.eth_is_link_up());
        assert_eq!(drv.eth_get_link_speed(), 100);
        assert!(drv.eth_receive().is_none());
        assert!(drv.eth_transmit(&[0x00]).is_ok());
    }

    #[test]
    fn stub_mcal_can_adapter_integration() {
        let drv = StubMcalCanDriver::new();
        let mut adapter = McalCanAdapter::new(drv);
        let frame = adapter.receive().unwrap().unwrap();
        assert_eq!(frame.id, 0x7FF);
    }

    #[test]
    fn stub_mcal_eth_adapter_integration() {
        let drv = StubMcalEthDriver::new();
        let mut adapter = McalEthAdapter::new(drv);
        assert!(adapter.link_is_up());
        assert_eq!(adapter.link_speed_mbps(), 100);
        assert!(adapter.receive().unwrap().is_none());
    }

    // ======================== S7 — BswM Transition Action ========================

    #[test]
    fn bswm_transition_action_called() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static CALL_COUNT: AtomicU8 = AtomicU8::new(0);

        fn on_transition(_from: BswModeId, _to: BswModeId) {
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        CALL_COUNT.store(0, Ordering::Relaxed);
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();
        mgr.set_transition_action(Some(on_transition));

        mgr.request_mode(BswModeId::Run).unwrap();
        assert_eq!(CALL_COUNT.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn bswm_transition_action_not_called_on_noop() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static NOOP_COUNT: AtomicU8 = AtomicU8::new(0);

        fn on_transition(_from: BswModeId, _to: BswModeId) {
            NOOP_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        NOOP_COUNT.store(0, Ordering::Relaxed);
        let mut mgr = BswModeManager::new();
        mgr.set_transition_action(Some(on_transition));

        // Same-mode request is a no-op — callback should not fire.
        mgr.request_mode(BswModeId::Startup).unwrap();
        assert_eq!(NOOP_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bswm_transition_action_cleared() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static CLEAR_COUNT: AtomicU8 = AtomicU8::new(0);

        fn on_transition(_from: BswModeId, _to: BswModeId) {
            CLEAR_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        CLEAR_COUNT.store(0, Ordering::Relaxed);
        let mut mgr = BswModeManager::new();
        mgr.add_rule(BswModeId::Startup, BswModeId::Run).unwrap();
        mgr.add_rule(BswModeId::Run, BswModeId::PostRun).unwrap();

        mgr.set_transition_action(Some(on_transition));
        mgr.request_mode(BswModeId::Run).unwrap();
        assert_eq!(CLEAR_COUNT.load(Ordering::Relaxed), 1);

        // Clear the action.
        mgr.set_transition_action(None);
        mgr.request_mode(BswModeId::PostRun).unwrap();
        assert_eq!(CLEAR_COUNT.load(Ordering::Relaxed), 1); // unchanged
    }

    // ======================== S8 — ComM is_communication_allowed ========================

    #[test]
    fn comm_is_communication_allowed_full_com() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(1, BusType::Can).unwrap();
        mgr.request_full_com(1).unwrap();

        assert!(mgr.is_communication_allowed(1));
    }

    #[test]
    fn comm_is_communication_allowed_no_com() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(2, BusType::Can).unwrap();
        // Default is NoCommunication.
        assert!(!mgr.is_communication_allowed(2));
    }

    #[test]
    fn comm_is_communication_allowed_inhibited() {
        let mut mgr = ComMManager::new();
        mgr.register_channel(3, BusType::CanFd).unwrap();
        mgr.request_full_com(3).unwrap();
        mgr.set_inhibit(3, true).unwrap();

        // Full com but inhibited — not allowed.
        assert!(!mgr.is_communication_allowed(3));
    }

    #[test]
    fn comm_is_communication_allowed_unknown_channel() {
        let mgr = ComMManager::new();
        assert!(!mgr.is_communication_allowed(99));
    }

    // ======================== S10 — DEM Freeze Frame ========================

    #[test]
    fn dem_freeze_frame_captured_on_confirmed() {
        let mut mgr = DemManager::new();
        let slot = mgr.register_event(make_dem_config(100)).unwrap(); // threshold = 3

        // Three failures → confirmed; freeze frame captured.
        for i in 0..3u64 {
            mgr.report_status(100, DemEventStatus::Failed, (i + 1) * 1000)
                .unwrap();
        }
        assert!(mgr.is_confirmed(100));

        let ff = mgr
            .get_freeze_frame(slot)
            .expect("freeze frame should exist");
        assert_eq!(ff.timestamp_us, 3000);
        assert_eq!(ff.dtc_number, 100); // event_id as DTC
    }

    #[test]
    fn dem_freeze_frame_not_captured_before_confirmed() {
        let mut mgr = DemManager::new();
        let slot = mgr.register_event(make_dem_config(101)).unwrap();

        // Two failures — not yet confirmed.
        mgr.report_status(101, DemEventStatus::Failed, 1000)
            .unwrap();
        mgr.report_status(101, DemEventStatus::Failed, 2000)
            .unwrap();
        assert!(!mgr.is_confirmed(101));
        assert!(mgr.get_freeze_frame(slot).is_none());
    }

    #[test]
    fn dem_freeze_frame_cleared_with_event() {
        let mut mgr = DemManager::new();
        let slot = mgr.register_event(make_dem_config(102)).unwrap();

        for i in 0..3u64 {
            mgr.report_status(102, DemEventStatus::Failed, (i + 1) * 1000)
                .unwrap();
        }
        assert!(mgr.get_freeze_frame(slot).is_some());

        mgr.clear_event(102).unwrap();
        assert!(mgr.get_freeze_frame(slot).is_none());
    }

    #[test]
    fn dem_freeze_frame_cleared_on_clear_all() {
        let mut mgr = DemManager::new();
        let mut cfg = make_dem_config(103);
        cfg.debounce_threshold = 1;
        let slot = mgr.register_event(cfg).unwrap();

        mgr.report_status(103, DemEventStatus::Failed, 1000)
            .unwrap();
        assert!(mgr.get_freeze_frame(slot).is_some());

        mgr.clear_all();
        assert!(mgr.get_freeze_frame(slot).is_none());
    }

    #[test]
    fn dem_freeze_frame_invalid_index() {
        let mgr = DemManager::new();
        assert!(mgr.get_freeze_frame(999).is_none());
        assert!(mgr.get_freeze_frame(0).is_none()); // slot 0 is inactive
    }

    // ======================== P5 — SecOC PDU Index ========================

    #[test]
    fn secoc_pdu_index_fast_lookup() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let slot = mgr.register_pdu(make_rx_config(0x100)).unwrap();

        // Fast path lookup should return the same slot.
        assert_eq!(mgr.find_pdu(0x100, SecOcDirection::Rx), Some(slot));
        // Different direction should not match.
        assert_eq!(mgr.find_pdu(0x100, SecOcDirection::Tx), None);
    }

    #[test]
    fn secoc_pdu_index_cleared_on_unregister() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let slot = mgr.register_pdu(make_rx_config(0x200)).unwrap();
        assert_eq!(mgr.find_pdu(0x200, SecOcDirection::Rx), Some(slot));

        mgr.unregister_pdu(slot).unwrap();
        assert_eq!(mgr.find_pdu(0x200, SecOcDirection::Rx), None);
    }

    #[test]
    fn secoc_pdu_index_tx_and_rx_independent() {
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let rx_slot = mgr.register_pdu(make_rx_config(0x300)).unwrap();
        let tx_slot = mgr.register_pdu(make_tx_config(0x300)).unwrap();

        assert_eq!(mgr.find_pdu(0x300, SecOcDirection::Rx), Some(rx_slot));
        assert_eq!(mgr.find_pdu(0x300, SecOcDirection::Tx), Some(tx_slot));
        assert_ne!(rx_slot, tx_slot);
    }

    #[test]
    fn secoc_roundtrip_still_works_with_index() {
        // Verify the index does not break the existing Tx→Rx roundtrip.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        mgr.register_pdu(make_tx_config(0x400)).unwrap();
        mgr.register_pdu(make_rx_config(0x400)).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x400;
        frame.data[0] = 0xCA;
        frame.data[1] = 0xFE;
        mgr.prepare_tx(&mut frame, 2, 5000).unwrap();

        assert_eq!(mgr.verify_rx(&frame, 5000), SecOcVerifyResult::Pass);
    }

    #[test]
    fn prepare_tx_dlc_overflow_returns_resource_exhausted() {
        // Register a Tx PDU with mac_len=16 and freshness_len=8 (trailer = 24 bytes).
        // If auth_data_len = 41, total would be 41 + 8 + 16 = 65 > 64.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let config = SecOcPduConfig {
            can_id: 0x500,
            key_id: 1,
            data_id: 0x0500,
            mac_len: 16,
            freshness_len: 8,
            direction: SecOcDirection::Tx,
            active: false,
        };
        mgr.register_pdu(config).unwrap();

        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x500;
        // Fill 41 bytes of auth data.
        for i in 0..41 {
            frame.data[i] = 0xAA;
        }

        let result = mgr.prepare_tx(&mut frame, 41, 1000);
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn find_pdu_linear_scan_fallback_for_high_can_id() {
        // Register an Rx PDU with can_id >= MAX_PDU_ID_INDEX (2048),
        // which forces linear scan instead of the O(1) index.
        let mut mgr = SecOcManager::new(StubCrypto, 100_000);
        let high_can_id = 3000u32; // above MAX_PDU_ID_INDEX (2048)

        // Register both Tx and Rx for roundtrip verification.
        let tx_config = SecOcPduConfig {
            can_id: high_can_id,
            key_id: 1,
            data_id: 0x0BB8, // 3000 — matches high_can_id for clarity
            mac_len: 4,
            freshness_len: 2,
            direction: SecOcDirection::Tx,
            active: false,
        };
        let rx_config = SecOcPduConfig {
            can_id: high_can_id,
            key_id: 1,
            data_id: 0x0BB8,
            mac_len: 4,
            freshness_len: 2,
            direction: SecOcDirection::Rx,
            active: false,
        };
        mgr.register_pdu(tx_config).unwrap();
        mgr.register_pdu(rx_config).unwrap();

        // Prepare a Tx frame then verify on Rx — exercises linear scan in find_pdu.
        let mut frame = RawCanFrame::zeroed();
        frame.id = high_can_id;
        frame.data[0] = 0xBE;
        frame.data[1] = 0xEF;
        mgr.prepare_tx(&mut frame, 2, 5000).unwrap();

        // verify_rx should find the PDU via linear scan and return Pass (not UnknownPdu).
        let result = mgr.verify_rx(&frame, 5000);
        assert_eq!(
            result,
            SecOcVerifyResult::Pass,
            "PDU with can_id above MAX_PDU_ID_INDEX should be found via linear scan"
        );
    }
}
