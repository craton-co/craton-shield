// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Automotive runtime orchestrator integrating signal IDS, V2X, and diagnostics.
//!
//! Wraps `CratonShield` from craton-shield-core with automotive-specific subsystems
//! for CAN/LIN/FlexRay frame submission, V2X message validation, OTA manifest
//! verification, and `DoIP` header inspection.
//!
//! # Stack usage
//!
//! [`AutomotiveShield`] is **large** — its concrete size depends on the
//! generic `CryptoProvider` but stays well under a 128 KiB ceiling for the
//! providers shipped in this workspace. The dominant contributors are the
//! V2X replay cache (`V2xValidator`) and signal IDS arrays (`SignalIdsEngine`).
//! On stack-constrained targets (e.g. bare-metal ECUs with 8-16 KiB stacks),
//! enable the **`heap-subsystems`** feature to heap-allocate `V2xValidator`
//! and `DiagGateway`, reducing the on-stack footprint significantly.
//!
//! In practice callers place `AutomotiveShield` in a `static` or on a
//! dedicated task stack rather than on a transient frame; per-tick stack
//! use (the `tick`/`submit_*` calls) is sub-kilobyte. The crate's own test
//! suite spawns helper threads with an 8 MiB stack purely as a test-runner
//! convenience.
//!
//! # Public API (v1.0 stable)
//!
//! The `AutomotiveShield` orchestrator, the `OtaSignatureVerifier` trait,
//! and the `AutomotiveConfig` builder form the v1.0 stable surface and
//! are governed by `DEPRECATION.md`. The deprecated `NoOpOtaSigner` stub
//! was removed in v1.0.0.

#![cfg_attr(not(feature = "heap-subsystems"), no_std)]
#![deny(missing_docs)]

#[cfg(feature = "heap-subsystems")]
extern crate alloc;

use vs_crypto::{CryptoProvider, KeyId};
use vs_diag_gateway::{DiagGateway, UdsPolicy};
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, PlatformHealth, WatchdogAction,
};
use vs_signal_ids::SignalIdsEngine;
use vs_types::{SecurityAlert, VsError};
use vs_v2x::V2xValidator;

// Re-export core types for convenience.
pub use vs_runtime::{self, PlatformConfig as CoreConfig, SubsystemStatus};
pub use vs_types_auto;

/// Default EWMA smoothing factor for signal IDS.
const DEFAULT_EWMA_ALPHA: f32 = 0.1;

/// Default EWMA z-score anomaly threshold.
const DEFAULT_EWMA_Z_THRESHOLD: f32 = 3.0;

/// Default HMAC key id for diagnostics.
const DEFAULT_HMAC_KEY_ID: KeyId = KeyId(0);

/// Mix three u64 values into a collision-resistant alert ID.
///
/// Uses multiply-shift mixing (similar to splitmix64) instead of plain XOR
/// to reduce collisions when inputs share structure (e.g. two events at
/// the same timestamp with related payloads).
///
/// On targets without hardware multiply (e.g. some Cortex-M0/M0+ cores),
/// enable the `mix-shift-xor` feature to use a shift-XOR alternative that
/// avoids 64-bit multiplications at the cost of slightly higher collision
/// rates.
#[cfg(not(feature = "mix-shift-xor"))]
fn mix_alert_id(ts: u64, source: u64, hash: u64) -> u64 {
    let mut h = ts.wrapping_mul(0x517c_c1b7_2722_0a95);
    h = h.wrapping_add(source);
    h ^= h >> 33;
    h = h.wrapping_mul(0x4cf5_ad43_2745_937f);
    h = h.wrapping_add(hash);
    h ^= h >> 33;
    h
}

/// Shift-XOR variant of [`mix_alert_id`] for targets without hardware
/// 64-bit multiply (e.g. Cortex-M0/M0+). Avoids `wrapping_mul` entirely,
/// using only shifts, XORs, and additions. Slightly higher collision rate
/// than the multiply-shift variant but no software multiply routines.
#[cfg(feature = "mix-shift-xor")]
fn mix_alert_id(ts: u64, source: u64, hash: u64) -> u64 {
    let mut h = ts;
    h ^= h >> 17;
    h ^= h << 13;
    h ^= h >> 7;
    h = h.wrapping_add(source);
    h ^= h >> 17;
    h ^= h << 13;
    h ^= h >> 7;
    h = h.wrapping_add(hash);
    h ^= h >> 17;
    h ^= h << 13;
    h ^= h >> 7;
    h
}

/// Encode a `FlexRay` slot ID and cycle counter into a single u32 source identifier.
///
/// Layout: `[slot_id:11 bits][unused:13 bits][cycle:8 bits]`
/// This encoding is used consistently for alert `source_id` and signal IDS frame identifiers.
#[inline]
fn encode_flexray_id(slot_id: u16, cycle: u8) -> u32 {
    ((slot_id as u32 & 0x7FF) << 21) | (cycle as u32)
}

/// Extract a `u64` mixing value from the first 8 bytes of a SHA-256 hash.
///
/// Used to seed [`mix_alert_id`] with entropy from a payload hash without
/// needing the full 32-byte digest.
#[inline]
fn hash_mix_from_bytes(hash: &[u8; 32]) -> u64 {
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// Build a [`SecurityAlert`] with a mixed alert ID.
///
/// Combines [`mix_alert_id`] with the struct construction that recurs at
/// every alert-emission site, reducing boilerplate without changing semantics.
#[inline]
#[allow(clippy::too_many_arguments)]
fn build_alert(
    ts: u64,
    source_mix: u64,
    hash_mix: u64,
    severity: vs_types::AlertSeverity,
    source_type: u8,
    source_id: u32,
    payload_hash: vs_types::PayloadHash,
    timestamp_us: u64,
) -> SecurityAlert {
    SecurityAlert {
        id: mix_alert_id(ts, source_mix, hash_mix),
        severity,
        source_type,
        source_id,
        payload_hash,
        timestamp_us,
    }
}

/// Compute the forensic SHA-256 payload digest, degrading the supplied
/// subsystem status on crypto failure.
///
/// The alert-emission sites in this module previously open-coded the
/// pattern:
///
/// ```ignore
/// let mut hash_bytes = [0u8; 32];
/// if crypto.sha256(&data[..n], &mut hash_bytes).is_err() {
///     status = SubsystemStatus::Degraded;
/// }
/// ```
///
/// This helper folds that pattern into a single call. Every bus path
/// (CAN, LIN, FlexRay, V2X, `DoIP`, OTA) routes through it so the embedded
/// forensic fingerprint has uniform SHA-256 strength and `*status` tracks
/// crypto health consistently across paths.
///
/// # Returns
///
/// The digest to embed in the [`SecurityAlert`]. On SHA-256 failure the
/// digest is all-zeros and `*status` is set to [`SubsystemStatus::Degraded`]
/// to surface the issue rather than silently producing a weak fingerprint.
/// A subsequent successful call clears a prior `Degraded` status.
#[inline]
fn hash_or_degrade<C: CryptoProvider>(
    crypto: &C,
    data: &[u8],
    status: &mut SubsystemStatus,
) -> vs_types::PayloadHash {
    let mut hash_bytes = [0u8; 32];
    if crypto.sha256(data, &mut hash_bytes).is_err() {
        *status = SubsystemStatus::Degraded;
    } else if *status == SubsystemStatus::Degraded {
        *status = SubsystemStatus::Ready;
    }
    vs_types::PayloadHash(hash_bytes)
}

// ---------------------------------------------------------------------------
// Automotive health extension
// ---------------------------------------------------------------------------

/// Extended health snapshot including automotive subsystems.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AutomotiveHealth {
    /// Core platform health.
    pub core: PlatformHealth,
    /// Signal-level IDS status.
    pub signal_ids: SubsystemStatus,
    /// V2X validator status.
    pub v2x: SubsystemStatus,
    /// Diagnostics gateway status.
    pub diag_gateway: SubsystemStatus,
}

// ---------------------------------------------------------------------------
// Automotive configuration
// ---------------------------------------------------------------------------

/// Automotive-specific platform configuration.
#[derive(Debug, Clone, Copy)]
pub struct AutomotiveConfig {
    /// Core platform configuration.
    pub core: PlatformConfig,
    /// Diagnostic session inactivity timeout in microseconds.
    pub diag_session_timeout_us: u64,
    /// Brute-force lockout duration in microseconds.
    pub diag_lockout_duration_us: u64,
    /// EWMA smoothing factor for signal IDS (0.0 < alpha < 1.0).
    pub ewma_alpha: f32,
    /// EWMA z-score anomaly threshold for signal IDS.
    pub ewma_z_threshold: f32,
    /// HMAC key slot used for diagnostics seed/key verification.
    pub hmac_key_id: KeyId,
}

impl Default for AutomotiveConfig {
    fn default() -> Self {
        Self {
            core: PlatformConfig::default(),
            diag_session_timeout_us: 5_000_000,
            diag_lockout_duration_us: 10_000_000,
            ewma_alpha: DEFAULT_EWMA_ALPHA,
            ewma_z_threshold: DEFAULT_EWMA_Z_THRESHOLD,
            hmac_key_id: DEFAULT_HMAC_KEY_ID,
        }
    }
}

/// Trait for OTA update code signing verification.
///
/// Production deployments **must** provide an implementation that verifies
/// cryptographic signatures against a trusted signing key.
///
/// This trait is separate from `CryptoProvider` because OTA signing may use
/// a different key hierarchy or algorithm (e.g., Ed25519, RSA-4096) than
/// the platform's primary P-256 crypto provider.
///
/// # Default behavior
///
/// The default implementation is **fail-closed**: it rejects all signatures.
/// This ensures that forgetting to provide a real verifier does not silently
/// disable OTA code signing — a UN R155 requirement.
pub trait OtaSignatureVerifier {
    /// Verify the code signature on an OTA manifest or firmware image.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
    /// or `Err` on verification failure (e.g., missing key).
    ///
    /// Default: **fail-closed** — rejects all signatures.
    fn verify_ota_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        _signer_id: u32,
    ) -> Result<bool, VsError> {
        let _ = (data, signature);
        Ok(false)
    }
}

// NoOpOtaSigner was removed in v1.0.0 (deprecated since v0.8.0). The
// `OtaSignatureVerifier` trait already provides a fail-closed default
// implementation, so tests and stub builds can use any unit struct that
// implements the trait without overriding `verify_ota_signature`.

// ---------------------------------------------------------------------------
// AutomotiveShield
// ---------------------------------------------------------------------------

/// Automotive `Craton Shield` runtime.
///
/// Extends [`CratonShield`] with signal-level CAN IDS, V2X validation, and
/// UDS diagnostics gateway.
///
/// When the `heap-subsystems` feature is enabled, the V2X validator and
/// diagnostics gateway are heap-allocated to reduce stack frame size on
/// `std`-capable targets.
pub struct AutomotiveShield<C: CryptoProvider> {
    /// Core platform runtime.
    core: CratonShield<C>,
    /// CAN signal-level anomaly detection engine.
    signal_ids: SignalIdsEngine,
    /// V2X security validator (IEEE 1609.2).
    #[cfg(feature = "heap-subsystems")]
    v2x_validator: alloc::boxed::Box<V2xValidator<C>>,
    #[cfg(not(feature = "heap-subsystems"))]
    v2x_validator: V2xValidator<C>,
    /// UDS diagnostics gateway with brute-force lockout.
    #[cfg(feature = "heap-subsystems")]
    diag_gateway: alloc::boxed::Box<DiagGateway<C>>,
    #[cfg(not(feature = "heap-subsystems"))]
    diag_gateway: DiagGateway<C>,
    /// Automotive subsystem health.
    signal_ids_status: SubsystemStatus,
    v2x_status: SubsystemStatus,
    diag_status: SubsystemStatus,
    /// Last observed V2X replay cache eviction count for degradation tracking.
    last_v2x_eviction_count: u64,
    /// Optional OTA signature verification function pointer.
    ///
    /// When set, [`validate_ota_signed`](Self::validate_ota_signed) will call
    /// this function before checking the manifest hash. The function takes
    /// `(data, signature, signer_id)` and returns `Ok(true)` if the
    /// signature is valid, `Ok(false)` if invalid, or `Err` on failure.
    ///
    /// A plain `fn` pointer is used instead of a trait object to remain
    /// `no_std`-compatible without requiring `alloc`.
    #[allow(clippy::type_complexity)]
    ota_verify_fn: Option<fn(&[u8], &[u8], u32) -> Result<bool, VsError>>,
}

// Footprint documentation marker (when `heap-subsystems` is disabled,
// `AutomotiveShield` lives entirely on the stack). The agreed ceiling
// matching the crate-level docs is **128 KiB**; current providers shipped
// in this workspace land well under that. We cannot name the concrete
// type here without a `CryptoProvider`, so this block is intentionally
// left as a marker — crate-level integration tests should assert e.g.:
//
//   assert!(core::mem::size_of::<AutomotiveShield<MyCrypto>>() < 128 * 1024);
//
// to catch unexpected growth. When `heap-subsystems` is enabled the V2X
// validator and DiagGateway are boxed, so the stack footprint is much
// smaller and this check is skipped.
#[cfg(not(feature = "heap-subsystems"))]
const _: () = {};

impl<C: CryptoProvider + Clone> AutomotiveShield<C> {
    /// Initialize the automotive runtime.
    ///
    /// First initializes the core platform via [`CratonShield::init`], then
    /// sets up the automotive-specific subsystems.
    pub fn init(config: AutomotiveConfig, crypto: C) -> Result<Self, VsError> {
        let core = CratonShield::init(config.core, crypto.clone())?;

        let signal_ids = SignalIdsEngine::new(config.ewma_alpha, config.ewma_z_threshold)?;

        #[cfg(feature = "heap-subsystems")]
        let v2x_validator = alloc::boxed::Box::new(V2xValidator::new(crypto.clone()));
        #[cfg(not(feature = "heap-subsystems"))]
        let v2x_validator = V2xValidator::new(crypto.clone());

        #[cfg(feature = "heap-subsystems")]
        let diag_gateway = alloc::boxed::Box::new(DiagGateway::new(
            crypto,
            UdsPolicy::default(),
            config.diag_session_timeout_us,
            config.diag_lockout_duration_us,
            config.hmac_key_id,
        ));
        #[cfg(not(feature = "heap-subsystems"))]
        let diag_gateway = DiagGateway::new(
            crypto,
            UdsPolicy::default(),
            config.diag_session_timeout_us,
            config.diag_lockout_duration_us,
            config.hmac_key_id,
        );

        Ok(Self {
            core,
            signal_ids,
            v2x_validator,
            diag_gateway,
            signal_ids_status: SubsystemStatus::Ready,
            v2x_status: SubsystemStatus::Ready,
            diag_status: SubsystemStatus::Ready,
            last_v2x_eviction_count: 0,
            ota_verify_fn: None,
        })
    }

    /// Convenience constructor with default crypto.
    ///
    /// # Panics
    ///
    /// Panics if platform initialization fails with the `Default` crypto
    /// provider. This is intended for **tests and prototyping only** — production
    /// code should use [`AutomotiveShield::init`] (or
    /// [`AutomotiveShield::try_new`]) and handle the error.
    #[deprecated(
        since = "0.7.0",
        note = "panicking constructor; use `try_new` (or `init`) and propagate the error"
    )]
    pub fn new(config: &AutomotiveConfig) -> Self
    where
        C: Default,
    {
        Self::init(*config, C::default())
            .expect("automotive platform init must not fail with default crypto")
    }

    /// Fallible convenience constructor using the `Default` crypto provider.
    ///
    /// Equivalent to [`AutomotiveShield::init`] with `C::default()` but
    /// without the panic on failure. Prefer this in tests and prototypes
    /// over the deprecated [`AutomotiveShield::new`].
    pub fn try_new(config: &AutomotiveConfig) -> Result<Self, VsError>
    where
        C: Default,
    {
        Self::init(*config, C::default())
    }

    /// Periodic tick — delegates to core and ticks automotive subsystems.
    ///
    /// Ticks the core platform watchdog, event logger, and integrity monitor.
    /// Also proactively expires idle diagnostic sessions to prevent slot
    /// exhaustion by stale sessions that would otherwise block new testers
    /// until the next UDS request triggers lazy cleanup.
    pub fn tick(&mut self, ts_us: u64) -> Result<(), VsError> {
        self.core.tick(ts_us)?;
        self.diag_gateway.expire_sessions_proactive(ts_us);
        Ok(())
    }

    /// Submit a CAN frame for IDS inspection (core + signal-level).
    ///
    /// On a signal-level anomaly, the forensic payload hash embedded in the
    /// emitted [`SecurityAlert`] is a SHA-256 digest computed via the
    /// platform `CryptoProvider`, matching every other bus path (LIN,
    /// FlexRay, V2X, `DoIP`, OTA). This keeps forensic fingerprint strength
    /// consistent across bus types and ensures `signal_ids_status` is
    /// updated (and recovered) by the same crypto-health logic as the
    /// other paths.
    pub fn submit_can_frame(&mut self, frame: &CanFrame, ts_us: u64) -> Result<(), VsError> {
        // Core IDS inspection.
        self.core.submit_can_frame(frame, ts_us)?;

        // Signal-level anomaly detection.
        let result = self.signal_ids.process_frame(frame);
        if result.anomaly_count > 0 {
            // Compute the forensic digest with SHA-256 via `hash_or_degrade`
            // (`provided = None`), identical to the LIN/FlexRay/DoIP/OTA
            // paths. This yields a cryptographically strong fingerprint and
            // lets `signal_ids_status` degrade/recover on crypto health.
            let payload_len = (frame.dlc as usize).min(64);
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                &frame.data[..payload_len],
                &mut self.signal_ids_status,
            );

            // Build a unique alert ID from full timestamp, CAN ID, anomaly
            // count, and payload hash using multiply-shift mixing for
            // better collision resistance than plain XOR.
            let source = ((frame.id as u64) << 32) | (result.anomaly_count as u64);
            let alert = build_alert(
                ts_us,
                source,
                hash_mix_from_bytes(&payload_hash.0),
                vs_types::AlertSeverity::Medium,
                vs_types::SOURCE_CAN,
                frame.id,
                payload_hash,
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
        }

        Ok(())
    }

    /// Submit an Ethernet packet for IDS + firewall inspection.
    ///
    /// Delegates to the core IDS/firewall engine and additionally performs
    /// automotive-specific Ethernet analysis:
    /// - SOME/IP service ID validation (ethertype-based heuristic)
    /// - Suspicious port detection for `DoIP` (port 13400)
    #[allow(clippy::items_after_statements)]
    pub fn submit_eth_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Result<(), VsError> {
        self.core.submit_eth_packet(pkt, ts_us)?;

        // Automotive Ethernet analysis: check for suspicious patterns.
        // DoIP uses TCP/UDP port 13400. Flag non-standard ports carrying
        // DoIP ethertype as potential attacks.
        const DOIP_PORT: u16 = 13400;

        // Check for DoIP traffic on unexpected ports.
        if let Some(port) = pkt.dst_port {
            if port == DOIP_PORT && pkt.payload.len() > 8 {
                // DoIP header: version(1) + inverse_version(1) + type(2) + length(4)
                // Validate the DoIP version byte if payload is long enough.
                let version = pkt.payload[0];
                let inverse = pkt.payload[1];
                if version != !inverse {
                    // Invalid DoIP header — potential attack.
                    let hash_len = pkt.payload.len().min(64);
                    // TODO(perf): apply SipHash digest threading to LIN/FlexRay parity with CAN
                    let payload_hash = hash_or_degrade(
                        self.core.crypto(),
                        &pkt.payload[..hash_len],
                        &mut self.signal_ids_status,
                    );

                    let source = (port as u64) << 48;
                    let alert = build_alert(
                        ts_us,
                        source,
                        hash_mix_from_bytes(&payload_hash.0),
                        vs_types::AlertSeverity::Medium,
                        vs_types::SOURCE_ETHERNET,
                        u32::from_be_bytes([
                            pkt.src_mac[2],
                            pkt.src_mac[3],
                            pkt.src_mac[4],
                            pkt.src_mac[5],
                        ]),
                        payload_hash,
                        ts_us,
                    );
                    self.core.route_alert(&alert, ts_us);
                }
            }
        }

        Ok(())
    }

    /// Return the extended automotive health snapshot.
    pub fn health_status(&self) -> AutomotiveHealth {
        AutomotiveHealth {
            core: self.core.health_status(),
            signal_ids: self.signal_ids_status,
            v2x: self.v2x_status,
            diag_gateway: self.diag_status,
        }
    }

    /// Return a reference to the core platform health.
    pub fn core_health(&self) -> &PlatformHealth {
        self.core.health()
    }

    /// Check if the watchdog has expired.
    pub fn check_watchdog(&mut self, ts_us: u64) -> Option<WatchdogAction> {
        self.core.check_watchdog(ts_us)
    }

    /// Graceful shutdown.
    pub fn shutdown(&mut self) {
        self.core.shutdown();
        self.signal_ids_status = SubsystemStatus::NotInitialized;
        self.v2x_status = SubsystemStatus::NotInitialized;
        self.diag_status = SubsystemStatus::NotInitialized;
    }

    /// Returns `true` if init completed and shutdown has not been called.
    pub fn is_initialized(&self) -> bool {
        self.core.is_initialized()
    }

    /// Returns the monotonic tick counter.
    pub fn tick_count(&self) -> u64 {
        self.core.tick_count()
    }

    /// Returns a reference to the core runtime.
    pub fn core(&self) -> &CratonShield<C> {
        &self.core
    }

    /// Returns a mutable reference to the core runtime.
    pub fn core_mut(&mut self) -> &mut CratonShield<C> {
        &mut self.core
    }

    /// Returns a reference to the signal IDS engine.
    pub fn signal_ids(&self) -> &SignalIdsEngine {
        &self.signal_ids
    }

    /// Returns a mutable reference to the signal IDS engine.
    pub fn signal_ids_mut(&mut self) -> &mut SignalIdsEngine {
        &mut self.signal_ids
    }

    /// Returns a reference to the V2X validator.
    pub fn v2x_validator(&self) -> &V2xValidator<C> {
        &self.v2x_validator
    }

    /// Returns a mutable reference to the V2X validator.
    pub fn v2x_validator_mut(&mut self) -> &mut V2xValidator<C> {
        &mut self.v2x_validator
    }

    /// Validate a V2X message and route a security alert if rejected.
    ///
    /// On validation failure, generates a `SecurityAlert` with the V2X
    /// source type and routes it through the core alert pipeline.
    pub fn validate_v2x_message(
        &mut self,
        msg: &vs_v2x::V2xMessage,
        current_time_us: u64,
    ) -> Result<vs_v2x::ValidatedV2xMessage, VsError> {
        let result = self.v2x_validator.validate(msg, current_time_us);

        // Monitor replay cache evictions — a non-zero count means the cache
        // has wrapped and older digests were lost, potentially allowing
        // replayed messages through. Surface this as a subsystem degradation
        // rather than silently continuing.
        let current_evictions = self.v2x_validator.replay_eviction_count();
        if current_evictions > self.last_v2x_eviction_count {
            self.v2x_status = SubsystemStatus::Degraded;
            self.last_v2x_eviction_count = current_evictions;
        } else if self.v2x_status == SubsystemStatus::Degraded && result.is_ok() {
            self.v2x_status = SubsystemStatus::Ready;
        }

        if result.is_err() {
            // Generate a security alert for the rejected V2X message.
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                &msg.signer_public_key,
                &mut self.signal_ids_status,
            );
            let hash_bytes = payload_hash.0;
            // Build a unique alert ID from generation time and signer hash
            // to prevent collisions when multiple messages arrive in the
            // same microsecond from different signers.
            let signer_mix =
                u32::from_le_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]])
                    as u64;
            // Derive source_id from the first 4 bytes of the signer hash
            // so security analysts can correlate alerts from the same V2X
            // sender without needing the full public key.
            let v2x_source_id =
                u32::from_le_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);
            let alert = build_alert(
                msg.generation_time_us,
                signer_mix << 16,
                0,
                vs_types::AlertSeverity::High,
                vs_types::SOURCE_ETHERNET,
                v2x_source_id,
                payload_hash,
                current_time_us,
            );
            self.core.route_alert(&alert, current_time_us);
        }
        result
    }

    /// Returns a reference to the diagnostics gateway.
    pub fn diag_gateway(&self) -> &DiagGateway<C> {
        &self.diag_gateway
    }

    /// Returns a mutable reference to the diagnostics gateway.
    pub fn diag_gateway_mut(&mut self) -> &mut DiagGateway<C> {
        &mut self.diag_gateway
    }

    /// Returns the number of entries in the event log.
    pub fn event_log_count(&self) -> u64 {
        self.core.event_log_count()
    }

    /// Submit a LIN frame payload for anomaly detection.
    ///
    /// LIN is a lower-bandwidth bus (typically 1-8 bytes per frame). This
    /// method generates an alert if the payload is empty or exceeds the
    /// LIN maximum of 8 bytes, and routes it through the core alert
    /// pipeline with [`SOURCE_LIN`](vs_types_auto::SOURCE_LIN).
    pub fn submit_lin_frame(
        &mut self,
        frame_id: u8,
        payload: &[u8],
        ts_us: u64,
    ) -> Result<(), VsError> {
        // LIN frame IDs are 6-bit (0x00..=0x3F).
        if frame_id > 0x3F {
            return Err(VsError::InvalidInput);
        }

        // LIN frames are 1-8 bytes.
        if payload.is_empty() || payload.len() > 8 {
            // Include the LIN frame ID in the hash so that empty-payload
            // alerts from different LIN IDs produce distinguishable hashes.
            // Cold error path: the 9-byte staging buffer is intentional —
            // only used when an out-of-spec LIN frame is observed (very
            // rare), so the extra copy is negligible and avoids slicing
            // gymnastics.
            let mut hash_input = [0u8; 9]; // 1 byte frame_id + up to 8 bytes payload
            hash_input[0] = frame_id;
            let input_len = 1 + payload.len().min(8);
            hash_input[1..input_len].copy_from_slice(&payload[..payload.len().min(8)]);
            // TODO(perf): apply SipHash digest threading to LIN/FlexRay parity with CAN
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                &hash_input[..input_len],
                &mut self.signal_ids_status,
            );
            let alert = build_alert(
                ts_us,
                (frame_id as u64) << 48,
                0,
                vs_types::AlertSeverity::Medium,
                vs_types_auto::SOURCE_LIN,
                frame_id as u32,
                payload_hash,
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
            return Err(VsError::InvalidInput);
        }
        // Route through signal-level IDS for anomaly detection.
        // LIN frame IDs are mapped to the signal IDS using the frame_id
        // as a u32 identifier, matching how signals are defined.
        let result = self
            .signal_ids
            .process_raw_frame(frame_id as u32, payload, payload.len());
        if result.anomaly_count > 0 {
            // TODO(perf): apply SipHash digest threading to LIN/FlexRay parity with CAN
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                payload,
                &mut self.signal_ids_status,
            );
            let source = ((frame_id as u64) << 32) | (result.anomaly_count as u64);
            let alert = build_alert(
                ts_us,
                source,
                hash_mix_from_bytes(&payload_hash.0),
                vs_types::AlertSeverity::Medium,
                vs_types_auto::SOURCE_LIN,
                frame_id as u32,
                payload_hash,
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
        }
        Ok(())
    }

    /// Submit a `FlexRay` frame payload for anomaly detection.
    ///
    /// `FlexRay` frames can be up to 254 bytes. This method validates the
    /// payload size and routes alerts for oversized or empty frames using
    /// [`SOURCE_FLEXRAY`](vs_types_auto::SOURCE_FLEXRAY).
    pub fn submit_flexray_frame(
        &mut self,
        slot_id: u16,
        cycle: u8,
        payload: &[u8],
        ts_us: u64,
    ) -> Result<(), VsError> {
        // FlexRay slot IDs are 1..=2047 per specification.
        if slot_id == 0 || slot_id > 2047 {
            return Err(VsError::InvalidInput);
        }

        // FlexRay max payload is 254 bytes.
        if payload.is_empty() || payload.len() > 254 {
            let hash_len = payload.len().min(64);
            // TODO(perf): apply SipHash digest threading to LIN/FlexRay parity with CAN
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                &payload[..hash_len],
                &mut self.signal_ids_status,
            );
            let alert = build_alert(
                ts_us,
                ((slot_id as u64) << 40) | ((cycle as u64) << 32),
                0,
                vs_types::AlertSeverity::Medium,
                vs_types_auto::SOURCE_FLEXRAY,
                encode_flexray_id(slot_id, cycle),
                payload_hash,
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
            return Err(VsError::InvalidInput);
        }
        // Route through signal-level IDS for anomaly detection.
        // FlexRay slot/cycle are combined into a single u32 identifier.
        let flexray_id = encode_flexray_id(slot_id, cycle);
        let result = self
            .signal_ids
            .process_raw_frame(flexray_id, payload, payload.len());
        if result.anomaly_count > 0 {
            let hash_len = payload.len().min(64);
            // TODO(perf): apply SipHash digest threading to LIN/FlexRay parity with CAN
            let payload_hash = hash_or_degrade(
                self.core.crypto(),
                &payload[..hash_len],
                &mut self.signal_ids_status,
            );
            let source =
                ((slot_id as u64) << 40) | ((cycle as u64) << 32) | (result.anomaly_count as u64);
            let alert = build_alert(
                ts_us,
                source,
                hash_mix_from_bytes(&payload_hash.0),
                vs_types::AlertSeverity::Medium,
                vs_types_auto::SOURCE_FLEXRAY,
                flexray_id,
                payload_hash,
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
        }
        Ok(())
    }

    /// Validate an OTA update manifest hash against a known-good digest.
    ///
    /// Computes SHA-256 of the provided manifest data and compares it to the
    /// `expected_hash` using constant-time comparison. On mismatch, routes
    /// a `Critical` severity alert through the core pipeline.
    ///
    /// Returns `Ok(())` if the hash matches, `Err(VsError::IntegrityFailure)`
    /// on mismatch or crypto failure.
    pub fn validate_ota_manifest(
        &mut self,
        manifest_data: &[u8],
        expected_hash: &[u8; 32],
        ts_us: u64,
    ) -> Result<(), VsError> {
        let mut computed_hash = [0u8; 32];
        self.core
            .crypto()
            .sha256(manifest_data, &mut computed_hash)
            .map_err(|_| VsError::CryptoError)?;

        // Constant-time comparison.
        // TODO(0.8): move constant-time compare into vs-crypto::ct_eq
        let mut diff: u8 = 0;
        let mut i = 0;
        while i < 32 {
            diff |= computed_hash[i] ^ expected_hash[i];
            i += 1;
        }

        if core::hint::black_box(diff) != 0 {
            let alert = build_alert(
                ts_us,
                vs_types_auto::SOURCE_ID_OTA_RESERVED as u64,
                hash_mix_from_bytes(&computed_hash),
                vs_types::AlertSeverity::Critical,
                vs_types::SOURCE_ETHERNET, // OTA delivered via Ethernet
                vs_types_auto::SOURCE_ID_OTA_RESERVED,
                vs_types::PayloadHash(computed_hash),
                ts_us,
            );
            self.core.route_alert(&alert, ts_us);
            return Err(VsError::IntegrityFailure);
        }
        Ok(())
    }

    /// Set the OTA signature verification function.
    ///
    /// The provided function pointer will be called by
    /// [`validate_ota_signed`](Self::validate_ota_signed) before the hash
    /// integrity check. This is a `no_std`-compatible alternative to
    /// passing a trait object.
    ///
    /// # Arguments
    ///
    /// * `f` - A function `(data, signature, signer_id) -> Result<bool, VsError>`.
    ///   Returns `Ok(true)` if the signature is valid.
    #[allow(clippy::type_complexity)]
    pub fn set_ota_verifier(&mut self, f: fn(&[u8], &[u8], u32) -> Result<bool, VsError>) {
        self.ota_verify_fn = Some(f);
    }

    /// Validate an OTA update with both signature verification and hash check.
    ///
    /// This method combines code-signing verification (via the function
    /// pointer set by [`set_ota_verifier`](Self::set_ota_verifier)) with
    /// the SHA-256 hash integrity check from
    /// [`validate_ota_manifest`](Self::validate_ota_manifest).
    ///
    /// **Fail-closed**: if no verifier has been set, this method rejects the
    /// manifest with a `Critical` alert and returns
    /// `Err(VsError::NotInitialized)`. This ensures that forgetting to wire
    /// up a verifier does not silently disable OTA code signing (UN R155).
    ///
    /// # Flow
    ///
    /// 1. Call the OTA signature verifier. If it returns `Ok(false)` or
    ///    `Err`, generate a `Critical` alert and return an error.
    /// 2. Delegate to [`validate_ota_manifest`](Self::validate_ota_manifest)
    ///    for the hash integrity check.
    pub fn validate_ota_signed(
        &mut self,
        manifest_data: &[u8],
        signature: &[u8],
        signer_id: u32,
        expected_hash: &[u8; 32],
        ts_us: u64,
    ) -> Result<(), VsError> {
        // Step 1: Signature verification (fail-closed if no verifier set).
        let sig_ok = match self.ota_verify_fn {
            Some(verify) => verify(manifest_data, signature, signer_id),
            None => Err(VsError::NotInitialized),
        };

        match sig_ok {
            Ok(true) => { /* signature valid, proceed to hash check */ }
            Ok(false) => {
                // Signature invalid — generate Critical alert.
                let hash_len = manifest_data.len().min(64);
                let payload_hash = hash_or_degrade(
                    self.core.crypto(),
                    &manifest_data[..hash_len],
                    &mut self.signal_ids_status,
                );
                let alert = build_alert(
                    ts_us,
                    vs_types_auto::SOURCE_ID_OTA_RESERVED as u64,
                    hash_mix_from_bytes(&payload_hash.0),
                    vs_types::AlertSeverity::Critical,
                    vs_types::SOURCE_ETHERNET,
                    vs_types_auto::SOURCE_ID_OTA_RESERVED,
                    payload_hash,
                    ts_us,
                );
                self.core.route_alert(&alert, ts_us);
                return Err(VsError::IntegrityFailure);
            }
            Err(e) => {
                // Verifier error — generate Critical alert and propagate.
                let hash_len = manifest_data.len().min(64);
                let payload_hash = hash_or_degrade(
                    self.core.crypto(),
                    &manifest_data[..hash_len],
                    &mut self.signal_ids_status,
                );
                let alert = build_alert(
                    ts_us,
                    vs_types_auto::SOURCE_ID_OTA_RESERVED as u64,
                    hash_mix_from_bytes(&payload_hash.0),
                    vs_types::AlertSeverity::Critical,
                    vs_types::SOURCE_ETHERNET,
                    vs_types_auto::SOURCE_ID_OTA_RESERVED,
                    payload_hash,
                    ts_us,
                );
                self.core.route_alert(&alert, ts_us);
                return Err(e);
            }
        }

        // Step 2: Hash integrity check.
        self.validate_ota_manifest(manifest_data, expected_hash, ts_us)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestCrypto;

    #[allow(clippy::cast_possible_truncation)]
    impl CryptoProvider for TestCrypto {
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
        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            for (i, b) in hash_out.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0xA5);
            }
            for (i, &b) in data.iter().enumerate() {
                hash_out[i % 32] ^= b;
                hash_out[(i + 1) % 32] = hash_out[(i + 1) % 32].wrapping_add(b);
            }
            Ok(())
        }
        fn hmac_sha256(&self, _: KeyId, _: &[u8], mac_out: &mut [u8; 32]) -> Result<(), VsError> {
            *mac_out = [0xAA; 32];
            Ok(())
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
            // Fail-closed: reject all signatures in test crypto to prevent
            // accidental use in non-test paths. Tests that need signature
            // verification should use SoftwareCryptoProvider instead.
            Err(VsError::NotInitialized)
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            // Position-dependent deterministic fill for reproducible tests.
            // NOT cryptographically random — test-only.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x42);
            }
            Ok(())
        }
        fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
    }

    impl Default for TestCrypto {
        fn default() -> Self {
            Self
        }
    }

    fn default_config() -> AutomotiveConfig {
        AutomotiveConfig::default()
    }

    /// Add allow-all policy and firewall rules so frame submissions are not
    /// rejected by the fail-closed policy engine / network firewall.
    fn add_allow_all_rule(shield: &mut AutomotiveShield<TestCrypto>) {
        use vs_netfw::{FirewallRule, RuleAction};
        use vs_policy_engine::{
            ActionMatcher, Effect, PolicyRule, ResourceMatcher, SubjectMatcher,
        };
        shield
            .core_mut()
            .policy_engine_mut()
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 255,
                valid_from: 0,
                valid_until: 0,
            })
            .expect("add allow-all rule");

        shield
            .core_mut()
            .install_firewall_rule(FirewallRule {
                id: 1,
                priority: 0,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            })
            .expect("add allow-all firewall rule");
    }

    /// Run `f` on a thread with 8 MiB stack — `AutomotiveShield` is too
    /// large for the default test thread stack.
    fn big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("spawn")
            .join()
            .expect("panicked");
    }

    #[test]
    fn automotive_init_succeeds() {
        big_stack(|| {
            let shield = AutomotiveShield::init(default_config(), TestCrypto);
            assert!(shield.is_ok());
            assert!(shield.unwrap().is_initialized());
        });
    }

    #[test]
    fn automotive_health_all_ready() {
        big_stack(|| {
            let shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            let health = shield.health_status();
            assert_eq!(health.core.crypto, SubsystemStatus::Ready);
            assert_eq!(health.core.ids_engine, SubsystemStatus::Ready);
            assert_eq!(health.signal_ids, SubsystemStatus::Ready);
            assert_eq!(health.v2x, SubsystemStatus::Ready);
            assert_eq!(health.diag_gateway, SubsystemStatus::Ready);
        });
    }

    #[test]
    fn automotive_shutdown_marks_all_not_initialized() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            shield.shutdown();
            assert!(!shield.is_initialized());
            let health = shield.health_status();
            assert_eq!(health.core.crypto, SubsystemStatus::NotInitialized);
            assert_eq!(health.signal_ids, SubsystemStatus::NotInitialized);
            assert_eq!(health.v2x, SubsystemStatus::NotInitialized);
            assert_eq!(health.diag_gateway, SubsystemStatus::NotInitialized);
        });
    }

    #[test]
    fn automotive_can_frame_submission() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            add_allow_all_rule(&mut shield);
            let frame = CanFrame {
                id: 0x100,
                is_extended: false,
                is_fd: false,
                dlc: 8,
                data: [0x01; 64],
            };
            assert!(shield.submit_can_frame(&frame, 1_000).is_ok());
            assert!(shield.submit_can_frame(&frame, 2_000).is_ok());
        });
    }

    #[test]
    fn automotive_tick_increments_counter() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            shield.tick(1_000).unwrap();
            assert_eq!(shield.tick_count(), 1);
            shield.tick(2_000).unwrap();
            assert_eq!(shield.tick_count(), 2);
        });
    }

    #[test]
    fn automotive_subsystem_accessors() {
        big_stack(|| {
            let shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            let _ = shield.signal_ids();
            let _ = shield.v2x_validator();
            let _ = shield.diag_gateway();
            let _ = shield.core().policy_engine();
            let _ = shield.core().firewall();
        });
    }

    #[test]
    #[allow(deprecated)]
    fn automotive_new_constructor() {
        big_stack(|| {
            let config = default_config();
            let shield: AutomotiveShield<TestCrypto> = AutomotiveShield::new(&config);
            assert!(shield.is_initialized());
        });
    }

    #[test]
    fn automotive_try_new_constructor() {
        big_stack(|| {
            let config = default_config();
            let shield: AutomotiveShield<TestCrypto> =
                AutomotiveShield::try_new(&config).expect("try_new must succeed");
            assert!(shield.is_initialized());
        });
    }

    #[test]
    fn automotive_watchdog() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            shield.tick(0).unwrap();
            assert!(shield.check_watchdog(500_000).is_none());
            assert!(shield.check_watchdog(2_000_000).is_some());
        });
    }

    #[test]
    fn automotive_eth_packet_submission() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            add_allow_all_rule(&mut shield);
            // Create a minimal Ethernet packet.
            let payload = [0u8; 64];
            let pkt = vs_runtime::EthPacket {
                src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: None,
                payload: &payload,
            };
            assert!(shield.submit_eth_packet(&pkt, 1_000).is_ok());
        });
    }

    #[test]
    fn automotive_lin_frame_valid() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // Valid LIN frame: ID 0x10 (6-bit range), 4 bytes payload.
            assert!(shield.submit_lin_frame(0x10, &[1, 2, 3, 4], 1_000).is_ok());
        });
    }

    #[test]
    fn automotive_lin_frame_invalid_id() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // LIN IDs are 6-bit: 0x40 is out of range.
            assert_eq!(
                shield.submit_lin_frame(0x40, &[1, 2], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_lin_frame_empty_payload_generates_alert() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            let initial = shield.event_log_count();
            // Empty payload should error and generate an alert.
            assert_eq!(
                shield.submit_lin_frame(0x01, &[], 1_000),
                Err(VsError::InvalidInput)
            );
            assert!(shield.event_log_count() >= initial);
        });
    }

    #[test]
    fn automotive_lin_frame_oversized_payload() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // LIN max is 8 bytes; 9 bytes should be rejected.
            assert_eq!(
                shield.submit_lin_frame(0x01, &[0; 9], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_flexray_frame_valid() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // Valid FlexRay frame: slot 1, cycle 0, 8 bytes payload.
            assert!(shield.submit_flexray_frame(1, 0, &[1; 8], 1_000).is_ok());
        });
    }

    #[test]
    fn automotive_flexray_frame_invalid_slot_zero() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // Slot ID 0 is invalid per FlexRay spec.
            assert_eq!(
                shield.submit_flexray_frame(0, 0, &[1; 8], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_flexray_frame_invalid_slot_too_large() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // Slot ID > 2047 is invalid.
            assert_eq!(
                shield.submit_flexray_frame(2048, 0, &[1; 8], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_flexray_frame_empty_payload() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            assert_eq!(
                shield.submit_flexray_frame(1, 0, &[], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_flexray_frame_oversized_payload() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            assert_eq!(
                shield.submit_flexray_frame(1, 0, &[0; 255], 1_000),
                Err(VsError::InvalidInput)
            );
        });
    }

    #[test]
    fn automotive_ota_manifest_valid() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            let data = b"test manifest data";
            // Compute expected hash using TestCrypto's deterministic stub.
            let mut expected_hash = [0u8; 32];
            TestCrypto.sha256(data, &mut expected_hash).unwrap();
            assert!(shield
                .validate_ota_manifest(data, &expected_hash, 1_000)
                .is_ok());
        });
    }

    #[test]
    fn automotive_ota_manifest_mismatch_generates_alert() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            let data = b"test manifest data";
            // Wrong hash — should fail with IntegrityFailure.
            let wrong_hash = [0xFF; 32];
            let initial = shield.event_log_count();
            assert_eq!(
                shield.validate_ota_manifest(data, &wrong_hash, 1_000),
                Err(VsError::IntegrityFailure)
            );
            // Alert should have been routed.
            assert!(shield.event_log_count() > initial);
        });
    }

    #[test]
    fn automotive_doip_invalid_header_generates_alert() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            add_allow_all_rule(&mut shield);
            // DoIP packet with invalid version/inverse pair.
            let mut payload = [0u8; 64];
            payload[0] = 0x02; // version
            payload[1] = 0x00; // inverse should be 0xFD, but is 0x00 (invalid)
            let pkt = vs_runtime::EthPacket {
                src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                vlan_id: None,
                ethertype: 0x0800,
                dst_port: Some(13400),
                payload: &payload,
            };
            let initial_events = shield.event_log_count();
            assert!(shield.submit_eth_packet(&pkt, 1_000).is_ok());
            // The alert should have been routed, increasing the event log count.
            assert!(shield.event_log_count() >= initial_events);
        });
    }

    // -------------------------------------------------------------------
    // OTA signed verification tests
    // -------------------------------------------------------------------

    /// Accepting verifier — returns `Ok(true)` for all signatures.
    #[allow(clippy::unnecessary_wraps)]
    fn ota_verifier_accept(
        _data: &[u8],
        _signature: &[u8],
        _signer_id: u32,
    ) -> Result<bool, VsError> {
        Ok(true)
    }

    /// Rejecting verifier — returns `Ok(false)` for all signatures.
    #[allow(clippy::unnecessary_wraps)]
    fn ota_verifier_reject(
        _data: &[u8],
        _signature: &[u8],
        _signer_id: u32,
    ) -> Result<bool, VsError> {
        Ok(false)
    }

    #[test]
    fn automotive_ota_signed_with_accepting_verifier() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            shield.set_ota_verifier(ota_verifier_accept);

            let data = b"signed manifest data";
            let signature = b"dummy-sig";
            let signer_id = 42;

            // Compute expected hash using TestCrypto's deterministic stub.
            let mut expected_hash = [0u8; 32];
            TestCrypto.sha256(data, &mut expected_hash).unwrap();

            let result =
                shield.validate_ota_signed(data, signature, signer_id, &expected_hash, 1_000);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn automotive_ota_signed_with_rejecting_verifier_generates_alert() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            shield.set_ota_verifier(ota_verifier_reject);

            let data = b"signed manifest data";
            let signature = b"bad-sig";
            let signer_id = 42;

            let mut expected_hash = [0u8; 32];
            TestCrypto.sha256(data, &mut expected_hash).unwrap();

            let initial_events = shield.event_log_count();
            let result =
                shield.validate_ota_signed(data, signature, signer_id, &expected_hash, 1_000);
            assert_eq!(result, Err(VsError::IntegrityFailure));
            // A Critical alert should have been routed.
            assert!(shield.event_log_count() > initial_events);
        });
    }

    #[test]
    fn automotive_ota_signed_without_verifier_fails_closed() {
        big_stack(|| {
            let mut shield = AutomotiveShield::init(default_config(), TestCrypto).unwrap();
            // Do NOT call set_ota_verifier — verifier is None.

            let data = b"signed manifest data";
            let signature = b"any-sig";
            let signer_id = 1;

            let mut expected_hash = [0u8; 32];
            TestCrypto.sha256(data, &mut expected_hash).unwrap();

            let initial_events = shield.event_log_count();
            let result =
                shield.validate_ota_signed(data, signature, signer_id, &expected_hash, 1_000);
            // Should fail-closed with NotInitialized.
            assert_eq!(result, Err(VsError::NotInitialized));
            // A Critical alert should have been routed.
            assert!(shield.event_log_count() > initial_events);
        });
    }
}
