// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `vs-runtime` -- `Craton Shield` platform orchestrator.
//!
//! This crate ties together all core subsystems (crypto, key management, IDS,
//! firewall, anomaly detection, policy engine, etc.) into a single
//! [`CratonShield`] struct that manages the full initialization sequence,
//! periodic tick, watchdog, and frame/packet ingestion.
//!
//! Domain-specific subsystems (automotive, industrial, medical) are provided
//! by addon crates that wrap `CratonShield` with domain extensions.
//!
//! # Public API (v1.0 stable)
//!
//! Every `pub` item below is part of the v1.0 stable surface and governed
//! by `DEPRECATION.md`. The `CratonShield` orchestrator type, its
//! `init` / `tick` / `submit_*` methods, and the `PlatformConfig` builder
//! are the stable integration surface; addon crates and FFI consumers
//! depend on these signatures.

use vs_anomaly::EwmaDetector;
use vs_crypto::{
    CryptoProvider, KeyId, PostQuantumProvider, StubPostQuantumProvider, MLDSA65_PUBLIC_KEY_LEN,
    MLDSA65_SIGNATURE_LEN, MLKEM768_CIPHERTEXT_LEN, MLKEM_SHARED_SECRET_LEN,
};
use vs_event_logger::{EventLog, EventType};
use vs_ids_engine::{IdsEngine, IdsResponse};
use vs_integrity::{IntegrityMonitor, IntegrityResult, IntegrityStatus};
use vs_key_manager::KeyManager;
use vs_netfw::{Firewall, FirewallRule, Verdict};
use vs_ota_validator::{OtaValidator, TufRoot};
use vs_policy_engine::{
    Action, ActionType, AuthenticationLevel, Effect, Environment, PolicyEngine, Resource, Subject,
};
use vs_secure_boot::{BootAttestation, BootEntry, BootFailurePolicy, BootVerifier};
use vs_types::{AlertSeverity, PayloadHash, SecurityAlert, VsError};

// Re-export types needed by the FFI layer and domain addons.
pub use vs_can_monitor::CanFrame;
pub use vs_eth_monitor::EthPacket;
pub use vs_integrity::IntegrityResult as IntegrityCheckResult;
pub use vs_ota_validator::TufRoot as OtaTrustedRoot;
pub use vs_secure_boot::{BootAttestation as BootChainAttestation, BootEntry as BootChainEntry};

// Re-export subsystem crates for downstream consumers.
pub use vs_hal;
pub use vs_storage;

use vs_can_monitor::CanMonitor;
use vs_eth_monitor::{EthMonitor, EthMonitorConfig};

/// Event log ring buffer capacity.
#[cfg(feature = "capacity-xl")]
const EVENT_LOG_CAPACITY: usize = 1024;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const EVENT_LOG_CAPACITY: usize = 512;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const EVENT_LOG_CAPACITY: usize = 256;

/// Default EWMA smoothing factor.
const DEFAULT_EWMA_ALPHA: f32 = 0.1;

/// Default EWMA z-score anomaly threshold.
const DEFAULT_EWMA_Z_THRESHOLD: f32 = 3.0;

/// Default HMAC key id for event log.
const DEFAULT_HMAC_KEY_ID: KeyId = KeyId(0);

/// How often (in ticks) to check subsystem capacities.
const CAPACITY_CHECK_INTERVAL: u64 = 100;

/// Capacity utilisation fraction that triggers a warning (90%).
///
/// The runtime no longer divides at the check site — the equivalent
/// integer-only test is `used * 10 >= max * 9` (see
/// [`CratonShield::check_one_capacity`]).  This constant is retained for
/// documentation purposes and as a compile-time invariant guard.
#[allow(dead_code)]
const CAPACITY_WARNING_THRESHOLD: usize = 90;

// Compile-time check: the integer-multiplication shortcut used in
// `check_one_capacity` only matches `CAPACITY_WARNING_THRESHOLD` when
// that threshold is 90.  If the constant ever changes, the shortcut
// must be updated in lockstep.
const _: () = assert!(CAPACITY_WARNING_THRESHOLD == 90);

/// Consecutive event-log append failures before health fails.
const MAX_LOG_FAILURES_BEFORE_FAILED: u64 = 5;

// ---------------------------------------------------------------------------
// SubsystemStatus
// ---------------------------------------------------------------------------

/// Per-subsystem health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SubsystemStatus {
    /// Subsystem initialised and operating nominally.
    Ready,
    /// Subsystem operational but reporting non-fatal degradation.
    Degraded,
    /// Subsystem encountered a fatal error and is no longer usable.
    Failed,
    /// Subsystem has not been initialised (or has been torn down).
    NotInitialized,
}

// ---------------------------------------------------------------------------
// RouteOutcome
// ---------------------------------------------------------------------------

/// Audit-trail outcome of a [`CratonShield::route_alert`] call.
///
/// `route_alert` can quietly *lose* the alert if the underlying event log
/// has failed repeatedly: after `MAX_LOG_FAILURES_BEFORE_FAILED` (5)
/// consecutive append failures the platform sets `initialized = false` to
/// prevent further operation without a functioning audit trail.  Callers
/// that care about audit-trail integrity should read this outcome via
/// [`CratonShield::last_route_outcome`].
///
/// As of audit F-RM-12 `route_alert` itself returns a [`RouteResult`]
/// (per-call sink backpressure); `RouteOutcome` remains the canonical
/// audit-trail-integrity signal and is recorded internally on every
/// `route_alert` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum RouteOutcome {
    /// Alert was appended to the event log successfully.
    Logged,
    /// Alert was appended but a prior failure has left the event logger
    /// in `Degraded` / `Failed` state — caller may want to flush an
    /// out-of-band warning.
    LoggedButPlatformDegraded,
    /// Alert append failed and the platform has been disabled (audit
    /// trail can no longer be trusted).
    Dropped,
}

// ---------------------------------------------------------------------------
// RouteResult
// ---------------------------------------------------------------------------

/// Backpressure-oriented outcome of a [`CratonShield::route_alert`] call.
///
/// Where [`RouteOutcome`] reports audit-trail health (did the append succeed
/// and is the platform still trusted?), `RouteResult` reports *downstream
/// sink* state so addon crates can surface per-call backpressure to operators
/// (audit finding F-RM-12).  The two enums are orthogonal — an alert can be
/// `Routed` (sink accepted it) while the platform is still
/// `LoggedButPlatformDegraded`, and conversely a `Dropped` here signals an
/// overwritten older alert in the event-log ring buffer even when the
/// underlying append returned `Ok` (the new entry made it in by displacing
/// an older one).
///
/// # Today
///
/// The current event-log implementation never refuses an append outright
/// (the ring buffer wraps), so `Throttled` is reserved for future rate-limit
/// integration and is not emitted by the stock orchestrator.  `Dropped` is
/// emitted whenever the per-append `event_logger.overflow_count()` advances —
/// i.e. an older alert was overwritten to make room.  `Routed` covers the
/// nominal path.
///
/// Marked `#[non_exhaustive]` so future variants (e.g. `Deferred`,
/// `BackpressureWarning`) can be added without a major version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub enum RouteResult {
    /// Alert was accepted by the downstream sink without displacing an
    /// older entry and without hitting any rate limit.
    Routed,
    /// Alert was accepted but an older queued alert was overwritten to make
    /// room (event-log ring buffer wrapped on this append).  Operators
    /// should treat this as an audit-completeness signal: the *current*
    /// alert is logged, but at least one historical alert has fallen off
    /// the end of the in-memory ring.
    Dropped,
    /// Alert was rejected by a downstream rate limiter and not routed.
    /// Reserved for future use — the stock orchestrator does not emit this
    /// variant today.
    Throttled,
}

// ---------------------------------------------------------------------------
// PlatformHealth
// ---------------------------------------------------------------------------

/// Health of all core subsystems.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PlatformHealth {
    /// Status of the cryptographic provider.
    pub crypto: SubsystemStatus,
    /// Status of the key manager.
    pub key_manager: SubsystemStatus,
    /// Status of the secure boot verifier.
    pub secure_boot: SubsystemStatus,
    /// Status of the tamper-evident event logger.
    pub event_logger: SubsystemStatus,
    /// Status of the CAN bus monitor.
    pub can_monitor: SubsystemStatus,
    /// Status of the Ethernet monitor.
    pub eth_monitor: SubsystemStatus,
    /// Status of the IDS engine.
    pub ids_engine: SubsystemStatus,
    /// Status of the firewall.
    pub firewall: SubsystemStatus,
    /// Status of the OTA validator.
    pub ota_validator: SubsystemStatus,
    /// Status of the anomaly detectors.
    pub anomaly: SubsystemStatus,
    /// Status of the integrity monitor.
    pub integrity: SubsystemStatus,
    /// Status of the policy engine.
    pub policy_engine: SubsystemStatus,
    /// Status of optional secure storage (set by domain addons).
    pub storage: SubsystemStatus,
    /// Status of the HAL layer (set by domain addons).
    pub hal: SubsystemStatus,
    /// Number of times the event-log ring buffer has overflowed.
    pub event_logger_overflow_count: u64,
}

impl PlatformHealth {
    /// Create a health snapshot with every subsystem marked
    /// [`NotInitialized`](SubsystemStatus::NotInitialized).
    pub const fn all_not_initialized() -> Self {
        Self {
            crypto: SubsystemStatus::NotInitialized,
            key_manager: SubsystemStatus::NotInitialized,
            secure_boot: SubsystemStatus::NotInitialized,
            event_logger: SubsystemStatus::NotInitialized,
            can_monitor: SubsystemStatus::NotInitialized,
            eth_monitor: SubsystemStatus::NotInitialized,
            ids_engine: SubsystemStatus::NotInitialized,
            firewall: SubsystemStatus::NotInitialized,
            ota_validator: SubsystemStatus::NotInitialized,
            anomaly: SubsystemStatus::NotInitialized,
            integrity: SubsystemStatus::NotInitialized,
            policy_engine: SubsystemStatus::NotInitialized,
            storage: SubsystemStatus::NotInitialized,
            hal: SubsystemStatus::NotInitialized,
            event_logger_overflow_count: 0,
        }
    }

    /// Create a health snapshot with every subsystem marked
    /// [`Ready`](SubsystemStatus::Ready).
    pub const fn all_ready() -> Self {
        Self {
            crypto: SubsystemStatus::Ready,
            key_manager: SubsystemStatus::Ready,
            secure_boot: SubsystemStatus::Ready,
            event_logger: SubsystemStatus::Ready,
            can_monitor: SubsystemStatus::Ready,
            eth_monitor: SubsystemStatus::Ready,
            ids_engine: SubsystemStatus::Ready,
            firewall: SubsystemStatus::Ready,
            ota_validator: SubsystemStatus::Ready,
            anomaly: SubsystemStatus::Ready,
            integrity: SubsystemStatus::Ready,
            policy_engine: SubsystemStatus::Ready,
            storage: SubsystemStatus::Ready,
            hal: SubsystemStatus::Ready,
            event_logger_overflow_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

/// Watchdog safe-state action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Log the watchdog expiry but take no further action.
    LogOnly,
    /// Request a system reset (executed by the caller / HAL layer).
    Reset,
    /// Request a controlled halt (executed by the caller / HAL layer).
    Halt,
}

// ---------------------------------------------------------------------------
// Platform configuration
// ---------------------------------------------------------------------------

/// Platform configuration supplied at initialisation time.
#[derive(Debug, Clone, Copy)]
pub struct PlatformConfig {
    /// Watchdog timeout in microseconds.  If `tick()` is not called within
    /// this interval, [`check_watchdog`](CratonShield::check_watchdog)
    /// triggers.
    pub watchdog_timeout_us: u64,
    /// Action to take when the watchdog fires.
    pub watchdog_action: WatchdogAction,
    /// IDS alert correlation window in microseconds.
    pub ids_correlation_window_us: u64,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            watchdog_timeout_us: 1_000_000,
            watchdog_action: WatchdogAction::Reset,
            ids_correlation_window_us: 5_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal macro for event-log appends with error tracking
// ---------------------------------------------------------------------------

/// Append to the event log and track consecutive failures.  Escalates
/// `event_logger` health to `Failed` after `MAX_LOG_FAILURES_BEFORE_FAILED`
/// consecutive failures and disables the platform to prevent further
/// operations without a functioning audit trail.  Resets the failure
/// counter on success.
macro_rules! try_log {
    ($self:ident, $event_type:expr, $payload:expr, $ts:expr) => {{
        match $self
            .event_logger
            .append($event_type, $payload, $ts, &$self.crypto)
        {
            Ok(_) => {
                $self.event_log_failures = 0;
                $self.last_log_failed = false;
            }
            Err(_) => {
                $self.event_log_failures = $self.event_log_failures.saturating_add(1);
                $self.last_log_failed = true;
                if $self.event_log_failures >= MAX_LOG_FAILURES_BEFORE_FAILED {
                    $self.health.event_logger = SubsystemStatus::Failed;
                    // Prevent further operations with a broken audit trail.
                    $self.initialized = false;
                }
            }
        }
        $self.health.event_logger_overflow_count = $self.event_logger.overflow_count();
    }};
}

/// Append a *safety-critical* event to the event log without ever
/// disabling the platform.
///
/// Identical to [`try_log!`] in tracking consecutive failures and
/// escalating `event_logger` health to `Degraded`/`Failed`, but it
/// deliberately **never** flips `initialized = false`.  This is used
/// for the watchdog signal: a watchdog expiry is the single most
/// safety-critical event, and it is the most likely to coincide with a
/// degraded logger.  Routing it through the ordinary `try_log!` would
/// let a failing audit trail silently turn the platform off on exactly
/// the signal a safe-state action depends on.  The watchdog action is
/// surfaced regardless of audit-log health.
macro_rules! try_log_safety_critical {
    ($self:ident, $event_type:expr, $payload:expr, $ts:expr) => {{
        match $self
            .event_logger
            .append($event_type, $payload, $ts, &$self.crypto)
        {
            Ok(_) => {
                $self.event_log_failures = 0;
                $self.last_log_failed = false;
            }
            Err(_) => {
                $self.event_log_failures = $self.event_log_failures.saturating_add(1);
                $self.last_log_failed = true;
                if $self.event_log_failures >= MAX_LOG_FAILURES_BEFORE_FAILED {
                    // Escalate health for visibility, but do NOT disable
                    // the platform: the safe-state action must still be
                    // delivered to the caller.
                    $self.health.event_logger = SubsystemStatus::Failed;
                }
            }
        }
        $self.health.event_logger_overflow_count = $self.event_logger.overflow_count();
    }};
}

// ---------------------------------------------------------------------------
// Craton Shield orchestrator
// ---------------------------------------------------------------------------

/// Top-level `Craton Shield` platform orchestrator.
///
/// Owns all core subsystems and manages the full initialization sequence,
/// periodic tick, watchdog, alert pipeline, and frame/packet ingestion.
///
/// # Type parameters
///
/// * `C`  — classical [`CryptoProvider`] (required, e.g. `RustCryptoProvider`).
/// * `PQ` — post-quantum [`PostQuantumProvider`].  Defaults to
///   [`StubPostQuantumProvider`] which returns `NotInitialized` for all PQ
///   operations (PQC disabled).  Pass a post-quantum provider via
///   [`init_with_pq`](Self::init_with_pq) to enable FIPS 203 / 204.
///
/// Domain-specific addons (automotive, industrial, medical) should wrap
/// this struct to add domain-specific subsystems.
#[allow(clippy::struct_excessive_bools)]
pub struct CratonShield<
    C: CryptoProvider,
    PQ: vs_crypto::PostQuantumProvider = vs_crypto::StubPostQuantumProvider,
> {
    /// Owned crypto provider (used by event logger, etc.).
    crypto: C,

    /// Central IDS engine (owns CAN and ETH monitors internally).
    ids_engine: IdsEngine,

    /// Network firewall.
    firewall: Firewall,

    /// Policy engine.
    policy_engine: PolicyEngine,

    /// Tamper-evident event log (HMAC-chained ring buffer).
    event_logger: EventLog<C, EVENT_LOG_CAPACITY>,

    /// Key lifecycle manager.
    key_manager: KeyManager<C>,

    /// EWMA-based anomaly detector for CAN inter-arrival times.
    anomaly_detector: EwmaDetector,

    /// EWMA-based anomaly detector for ETH inter-arrival times.
    eth_anomaly_detector: EwmaDetector,

    /// TUF/Uptane OTA update validator.
    ///
    /// `None` until [`configure_ota`](Self::configure_ota) is called with a
    /// valid [`TufRoot`] that has real keys and non-zero thresholds.
    ota_validator: Option<OtaValidator<C>>,

    /// Secure boot chain verifier.
    boot_verifier: BootVerifier<C>,

    /// Memory region integrity monitor.
    integrity_monitor: IntegrityMonitor<C>,

    /// Aggregate health of all subsystems.
    health: PlatformHealth,

    /// Monotonic tick counter.
    tick_counter: u64,

    /// Timestamp of the most recent `tick()` call.
    last_tick_us: u64,

    /// Monotonic alert sequence counter.
    alert_sequence: u64,

    /// Watchdog configuration.
    watchdog_timeout_us: u64,
    watchdog_action: WatchdogAction,

    /// Whether `init()` completed successfully.
    initialized: bool,

    /// `true` once at least one firewall rule has been successfully
    /// installed via [`install_firewall_rule`](Self::install_firewall_rule)
    /// or [`install_dynamic_firewall_rule`](Self::install_dynamic_firewall_rule).
    ///
    /// Sticky: once set, never cleared.  Drives the fail-closed gate in
    /// [`submit_eth_packet`](Self::submit_eth_packet) so that transient
    /// emptiness of the rule table (e.g. after every dynamic rule
    /// expires) does **not** silently start blocking all Ethernet
    /// traffic.  An operator that has configured firewall policy will
    /// continue to use that policy's evaluate path (which has its own
    /// default-deny semantics on no-match) rather than tripping the
    /// "no rules loaded" sentinel.
    firewall_configured: bool,

    /// Consecutive event-log append failures.
    event_log_failures: u64,

    /// Whether secure boot has been verified via [`verify_boot_chain`](Self::verify_boot_chain).
    boot_verified: bool,

    /// Timestamp of the last CAN frame (for anomaly inter-arrival tracking).
    last_can_ts: u64,

    /// Number of CAN frames submitted (to skip first anomaly check).
    can_frame_count: u64,

    /// Timestamp of the last ETH packet (for anomaly inter-arrival tracking).
    last_eth_ts: u64,

    /// Number of ETH packets submitted (to skip first anomaly check).
    eth_frame_count: u64,

    /// Optional callback invoked when the IDS engine triggers a Block
    /// response.  Arguments are `(bus_id, duration_us)`.
    block_callback: Option<fn(u32, u64)>,

    /// Optional callback invoked when the IDS engine triggers an Isolate
    /// response.
    isolate_callback: Option<fn()>,

    /// `true` if the most recent event-log append failed.
    last_log_failed: bool,

    /// Outcome of the most recent [`route_alert`](Self::route_alert) call.
    /// Exposed via [`last_route_outcome`](Self::last_route_outcome) so that
    /// callers which discard the direct return value can still detect
    /// `Dropped` / `LoggedButPlatformDegraded`.  Initialised to
    /// [`RouteOutcome::Logged`] (no alerts routed yet ≡ no failures).
    last_route_outcome: RouteOutcome,

    /// Post-quantum cryptography provider (FIPS 203 / 204).
    ///
    /// Defaults to [`StubPostQuantumProvider`] which returns
    /// [`VsError::NotInitialized`] for all operations (PQC disabled).
    /// Replaced by a real [`PostQuantumProvider`] when constructed via
    /// [`init_with_pq`](Self::init_with_pq).
    pq_provider: PQ,
}

// ---------------------------------------------------------------------------
// Internal platform initialisation — shared by `init` and `init_with_pq`.
//
// Accepts the post-quantum provider as an explicit parameter so neither
// variant needs a `PQ: Default` bound, eliminating the type-inference
// ambiguity that arises when multiple `Default + PostQuantumProvider`
// implementations are in scope (StubPostQuantumProvider, SoftwarePostQuantumProvider,
// RustCryptoPqProvider).
// ---------------------------------------------------------------------------
#[allow(deprecated)]
fn platform_init_impl<C: CryptoProvider + Clone, PQ: PostQuantumProvider>(
    config: PlatformConfig,
    crypto: C,
    pq: PQ,
) -> Result<CratonShield<C, PQ>, VsError> {
    let mut health = PlatformHealth::all_not_initialized();

    // Step 1 -- Crypto provider self-test canary
    crypto.self_test()?;
    health.crypto = SubsystemStatus::Ready;

    // Step 2 -- Key manager (backed by the crypto provider)
    let key_manager: KeyManager<C> = KeyManager::new(crypto.clone());
    health.key_manager = SubsystemStatus::Ready;

    // Step 3 -- Secure boot verifier (stays NotInitialized until
    // verify_boot_chain is called with a valid boot chain)
    let boot_verifier = BootVerifier::new(crypto.clone(), BootFailurePolicy::ReportOnly);
    // health.secure_boot stays NotInitialized

    // Step 4 -- Event logger
    let event_logger: EventLog<C, EVENT_LOG_CAPACITY> =
        EventLog::new(DEFAULT_HMAC_KEY_ID, &crypto)?;
    health.event_logger = SubsystemStatus::Ready;

    // Step 5 -- CAN monitor (use crypto RNG for SipHash replay key)
    //
    // RNG health check: verify the entropy source is properly seeded
    // before consuming random bytes for security-critical purposes.
    // A broken or unseeded RNG may return all-zeros or uniform bytes,
    // which would undermine replay detection and flow hashing.
    {
        let mut probe = [0u8; 32];
        crypto.random_bytes(&mut probe)?;
        // Reject all-zero output (unseeded or stuck RNG).
        if probe.iter().all(|&b| b == 0) {
            return Err(VsError::NotInitialized);
        }
        // Reject uniform-byte output (degenerate source).
        if probe.iter().all(|&b| b == probe[0]) {
            return Err(VsError::NotInitialized);
        }
    }
    let mut replay_key = [0u8; 16];
    crypto.random_bytes(&mut replay_key)?;
    let can_monitor = CanMonitor::new(replay_key);
    health.can_monitor = SubsystemStatus::Ready;

    // Step 6 -- Ethernet monitor
    //
    // Generate random SipHash keys from the TRNG, matching the approach
    // used for the CAN monitor replay key above. Using hardcoded defaults
    // would allow an attacker who knows the keys to craft hash collisions.
    let mut eth_siphash_keys = [(0u64, 0u64); 4];
    for key_pair in &mut eth_siphash_keys {
        let mut k0_bytes = [0u8; 8];
        let mut k1_bytes = [0u8; 8];
        crypto.random_bytes(&mut k0_bytes)?;
        crypto.random_bytes(&mut k1_bytes)?;
        key_pair.0 = u64::from_le_bytes(k0_bytes);
        key_pair.1 = u64::from_le_bytes(k1_bytes);
    }
    let eth_monitor = EthMonitor::new(&EthMonitorConfig::default(), eth_siphash_keys)?;
    health.eth_monitor = SubsystemStatus::Ready;

    // Step 7 -- IDS engine
    let ids_engine = IdsEngine::new(can_monitor, eth_monitor, config.ids_correlation_window_us);
    health.ids_engine = SubsystemStatus::Ready;

    // Step 8 -- Firewall
    let firewall = Firewall::new();
    health.firewall = SubsystemStatus::Ready;

    // Step 9 -- OTA validator: None until configure_ota() is called
    // with a TufRoot that has real keys and non-zero thresholds.
    // health.ota_validator stays NotInitialized

    // Step 10 -- Anomaly detectors, integrity monitor
    let anomaly_detector = EwmaDetector::new(DEFAULT_EWMA_ALPHA, DEFAULT_EWMA_Z_THRESHOLD)
        .ok_or(VsError::InvalidConfig)?;
    let eth_anomaly_detector = EwmaDetector::new(DEFAULT_EWMA_ALPHA, DEFAULT_EWMA_Z_THRESHOLD)
        .ok_or(VsError::InvalidConfig)?;
    health.anomaly = SubsystemStatus::Ready;

    let integrity_monitor = IntegrityMonitor::new(crypto.clone());
    health.integrity = SubsystemStatus::Ready;

    // Step 11 -- Policy engine
    let policy_engine = PolicyEngine::new();
    health.policy_engine = SubsystemStatus::Ready;

    // Storage and HAL are optional subsystems that require explicit
    // setup by domain addons.  They remain NotInitialized until the
    // addon layer configures them.

    Ok(CratonShield {
        crypto,
        ids_engine,
        firewall,
        policy_engine,
        event_logger,
        key_manager,
        anomaly_detector,
        eth_anomaly_detector,
        ota_validator: None,
        boot_verifier,
        integrity_monitor,
        health,
        tick_counter: 0,
        last_tick_us: 0,
        alert_sequence: 0,
        watchdog_timeout_us: config.watchdog_timeout_us,
        watchdog_action: config.watchdog_action,
        initialized: true,
        firewall_configured: false,
        event_log_failures: 0,
        boot_verified: false,
        last_can_ts: 0,
        can_frame_count: 0,
        last_eth_ts: 0,
        eth_frame_count: 0,
        block_callback: None,
        isolate_callback: None,
        last_log_failed: false,
        last_route_outcome: RouteOutcome::Logged,
        pq_provider: pq,
    })
}

// ---------------------------------------------------------------------------
// `init` / `new` — default PQ = StubPostQuantumProvider
//
// Placing these constructors in a specific impl block (rather than the generic
// `impl<C, PQ>` block) avoids type-inference ambiguity: the compiler can
// immediately resolve the return type to `CratonShield<C, StubPostQuantumProvider>`
// without having to disambiguate between multiple `Default + PostQuantumProvider`
// implementations that may be in scope.
// ---------------------------------------------------------------------------
impl<C: CryptoProvider + Clone> CratonShield<C, StubPostQuantumProvider> {
    /// Perform the full platform initialization sequence using the default
    /// (stub / no-op) post-quantum provider.
    ///
    /// For platforms that require real ML-KEM / ML-DSA operations use
    /// [`init_with_pq`](CratonShield::init_with_pq) instead.
    ///
    /// # Initialization order
    ///
    ///  1. Crypto provider
    ///  2. Key manager
    ///  3. Secure boot verifier (health stays `NotInitialized` until
    ///     [`verify_boot_chain`](CratonShield::verify_boot_chain) succeeds)
    ///  4. Event logger
    ///  5. CAN monitor
    ///  6. Ethernet monitor
    ///  7. IDS engine (consumes CAN + ETH monitors)
    ///  8. Firewall
    ///  9. OTA validator (`None` — call [`configure_ota`](CratonShield::configure_ota)
    ///     with a real [`TufRoot`] before use)
    /// 10. Anomaly detector / integrity monitor
    /// 11. Policy engine
    pub fn init(config: PlatformConfig, crypto: C) -> Result<Self, VsError> {
        platform_init_impl(config, crypto, StubPostQuantumProvider)
    }

    /// Convenience constructor used by the FFI layer and test harnesses.
    ///
    /// Equivalent to `Self::init(config, C::default())`.
    pub fn new(config: &PlatformConfig) -> Result<Self, VsError>
    where
        C: Default,
    {
        Self::init(*config, C::default())
    }
}

// ---------------------------------------------------------------------------
// Generic impl — all methods available regardless of PQ choice.
// ---------------------------------------------------------------------------
impl<C: CryptoProvider + Clone, PQ: PostQuantumProvider> CratonShield<C, PQ> {
    /// Construct a `CratonShield` with an explicit post-quantum provider.
    ///
    /// Use this when you want to activate real ML-KEM / ML-DSA operations
    /// (e.g. supply a post-quantum provider with keys already
    /// provisioned via its `set_mlkem_key` / `set_mldsa_key` methods, or
    /// provision them after construction using [`Self::pq_provision_mlkem_key`] /
    /// [`Self::pq_provision_mldsa_key`]).
    ///
    /// For the common case where PQC is not required, prefer [`Self::init`]
    /// or [`Self::new`] which use the zero-cost [`StubPostQuantumProvider`].
    ///
    /// # Example
    /// ```ignore
    /// // pq Cargo feature must be enabled
    /// let pq = RustCryptoPqProvider::new(my_trng_fn);
    /// let mut shield = CratonShield::init_with_pq(config, crypto, pq)?;
    /// let seed = trng_read_64_bytes();
    /// shield.pq_provision_mlkem_key(KeyId(0), &seed)?;
    /// ```
    pub fn init_with_pq(config: PlatformConfig, crypto: C, pq: PQ) -> Result<Self, VsError> {
        platform_init_impl(config, crypto, pq)
    }

    // -----------------------------------------------------------------------
    // IDS callback setters
    // -----------------------------------------------------------------------

    /// Set a callback for IDS block actions.
    /// Called with (bus_id, duration_us) when an IDS block response is triggered.
    pub fn set_block_handler(&mut self, handler: fn(u32, u64)) {
        self.block_callback = Some(handler);
    }

    /// Set a callback for IDS isolate actions.
    /// Called when an IDS isolate response is triggered.
    pub fn set_isolate_handler(&mut self, handler: fn()) {
        self.isolate_callback = Some(handler);
    }

    /// Returns true if the last event log write failed.
    pub fn last_log_failed(&self) -> bool {
        self.last_log_failed
    }

    // -----------------------------------------------------------------------
    // Post-Quantum Cryptography (FIPS 203 / 204)
    //
    // All methods delegate to the `PQ` provider.  When the crate is built
    // without the `pq` feature the provider is `StubPostQuantumProvider`,
    // which returns `VsError::NotInitialized` for every call — so callers
    // that don't enable the feature get a clear error rather than silent
    // failure or a missing-symbol link error.
    // -----------------------------------------------------------------------

    /// Provision an ML-KEM-768 key slot from an explicit 64-byte seed
    /// (the d ∥ z byte string defined in FIPS 203).
    ///
    /// The seed must be generated from a TRNG and must be device-unique.
    /// The slot index is taken from `key_id.0`.
    ///
    /// With the default [`StubPostQuantumProvider`] this always returns
    /// [`VsError::NotInitialized`].  Use a post-quantum provider
    /// (enabled via the `pq` feature) to provision real keys.
    pub fn pq_provision_mlkem_key(
        &mut self,
        key_id: KeyId,
        seed: &[u8; 64],
    ) -> Result<(), VsError> {
        self.pq_provider.provision_mlkem_key(key_id, seed)
    }

    /// Provision an ML-DSA-65 signing key slot from a 32-byte seed (ξ in
    /// FIPS 204).
    ///
    /// The seed must be generated from a TRNG and must be device-unique.
    pub fn pq_provision_mldsa_key(
        &mut self,
        key_id: KeyId,
        seed: &[u8; 32],
    ) -> Result<(), VsError> {
        self.pq_provider.provision_mldsa_key(key_id, seed)
    }

    /// ML-KEM-768 encapsulation (FIPS 203).
    ///
    /// Generates a fresh shared secret, writes the 1088-byte ciphertext to
    /// `ct_out` and the 32-byte shared secret to `ss_out`.
    ///
    /// The RNG embedded in the PQ provider supplies the randomness; no
    /// external seed is needed at call time.
    pub fn pq_mlkem_encapsulate(
        &self,
        key_id: KeyId,
        ct_out: &mut [u8; MLKEM768_CIPHERTEXT_LEN],
        ss_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        self.pq_provider.mlkem_encapsulate(key_id, ct_out, ss_out)
    }

    /// ML-KEM-768 decapsulation (FIPS 203).
    ///
    /// Recovers the shared secret from `ciphertext`, writing the 32-byte
    /// result to `ss_out`.
    pub fn pq_mlkem_decapsulate(
        &self,
        key_id: KeyId,
        ciphertext: &[u8; MLKEM768_CIPHERTEXT_LEN],
        ss_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        self.pq_provider
            .mlkem_decapsulate(key_id, ciphertext, ss_out)
    }

    /// ML-DSA-65 signing (FIPS 204).
    ///
    /// Signs `message` with the private key in `key_id`, writing the
    /// 3309-byte signature to `sig_out`.
    pub fn pq_mldsa_sign(
        &self,
        key_id: KeyId,
        message: &[u8],
        sig_out: &mut [u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<(), VsError> {
        self.pq_provider.mldsa_sign(key_id, message, sig_out)
    }

    /// ML-DSA-65 signature verification (FIPS 204).
    ///
    /// `pub_key` is the raw 1952-byte ML-DSA-65 public key.
    /// Returns `Ok(true)` if valid, `Ok(false)` if the signature is invalid.
    pub fn pq_mldsa_verify(
        &self,
        pub_key: &[u8; MLDSA65_PUBLIC_KEY_LEN],
        message: &[u8],
        sig: &[u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<bool, VsError> {
        self.pq_provider.mldsa_verify(pub_key, message, sig)
    }

    // -----------------------------------------------------------------------
    // Tick & Watchdog
    // -----------------------------------------------------------------------

    /// Periodic tick -- must be called at a regular cadence.
    ///
    /// `ts_us` must be monotonically non-decreasing.  If a timestamp earlier
    /// than the previous tick is supplied, the call returns
    /// [`VsError::InvalidInput`].
    pub fn tick(&mut self, ts_us: u64) -> Result<(), VsError> {
        if !self.initialized {
            return Err(VsError::NotInitialized);
        }

        // Enforce monotonicity -- a backwards timestamp could reset the
        // watchdog window or corrupt IDS correlation.
        if ts_us < self.last_tick_us {
            return Err(VsError::InvalidInput);
        }

        self.ids_engine.tick(ts_us);
        self.firewall.expire_rules(ts_us);
        self.last_tick_us = ts_us;
        self.key_manager.tick(ts_us);
        self.tick_counter = self.tick_counter.saturating_add(1);

        if CAPACITY_CHECK_INTERVAL > 0 && self.tick_counter % CAPACITY_CHECK_INTERVAL == 0 {
            self.check_capacities(ts_us);
        }

        Ok(())
    }

    /// Check if the watchdog has expired.
    ///
    /// When the watchdog fires, a `SystemEvent` is logged with the elapsed
    /// time and the configured action before returning the action to the
    /// caller.  Actual execution of the action (reset, halt) is the
    /// responsibility of the caller / HAL layer.
    ///
    /// # Audit-trail interaction
    ///
    /// The watchdog log append is **safety-critical** and is routed
    /// through a dedicated path (`try_log_safety_critical!`) that, unlike
    /// the ordinary `try_log!` / [`route_alert`](Self::route_alert)
    /// pipeline, **never disables the platform**.  A degraded or failed
    /// event log may escalate `event_logger` health to
    /// [`SubsystemStatus::Failed`], but it will *not* flip
    /// `initialized = false`: the watchdog expiry — the single most
    /// safety-critical signal — is always surfaced to the caller so the
    /// configured safe-state action (reset/halt) can be taken regardless
    /// of audit-log health.  The returned [`WatchdogAction`] is therefore
    /// authoritative even when the audit trail is broken.
    pub fn check_watchdog(&mut self, ts_us: u64) -> Option<WatchdogAction> {
        let elapsed = ts_us.saturating_sub(self.last_tick_us);
        if elapsed > self.watchdog_timeout_us {
            // Log the watchdog expiry so there is an audit trail, but use
            // the safety-critical path: a failing event log must never
            // suppress the watchdog action.
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&elapsed.to_le_bytes());
            payload[8] = watchdog_action_to_u8(self.watchdog_action);
            try_log_safety_critical!(self, EventType::SystemEvent, &payload[..9], ts_us);
            Some(self.watchdog_action)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Health & Lifecycle
    // -----------------------------------------------------------------------

    /// Return the current subsystem health snapshot.
    pub fn health_status(&self) -> PlatformHealth {
        self.health
    }

    /// Return a reference to the current health snapshot.
    pub fn health(&self) -> &PlatformHealth {
        &self.health
    }

    /// Returns `true` if `init()` completed and `shutdown()` has not been
    /// called.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Graceful shutdown -- zeroizes key material and marks every subsystem
    /// as `NotInitialized`.
    pub fn shutdown(&mut self) {
        // Zeroize all cryptographic key material before marking subsystems
        // as torn down, so keys do not persist in memory.
        self.key_manager.keym_finalize();
        self.health = PlatformHealth::all_not_initialized();
        self.initialized = false;
    }

    // -----------------------------------------------------------------------
    // Frame / Packet Ingestion
    // -----------------------------------------------------------------------

    /// Submit a CAN frame for policy check, IDS inspection, and anomaly
    /// detection.
    ///
    /// Returns [`VsError::NotInitialized`] if the platform has been shut down,
    /// [`VsError::PolicyViolation`] if the policy engine denies the frame, or
    /// [`VsError::StorageError`] if a security alert raised during this
    /// submit could not be committed to the tamper-evident audit log (a
    /// [`RouteOutcome::Dropped`]).  In the last case the frame may have been
    /// inspected, but the audit trail is incomplete and the caller must
    /// treat the submit as failed.
    pub fn submit_can_frame(&mut self, frame: &CanFrame, ts_us: u64) -> Result<(), VsError> {
        if !self.initialized {
            return Err(VsError::NotInitialized);
        }

        // --- Policy engine authorization ---
        if self.policy_engine.rule_count() > 0 {
            let subject = Subject {
                address: frame.id,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            };
            let resource = Resource {
                bus_type: Some(vs_types::SOURCE_CAN),
                bus_id: Some(frame.id),
                service_id: None,
                firmware_region: None,
            };
            let action = Action {
                action_type: ActionType::Transmit,
            };
            let env = Environment {
                timestamp_us: ts_us,
            };
            let decision = self
                .policy_engine
                .evaluate(&subject, &resource, &action, &env);
            match decision.effect {
                Effect::DenyAudit => {
                    let alert = SecurityAlert {
                        id: self.alert_sequence,
                        severity: AlertSeverity::Medium,
                        source_type: vs_types::SOURCE_CAN,
                        source_id: frame.id,
                        payload_hash: PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    };
                    // Fail-closed: a dropped audit alert means the
                    // tamper-evident log could not record this denial.
                    // Surface the audit-log failure rather than the
                    // (less severe) policy violation.
                    if self.route_alert(&alert, ts_us) == RouteOutcome::Dropped {
                        return Err(VsError::StorageError);
                    }
                    return Err(VsError::PolicyViolation);
                }
                Effect::Deny => return Err(VsError::PolicyViolation),
                Effect::Permit => {}
            }
        } else {
            // Always fail-closed: no policy rules loaded → deny (C1 fix).
            return Err(VsError::PolicyViolation);
        }

        // --- IDS inspection (always runs for detection) ---
        let alert = self.ids_engine.submit_can_frame(frame, ts_us);
        let mut alert_dropped = false;
        if let Some(ref a) = alert {
            // Fail-closed: if the security alert could not be recorded
            // in the tamper-evident log, the submit must not silently
            // return Ok -- track the drop and surface it below.
            if self.route_alert(a, ts_us) == RouteOutcome::Dropped {
                alert_dropped = true;
            }
            let result = self.ids_engine.dispatch_and_respond(a);
            self.execute_ids_response(result.response, ts_us);
        }

        // --- Anomaly detection (CAN inter-arrival time) ---
        if self.can_frame_count > 0 {
            // Keep the inter-arrival accumulator in u64.  The cast to
            // f32 happens only here at the EWMA-update boundary so that
            // we don't lose precision on deltas > 2^24 µs (~16.7 s).
            let delta_us: u64 = ts_us.saturating_sub(self.last_can_ts);
            let delta = delta_us as f32;
            if let Some(score) = self.anomaly_detector.update(delta) {
                if score.is_anomalous {
                    let anomaly_alert = SecurityAlert {
                        id: self.alert_sequence,
                        severity: AlertSeverity::Medium,
                        source_type: vs_types::SOURCE_CAN,
                        source_id: 0,
                        payload_hash: PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    };
                    if self.route_alert(&anomaly_alert, ts_us) == RouteOutcome::Dropped {
                        alert_dropped = true;
                    }
                }
            }
        }
        self.last_can_ts = ts_us;
        self.can_frame_count = self.can_frame_count.saturating_add(1);

        // A security alert raised during this submit could not be
        // committed to the tamper-evident audit log -- fail closed so
        // the caller does not mistake a lost alert for a clean submit.
        if alert_dropped {
            return Err(VsError::StorageError);
        }

        Ok(())
    }

    /// Submit an Ethernet packet for policy check, IDS inspection, firewall
    /// enforcement, and anomaly detection.
    ///
    /// Returns [`VsError::NotInitialized`] if the platform has been shut down,
    /// [`VsError::PolicyViolation`] if the policy engine or firewall denies
    /// the packet, or [`VsError::StorageError`] if a security alert raised
    /// during this submit could not be committed to the tamper-evident
    /// audit log (a [`RouteOutcome::Dropped`]) -- in which case the audit
    /// trail is incomplete and the caller must treat the submit as failed.
    pub fn submit_eth_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Result<(), VsError> {
        if !self.initialized {
            return Err(VsError::NotInitialized);
        }

        // --- Policy engine authorization ---
        if self.policy_engine.rule_count() > 0 {
            // Hash the full 6-byte MAC down to a u32 — see `mac_to_u32`
            // for why we no longer truncate to the low 4 bytes.
            let src_id = mac_to_u32(&pkt.src_mac);
            let subject = Subject {
                address: src_id,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            };
            let resource = Resource {
                bus_type: Some(vs_types::SOURCE_ETHERNET),
                bus_id: Some(pkt.ethertype as u32),
                service_id: None,
                firmware_region: None,
            };
            let action = Action {
                action_type: ActionType::Transmit,
            };
            let env = Environment {
                timestamp_us: ts_us,
            };
            let decision = self
                .policy_engine
                .evaluate(&subject, &resource, &action, &env);
            match decision.effect {
                Effect::DenyAudit => {
                    let alert = SecurityAlert {
                        id: self.alert_sequence,
                        severity: AlertSeverity::Medium,
                        source_type: vs_types::SOURCE_ETHERNET,
                        source_id: src_id,
                        payload_hash: PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    };
                    // Fail-closed: a dropped audit alert means the
                    // tamper-evident log could not record this denial.
                    if self.route_alert(&alert, ts_us) == RouteOutcome::Dropped {
                        return Err(VsError::StorageError);
                    }
                    return Err(VsError::PolicyViolation);
                }
                Effect::Deny => return Err(VsError::PolicyViolation),
                Effect::Permit => {}
            }
        } else {
            // Always fail-closed: no policy rules loaded → deny (C1 fix).
            return Err(VsError::PolicyViolation);
        }

        // --- IDS inspection (always runs for detection purposes) ---
        let alert = self.ids_engine.submit_eth_packet(pkt, ts_us);
        let mut alert_dropped = false;
        if let Some(ref a) = alert {
            // Fail-closed: a dropped security alert must not be masked
            // by an Ok return -- track the drop and surface it below.
            if self.route_alert(a, ts_us) == RouteOutcome::Dropped {
                alert_dropped = true;
            }
            let result = self.ids_engine.dispatch_and_respond(a);
            self.execute_ids_response(result.response, ts_us);
        }

        // --- Firewall enforcement ---
        // Always fail-closed: if the firewall has never been configured
        // with at least one rule, deny the packet (C1 fix).
        //
        // We deliberately gate on the sticky `firewall_configured` flag
        // rather than the live `rule_capacity().0` (active rule count).
        // The active count can transiently drop to zero -- e.g. after
        // every dynamic rule has expired -- without operator intent to
        // disable firewall policy.  Falling back to live count there
        // would silently start dropping all ETH traffic.  Once the
        // operator has installed any rule, the firewall's evaluate()
        // path (which has its own default-deny on no-match) is the
        // authoritative enforcement boundary.
        if !self.firewall_configured {
            return Err(VsError::PolicyViolation);
        }
        {
            let verdict = self.firewall.evaluate(pkt, ts_us);
            match verdict {
                Verdict::Drop | Verdict::RateLimitDrop(_) => {
                    // Log the drop as a security event.  Hash the full
                    // MAC (see `mac_to_u32`) instead of truncating to
                    // the low 4 bytes.
                    let drop_alert = SecurityAlert {
                        id: self.alert_sequence,
                        severity: AlertSeverity::Low,
                        source_type: vs_types::SOURCE_ETHERNET,
                        source_id: mac_to_u32(&pkt.src_mac),
                        payload_hash: PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    };
                    // Fail-closed: a dropped audit alert means the
                    // firewall drop could not be recorded.
                    if self.route_alert(&drop_alert, ts_us) == RouteOutcome::Dropped {
                        return Err(VsError::StorageError);
                    }
                    return Err(VsError::PolicyViolation);
                }
                Verdict::Log => {
                    // Allow but log the packet event.
                    let mut payload = [0u8; 14];
                    payload[..6].copy_from_slice(&pkt.src_mac);
                    payload[6..12].copy_from_slice(&pkt.dst_mac);
                    payload[12..14].copy_from_slice(&pkt.ethertype.to_le_bytes());
                    try_log!(self, EventType::SystemEvent, &payload[..14], ts_us);
                }
                Verdict::Allow | Verdict::RateLimitAllow(_) => {}
            }
        } // end firewall evaluation (rules were loaded)

        // --- Anomaly detection (ETH inter-arrival time) ---
        if self.eth_frame_count > 0 {
            // Keep the inter-arrival accumulator in u64.  The cast to
            // f32 happens only here at the EWMA-update boundary so that
            // we don't lose precision on deltas > 2^24 µs (~16.7 s).
            let delta_us: u64 = ts_us.saturating_sub(self.last_eth_ts);
            let delta = delta_us as f32;
            if let Some(score) = self.eth_anomaly_detector.update(delta) {
                if score.is_anomalous {
                    let anomaly_alert = SecurityAlert {
                        id: self.alert_sequence,
                        severity: AlertSeverity::Medium,
                        source_type: vs_types::SOURCE_ETHERNET,
                        source_id: 0,
                        payload_hash: PayloadHash::ZERO,
                        timestamp_us: ts_us,
                    };
                    if self.route_alert(&anomaly_alert, ts_us) == RouteOutcome::Dropped {
                        alert_dropped = true;
                    }
                }
            }
        }
        self.last_eth_ts = ts_us;
        self.eth_frame_count = self.eth_frame_count.saturating_add(1);

        // A security alert raised during this submit could not be
        // committed to the tamper-evident audit log -- fail closed.
        if alert_dropped {
            return Err(VsError::StorageError);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Alert Pipeline
    // -----------------------------------------------------------------------

    /// Route a security alert through the event logger.
    ///
    /// This method is public so domain addons can route their own alerts
    /// through the core pipeline.  Event-log append failures are tracked;
    /// after `MAX_LOG_FAILURES_BEFORE_FAILED` (5) consecutive failures the
    /// `event_logger` health escalates to [`SubsystemStatus::Failed`] and
    /// the platform is disabled (`initialized = false`) to prevent further
    /// operation without a functioning audit trail.
    ///
    /// # Returns
    ///
    /// A [`RouteResult`] describing downstream sink backpressure for the
    /// individual call (audit F-RM-12):
    /// - [`RouteResult::Routed`] -- alert accepted by the sink, no older
    ///   entry overwritten, no rate limit hit.
    /// - [`RouteResult::Dropped`] -- alert accepted but the event-log ring
    ///   buffer wrapped and an older alert was overwritten to make room.
    ///   The current alert is in the log; one (or more) historical alerts
    ///   have fallen off the end of the in-memory ring.  Operators should
    ///   treat this as an audit-completeness signal and ensure off-board
    ///   exfiltration is fast enough to keep up.
    /// - [`RouteResult::Throttled`] -- reserved for future rate-limit
    ///   integration; the stock orchestrator never emits this today.
    ///
    /// Audit-trail health (event-log append failures, platform-disable
    /// state) is reported separately via [`Self::last_route_outcome`] /
    /// the [`RouteOutcome`] enum so per-call backpressure and audit-trail
    /// integrity remain orthogonal signals.
    ///
    /// # Alert ID contract
    ///
    /// Alert ids assigned by `route_alert` are strictly monotonic and
    /// **start at 1**: the alert-sequence counter is incremented *before*
    /// the payload is serialised, and the first 8 bytes of the logged
    /// payload always carry the post-increment value.  Sequence 0 is
    /// reserved as a sentinel and never appears in the event log, so any
    /// caller-supplied `alert.id` field is ignored for routing purposes.
    pub fn route_alert(&mut self, alert: &SecurityAlert, ts_us: u64) -> RouteResult {
        // Pre-increment so that sequence 0 is never used as an alert id,
        // ensuring every alert gets a unique non-zero identifier.  The
        // caller-supplied `alert.id` is overwritten below with this
        // freshly-allocated sequence number to enforce the contract.
        self.alert_sequence = self.alert_sequence.saturating_add(1);
        let assigned_id = self.alert_sequence;

        // Serialise the alert payload directly into a fixed-layout
        // buffer using known field offsets — avoids the
        // zero-then-field-by-field copy pattern.  The buffer is sized
        // exactly to the wire format (54 bytes) rather than 128 bytes.
        //
        // Wire layout (little-endian for multi-byte integers):
        //   0..8    id          u64
        //   8       severity    u8
        //   9       source_type u8
        //  10..14   source_id   u32
        //  14..46   payload_hash [u8; 32]
        //  46..54   timestamp_us u64
        let payload = AlertPayload {
            id: assigned_id.to_le_bytes(),
            severity: severity_to_u8(alert.severity),
            source_type: alert.source_type,
            source_id: alert.source_id.to_le_bytes(),
            payload_hash: *alert.payload_hash.as_bytes(),
            timestamp_us: alert.timestamp_us.to_le_bytes(),
        };
        let bytes = payload.to_bytes();

        // Snapshot the event-log failure counter and ring-buffer
        // overflow counter before the append.  The two snapshots feed
        // two orthogonal post-conditions:
        //
        //  * `failures_before` vs `event_log_failures`  -> RouteOutcome
        //    (audit-trail integrity, surfaced via `last_route_outcome`).
        //  * `overflow_before`  vs `overflow_count()`   -> RouteResult
        //    (per-call sink backpressure, returned to the caller).
        let failures_before = self.event_log_failures;
        let overflow_before = self.event_logger.overflow_count();
        try_log!(self, EventType::SecurityAlert, &bytes, ts_us);

        let outcome = if self.event_log_failures == 0 {
            // Append succeeded and the failure counter was reset.
            if failures_before > 0 {
                // We recovered from a prior failure streak — surface the
                // recent degradation even though this individual append
                // landed cleanly.
                RouteOutcome::LoggedButPlatformDegraded
            } else {
                RouteOutcome::Logged
            }
        } else {
            // `event_log_failures > 0` ⇒ this append failed.  The alert
            // is lost regardless of whether the disable threshold was
            // reached this round; once the counter hits
            // `MAX_LOG_FAILURES_BEFORE_FAILED` the platform also flips
            // `initialized = false` via the `try_log!` macro.
            RouteOutcome::Dropped
        };

        self.last_route_outcome = outcome;

        // RouteResult: backpressure signal for the caller.  An audit-trail
        // failure (`event_log_failures > 0`) also surfaces as `Dropped`
        // here so addon crates that only inspect `RouteResult` still
        // observe lost alerts.  Otherwise: if the event-log ring buffer
        // wrapped on this append (overflow_count advanced), an older
        // alert was overwritten and we report `Dropped`.  Nominal path
        // is `Routed`.  `Throttled` is reserved for future rate-limit
        // integration and is not emitted by the stock orchestrator.
        let overflow_after = self.event_logger.overflow_count();
        if self.event_log_failures > 0 || overflow_after > overflow_before {
            RouteResult::Dropped
        } else {
            RouteResult::Routed
        }
    }

    /// Returns the outcome of the most recent [`route_alert`](Self::route_alert)
    /// call.  Initialised to [`RouteOutcome::Logged`] before any alerts
    /// have been routed.  Useful for callers that discard the direct
    /// return value but still need to detect dropped alerts or platform
    /// degradation out-of-band.
    pub fn last_route_outcome(&self) -> RouteOutcome {
        self.last_route_outcome
    }

    // -----------------------------------------------------------------------
    // IDS Response Execution
    // -----------------------------------------------------------------------

    /// Execute an IDS response action.
    ///
    /// - `Log` / `Alert`: already handled by `route_alert` -- no-op here.
    /// - `Block`: logs the block request.  Actual bus-level blocking
    ///   requires HAL integration provided by domain addons.
    /// - `Isolate`: logs the isolation request and degrades IDS health.
    /// - `Shutdown`: initiates a graceful shutdown of the entire platform.
    fn execute_ids_response(&mut self, response: IdsResponse, ts_us: u64) {
        match response {
            IdsResponse::Log | IdsResponse::Alert => {
                // Already handled by route_alert.
            }
            IdsResponse::Block {
                bus_id,
                duration_us,
            } => {
                let mut payload = [0u8; 16];
                payload[0] = b'B'; // Block marker
                payload[1] = bus_id;
                payload[2..6].copy_from_slice(&duration_us.to_le_bytes());
                try_log!(self, EventType::SecurityAlert, &payload[..6], ts_us);
                if let Some(cb) = self.block_callback {
                    cb(bus_id as u32, duration_us as u64);
                }
            }
            IdsResponse::Isolate => {
                // Log the isolation request.  Actual network segment
                // isolation requires HAL support provided by domain
                // addons.  The IDS engine itself is healthy (it detected
                // the threat correctly).
                let payload = b"ISOLATE";
                try_log!(self, EventType::SecurityAlert, payload.as_slice(), ts_us);
                if let Some(cb) = self.isolate_callback {
                    cb();
                }
            }
            IdsResponse::Shutdown => {
                // Log the shutdown request but do NOT execute it.
                // Shutdown requires out-of-band authenticated confirmation
                // from the caller to prevent attacker-triggered DoS via
                // crafted IDS responses.
                let payload = b"IDS_SHUTDOWN_DENIED";
                try_log!(self, EventType::SecurityAlert, payload.as_slice(), ts_us);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capacity Monitoring
    // -----------------------------------------------------------------------

    /// Check subsystem capacities and emit warning events when any structure
    /// exceeds 90% utilisation.
    ///
    /// Performance: rather than allocating a 6-tuple array on every
    /// 100th tick, each capacity is read and tested inline so the
    /// compiler can keep the operation entirely register-resident.
    fn check_capacities(&mut self, ts_us: u64) {
        let (used, max) = self.ids_engine.can_monitor().rule_capacity();
        self.check_one_capacity("can_rules", used, max, ts_us);

        let (used, max) = self.ids_engine.can_monitor().stats_capacity();
        self.check_one_capacity("can_stats", used, max, ts_us);

        // NOTE: EthMonitor does not currently expose a capacity method.

        let (used, max) = self.firewall.rule_capacity();
        self.check_one_capacity("fw_rules", used, max, ts_us);

        let (used, max) = self.policy_engine.rule_capacity();
        self.check_one_capacity("policy_rules", used, max, ts_us);

        let (used, max) = self.key_manager.key_capacity();
        self.check_one_capacity("key_slots", used, max, ts_us);

        let (used, max) = self.integrity_monitor.region_capacity();
        self.check_one_capacity("integrity_regions", used, max, ts_us);
    }

    /// Emit a capacity warning event when usage >= 90%.
    ///
    /// Threshold check uses `used * 10 >= max * 9` to avoid a `usize`
    /// division on the hot path (the equivalent of the old
    /// `(used * 100) / max >= 90` check).
    fn check_one_capacity(&mut self, label: &str, used: usize, max: usize, ts_us: u64) {
        if max == 0 {
            return;
        }
        // 90% threshold without division.  Equivalent to
        // `(used * 100) / max >= CAPACITY_WARNING_THRESHOLD` for the
        // current threshold of 90, but avoids a `usize` division on the
        // hot path: `used/max >= 9/10  ⇔  used*10 >= max*9`.
        if used.saturating_mul(10) < max.saturating_mul(9) {
            return;
        }
        let mut payload = [0u8; 64];
        let prefix = b"CAP:";
        let mut offset = 0usize;
        for &b in prefix {
            if offset < 64 {
                payload[offset] = b;
                offset += 1;
            }
        }
        for &b in label.as_bytes() {
            if offset < 64 {
                payload[offset] = b;
                offset += 1;
            }
        }
        if offset < 64 {
            payload[offset] = b':';
            offset += 1;
        }
        offset = write_usize_decimal(&mut payload, offset, used);
        if offset < 64 {
            payload[offset] = b'/';
            offset += 1;
        }
        offset = write_usize_decimal(&mut payload, offset, max);

        try_log!(self, EventType::SystemEvent, &payload[..offset], ts_us);
    }

    // -----------------------------------------------------------------------
    // Boot Verification
    // -----------------------------------------------------------------------

    /// Register a public key for boot chain verification.
    pub fn register_boot_key(&mut self, key_id: KeyId, pub_key: &[u8; 65]) -> Result<(), VsError> {
        self.boot_verifier.register_pub_key(key_id, pub_key)
    }

    /// Verify a secure boot chain.
    ///
    /// On success, marks `secure_boot` health as [`SubsystemStatus::Ready`]
    /// and returns the attestation.  On failure the health is set to
    /// [`SubsystemStatus::Failed`] and the error is propagated.
    pub fn verify_boot_chain(
        &mut self,
        entries: &[BootEntry],
        ts_us: u64,
    ) -> Result<BootAttestation, VsError> {
        match self.boot_verifier.verify_boot_chain(entries, ts_us) {
            Ok(attestation) => {
                self.boot_verified = true;
                self.health.secure_boot = SubsystemStatus::Ready;

                // Log boot verification success.
                let mut payload = [0u8; 64];
                payload[..32].copy_from_slice(&attestation.chain_hash);
                try_log!(self, EventType::BootEvent, &payload[..32], ts_us);

                Ok(attestation)
            }
            Err(e) => {
                self.health.secure_boot = SubsystemStatus::Failed;
                Err(e)
            }
        }
    }

    /// Returns `true` if [`verify_boot_chain`](Self::verify_boot_chain) has
    /// completed successfully.
    pub fn is_boot_verified(&self) -> bool {
        self.boot_verified
    }

    // -----------------------------------------------------------------------
    // OTA Configuration
    // -----------------------------------------------------------------------

    /// Configure the OTA validator with a trusted TUF root.
    ///
    /// The supplied root **must** have at least one key and a non-zero
    /// threshold for the `Root` role; otherwise the call returns
    /// [`VsError::InvalidConfig`].
    ///
    /// Until this method is called, `ota_validator()` returns `None` and
    /// `health.ota_validator` is `NotInitialized`.
    pub fn configure_ota(&mut self, root: TufRoot) -> Result<(), VsError> {
        // Validate that the root has at least one key and a non-zero
        // threshold for the Root role to prevent a configuration that
        // would accept unsigned metadata.
        if root.threshold == 0 {
            return Err(VsError::InvalidConfig);
        }
        let has_root_key = root.root_keys.iter().any(|k| k.is_some());
        if !has_root_key {
            return Err(VsError::InvalidConfig);
        }
        // Targets, snapshot, and timestamp thresholds must also be > 0
        // when their keys are present.
        if root.targets_threshold == 0
            || root.snapshot_threshold == 0
            || root.timestamp_threshold == 0
        {
            return Err(VsError::InvalidConfig);
        }

        self.ota_validator = Some(OtaValidator::new(self.crypto.clone(), root)?);
        self.health.ota_validator = SubsystemStatus::Ready;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Integrity Verification
    // -----------------------------------------------------------------------

    /// Verify all registered integrity regions.
    ///
    /// `data_provider` is called for each active region with
    /// `(region_id, base_addr, length)` and must return the current memory
    /// contents (or `None` if the region is inaccessible).
    ///
    /// Any tampered region triggers a `Critical` alert and degrades
    /// `integrity` health to `Degraded`.
    ///
    /// Returns [`VsError::StorageError`] if a tamper alert could not be
    /// committed to the tamper-evident audit log (a
    /// [`RouteOutcome::Dropped`]); a tamper detection with a lost audit
    /// record must not be reported as a clean verification pass.
    pub fn verify_integrity<'a, F>(
        &mut self,
        data_provider: F,
        results: &mut [IntegrityResult],
        ts_us: u64,
    ) -> Result<usize, VsError>
    where
        F: FnMut(u32, usize, usize) -> Option<&'a [u8]>,
    {
        let count = self.integrity_monitor.verify_all(data_provider, results)?;

        let mut alert_dropped = false;
        for r in results[..count].iter() {
            if r.status == IntegrityStatus::Tampered {
                self.health.integrity = SubsystemStatus::Degraded;
                let alert = SecurityAlert {
                    id: self.alert_sequence,
                    severity: AlertSeverity::Critical,
                    source_type: vs_types::SOURCE_UNKNOWN,
                    source_id: r.region_id,
                    payload_hash: PayloadHash::ZERO,
                    timestamp_us: ts_us,
                };
                if self.route_alert(&alert, ts_us) == RouteOutcome::Dropped {
                    alert_dropped = true;
                }
            }
        }

        // Fail-closed: a tamper detection whose Critical alert could not
        // be committed to the audit log must not be reported as a clean
        // verification pass.
        if alert_dropped {
            return Err(VsError::StorageError);
        }

        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Counters & Accessors
    // -----------------------------------------------------------------------

    /// Returns the monotonic tick counter.
    pub fn tick_count(&self) -> u64 {
        self.tick_counter
    }

    /// Returns the number of entries in the event log.
    pub fn event_log_count(&self) -> u64 {
        self.event_logger.entry_count()
    }

    /// Returns the alert sequence counter.
    pub fn alert_sequence(&self) -> u64 {
        self.alert_sequence
    }

    /// Returns the number of consecutive event-log append failures.
    pub fn event_log_failures(&self) -> u64 {
        self.event_log_failures
    }

    /// Returns a reference to the crypto provider.
    pub fn crypto(&self) -> &C {
        &self.crypto
    }

    /// Returns a reference to the policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Returns a mutable reference to the policy engine.
    pub fn policy_engine_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy_engine
    }

    /// Returns a reference to the firewall.
    pub fn firewall(&self) -> &Firewall {
        &self.firewall
    }

    /// Returns a mutable reference to the firewall.
    ///
    /// Note: prefer [`install_firewall_rule`](Self::install_firewall_rule)
    /// and [`install_dynamic_firewall_rule`](Self::install_dynamic_firewall_rule)
    /// over `firewall_mut().add_rule(..)` because the install helpers
    /// also flip the sticky `firewall_configured` flag that drives the
    /// fail-closed gate in [`submit_eth_packet`](Self::submit_eth_packet).
    /// Bypassing them by calling `add_rule` directly is supported for
    /// read-only inspection / non-rule mutations (e.g. setting a log
    /// callback) but means the runtime will continue to fail-closed on
    /// ETH traffic until an install helper has run.
    pub fn firewall_mut(&mut self) -> &mut Firewall {
        &mut self.firewall
    }

    /// Returns `true` once at least one firewall rule has been
    /// installed via [`install_firewall_rule`](Self::install_firewall_rule)
    /// or [`install_dynamic_firewall_rule`](Self::install_dynamic_firewall_rule).
    /// Sticky: never cleared once set, even after every dynamic rule
    /// expires.  See the `firewall_configured` field docs for rationale.
    #[must_use]
    pub fn firewall_configured(&self) -> bool {
        self.firewall_configured
    }

    /// Install a static firewall rule and mark the firewall as
    /// configured.  Prefer this over `firewall_mut().add_rule(..)`.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by [`Firewall::add_rule`].  The
    /// `firewall_configured` flag is only flipped when the underlying
    /// call succeeds.
    pub fn install_firewall_rule(&mut self, rule: FirewallRule) -> Result<(), VsError> {
        self.firewall.add_rule(rule)?;
        self.firewall_configured = true;
        Ok(())
    }

    /// Install a dynamic (auto-expiring) firewall rule and mark the
    /// firewall as configured.  Prefer this over
    /// `firewall_mut().insert_dynamic_rule(..)`.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by [`Firewall::insert_dynamic_rule`].
    /// The `firewall_configured` flag is only flipped when the
    /// underlying call succeeds.
    pub fn install_dynamic_firewall_rule(
        &mut self,
        rule: FirewallRule,
        expiry_us: u64,
    ) -> Result<(), VsError> {
        self.firewall.insert_dynamic_rule(rule, expiry_us)?;
        self.firewall_configured = true;
        Ok(())
    }

    /// Returns a reference to the event logger.
    pub fn event_logger(&self) -> &EventLog<C, EVENT_LOG_CAPACITY> {
        &self.event_logger
    }

    /// Returns a reference to the anomaly detector.
    pub fn anomaly_detector(&self) -> &EwmaDetector {
        &self.anomaly_detector
    }

    /// Returns a mutable reference to the anomaly detector.
    pub fn anomaly_detector_mut(&mut self) -> &mut EwmaDetector {
        &mut self.anomaly_detector
    }

    /// Returns a reference to the key manager.
    pub fn key_manager(&self) -> &KeyManager<C> {
        &self.key_manager
    }

    /// Returns a mutable reference to the key manager.
    pub fn key_manager_mut(&mut self) -> &mut KeyManager<C> {
        &mut self.key_manager
    }

    /// Returns a reference to the integrity monitor.
    pub fn integrity_monitor(&self) -> &IntegrityMonitor<C> {
        &self.integrity_monitor
    }

    /// Returns a mutable reference to the integrity monitor.
    pub fn integrity_monitor_mut(&mut self) -> &mut IntegrityMonitor<C> {
        &mut self.integrity_monitor
    }

    /// Returns a reference to the OTA validator, or `None` if
    /// [`configure_ota`](Self::configure_ota) has not been called.
    pub fn ota_validator(&self) -> Option<&OtaValidator<C>> {
        self.ota_validator.as_ref()
    }

    /// Returns a mutable reference to the OTA validator, or `None` if
    /// [`configure_ota`](Self::configure_ota) has not been called.
    pub fn ota_validator_mut(&mut self) -> Option<&mut OtaValidator<C>> {
        self.ota_validator.as_mut()
    }

    /// Returns a reference to the boot verifier.
    pub fn boot_verifier(&self) -> &BootVerifier<C> {
        &self.boot_verifier
    }

    /// Returns a reference to the IDS engine.
    pub fn ids_engine(&self) -> &IdsEngine {
        &self.ids_engine
    }

    /// Returns a mutable reference to the IDS engine.
    pub fn ids_engine_mut(&mut self) -> &mut IdsEngine {
        &mut self.ids_engine
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialised wire-format of a [`SecurityAlert`] event-log payload.
///
/// The `#[repr(C)]` layout is informational: serialisation goes through
/// [`AlertPayload::to_bytes`] (which assembles the bytes via the safe
/// copy-into-fixed-offsets pattern) rather than relying on the in-memory
/// representation.  This keeps the crate compatible with
/// `#![forbid(unsafe_code)]` while avoiding the prior zero-128-then-
/// field-by-field-copy pattern.
#[repr(C)]
struct AlertPayload {
    id: [u8; 8],
    severity: u8,
    source_type: u8,
    source_id: [u8; 4],
    payload_hash: [u8; 32],
    timestamp_us: [u8; 8],
}

impl AlertPayload {
    /// Wire-format length in bytes (8 + 1 + 1 + 4 + 32 + 8).
    const LEN: usize = 54;

    /// Serialise the payload into a contiguous byte array.
    ///
    /// Builds the output via a single array literal expression — every
    /// byte is written exactly once, so there is no zero-then-overwrite
    /// step.  The compiler can fold this into a small fixed-size
    /// memcpy-style emission.
    fn to_bytes(&self) -> [u8; Self::LEN] {
        let h = &self.payload_hash;
        [
            // id (8)
            self.id[0],
            self.id[1],
            self.id[2],
            self.id[3],
            self.id[4],
            self.id[5],
            self.id[6],
            self.id[7],
            // severity (1)
            self.severity,
            // source_type (1)
            self.source_type,
            // source_id (4)
            self.source_id[0],
            self.source_id[1],
            self.source_id[2],
            self.source_id[3],
            // payload_hash (32)
            h[0],
            h[1],
            h[2],
            h[3],
            h[4],
            h[5],
            h[6],
            h[7],
            h[8],
            h[9],
            h[10],
            h[11],
            h[12],
            h[13],
            h[14],
            h[15],
            h[16],
            h[17],
            h[18],
            h[19],
            h[20],
            h[21],
            h[22],
            h[23],
            h[24],
            h[25],
            h[26],
            h[27],
            h[28],
            h[29],
            h[30],
            h[31],
            // timestamp_us (8)
            self.timestamp_us[0],
            self.timestamp_us[1],
            self.timestamp_us[2],
            self.timestamp_us[3],
            self.timestamp_us[4],
            self.timestamp_us[5],
            self.timestamp_us[6],
            self.timestamp_us[7],
        ]
    }
}

fn severity_to_u8(s: AlertSeverity) -> u8 {
    match s {
        AlertSeverity::Info => 0,
        AlertSeverity::Low => 1,
        AlertSeverity::Medium => 2,
        AlertSeverity::High => 3,
        AlertSeverity::Critical => 4,
        // `AlertSeverity` is `#[non_exhaustive]`. Unknown future variants
        // map to the highest known severity for fail-loud reporting.
        _ => 4,
    }
}

/// Compress a 6-byte MAC address into a `u32` policy/alert identifier.
///
/// The legacy implementation took `u32::from_be_bytes(src_mac[2..6])`,
/// which silently discarded the upper two MAC bytes — two MACs sharing
/// their low-32-bits then collided at the policy / alert layer.  This
/// helper folds the *full* 6-byte MAC through SipHash-2-4 (the same hash
/// already used by the Ethernet monitor) so that every MAC byte
/// contributes to the result.  Keys are fixed constants chosen so that
/// the hash is deterministic across runs (this is an *identifier*
/// derivation, not a security MAC — the underlying alert pipeline still
/// authenticates entries via HMAC in the event logger).
fn mac_to_u32(mac: &[u8; 6]) -> u32 {
    // Deterministic SipHash-2-4 keys.  We expose the same identifier
    // domain to policy lookups and alert source_id derivation so they
    // stay consistent across both call sites.
    const MAC_HASH_K0: u64 = 0x0123_4567_89AB_CDEF;
    const MAC_HASH_K1: u64 = 0xFEDC_BA98_7654_3210;
    let h = vs_types::siphash_2_4(mac, MAC_HASH_K0, MAC_HASH_K1);
    // Fold the 64-bit digest down to u32 by XOR'ing the two halves so
    // every output bit depends on every input bit.
    ((h >> 32) as u32) ^ (h as u32)
}

fn watchdog_action_to_u8(a: WatchdogAction) -> u8 {
    match a {
        WatchdogAction::LogOnly => 0,
        WatchdogAction::Reset => 1,
        WatchdogAction::Halt => 2,
    }
}

/// Write a `usize` as decimal ASCII digits into `buf` starting at `offset`.
/// Returns the new offset after the last digit written.
fn write_usize_decimal(buf: &mut [u8], mut offset: usize, mut val: usize) -> usize {
    if val == 0 {
        if offset < buf.len() {
            buf[offset] = b'0';
            return offset + 1;
        }
        return offset;
    }
    let mut digits = [0u8; 20];
    let mut len = 0;
    while val > 0 && len < 20 {
        digits[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        if offset < buf.len() {
            buf[offset] = digits[i];
            offset += 1;
        }
    }
    offset
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use vs_crypto::KeyId;

    #[derive(Clone)]
    struct TestCrypto;

    /// Type alias for tests: default (Stub) PQ provider.
    type Shield = CratonShield<TestCrypto>;

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
            // Return a non-zero deterministic hash so that the self-test
            // canary passes. V9: different inputs must produce different
            // outputs to satisfy the enhanced KAT (determinism + collision check).
            *hash_out = [0x42; 32];
            for (i, &b) in data.iter().enumerate() {
                hash_out[i % 32] ^= b;
                hash_out[(i + 7) % 32] = hash_out[(i + 7) % 32].wrapping_add(b);
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
            Ok(true)
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (0x42 ^ i as u8).wrapping_add(i as u8);
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

    fn default_config() -> PlatformConfig {
        PlatformConfig {
            watchdog_timeout_us: 1_000_000,
            watchdog_action: WatchdogAction::Reset,
            ids_correlation_window_us: 100_000,
        }
    }

    fn make_can_frame(id: u32) -> CanFrame {
        CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc: 8,
            data: [0x01; 64],
        }
    }

    fn make_eth_packet(payload: &[u8]) -> EthPacket<'_> {
        EthPacket {
            src_mac: [0xAA; 6],
            dst_mac: [0xBB; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload,
        }
    }

    // -- Initialization & Lifecycle -----------------------------------------

    #[test]
    fn platform_init_completes_successfully() {
        let result: Result<Shield, _> = CratonShield::init(default_config(), TestCrypto);
        assert!(result.is_ok());
        let shield = result.unwrap();
        assert!(shield.is_initialized());
    }

    #[test]
    fn health_status_after_init() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let health = shield.health_status();
        // Subsystems that are immediately ready:
        assert_eq!(health.crypto, SubsystemStatus::Ready);
        assert_eq!(health.key_manager, SubsystemStatus::Ready);
        assert_eq!(health.event_logger, SubsystemStatus::Ready);
        assert_eq!(health.can_monitor, SubsystemStatus::Ready);
        assert_eq!(health.eth_monitor, SubsystemStatus::Ready);
        assert_eq!(health.ids_engine, SubsystemStatus::Ready);
        assert_eq!(health.firewall, SubsystemStatus::Ready);
        assert_eq!(health.anomaly, SubsystemStatus::Ready);
        assert_eq!(health.integrity, SubsystemStatus::Ready);
        assert_eq!(health.policy_engine, SubsystemStatus::Ready);
        // Subsystems that require explicit setup:
        assert_eq!(health.secure_boot, SubsystemStatus::NotInitialized);
        assert_eq!(health.ota_validator, SubsystemStatus::NotInitialized);
        assert_eq!(health.storage, SubsystemStatus::NotInitialized);
        assert_eq!(health.hal, SubsystemStatus::NotInitialized);
    }

    #[test]
    fn shutdown_marks_all_not_initialized() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.shutdown();
        assert!(!shield.is_initialized());
        let health = shield.health_status();
        assert_eq!(health.crypto, SubsystemStatus::NotInitialized);
        assert_eq!(health.firewall, SubsystemStatus::NotInitialized);
        assert_eq!(health.policy_engine, SubsystemStatus::NotInitialized);
    }

    #[test]
    fn tick_fails_after_shutdown() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.shutdown();
        assert_eq!(shield.tick(1_000), Err(VsError::NotInitialized));
    }

    #[test]
    fn submit_can_frame_fails_after_shutdown() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.shutdown();
        let frame = make_can_frame(0x100);
        assert_eq!(
            shield.submit_can_frame(&frame, 1_000),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn submit_eth_packet_fails_after_shutdown() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.shutdown();
        let payload = [0u8; 64];
        let pkt = make_eth_packet(&payload);
        assert_eq!(
            shield.submit_eth_packet(&pkt, 1_000),
            Err(VsError::NotInitialized)
        );
    }

    // -- Tick & Watchdog ----------------------------------------------------

    #[test]
    fn tick_increments_counter() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.tick_count(), 0);
        shield.tick(1_000).unwrap();
        assert_eq!(shield.tick_count(), 1);
        shield.tick(2_000).unwrap();
        assert_eq!(shield.tick_count(), 2);
    }

    #[test]
    fn tick_rejects_backwards_timestamp() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.tick(5_000).unwrap();
        assert_eq!(shield.tick(3_000), Err(VsError::InvalidInput));
        // Forward tick still works after rejection.
        assert!(shield.tick(6_000).is_ok());
    }

    #[test]
    fn watchdog_fires_after_timeout() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.tick(0).unwrap();
        let action = shield.check_watchdog(2_000_000);
        assert_eq!(action, Some(WatchdogAction::Reset));
    }

    #[test]
    fn watchdog_returns_none_within_timeout() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.tick(1_000).unwrap();
        let action = shield.check_watchdog(1_500);
        assert_eq!(action, None);
    }

    #[test]
    fn watchdog_action_configurable() {
        let mut config = default_config();
        config.watchdog_action = WatchdogAction::Halt;
        config.watchdog_timeout_us = 500_000;
        let mut shield: Shield = CratonShield::init(config, TestCrypto).unwrap();
        shield.tick(0).unwrap();
        assert_eq!(shield.check_watchdog(1_000_000), Some(WatchdogAction::Halt));
    }

    #[test]
    fn multiple_ticks_advance_counter_monotonically() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        for i in 0..100u64 {
            shield.tick(i.saturating_mul(10_000)).unwrap();
        }
        assert_eq!(shield.tick_count(), 100);
    }

    // -- Frame / Packet Processing ------------------------------------------

    #[test]
    fn submit_can_frame_denied_when_no_rules() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let frame = make_can_frame(0x100);
        // System always fails closed when no policy rules are loaded.
        assert_eq!(
            shield.submit_can_frame(&frame, 1_000),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn submit_eth_packet_denied_when_no_rules() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let payload = [0u8; 64];
        let pkt = make_eth_packet(&payload);
        // System always fails closed when no policy rules are loaded.
        assert_eq!(
            shield.submit_eth_packet(&pkt, 1_000),
            Err(VsError::PolicyViolation)
        );
    }

    /// Regression for the firewall fail-closed gate.
    ///
    /// Prior to the fix, the ETH submission path checked
    /// `firewall.rule_capacity().0 == 0` (live active rule count).
    /// Once every dynamic rule expired the active count returned to
    /// zero and the runtime silently blocked all subsequent Ethernet
    /// traffic -- even though the operator had clearly configured
    /// firewall policy.  The gate now reads the sticky
    /// `firewall_configured` flag set on first successful rule install.
    #[test]
    fn firewall_fail_closed_persists_after_dynamic_rule_expiry() {
        use vs_netfw::RuleAction;
        use vs_policy_engine::{ActionMatcher, PolicyRule, ResourceMatcher, SubjectMatcher};

        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();

        // Install a permit-all policy rule so the policy engine does
        // not short-circuit before we reach the firewall gate.
        shield
            .policy_engine_mut()
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 0,
                valid_from: 0,
                valid_until: 0,
            })
            .expect("add permit-all policy rule");

        // Sanity check: fail-closed before any firewall rule is
        // installed.  (Same coverage as `submit_eth_packet_denied_when_no_rules`
        // but with the policy engine open.)
        assert!(!shield.firewall_configured());
        let payload = [0u8; 64];
        let pkt = make_eth_packet(&payload);
        assert_eq!(
            shield.submit_eth_packet(&pkt, 1_000),
            Err(VsError::PolicyViolation),
            "must fail-closed before any firewall rule is installed"
        );

        // Install a dynamic allow-all rule that expires at t = 2_000_000 us.
        let expiry_us = 2_000_000u64;
        shield
            .install_dynamic_firewall_rule(
                FirewallRule {
                    id: 1,
                    priority: 0,
                    action: RuleAction::Allow,
                    active: true,
                    ..FirewallRule::default()
                },
                expiry_us,
            )
            .expect("install dynamic allow-all rule");
        assert!(shield.firewall_configured());
        assert_eq!(shield.firewall().rule_capacity().0, 1);

        // While the rule is active, traffic is allowed.
        assert!(shield.submit_eth_packet(&pkt, 1_500_000).is_ok());

        // Force every dynamic rule to expire.  Active rule count
        // returns to zero.
        shield.firewall_mut().expire_rules(expiry_us + 1);
        assert_eq!(
            shield.firewall().rule_capacity().0,
            0,
            "all dynamic rules should have expired"
        );

        // CRITICAL: the firewall has been configured at least once, so
        // the sticky sentinel must NOT fire.  Snapshot the event-log
        // count, then submit a post-expiry packet.  The firewall's
        // default-deny on no-match should fire `evaluate()` and route a
        // drop alert -- visible as an extra event-log entry.  Under the
        // buggy short-circuit path the runtime would just return
        // PolicyViolation without invoking `evaluate()` or logging the
        // drop alert at all, so `event_log_count` would be unchanged.
        assert!(
            shield.firewall_configured(),
            "firewall_configured must remain set after rule expiry"
        );
        let before = shield.event_log_count();
        let post_expiry_result = shield.submit_eth_packet(&pkt, expiry_us + 1_000);
        assert_eq!(
            post_expiry_result,
            Err(VsError::PolicyViolation),
            "post-expiry packet should be dropped by firewall default-deny"
        );
        let after = shield.event_log_count();
        assert!(
            after > before,
            "expected firewall evaluate() to log a drop alert \
             (before={before}, after={after}); the buggy short-circuit \
             would have produced no new event-log entries"
        );
    }

    /// Confirm that `install_firewall_rule` is the supported path for
    /// flipping `firewall_configured` to true.
    #[test]
    fn install_firewall_rule_marks_configured() {
        use vs_netfw::RuleAction;

        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert!(!shield.firewall_configured());

        shield
            .install_firewall_rule(FirewallRule {
                id: 1,
                priority: 0,
                action: RuleAction::Allow,
                active: true,
                ..FirewallRule::default()
            })
            .expect("install allow rule");

        assert!(shield.firewall_configured());

        // Removing the rule must NOT clear the sticky flag.
        assert!(shield.firewall_mut().remove_rule(1));
        assert_eq!(shield.firewall().rule_capacity().0, 0);
        assert!(
            shield.firewall_configured(),
            "firewall_configured must remain set after explicit rule removal"
        );
    }

    /// A failed install (e.g. duplicate id) must NOT flip the flag.
    #[test]
    fn install_firewall_rule_failure_does_not_mark_configured() {
        use vs_netfw::RuleAction;

        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();

        // First install succeeds and flips the flag.
        shield
            .install_firewall_rule(FirewallRule {
                id: 1,
                priority: 0,
                action: RuleAction::Allow,
                active: true,
                ..FirewallRule::default()
            })
            .expect("first install");
        assert!(shield.firewall_configured());

        // Remove + force a fresh shield to test the failure path.
        let mut fresh: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert!(!fresh.firewall_configured());

        // Install one rule, then attempt to install a duplicate.
        fresh
            .install_firewall_rule(FirewallRule {
                id: 1,
                priority: 0,
                action: RuleAction::Allow,
                active: true,
                ..FirewallRule::default()
            })
            .expect("first fresh install");
        assert!(fresh.firewall_configured());

        // Now remove the rule and reset the flag for the failure-path
        // check.  We can't reset the flag from outside, so test the
        // failure on a *third* shield.
        let mut third: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        // Pre-populate via direct firewall_mut to seed a rule id without
        // flipping the flag, so the next install_firewall_rule will fail.
        third
            .firewall_mut()
            .add_rule(FirewallRule {
                id: 1,
                priority: 0,
                action: RuleAction::Allow,
                active: true,
                ..FirewallRule::default()
            })
            .expect("seed rule via firewall_mut");
        assert!(
            !third.firewall_configured(),
            "direct firewall_mut().add_rule must NOT flip firewall_configured"
        );

        // Duplicate install via the wrapper must fail and leave the
        // flag clear.
        let res = third.install_firewall_rule(FirewallRule {
            id: 1,
            priority: 0,
            action: RuleAction::Allow,
            active: true,
            ..FirewallRule::default()
        });
        assert!(res.is_err());
        assert!(
            !third.firewall_configured(),
            "failed install_firewall_rule must NOT flip firewall_configured"
        );
    }

    // -- Alert Pipeline -----------------------------------------------------

    #[test]
    fn alert_pipeline_end_to_end() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.event_log_count(), 0);

        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0x100,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 1000,
        };
        shield.route_alert(&alert, 1000);

        assert_eq!(shield.event_log_count(), 1);
        assert_eq!(shield.alert_sequence(), 1);
    }

    #[test]
    fn multiple_alerts_increase_sequence() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();

        for i in 0..5u64 {
            let alert = SecurityAlert {
                id: i,
                severity: AlertSeverity::Medium,
                source_type: vs_types::SOURCE_ETHERNET,
                source_id: 0x200,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: i * 1000,
            };
            shield.route_alert(&alert, i * 1000);
        }

        assert_eq!(shield.event_log_count(), 5);
        assert_eq!(shield.alert_sequence(), 5);
    }

    /// Regression for the alert-sequence post-increment bug.
    ///
    /// Prior to the fix, `route_alert` serialised the *pre-increment*
    /// alert-sequence value into the first 8 bytes of the logged payload
    /// and only incremented at the end of the function.  The first
    /// routed alert therefore carried id=0 in the event log -- colliding
    /// with the reserved sentinel and making the first alert
    /// indistinguishable from a zero-initialised buffer.
    ///
    /// The contract is now: alert ids assigned by `route_alert` start
    /// at 1 and are strictly monotonic.  This test inspects the raw
    /// logged payload to confirm the contract.
    #[test]
    fn route_alert_assigns_nonzero_monotonic_ids() {
        use vs_event_logger::LogEntry;

        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();

        // Route three alerts, deliberately supplying alert.id = 0 to
        // confirm that the caller-supplied id is ignored / overwritten.
        for i in 0..3u64 {
            let alert = SecurityAlert {
                id: 0,
                severity: AlertSeverity::High,
                source_type: vs_types::SOURCE_CAN,
                source_id: 0x100,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: (i + 1) * 1000,
            };
            shield.route_alert(&alert, (i + 1) * 1000);
        }

        // Pull the three log entries back out.
        const ZERO_ENTRY: LogEntry = LogEntry {
            sequence: 0,
            timestamp_us: 0,
            event_type: EventType::SystemEvent,
            payload: [0u8; 128],
            payload_len: 0,
            prev_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        };
        // The event-logger assigns its own per-entry sequence starting
        // at 0; export over the full range to capture all three.
        let mut out = [ZERO_ENTRY; 4];
        let copied = shield.event_logger().export_entries(0, u64::MAX, &mut out);
        assert_eq!(copied, 3, "expected 3 alert entries in the event log");

        // Decode the alert id from the first 8 bytes of each payload
        // and confirm it is 1, 2, 3 (post-increment monotonic).
        for (i, entry) in out[..copied].iter().enumerate() {
            let expected_id = (i + 1) as u64;
            let actual_id = u64::from_le_bytes(entry.payload[0..8].try_into().unwrap());
            assert_eq!(
                actual_id, expected_id,
                "alert payload[0..8] decoded as {actual_id}, expected {expected_id}"
            );
            assert_ne!(actual_id, 0, "alert id 0 is reserved and must never appear");
        }

        // Counter should reflect the three assignments.
        assert_eq!(shield.alert_sequence(), 3);
    }

    // -- OTA Configuration --------------------------------------------------

    #[test]
    fn ota_validator_none_before_configure() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert!(shield.ota_validator().is_none());
        assert_eq!(
            shield.health_status().ota_validator,
            SubsystemStatus::NotInitialized
        );
    }

    #[test]
    fn configure_ota_rejects_zero_threshold() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let bad_root = TufRoot {
            version: 1,
            expires_us: u64::MAX,
            root_keys: [None; 4],
            threshold: 0,
            targets_keys: [None; 4],
            targets_threshold: 0,
            snapshot_keys: [None; 4],
            snapshot_threshold: 0,
            timestamp_keys: [None; 4],
            timestamp_threshold: 0,
        };
        assert_eq!(shield.configure_ota(bad_root), Err(VsError::InvalidConfig));
        assert!(shield.ota_validator().is_none());
    }

    #[test]
    fn configure_ota_rejects_no_keys() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let bad_root = TufRoot {
            version: 1,
            expires_us: u64::MAX,
            root_keys: [None; 4],
            threshold: 1,
            targets_keys: [None; 4],
            targets_threshold: 1,
            snapshot_keys: [None; 4],
            snapshot_threshold: 1,
            timestamp_keys: [None; 4],
            timestamp_threshold: 1,
        };
        assert_eq!(shield.configure_ota(bad_root), Err(VsError::InvalidConfig));
    }

    // -- Boot Verification --------------------------------------------------

    #[test]
    fn boot_not_verified_after_init() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert!(!shield.is_boot_verified());
        assert_eq!(
            shield.health_status().secure_boot,
            SubsystemStatus::NotInitialized
        );
    }

    // -- Accessor Smoke Tests -----------------------------------------------

    #[test]
    fn policy_engine_accessible() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.policy_engine().rule_count(), 0);
    }

    #[test]
    fn firewall_accessible() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.firewall().drop_count(), 0);
    }

    #[test]
    fn anomaly_detector_accessible() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.anomaly_detector().count(), 0);
    }

    #[test]
    fn key_manager_accessible() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let _km = shield.key_manager();
    }

    #[test]
    fn integrity_monitor_accessible() {
        let shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        assert_eq!(shield.integrity_monitor().active_region_count(), 0);
    }

    #[test]
    fn new_constructor_creates_all_subsystems() {
        let config = default_config();
        let shield: CratonShield<TestCrypto> = CratonShield::new(&config).unwrap();
        assert!(shield.is_initialized());
        assert_eq!(shield.event_log_count(), 0);
    }

    // -- Capacity Checks ----------------------------------------------------

    #[test]
    fn capacity_check_runs_on_tick() {
        let config = default_config();
        let mut shield: Shield = CratonShield::init(config, TestCrypto).unwrap();
        assert_eq!(shield.event_log_count(), 0);

        // Without policy rules, CAN frames are denied (fail-closed).
        // We test the capacity check pathway by ticking enough times to
        // trigger the periodic check without needing to submit frames.
        let ts_base = 1_000_000u64;
        for t in 0..200u64 {
            let _ = shield.tick(ts_base + t * 100_000);
        }
        // The capacity check runs every CAPACITY_CHECK_INTERVAL ticks;
        // verify it did not panic or corrupt health.
        assert_eq!(shield.health_status().crypto, SubsystemStatus::Ready);
    }

    // -- Helpers ------------------------------------------------------------

    #[test]
    fn write_usize_decimal_works() {
        let mut buf = [0u8; 32];
        let end = write_usize_decimal(&mut buf, 0, 0);
        assert_eq!(&buf[..end], b"0");

        let mut buf = [0u8; 32];
        let end = write_usize_decimal(&mut buf, 0, 12345);
        assert_eq!(&buf[..end], b"12345");

        let mut buf = [0u8; 32];
        let end = write_usize_decimal(&mut buf, 4, 99);
        assert_eq!(end, 6);
        assert_eq!(&buf[4..6], b"99");
    }

    #[test]
    fn health_status_reflects_correct_subsystem_count() {
        let h = PlatformHealth::all_ready();
        let statuses = [
            h.crypto,
            h.key_manager,
            h.secure_boot,
            h.event_logger,
            h.can_monitor,
            h.eth_monitor,
            h.ids_engine,
            h.firewall,
            h.ota_validator,
            h.anomaly,
            h.integrity,
            h.policy_engine,
            h.storage,
            h.hal,
        ];
        assert_eq!(statuses.len(), 14);
        for status in &statuses {
            assert_eq!(*status, SubsystemStatus::Ready);
        }
    }

    // -- Watchdog Logging ---------------------------------------------------

    #[test]
    fn watchdog_fire_generates_log_event() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.tick(0).unwrap();
        let before = shield.event_log_count();
        let action = shield.check_watchdog(2_000_000);
        assert_eq!(action, Some(WatchdogAction::Reset));
        assert!(
            shield.event_log_count() > before,
            "watchdog fire should generate a log event"
        );
    }

    // -- ETH Anomaly Detection ----------------------------------------------

    #[test]
    fn eth_packets_denied_without_rules() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let payload = [0u8; 64];
        let pkt = make_eth_packet(&payload);
        // With no policy rules loaded, ETH packets are denied (fail-closed).
        for i in 0..10u64 {
            assert_eq!(
                shield.submit_eth_packet(&pkt, i * 20_000),
                Err(VsError::PolicyViolation)
            );
        }
    }

    // -- IDS Response -------------------------------------------------------

    #[test]
    fn ids_log_response_does_not_alter_health() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        // IDS engine with default (no policies) returns Log for any severity.
        // With no policy rules loaded, CAN frame submission is denied
        // (fail-closed), so we test IDS health via execute_ids_response.
        shield.execute_ids_response(IdsResponse::Log, 1_000);
        assert_eq!(shield.health_status().ids_engine, SubsystemStatus::Ready);
    }

    // -- Shutdown Key Zeroization -------------------------------------------

    #[test]
    fn shutdown_calls_keym_finalize() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        // Generate a key (uses the crypto provider's RNG), then shutdown.
        use vs_key_manager::{KeyAlgorithm, KeyMetadata, KeyPurpose};
        let meta = KeyMetadata {
            key_id: KeyId(1),
            algorithm: KeyAlgorithm::HmacSha256,
            purpose: KeyPurpose::BusAuthentication,
            created_at: 1_000,
            expires_at: None,
            rotation_count: 0,
            cumulative_nonce_count: 0,
        };
        shield
            .key_manager_mut()
            .generate_key(KeyId(1), meta)
            .expect("key generation should succeed");
        assert!(shield.key_manager().is_key_valid(KeyId(1), 2_000));

        shield.shutdown();
        // After shutdown, keym_finalize zeroized all key material.
        // The key manager's slots are cleared -- key_valid will be false
        // even if we could call it (the key_manager field is still
        // accessible on the struct even though the platform is shut down).
        assert!(!shield.is_initialized());
        assert!(!shield.key_manager().is_key_valid(KeyId(1), 2_000));
    }

    // -- Always fail-closed Policy -------------------------------------------

    #[test]
    fn always_fail_closed_policy_denies_when_no_rules() {
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        let frame = make_can_frame(0x100);
        let result = shield.submit_can_frame(&frame, 1000);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    // -- IDS Callbacks -----------------------------------------------------

    #[test]
    fn ids_block_callback_invoked() {
        use core::sync::atomic::{AtomicBool, Ordering};
        static CALLED: AtomicBool = AtomicBool::new(false);
        fn block_handler(_bus: u32, _dur: u64) {
            CALLED.store(true, Ordering::SeqCst);
        }
        let mut shield: Shield = CratonShield::init(default_config(), TestCrypto).unwrap();
        shield.set_block_handler(block_handler);
        shield.execute_ids_response(
            IdsResponse::Block {
                bus_id: 1,
                duration_us: 5000,
            },
            1000,
        );
        assert!(CALLED.load(Ordering::SeqCst));
    }
}
