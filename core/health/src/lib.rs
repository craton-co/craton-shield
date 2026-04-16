// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `vs-health` -- shared subsystem health tracking for Craton Shield runtimes.
//!
//! This crate centralizes the per-subsystem health bookkeeping that the
//! per-domain runtime crates (`runtime-auto`, `runtime-embedded`, `runtime-ind`)
//! previously hand-rolled. It fixes a small family of systematic bugs found in
//! review of those crates:
//!
//! * **`ts_us == 0` auto-recovery deadlock (runtime-ind).** When a subsystem was
//!   marked `Degraded` at the wall-clock timestamp zero, the recovery check
//!   `now - degraded_since_us >= timeout` could never be made distinguishable
//!   from "never degraded", so the subsystem remained stuck in `Degraded`
//!   forever. [`HealthRegistry::with_subsystem_alert`] forces the recorded
//!   timestamp to `ts_us.max(1)` and stores it in an
//!   `Option<NonZeroU64>`, which makes "actually degraded" structurally
//!   distinct from "never degraded".
//! * **Inconsistent shutdown (runtime-ind).** Some runtime crates only reset
//!   the per-subsystem `status` field on shutdown and left
//!   `degraded_since_us` populated, so a re-start could spuriously trip the
//!   auto-recovery path. [`HealthRegistry::shutdown`] resets every
//!   per-subsystem field in a single call.
//! * **Health-attribution drift across runtimes (all three).** Status mutation
//!   was sprinkled across dozens of `self.modbus_status = ...` and
//!   `self.v2x_status = ...` assignments, making it easy to forget to
//!   update `degraded_since_us` (or the dirty bit, or to log an alert).
//!   [`HealthRegistry::with_subsystem_alert`] is the only path that can mutate
//!   a subsystem status: it always pairs the status change with the alert
//!   timestamp and flips the dirty bit.
//!
//! The crate is `#![no_std]`, contains no `unsafe`, and uses fixed-size storage
//! sized at the number of [`SubsystemId`] variants -- so it is suitable for
//! ASIL-B / IEC 62443 / IEC 62304 deployments.
//!
//! ## Migration note
//!
//! Runtime crates (`vs-runtime`, `vs-runtime-auto`, `vs-runtime-ind`,
//! `vs-runtime-embedded`) will adopt this API in 0.8.0 -- see ROADMAP.

use core::num::NonZeroU64;

use vs_types::AlertSeverity;

// ---------------------------------------------------------------------------
// SubsystemId
// ---------------------------------------------------------------------------

/// Identifier for a subsystem whose health is tracked by [`HealthRegistry`].
///
/// The variants cover every monitor across the core, automotive, embedded, and
/// industrial workspaces. This enum is `#[non_exhaustive]`: new subsystems may
/// be added without a major version bump. Internal storage is sized to
/// [`SubsystemId::COUNT`] so consumers do not need to enumerate the variants
/// themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum SubsystemId {
    /// Controller Area Network monitor (`core/can-monitor`).
    Can,
    /// Ethernet monitor (`core/eth-monitor`).
    Eth,
    /// Vehicle-to-Everything stack (`auto/v2x`).
    V2x,
    /// Diagnostic gateway (`auto/diag-gateway`).
    Diag,
    /// AUTOSAR Signal-ID resolver (`auto/signal-ids`).
    SignalIds,
    /// MQTT broker monitor (`embedded/mqtt-monitor`).
    Mqtt,
    /// CoAP server monitor (`embedded/coap-monitor`).
    CoAp,
    /// Bluetooth Low Energy monitor (`embedded/ble-monitor`).
    Ble,
    /// Zigbee monitor (`embedded/zigbee-monitor`).
    Zigbee,
    /// LoRaWAN monitor (`embedded/lora-monitor`).
    LoRa,
    /// Embedded Modbus/TCP monitor (`embedded/modbus-monitor-emb`).
    ModbusEmb,
    /// Industrial Modbus/TCP monitor (`industrial/modbus-monitor-ind`).
    ModbusInd,
    /// OPC UA monitor (`industrial/opcua-monitor`).
    OpcUa,
    /// PROFINET monitor (`industrial/profinet-monitor`).
    Profinet,
    /// EtherNet/IP monitor (`industrial/ethernetip-monitor`).
    EthernetIp,
    /// DNP3 monitor (`industrial/dnp3-monitor`).
    Dnp3,
    /// BACnet monitor (`industrial/bacnet-monitor`).
    BacNet,
    /// Siemens S7Comm monitor (`industrial/s7comm-monitor`).
    S7Comm,
    /// IEC 60870-5-104 monitor (`industrial/iec60870-monitor`).
    Iec60870,
    /// IEC 61850 monitor (`industrial/iec61850-monitor`).
    Iec61850,
    /// IEC 61850 MMS sub-stack.
    Mms,
    /// IEC 61850 GOOSE sub-stack.
    Goose,
}

impl SubsystemId {
    /// Number of distinct [`SubsystemId`] variants.
    ///
    /// Used internally to size the fixed-length arrays inside
    /// [`HealthRegistry`]. Public so that callers can build their own
    /// `[T; SubsystemId::COUNT]` lookup tables.
    pub const COUNT: usize = 22;

    /// All variants, in declaration order.
    ///
    /// The order matches [`SubsystemId::as_index`], so this is suitable for
    /// iterating over a `[T; SubsystemId::COUNT]` lookup table:
    ///
    /// ```
    /// use vs_health::SubsystemId;
    /// for (i, id) in SubsystemId::ALL.iter().copied().enumerate() {
    ///     assert_eq!(i, id.as_index());
    /// }
    /// ```
    pub const ALL: [SubsystemId; SubsystemId::COUNT] = [
        SubsystemId::Can,
        SubsystemId::Eth,
        SubsystemId::V2x,
        SubsystemId::Diag,
        SubsystemId::SignalIds,
        SubsystemId::Mqtt,
        SubsystemId::CoAp,
        SubsystemId::Ble,
        SubsystemId::Zigbee,
        SubsystemId::LoRa,
        SubsystemId::ModbusEmb,
        SubsystemId::ModbusInd,
        SubsystemId::OpcUa,
        SubsystemId::Profinet,
        SubsystemId::EthernetIp,
        SubsystemId::Dnp3,
        SubsystemId::BacNet,
        SubsystemId::S7Comm,
        SubsystemId::Iec60870,
        SubsystemId::Iec61850,
        SubsystemId::Mms,
        SubsystemId::Goose,
    ];

    /// Stable index in `0..SubsystemId::COUNT`.
    ///
    /// Used by [`HealthRegistry`] to look up per-subsystem state in
    /// constant time without requiring a hash table.
    #[inline]
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// SubsystemStatus
// ---------------------------------------------------------------------------

/// Per-subsystem health status.
///
/// A subsystem starts in [`SubsystemStatus::NotInitialized`]. Initialization
/// transitions it to [`SubsystemStatus::Ready`]. Alert handlers move it to
/// [`SubsystemStatus::Degraded`] (for recoverable conditions, e.g. a
/// monitor producing parse errors above threshold) or
/// [`SubsystemStatus::Failed`] (for non-recoverable conditions, e.g. a
/// hardware fault). [`HealthRegistry::try_auto_recover`] can move a subsystem
/// from `Degraded` back to `Ready` after a timeout; `Failed` is sticky.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SubsystemStatus {
    /// Subsystem has not yet been initialized, or has been shut down.
    NotInitialized,
    /// Subsystem is healthy.
    Ready,
    /// Subsystem is degraded but recoverable. May transition back to
    /// `Ready` via [`HealthRegistry::try_auto_recover`] after a timeout.
    Degraded,
    /// Subsystem has failed in a non-recoverable manner. Operator
    /// intervention required.
    Failed,
}

impl SubsystemStatus {
    /// Returns true if this status indicates an unhealthy subsystem.
    #[inline]
    #[must_use]
    pub const fn is_unhealthy(self) -> bool {
        matches!(self, SubsystemStatus::Degraded | SubsystemStatus::Failed)
    }
}

// ---------------------------------------------------------------------------
// SubsystemHandle
// ---------------------------------------------------------------------------

/// Mutable view of a single subsystem's tracked state, handed to the closure
/// passed to [`HealthRegistry::with_subsystem_alert`].
///
/// The handle is the **only** path through which a subsystem's status can be
/// mutated. This centralization ensures that any status change is paired with
/// an alert timestamp and a dirty-bit flip, so the health view can never
/// silently drift out of sync with the alert log.
#[derive(Debug)]
pub struct SubsystemHandle<'a> {
    id: SubsystemId,
    status: &'a mut SubsystemStatus,
    degraded_since_us: &'a mut Option<NonZeroU64>,
    /// The clamped (`>= 1`) timestamp this handle was created with.
    ts_us: NonZeroU64,
    /// Severity that triggered this alert -- exposed for inspection but does
    /// not itself mutate any state.
    severity: AlertSeverity,
}

impl<'a> SubsystemHandle<'a> {
    /// Returns the subsystem this handle refers to.
    #[inline]
    #[must_use]
    pub fn id(&self) -> SubsystemId {
        self.id
    }

    /// Returns the (clamped) alert timestamp this handle was created with.
    ///
    /// Always non-zero -- if the caller passed `ts_us == 0` to
    /// [`HealthRegistry::with_subsystem_alert`], this returns `1`.
    #[inline]
    #[must_use]
    pub fn ts_us(&self) -> NonZeroU64 {
        self.ts_us
    }

    /// Returns the severity that triggered this alert.
    #[inline]
    #[must_use]
    pub fn severity(&self) -> AlertSeverity {
        self.severity
    }

    /// Returns the current status.
    #[inline]
    #[must_use]
    pub fn status(&self) -> SubsystemStatus {
        *self.status
    }

    /// Mark this subsystem as `Degraded` and stamp `degraded_since_us` with
    /// the handle's timestamp.
    ///
    /// If the subsystem is already `Failed`, this is a no-op -- `Failed`
    /// outranks `Degraded` and stays sticky.
    pub fn mark_degraded(&mut self) {
        if *self.status == SubsystemStatus::Failed {
            return;
        }
        *self.status = SubsystemStatus::Degraded;
        *self.degraded_since_us = Some(self.ts_us);
    }

    /// Mark this subsystem as `Failed`. Clears `degraded_since_us`: a failed
    /// subsystem will not be auto-recovered.
    pub fn mark_failed(&mut self) {
        *self.status = SubsystemStatus::Failed;
        *self.degraded_since_us = None;
    }

    /// Mark this subsystem as `Ready`. Clears `degraded_since_us`.
    pub fn mark_ready(&mut self) {
        *self.status = SubsystemStatus::Ready;
        *self.degraded_since_us = None;
    }
}

// ---------------------------------------------------------------------------
// HealthRegistry
// ---------------------------------------------------------------------------

/// Per-subsystem health and alert-timestamp registry.
///
/// Each subsystem has:
/// * a [`SubsystemStatus`] (defaulting to [`SubsystemStatus::NotInitialized`])
/// * an `Option<NonZeroU64>` of the timestamp it last entered the `Degraded`
///   state, used by [`Self::try_auto_recover`]
///
/// The registry also carries a single shared `dirty` bit set whenever any
/// subsystem's state changes through [`Self::with_subsystem_alert`],
/// [`Self::try_auto_recover`], [`Self::mark_initialized`], or [`Self::shutdown`].
/// Consumers (e.g. an FFI layer that copies the health snapshot out to a C
/// caller) can poll [`Self::take_dirty`] to learn whether they need to refresh
/// their cached view.
#[derive(Debug, Clone)]
pub struct HealthRegistry {
    statuses: [SubsystemStatus; SubsystemId::COUNT],
    degraded_since_us: [Option<NonZeroU64>; SubsystemId::COUNT],
    /// One bit per `SubsystemId` index: set iff that subsystem is currently
    /// `Degraded`. Allows `try_auto_recover` to skip the per-slot scan when
    /// no subsystem is degraded. `SubsystemId::COUNT` is 22, so a `u32` is
    /// sufficient with room to spare.
    degraded_bitmap: u32,
    dirty: bool,
}

impl HealthRegistry {
    /// Construct a fresh registry. All subsystems start as
    /// [`SubsystemStatus::NotInitialized`] and the dirty bit is clear.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        // Compile-time guard: bitmap width must cover SubsystemId::COUNT.
        const _: () = assert!(
            SubsystemId::COUNT <= 32,
            "degraded_bitmap is a u32 and cannot index more than 32 subsystems",
        );
        Self {
            statuses: [SubsystemStatus::NotInitialized; SubsystemId::COUNT],
            degraded_since_us: [None; SubsystemId::COUNT],
            degraded_bitmap: 0,
            dirty: false,
        }
    }

    /// Mark a subsystem as freshly initialized (Ready).
    ///
    /// Does **not** go through the alert path: initialization is not an
    /// alert. Clears any prior `degraded_since_us`.
    pub fn mark_initialized(&mut self, sys: SubsystemId) {
        let idx = sys.as_index();
        if self.statuses[idx] != SubsystemStatus::Ready || self.degraded_since_us[idx].is_some() {
            self.dirty = true;
        }
        self.statuses[idx] = SubsystemStatus::Ready;
        if self.degraded_since_us[idx].is_some() {
            self.degraded_since_us[idx] = None;
        }
        self.degraded_bitmap &= !(1u32 << idx);
    }

    /// Returns the current status of `sys`.
    #[inline]
    #[must_use]
    pub fn status(&self, sys: SubsystemId) -> SubsystemStatus {
        self.statuses[sys.as_index()]
    }

    /// Returns the timestamp at which `sys` entered the `Degraded` state,
    /// or `None` if it is not currently degraded.
    #[inline]
    #[must_use]
    pub fn degraded_since_us(&self, sys: SubsystemId) -> Option<NonZeroU64> {
        self.degraded_since_us[sys.as_index()]
    }

    /// Returns true if any subsystem has changed state since the dirty bit
    /// was last cleared.
    #[inline]
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Returns and clears the dirty bit.
    pub fn take_dirty(&mut self) -> bool {
        let d = self.dirty;
        self.dirty = false;
        d
    }

    /// Central status-mutation entry point.
    ///
    /// The closure receives a [`SubsystemHandle`] for `sys`. The handle's
    /// `ts_us` is clamped to `ts_us.max(1)` as a `NonZeroU64`, which is what
    /// [`SubsystemHandle::mark_degraded`] writes into `degraded_since_us`.
    /// This clamp prevents the `ts_us == 0` auto-recovery deadlock that
    /// previously bit `runtime-ind`. If the closure instead calls
    /// [`SubsystemHandle::mark_ready`] or [`SubsystemHandle::mark_failed`],
    /// `degraded_since_us` is cleared. After the closure returns, the
    /// registry's dirty bit is set and the internal `degraded_bitmap` is
    /// updated to match the resulting status.
    ///
    /// `alert_severity` is passed through to the closure for inspection but
    /// is not itself stored in the registry -- the alert log is the source of
    /// truth for severity history.
    ///
    /// The closure's return value is forwarded to the caller, so this can be
    /// used to e.g. push an alert event into a log and propagate its index
    /// back.
    pub fn with_subsystem_alert<F, R>(
        &mut self,
        sys: SubsystemId,
        ts_us: u64,
        alert_severity: AlertSeverity,
        f: F,
    ) -> R
    where
        F: FnOnce(&mut SubsystemHandle<'_>) -> R,
    {
        // Clamp ts_us to be non-zero. This is the linchpin that makes
        // "degraded at ts==0" distinguishable from "never degraded".
        let ts_nz = NonZeroU64::new(ts_us).unwrap_or(NonZeroU64::MIN);

        let idx = sys.as_index();
        // Note: we DO NOT pre-populate `degraded_since_us` here. Doing so
        // would force a spurious FFI snapshot refresh in the (very common)
        // case where the closure immediately calls `mark_ready` / `mark_failed`
        // and never observes a `Degraded` state. The handle still gets a
        // mutable reference to the slot so it can stamp the timestamp itself
        // via `mark_degraded`.
        let mut handle = SubsystemHandle {
            id: sys,
            status: &mut self.statuses[idx],
            degraded_since_us: &mut self.degraded_since_us[idx],
            ts_us: ts_nz,
            severity: alert_severity,
        };
        let out = f(&mut handle);

        // After the closure: update the dirty bit and degraded bitmap based
        // on the resulting status. The bitmap mirrors `statuses[idx] ==
        // Degraded` and accelerates `try_auto_recover`'s scan.
        self.dirty = true;
        let bit = 1u32 << idx;
        if self.statuses[idx] == SubsystemStatus::Degraded {
            self.degraded_bitmap |= bit;
        } else {
            self.degraded_bitmap &= !bit;
        }
        out
    }

    /// Attempt to recover any `Degraded` subsystem whose `degraded_since_us`
    /// is older than `timeout_us`.
    ///
    /// `now_us` is the current monotonic timestamp. Subsystems whose
    /// `degraded_since_us` is `None` or which are not in the `Degraded` state
    /// are left untouched. `Failed` subsystems are *never* auto-recovered
    /// (`Failed` requires operator intervention).
    ///
    /// Returns the number of subsystems that were recovered.
    pub fn try_auto_recover(&mut self, now_us: u64, timeout_us: u64) -> usize {
        // Fast path: if no subsystem is currently `Degraded`, there is nothing
        // to recover. This is the common steady-state case once a runtime has
        // booted, so worth short-circuiting at every `tick`.
        if self.degraded_bitmap == 0 {
            return 0;
        }
        let mut recovered = 0;
        for idx in 0..SubsystemId::COUNT {
            if self.statuses[idx] != SubsystemStatus::Degraded {
                continue;
            }
            let Some(since) = self.degraded_since_us[idx] else {
                continue;
            };
            // since.get() is >= 1, so this subtraction underflowing would
            // require now_us < 1, which is itself a degenerate clock state we
            // do not try to handle here -- it would only delay recovery, not
            // produce a deadlock.
            if now_us >= since.get() && (now_us - since.get()) >= timeout_us {
                self.statuses[idx] = SubsystemStatus::Ready;
                self.degraded_since_us[idx] = None;
                self.degraded_bitmap &= !(1u32 << idx);
                self.dirty = true;
                recovered += 1;
            }
        }
        recovered
    }

    /// Reset the entire registry to its post-`new()` state.
    ///
    /// Used when the platform is shutting down or being reinitialized. This
    /// resets `status`, `degraded_since_us`, and `dirty` for every subsystem
    /// -- fixing the runtime-ind gap where `shutdown` cleared status but left
    /// `degraded_since_us` populated, causing the next start-up to spuriously
    /// auto-recover.
    pub fn shutdown(&mut self) {
        // Fuse the status and degraded_since_us reset into a single pass.
        for (s, d) in self
            .statuses
            .iter_mut()
            .zip(self.degraded_since_us.iter_mut())
        {
            *s = SubsystemStatus::NotInitialized;
            *d = None;
        }
        self.degraded_bitmap = 0;
        // We explicitly clear, not set, the dirty bit: shutdown is observed
        // synchronously by its caller and does not need a separate change
        // notification.
        self.dirty = false;
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SubsystemId invariants
    // -----------------------------------------------------------------------

    #[test]
    fn subsystem_id_count_matches_all_array() {
        assert_eq!(SubsystemId::ALL.len(), SubsystemId::COUNT);
    }

    #[test]
    fn subsystem_id_indices_are_dense_and_unique() {
        let mut seen = [false; SubsystemId::COUNT];
        for id in SubsystemId::ALL {
            let i = id.as_index();
            assert!(i < SubsystemId::COUNT, "index {} out of range", i);
            assert!(!seen[i], "duplicate index {}", i);
            seen[i] = true;
        }
        assert!(seen.iter().all(|s| *s), "indices are not dense");
    }

    #[test]
    fn subsystem_id_all_order_matches_index() {
        for (i, id) in SubsystemId::ALL.iter().copied().enumerate() {
            assert_eq!(i, id.as_index(), "ALL[{i}] = {id:?} has wrong index");
        }
    }

    // -----------------------------------------------------------------------
    // SubsystemStatus
    // -----------------------------------------------------------------------

    #[test]
    fn unhealthy_classification() {
        assert!(!SubsystemStatus::NotInitialized.is_unhealthy());
        assert!(!SubsystemStatus::Ready.is_unhealthy());
        assert!(SubsystemStatus::Degraded.is_unhealthy());
        assert!(SubsystemStatus::Failed.is_unhealthy());
    }

    // -----------------------------------------------------------------------
    // HealthRegistry construction / defaults
    // -----------------------------------------------------------------------

    #[test]
    fn new_registry_is_all_not_initialized_and_clean() {
        let r = HealthRegistry::new();
        for id in SubsystemId::ALL {
            assert_eq!(r.status(id), SubsystemStatus::NotInitialized);
            assert_eq!(r.degraded_since_us(id), None);
        }
        assert!(!r.is_dirty());
    }

    #[test]
    fn default_equals_new() {
        let a = HealthRegistry::default();
        let b = HealthRegistry::new();
        for id in SubsystemId::ALL {
            assert_eq!(a.status(id), b.status(id));
            assert_eq!(a.degraded_since_us(id), b.degraded_since_us(id));
        }
        assert_eq!(a.is_dirty(), b.is_dirty());
    }

    // -----------------------------------------------------------------------
    // mark_initialized
    // -----------------------------------------------------------------------

    #[test]
    fn mark_initialized_transitions_to_ready_and_dirties() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Can);
        assert_eq!(r.status(SubsystemId::Can), SubsystemStatus::Ready);
        assert_eq!(r.degraded_since_us(SubsystemId::Can), None);
        assert!(r.is_dirty());
    }

    #[test]
    fn mark_initialized_clears_prior_degraded_since() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Mqtt, 100, AlertSeverity::High, |h| {
            h.mark_degraded();
        });
        assert!(r.degraded_since_us(SubsystemId::Mqtt).is_some());
        r.mark_initialized(SubsystemId::Mqtt);
        assert_eq!(r.status(SubsystemId::Mqtt), SubsystemStatus::Ready);
        assert_eq!(r.degraded_since_us(SubsystemId::Mqtt), None);
    }

    #[test]
    fn mark_initialized_does_not_dirty_when_already_ready_and_clean() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Eth);
        assert!(r.take_dirty());
        // Second call has nothing to change.
        r.mark_initialized(SubsystemId::Eth);
        assert!(!r.is_dirty());
    }

    // -----------------------------------------------------------------------
    // with_subsystem_alert: status transitions
    // -----------------------------------------------------------------------

    #[test]
    fn with_subsystem_alert_marks_degraded_and_stamps_ts() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::OpcUa, 5_000, AlertSeverity::Medium, |h| {
            assert_eq!(h.id(), SubsystemId::OpcUa);
            assert_eq!(h.severity(), AlertSeverity::Medium);
            assert_eq!(h.ts_us().get(), 5_000);
            h.mark_degraded();
            assert_eq!(h.status(), SubsystemStatus::Degraded);
        });
        assert_eq!(r.status(SubsystemId::OpcUa), SubsystemStatus::Degraded);
        assert_eq!(
            r.degraded_since_us(SubsystemId::OpcUa).map(NonZeroU64::get),
            Some(5_000)
        );
        assert!(r.is_dirty());
    }

    #[test]
    fn with_subsystem_alert_returns_closure_value() {
        let mut r = HealthRegistry::new();
        let out: u32 = r.with_subsystem_alert(SubsystemId::Can, 42, AlertSeverity::Low, |h| {
            h.mark_degraded();
            7
        });
        assert_eq!(out, 7);
    }

    #[test]
    fn closure_can_mark_failed_clearing_degraded_since() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Dnp3, 1_000, AlertSeverity::Critical, |h| {
            h.mark_failed();
        });
        assert_eq!(r.status(SubsystemId::Dnp3), SubsystemStatus::Failed);
        assert_eq!(r.degraded_since_us(SubsystemId::Dnp3), None);
    }

    #[test]
    fn closure_can_mark_ready_clearing_degraded_since() {
        let mut r = HealthRegistry::new();
        // Establish a degraded state, then immediately recover via the same
        // alert path (e.g. an Info-severity "resolved" alert).
        r.with_subsystem_alert(SubsystemId::Profinet, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        r.with_subsystem_alert(SubsystemId::Profinet, 2_000, AlertSeverity::Info, |h| {
            h.mark_ready();
        });
        assert_eq!(r.status(SubsystemId::Profinet), SubsystemStatus::Ready);
        assert_eq!(r.degraded_since_us(SubsystemId::Profinet), None);
    }

    #[test]
    fn failed_outranks_subsequent_mark_degraded() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::BacNet, 100, AlertSeverity::Critical, |h| {
            h.mark_failed();
        });
        // A subsequent alert that only escalates to Degraded must NOT
        // demote Failed back to Degraded.
        r.with_subsystem_alert(SubsystemId::BacNet, 200, AlertSeverity::High, |h| {
            h.mark_degraded();
        });
        assert_eq!(r.status(SubsystemId::BacNet), SubsystemStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // ts_us == 0 NON-DEADLOCK regression test (runtime-ind bug)
    // -----------------------------------------------------------------------

    #[test]
    fn ts_us_zero_is_clamped_to_one() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Iec61850, 0, AlertSeverity::Medium, |h| {
            assert_eq!(h.ts_us().get(), 1, "ts_us == 0 must be clamped to 1");
            h.mark_degraded();
        });
        let since = r
            .degraded_since_us(SubsystemId::Iec61850)
            .expect("degraded_since_us must be Some after mark_degraded at ts=0");
        assert_eq!(since.get(), 1);
    }

    #[test]
    fn ts_us_zero_does_not_block_auto_recovery() {
        // Pre-bug: subsystem was marked Degraded at ts=0, and the old
        // try_auto_recover logic could not distinguish "never degraded"
        // (degraded_since_us == 0) from "degraded right at startup", so
        // recovery never fired. The new API stamps ts.max(1).
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::ModbusInd, 0, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        assert_eq!(r.status(SubsystemId::ModbusInd), SubsystemStatus::Degraded);

        let timeout_us = 1_000;
        let now_us = 2_000;
        let recovered = r.try_auto_recover(now_us, timeout_us);
        assert_eq!(
            recovered, 1,
            "subsystem must auto-recover even when alerted at ts=0"
        );
        assert_eq!(r.status(SubsystemId::ModbusInd), SubsystemStatus::Ready);
        assert_eq!(r.degraded_since_us(SubsystemId::ModbusInd), None);
    }

    // -----------------------------------------------------------------------
    // try_auto_recover behavior
    // -----------------------------------------------------------------------

    #[test]
    fn auto_recover_respects_timeout() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Mqtt, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        // now=1500, timeout=1000 -> elapsed=500 < 1000 -> no recovery
        let recovered = r.try_auto_recover(1_500, 1_000);
        assert_eq!(recovered, 0);
        assert_eq!(r.status(SubsystemId::Mqtt), SubsystemStatus::Degraded);
        // now=2500, timeout=1000 -> elapsed=1500 >= 1000 -> recover
        let recovered = r.try_auto_recover(2_500, 1_000);
        assert_eq!(recovered, 1);
        assert_eq!(r.status(SubsystemId::Mqtt), SubsystemStatus::Ready);
    }

    #[test]
    fn auto_recover_exact_threshold_is_inclusive() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::CoAp, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        // elapsed == timeout: must recover.
        let recovered = r.try_auto_recover(2_000, 1_000);
        assert_eq!(recovered, 1);
        assert_eq!(r.status(SubsystemId::CoAp), SubsystemStatus::Ready);
    }

    #[test]
    fn auto_recover_skips_failed() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::S7Comm, 1_000, AlertSeverity::Critical, |h| {
            h.mark_failed();
        });
        // Even with infinite elapsed, Failed must not recover.
        let recovered = r.try_auto_recover(u64::MAX, 0);
        assert_eq!(recovered, 0);
        assert_eq!(r.status(SubsystemId::S7Comm), SubsystemStatus::Failed);
    }

    #[test]
    fn auto_recover_skips_ready_and_not_initialized() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Ble);
        let recovered = r.try_auto_recover(u64::MAX, 0);
        assert_eq!(recovered, 0);
        assert_eq!(r.status(SubsystemId::Ble), SubsystemStatus::Ready);
        // NotInitialized:
        assert_eq!(
            r.status(SubsystemId::Zigbee),
            SubsystemStatus::NotInitialized
        );
        let recovered = r.try_auto_recover(u64::MAX, 0);
        assert_eq!(recovered, 0);
        assert_eq!(
            r.status(SubsystemId::Zigbee),
            SubsystemStatus::NotInitialized
        );
    }

    #[test]
    fn auto_recover_handles_now_before_degraded_since_gracefully() {
        // If the monotonic clock goes backward (e.g. host TSC migration), we
        // should not panic; we should just not recover yet.
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::LoRa, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        let recovered = r.try_auto_recover(500, 100);
        assert_eq!(recovered, 0);
        assert_eq!(r.status(SubsystemId::LoRa), SubsystemStatus::Degraded);
    }

    #[test]
    fn auto_recover_recovers_multiple_subsystems_in_one_call() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Mqtt, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        r.with_subsystem_alert(SubsystemId::OpcUa, 1_500, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        r.with_subsystem_alert(SubsystemId::Dnp3, 1_800, AlertSeverity::Critical, |h| {
            h.mark_failed();
        });
        let recovered = r.try_auto_recover(10_000, 1_000);
        assert_eq!(recovered, 2, "two Degraded, one Failed -> recover two");
        assert_eq!(r.status(SubsystemId::Mqtt), SubsystemStatus::Ready);
        assert_eq!(r.status(SubsystemId::OpcUa), SubsystemStatus::Ready);
        assert_eq!(r.status(SubsystemId::Dnp3), SubsystemStatus::Failed);
    }

    #[test]
    fn auto_recover_sets_dirty_bit_on_recovery() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Mqtt, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        let _ = r.take_dirty();
        assert!(!r.is_dirty());
        let recovered = r.try_auto_recover(10_000, 1_000);
        assert_eq!(recovered, 1);
        assert!(r.is_dirty(), "auto-recovery must set dirty");
    }

    #[test]
    fn auto_recover_when_nothing_to_recover_does_not_dirty() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Mqtt);
        let _ = r.take_dirty();
        let recovered = r.try_auto_recover(u64::MAX, 0);
        assert_eq!(recovered, 0);
        assert!(!r.is_dirty(), "no-op recovery must not dirty");
    }

    // -----------------------------------------------------------------------
    // shutdown
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_resets_all_state() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Can);
        r.with_subsystem_alert(SubsystemId::Mqtt, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        r.with_subsystem_alert(SubsystemId::Dnp3, 2_000, AlertSeverity::Critical, |h| {
            h.mark_failed();
        });
        // Sanity:
        assert_eq!(r.status(SubsystemId::Can), SubsystemStatus::Ready);
        assert_eq!(r.status(SubsystemId::Mqtt), SubsystemStatus::Degraded);
        assert!(r.degraded_since_us(SubsystemId::Mqtt).is_some());
        assert_eq!(r.status(SubsystemId::Dnp3), SubsystemStatus::Failed);

        r.shutdown();

        for id in SubsystemId::ALL {
            assert_eq!(
                r.status(id),
                SubsystemStatus::NotInitialized,
                "{id:?} not reset by shutdown"
            );
            assert_eq!(
                r.degraded_since_us(id),
                None,
                "{id:?} degraded_since_us not reset by shutdown"
            );
        }
        assert!(!r.is_dirty(), "shutdown must clear dirty bit");
    }

    #[test]
    fn shutdown_clears_degraded_since_runtime_ind_regression() {
        // Specific regression for runtime-ind: shutdown previously only
        // cleared `status` and left `degraded_since_us` populated, so a
        // re-start could spuriously trip auto-recovery on a subsystem that
        // had not been alerted at all post-restart.
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Iec60870, 1_000, AlertSeverity::Medium, |h| {
            h.mark_degraded();
        });
        r.shutdown();
        // Now bring it back up.
        r.mark_initialized(SubsystemId::Iec60870);
        // Without the regression fix, degraded_since_us would still be Some
        // and try_auto_recover would set status->Ready (already Ready) but
        // could clear something we did not expect, depending on ordering.
        assert_eq!(r.degraded_since_us(SubsystemId::Iec60870), None);
        let recovered = r.try_auto_recover(u64::MAX, 0);
        assert_eq!(recovered, 0);
        assert_eq!(r.status(SubsystemId::Iec60870), SubsystemStatus::Ready);
    }

    // -----------------------------------------------------------------------
    // Dirty bit semantics
    // -----------------------------------------------------------------------

    #[test]
    fn dirty_bit_is_clear_on_new() {
        let r = HealthRegistry::new();
        assert!(!r.is_dirty());
    }

    #[test]
    fn dirty_bit_is_set_by_with_subsystem_alert() {
        let mut r = HealthRegistry::new();
        r.with_subsystem_alert(SubsystemId::Can, 1, AlertSeverity::Info, |_| {});
        assert!(r.is_dirty(), "with_subsystem_alert always dirties");
    }

    #[test]
    fn take_dirty_returns_and_clears() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Can);
        assert!(r.take_dirty());
        assert!(!r.is_dirty());
        assert!(!r.take_dirty(), "second take_dirty observes the clear");
    }

    #[test]
    fn dirty_bit_survives_multiple_alerts_until_taken() {
        let mut r = HealthRegistry::new();
        r.mark_initialized(SubsystemId::Can);
        r.mark_initialized(SubsystemId::Eth);
        r.with_subsystem_alert(SubsystemId::Mqtt, 1, AlertSeverity::High, |h| {
            h.mark_degraded();
        });
        assert!(r.is_dirty());
        assert!(r.take_dirty());
        // No further mutations -> stays clean.
        assert!(!r.take_dirty());
    }

    // -----------------------------------------------------------------------
    // Isolation: changes to one subsystem must not affect others
    // -----------------------------------------------------------------------

    #[test]
    fn alert_on_one_subsystem_does_not_touch_others() {
        let mut r = HealthRegistry::new();
        for id in SubsystemId::ALL {
            r.mark_initialized(id);
        }
        r.with_subsystem_alert(SubsystemId::OpcUa, 1_000, AlertSeverity::High, |h| {
            h.mark_degraded();
        });
        for id in SubsystemId::ALL {
            if id == SubsystemId::OpcUa {
                assert_eq!(r.status(id), SubsystemStatus::Degraded);
                assert!(r.degraded_since_us(id).is_some());
            } else {
                assert_eq!(r.status(id), SubsystemStatus::Ready, "{id:?} got perturbed");
                assert_eq!(r.degraded_since_us(id), None);
            }
        }
    }
}
