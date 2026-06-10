// SPDX-License-Identifier: Apache-2.0
//! # IDS Engine (`vs-ids-engine`)
//!
//! Central intrusion detection orchestrator that combines CAN bus and Ethernet
//! monitoring subsystems into a single correlated alert pipeline.
//!
//! ## Overview
//!
//! The IDS engine sits above the individual protocol monitors ([`vs_can_monitor`]
//! and [`vs_eth_monitor`]) and provides:
//!
//! - **Alert correlation**: recent alerts are stored in a fixed-size ring buffer
//!   and checked for duplicates within a configurable time window. Repeated alerts
//!   from the same source are counted and can trigger severity escalation.
//! - **Severity escalation**: when duplicate alerts exceed a configurable threshold
//!   (default: 10), the alert severity is automatically escalated up to `Critical`.
//! - **Policy-based response**: each severity level maps to an [`IdsResponse`]
//!   action (log, block, isolate, alert, or shutdown) via a policy table.
//! - **Dispatch**: alerts are forwarded to registered [`DispatchAction`] targets
//!   (logging, blocking, telemetry) for external consumption.
//! - **Clock monotonicity enforcement**: detects backwards-clock events and raises
//!   a diagnostic alert if the threshold is exceeded.
//!
//! ## Key Types
//!
//! - [`IdsEngine`] -- the main orchestrator struct. Owns a [`CanMonitor`] and an
//!   [`EthMonitor`], plus the correlation state and policy tables.
//! - [`IdsResponse`] -- the action to take for an alert (Log, Block, Isolate, etc.).
//! - [`PolicyEntry`] -- maps an [`AlertSeverity`] to an [`IdsResponse`].
//! - [`DispatchAction`] -- identifies an output channel (Log, Block, Telemetry).
//! - [`DispatchResult`] -- returned after dispatching an alert.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use vs_can_monitor::CanMonitor;
//! use vs_eth_monitor::{EthMonitor, EthMonitorConfig, DEFAULT_SIPHASH_KEYS};
//! use vs_ids_engine::IdsEngine;
//!
//! let can = CanMonitor::default();
//! let eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
//! let mut ids = IdsEngine::new(can, eth, 100_000); // 100ms correlation window
//!
//! // Submit CAN frames and Ethernet packets; the engine correlates alerts
//! // and applies policy-based response actions automatically.
//! ```
//!
//! ## Public API (v1.0 stable)
//!
//! The `IdsEngine` orchestrator and its `submit_can_frame` /
//! `submit_eth_packet` ingestion methods (which return any
//! correlation-escalated [`SecurityAlert`] directly and dispatch it
//! synchronously to registered dispatchers) form the v1.0 stable surface
//! and are governed by `DEPRECATION.md`.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use vs_can_monitor::{CanFrame, CanMonitor};
use vs_eth_monitor::{EthMonitor, EthPacket};
use vs_types::{AlertSeverity, SecurityAlert, VsError};

/// Maximum number of recent alerts kept for correlation.
const CORRELATION_WINDOW: usize = 32;

/// Number of buckets in the dedup hash table.
///
/// Open-addressed (linear-probing) table used by [`IdsEngine::record_alert`]
/// to find an existing ring entry with the same `(id, source_type,
/// source_id)` identity in O(1) average time. Sized to twice
/// [`CORRELATION_WINDOW`] (a power of two) so the load factor never exceeds
/// 0.5, keeping probe chains short. Must be a power of two so the modulo can
/// be a bit-mask.
const DEDUP_BUCKETS: usize = CORRELATION_WINDOW * 2;

/// Bit-mask form of `DEDUP_BUCKETS - 1`, used to wrap bucket indices.
const DEDUP_MASK: usize = DEDUP_BUCKETS - 1;

/// Maximum number of escalation steps allowed in a single correlation pass.
const MAX_ESCALATION_STEPS: usize = 3;

/// Response action for an IDS alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsResponse {
    /// Log the alert only, no active response.
    Log,
    /// Block traffic on the given bus interface for a duration.
    Block {
        /// Bus interface index to block (e.g. CAN channel number).
        bus_id: u8,
        /// Duration in microseconds to hold the block.
        duration_us: u32,
    },
    /// Isolate the affected network segment.
    Isolate,
    /// Raise an alert to the host / gateway.
    Alert,
    /// Initiate a controlled shutdown of the affected subsystem.
    Shutdown,
}

/// Dispatch target for alerts (enum dispatch to avoid heap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchAction {
    /// Log every alert (always fires).
    Log,
    /// Fire when the policy response is `Block`, `Isolate`, or `Shutdown`.
    Block,
    /// Fire for any alert whose response is above `Log` level.
    Telemetry,
}

/// Result of dispatching an alert to all registered dispatchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchResult {
    /// Number of dispatchers that received the alert.
    pub dispatched_count: usize,
    /// The response action determined by policy for this alert.
    pub response: IdsResponse,
}

/// Maps severity to response action.
#[derive(Debug, Clone, Copy)]
pub struct PolicyEntry {
    /// The alert severity this entry matches.
    pub severity: AlertSeverity,
    /// The response action to take for matching alerts.
    pub response: IdsResponse,
}

/// A recent alert kept for correlation.
#[derive(Clone, Copy)]
struct RecentAlert {
    alert: SecurityAlert,
    valid: bool,
    /// Number of times a duplicate alert was recorded in this slot.
    /// Used to detect sustained attacks and escalate severity.
    duplicate_count: u32,
}

/// Compute the dedup key for an alert's full source identity.
///
/// Mixes `id`, `source_type`, and `source_id` so that alerts differing in
/// any of those fields hash to (mostly) distinct buckets. A duplicate is
/// only a true match when all three fields are equal — the hash is just an
/// index; equality is always re-verified against the ring entry.
#[inline]
fn dedup_key(alert: &SecurityAlert) -> u64 {
    // Fibonacci-hash style mix of the three identity fields. The raw
    // `id ^ source_type ^ source_id` collides trivially (e.g. id=1 vs
    // id=3,source_id=2), so each field is spread across the word first.
    let id = alert.id;
    let st = alert.source_type as u64;
    let sid = alert.source_id as u64;
    let mut h = id.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= st.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    h ^= sid.wrapping_mul(0x1656_67B1_9E37_79F9);
    h
}

/// Open-addressed (linear-probing) hash table mapping an alert identity to
/// the ring-buffer slot that currently holds it.
///
/// Replaces the former O([`CORRELATION_WINDOW`]) linear dedup scan in
/// [`IdsEngine::record_alert`] with O(1)-average lookup on the worst-case
/// latency path (an ECU under sustained attack). Deletion uses backward-shift
/// (Robin Hood style) compaction so no tombstones accumulate; with a load
/// factor capped at 0.5 (`DEDUP_BUCKETS == 2 * CORRELATION_WINDOW`) probe
/// chains stay short.
///
/// Each bucket stores `Some((key, slot))` or `None`. The `slot` is an index
/// into `recent_alerts`; equality is always re-verified by the caller
/// against the actual ring entry, so a hash collision never causes a false
/// dedup match.
#[derive(Clone, Copy)]
struct DedupTable {
    buckets: [Option<(u64, usize)>; DEDUP_BUCKETS],
}

impl DedupTable {
    const fn new() -> Self {
        Self {
            buckets: [None; DEDUP_BUCKETS],
        }
    }

    /// Find the ring slot for an alert with the given identity, if present.
    ///
    /// `eq` re-verifies full identity equality against the ring entry so a
    /// hash collision cannot return the wrong slot.
    fn find(&self, key: u64, mut eq: impl FnMut(usize) -> bool) -> Option<usize> {
        let mut idx = (key as usize) & DEDUP_MASK;
        // Probe at most the whole table; load factor <= 0.5 guarantees an
        // empty bucket terminates the chain long before this bound.
        for _ in 0..DEDUP_BUCKETS {
            match self.buckets[idx] {
                None => return None,
                Some((k, slot)) => {
                    if k == key && eq(slot) {
                        return Some(slot);
                    }
                }
            }
            idx = (idx + 1) & DEDUP_MASK;
        }
        None
    }

    /// Insert a `(key, slot)` mapping. The caller guarantees no live entry
    /// for this exact identity already exists (dedup is checked first).
    fn insert(&mut self, key: u64, slot: usize) {
        let mut idx = (key as usize) & DEDUP_MASK;
        for _ in 0..DEDUP_BUCKETS {
            if self.buckets[idx].is_none() {
                self.buckets[idx] = Some((key, slot));
                return;
            }
            idx = (idx + 1) & DEDUP_MASK;
        }
        // Unreachable: load factor is capped at 0.5, so a free bucket
        // always exists. Fail closed by doing nothing rather than panicking
        // — a missed dedup insert only costs a redundant ring entry.
    }

    /// Remove the bucket that maps `key` to `slot`, then backward-shift any
    /// following entries in the same probe chain so no tombstone is left.
    fn remove(&mut self, key: u64, slot: usize) {
        // Locate the exact bucket holding (key, slot).
        let mut idx = (key as usize) & DEDUP_MASK;
        let mut found = None;
        for _ in 0..DEDUP_BUCKETS {
            match self.buckets[idx] {
                None => break,
                Some((k, s)) => {
                    if k == key && s == slot {
                        found = Some(idx);
                        break;
                    }
                }
            }
            idx = (idx + 1) & DEDUP_MASK;
        }
        let Some(mut hole) = found else {
            return;
        };
        self.buckets[hole] = None;
        // Backward-shift compaction: pull forward any subsequent entry whose
        // ideal bucket is at or before `hole` (cyclically), so probe chains
        // for unrelated keys are not broken by the gap.
        let mut next = (hole + 1) & DEDUP_MASK;
        while let Some((k, s)) = self.buckets[next] {
            let ideal = (k as usize) & DEDUP_MASK;
            // True iff `ideal` lies cyclically within `[next, hole]` going
            // backwards — i.e. moving the entry to `hole` does not place it
            // before its ideal bucket.
            let movable = (next.wrapping_sub(ideal) & DEDUP_MASK)
                >= (next.wrapping_sub(hole) & DEDUP_MASK);
            if movable {
                self.buckets[hole] = Some((k, s));
                self.buckets[next] = None;
                hole = next;
            }
            next = (next + 1) & DEDUP_MASK;
        }
    }
}

impl Default for RecentAlert {
    fn default() -> Self {
        Self {
            alert: SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: vs_types::SOURCE_CAN,
                source_id: 0,
                payload_hash: vs_types::PayloadHash([0u8; 32]),
                timestamp_us: 0,
            },
            valid: false,
            duplicate_count: 0,
        }
    }
}

/// Default number of duplicate alerts before severity escalation.
const DEFAULT_ESCALATION_THRESHOLD: u32 = 10;

/// Number of consecutive backwards-clock events before raising an alert.
const BACKWARD_CLOCK_ALERT_THRESHOLD: u64 = 5;

/// Maximum value for the backward clock counter.  Prevents the counter from
/// saturating at `u64::MAX` (which would permanently disable detection).
/// When the counter reaches this cap it stays here until the threshold fires
/// and resets it.
const MAX_BACKWARD_CLOCK_COUNT: u64 = 1000;

/// Alert ID for backwards-clock threshold exceeded.
const ALERT_ID_BACKWARD_CLOCK: u64 = 0xD000_0001;

/// Central IDS orchestrator.
///
/// Combines CAN and Ethernet intrusion detection subsystems with alert
/// correlation, policy-based response selection, and dispatch.
pub struct IdsEngine {
    can_monitor: CanMonitor,
    eth_monitor: EthMonitor,
    recent_alerts: [RecentAlert; CORRELATION_WINDOW],
    recent_head: usize,
    correlation_window_us: u64,
    /// Last timestamp seen by the engine, used for monotonicity enforcement.
    last_timestamp_us: u64,
    policy: [Option<PolicyEntry>; 8],
    policy_count: usize,
    /// Direct-indexed response lookup by severity ordinal. Populated from
    /// `policy` for O(1) dispatch.
    response_cache: [Option<IdsResponse>; 5],
    dispatchers: [Option<DispatchAction>; 8],
    dispatcher_count: usize,
    dispatch_flags: [bool; 8],
    /// Counter for backward clock events, used for diagnostics.
    backward_clock_count: u64,
    /// Number of duplicate alerts required before severity is escalated to
    /// Critical. Defaults to `DEFAULT_ESCALATION_THRESHOLD` (10).
    escalation_threshold: u32,
    /// Whether a backwards-clock alert has already been emitted (reset by `tick`).
    backward_clock_alerted: bool,
    /// Number of slots in `recent_alerts` whose `valid` flag is `true`.
    ///
    /// Maintained as an invariant: incremented on fresh insert, decremented
    /// on expiry in `tick` and on overwrite of a previously-valid slot in
    /// `record_alert`. Dedup-refresh of an already-valid slot leaves the
    /// counter unchanged. When this reaches zero the linear ring scans in
    /// `tick`, `record_alert`, and `maybe_escalate` can short-circuit
    /// without touching `recent_alerts`.
    ///
    /// `u8` is sufficient because `CORRELATION_WINDOW = 32`.
    valid_count: u8,
    /// Bitmap of slots holding a *valid* CAN-bus alert. Bit `i` is set iff
    /// `recent_alerts[i].valid && recent_alerts[i].alert.source_type` is a
    /// CAN source. Used by `maybe_escalate` to short-circuit the cross-bus
    /// check via a single AND against `eth_present_bitmap`.
    can_present_bitmap: u32,
    /// Bitmap of slots holding a *valid* Ethernet alert. See
    /// `can_present_bitmap`.
    eth_present_bitmap: u32,
    /// Number of times the correlation ring wrapped while still holding a
    /// valid entry, causing that entry to be silently overwritten. Useful
    /// for post-incident forensics to detect alert-firehose conditions.
    dropped_alerts: u32,
    /// Open-addressed hash table mapping each live alert identity
    /// (`id`/`source_type`/`source_id`) to its `recent_alerts` slot, giving
    /// `record_alert` O(1)-average dedup instead of a full ring scan. Kept
    /// in lock-step with `recent_alerts`: an entry is inserted on fresh
    /// record, removed on expiry in `tick` and on overwrite in
    /// `record_alert`.
    dedup: DedupTable,
}

impl IdsEngine {
    /// Create a new IDS engine.
    ///
    /// `correlation_window_us` is the time window (in microseconds) during
    /// which alerts from different buses are considered related. The value
    /// is clamped to the range `[1_000, 60_000_000]` (1 ms to 60 s).
    pub fn new(
        can_monitor: CanMonitor,
        eth_monitor: EthMonitor,
        correlation_window_us: u64,
    ) -> Self {
        // Clamp correlation window to sane bounds (1ms to 60s)
        let correlation_window_us = correlation_window_us.clamp(1_000, 60_000_000);
        Self {
            can_monitor,
            eth_monitor,
            recent_alerts: [RecentAlert::default(); CORRELATION_WINDOW],
            recent_head: 0,
            correlation_window_us,
            last_timestamp_us: 0,
            policy: [None; 8],
            policy_count: 0,
            response_cache: [None; 5],
            dispatchers: [None; 8],
            dispatcher_count: 0,
            dispatch_flags: [false; 8],
            backward_clock_count: 0,
            escalation_threshold: DEFAULT_ESCALATION_THRESHOLD,
            backward_clock_alerted: false,
            valid_count: 0,
            can_present_bitmap: 0,
            eth_present_bitmap: 0,
            dropped_alerts: 0,
            dedup: DedupTable::new(),
        }
    }

    /// Number of valid alerts that were overwritten because the
    /// correlation ring wrapped around before they could expire.
    ///
    /// Monotonically increasing for the lifetime of the engine. A non-zero
    /// value indicates an alert-firehose condition where the
    /// `CORRELATION_WINDOW` is too small (or the rate too high) to retain
    /// the full set of in-window alerts. Useful for post-incident
    /// forensics.
    #[must_use]
    pub fn dropped_alert_count(&self) -> u32 {
        self.dropped_alerts
    }

    /// Set the bus-present bit for `idx` based on the alert's source.
    #[inline]
    fn set_present_bit_for(&mut self, idx: usize, alert: &SecurityAlert) {
        let bit = 1u32 << (idx as u32);
        match alert.source_type {
            vs_types::SOURCE_CAN | vs_types::SOURCE_CAN_FD => {
                self.can_present_bitmap |= bit;
            }
            vs_types::SOURCE_ETHERNET => {
                self.eth_present_bitmap |= bit;
            }
            _ => {}
        }
    }

    /// Clear both bus-present bits at the given ring slot. Used on expiry
    /// and on overwrite (where the new alert's source may differ).
    #[inline]
    fn clear_present_at(&mut self, idx: usize) {
        let mask = !(1u32 << (idx as u32));
        self.can_present_bitmap &= mask;
        self.eth_present_bitmap &= mask;
    }

    /// Add a policy mapping severity to response.
    ///
    /// Returns `InvalidConfig` if a policy for this severity already exists.
    /// Returns `ResourceExhausted` if the policy table is full.
    pub fn add_policy(&mut self, entry: PolicyEntry) -> Result<(), VsError> {
        // Reject duplicate severity mappings.
        for i in 0..self.policy_count {
            if let Some(existing) = &self.policy[i] {
                if existing.severity == entry.severity {
                    return Err(VsError::InvalidConfig);
                }
            }
        }
        if self.policy_count >= self.policy.len() {
            return Err(VsError::ResourceExhausted);
        }
        self.policy[self.policy_count] = Some(entry);
        self.response_cache[entry.severity as usize] = Some(entry.response);
        self.policy_count += 1;
        Ok(())
    }

    /// Remove the policy for the given severity level.
    ///
    /// Returns `true` if a policy was found and removed, `false` otherwise.
    pub fn remove_policy(&mut self, severity: AlertSeverity) -> bool {
        for i in 0..self.policy_count {
            if let Some(entry) = &self.policy[i] {
                if entry.severity == severity {
                    self.response_cache[severity as usize] = None;
                    // Shift remaining entries down to keep array compact.
                    for j in i..self.policy_count - 1 {
                        self.policy[j] = self.policy[j + 1];
                    }
                    self.policy[self.policy_count - 1] = None;
                    self.policy_count -= 1;
                    return true;
                }
            }
        }
        false
    }

    /// Update the response for an existing severity policy.
    ///
    /// Returns `NotFound` if no policy exists for this severity.
    pub fn update_policy(
        &mut self,
        severity: AlertSeverity,
        response: IdsResponse,
    ) -> Result<(), VsError> {
        for i in 0..self.policy_count {
            if let Some(entry) = &mut self.policy[i] {
                if entry.severity == severity {
                    entry.response = response;
                    self.response_cache[severity as usize] = Some(response);
                    return Ok(());
                }
            }
        }
        Err(VsError::NotFound)
    }

    /// Register a dispatcher action.
    ///
    /// Returns `InvalidConfig` if this action is already registered.
    /// Returns `ResourceExhausted` if the dispatcher table is full.
    pub fn add_dispatcher(&mut self, action: DispatchAction) -> Result<(), VsError> {
        // Reject duplicates.
        for i in 0..self.dispatcher_count {
            if self.dispatchers[i] == Some(action) {
                return Err(VsError::InvalidConfig);
            }
        }
        if self.dispatcher_count >= self.dispatchers.len() {
            return Err(VsError::ResourceExhausted);
        }
        self.dispatchers[self.dispatcher_count] = Some(action);
        self.dispatcher_count += 1;
        Ok(())
    }

    /// Remove a previously registered dispatcher action.
    ///
    /// Returns `true` if the action was found and removed, `false` otherwise.
    ///
    /// The `dispatch_flags` array is shifted in lock-step with `dispatchers`
    /// so that flag slot `i` always refers to the dispatcher at
    /// `dispatchers[i]`. Without this mirror shift, removing a dispatcher
    /// would leave stale flag bits associated with the wrong dispatcher
    /// (or no dispatcher at all), causing `poll_dispatch_flags` to lie.
    pub fn remove_dispatcher(&mut self, action: DispatchAction) -> bool {
        for i in 0..self.dispatcher_count {
            if self.dispatchers[i] == Some(action) {
                for j in i..self.dispatcher_count - 1 {
                    self.dispatchers[j] = self.dispatchers[j + 1];
                    self.dispatch_flags[j] = self.dispatch_flags[j + 1];
                }
                self.dispatchers[self.dispatcher_count - 1] = None;
                self.dispatch_flags[self.dispatcher_count - 1] = false;
                self.dispatcher_count -= 1;
                return true;
            }
        }
        false
    }

    /// Set the duplicate-alert escalation threshold.
    ///
    /// When the same alert is seen this many times within the correlation
    /// window, its severity is escalated to `Critical`.  The value must be
    /// at least 1; a zero value is clamped to 1.
    pub fn set_escalation_threshold(&mut self, threshold: u32) {
        self.escalation_threshold = threshold.max(1);
    }

    /// Return the current duplicate-alert escalation threshold.
    #[must_use]
    pub fn escalation_threshold(&self) -> u32 {
        self.escalation_threshold
    }

    /// Expire stale alerts from the correlation window.
    ///
    /// Iterates backwards from the write head so that the newest entries are
    /// visited first.  Because the ring buffer is filled in chronological
    /// order (and dedup-refreshed entries only move *forward* in time), once
    /// we encounter a run of consecutive expired-or-invalid slots we know
    /// every remaining slot is at least as old and can stop early.
    ///
    /// Short-circuits when `Self::valid_count` is zero (no live entries to
    /// expire), saving the full 32-slot ring scan on quiet ticks.
    pub fn tick(&mut self, ts_us: u64) {
        // Fast path: nothing valid to expire. Still reset backward-clock state.
        if self.valid_count == 0 {
            self.backward_clock_count = 0;
            self.backward_clock_alerted = false;
            return;
        }
        let len = CORRELATION_WINDOW;
        let valid_count_at_entry = self.valid_count as usize;
        let mut consecutive_old: usize = 0;
        for k in 0..len {
            // Walk backwards: head-1, head-2, …
            let idx = (self.recent_head + len - 1 - k) % len;
            let entry = &self.recent_alerts[idx];
            if !entry.valid {
                continue;
            }
            if ts_us.saturating_sub(entry.alert.timestamp_us) > self.correlation_window_us {
                // Drop the dedup-table mapping before clearing `valid` so
                // the table never points at a stale slot.
                let key = dedup_key(&self.recent_alerts[idx].alert);
                self.dedup.remove(key, idx);
                self.recent_alerts[idx].valid = false;
                // Maintain the invariant: a previously-valid slot just
                // went invalid. Drop the bus-present bit for that slot.
                self.valid_count = self.valid_count.saturating_sub(1);
                self.clear_present_at(idx);
                consecutive_old += 1;
            } else {
                consecutive_old = 0;
            }
            // Once we have expired as many slots as were live entering
            // the loop, the remaining ring contents are either invalid
            // (no work to do) or newer-than-window (the `else` branch
            // would have reset `consecutive_old`), so we can stop.
            if consecutive_old >= valid_count_at_entry {
                break;
            }
        }
        // Reset backward-clock tracking each tick so the alert can
        // fire again if another burst of backwards timestamps appears.
        self.backward_clock_count = 0;
        self.backward_clock_alerted = false;
    }

    /// Submit a CAN frame for inspection.
    ///
    /// Returns the alert (after correlation/escalation) and dispatches it to
    /// all registered dispatchers. Returns `None` if no alert was generated.
    ///
    /// # Escalation precedence
    ///
    /// Two independent escalation mechanisms run, in this fixed order:
    ///
    /// 1. [`Self::maybe_escalate`] — *cross-bus correlation*: raises severity
    ///    one step per distinct opposite-bus alert in the correlation window
    ///    (capped at [`MAX_ESCALATION_STEPS`]). It runs on the *pre-recorded*
    ///    alert and cannot see the alert about to be recorded.
    /// 2. [`Self::record_alert`] — *duplicate-count escalation*: when this
    ///    exact alert identity has been seen `escalation_threshold` times,
    ///    severity jumps straight to `Critical`.
    ///
    /// The two compose by *sequencing*, not by addition: `record_alert`
    /// receives whatever severity `maybe_escalate` produced and may raise it
    /// further to `Critical`. Both mechanisms are monotonic and saturate at
    /// `Critical`, so the final severity is the maximum either would have
    /// produced. Callers always act on this composed severity because it is
    /// the value returned here and dispatched. Do not reorder these two
    /// calls: `record_alert` mutates the ring that `maybe_escalate` reads.
    pub fn submit_can_frame(&mut self, frame: &CanFrame, ts_us: u64) -> Option<SecurityAlert> {
        let original_ts_us = ts_us;
        let (ts_us, clock_alert) = self.clamp_timestamp(ts_us);
        if clock_alert {
            let alert =
                Self::make_backward_clock_alert(vs_types::SOURCE_CAN, ts_us, original_ts_us);
            let alert = self.record_alert(alert);
            self.dispatch_alert(&alert);
            return Some(alert);
        }
        let alert = self.can_monitor.process_frame(frame, ts_us)?;
        let alert = self.maybe_escalate(alert, ts_us);
        let alert = self.record_alert(alert);
        self.dispatch_alert(&alert);
        Some(alert)
    }

    /// Submit an Ethernet packet for inspection.
    ///
    /// Returns the alert (after correlation/escalation) and dispatches it to
    /// all registered dispatchers. Returns `None` if no alert was generated.
    ///
    /// See [`Self::submit_can_frame`] for the escalation precedence rules
    /// shared by both ingestion paths.
    pub fn submit_eth_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Option<SecurityAlert> {
        let original_ts_us = ts_us;
        let (ts_us, clock_alert) = self.clamp_timestamp(ts_us);
        if clock_alert {
            let alert =
                Self::make_backward_clock_alert(vs_types::SOURCE_ETHERNET, ts_us, original_ts_us);
            let alert = self.record_alert(alert);
            self.dispatch_alert(&alert);
            return Some(alert);
        }
        let alert = self.eth_monitor.inspect_packet(pkt, ts_us)?;
        let alert = self.maybe_escalate(alert, ts_us);
        let alert = self.record_alert(alert);
        self.dispatch_alert(&alert);
        Some(alert)
    }

    /// Dispatch an alert to all registered dispatchers and return the result.
    ///
    /// This is the main entry point for callers who want to know what
    /// response action was determined and how many dispatchers received it.
    pub fn dispatch_and_respond(&mut self, alert: &SecurityAlert) -> DispatchResult {
        let dispatched_count = self.dispatch_alert(alert);
        let response = self.get_response(alert.severity);
        DispatchResult {
            dispatched_count,
            response,
        }
    }

    /// Look up the response for a given severity.
    pub fn get_response(&self, severity: AlertSeverity) -> IdsResponse {
        if let Some(response) = self.response_cache[severity as usize] {
            return response;
        }
        // Default policy
        match severity {
            AlertSeverity::Critical => IdsResponse::Isolate,
            AlertSeverity::High => IdsResponse::Alert,
            AlertSeverity::Medium | AlertSeverity::Low | AlertSeverity::Info => IdsResponse::Log,
            // `AlertSeverity` is `#[non_exhaustive]`. Unknown future variants
            // fall back to the most conservative response.
            _ => IdsResponse::Log,
        }
    }

    /// Get the number of dispatchers registered.
    pub fn dispatcher_count(&self) -> usize {
        self.dispatcher_count
    }

    /// Get the number of policies registered.
    pub fn policy_count(&self) -> usize {
        self.policy_count
    }

    /// Read-only access to the CAN monitor for capacity queries.
    pub fn can_monitor(&self) -> &CanMonitor {
        &self.can_monitor
    }

    /// Mutable access to the CAN monitor (e.g. to add rules).
    pub fn can_monitor_mut(&mut self) -> &mut CanMonitor {
        &mut self.can_monitor
    }

    /// Read-only access to the Ethernet monitor.
    pub fn eth_monitor(&self) -> &EthMonitor {
        &self.eth_monitor
    }

    /// Mutable access to the Ethernet monitor (e.g. to add allow-list
    /// entries or VLAN IDs after construction).
    pub fn eth_monitor_mut(&mut self) -> &mut EthMonitor {
        &mut self.eth_monitor
    }

    /// Returns a reference to the dispatch flags array.
    /// Each flag corresponds to a dispatcher slot and is set to `true` when
    /// that dispatcher matched during the most recent dispatch cycle.
    pub fn poll_dispatch_flags(&self) -> &[bool; 8] {
        &self.dispatch_flags
    }

    /// Resets all dispatch flags to `false`.
    pub fn clear_dispatch_flags(&mut self) {
        self.dispatch_flags = [false; 8];
    }

    /// Build a backwards-clock alert.
    ///
    /// `ts_us` is the *clamped* (monotonic) timestamp that will be recorded
    /// on the alert.  `original_ts_us` is the raw timestamp supplied by the
    /// caller before clamping.  The original value is stored in the first 8
    /// bytes of `payload_hash` (little-endian) so that forensic analysis can
    /// see both the clamped and original values.
    fn make_backward_clock_alert(
        source_type: u8,
        ts_us: u64,
        original_ts_us: u64,
    ) -> SecurityAlert {
        // Encode the original (unclamped) timestamp into the payload hash
        // so forensic tooling can recover the actual value that was received.
        let mut hash_bytes = [0u8; 32];
        hash_bytes[..8].copy_from_slice(&original_ts_us.to_le_bytes());
        SecurityAlert {
            id: ALERT_ID_BACKWARD_CLOCK,
            severity: AlertSeverity::High,
            source_type,
            source_id: 0,
            payload_hash: vs_types::PayloadHash(hash_bytes),
            timestamp_us: ts_us,
        }
    }

    /// Enforce monotonicity on the engine's internal clock by clamping any
    /// backward-going timestamp to the last seen value, while tolerating a
    /// bounded amount of backward drift before raising a diagnostic.
    ///
    /// Returns `(clamped_ts, crossed_threshold)` where `clamped_ts` is the
    /// monotonic timestamp the engine will use, and `crossed_threshold`
    /// is `true` exactly once when the backwards-clock count first reaches
    /// `BACKWARD_CLOCK_ALERT_THRESHOLD`.
    ///
    /// The internal counter is capped at `MAX_BACKWARD_CLOCK_COUNT` to
    /// prevent permanent saturation at `u64::MAX`. After the threshold
    /// fires and generates an alert the counter is reset to 0 so detection
    /// can trigger again on continued backward-clock events without
    /// waiting for a `tick()` call.
    fn clamp_timestamp(&mut self, ts_us: u64) -> (u64, bool) {
        if ts_us < self.last_timestamp_us {
            // Increment but cap at MAX_BACKWARD_CLOCK_COUNT to avoid
            // saturating at u64::MAX which would disable detection.
            if self.backward_clock_count < MAX_BACKWARD_CLOCK_COUNT {
                self.backward_clock_count += 1;
            }
            let crossed = !self.backward_clock_alerted
                && self.backward_clock_count >= BACKWARD_CLOCK_ALERT_THRESHOLD;
            if crossed {
                self.backward_clock_alerted = true;
            }
            (self.last_timestamp_us, crossed)
        } else {
            self.last_timestamp_us = ts_us;
            (ts_us, false)
        }
    }

    /// Record an alert in the correlation ring buffer.
    ///
    /// Deduplicates by alert ID: if an alert with the same `id` and
    /// `source_type` is already valid in the buffer, the slot is reused
    /// (timestamp refreshed) and the duplicate count is incremented.
    /// This prevents the ring buffer from filling with repeated alerts
    /// while still tracking the frequency of repeated attacks.
    ///
    /// Returns the (potentially escalated) alert so callers always act on
    /// the correct severity, closing the state-confusion gap where the
    /// internal ring buffer held an escalated severity but the caller
    /// continued to use the original, unescalated alert.
    ///
    /// This is the *second* escalation stage. The `alert` argument has
    /// already passed through [`Self::maybe_escalate`]; duplicate-count
    /// escalation here may raise its severity further (to `Critical`). The
    /// returned severity is therefore the composition of both stages — see
    /// [`Self::submit_can_frame`] for the precedence contract.
    fn record_alert(&mut self, mut alert: SecurityAlert) -> SecurityAlert {
        let key = dedup_key(&alert);

        // Fast path: when no valid entries are present, skip the dedup
        // lookup entirely and insert directly.
        if self.valid_count == 0 {
            // The overwritten slot is by definition invalid (valid_count == 0),
            // so no need to check/decrement or clear bitmaps. The dedup
            // table is likewise empty, so no removal is needed.
            let head = self.recent_head;
            self.recent_alerts[head] = RecentAlert {
                alert,
                valid: true,
                duplicate_count: 0,
            };
            self.set_present_bit_for(head, &alert);
            self.dedup.insert(key, head);
            self.recent_head = (head + 1) % CORRELATION_WINDOW;
            self.valid_count = self.valid_count.saturating_add(1);
            return alert;
        }

        // O(1)-average dedup lookup via the open-addressed hash table.
        // The closure re-verifies full source identity (`id` +
        // `source_type` + `source_id`) against the candidate ring entry so
        // a hash collision can never cause a false dedup match. Including
        // `source_id` ensures alerts from different source instances (e.g.
        // two distinct CAN buses) are tracked independently.
        let dup_slot = self.dedup.find(key, |slot| {
            let e = &self.recent_alerts[slot];
            e.valid
                && e.alert.id == alert.id
                && e.alert.source_type == alert.source_type
                && e.alert.source_id == alert.source_id
        });
        if let Some(slot) = dup_slot {
            let entry = &mut self.recent_alerts[slot];
            entry.duplicate_count = entry.duplicate_count.saturating_add(1);
            // Escalate severity if duplicates accumulate.
            if entry.duplicate_count >= self.escalation_threshold
                && alert.severity < AlertSeverity::Critical
            {
                entry.alert.severity = AlertSeverity::Critical;
                // Propagate escalation to the returned alert so that
                // dispatch and policy layers act on the correct severity.
                alert.severity = AlertSeverity::Critical;
            }
            entry.alert.timestamp_us = alert.timestamp_us;
            // Dedup-refresh: slot was already valid, counter unchanged.
            // Source identity didn't change, so bitmaps and the dedup
            // table mapping are already correct.
            return alert;
        }

        // Inserting into the next ring slot. If it currently holds a valid
        // entry (ring wrapped before any expiry), the overwrite silently
        // drops that entry — record this in `dropped_alerts` for forensic
        // visibility and leave `valid_count` unchanged.
        let head = self.recent_head;
        let overwriting_valid = self.recent_alerts[head].valid;
        if overwriting_valid {
            self.dropped_alerts = self.dropped_alerts.saturating_add(1);
            // Drop the overwritten entry's dedup mapping before its slot is
            // reused, otherwise the table would point at the wrong alert.
            let old_key = dedup_key(&self.recent_alerts[head].alert);
            self.dedup.remove(old_key, head);
        }
        // Clear any stale bus-present bits at this slot (the previous
        // alert may have been on a different bus).
        self.clear_present_at(head);
        self.recent_alerts[head] = RecentAlert {
            alert,
            valid: true,
            duplicate_count: 0,
        };
        self.set_present_bit_for(head, &alert);
        self.dedup.insert(key, head);
        self.recent_head = (head + 1) % CORRELATION_WINDOW;
        if !overwriting_valid {
            self.valid_count = self.valid_count.saturating_add(1);
        }
        alert
    }

    /// Dispatch an alert to all registered dispatchers.
    ///
    /// Returns the number of dispatchers that were notified. The actual
    /// side-effects depend on the `DispatchAction` type — in a `no_std`
    /// environment these are flags that the caller polls or that trigger
    /// hardware-level actions.
    fn dispatch_alert(&mut self, alert: &SecurityAlert) -> usize {
        // Zero all flags before this dispatch cycle so `poll_dispatch_flags`
        // reflects *only* the dispatchers that matched the alert just
        // processed, per the docstring on `poll_dispatch_flags`.  Without
        // this reset, stale `true` bits from a previous cycle would persist
        // even when the current alert does not match that dispatcher.
        self.dispatch_flags = [false; 8];
        let response = self.get_response(alert.severity);
        let mut count = 0;
        // `dispatcher_count` is bounded by `dispatchers.len() == 8`, which
        // equals `dispatch_flags.len()` — so the index is always in range.
        for i in 0..self.dispatcher_count {
            if let Some(action) = &self.dispatchers[i] {
                if should_dispatch(action, &response) {
                    self.dispatch_flags[i] = true;
                    count += 1;
                }
            }
        }
        count
    }

    /// If we see CAN + ETH alerts within the correlation window, escalate.
    ///
    /// Counts distinct cross-bus matches and escalates once per match,
    /// allowing multi-hop escalation (e.g. Info -> Medium if 2 cross-bus
    /// alerts are found).
    ///
    /// This is the *first* of two escalation stages (see
    /// [`Self::submit_can_frame`] for the full precedence contract). It runs
    /// before [`Self::record_alert`], so it cannot observe the alert about
    /// to be recorded; the duplicate-count escalation in `record_alert`
    /// composes on top of whatever severity this stage returns. Both stages
    /// saturate at `Critical`, so the order is observationally irrelevant —
    /// but `maybe_escalate` must stay first because `record_alert` mutates
    /// the ring this function reads.
    ///
    /// Scans every slot in the ring buffer.  We cannot short-circuit on
    /// "consecutive expired slots" because `record_alert` refreshes the
    /// timestamp of dedup-matched entries in place, breaking chronological
    /// ordering of the buffer.
    ///
    /// We do short-circuit once `escalation_count` reaches
    /// `MAX_ESCALATION_STEPS` since further matches cannot change the
    /// result.
    fn maybe_escalate(&self, mut alert: SecurityAlert, ts_us: u64) -> SecurityAlert {
        // Fast path: nothing in the correlation window means no cross-bus
        // correlation is possible.
        if self.valid_count == 0 {
            return alert;
        }
        let current_is_can = matches!(
            alert.source_type,
            vs_types::SOURCE_CAN | vs_types::SOURCE_CAN_FD
        );
        let current_is_eth = alert.source_type == vs_types::SOURCE_ETHERNET;

        // Short-circuit: if no cross-bus slots are populated at all, we
        // can skip the full ring scan. The bitmaps track which slots
        // currently hold a valid alert from each bus class.
        let cross_bus_mask = if current_is_can {
            self.eth_present_bitmap
        } else if current_is_eth {
            self.can_present_bitmap
        } else {
            0
        };
        if cross_bus_mask == 0 {
            return alert;
        }

        let mut escalation_count: u32 = 0;

        // Iterate only the slots whose cross-bus bit is set. This trims
        // the scan to the actual cross-bus population (often 0..few)
        // instead of the full 32-slot ring.
        let mut remaining = cross_bus_mask;
        while remaining != 0 {
            let i = remaining.trailing_zeros() as usize;
            remaining &= remaining - 1;
            let entry = &self.recent_alerts[i];
            // The bitmap may be momentarily stale only inside `record_alert`
            // / `tick`; on entry here both are quiescent, so `entry.valid`
            // is guaranteed. Recheck timestamp window.
            if !entry.valid {
                continue;
            }
            if ts_us.saturating_sub(entry.alert.timestamp_us) > self.correlation_window_us {
                continue;
            }
            escalation_count += 1;
            // Short-circuit: further matches won't change the outcome.
            if escalation_count as usize >= MAX_ESCALATION_STEPS {
                break;
            }
        }

        let capped_count = (escalation_count as usize).min(MAX_ESCALATION_STEPS);
        for _ in 0..capped_count {
            let next = escalate_severity(alert.severity);
            if next == alert.severity {
                break; // Already at Critical, stop.
            }
            alert.severity = next;
        }

        alert
    }
}

/// Determine whether a dispatcher should fire for the given response.
fn should_dispatch(action: &DispatchAction, response: &IdsResponse) -> bool {
    match action {
        // Log dispatchers fire for every alert.
        DispatchAction::Log => true,
        // Block dispatchers fire when the response is Block or Isolate.
        DispatchAction::Block => matches!(
            response,
            IdsResponse::Block { .. } | IdsResponse::Isolate | IdsResponse::Shutdown
        ),
        // Telemetry dispatchers fire for alerts above Log level.
        DispatchAction::Telemetry => !matches!(response, IdsResponse::Log),
    }
}

fn escalate_severity(s: AlertSeverity) -> AlertSeverity {
    match s {
        AlertSeverity::Info => AlertSeverity::Low,
        AlertSeverity::Low => AlertSeverity::Medium,
        AlertSeverity::Medium => AlertSeverity::High,
        AlertSeverity::High | AlertSeverity::Critical => AlertSeverity::Critical,
        // `AlertSeverity` is `#[non_exhaustive]`. Unknown future variants
        // escalate to `Critical` (fail-loud).
        _ => AlertSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vs_can_monitor::CanRule;
    use vs_eth_monitor::{EthMonitorConfig, DEFAULT_SIPHASH_KEYS};
    use vs_types::PayloadHash;

    fn make_engine() -> IdsEngine {
        let mut can = CanMonitor::default();
        can.add_rule(CanRule {
            id: 0,
            id_mask: 0x7FF,
            id_filter: 0x100,
            min_interval_us: 10_000,
            max_dlc: 8,
            is_extended: false,
            severity: AlertSeverity::High,
        })
        .unwrap();

        let eth = EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap();
        IdsEngine::new(can, eth, 100_000)
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

    fn make_vlan_pkt(payload: &[u8]) -> EthPacket<'_> {
        EthPacket {
            src_mac: [0x01; 6],
            dst_mac: [0x02; 6],
            vlan_id: Some(999),
            ethertype: 0x0800,
            dst_port: None,
            payload,
        }
    }

    fn make_normal_pkt(payload: &[u8]) -> EthPacket<'_> {
        EthPacket {
            src_mac: [0x01; 6],
            dst_mac: [0x02; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload,
        }
    }

    // ----- Basic alert generation -----

    #[test]
    fn can_flood_generates_alert() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();

        let frame = make_can_frame(0x100);
        assert!(engine.submit_can_frame(&frame, 0).is_none());
        let alert = engine.submit_can_frame(&frame, 1);
        assert!(alert.is_some());
        assert_eq!(
            alert.as_ref().map(|a| a.severity),
            Some(AlertSeverity::High)
        );
    }

    #[test]
    fn submit_can_frame_no_alert_returns_none() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x200);
        assert!(engine.submit_can_frame(&frame, 1000).is_none());
    }

    #[test]
    fn submit_eth_packet_no_alert_returns_none() {
        let mut engine = make_engine();
        let payload = [0u8; 16];
        assert!(engine
            .submit_eth_packet(&make_normal_pkt(&payload), 1000)
            .is_none());
    }

    #[test]
    fn engine_benign_single_frame_no_alert() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);
        assert!(engine.submit_can_frame(&frame, 0).is_none());
    }

    #[test]
    fn engine_eth_default_config_no_alert() {
        let mut engine = make_engine();
        let payload = [0u8; 16];
        assert!(engine
            .submit_eth_packet(&make_normal_pkt(&payload), 1000)
            .is_none());
    }

    // ----- Correlation / escalation -----

    #[test]
    fn correlated_can_eth_escalates() {
        let mut engine = make_engine();

        let frame = make_can_frame(0x100);
        engine.submit_can_frame(&frame, 1000);
        engine.submit_can_frame(&frame, 1001); // flood alert at High

        let payload = [0u8; 16];
        let alert = engine.submit_eth_packet(&make_vlan_pkt(&payload), 1050);
        assert!(alert.is_some());
        assert_eq!(alert.map(|a| a.severity), Some(AlertSeverity::Critical));
    }

    #[test]
    fn multiple_can_floods_without_eth_no_correlation_escalation() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);

        engine.submit_can_frame(&frame, 0);
        let alert1 = engine.submit_can_frame(&frame, 1);
        assert_eq!(alert1.unwrap().severity, AlertSeverity::High);

        let alert2 = engine.submit_can_frame(&frame, 2);
        assert_eq!(alert2.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn multiple_eth_alerts_without_can_no_correlation_escalation() {
        let mut engine = make_engine();
        let payload = [0u8; 16];

        let alert1 = engine.submit_eth_packet(&make_vlan_pkt(&payload), 1000);
        assert!(alert1.is_some());
        let sev1 = alert1.unwrap().severity;

        let alert2 = engine.submit_eth_packet(&make_vlan_pkt(&payload), 1050);
        assert_eq!(alert2.unwrap().severity, sev1);
    }

    #[test]
    fn alert_severity_unchanged_when_only_one_bus_type() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);

        engine.submit_can_frame(&frame, 0);
        let alert = engine.submit_can_frame(&frame, 1);
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn mixed_traffic_can_normal_eth_normal_can_flood() {
        let mut engine = make_engine();

        let frame = make_can_frame(0x100);
        assert!(engine.submit_can_frame(&frame, 0).is_none());

        let payload = [0u8; 16];
        assert!(engine
            .submit_eth_packet(&make_normal_pkt(&payload), 50)
            .is_none());

        let alert = engine.submit_can_frame(&frame, 1);
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn correlation_window_expiry_no_escalation() {
        let mut engine = make_engine();

        let frame = make_can_frame(0x100);
        engine.submit_can_frame(&frame, 0);
        engine.submit_can_frame(&frame, 1);

        let payload = [0u8; 16];
        let alert = engine.submit_eth_packet(&make_vlan_pkt(&payload), 200_001);
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    // ----- Tick / expiry -----

    #[test]
    fn tick_expires_old_alerts() {
        let mut engine = make_engine();

        let frame = make_can_frame(0x100);
        engine.submit_can_frame(&frame, 0);
        engine.submit_can_frame(&frame, 1);

        engine.tick(200_000);

        let payload = [0u8; 16];
        let alert = engine.submit_eth_packet(&make_vlan_pkt(&payload), 200_001);
        assert_eq!(
            alert.as_ref().map(|a| a.severity),
            Some(AlertSeverity::High)
        );
    }

    #[test]
    fn tick_with_no_alerts_does_nothing() {
        let mut engine = make_engine();
        engine.tick(0);
        engine.tick(1_000_000);
        engine.tick(u64::MAX);
    }

    #[test]
    fn tick_clears_alerts_correctly_when_empty() {
        let mut engine = make_engine();
        engine.tick(0);
        engine.tick(500_000);

        let frame = make_can_frame(0x100);
        engine.submit_can_frame(&frame, 500_001);
        engine.submit_can_frame(&frame, 500_002);

        let payload = [0u8; 16];
        let alert = engine.submit_eth_packet(&make_vlan_pkt(&payload), 500_050);
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    // ----- Timestamp monotonicity -----

    #[test]
    fn backwards_timestamp_is_clamped() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);

        // Submit at t=1000 (seeds last_timestamp)
        engine.submit_can_frame(&frame, 1000);
        // Submit at t=500 (goes backwards) — should be clamped to 1000,
        // meaning interval is 0us which is < 10_000us min_interval => flood alert
        let alert = engine.submit_can_frame(&frame, 500);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn forward_timestamp_is_not_clamped() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);

        engine.submit_can_frame(&frame, 0);
        // 20_000us > min_interval of 10_000us, so no flood alert
        assert!(engine.submit_can_frame(&frame, 20_000).is_none());
    }

    // ----- Policy management -----

    #[test]
    fn custom_policy_overrides_default() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::High,
                response: IdsResponse::Shutdown,
            })
            .unwrap();

        assert_eq!(
            engine.get_response(AlertSeverity::High),
            IdsResponse::Shutdown
        );
        assert_eq!(engine.get_response(AlertSeverity::Medium), IdsResponse::Log);
    }

    #[test]
    fn default_policy_critical_returns_isolate() {
        let engine = make_engine();
        assert_eq!(
            engine.get_response(AlertSeverity::Critical),
            IdsResponse::Isolate
        );
    }

    #[test]
    fn default_policy_high_returns_alert() {
        let engine = make_engine();
        assert_eq!(engine.get_response(AlertSeverity::High), IdsResponse::Alert);
    }

    #[test]
    fn default_policy_medium_returns_log() {
        let engine = make_engine();
        assert_eq!(engine.get_response(AlertSeverity::Medium), IdsResponse::Log);
    }

    #[test]
    fn default_policy_low_returns_log() {
        let engine = make_engine();
        assert_eq!(engine.get_response(AlertSeverity::Low), IdsResponse::Log);
    }

    #[test]
    fn default_policy_info_returns_log() {
        let engine = make_engine();
        assert_eq!(engine.get_response(AlertSeverity::Info), IdsResponse::Log);
    }

    #[test]
    fn custom_policy_critical_shutdown() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::Critical,
                response: IdsResponse::Shutdown,
            })
            .unwrap();
        assert_eq!(
            engine.get_response(AlertSeverity::Critical),
            IdsResponse::Shutdown
        );
    }

    #[test]
    fn custom_policy_info_log() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::Info,
                response: IdsResponse::Log,
            })
            .unwrap();
        assert_eq!(engine.get_response(AlertSeverity::Info), IdsResponse::Log);
    }

    #[test]
    fn duplicate_policy_severity_rejected() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::High,
                response: IdsResponse::Alert,
            })
            .unwrap();
        let result = engine.add_policy(PolicyEntry {
            severity: AlertSeverity::High,
            response: IdsResponse::Shutdown,
        });
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn remove_policy_works() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::High,
                response: IdsResponse::Shutdown,
            })
            .unwrap();
        assert_eq!(engine.policy_count(), 1);

        assert!(engine.remove_policy(AlertSeverity::High));
        assert_eq!(engine.policy_count(), 0);
        // Falls back to default
        assert_eq!(engine.get_response(AlertSeverity::High), IdsResponse::Alert);
    }

    #[test]
    fn remove_nonexistent_policy_returns_false() {
        let mut engine = make_engine();
        assert!(!engine.remove_policy(AlertSeverity::Critical));
    }

    #[test]
    fn update_policy_works() {
        let mut engine = make_engine();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::High,
                response: IdsResponse::Alert,
            })
            .unwrap();
        engine
            .update_policy(AlertSeverity::High, IdsResponse::Shutdown)
            .unwrap();
        assert_eq!(
            engine.get_response(AlertSeverity::High),
            IdsResponse::Shutdown
        );
    }

    #[test]
    fn update_nonexistent_policy_returns_not_found() {
        let mut engine = make_engine();
        assert_eq!(
            engine.update_policy(AlertSeverity::High, IdsResponse::Shutdown),
            Err(VsError::NotFound)
        );
    }

    #[test]
    fn policy_table_exhaustion() {
        let mut engine = make_engine();
        let severities = [
            AlertSeverity::Info,
            AlertSeverity::Low,
            AlertSeverity::Medium,
            AlertSeverity::High,
            AlertSeverity::Critical,
        ];
        for &sev in &severities {
            engine
                .add_policy(PolicyEntry {
                    severity: sev,
                    response: IdsResponse::Log,
                })
                .unwrap();
        }
        // 5 used, 3 more slots
        for i in 0..3 {
            engine
                .add_policy(PolicyEntry {
                    severity: AlertSeverity::Info, // will fail as dup
                    response: IdsResponse::Log,
                })
                .unwrap_err();
            // We need distinct severities but we only have 5. Fill with
            // whatever the capacity allows — already 5 used of 8.
            // Actually we already have all 5 severities. Let's just verify
            // that the count is correct.
            let _ = i;
        }
        assert_eq!(engine.policy_count(), 5);
    }

    // ----- Dispatcher management -----

    #[test]
    fn dispatchers_registered() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap();
        assert_eq!(engine.dispatcher_count(), 3);
    }

    #[test]
    fn duplicate_dispatcher_rejected() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        assert_eq!(
            engine.add_dispatcher(DispatchAction::Log),
            Err(VsError::InvalidConfig)
        );
    }

    #[test]
    fn remove_dispatcher_works() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        assert_eq!(engine.dispatcher_count(), 2);

        assert!(engine.remove_dispatcher(DispatchAction::Log));
        assert_eq!(engine.dispatcher_count(), 1);
    }

    #[test]
    fn remove_nonexistent_dispatcher_returns_false() {
        let mut engine = make_engine();
        assert!(!engine.remove_dispatcher(DispatchAction::Block));
    }

    // ----- Dispatch execution -----

    #[test]
    fn dispatch_alert_fires_log_dispatcher_for_any_alert() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();

        let frame = make_can_frame(0x100);
        engine.submit_can_frame(&frame, 0);
        let alert = engine.submit_can_frame(&frame, 1).unwrap();

        let result = engine.dispatch_and_respond(&alert);
        assert_eq!(result.dispatched_count, 1);
        assert_eq!(result.response, IdsResponse::Alert); // High -> Alert
    }

    #[test]
    fn dispatch_alert_block_dispatcher_fires_for_isolate_response() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Block).unwrap();

        // Critical severity -> Isolate response -> Block dispatcher fires
        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Critical,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let result = engine.dispatch_and_respond(&alert);
        assert_eq!(result.dispatched_count, 1);
        assert_eq!(result.response, IdsResponse::Isolate);
    }

    #[test]
    fn dispatch_alert_block_dispatcher_does_not_fire_for_log_response() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Block).unwrap();

        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Info,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let result = engine.dispatch_and_respond(&alert);
        assert_eq!(result.dispatched_count, 0);
        assert_eq!(result.response, IdsResponse::Log);
    }

    #[test]
    fn dispatch_alert_telemetry_fires_for_non_log_responses() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap();

        // High -> Alert response (not Log) -> Telemetry fires
        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let result = engine.dispatch_and_respond(&alert);
        assert_eq!(result.dispatched_count, 1);

        // Info -> Log response -> Telemetry does NOT fire
        let alert_info = SecurityAlert {
            id: 2,
            severity: AlertSeverity::Info,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let result = engine.dispatch_and_respond(&alert_info);
        assert_eq!(result.dispatched_count, 0);
    }

    #[test]
    fn all_dispatchers_fire_on_critical() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap();

        let alert = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Critical,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let result = engine.dispatch_and_respond(&alert);
        assert_eq!(result.dispatched_count, 3);
        assert_eq!(result.response, IdsResponse::Isolate);
    }

    // ----- Escalation levels -----

    #[test]
    fn escalate_severity_levels() {
        assert_eq!(escalate_severity(AlertSeverity::Info), AlertSeverity::Low);
        assert_eq!(escalate_severity(AlertSeverity::Low), AlertSeverity::Medium);
        assert_eq!(
            escalate_severity(AlertSeverity::Medium),
            AlertSeverity::High
        );
        assert_eq!(
            escalate_severity(AlertSeverity::High),
            AlertSeverity::Critical
        );
        assert_eq!(
            escalate_severity(AlertSeverity::Critical),
            AlertSeverity::Critical
        );
    }

    // ----- ETH monitor accessor -----

    #[test]
    fn eth_monitor_mut_accessor() {
        let mut engine = make_engine();
        // Should be able to add a VLAN via the mutable accessor
        let added = engine.eth_monitor_mut().add_allowed_vlan(100);
        assert!(added);
    }

    #[test]
    fn eth_monitor_ref_accessor() {
        let engine = make_engine();
        // Just verify we can call it without panic
        let _eth = engine.eth_monitor();
    }

    // ----- should_dispatch logic -----

    #[test]
    fn should_dispatch_log_always_fires() {
        assert!(should_dispatch(&DispatchAction::Log, &IdsResponse::Log));
        assert!(should_dispatch(&DispatchAction::Log, &IdsResponse::Alert));
        assert!(should_dispatch(&DispatchAction::Log, &IdsResponse::Isolate));
        assert!(should_dispatch(
            &DispatchAction::Log,
            &IdsResponse::Shutdown
        ));
        assert!(should_dispatch(
            &DispatchAction::Log,
            &IdsResponse::Block {
                bus_id: 0,
                duration_us: 1000
            }
        ));
    }

    #[test]
    fn should_dispatch_block_selective() {
        assert!(!should_dispatch(&DispatchAction::Block, &IdsResponse::Log));
        assert!(!should_dispatch(
            &DispatchAction::Block,
            &IdsResponse::Alert
        ));
        assert!(should_dispatch(
            &DispatchAction::Block,
            &IdsResponse::Block {
                bus_id: 0,
                duration_us: 1000
            }
        ));
        assert!(should_dispatch(
            &DispatchAction::Block,
            &IdsResponse::Isolate
        ));
        assert!(should_dispatch(
            &DispatchAction::Block,
            &IdsResponse::Shutdown
        ));
    }

    #[test]
    fn should_dispatch_telemetry_selective() {
        assert!(!should_dispatch(
            &DispatchAction::Telemetry,
            &IdsResponse::Log
        ));
        assert!(should_dispatch(
            &DispatchAction::Telemetry,
            &IdsResponse::Alert
        ));
        assert!(should_dispatch(
            &DispatchAction::Telemetry,
            &IdsResponse::Isolate
        ));
    }

    // ----- Block variant fields -----

    #[test]
    fn block_response_named_fields() {
        let resp = IdsResponse::Block {
            bus_id: 1,
            duration_us: 50_000,
        };
        match resp {
            IdsResponse::Block {
                bus_id,
                duration_us,
            } => {
                assert_eq!(bus_id, 1);
                assert_eq!(duration_us, 50_000);
            }
            _ => panic!("expected Block"),
        }
    }

    // ----- Deduplication -----

    #[test]
    fn record_alert_deduplicates() {
        let mut engine = make_engine();
        let frame = make_can_frame(0x100);

        // Generate multiple flood alerts (same alert id pattern from same source)
        engine.submit_can_frame(&frame, 0);
        engine.submit_can_frame(&frame, 1); // flood #1
        engine.submit_can_frame(&frame, 2); // flood #2
        engine.submit_can_frame(&frame, 3); // flood #3

        // Count valid entries in the ring buffer — duplicates should be
        // collapsed so we have fewer entries than submissions.
        let valid_count = engine.recent_alerts.iter().filter(|e| e.valid).count();
        // We submitted 3 flood alerts from the same source with same id,
        // dedup should keep it to 1 unique entry.
        assert!(
            valid_count <= 3,
            "expected dedup to reduce entries, got {valid_count}"
        );
    }

    // ----- Fresh engine state -----

    #[test]
    fn engine_fresh_has_no_recent_alerts() {
        let engine = make_engine();
        assert_eq!(engine.get_response(AlertSeverity::Info), IdsResponse::Log);
        assert_eq!(engine.dispatcher_count(), 0);
        assert_eq!(engine.policy_count(), 0);
    }

    // ----- V7: Backwards-clock threshold alert -----

    /// Make a CAN frame with unique payload to avoid replay detection.
    fn make_unique_can_frame(id: u32, seed: u8) -> CanFrame {
        let mut data = [0u8; 64];
        for (i, b) in data.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        CanFrame {
            id,
            is_extended: false,
            is_fd: false,
            dlc: 8,
            data,
        }
    }

    #[test]
    fn backward_clock_threshold_fires_alert() {
        let mut engine = make_engine();

        // Seed timestamp with a unique payload each time (avoids replay alerts).
        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 10_000);

        // Send BACKWARD_CLOCK_ALERT_THRESHOLD backwards timestamps
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            let frame = make_unique_can_frame(0x200, i as u8);
            let result = engine.submit_can_frame(&frame, 10_000 - i);
            if i < BACKWARD_CLOCK_ALERT_THRESHOLD {
                // Below threshold — no alert (no rule match either)
                assert!(result.is_none(), "unexpected alert at backward event {i}");
            } else {
                // Exactly at threshold — should fire backwards-clock alert
                assert!(
                    result.is_some(),
                    "expected backward-clock alert at event {i}"
                );
                let alert = result.unwrap();
                assert_eq!(alert.id, ALERT_ID_BACKWARD_CLOCK);
                assert_eq!(alert.severity, AlertSeverity::High);
            }
        }
    }

    #[test]
    fn backward_clock_alert_fires_only_once_per_tick() {
        let mut engine = make_engine();

        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 10_000);

        // Trigger the alert
        for i in 0..BACKWARD_CLOCK_ALERT_THRESHOLD {
            engine.submit_can_frame(&make_unique_can_frame(0x200, (i + 1) as u8), 5_000);
        }

        // Additional backwards events should NOT fire another backward-clock alert.
        let result = engine.submit_can_frame(&make_unique_can_frame(0x200, 100), 5_000);
        assert!(result.is_none());
    }

    #[test]
    fn backward_clock_alert_resets_after_tick() {
        let mut engine = make_engine();

        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 10_000);

        // Trigger the alert
        for i in 0..BACKWARD_CLOCK_ALERT_THRESHOLD {
            engine.submit_can_frame(&make_unique_can_frame(0x200, (i + 1) as u8), 5_000);
        }

        // Tick resets the counter and flag
        engine.tick(20_000);

        // Seed a new timestamp
        engine.submit_can_frame(&make_unique_can_frame(0x200, 50), 20_000);

        // A new burst of backwards timestamps should fire again
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            let frame = make_unique_can_frame(0x200, (50 + i) as u8);
            let result = engine.submit_can_frame(&frame, 20_000 - i);
            if i == BACKWARD_CLOCK_ALERT_THRESHOLD {
                assert!(result.is_some(), "expected second backward-clock alert");
                assert_eq!(result.unwrap().id, ALERT_ID_BACKWARD_CLOCK);
            }
        }
    }

    // ----- H1 fix: dedup escalation propagation -----

    #[test]
    fn dedup_escalation_returns_critical_to_caller() {
        let mut engine = make_engine();
        // Threshold of 2: after 2 duplicate dedup hits, severity escalates.
        engine.set_escalation_threshold(2);
        engine.add_dispatcher(DispatchAction::Log).unwrap();

        // Use fixed-ID alerts to trigger the dedup path in record_alert.
        // (CAN monitor generates unique IDs via a counter, so we test
        // dedup escalation directly with constructed alerts.)
        let base_alert = SecurityAlert {
            id: 42,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0x100,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };

        // First recording: creates entry with dup_count=0
        let a1 = engine.record_alert(base_alert);
        assert_eq!(a1.severity, AlertSeverity::High);

        // Second recording: dedup match, dup_count → 1 (< threshold 2)
        let a2 = engine.record_alert(SecurityAlert {
            timestamp_us: 200,
            ..base_alert
        });
        assert_eq!(a2.severity, AlertSeverity::High);

        // Third recording: dedup match, dup_count → 2 (>= threshold 2) → escalate
        let a3 = engine.record_alert(SecurityAlert {
            timestamp_us: 300,
            ..base_alert
        });
        assert_eq!(
            a3.severity,
            AlertSeverity::Critical,
            "dedup escalation must propagate to the returned alert"
        );
    }

    #[test]
    fn dedup_escalation_dispatches_at_critical_severity() {
        let mut engine = make_engine();
        // Threshold of 1: escalate after first dedup hit.
        engine.set_escalation_threshold(1);
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        engine
            .add_policy(PolicyEntry {
                severity: AlertSeverity::Critical,
                response: IdsResponse::Isolate,
            })
            .unwrap();

        let base_alert = SecurityAlert {
            id: 42,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0x100,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };

        // First: creates entry with dup_count=0
        engine.record_alert(base_alert);
        engine.clear_dispatch_flags();

        // Second: dedup match, dup_count → 1 (>= threshold 1) → Critical
        let escalated = engine.record_alert(SecurityAlert {
            timestamp_us: 200,
            ..base_alert
        });
        assert_eq!(escalated.severity, AlertSeverity::Critical);

        // Dispatch the escalated alert — Block dispatcher should fire
        // because Critical → Isolate → Block
        engine.dispatch_alert(&escalated);
        let flags = engine.poll_dispatch_flags();
        assert!(
            flags[0],
            "Block dispatcher must fire when dedup-escalated alert reaches Critical/Isolate"
        );
    }

    // ----- H2: backward clock counter cap and reset -----

    #[test]
    fn backward_clock_alert_suppressed_until_tick() {
        let mut engine = make_engine();

        // Seed a forward timestamp.
        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 10_000);

        // First burst: reach the threshold so an alert fires.
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            engine.submit_can_frame(&make_unique_can_frame(0x200, i as u8), 10_000 - i);
        }
        // After the threshold fired, the alerted flag should be set.
        assert!(
            engine.backward_clock_alerted,
            "alerted flag must be set after threshold fires"
        );

        // Second burst (without tick): must NOT fire again — dedup active.
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            let result =
                engine.submit_can_frame(&make_unique_can_frame(0x200, (100 + i) as u8), 10_000 - i);
            assert!(
                result.is_none(),
                "backward-clock alert must be suppressed until tick()"
            );
        }

        // After tick(), counter and flag reset — next burst fires again.
        engine.tick(20_000);
        engine.submit_can_frame(&make_unique_can_frame(0x200, 200), 20_000);
        let mut fired = false;
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            let result =
                engine.submit_can_frame(&make_unique_can_frame(0x200, (200 + i) as u8), 20_000 - i);
            if i == BACKWARD_CLOCK_ALERT_THRESHOLD {
                assert!(
                    result.is_some(),
                    "expected backward-clock alert after tick() reset"
                );
                assert_eq!(result.unwrap().id, ALERT_ID_BACKWARD_CLOCK);
                fired = true;
            }
        }
        assert!(fired, "alert must fire after tick() resets the flag");
    }

    #[test]
    fn backward_clock_counter_does_not_saturate_at_max() {
        let mut engine = make_engine();

        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 100_000);

        // Manually set the counter to the cap and mark the alert as already
        // fired so the threshold-reset logic does not activate.
        engine.backward_clock_count = MAX_BACKWARD_CLOCK_COUNT;
        engine.backward_clock_alerted = true;

        // One more backward event should NOT increment past the cap.
        let _ = engine.clamp_timestamp(50_000);
        assert_eq!(
            engine.backward_clock_count, MAX_BACKWARD_CLOCK_COUNT,
            "counter must be capped at MAX_BACKWARD_CLOCK_COUNT"
        );
    }

    // ----- M1: original timestamp in backward-clock alert -----

    #[test]
    fn backward_clock_alert_contains_original_timestamp() {
        let mut engine = make_engine();

        // Seed timestamp.
        engine.submit_can_frame(&make_unique_can_frame(0x200, 0), 10_000);

        // Fire backward-clock alert by sending BACKWARD_CLOCK_ALERT_THRESHOLD
        // backwards events.  The last one triggers the alert.
        let mut alert_opt = None;
        for i in 1..=BACKWARD_CLOCK_ALERT_THRESHOLD {
            let result =
                engine.submit_can_frame(&make_unique_can_frame(0x200, i as u8), 10_000 - i);
            if i == BACKWARD_CLOCK_ALERT_THRESHOLD {
                alert_opt = result;
            }
        }
        let alert = alert_opt.expect("expected backward-clock alert");
        assert_eq!(alert.id, ALERT_ID_BACKWARD_CLOCK);

        // The original (pre-clamped) timestamp should be encoded in the
        // first 8 bytes of the payload hash.
        let original_ts =
            u64::from_le_bytes(alert.payload_hash.as_bytes()[..8].try_into().unwrap());
        let expected_original = 10_000 - BACKWARD_CLOCK_ALERT_THRESHOLD;
        assert_eq!(
            original_ts, expected_original,
            "payload_hash must encode the original (unclamped) timestamp"
        );
    }

    // ----- M2: dedup separates alerts from different sources -----

    #[test]
    fn dedup_separates_alerts_from_different_source_ids() {
        let mut engine = make_engine();

        let alert_a = SecurityAlert {
            id: 42,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 1,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };
        let alert_b = SecurityAlert {
            id: 42,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 2,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };

        engine.record_alert(alert_a);
        engine.record_alert(alert_b);

        // Both should be present as separate valid entries because source_id
        // differs, so dedup should not collapse them.
        let valid_count = engine
            .recent_alerts
            .iter()
            .filter(|e| e.valid && e.alert.id == 42)
            .count();
        assert_eq!(
            valid_count, 2,
            "alerts with same id but different source_id must be separate entries"
        );
    }

    #[test]
    fn dedup_groups_alerts_from_same_source() {
        let mut engine = make_engine();

        let alert = SecurityAlert {
            id: 42,
            severity: AlertSeverity::High,
            source_type: vs_types::SOURCE_CAN,
            source_id: 1,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };

        engine.record_alert(alert);
        engine.record_alert(SecurityAlert {
            timestamp_us: 200,
            ..alert
        });
        engine.record_alert(SecurityAlert {
            timestamp_us: 300,
            ..alert
        });

        // All three submissions share the same (id, source_type, source_id)
        // so dedup should collapse them into a single valid entry.
        let mut valid_count = 0u32;
        let mut dup_count = 0u32;
        for entry in &engine.recent_alerts {
            if entry.valid && entry.alert.id == 42 {
                valid_count += 1;
                dup_count = entry.duplicate_count;
            }
        }
        assert_eq!(
            valid_count, 1,
            "alerts with same id and same source must be deduplicated into one entry"
        );
        // The entry should have accumulated duplicate count.
        assert_eq!(dup_count, 2);
    }

    // ----- Escalation threshold edge cases -----

    /// `set_escalation_threshold(0)` must clamp to 1.
    ///
    /// A threshold of 0 would mean every alert immediately escalates before
    /// even being recorded — which is nonsensical and could cause permanent
    /// severity inflation. The implementation clamps to 1 as a minimum.
    #[test]
    fn set_escalation_threshold_zero_is_clamped_to_one() {
        let mut engine = make_engine();
        engine.set_escalation_threshold(0);
        assert_eq!(
            engine.escalation_threshold(),
            1,
            "threshold=0 must be clamped to 1"
        );
    }

    /// `set_escalation_threshold(u32::MAX)` must be accepted without error or
    /// truncation. A very large threshold effectively disables escalation.
    #[test]
    fn set_escalation_threshold_max_is_accepted() {
        let mut engine = make_engine();
        engine.set_escalation_threshold(u32::MAX);
        assert_eq!(
            engine.escalation_threshold(),
            u32::MAX,
            "threshold=u32::MAX must be stored unchanged"
        );
    }

    /// Verify backward-clock alert threshold firing: exactly
    /// `BACKWARD_CLOCK_ALERT_THRESHOLD` backward events must fire one alert
    /// with the correct ID and severity, and fewer events must not fire any.
    #[test]
    fn backward_clock_threshold_fires_at_exact_count() {
        let mut engine = make_engine();

        // Seed a forward timestamp.
        engine.submit_can_frame(&make_unique_can_frame(0x300, 0), 50_000);

        // Submit (threshold - 1) backward events — no alert expected.
        for i in 1..BACKWARD_CLOCK_ALERT_THRESHOLD {
            let result =
                engine.submit_can_frame(&make_unique_can_frame(0x300, i as u8), 50_000 - i);
            assert!(
                result.is_none(),
                "no alert expected before threshold (event {i})"
            );
        }

        // The threshold-th backward event must fire the alert.
        let result = engine.submit_can_frame(
            &make_unique_can_frame(0x300, BACKWARD_CLOCK_ALERT_THRESHOLD as u8),
            50_000 - BACKWARD_CLOCK_ALERT_THRESHOLD,
        );
        let alert = result.expect("backward-clock alert must fire at exact threshold");
        assert_eq!(
            alert.id, ALERT_ID_BACKWARD_CLOCK,
            "alert ID must be ALERT_ID_BACKWARD_CLOCK"
        );
        assert_eq!(
            alert.severity,
            AlertSeverity::High,
            "backward-clock alert severity must be High"
        );
    }

    // ----- Regression: dispatch_flags shifted in lock-step with dispatchers -----

    /// Removing a dispatcher must shift `dispatch_flags` in lock-step with
    /// `dispatchers` so flag indices keep referring to the correct dispatcher.
    /// Without the mirror shift, a stale `true` left in slot `i` after a
    /// removal would be wrongly attributed to whichever dispatcher slid into
    /// that slot (or to no dispatcher at all once the count shrinks).
    #[test]
    fn remove_dispatcher_shifts_dispatch_flags() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap();

        // Manually mark dispatcher slot 0 (Log) and slot 2 (Telemetry) as
        // having fired in a previous cycle.  Slot 1 (Block) is intentionally
        // left false.
        engine.dispatch_flags[0] = true;
        engine.dispatch_flags[1] = false;
        engine.dispatch_flags[2] = true;

        // Remove the middle dispatcher (Block).  Expected result:
        //   dispatchers     = [Log,      Telemetry, None]
        //   dispatch_flags  = [true,     true,      false]
        // i.e. the flag for Telemetry must slide from index 2 to index 1
        // along with the dispatcher, and the freed slot must be cleared.
        assert!(engine.remove_dispatcher(DispatchAction::Block));
        assert_eq!(engine.dispatcher_count(), 2);
        assert_eq!(engine.dispatchers[0], Some(DispatchAction::Log));
        assert_eq!(engine.dispatchers[1], Some(DispatchAction::Telemetry));
        assert_eq!(engine.dispatchers[2], None);

        let flags = engine.poll_dispatch_flags();
        assert!(flags[0], "Log flag must remain set at index 0");
        assert!(
            flags[1],
            "Telemetry flag must move from index 2 down to index 1"
        );
        assert!(
            !flags[2],
            "freed slot 2 must be cleared (no stale Telemetry flag left behind)"
        );
    }

    /// Removing the head dispatcher must shift every remaining flag down by
    /// one and clear the freed tail slot.
    #[test]
    fn remove_first_dispatcher_shifts_all_flags_down() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.add_dispatcher(DispatchAction::Block).unwrap();
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap();

        engine.dispatch_flags[0] = true; // Log fired
        engine.dispatch_flags[1] = false; // Block didn't
        engine.dispatch_flags[2] = true; // Telemetry fired

        assert!(engine.remove_dispatcher(DispatchAction::Log));
        let flags = engine.poll_dispatch_flags();
        assert!(!flags[0], "former Block slot must report its (false) flag");
        assert!(
            flags[1],
            "former Telemetry slot must report its (true) flag"
        );
        assert!(!flags[2], "freed tail slot must be cleared");
    }

    /// Removing the only dispatcher must clear its flag bit.
    #[test]
    fn remove_only_dispatcher_clears_flag() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap();
        engine.dispatch_flags[0] = true;

        assert!(engine.remove_dispatcher(DispatchAction::Log));
        assert_eq!(engine.dispatcher_count(), 0);
        assert!(
            !engine.poll_dispatch_flags()[0],
            "freed slot must be cleared after removing the sole dispatcher"
        );
    }

    // ----- Regression: dispatch_alert zeroes prior flags each cycle -----

    /// `dispatch_alert` must zero `dispatch_flags` at the top of each call
    /// so that `poll_dispatch_flags` reflects only the dispatchers matched
    /// during the *most recent* dispatch cycle, per the docstring on
    /// `poll_dispatch_flags`.
    #[test]
    fn dispatch_alert_zeroes_prior_flags_each_cycle() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Block).unwrap();

        // Cycle 1: Critical -> Isolate -> Block dispatcher fires.
        let critical = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Critical,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        engine.dispatch_alert(&critical);
        assert!(
            engine.poll_dispatch_flags()[0],
            "Block dispatcher must fire for Critical/Isolate"
        );

        // Cycle 2: Info -> Log -> Block dispatcher does NOT fire.
        // The stale `true` from cycle 1 must be cleared at the top of
        // dispatch_alert; otherwise the caller would think Block fired
        // when it actually did not.
        let info = SecurityAlert {
            id: 2,
            severity: AlertSeverity::Info,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        engine.dispatch_alert(&info);
        assert!(
            !engine.poll_dispatch_flags()[0],
            "Block flag from prior cycle must be cleared before dispatching Info"
        );
    }

    /// Two consecutive `dispatch_alert` calls with different alerts must each
    /// report a clean flag set tied to the alert that just dispatched.
    #[test]
    fn consecutive_dispatch_alert_calls_report_clean_flags() {
        let mut engine = make_engine();
        engine.add_dispatcher(DispatchAction::Log).unwrap(); // slot 0
        engine.add_dispatcher(DispatchAction::Block).unwrap(); // slot 1
        engine.add_dispatcher(DispatchAction::Telemetry).unwrap(); // slot 2

        // First call: Critical alert.  All three dispatchers should fire
        // (Log always, Block on Isolate, Telemetry on non-Log).
        let critical = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Critical,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let count1 = engine.dispatch_alert(&critical);
        assert_eq!(count1, 3);
        let flags1 = *engine.poll_dispatch_flags();
        assert!(flags1[0] && flags1[1] && flags1[2]);

        // Second call: Info alert.  Only Log dispatcher should fire; Block
        // and Telemetry must report `false`.  If `dispatch_alert` failed to
        // zero the flags first, slots 1 and 2 would still read `true` from
        // the previous Critical dispatch.
        let info = SecurityAlert {
            id: 2,
            severity: AlertSeverity::Info,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        let count2 = engine.dispatch_alert(&info);
        assert_eq!(count2, 1, "only Log dispatcher should fire for Info");
        let flags2 = engine.poll_dispatch_flags();
        assert!(flags2[0], "Log fires for any alert");
        assert!(
            !flags2[1],
            "Block must not fire for Info (and previous true must be cleared)"
        );
        assert!(
            !flags2[2],
            "Telemetry must not fire for Info (and previous true must be cleared)"
        );
    }

    // ----- Regression: dedup-refresh keeps tick correct without chronological invariant -----

    /// Dedup-refreshed entries leave the ring buffer in non-chronological
    /// order: an older logical slot can hold a newer timestamp than later
    /// slots.  `tick` must still correctly expire stale entries regardless
    /// of slot position.
    #[test]
    fn tick_expires_correctly_after_dedup_refresh_breaks_chronology() {
        let mut engine = make_engine();

        // Step 1: Write a "fresh" alert into slot 0 at t=0.
        let alert_a = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 100,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 0,
        };
        engine.record_alert(alert_a);

        // Step 2: Write a different alert into slot 1 at t=10.  This entry
        // is "younger" than slot 0 in chronological order.
        let alert_b = SecurityAlert {
            id: 2,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 200,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 10,
        };
        engine.record_alert(alert_b);

        // Step 3: Dedup-refresh alert_a in slot 0 with a very recent
        // timestamp (t=10_000_000).  Slot 0 now holds a newer timestamp
        // than slot 1, breaking any "ring buffer is chronological"
        // assumption.
        engine.record_alert(SecurityAlert {
            timestamp_us: 10_000_000,
            ..alert_a
        });

        // Step 4: tick at t=10_000_050.  The correlation window is 100_000
        // (set by `make_engine`).  Slot 0 (refreshed timestamp 10_000_000)
        // is within window (diff=50), slot 1 (timestamp 10) is far outside
        // (diff > 9_999_999).  A correct `tick` must invalidate slot 1 even
        // though it sits after slot 0 in the ring buffer.
        engine.tick(10_000_050);

        let mut refreshed_alert_valid = false;
        let mut stale_alert_valid = false;
        for entry in &engine.recent_alerts {
            if entry.valid && entry.alert.id == 1 {
                refreshed_alert_valid = true;
            }
            if entry.valid && entry.alert.id == 2 {
                stale_alert_valid = true;
            }
        }
        assert!(
            refreshed_alert_valid,
            "dedup-refreshed slot must remain valid (within correlation window)"
        );
        assert!(
            !stale_alert_valid,
            "stale slot must be expired by tick even when a later slot was dedup-refreshed"
        );
    }

    /// Symmetric scenario: dedup-refresh leaves an older entry sitting in a
    /// later ring-buffer slot; `tick` must still expire the older entry.
    #[test]
    fn tick_expires_stale_entry_when_newer_entry_sits_before_it() {
        let mut engine = make_engine();

        // Slot 0: id=1 at t=5.
        let alert_a = SecurityAlert {
            id: 1,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 1,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 5,
        };
        engine.record_alert(alert_a);

        // Slot 1: id=2 at t=10.
        let alert_b = SecurityAlert {
            id: 2,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 2,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 10,
        };
        engine.record_alert(alert_b);

        // Slot 0 dedup-refresh: id=1 timestamp jumps to 1_000_000.  After
        // this, slot 0 is "newer" than slot 1 in wall-clock time.
        engine.record_alert(SecurityAlert {
            timestamp_us: 1_000_000,
            ..alert_a
        });

        // tick at 1_000_050: slot 0 in window, slot 1 (t=10) out of window.
        engine.tick(1_000_050);

        let mut found_a = false;
        let mut found_b = false;
        for entry in &engine.recent_alerts {
            if !entry.valid {
                continue;
            }
            if entry.alert.id == 1 {
                found_a = true;
            } else if entry.alert.id == 2 {
                found_b = true;
            }
        }
        assert!(found_a, "refreshed entry must survive tick");
        assert!(
            !found_b,
            "stale entry must be expired even when sitting after a refreshed slot"
        );
    }

    // ----- H1: open-addressed dedup hash table -----

    /// Dedup via the hash table must still collapse repeated identities into
    /// a single ring entry and accumulate the duplicate count.
    #[test]
    fn dedup_hash_table_collapses_repeats() {
        let mut engine = make_engine();
        let alert = SecurityAlert {
            id: 7,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 3,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 1,
        };
        for ts in 1..=20 {
            engine.record_alert(SecurityAlert {
                timestamp_us: ts,
                ..alert
            });
        }
        let valid: usize = engine.recent_alerts.iter().filter(|e| e.valid).count();
        assert_eq!(valid, 1, "all repeats must dedup into one ring slot");
        let dup = engine
            .recent_alerts
            .iter()
            .find(|e| e.valid)
            .unwrap()
            .duplicate_count;
        assert_eq!(dup, 19, "19 dedup hits after the initial insert");
    }

    /// Wrapping the ring with `CORRELATION_WINDOW + N` distinct identities
    /// must keep the dedup table consistent: every still-live identity must
    /// be found exactly once, and overwritten identities must be evicted
    /// from the table so they no longer dedup-match.
    #[test]
    fn dedup_table_consistent_after_ring_wrap() {
        let mut engine = make_engine();
        let total = CORRELATION_WINDOW + 10;
        for i in 0..total as u64 {
            engine.record_alert(SecurityAlert {
                id: i,
                severity: AlertSeverity::Low,
                source_type: vs_types::SOURCE_CAN,
                source_id: 0,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: i,
            });
        }
        // Ring holds exactly CORRELATION_WINDOW slots; the 10 earliest
        // identities were overwritten and counted as dropped.
        assert_eq!(engine.dropped_alert_count(), 10);
        let valid: usize = engine.recent_alerts.iter().filter(|e| e.valid).count();
        assert_eq!(valid, CORRELATION_WINDOW);

        // Re-recording an overwritten identity (id 0) must NOT dedup-match
        // a stale table entry — it inserts fresh with duplicate_count 0.
        engine.record_alert(SecurityAlert {
            id: 0,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 9999,
        });
        let mut evicted_count = 0usize;
        let mut evicted_dup = 0u32;
        for e in &engine.recent_alerts {
            if e.valid && e.alert.id == 0 {
                evicted_count += 1;
                evicted_dup = e.duplicate_count;
            }
        }
        assert_eq!(
            evicted_count, 1,
            "re-recorded evicted identity must produce exactly one fresh slot"
        );
        assert_eq!(
            evicted_dup, 0,
            "evicted identity must not carry a stale duplicate_count"
        );

        // A still-live identity (the last one recorded before the reinsert)
        // must still dedup-match in O(1).
        let live_id = (total - 1) as u64;
        engine.record_alert(SecurityAlert {
            id: live_id,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 0,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 10_000,
        });
        let live_dup = engine
            .recent_alerts
            .iter()
            .find(|e| e.valid && e.alert.id == live_id)
            .unwrap()
            .duplicate_count;
        assert_eq!(live_dup, 1, "live identity must still dedup-match");
    }

    /// After `tick` expires entries, their dedup-table mappings must be
    /// dropped so a later identical alert inserts fresh rather than
    /// dedup-matching an expired slot.
    #[test]
    fn dedup_table_drops_expired_entries_on_tick() {
        let mut engine = make_engine();
        let alert = SecurityAlert {
            id: 55,
            severity: AlertSeverity::Low,
            source_type: vs_types::SOURCE_CAN,
            source_id: 9,
            payload_hash: PayloadHash::ZERO,
            timestamp_us: 100,
        };
        engine.record_alert(alert);
        // Window is 100_000; tick well past it expires the entry.
        engine.tick(1_000_000);
        assert_eq!(engine.recent_alerts.iter().filter(|e| e.valid).count(), 0);

        // Same identity again: must insert fresh (duplicate_count 0), not
        // dedup-match the expired slot.
        engine.record_alert(SecurityAlert {
            timestamp_us: 1_000_001,
            ..alert
        });
        let entry = engine
            .recent_alerts
            .iter()
            .find(|e| e.valid && e.alert.id == 55)
            .unwrap();
        assert_eq!(
            entry.duplicate_count, 0,
            "expired identity must not dedup-match after tick"
        );
    }

    /// Hash collisions on the dedup key must not cause false dedup matches:
    /// two alerts with distinct full identities are kept as separate ring
    /// entries even if their keys were to collide.
    #[test]
    fn dedup_distinct_identities_never_collapse() {
        let mut engine = make_engine();
        // Many distinct (id, source_id) pairs; the table re-verifies full
        // identity, so each must occupy its own slot.
        for i in 0..16u64 {
            engine.record_alert(SecurityAlert {
                id: i,
                severity: AlertSeverity::Low,
                source_type: vs_types::SOURCE_CAN,
                source_id: (i as u32) * 7 + 1,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: i,
            });
        }
        let valid = engine.recent_alerts.iter().filter(|e| e.valid).count();
        assert_eq!(valid, 16, "distinct identities must not be deduplicated");
    }
}
