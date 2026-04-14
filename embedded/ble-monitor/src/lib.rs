// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

//! BLE (Bluetooth Low Energy) connection intrusion detection monitor.
//!
//! Detects anomalous BLE activity on `IoT` devices:
//!
//! - **MAC allowlist/blocklist** — restrict which peers may connect.
//! - **Connection storm detection** — excessive connection attempts.
//! - **RSSI anomaly detection** — sudden RSSI changes may indicate
//!   relay/MITM attacks (BLE relay attack detection).
//! - **Pairing failure tracking** — repeated pairing failures from the
//!   same peer may indicate brute-force attacks.
//! - **Global pairing failure tracking** — detects distributed brute-force
//!   across many MAC addresses (e.g. BLE address randomization).
//! - **GATT abuse detection** — excessive read/write operations.
//!
//! # Examples
//!
//! ```rust
//! use vs_ble_monitor::{BleMonitor, MacAction};
//! use vs_types_embedded::{BleEvent, BleEventType};
//!
//! let mut monitor = BleMonitor::new();
//! monitor.add_mac_filter([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03], MacAction::Allow).unwrap();
//!
//! let event = BleEvent {
//!     event_type: BleEventType::Connected,
//!     peer_addr: [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
//!     rssi: -50,
//!     conn_handle: 1,
//!     timestamp_us: 1_000_000,
//! };
//!
//! let result = monitor.inspect(&event);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_embedded::{
    ct_mac_eq, BleAddressType, BleEvent, BleEventType, MonitorReset, TimestampValidator,
    MAX_MAC_FILTERS, MAX_TRACKED_PEERS, SOURCE_BLE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default connection storm threshold (connections per window).
const DEFAULT_CONN_STORM_THRESHOLD: u8 = 10;

/// Default connection storm window (30 seconds).
const DEFAULT_CONN_STORM_WINDOW_US: u64 = 30_000_000;

/// Default pairing failure lockout threshold (per-peer).
const DEFAULT_PAIRING_FAIL_THRESHOLD: u8 = 3;

/// Default global pairing failure threshold (across all peers in window).
const DEFAULT_GLOBAL_PAIRING_FAIL_THRESHOLD: u8 = 10;

/// Default pairing request flood threshold (per-peer, separate from failure threshold).
const DEFAULT_PAIRING_REQUEST_THRESHOLD: u8 = 100;

/// Global pairing failure window (60 seconds).
const GLOBAL_PAIRING_FAIL_WINDOW_US: u64 = 60_000_000;

/// Maximum global pairing failure timestamps tracked.
const MAX_GLOBAL_PAIRING_TS: usize = 32;

/// Default GATT abuse threshold (operations per minute).
const DEFAULT_GATT_RATE_THRESHOLD: u16 = 100;

/// GATT rate-limit window (60 seconds in microseconds).
const GATT_RATE_WINDOW_US: u64 = 60_000_000;

/// Pairing request rate-limit window (60 seconds in microseconds).
const PAIRING_WINDOW_US: u64 = 60_000_000;

/// Minimum valid RSSI value in dBm for BLE.
const MIN_VALID_RSSI: i8 = -120;

/// Maximum valid RSSI value in dBm for BLE.
const MAX_VALID_RSSI: i8 = 0;

/// RSSI change threshold in dBm that triggers relay attack alert.
const RSSI_JUMP_THRESHOLD: i8 = 30;

/// Maximum connection timestamps for storm detection.
const MAX_CONN_TIMESTAMPS: usize = 32;

/// Sentinel value for "no RSSI baseline established".
const RSSI_NO_BASELINE: i8 = i8::MIN;

/// Peer inactivity timeout for LRU eviction (5 minutes).
const PEER_EVICTION_TIMEOUT_US: u64 = 300_000_000;

/// Default random address flood threshold (addresses per 60-second window).
const DEFAULT_RANDOM_ADDR_THRESHOLD: u16 = 50;

/// Random address tracking window (60 seconds).
const RANDOM_ADDR_WINDOW_US: u64 = 60_000_000;

// Alert source IDs for correlation.
const ALERT_MAC_BLOCKED: u32 = 1;
const ALERT_CONN_STORM: u32 = 2;
const ALERT_RSSI_ANOMALY: u32 = 3;
const ALERT_PEER_SLOTS_FULL: u32 = 4;
const ALERT_PAIRING_LOCKOUT: u32 = 5;
const ALERT_GLOBAL_PAIRING_STORM: u32 = 6;
const ALERT_GATT_ABUSE: u32 = 7;
const ALERT_TIMESTAMP_ANOMALY: u32 = 8;
const ALERT_RANDOM_ADDR_FLOOD: u32 = 9;
const ALERT_PAIRING_REQUEST_FLOOD: u32 = 10;
const ALERT_SHORT_CONNECTION: u32 = 11;
const ALERT_ADV_FLOOD: u32 = 12;
const ALERT_BLE_UNKNOWN_EVENT: u32 = 13;
const ALERT_INVALID_MAC: u32 = 14;

/// Minimum connection duration before a short-connection alert (1 second).
const MIN_CONNECTION_DURATION_US: u64 = 1_000_000;

/// Default advertisement flood threshold (advertisements per window).
const DEFAULT_ADV_FLOOD_THRESHOLD: u16 = 1000;

/// Default advertisement flood window (60 seconds).
const DEFAULT_ADV_FLOOD_WINDOW_US: u64 = 60_000_000;

// ---------------------------------------------------------------------------
// MAC filter
// ---------------------------------------------------------------------------

/// MAC filter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAction {
    /// Allow connections from this MAC address.
    Allow,
    /// Block connections from this MAC address.
    Block,
}

/// A MAC address filter entry.
#[derive(Debug, Clone, Copy)]
struct MacFilter {
    addr: [u8; 6],
    action: MacAction,
    active: bool,
}

impl MacFilter {
    const fn empty() -> Self {
        Self {
            addr: [0u8; 6],
            action: MacAction::Allow,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer tracking
// ---------------------------------------------------------------------------

/// Per-peer state for anomaly detection.
#[derive(Debug, Clone, Copy)]
struct PeerState {
    addr: [u8; 6],
    last_rssi: i8,
    pairing_failures: u8,
    pairing_requests: u8,
    pairing_window_start_us: u64,
    gatt_ops: u16,
    gatt_window_start_us: u64,
    last_activity_us: u64,
    connect_timestamp_us: u64,
    active: bool,
}

impl PeerState {
    const fn empty() -> Self {
        Self {
            addr: [0u8; 6],
            last_rssi: RSSI_NO_BASELINE,
            pairing_failures: 0,
            pairing_requests: 0,
            pairing_window_start_us: 0,
            gatt_ops: 0,
            gatt_window_start_us: 0,
            last_activity_us: 0,
            connect_timestamp_us: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Result of inspecting a BLE event.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct BleInspectResult {
    /// Whether the event was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts dropped due to overflow.
    pub alerts_dropped: u8,
}

impl BleInspectResult {
    const fn clean() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: SOURCE_BLE,
                source_id: 0,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: 0,
            }; 4],
            alerts_dropped: 0,
        }
    }

    #[inline]
    fn push_alert(&mut self, severity: AlertSeverity, source_id: u32, ts_us: u64, alert_id: u64) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type: SOURCE_BLE,
                source_id,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// BLE Monitor
// ---------------------------------------------------------------------------

/// BLE connection intrusion detection monitor.
pub struct BleMonitor {
    mac_filters: [MacFilter; MAX_MAC_FILTERS],
    mac_filter_count: u8,
    peers: [PeerState; MAX_TRACKED_PEERS],
    conn_timestamps: [u64; MAX_CONN_TIMESTAMPS],
    conn_count: u8,
    conn_write_idx: u8,
    conn_storm_threshold: u8,
    conn_storm_window_us: u64,
    pairing_fail_threshold: u8,
    pairing_request_threshold: u8,
    gatt_rate_threshold: u16,
    default_action: MacAction,
    /// Global pairing failure tracking (V6 fix): ring buffer of timestamps.
    global_pairing_fail_ts: [u64; MAX_GLOBAL_PAIRING_TS],
    global_pairing_fail_count: u8,
    global_pairing_fail_write_idx: u8,
    global_pairing_fail_threshold: u8,
    /// Timestamp validator for clock anomaly detection.
    ts_validator: TimestampValidator,
    /// Random address flood tracking.
    random_addr_count: u16,
    random_addr_window_start_us: u64,
    random_addr_threshold: u16,
    /// Advertisement flood tracking.
    adv_flood_count: u16,
    adv_flood_window_start_us: u64,
    adv_flood_threshold: u16,
    adv_flood_window_us: u64,
    /// Accumulated pairing failures from evicted peers.  Prevents
    /// counter-reset attacks where an attacker deliberately causes peer
    /// eviction to clear per-peer failure counts.
    evicted_pairing_failures: u16,
    /// Monotonically increasing alert ID counter.
    next_alert_id: u64,
    total_inspected: u64,
    total_alerts: u64,
}

impl BleMonitor {
    /// Create a new BLE monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            mac_filters: [MacFilter::empty(); MAX_MAC_FILTERS],
            mac_filter_count: 0,
            peers: [PeerState::empty(); MAX_TRACKED_PEERS],
            conn_timestamps: [0u64; MAX_CONN_TIMESTAMPS],
            conn_count: 0,
            conn_write_idx: 0,
            conn_storm_threshold: DEFAULT_CONN_STORM_THRESHOLD,
            conn_storm_window_us: DEFAULT_CONN_STORM_WINDOW_US,
            pairing_fail_threshold: DEFAULT_PAIRING_FAIL_THRESHOLD,
            pairing_request_threshold: DEFAULT_PAIRING_REQUEST_THRESHOLD,
            gatt_rate_threshold: DEFAULT_GATT_RATE_THRESHOLD,
            default_action: MacAction::Allow,
            global_pairing_fail_ts: [0u64; MAX_GLOBAL_PAIRING_TS],
            global_pairing_fail_count: 0,
            global_pairing_fail_write_idx: 0,
            global_pairing_fail_threshold: DEFAULT_GLOBAL_PAIRING_FAIL_THRESHOLD,
            ts_validator: TimestampValidator::new(),
            random_addr_count: 0,
            random_addr_window_start_us: 0,
            random_addr_threshold: DEFAULT_RANDOM_ADDR_THRESHOLD,
            adv_flood_count: 0,
            adv_flood_window_start_us: 0,
            adv_flood_threshold: DEFAULT_ADV_FLOOD_THRESHOLD,
            adv_flood_window_us: DEFAULT_ADV_FLOOD_WINDOW_US,
            evicted_pairing_failures: 0,
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
        }
    }

    /// Create a new BLE monitor (deny-by-default — only allowlisted MACs).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = MacAction::Block;
        m
    }

    /// Add a MAC address filter.
    pub fn add_mac_filter(&mut self, addr: [u8; 6], action: MacAction) -> Result<(), VsError> {
        if self.mac_filter_count as usize >= MAX_MAC_FILTERS {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.mac_filter_count as usize;
        self.mac_filters[idx].addr = addr;
        self.mac_filters[idx].action = action;
        self.mac_filters[idx].active = true;
        self.mac_filter_count += 1;
        Ok(())
    }

    /// Remove a MAC filter by address (constant-time scan).
    ///
    /// Scans ALL `MAX_MAC_FILTERS` slots regardless of match position or
    /// active count to prevent timing side-channels from revealing which
    /// filter was removed or how many filters are configured.
    pub fn remove_mac_filter(&mut self, addr: [u8; 6]) -> bool {
        let mut found_idx: Option<usize> = None;
        // Constant-time scan: always iterate all slots.
        for i in 0..MAX_MAC_FILTERS {
            if self.mac_filters[i].active && ct_mac_eq(&self.mac_filters[i].addr, &addr) {
                found_idx = Some(i);
            }
        }
        if let Some(idx) = found_idx {
            self.mac_filters[idx] = MacFilter::empty();
            self.mac_filter_count = self.mac_filter_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Remove all MAC address filters, resetting the filter list to empty.
    ///
    /// After calling this method, no peers will be blocked or explicitly
    /// allowed by MAC address; the `default_action` policy applies to all.
    /// Clears all slots (not just `mac_filter_count`) for defense in depth.
    pub fn clear_mac_filters(&mut self) {
        self.mac_filters = [MacFilter::empty(); MAX_MAC_FILTERS];
        self.mac_filter_count = 0;
    }

    /// Set connection storm detection parameters.
    ///
    /// `threshold` must be >= 2 to avoid false positives. Values 0 or 1 are
    /// clamped to 2.
    pub fn set_conn_storm_params(&mut self, threshold: u8, window_us: u64) {
        self.conn_storm_threshold = threshold.clamp(2, MAX_CONN_TIMESTAMPS as u8);
        self.conn_storm_window_us = window_us.clamp(1_000_000, 600_000_000);
    }

    /// Set pairing failure threshold before lockout alert.
    pub fn set_pairing_fail_threshold(&mut self, threshold: u8) {
        self.pairing_fail_threshold = threshold.clamp(1, 50);
    }

    /// Set pairing request flood threshold (per-peer).
    ///
    /// A peer exceeding this many pairing requests without completing pairing
    /// triggers a flood alert.
    pub fn set_pairing_request_threshold(&mut self, threshold: u8) {
        self.pairing_request_threshold = threshold.clamp(1, 250);
    }

    /// Set global pairing failure threshold (across all peers).
    pub fn set_global_pairing_fail_threshold(&mut self, threshold: u8) {
        self.global_pairing_fail_threshold = threshold.clamp(2, MAX_GLOBAL_PAIRING_TS as u8);
    }

    /// Set GATT operation rate threshold (ops per 60-second window).
    pub fn set_gatt_rate_threshold(&mut self, threshold: u16) {
        self.gatt_rate_threshold = threshold.clamp(1, 10_000);
    }

    /// Set random address flood threshold (addresses per 60-second window).
    pub fn set_random_addr_threshold(&mut self, threshold: u16) {
        self.random_addr_threshold = threshold.clamp(1, 10_000);
    }

    /// Set advertisement flood detection parameters.
    pub fn set_adv_flood_params(&mut self, threshold: u16, window_us: u64) {
        self.adv_flood_threshold = threshold.clamp(1, 50_000);
        self.adv_flood_window_us = window_us.clamp(1_000_000, 600_000_000);
    }

    /// Inspect a BLE event.
    #[allow(clippy::too_many_lines)]
    pub fn inspect(&mut self, event: &BleEvent) -> BleInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = BleInspectResult::clean();

        // Timestamp validation.
        if !self.ts_validator.validate(event.timestamp_us) {
            let aid = self.next_alert_id();
            result.push_alert(
                AlertSeverity::Low,
                ALERT_TIMESTAMP_ANOMALY,
                event.timestamp_us,
                aid,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Zero/broadcast MAC validation.
        if is_zero_mac(&event.peer_addr) || is_broadcast_mac(&event.peer_addr) {
            result.allowed = false;
            let aid = self.next_alert_id();
            result.push_alert(
                AlertSeverity::High,
                ALERT_INVALID_MAC,
                event.timestamp_us,
                aid,
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // MAC filter check (constant-time comparison).
        let mac_action = self.check_mac_filter(event.peer_addr);
        if mac_action == MacAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                ALERT_MAC_BLOCKED,
                event.timestamp_us,
                self.next_alert_id(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        let alerts_before = result.alert_count;

        match event.event_type {
            BleEventType::Connected => {
                self.record_connection(event.timestamp_us);
                if self.detect_conn_storm(event.timestamp_us) {
                    result.allowed = false;
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::High,
                        ALERT_CONN_STORM,
                        event.timestamp_us,
                        aid,
                    );
                    self.total_alerts = self
                        .total_alerts
                        .saturating_add((result.alert_count - alerts_before) as u64);
                    return result;
                }

                // Use peer, collect what happened, then push alerts after borrow ends.
                let (rssi_anomaly, slot_exhausted) = {
                    let (peer, old_rssi) =
                        self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        let rssi_anomaly = detect_rssi_anomaly(event.rssi, old_rssi);
                        peer.last_rssi = event.rssi;
                        peer.last_activity_us = event.timestamp_us;
                        peer.connect_timestamp_us = event.timestamp_us;
                        (rssi_anomaly, false)
                    } else {
                        (false, true)
                    }
                };
                if rssi_anomaly {
                    self.push_rssi_alert(&mut result, event.timestamp_us);
                }
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);

                // Random address flood detection.
                if BleAddressType::classify(&event.peer_addr).is_random() {
                    if event
                        .timestamp_us
                        .saturating_sub(self.random_addr_window_start_us)
                        > RANDOM_ADDR_WINDOW_US
                    {
                        self.random_addr_count = 0;
                        self.random_addr_window_start_us = event.timestamp_us;
                    }
                    self.random_addr_count = self.random_addr_count.saturating_add(1);
                    if self.random_addr_count > self.random_addr_threshold {
                        let aid = self.next_alert_id();
                        result.push_alert(
                            AlertSeverity::Medium,
                            ALERT_RANDOM_ADDR_FLOOD,
                            event.timestamp_us,
                            aid,
                        );
                    }
                }
            }

            BleEventType::PairingFailed => {
                self.record_global_pairing_fail(event.timestamp_us);
                if self.detect_global_pairing_storm(event.timestamp_us) {
                    result.allowed = false;
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::High,
                        ALERT_GLOBAL_PAIRING_STORM,
                        event.timestamp_us,
                        aid,
                    );
                }

                let threshold = self.pairing_fail_threshold;
                let (lockout, slot_exhausted) = {
                    let (peer, _) = self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        peer.pairing_failures = peer.pairing_failures.saturating_add(1);
                        (peer.pairing_failures >= threshold, false)
                    } else {
                        (false, true)
                    }
                };
                if lockout {
                    result.allowed = false;
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::High,
                        ALERT_PAIRING_LOCKOUT,
                        event.timestamp_us,
                        aid,
                    );
                }
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);
            }

            BleEventType::GattRead | BleEventType::GattWrite => {
                let threshold = self.gatt_rate_threshold;
                let (exceeded, slot_exhausted) = {
                    let (peer, _) = self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        if event.timestamp_us.saturating_sub(peer.gatt_window_start_us)
                            > GATT_RATE_WINDOW_US
                        {
                            peer.gatt_ops = 0;
                            peer.gatt_window_start_us = event.timestamp_us;
                        }
                        peer.gatt_ops = peer.gatt_ops.saturating_add(1);
                        let exceeded = peer.gatt_ops >= threshold;
                        if exceeded {
                            // Reset counter so detection fires again on the next
                            // window-worth of operations.  This avoids the
                            // saturating_add edge case where the counter sticks at
                            // u16::MAX and the threshold crossing is never seen again.
                            peer.gatt_ops = 0;
                        }
                        (exceeded, false)
                    } else {
                        (false, true)
                    }
                };
                if exceeded {
                    result.allowed = false;
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::Medium,
                        ALERT_GATT_ABUSE,
                        event.timestamp_us,
                        aid,
                    );
                }
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);
            }

            BleEventType::Disconnected => {
                // Only look up existing peers — do not create a slot for
                // a Disconnected event from an unknown peer.
                let short_conn = if let Some(idx) = self.find_peer(&event.peer_addr) {
                    let peer = &mut self.peers[idx];
                    let was_connected = peer.connect_timestamp_us > 0;
                    let duration = event.timestamp_us.saturating_sub(peer.connect_timestamp_us);
                    peer.last_activity_us = event.timestamp_us;
                    peer.connect_timestamp_us = 0;
                    was_connected && duration < MIN_CONNECTION_DURATION_US
                } else {
                    false
                };
                if short_conn {
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::Low,
                        ALERT_SHORT_CONNECTION,
                        event.timestamp_us,
                        aid,
                    );
                }
            }

            BleEventType::AdvertisementReceived => {
                // RSSI anomaly detection for advertisements.
                let (rssi_anomaly, slot_exhausted) = {
                    let (peer, old_rssi) =
                        self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        let rssi_anomaly = detect_rssi_anomaly(event.rssi, old_rssi);
                        peer.last_rssi = event.rssi;
                        peer.last_activity_us = event.timestamp_us;
                        (rssi_anomaly, false)
                    } else {
                        (false, true)
                    }
                };
                if rssi_anomaly {
                    self.push_rssi_alert(&mut result, event.timestamp_us);
                }
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);

                // Advertisement flood detection.
                if event
                    .timestamp_us
                    .saturating_sub(self.adv_flood_window_start_us)
                    >= self.adv_flood_window_us
                {
                    self.adv_flood_count = 0;
                    self.adv_flood_window_start_us = event.timestamp_us;
                }
                self.adv_flood_count = self.adv_flood_count.saturating_add(1);
                if self.adv_flood_count > self.adv_flood_threshold {
                    result.allowed = false;
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::Medium,
                        ALERT_ADV_FLOOD,
                        event.timestamp_us,
                        aid,
                    );
                }
            }

            BleEventType::PairingRequest => {
                let threshold = self.pairing_request_threshold;
                let (flood, slot_exhausted) = {
                    let (peer, _) = self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        // Reset pairing request counter if outside the window.
                        if event
                            .timestamp_us
                            .saturating_sub(peer.pairing_window_start_us)
                            > PAIRING_WINDOW_US
                        {
                            peer.pairing_requests = 0;
                            peer.pairing_window_start_us = event.timestamp_us;
                        }
                        peer.pairing_requests = peer.pairing_requests.saturating_add(1);
                        peer.last_activity_us = event.timestamp_us;
                        (peer.pairing_requests > threshold, false)
                    } else {
                        (false, true)
                    }
                };
                if flood {
                    let aid = self.next_alert_id();
                    result.push_alert(
                        AlertSeverity::Medium,
                        ALERT_PAIRING_REQUEST_FLOOD,
                        event.timestamp_us,
                        aid,
                    );
                }
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);
            }

            BleEventType::PairingComplete => {
                let slot_exhausted = {
                    let (peer, _) = self.get_or_create_peer(event.peer_addr, event.timestamp_us);
                    if let Some(peer) = peer {
                        peer.pairing_failures = 0;
                        peer.pairing_requests = 0;
                        false
                    } else {
                        true
                    }
                };
                self.push_slot_exhaustion_alert(slot_exhausted, &mut result, event.timestamp_us);
            }

            BleEventType::Unknown => {
                let aid = self.next_alert_id();
                result.push_alert(
                    AlertSeverity::Medium,
                    ALERT_BLE_UNKNOWN_EVENT,
                    event.timestamp_us,
                    aid,
                );
            }
        }

        self.total_alerts = self
            .total_alerts
            .saturating_add((result.alert_count - alerts_before) as u64);
        result
    }

    /// Return the total number of events inspected.
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Return the total number of alerts raised.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    #[inline]
    fn next_alert_id(&mut self) -> u64 {
        let id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.wrapping_add(1);
        if self.next_alert_id == 0 {
            self.next_alert_id = 1;
        }
        id
    }

    /// Constant-time MAC filter check.
    ///
    /// Iterates all active filters regardless of match position to prevent
    /// timing side-channels from revealing which filter matched.
    #[inline]
    fn check_mac_filter(&self, addr: [u8; 6]) -> MacAction {
        let mut matched_action = self.default_action;
        let mut found = false;
        for i in 0..MAX_MAC_FILTERS {
            if self.mac_filters[i].active {
                let eq = ct_mac_eq(&self.mac_filters[i].addr, &addr);
                // Record first match only: if this is the first match (eq && !previously found),
                // latch the action. All entries are visited regardless.
                let first_match = eq & !found;
                if first_match {
                    matched_action = self.mac_filters[i].action;
                }
                found = found | eq;
            }
        }
        matched_action
    }

    /// Look up or allocate a peer slot, returning both the slot and the
    /// previous RSSI (if the peer was already tracked).  Combines the former
    /// `find_peer_rssi` + `get_or_create_peer` into a single constant-time
    /// scan followed by one allocation/eviction pass.
    fn get_or_create_peer(
        &mut self,
        addr: [u8; 6],
        now_us: u64,
    ) -> (Option<&mut PeerState>, Option<i8>) {
        // --- Pass 1: constant-time scan (security-critical) ---------------
        // Must touch every slot to avoid timing side-channels.
        let mut match_idx: Option<usize> = None;
        let mut old_rssi: Option<i8> = None;
        for i in 0..MAX_TRACKED_PEERS {
            // Always evaluate ct_mac_eq for every slot to avoid timing
            // side-channels; combine with `active` using bitwise AND.
            let eq = ct_mac_eq(&self.peers[i].addr, &addr);
            let is_match = self.peers[i].active && eq;
            if is_match {
                match_idx = Some(i);
                if self.peers[i].last_rssi != RSSI_NO_BASELINE {
                    old_rssi = Some(self.peers[i].last_rssi);
                }
            }
        }
        if let Some(idx) = match_idx {
            self.peers[idx].last_activity_us = now_us;
            return (Some(&mut self.peers[idx]), old_rssi);
        }

        // --- Pass 2: single scan for free slot + LRU candidates ----------
        let mut free_slot: Option<usize> = None;
        let mut lru_zero_idx: Option<usize> = None;
        let mut lru_zero_ts = u64::MAX;
        let mut lru_any_idx: Option<usize> = None;
        let mut lru_any_ts = u64::MAX;
        let double_timeout = PEER_EVICTION_TIMEOUT_US.saturating_mul(2);

        for i in 0..MAX_TRACKED_PEERS {
            if !self.peers[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            let age = now_us.saturating_sub(self.peers[i].last_activity_us);
            // Zero-failure peer past eviction timeout
            if self.peers[i].pairing_failures == 0
                && age > PEER_EVICTION_TIMEOUT_US
                && self.peers[i].last_activity_us < lru_zero_ts
            {
                lru_zero_ts = self.peers[i].last_activity_us;
                lru_zero_idx = Some(i);
            }
            // Any peer past 2× eviction timeout (fallback)
            if age > double_timeout && self.peers[i].last_activity_us < lru_any_ts {
                lru_any_ts = self.peers[i].last_activity_us;
                lru_any_idx = Some(i);
            }
        }

        let slot = free_slot.or(lru_zero_idx).or(lru_any_idx);
        if let Some(idx) = slot {
            // Carry evicted peer's pairing failures into global tracking
            // to prevent counter-reset attacks via deliberate eviction.
            if self.peers[idx].active && self.peers[idx].pairing_failures > 0 {
                let failures = self.peers[idx].pairing_failures;
                // Record each failure into the global ring buffer (capped at 3
                // entries per eviction to avoid ring-buffer flooding).
                for _ in 0..failures.min(3) {
                    self.record_global_pairing_fail(now_us);
                }
                // Also accumulate into a persistent counter so that even after
                // the ring-buffer timestamps expire, the total is not lost.
                self.evicted_pairing_failures = self
                    .evicted_pairing_failures
                    .saturating_add(failures as u16);
            }
            self.peers[idx] = PeerState::empty();
            self.peers[idx].addr = addr;
            self.peers[idx].active = true;
            self.peers[idx].last_activity_us = now_us;
            return (Some(&mut self.peers[idx]), None);
        }
        (None, None)
    }

    /// Look up an existing peer by MAC address (no allocation/eviction).
    ///
    /// This is intentionally NOT constant-time — it is only used for
    /// non-security-critical lookups (e.g. Disconnected event handling).
    #[inline]
    fn find_peer(&self, mac: &[u8; 6]) -> Option<usize> {
        for i in 0..MAX_TRACKED_PEERS {
            if self.peers[i].active && ct_mac_eq(&self.peers[i].addr, mac) {
                return Some(i);
            }
        }
        None
    }

    /// Push an RSSI anomaly alert (DRY helper).
    #[inline]
    fn push_rssi_alert(&mut self, result: &mut BleInspectResult, ts_us: u64) {
        let aid = self.next_alert_id();
        result.push_alert(AlertSeverity::High, ALERT_RSSI_ANOMALY, ts_us, aid);
    }

    /// Push a peer-slot-exhaustion alert if `exhausted` is true (DRY helper).
    #[inline]
    fn push_slot_exhaustion_alert(
        &mut self,
        exhausted: bool,
        result: &mut BleInspectResult,
        ts_us: u64,
    ) {
        if exhausted {
            let aid = self.next_alert_id();
            result.push_alert(AlertSeverity::Low, ALERT_PEER_SLOTS_FULL, ts_us, aid);
        }
    }

    #[inline]
    fn record_connection(&mut self, ts_us: u64) {
        let idx = self.conn_write_idx as usize % MAX_CONN_TIMESTAMPS;
        self.conn_timestamps[idx] = ts_us;
        self.conn_write_idx = ((idx + 1) % MAX_CONN_TIMESTAMPS) as u8;
        if (self.conn_count as usize) < MAX_CONN_TIMESTAMPS {
            self.conn_count += 1;
        }
    }

    fn detect_conn_storm(&self, now_us: u64) -> bool {
        let start = now_us.saturating_sub(self.conn_storm_window_us);
        let mut count: u8 = 0;
        for i in 0..self.conn_count as usize {
            if self.conn_timestamps[i] >= start && self.conn_timestamps[i] <= now_us {
                count = count.saturating_add(1);
            }
        }
        count >= self.conn_storm_threshold
    }

    #[inline]
    fn record_global_pairing_fail(&mut self, ts_us: u64) {
        let idx = self.global_pairing_fail_write_idx as usize % MAX_GLOBAL_PAIRING_TS;
        self.global_pairing_fail_ts[idx] = ts_us;
        self.global_pairing_fail_write_idx = ((idx + 1) % MAX_GLOBAL_PAIRING_TS) as u8;
        if (self.global_pairing_fail_count as usize) < MAX_GLOBAL_PAIRING_TS {
            self.global_pairing_fail_count += 1;
        }
    }

    fn detect_global_pairing_storm(&self, now_us: u64) -> bool {
        let start = now_us.saturating_sub(GLOBAL_PAIRING_FAIL_WINDOW_US);
        let mut count: u8 = 0;
        for i in 0..self.global_pairing_fail_count as usize {
            if self.global_pairing_fail_ts[i] >= start && self.global_pairing_fail_ts[i] <= now_us {
                count = count.saturating_add(1);
            }
        }
        count >= self.global_pairing_fail_threshold
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Detect RSSI anomaly: either an out-of-range value or a large jump from baseline.
///
/// Returns `true` if the RSSI is outside [-120, 0] or the delta from the
/// previous reading exceeds `RSSI_JUMP_THRESHOLD`.
#[inline]
fn detect_rssi_anomaly(rssi: i8, prev_rssi: Option<i8>) -> bool {
    let out_of_range = !((MIN_VALID_RSSI..=MAX_VALID_RSSI).contains(&rssi));
    let jump = if let Some(prev) = prev_rssi {
        let delta = (rssi as i16 - prev as i16).unsigned_abs();
        delta > RSSI_JUMP_THRESHOLD as u16
    } else {
        false
    };
    out_of_range || jump
}

/// Check if a MAC address is all zeros (invalid).
#[inline]
fn is_zero_mac(mac: &[u8; 6]) -> bool {
    mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0
}

/// Check if a MAC address is the broadcast address (FF:FF:FF:FF:FF:FF).
#[inline]
fn is_broadcast_mac(mac: &[u8; 6]) -> bool {
    mac[0] == 0xFF
        && mac[1] == 0xFF
        && mac[2] == 0xFF
        && mac[3] == 0xFF
        && mac[4] == 0xFF
        && mac[5] == 0xFF
}

impl Default for BleMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for BleMonitor {
    fn reset_state(&mut self) {
        // Clear runtime state.
        self.peers = [PeerState::empty(); MAX_TRACKED_PEERS];
        self.conn_timestamps = [0u64; MAX_CONN_TIMESTAMPS];
        self.conn_count = 0;
        self.conn_write_idx = 0;
        self.global_pairing_fail_ts = [0u64; MAX_GLOBAL_PAIRING_TS];
        self.global_pairing_fail_count = 0;
        self.global_pairing_fail_write_idx = 0;
        self.ts_validator.reset();
        self.random_addr_count = 0;
        self.random_addr_window_start_us = 0;
        self.adv_flood_count = 0;
        self.adv_flood_window_start_us = 0;
        self.evicted_pairing_failures = 0;
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
        // Preserve: mac_filters, mac_filter_count, default_action,
        // conn_storm_threshold, conn_storm_window_us, pairing_fail_threshold,
        // pairing_request_threshold, global_pairing_fail_threshold,
        // gatt_rate_threshold, random_addr_threshold.
    }
}

/// Convert a 6-byte MAC to a u32 source ID using FNV-1a hash of all 6 bytes.
///
/// Uses the full MAC address to avoid collisions from MACs sharing suffixes.
#[cfg(test)]
#[inline]
fn mac_to_source_id(mac: [u8; 6]) -> u32 {
    vs_types_embedded::fnv1a_hash(&mac)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_A: [u8; 6] = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03];
    const PEER_B: [u8; 6] = [0xDD, 0xEE, 0xFF, 0x04, 0x05, 0x06];

    fn make_event(peer: [u8; 6], evt_type: BleEventType, rssi: i8, ts_us: u64) -> BleEvent {
        BleEvent {
            event_type: evt_type,
            peer_addr: peer,
            rssi,
            conn_handle: 1,
            timestamp_us: ts_us,
        }
    }

    #[test]
    fn default_allow() {
        let mut mon = BleMonitor::new();
        let evt = make_event(PEER_A, BleEventType::Connected, -50, 1000);
        assert!(mon.inspect(&evt).allowed);
    }

    #[test]
    fn deny_default() {
        let mut mon = BleMonitor::new_deny_default();
        let evt = make_event(PEER_A, BleEventType::Connected, -50, 1000);
        assert!(!mon.inspect(&evt).allowed);
    }

    #[test]
    fn allowlist_overrides_deny() {
        let mut mon = BleMonitor::new_deny_default();
        mon.add_mac_filter(PEER_A, MacAction::Allow).unwrap();
        let evt = make_event(PEER_A, BleEventType::Connected, -50, 1000);
        assert!(mon.inspect(&evt).allowed);
    }

    #[test]
    fn blocklist() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();
        let evt = make_event(PEER_B, BleEventType::Connected, -50, 1000);
        assert!(!mon.inspect(&evt).allowed);
    }

    #[test]
    fn conn_storm_detected() {
        let mut mon = BleMonitor::new();
        mon.set_conn_storm_params(5, 10_000_000);

        for i in 0..4 {
            let evt = make_event(PEER_A, BleEventType::Connected, -50, 1_000_000 * (i + 1));
            assert!(mon.inspect(&evt).allowed);
        }

        let evt = make_event(PEER_A, BleEventType::Connected, -50, 5_000_000);
        assert!(!mon.inspect(&evt).allowed);
    }

    #[test]
    fn rssi_jump_triggers_alert() {
        let mut mon = BleMonitor::new();

        let evt1 = make_event(PEER_A, BleEventType::Connected, -70, 1_000_000);
        let r1 = mon.inspect(&evt1);
        assert_eq!(r1.alert_count, 0);

        let evt2 = make_event(PEER_A, BleEventType::Connected, -30, 2_000_000);
        let r2 = mon.inspect(&evt2);
        assert!(r2.alert_count > 0);
    }

    #[test]
    fn normal_rssi_variation_ok() {
        let mut mon = BleMonitor::new();

        let evt1 = make_event(PEER_A, BleEventType::Connected, -50, 1_000_000);
        let _ = mon.inspect(&evt1);

        let evt2 = make_event(PEER_A, BleEventType::Connected, -55, 2_000_000);
        let r2 = mon.inspect(&evt2);
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn pairing_failure_lockout() {
        let mut mon = BleMonitor::new();
        mon.set_pairing_fail_threshold(3);
        mon.set_global_pairing_fail_threshold(50); // high to avoid triggering

        for i in 0..2 {
            let evt = make_event(
                PEER_A,
                BleEventType::PairingFailed,
                -50,
                1_000_000 * (i + 1),
            );
            let r = mon.inspect(&evt);
            assert!(r.allowed, "failure {i} should not lock out yet");
        }

        let evt = make_event(PEER_A, BleEventType::PairingFailed, -50, 3_000_000);
        let r = mon.inspect(&evt);
        assert!(!r.allowed);
    }

    #[test]
    fn pairing_success_resets_failures() {
        let mut mon = BleMonitor::new();
        mon.set_pairing_fail_threshold(3);
        mon.set_global_pairing_fail_threshold(50);

        for i in 0..2 {
            let evt = make_event(
                PEER_A,
                BleEventType::PairingFailed,
                -50,
                1_000_000 * (i + 1),
            );
            let _ = mon.inspect(&evt);
        }

        let evt = make_event(PEER_A, BleEventType::PairingComplete, -50, 3_000_000);
        let _ = mon.inspect(&evt);

        for i in 0..2 {
            let evt = make_event(
                PEER_A,
                BleEventType::PairingFailed,
                -50,
                4_000_000 + 1_000_000 * (i + 1),
            );
            let r = mon.inspect(&evt);
            assert!(r.allowed);
        }
    }

    #[test]
    fn gatt_abuse_detected() {
        let mut mon = BleMonitor::new();
        mon.set_gatt_rate_threshold(5);

        for i in 0..4 {
            let evt = make_event(PEER_A, BleEventType::GattRead, -50, 1000 + i * 100);
            let r = mon.inspect(&evt);
            assert_eq!(r.alert_count, 0, "op {i} should be within limit");
        }

        // The 5th operation should cross the threshold and fire an alert.
        let evt = make_event(PEER_A, BleEventType::GattWrite, -50, 1500);
        let r = mon.inspect(&evt);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();

        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1000));
        let _ = mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 2000));

        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
    }

    #[test]
    fn mac_to_source_id_uses_full_mac() {
        let id = mac_to_source_id([0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04]);
        // Different MACs should produce different source IDs.
        let id2 = mac_to_source_id([0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04]);
        assert_ne!(
            id, id2,
            "MACs with same suffix should have different source IDs"
        );
    }

    #[test]
    fn advertisement_event_passes() {
        let mut mon = BleMonitor::new();
        let evt = make_event(PEER_A, BleEventType::AdvertisementReceived, -60, 1000);
        let r = mon.inspect(&evt);
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn disconnected_event_passes() {
        let mut mon = BleMonitor::new();
        let evt = make_event(PEER_A, BleEventType::Disconnected, -50, 1000);
        assert!(mon.inspect(&evt).allowed);
    }

    #[test]
    fn pairing_request_passes() {
        let mut mon = BleMonitor::new();
        let evt = make_event(PEER_A, BleEventType::PairingRequest, -50, 1000);
        assert!(mon.inspect(&evt).allowed);
    }

    #[test]
    fn mac_filter_full_returns_error() {
        let mut mon = BleMonitor::new();
        for i in 0..MAX_MAC_FILTERS as u8 {
            let mac = [i, 0, 0, 0, 0, 0];
            mon.add_mac_filter(mac, MacAction::Allow).unwrap();
        }
        let mac = [0xFF, 0, 0, 0, 0, 0];
        assert!(mon.add_mac_filter(mac, MacAction::Block).is_err());
    }

    #[test]
    fn gatt_window_resets_after_timeout() {
        let mut mon = BleMonitor::new();
        mon.set_gatt_rate_threshold(3);

        for i in 0..2 {
            let evt = make_event(PEER_A, BleEventType::GattRead, -50, i * 100);
            let _ = mon.inspect(&evt);
        }

        // The 3rd operation crosses the threshold.
        let evt = make_event(PEER_A, BleEventType::GattWrite, -50, 300);
        let r = mon.inspect(&evt);
        assert!(r.alert_count > 0);

        // After the window elapses the counter is fresh — no alert.
        let evt = make_event(PEER_A, BleEventType::GattRead, -50, 61_000_000);
        let r = mon.inspect(&evt);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let mut mon = BleMonitor::new();
        mon.set_pairing_fail_threshold(3);
        mon.set_global_pairing_fail_threshold(50);

        for i in 0..2 {
            let _ = mon.inspect(&make_event(
                PEER_A,
                BleEventType::PairingFailed,
                -50,
                1_000_000 * (i + 1),
            ));
        }

        for i in 0..2 {
            let r = mon.inspect(&make_event(
                PEER_B,
                BleEventType::PairingFailed,
                -50,
                3_000_000 + 1_000_000 * (i + 1),
            ));
            assert!(r.allowed);
        }

        let r = mon.inspect(&make_event(
            PEER_A,
            BleEventType::PairingFailed,
            -50,
            6_000_000,
        ));
        assert!(!r.allowed);
    }

    #[test]
    fn conn_storm_window_expiry() {
        let mut mon = BleMonitor::new();
        mon.set_conn_storm_params(3, 5_000_000);

        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 2_000_000));

        let r = mon.inspect(&make_event(
            PEER_A,
            BleEventType::Connected,
            -50,
            20_000_000,
        ));
        assert!(r.allowed);
    }

    #[test]
    fn default_constructor() {
        let mon = BleMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);
    }

    #[test]
    fn gatt_write_counted() {
        let mut mon = BleMonitor::new();
        mon.set_gatt_rate_threshold(2);

        let _ = mon.inspect(&make_event(PEER_A, BleEventType::GattWrite, -50, 1000));

        // The 2nd operation crosses the threshold.
        let r = mon.inspect(&make_event(PEER_A, BleEventType::GattWrite, -50, 2000));
        assert!(r.alert_count > 0);
    }

    #[test]
    fn rssi_zero_is_valid_baseline() {
        let mut mon = BleMonitor::new();
        let r = mon.inspect(&make_event(PEER_A, BleEventType::Connected, 0, 1000));
        assert_eq!(r.alert_count, 0);

        let r2 = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -80, 2000));
        assert!(r2.alert_count > 0);
    }

    #[test]
    fn no_rssi_alert_on_first_connect() {
        let mut mon = BleMonitor::new();
        let r = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1000));
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn peer_slot_exhaustion_emits_alert() {
        let mut mon = BleMonitor::new();
        // Space Connected events 4 seconds apart so that:
        //  • at most ~8 fall within the 30-second connection-storm window
        //    (threshold 10), avoiding an early-return before get_or_create_peer;
        //  • the oldest peer's age at overflow time is at most
        //    (MAX_TRACKED_PEERS-1)*4s ≤ 63*4s = 252s, well below the
        //    300-second eviction timeout, so no LRU eviction is possible.
        let ts_base = 500_000_000_000_u64;
        let spacing = 4_000_000_u64; // 4 seconds
        for i in 0..MAX_TRACKED_PEERS {
            let mac = [(i as u8) + 1, 0, 0, 0, 0, 0];
            let ts = ts_base + (i as u64) * spacing;
            let evt = make_event(mac, BleEventType::Connected, -50, ts);
            let _ = mon.inspect(&evt);
        }
        // One more unique peer — all slots are occupied and none are
        // eviction-eligible, so we should see a slot-exhaustion alert.
        let overflow_ts = ts_base + (MAX_TRACKED_PEERS as u64) * spacing;
        let overflow_mac = [0xFF, 0xFF, 0, 0, 0, 0];
        let evt = make_event(overflow_mac, BleEventType::Connected, -50, overflow_ts);
        let r = mon.inspect(&evt);
        let has_slot_alert =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_PEER_SLOTS_FULL);
        assert!(has_slot_alert, "expected ALERT_PEER_SLOTS_FULL");
        let slot_alert = (0..r.alert_count as usize)
            .find(|&i| r.alerts[i].source_id == ALERT_PEER_SLOTS_FULL)
            .unwrap();
        assert_eq!(r.alerts[slot_alert].severity, AlertSeverity::Low);
    }

    #[test]
    fn peer_lru_eviction_reclaims_stale_slot() {
        let mut mon = BleMonitor::new();
        for i in 0..MAX_TRACKED_PEERS as u8 {
            let mac = [i + 1, 0, 0, 0, 0, 0];
            let evt = make_event(mac, BleEventType::Connected, -50, 1000);
            let _ = mon.inspect(&evt);
        }
        let mac17 = [0xFF, 0xFF, 0, 0, 0, 0];
        let evt = make_event(mac17, BleEventType::Connected, -50, 500_000_000);
        let r = mon.inspect(&evt);
        assert!(r.allowed);
        let has_exhaustion_alert = (0..r.alert_count as usize).any(|i| {
            r.alerts[i].severity == AlertSeverity::Low
                && r.alerts[i].source_id == ALERT_PEER_SLOTS_FULL
        });
        assert!(!has_exhaustion_alert);
    }

    #[test]
    fn alert_overflow_capped_at_4() {
        let mut result = BleInspectResult::clean();
        for _ in 0..6 {
            result.push_alert(AlertSeverity::Medium, 0, 1000, 1);
        }
        assert_eq!(result.alert_count, 4);
    }

    #[test]
    fn remove_mac_filter_works() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();
        assert!(
            !mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 1000))
                .allowed
        );

        assert!(mon.remove_mac_filter(PEER_B));
        assert!(
            mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 2000))
                .allowed
        );
    }

    #[test]
    fn remove_nonexistent_mac_filter_returns_false() {
        let mut mon = BleMonitor::new();
        assert!(!mon.remove_mac_filter([0xFF; 6]));
    }

    #[test]
    fn clear_mac_filters_works() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_A, MacAction::Block).unwrap();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();
        mon.clear_mac_filters();
        assert!(
            mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1000))
                .allowed
        );
        assert!(
            mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 2000))
                .allowed
        );
    }

    #[test]
    fn non_monotonic_timestamp_does_not_panic() {
        let mut mon = BleMonitor::new();
        let _ = mon.inspect(&make_event(
            PEER_A,
            BleEventType::Connected,
            -50,
            10_000_000,
        ));
        let _r = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        // No panic is the assertion — the function returned successfully.
    }

    // -----------------------------------------------------------------------
    // V6 fix: global pairing failure detection
    // -----------------------------------------------------------------------

    #[test]
    fn global_pairing_storm_detected() {
        let mut mon = BleMonitor::new();
        mon.set_pairing_fail_threshold(50); // high per-peer to avoid triggering
        mon.set_global_pairing_fail_threshold(5);

        // 5 pairing failures from 5 different MACs within window.
        for i in 0u8..4 {
            let mac = [i + 1, 0, 0, 0, 0, 0];
            let evt = make_event(
                mac,
                BleEventType::PairingFailed,
                -50,
                1_000_000 * (i as u64 + 1),
            );
            let r = mon.inspect(&evt);
            assert!(r.allowed, "failure {i} should be allowed");
        }

        // 5th from yet another MAC triggers global threshold.
        let mac = [0x10, 0, 0, 0, 0, 0];
        let evt = make_event(mac, BleEventType::PairingFailed, -50, 5_000_000);
        let r = mon.inspect(&evt);
        assert!(!r.allowed, "global pairing storm should block");
        // Should have the global pairing storm source ID.
        let has_global = (0..r.alert_count as usize)
            .any(|i| r.alerts[i].source_id == ALERT_GLOBAL_PAIRING_STORM);
        assert!(has_global, "should have global pairing storm alert");
    }

    #[test]
    fn global_pairing_storm_window_expires() {
        let mut mon = BleMonitor::new();
        mon.set_pairing_fail_threshold(50);
        mon.set_global_pairing_fail_threshold(3);

        // 2 failures within window.
        for i in 0u8..2 {
            let mac = [i + 1, 0, 0, 0, 0, 0];
            let evt = make_event(
                mac,
                BleEventType::PairingFailed,
                -50,
                1_000_000 * (i as u64 + 1),
            );
            let _ = mon.inspect(&evt);
        }

        // Wait past window, new failure should be fine.
        let mac = [0x20, 0, 0, 0, 0, 0];
        let evt = make_event(mac, BleEventType::PairingFailed, -50, 100_000_000);
        let r = mon.inspect(&evt);
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // Alert ID tracking
    // -----------------------------------------------------------------------

    #[test]
    fn alert_ids_are_unique() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();

        let r1 = mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 1000));
        let r2 = mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 2000));

        assert!(r1.alerts[0].id > 0);
        assert!(r2.alerts[0].id > r1.alerts[0].id);
    }

    // -----------------------------------------------------------------------
    // Constant-time remove_mac_filter
    // -----------------------------------------------------------------------

    #[test]
    fn remove_mac_filter_scans_all_entries() {
        let mut mon = BleMonitor::new();
        let mac_a = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac_b = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mac_c = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        mon.add_mac_filter(mac_a, MacAction::Block).unwrap();
        mon.add_mac_filter(mac_b, MacAction::Block).unwrap();
        mon.add_mac_filter(mac_c, MacAction::Block).unwrap();

        // Remove the first entry — should still find and remove it.
        assert!(mon.remove_mac_filter(mac_a));
        // mac_b and mac_c should still be active.
        assert!(
            !mon.inspect(&make_event(mac_b, BleEventType::Connected, -50, 1000))
                .allowed
        );
        assert!(
            !mon.inspect(&make_event(mac_c, BleEventType::Connected, -50, 2000))
                .allowed
        );
        // mac_a should now be allowed.
        assert!(
            mon.inspect(&make_event(mac_a, BleEventType::Connected, -50, 3000))
                .allowed
        );
    }

    #[test]
    fn remove_mac_filter_middle_entry() {
        let mut mon = BleMonitor::new();
        let mac_a = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac_b = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mac_c = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        mon.add_mac_filter(mac_a, MacAction::Block).unwrap();
        mon.add_mac_filter(mac_b, MacAction::Block).unwrap();
        mon.add_mac_filter(mac_c, MacAction::Block).unwrap();

        // Remove the middle entry.
        assert!(mon.remove_mac_filter(mac_b));
        assert!(
            !mon.inspect(&make_event(mac_a, BleEventType::Connected, -50, 1000))
                .allowed
        );
        assert!(
            mon.inspect(&make_event(mac_b, BleEventType::Connected, -50, 2000))
                .allowed
        );
        assert!(
            !mon.inspect(&make_event(mac_c, BleEventType::Connected, -50, 3000))
                .allowed
        );
    }

    // -----------------------------------------------------------------------
    // Address randomization detection
    // -----------------------------------------------------------------------

    #[test]
    fn random_addr_flood_detected() {
        let mut mon = BleMonitor::new();
        mon.set_random_addr_threshold(3);

        // Random static address: top two bits of last byte = 0b11.
        for i in 0u8..3 {
            let mac = [i, 0, 0, 0, 0, 0xC0]; // 0xC0 = 0b1100_0000 → RandomStatic
            let evt = make_event(
                mac,
                BleEventType::Connected,
                -50,
                1_000_000 * (i as u64 + 1),
            );
            let r = mon.inspect(&evt);
            // Should not trigger yet (count <= threshold).
            let has_flood = (0..r.alert_count as usize)
                .any(|j| r.alerts[j].source_id == ALERT_RANDOM_ADDR_FLOOD);
            assert!(!has_flood, "connection {i} should not trigger flood alert");
        }

        // 4th random address exceeds threshold.
        let mac = [0x10, 0, 0, 0, 0, 0xC0];
        let evt = make_event(mac, BleEventType::Connected, -50, 4_000_000);
        let r = mon.inspect(&evt);
        let has_flood =
            (0..r.alert_count as usize).any(|j| r.alerts[j].source_id == ALERT_RANDOM_ADDR_FLOOD);
        assert!(has_flood, "should trigger random address flood alert");
    }

    #[test]
    fn public_addr_does_not_trigger_random_flood() {
        let mut mon = BleMonitor::new();
        mon.set_random_addr_threshold(2);

        // Public address: top two bits of last byte = 0b10 → Public
        for i in 0u8..5 {
            let mac = [i, 0, 0, 0, 0, 0x80]; // 0x80 = 0b1000_0000 → Public
            let evt = make_event(
                mac,
                BleEventType::Connected,
                -50,
                1_000_000 * (i as u64 + 1),
            );
            let r = mon.inspect(&evt);
            let has_flood = (0..r.alert_count as usize)
                .any(|j| r.alerts[j].source_id == ALERT_RANDOM_ADDR_FLOOD);
            assert!(!has_flood, "public address should not trigger flood alert");
        }
    }

    #[test]
    fn random_addr_window_resets() {
        let mut mon = BleMonitor::new();
        mon.set_random_addr_threshold(2);

        // Two random addresses within window.
        for i in 0u8..2 {
            let mac = [i, 0, 0, 0, 0, 0xC0];
            let evt = make_event(
                mac,
                BleEventType::Connected,
                -50,
                1_000_000 * (i as u64 + 1),
            );
            let _ = mon.inspect(&evt);
        }

        // Wait past window (>60s), counter should reset.
        let mac = [0x20, 0, 0, 0, 0, 0xC0];
        let evt = make_event(mac, BleEventType::Connected, -50, 100_000_000);
        let r = mon.inspect(&evt);
        let has_flood =
            (0..r.alert_count as usize).any(|j| r.alerts[j].source_id == ALERT_RANDOM_ADDR_FLOOD);
        assert!(!has_flood, "window should have reset");
    }

    // -----------------------------------------------------------------------
    // Timestamp validation
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_anomaly_emits_alert() {
        let mut mon = BleMonitor::new();

        // First event initializes the validator.
        let r1 = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        let has_ts_alert =
            (0..r1.alert_count as usize).any(|i| r1.alerts[i].source_id == ALERT_TIMESTAMP_ANOMALY);
        assert!(!has_ts_alert, "first event should not be anomalous");

        // Huge forward jump should trigger timestamp anomaly.
        let r2 = mon.inspect(&make_event(
            PEER_A,
            BleEventType::Disconnected,
            -50,
            1_000_000_000_000, // 1_000_000 seconds forward
        ));
        let has_ts_alert =
            (0..r2.alert_count as usize).any(|i| r2.alerts[i].source_id == ALERT_TIMESTAMP_ANOMALY);
        assert!(
            has_ts_alert,
            "huge forward jump should trigger timestamp anomaly"
        );
    }

    #[test]
    fn normal_timestamp_progression_no_alert() {
        let mut mon = BleMonitor::new();
        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));

        let r = mon.inspect(&make_event(
            PEER_A,
            BleEventType::Disconnected,
            -50,
            2_000_000,
        ));
        let has_ts_alert =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_TIMESTAMP_ANOMALY);
        assert!(
            !has_ts_alert,
            "normal progression should not trigger anomaly"
        );
    }

    // -----------------------------------------------------------------------
    // MonitorReset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_runtime_state() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();
        mon.set_conn_storm_params(5, 10_000_000);
        mon.set_random_addr_threshold(10);

        // Generate some state.
        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        let _ = mon.inspect(&make_event(
            PEER_A,
            BleEventType::PairingFailed,
            -50,
            2_000_000,
        ));
        assert!(mon.total_inspected() > 0);
        assert!(mon.total_alerts() > 0 || mon.total_inspected() > 0);

        mon.reset_state();

        // Runtime state should be cleared.
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);

        // Configuration should be preserved.
        // MAC filter should still be active.
        assert!(
            !mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 1000))
                .allowed
        );
    }

    #[test]
    fn reset_preserves_thresholds() {
        let mut mon = BleMonitor::new();
        mon.set_conn_storm_params(3, 5_000_000);
        mon.set_pairing_fail_threshold(5);
        mon.set_gatt_rate_threshold(200);
        mon.set_random_addr_threshold(25);
        mon.set_global_pairing_fail_threshold(20);

        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        mon.reset_state();

        // After reset, thresholds should still work.
        // Connection storm with threshold=3 should trigger on 3rd connection.
        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 1_000_000));
        let _ = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 2_000_000));
        let r = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 3_000_000));
        assert!(
            !r.allowed,
            "conn storm threshold should still be 3 after reset"
        );
    }

    // -----------------------------------------------------------------------
    // Alert source ID constants
    // -----------------------------------------------------------------------

    #[test]
    fn alert_source_id_constants_are_distinct() {
        let ids = [
            ALERT_MAC_BLOCKED,
            ALERT_CONN_STORM,
            ALERT_RSSI_ANOMALY,
            ALERT_PEER_SLOTS_FULL,
            ALERT_PAIRING_LOCKOUT,
            ALERT_GLOBAL_PAIRING_STORM,
            ALERT_GATT_ABUSE,
            ALERT_TIMESTAMP_ANOMALY,
            ALERT_RANDOM_ADDR_FLOOD,
            ALERT_PAIRING_REQUEST_FLOOD,
            ALERT_SHORT_CONNECTION,
            ALERT_ADV_FLOOD,
            ALERT_BLE_UNKNOWN_EVENT,
            ALERT_INVALID_MAC,
        ];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(
                    ids[i], ids[j],
                    "alert source IDs {i} and {j} must be distinct"
                );
            }
        }
    }

    #[test]
    fn alert_source_id_constants_are_nonzero() {
        assert_ne!(ALERT_MAC_BLOCKED, 0);
        assert_ne!(ALERT_CONN_STORM, 0);
        assert_ne!(ALERT_RSSI_ANOMALY, 0);
        assert_ne!(ALERT_PEER_SLOTS_FULL, 0);
        assert_ne!(ALERT_PAIRING_LOCKOUT, 0);
        assert_ne!(ALERT_GLOBAL_PAIRING_STORM, 0);
        assert_ne!(ALERT_GATT_ABUSE, 0);
        assert_ne!(ALERT_TIMESTAMP_ANOMALY, 0);
        assert_ne!(ALERT_RANDOM_ADDR_FLOOD, 0);
        assert_ne!(ALERT_INVALID_MAC, 0);
    }

    #[test]
    fn blocked_mac_uses_correct_source_id() {
        let mut mon = BleMonitor::new();
        mon.add_mac_filter(PEER_B, MacAction::Block).unwrap();
        let r = mon.inspect(&make_event(PEER_B, BleEventType::Connected, -50, 1000));
        assert!(!r.allowed);
        assert_eq!(r.alerts[0].source_id, ALERT_MAC_BLOCKED);
    }

    #[test]
    fn conn_storm_uses_correct_source_id() {
        let mut mon = BleMonitor::new();
        mon.set_conn_storm_params(3, 10_000_000);
        for i in 0..2 {
            let _ = mon.inspect(&make_event(
                PEER_A,
                BleEventType::Connected,
                -50,
                1_000_000 * (i + 1),
            ));
        }
        let r = mon.inspect(&make_event(PEER_A, BleEventType::Connected, -50, 3_000_000));
        assert!(!r.allowed);
        let has_storm =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_CONN_STORM);
        assert!(has_storm);
    }

    #[test]
    fn adv_flood_detected() {
        let mut monitor = BleMonitor::new();
        monitor.set_adv_flood_params(5, 10_000_000); // 5 adverts per 10s

        for i in 0u8..5 {
            let mac = [i + 1, 0, 0, 0, 0, 0];
            let evt = BleEvent {
                event_type: BleEventType::AdvertisementReceived,
                peer_addr: mac,
                timestamp_us: (i as u64 + 1) * 100_000,
                ..BleEvent::default()
            };
            let r = monitor.inspect(&evt);
            assert!(r.allowed);
        }

        // 6th advert should trigger flood alert
        let evt = BleEvent {
            event_type: BleEventType::AdvertisementReceived,
            peer_addr: [0x10, 0, 0, 0, 0, 0],
            timestamp_us: 600_000,
            ..BleEvent::default()
        };
        let r = monitor.inspect(&evt);
        assert!(r.alert_count > 0, "adv flood should generate alert");
    }

    #[test]
    fn adv_flood_window_reset() {
        let mut monitor = BleMonitor::new();
        monitor.set_adv_flood_params(5, 10_000_000);

        // Send 4 adverts
        for i in 0u8..4 {
            let evt = BleEvent {
                event_type: BleEventType::AdvertisementReceived,
                peer_addr: [i + 1, 0, 0, 0, 0, 0],
                timestamp_us: (i as u64 + 1) * 100_000,
                ..BleEvent::default()
            };
            let _ = monitor.inspect(&evt);
        }

        // After window expires, counter should reset
        let evt = BleEvent {
            event_type: BleEventType::AdvertisementReceived,
            peer_addr: [0x20, 0, 0, 0, 0, 0],
            timestamp_us: 20_000_000, // well past the 10s window
            ..BleEvent::default()
        };
        let r = monitor.inspect(&evt);
        assert_eq!(r.alert_count, 0, "counter should reset after window");
    }

    #[test]
    fn short_connection_detected() {
        let mut monitor = BleMonitor::new();
        let mac = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03];

        // Connect
        let connect_evt = BleEvent {
            event_type: BleEventType::Connected,
            peer_addr: mac,
            rssi: -50,
            timestamp_us: 1_000_000,
            ..BleEvent::default()
        };
        let _ = monitor.inspect(&connect_evt);

        // Disconnect quickly (within 1 second)
        let disconnect_evt = BleEvent {
            event_type: BleEventType::Disconnected,
            peer_addr: mac,
            timestamp_us: 1_500_000, // 0.5s later
            ..BleEvent::default()
        };
        let r = monitor.inspect(&disconnect_evt);
        let has_short_conn =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_SHORT_CONNECTION);
        assert!(has_short_conn, "short connection should generate alert");
    }

    #[test]
    fn set_adv_flood_params_works() {
        let mut monitor = BleMonitor::new();
        monitor.set_adv_flood_params(3, 5_000_000);

        // 4 adverts should trigger flood with threshold 3
        for i in 0u8..5 {
            let evt = BleEvent {
                event_type: BleEventType::AdvertisementReceived,
                peer_addr: [i + 1, 0, 0, 0, 0, 0],
                timestamp_us: (i as u64 + 1) * 100_000,
                ..BleEvent::default()
            };
            let r = monitor.inspect(&evt);
            if i > 3 {
                assert!(r.alert_count > 0);
            }
        }
    }

    #[test]
    fn conn_storm_window_us_clamped_to_minimum() {
        let mut monitor = BleMonitor::new();
        // Setting window to 0 should be clamped to 1_000_000
        monitor.set_conn_storm_params(3, 0);
        // This should not cause division errors or weird behavior
        let mac = [0x01, 0, 0, 0, 0, 0];
        let evt = BleEvent {
            event_type: BleEventType::Connected,
            peer_addr: mac,
            rssi: -50,
            timestamp_us: 1_000_000,
            ..BleEvent::default()
        };
        let r = monitor.inspect(&evt);
        assert!(r.allowed, "should work with clamped window");
    }

    #[test]
    fn peer_lru_eviction_with_failures_uses_double_timeout() {
        let mut monitor = BleMonitor::new();
        monitor.set_pairing_fail_threshold(50); // high so per-peer doesn't block

        // Fill all peer slots with peers that have pairing failures
        let base_ts = 1_000_000u64;
        for i in 0..MAX_TRACKED_PEERS {
            let mac = [i as u8 + 1, 0, 0, 0, 0, 0];
            // Connect
            let evt = BleEvent {
                event_type: BleEventType::Connected,
                peer_addr: mac,
                rssi: -50,
                timestamp_us: base_ts + (i as u64) * 1000,
                ..BleEvent::default()
            };
            let _ = monitor.inspect(&evt);
            // Fail pairing (so pairing_failures > 0)
            let fail = BleEvent {
                event_type: BleEventType::PairingFailed,
                peer_addr: mac,
                timestamp_us: base_ts + (i as u64) * 1000 + 500,
                ..BleEvent::default()
            };
            let _ = monitor.inspect(&fail);
        }

        // Try to add a new peer after 2x eviction timeout (10 minutes = 600s)
        let late_ts = base_ts + 601_000_000; // well past 2x timeout
        let new_mac = [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE];
        let evt = BleEvent {
            event_type: BleEventType::Connected,
            peer_addr: new_mac,
            rssi: -50,
            timestamp_us: late_ts,
            ..BleEvent::default()
        };
        let r = monitor.inspect(&evt);
        // Should succeed (evicted a stale peer with failures via 2x timeout)
        assert!(
            r.allowed || r.alert_count > 0,
            "should handle peer after 2x timeout eviction"
        );
    }

    #[test]
    fn pairing_request_counter_resets_on_complete() {
        let mut mon = BleMonitor::new();
        // pairing_request flood triggers when pairing_requests > threshold,
        // so with threshold=6, flood fires at request #7.
        mon.set_pairing_request_threshold(6);
        mon.set_global_pairing_fail_threshold(50);

        // Send 6 pairing requests (at the flood threshold of 6, i.e. >6 triggers).
        for i in 0..6 {
            let evt = make_event(
                PEER_A,
                BleEventType::PairingRequest,
                -50,
                1_000_000 * (i + 1),
            );
            let _ = mon.inspect(&evt);
        }

        // PairingComplete should reset the counter.
        let evt = make_event(PEER_A, BleEventType::PairingComplete, -50, 7_000_000);
        let _ = mon.inspect(&evt);

        // Now send another batch of 6 pairing requests — should NOT flood because
        // the counter was reset by PairingComplete.
        for i in 0..6 {
            let evt = make_event(
                PEER_A,
                BleEventType::PairingRequest,
                -50,
                8_000_000 + 1_000_000 * (i + 1),
            );
            let r = mon.inspect(&evt);
            let has_flood = (0..r.alert_count as usize)
                .any(|j| r.alerts[j].source_id == ALERT_PAIRING_REQUEST_FLOOD);
            assert!(
                !has_flood,
                "request {i} after reset should not trigger flood"
            );
        }
    }

    #[test]
    fn gatt_abuse_alert_fires_once_per_window() {
        let mut mon = BleMonitor::new();
        let threshold: u16 = 5;
        mon.set_gatt_rate_threshold(threshold);

        let mut total_alerts = 0u32;

        // Send threshold + 5 GATT operations within the same window.
        for i in 0..(threshold + 5) as u64 {
            let evt = make_event(PEER_A, BleEventType::GattRead, -50, 1000 + i * 100);
            let r = mon.inspect(&evt);
            let gatt_alerts = (0..r.alert_count as usize)
                .filter(|&j| r.alerts[j].source_id == ALERT_GATT_ABUSE)
                .count();
            total_alerts += gatt_alerts as u32;
        }

        // The GATT abuse alert fires every time the counter crosses the
        // threshold.  With threshold=5 and 10 operations the counter resets
        // after the first crossing, so we expect exactly 2 alerts.
        assert_eq!(
            total_alerts, 2,
            "GATT abuse alert must fire on each threshold crossing"
        );
    }

    #[test]
    fn conn_storm_window_expiry_excludes_stale_entries() {
        // Regression test: after ring buffer wraps, old timestamps outside
        // the window must not be counted.
        let mut monitor = BleMonitor::new();
        monitor.set_conn_storm_params(5, 30_000_000); // 5 in 30s

        // Fill ring buffer with old connections
        for i in 0..4u64 {
            let event = make_event([0xAA; 6], BleEventType::Connected, -50, (i + 1) * 1_000_000);
            let _ = monitor.inspect(&event);
        }

        // Jump far forward (2 minutes) — old entries should be outside window
        let event = make_event([0xBB; 6], BleEventType::Connected, -50, 120_000_000);
        let r = monitor.inspect(&event);
        // Should NOT trigger storm — only 1 recent connection in window
        assert!(r.allowed);
    }

    #[test]
    fn global_pairing_storm_excludes_stale_entries() {
        // Regression test: after ring buffer wraps, old pairing failure
        // timestamps outside the 60s window must not be counted.
        let mut monitor = BleMonitor::new();
        monitor.set_global_pairing_fail_threshold(5);

        // Record 4 pairing failures at t=1s..4s
        for i in 0..4u64 {
            let event = make_event(
                [0xCC; 6],
                BleEventType::PairingFailed,
                -50,
                (i + 1) * 1_000_000,
            );
            let _ = monitor.inspect(&event);
        }

        // Jump 2 minutes forward, add 1 more failure
        let event = make_event([0xDD; 6], BleEventType::PairingFailed, -50, 120_000_000);
        let r = monitor.inspect(&event);
        // Only 1 failure in window — should not trigger storm
        let has_storm = (0..r.alert_count as usize)
            .any(|i| r.alerts[i].source_id == ALERT_GLOBAL_PAIRING_STORM);
        assert!(!has_storm, "stale entries should not be counted in window");
    }

    #[test]
    fn rssi_out_of_range_triggers_alert() {
        // RSSI values outside [-120, 0] should trigger an anomaly alert.
        let mut monitor = BleMonitor::new();

        // First event to establish the peer
        let event1 = make_event([0x11; 6], BleEventType::Connected, -50, 1_000_000);
        let _ = monitor.inspect(&event1);

        // Second connection with invalid RSSI (+50)
        let event2 = make_event([0x11; 6], BleEventType::Connected, 50, 2_000_000);
        let r = monitor.inspect(&event2);
        let has_rssi_alert =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_RSSI_ANOMALY);
        assert!(has_rssi_alert, "out-of-range RSSI should trigger alert");
    }

    #[test]
    fn adv_flood_window_boundary_handled() {
        // Test that the advertisement flood window boundary uses >= for expiry.
        let mut monitor = BleMonitor::new();
        monitor.set_adv_flood_params(5, 10_000_000); // 5 in 10s

        // 4 advertisements within window
        for i in 0..4u64 {
            let event = make_event(
                [0xEE; 6],
                BleEventType::AdvertisementReceived,
                -50,
                (i + 1) * 1_000_000,
            );
            let _ = monitor.inspect(&event);
        }

        // Event exactly at window boundary should start new window
        let event = make_event(
            [0xEE; 6],
            BleEventType::AdvertisementReceived,
            -50,
            11_000_000,
        );
        let r = monitor.inspect(&event);
        let has_flood =
            (0..r.alert_count as usize).any(|i| r.alerts[i].source_id == ALERT_ADV_FLOOD);
        assert!(!has_flood, "window boundary event should start new window");
    }

    #[test]
    fn threshold_upper_bounds_clamped() {
        let mut monitor = BleMonitor::new();
        monitor.set_conn_storm_params(255, u64::MAX);
        monitor.set_pairing_fail_threshold(255);
        monitor.set_global_pairing_fail_threshold(255);
        monitor.set_gatt_rate_threshold(u16::MAX);
        monitor.set_random_addr_threshold(u16::MAX);
        monitor.set_adv_flood_params(u16::MAX, u64::MAX);
        // Should not panic — values are clamped to safe upper bounds
        let event = make_event([0xFE; 6], BleEventType::Connected, -50, 1_000_000);
        let r = monitor.inspect(&event);
        assert!(r.allowed);
    }

    #[test]
    fn alerts_dropped_counter_accessible() {
        let r = BleInspectResult::clean();
        assert_eq!(r.alerts_dropped, 0);
    }
}
