// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

//! IoT/embedded runtime for `Craton Shield`.
//!
//! Wraps [`CratonShield`] from the core runtime and adds IoT-specific
//! protocol monitors:
//!
//! - **MQTT monitor** — topic allowlist/blocklist, rate limiting, connect
//!   storm detection, `QoS` enforcement, payload size anomaly detection.
//! - **`CoAP` monitor** — URI allowlist/blocklist, method enforcement, rate
//!   limiting, amplification detection.
//! - **BLE monitor** — MAC filtering, connection storm detection, RSSI
//!   anomaly (relay attack), pairing brute-force, GATT abuse.
//! - **Zigbee monitor** — address filtering, PAN ID enforcement, frame type
//!   filtering, replay protection, Trust Center monitoring.
//! - **`LoRa` monitor** — device filtering, replay detection, join flood
//!   detection, ADR monitoring, duty cycle tracking.
//! - **Modbus monitor** — unit ID filtering, function code enforcement,
//!   register range protection, IP filtering, exception flood detection.
//!
//! # Timestamp Source Requirements
//!
//! All `submit_*` methods require a `ts_us` parameter representing the
//! current time in microseconds. Timestamps **MUST** originate from a
//! synchronized clock source (NTP, hardware RTC, GPS PPS).
//! Unsynchronized or attacker-controlled timestamps can defeat
//! time-windowed detection mechanisms (rate limiting, flood detection,
//! replay protection).
//!
//! # Stack Size Warning
//!
//! `EmbeddedShield` is a large struct (30+ KB on default capacity) due to
//! fixed-size arrays. On MCU targets with limited stack (4-16 KB typical),
//! place this in a `static` or use `Box` (if allocator is available).
//! Do **not** allocate it on the stack in interrupt handlers.
//!
//! ```rust,ignore
//! // Recommended: static placement for MCU targets.
//! // Use `cortex_m::singleton!()`, `static_cell::StaticCell`, or a
//! // `Mutex<RefCell<>>` wrapper — avoid bare `static mut` which is
//! // unsound without external synchronization.
//! use static_cell::StaticCell;
//! static SHIELD: StaticCell<EmbeddedShield<MyCrypto>> = StaticCell::new();
//! ```

use vs_ble_monitor::{BleInspectResult, BleMonitor};
use vs_coap_monitor::{CoapInspectResult, CoapMonitor};
use vs_crypto::CryptoProvider;
use vs_lora_monitor::{LoraInspectResult, LoraMonitor};
use vs_modbus_monitor::{ModbusInspectResult, ModbusMonitor};
use vs_mqtt_monitor::{MqttInspectResult, MqttMonitor};
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, PlatformHealth, SubsystemStatus,
    WatchdogAction,
};
use vs_types::{SecurityAlert, VsError};
use vs_types_embedded::MonitorReset;
use vs_types_embedded::{
    AlertCallback, BleEvent, CoapMessage, ConfigAuditLog, ConfigChangeType, LoraMessage,
    ModbusRtuMessage, ModbusTcpMessage, MqttMessage, NoopAlertCallback, TimestampValidator,
    ZigbeeFrame,
};
use vs_zigbee_monitor::{ZigbeeInspectResult, ZigbeeMonitor};

// Re-export for convenience.
pub use vs_ble_monitor;
pub use vs_coap_monitor;
pub use vs_lora_monitor;
pub use vs_modbus_monitor;
pub use vs_mqtt_monitor;
pub use vs_runtime::{self, PlatformConfig as CoreConfig};
pub use vs_types_embedded;
pub use vs_zigbee_monitor;

// ---------------------------------------------------------------------------
// Embedded health extension
// ---------------------------------------------------------------------------

/// Extended health snapshot including `IoT` subsystems.
///
/// # `repr(C)`
///
/// This struct uses `#[repr(C)]` to guarantee a stable, predictable memory
/// layout.  This is required for FFI compatibility: C/C++ firmware, RTOS
/// tasks, and other cross-language consumers read this struct directly
/// through a shared-memory or pointer-based interface.  Without `repr(C)`,
/// the Rust compiler is free to reorder fields, making the layout
/// ABI-incompatible with foreign callers.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EmbeddedHealth {
    /// Core platform health.
    pub core: PlatformHealth,
    /// MQTT monitor status.
    pub mqtt: SubsystemStatus,
    /// `CoAP` monitor status.
    pub coap: SubsystemStatus,
    /// BLE monitor status.
    pub ble: SubsystemStatus,
    /// Zigbee monitor status.
    pub zigbee: SubsystemStatus,
    /// `LoRa` monitor status.
    pub lora: SubsystemStatus,
    /// Modbus monitor status.
    pub modbus: SubsystemStatus,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of recent alerts stored in the ring buffer.
const MAX_RECENT_ALERTS: usize = 32;
const _: () = assert!(
    MAX_RECENT_ALERTS.is_power_of_two(),
    "MAX_RECENT_ALERTS must be power of 2 for bitmask optimization"
);

/// Sentinel value for an empty alert slot (id == 0 means unused).
const EMPTY_ALERT: SecurityAlert = SecurityAlert {
    id: 0,
    severity: vs_types::AlertSeverity::Info,
    source_type: 0,
    source_id: 0,
    payload_hash: vs_types::PayloadHash::ZERO,
    timestamp_us: 0,
};

/// Maximum consecutive alerts with the same `source_id` before callback is throttled.
const MAX_CALLBACK_BURST: u8 = 8;

/// Sliding window for callback throttle (1 second in microseconds).
const CALLBACK_THROTTLE_WINDOW_US: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Blocked-result helpers
// ---------------------------------------------------------------------------
//
// Each `submit_*` method returns one of these when the shield is not
// initialized or the timestamp is invalid.  The `blocked_result!` macro
// eliminates per-protocol copy-paste and makes it trivial to update if new
// fields are added to an `InspectResult` type.

/// Construct a "blocked" (denied, zero-alert) inspect result for a given
/// result type and `source_type` constant.  All seven protocol-specific
/// helpers are generated from this single definition.
///
/// Uses `core::mem::zeroed`-equivalent initialization via byte-zero default
/// for the alerts array to avoid constructing four full `SecurityAlert`
/// values on the stack when `alert_count` is 0 and none will be read.
macro_rules! blocked_result {
    ($result_ty:ident, $source:expr) => {{
        // Construct a single sentinel alert and reuse it for all four slots.
        // This is cheaper than constructing four distinct SecurityAlert values
        // because the compiler can emit a single memcpy/rep-stosd.
        // alert_count = 0 guarantees callers never read these slots.
        const SENTINEL: SecurityAlert = SecurityAlert {
            id: 0,
            severity: vs_types::AlertSeverity::Info,
            source_type: $source,
            source_id: 0,
            payload_hash: vs_types::PayloadHash::ZERO,
            timestamp_us: 0,
        };
        $result_ty {
            allowed: false,
            alert_count: 0,
            alerts: [SENTINEL; 4],
            alerts_dropped: 0,
        }
    }};
}

#[inline]
fn blocked_mqtt_result() -> MqttInspectResult {
    blocked_result!(MqttInspectResult, vs_types_embedded::SOURCE_MQTT)
}

#[inline]
fn blocked_coap_result() -> CoapInspectResult {
    blocked_result!(CoapInspectResult, vs_types_embedded::SOURCE_COAP)
}

#[inline]
fn blocked_ble_result() -> BleInspectResult {
    blocked_result!(BleInspectResult, vs_types_embedded::SOURCE_BLE)
}

#[inline]
fn blocked_zigbee_result() -> ZigbeeInspectResult {
    blocked_result!(ZigbeeInspectResult, vs_types_embedded::SOURCE_ZIGBEE)
}

#[inline]
fn blocked_lora_result() -> LoraInspectResult {
    blocked_result!(LoraInspectResult, vs_types_embedded::SOURCE_LORA)
}

#[inline]
fn blocked_modbus_rtu_result() -> ModbusInspectResult {
    blocked_result!(ModbusInspectResult, vs_types_embedded::SOURCE_MODBUS_RTU)
}

#[inline]
fn blocked_modbus_tcp_result() -> ModbusInspectResult {
    blocked_result!(ModbusInspectResult, vs_types_embedded::SOURCE_MODBUS_TCP)
}

/// Minimum number of inspected messages before health degradation applies.
const HEALTH_MIN_MESSAGES: u64 = 100;

/// Common body for all `submit_*` protocol methods.
///
/// Parameters:
/// - `$self`: the `EmbeddedShield` receiver (`&mut self`)
/// - `$monitor`: field name of the protocol monitor (e.g. `mqtt_monitor`)
/// - `$inspect_method`: method to call on the monitor (e.g. `inspect`, `inspect_rtu`)
/// - `$msg`: the message/event reference to inspect
/// - `$ts_us`: caller-provided timestamp in microseconds
/// - `$blocked_fn`: function returning the blocked result sentinel
/// - `$monitor_bit`: bitmask constant for the active-monitors tracker
macro_rules! submit_body {
    ($self:ident, $monitor:ident, $inspect_method:ident, $msg:expr, $ts_us:expr, $blocked_fn:expr, $monitor_bit:expr) => {{
        if !$self.is_initialized() {
            return $blocked_fn;
        }
        // Reject zero timestamps — they defeat all time-windowed detection.
        if $ts_us == 0 {
            return $blocked_fn;
        }
        $self.active_monitors |= $monitor_bit;
        let result = $self.$monitor.$inspect_method($msg);
        $self.health_dirty = true;
        let n = core::cmp::min(result.alert_count as usize, result.alerts.len());
        for i in 0..n {
            $self.core.route_alert(&result.alerts[i], $ts_us);
            $self.store_recent_alert(&result.alerts[i]);
        }
        result
    }};
}

// ---------------------------------------------------------------------------
// Active monitor bitmask constants
// ---------------------------------------------------------------------------

/// Bitmask bit for the MQTT monitor.
/// (Part of the 8-bit protocol monitor mask: MQTT (0), CoAP (1), BLE (2), Zigbee (3),
/// LoRa (4), Modbus (5), with bits 6-7 reserved for future protocols.)
const MONITOR_MQTT: u8 = 1 << 0;
/// Bitmask bit for the `CoAP` monitor.
const MONITOR_COAP: u8 = 1 << 1;
/// Bitmask bit for the BLE monitor.
const MONITOR_BLE: u8 = 1 << 2;
/// Bitmask bit for the Zigbee monitor.
const MONITOR_ZIGBEE: u8 = 1 << 3;
/// Bitmask bit for the `LoRa` monitor.
const MONITOR_LORA: u8 = 1 << 4;
/// Bitmask bit for the Modbus monitor.
const MONITOR_MODBUS: u8 = 1 << 5;

// ---------------------------------------------------------------------------
// EmbeddedShield
// ---------------------------------------------------------------------------

/// IoT/embedded `Craton Shield` runtime.
///
/// Extends [`CratonShield`] with MQTT, `CoAP`, BLE, Zigbee, `LoRa`, and Modbus
/// protocol monitors.  Suitable for resource-constrained devices (ESP32,
/// STM32, nRF52, etc.).
///
/// The optional `CB` type parameter lets callers install a synchronous
/// [`AlertCallback`] that is invoked for every security alert generated by any
/// protocol monitor.  The default is [`NoopAlertCallback`].  Use
/// [`EmbeddedShield::init`] for the default and
/// [`EmbeddedShield::init_with_callback`] to supply a custom callback.
///
/// # Stack Size Warning
///
/// This struct is large (30+ KB on default capacity). See module-level
/// documentation for guidance on placement in embedded targets.
pub struct EmbeddedShield<C: CryptoProvider, CB: AlertCallback = NoopAlertCallback> {
    core: CratonShield<C>,
    mqtt_monitor: MqttMonitor,
    coap_monitor: CoapMonitor,
    ble_monitor: BleMonitor,
    zigbee_monitor: ZigbeeMonitor,
    lora_monitor: LoraMonitor,
    modbus_monitor: ModbusMonitor,
    mqtt_status: SubsystemStatus,
    coap_status: SubsystemStatus,
    ble_status: SubsystemStatus,
    zigbee_status: SubsystemStatus,
    lora_status: SubsystemStatus,
    modbus_status: SubsystemStatus,
    // Recent alerts ring buffer using sentinel pattern (id == 0 means empty).
    // This avoids the discriminant byte overhead of `Option<SecurityAlert>`
    // (~32 bytes saved, better cache behavior).
    recent_alerts: [SecurityAlert; MAX_RECENT_ALERTS],
    recent_alert_count: u32,
    recent_alert_write_idx: u16,
    // Configuration audit log.
    config_audit: ConfigAuditLog<32>,
    // Alert callback — invoked synchronously for every generated alert.
    alert_callback: CB,
    /// Bitmask of monitors that have received at least one `submit_*` call.
    /// Used by `update_monitor_health` to skip unused monitors.
    active_monitors: u8,
    /// Timestamp of the start of the current callback throttle window.
    callback_window_start_us: u64,
    /// Number of callbacks invoked in the current throttle window.
    callback_window_count: u8,
    /// Validates caller-provided timestamps to detect clock manipulation.
    ///
    /// Callback throttling relies on monotonically increasing timestamps.
    /// Without validation, a caller could supply crafted timestamps to
    /// bypass the sliding-window throttle or defeat time-windowed detection.
    callback_ts_validator: TimestampValidator,
    /// Dirty flag set when a `submit_*` method processes a message, so that
    /// `tick` only calls `update_monitor_health()` when there is new data.
    health_dirty: bool,
}

impl<C: CryptoProvider + Clone> EmbeddedShield<C> {
    /// Initialize the embedded runtime with the default no-op alert callback.
    pub fn init(config: PlatformConfig, crypto: C) -> Result<Self, VsError> {
        EmbeddedShield::init_with_callback(config, crypto, NoopAlertCallback)
    }

    /// Convenience constructor with default crypto.
    ///
    /// Returns `Err` if core platform initialization fails.
    pub fn try_new(config: &PlatformConfig) -> Result<Self, VsError>
    where
        C: Default,
    {
        Self::init(*config, C::default())
    }
}

impl<C: CryptoProvider + Clone, CB: AlertCallback> EmbeddedShield<C, CB> {
    /// Initialize the embedded runtime with a custom alert callback.
    ///
    /// The `alert_callback` is invoked synchronously inside `store_recent_alert`
    /// for every security alert generated by any protocol monitor.  Use
    /// [`EmbeddedShield::init`] or [`NoopAlertCallback`] when no external
    /// action is needed.
    ///
    /// # Callback Requirements
    ///
    /// Callback implementations **MUST** be fast (< 1ms), non-blocking, and
    /// must not panic. A panicking callback will unwind through the monitor
    /// and leave it in an undefined state.
    pub fn init_with_callback(
        config: PlatformConfig,
        crypto: C,
        alert_callback: CB,
    ) -> Result<Self, VsError> {
        let core = CratonShield::init(config, crypto)?;
        Ok(Self {
            core,
            mqtt_monitor: MqttMonitor::new(),
            coap_monitor: CoapMonitor::new(),
            ble_monitor: BleMonitor::new(),
            zigbee_monitor: ZigbeeMonitor::new(),
            lora_monitor: LoraMonitor::new(),
            modbus_monitor: ModbusMonitor::new(),
            mqtt_status: SubsystemStatus::Ready,
            coap_status: SubsystemStatus::Ready,
            ble_status: SubsystemStatus::Ready,
            zigbee_status: SubsystemStatus::Ready,
            lora_status: SubsystemStatus::Ready,
            modbus_status: SubsystemStatus::Ready,
            recent_alerts: [EMPTY_ALERT; MAX_RECENT_ALERTS],
            recent_alert_count: 0,
            recent_alert_write_idx: 0,
            config_audit: ConfigAuditLog::new(),
            alert_callback,
            active_monitors: 0,
            callback_window_start_us: 0,
            callback_window_count: 0,
            callback_ts_validator: TimestampValidator::new(),
            health_dirty: false,
        })
    }

    /// Returns a reference to the installed alert callback.
    #[inline]
    pub fn alert_callback(&self) -> &CB {
        &self.alert_callback
    }

    /// Periodic tick — delegates to core and updates monitor health.
    ///
    /// Monitor health is only updated when the core tick succeeds; a failed
    /// tick preserves the previous health status to avoid masking errors.
    pub fn tick(&mut self, ts_us: u64) -> Result<(), VsError> {
        let r = self.core.tick(ts_us);
        if r.is_ok() && self.health_dirty {
            self.update_monitor_health();
            self.health_dirty = false;
        }
        r
    }

    /// Store an alert in the recent alerts ring buffer and invoke the
    /// installed [`AlertCallback`].
    ///
    /// The callback is suppressed when the alert's timestamp fails
    /// monotonicity validation (see [`TimestampValidator`]), as a
    /// suspicious clock value could be used to manipulate the
    /// sliding-window throttle.
    #[inline]
    fn store_recent_alert(&mut self, alert: &SecurityAlert) {
        let idx = self.recent_alert_write_idx as usize;
        self.recent_alerts[idx] = *alert;
        self.recent_alert_write_idx = ((idx + 1) & (MAX_RECENT_ALERTS - 1)) as u16;
        self.recent_alert_count = self.recent_alert_count.saturating_add(1);

        // Validate the caller-provided timestamp before using it to drive
        // the callback throttle window.  Zero timestamps are already
        // rejected at the submit_* call sites, but defend-in-depth here
        // against large backward/forward jumps that could reset or skip the
        // throttle window.
        if alert.timestamp_us == 0 || !self.callback_ts_validator.validate(alert.timestamp_us) {
            return;
        }

        // Sliding-window callback throttle: reset the window when the
        // current alert's timestamp is beyond the previous window.
        // Guard against large forward timestamp jumps resetting throttle.
        // If the jump exceeds 2x the window, it's likely a clock manipulation
        // attempt -- don't reset the burst counter, just update the window start.
        let jump = alert
            .timestamp_us
            .saturating_sub(self.callback_window_start_us);
        if jump > CALLBACK_THROTTLE_WINDOW_US {
            self.callback_window_start_us = alert.timestamp_us;
            if jump <= CALLBACK_THROTTLE_WINDOW_US * 2 {
                self.callback_window_count = 0;
            }
            // else: large jump, keep count to throttle potential abuse
        }
        self.callback_window_count = self.callback_window_count.saturating_add(1);
        if self.callback_window_count <= MAX_CALLBACK_BURST {
            self.alert_callback.on_alert(alert, alert.timestamp_us);
        }
    }

    // -----------------------------------------------------------------------
    // CAN / Ethernet (pass-through to core)
    // -----------------------------------------------------------------------
    //
    // # Timestamp Source Requirements
    //
    // All `submit_*` methods require a `ts_us` parameter representing the
    // current time in microseconds. Timestamps **MUST** originate from a
    // synchronized clock source (NTP, hardware RTC, GPS PPS).
    // Unsynchronized or attacker-controlled timestamps can defeat
    // time-windowed detection mechanisms (rate limiting, flood detection,
    // replay protection).

    /// Submit a CAN frame for IDS inspection.
    pub fn submit_can_frame(&mut self, frame: &CanFrame, ts_us: u64) -> Result<(), VsError> {
        if !self.is_initialized() {
            return Err(VsError::NotInitialized);
        }
        if ts_us == 0 {
            return Err(VsError::InvalidInput);
        }
        self.core.submit_can_frame(frame, ts_us)
    }

    /// Submit an Ethernet packet for IDS + firewall inspection.
    pub fn submit_eth_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Result<(), VsError> {
        if !self.is_initialized() {
            return Err(VsError::NotInitialized);
        }
        if ts_us == 0 {
            return Err(VsError::InvalidInput);
        }
        self.core.submit_eth_packet(pkt, ts_us)
    }

    // -----------------------------------------------------------------------
    // MQTT
    // -----------------------------------------------------------------------

    /// Submit an MQTT message for inspection.
    ///
    /// Returns a clean result if the system has been shut down.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_mqtt_message(&mut self, msg: &mut MqttMessage, ts_us: u64) -> MqttInspectResult {
        msg.timestamp_us = ts_us;
        submit_body!(
            self,
            mqtt_monitor,
            inspect,
            msg,
            ts_us,
            blocked_mqtt_result(),
            MONITOR_MQTT
        )
    }

    // -----------------------------------------------------------------------
    // CoAP
    // -----------------------------------------------------------------------

    /// Submit a `CoAP` message for inspection.
    ///
    /// Returns a clean result if the system has been shut down.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_coap_message(&mut self, msg: &mut CoapMessage, ts_us: u64) -> CoapInspectResult {
        msg.timestamp_us = ts_us;
        submit_body!(
            self,
            coap_monitor,
            inspect,
            msg,
            ts_us,
            blocked_coap_result(),
            MONITOR_COAP
        )
    }

    /// Check for `CoAP` amplification attack on a response.
    pub fn check_coap_amplification(
        &mut self,
        message_id: u16,
        token: &[u8],
        response_payload_len: u16,
        ts_us: u64,
    ) -> Option<SecurityAlert> {
        if !self.is_initialized() {
            return None;
        }
        // Reject zero timestamps — they defeat all time-windowed detection.
        if ts_us == 0 {
            return None;
        }
        let alert =
            self.coap_monitor
                .check_amplification(message_id, token, response_payload_len, ts_us);
        if let Some(ref a) = alert {
            self.core.route_alert(a, ts_us);
            self.store_recent_alert(a);
        }
        alert
    }

    // -----------------------------------------------------------------------
    // BLE
    // -----------------------------------------------------------------------

    /// Submit a BLE event for inspection.
    ///
    /// Returns a clean result if the system has been shut down.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_ble_event(&mut self, event: &mut BleEvent, ts_us: u64) -> BleInspectResult {
        event.timestamp_us = ts_us;
        submit_body!(
            self,
            ble_monitor,
            inspect,
            event,
            ts_us,
            blocked_ble_result(),
            MONITOR_BLE
        )
    }

    // -----------------------------------------------------------------------
    // Zigbee
    // -----------------------------------------------------------------------

    /// Submit a Zigbee frame for inspection.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_zigbee_frame(
        &mut self,
        frame: &mut ZigbeeFrame,
        ts_us: u64,
    ) -> ZigbeeInspectResult {
        frame.timestamp_us = ts_us;
        submit_body!(
            self,
            zigbee_monitor,
            inspect,
            frame,
            ts_us,
            blocked_zigbee_result(),
            MONITOR_ZIGBEE
        )
    }

    // -----------------------------------------------------------------------
    // LoRa
    // -----------------------------------------------------------------------

    /// Submit a `LoRa` message for inspection.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_lora_message(&mut self, msg: &mut LoraMessage, ts_us: u64) -> LoraInspectResult {
        msg.timestamp_us = ts_us;
        submit_body!(
            self,
            lora_monitor,
            inspect,
            msg,
            ts_us,
            blocked_lora_result(),
            MONITOR_LORA
        )
    }

    // -----------------------------------------------------------------------
    // Modbus
    // -----------------------------------------------------------------------

    /// Submit a Modbus RTU message for inspection.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_modbus_rtu(
        &mut self,
        msg: &mut ModbusRtuMessage,
        ts_us: u64,
    ) -> ModbusInspectResult {
        msg.timestamp_us = ts_us;
        submit_body!(
            self,
            modbus_monitor,
            inspect_rtu,
            msg,
            ts_us,
            blocked_modbus_rtu_result(),
            MONITOR_MODBUS
        )
    }

    /// Submit a Modbus TCP message for inspection.
    ///
    /// # Timestamp Requirements
    ///
    /// `ts_us` **MUST** originate from a synchronized clock source (NTP,
    /// hardware RTC, GPS PPS). Unsynchronized or attacker-controlled
    /// timestamps can defeat time-windowed detection mechanisms.
    pub fn submit_modbus_tcp(
        &mut self,
        msg: &mut ModbusTcpMessage,
        ts_us: u64,
    ) -> ModbusInspectResult {
        msg.rtu.timestamp_us = ts_us;
        submit_body!(
            self,
            modbus_monitor,
            inspect_tcp,
            msg,
            ts_us,
            blocked_modbus_tcp_result(),
            MONITOR_MODBUS
        )
    }

    // -----------------------------------------------------------------------
    // Health & accessors
    // -----------------------------------------------------------------------

    /// Return the extended embedded health snapshot.
    pub fn health_status(&self) -> EmbeddedHealth {
        EmbeddedHealth {
            core: self.core.health_status(),
            mqtt: self.mqtt_status,
            coap: self.coap_status,
            ble: self.ble_status,
            zigbee: self.zigbee_status,
            lora: self.lora_status,
            modbus: self.modbus_status,
        }
    }

    /// Check if the watchdog has expired.
    pub fn check_watchdog(&mut self, ts_us: u64) -> Option<WatchdogAction> {
        self.core.check_watchdog(ts_us)
    }

    /// Graceful shutdown — resets all monitor state and flushes buffers.
    pub fn shutdown(&mut self) {
        self.core.shutdown();
        // Reset all monitor runtime state (preserves configuration).
        self.mqtt_monitor.reset_state();
        self.coap_monitor.reset_state();
        self.ble_monitor.reset_state();
        self.zigbee_monitor.reset_state();
        self.lora_monitor.reset_state();
        self.modbus_monitor.reset_state();
        self.mqtt_status = SubsystemStatus::NotInitialized;
        self.coap_status = SubsystemStatus::NotInitialized;
        self.ble_status = SubsystemStatus::NotInitialized;
        self.zigbee_status = SubsystemStatus::NotInitialized;
        self.lora_status = SubsystemStatus::NotInitialized;
        self.modbus_status = SubsystemStatus::NotInitialized;
        // Clear recent alerts ring buffer.
        self.recent_alerts = [EMPTY_ALERT; MAX_RECENT_ALERTS];
        self.recent_alert_count = 0;
        self.recent_alert_write_idx = 0;
        self.callback_window_start_us = 0;
        self.callback_window_count = 0;
        self.callback_ts_validator.reset();
        self.active_monitors = 0;
        self.health_dirty = false;
    }

    /// Returns `true` if init completed and shutdown has not been called.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.core.is_initialized()
    }

    /// Returns the monotonic tick counter.
    #[inline]
    pub fn tick_count(&self) -> u64 {
        self.core.tick_count()
    }

    /// Returns a reference to the core runtime.
    pub fn core(&self) -> &CratonShield<C> {
        &self.core
    }

    /// Returns a mutable reference to the core runtime.
    ///
    /// # Security Warning
    ///
    /// Direct mutation of the core runtime bypasses alert routing, health
    /// tracking, and audit logging performed by `EmbeddedShield`. Prefer
    /// using the typed `submit_*` methods and configuration accessors instead.
    /// This method is provided for advanced use cases only.
    #[cfg(test)]
    #[deprecated(
        note = "Direct core mutation bypasses security encapsulation. Use typed submit_*/config methods. Feature renamed from unsafe-access to direct-access in v0.8."
    )]
    pub fn core_mut(&mut self) -> &mut CratonShield<C> {
        &mut self.core
    }

    /// Returns a reference to the MQTT monitor.
    pub fn mqtt_monitor(&self) -> &MqttMonitor {
        &self.mqtt_monitor
    }

    /// Configure the MQTT monitor via a closure.
    ///
    /// Preferred over the deprecated `mqtt_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_mqtt<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut MqttMonitor) -> Result<(), VsError>,
    {
        f(&mut self.mqtt_monitor)
    }

    /// Configure the `CoAP` monitor via a closure.
    ///
    /// Preferred over the deprecated `coap_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_coap<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut CoapMonitor) -> Result<(), VsError>,
    {
        f(&mut self.coap_monitor)
    }

    /// Configure the BLE monitor via a closure.
    ///
    /// Preferred over the deprecated `ble_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_ble<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut BleMonitor) -> Result<(), VsError>,
    {
        f(&mut self.ble_monitor)
    }

    /// Configure the Zigbee monitor via a closure.
    ///
    /// Preferred over the deprecated `zigbee_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_zigbee<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut ZigbeeMonitor) -> Result<(), VsError>,
    {
        f(&mut self.zigbee_monitor)
    }

    /// Configure the `LoRa` monitor via a closure.
    ///
    /// Preferred over the deprecated `lora_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_lora<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut LoraMonitor) -> Result<(), VsError>,
    {
        f(&mut self.lora_monitor)
    }

    /// Configure the Modbus monitor via a closure.
    ///
    /// Preferred over the deprecated `modbus_monitor_mut` accessor. The closure
    /// receives a mutable reference to the monitor and should return `Ok(())`
    /// on success.
    pub fn configure_modbus<F>(&mut self, f: F) -> Result<(), VsError>
    where
        F: FnOnce(&mut ModbusMonitor) -> Result<(), VsError>,
    {
        f(&mut self.modbus_monitor)
    }

    /// Returns a mutable reference to the MQTT monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_mqtt() instead."
    )]
    pub fn mqtt_monitor_mut(&mut self) -> &mut MqttMonitor {
        &mut self.mqtt_monitor
    }

    /// Returns a reference to the `CoAP` monitor.
    pub fn coap_monitor(&self) -> &CoapMonitor {
        &self.coap_monitor
    }

    /// Returns a mutable reference to the `CoAP` monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_coap() instead."
    )]
    pub fn coap_monitor_mut(&mut self) -> &mut CoapMonitor {
        &mut self.coap_monitor
    }

    /// Returns a reference to the BLE monitor.
    pub fn ble_monitor(&self) -> &BleMonitor {
        &self.ble_monitor
    }

    /// Returns a mutable reference to the BLE monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_ble() instead."
    )]
    pub fn ble_monitor_mut(&mut self) -> &mut BleMonitor {
        &mut self.ble_monitor
    }

    /// Returns a reference to the Zigbee monitor.
    pub fn zigbee_monitor(&self) -> &ZigbeeMonitor {
        &self.zigbee_monitor
    }

    /// Returns a mutable reference to the Zigbee monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_zigbee() instead."
    )]
    pub fn zigbee_monitor_mut(&mut self) -> &mut ZigbeeMonitor {
        &mut self.zigbee_monitor
    }

    /// Returns a reference to the `LoRa` monitor.
    pub fn lora_monitor(&self) -> &LoraMonitor {
        &self.lora_monitor
    }

    /// Returns a mutable reference to the `LoRa` monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_lora() instead."
    )]
    pub fn lora_monitor_mut(&mut self) -> &mut LoraMonitor {
        &mut self.lora_monitor
    }

    /// Returns a reference to the Modbus monitor.
    pub fn modbus_monitor(&self) -> &ModbusMonitor {
        &self.modbus_monitor
    }

    /// Returns a mutable reference to the Modbus monitor.
    #[cfg(test)]
    #[deprecated(
        note = "Direct monitor mutation bypasses audit logging. Use configure_modbus() instead."
    )]
    pub fn modbus_monitor_mut(&mut self) -> &mut ModbusMonitor {
        &mut self.modbus_monitor
    }

    // -----------------------------------------------------------------------
    // Recent alerts ring buffer
    // -----------------------------------------------------------------------

    /// Returns a reference to the recent alerts ring buffer.
    ///
    /// Slots with `id == 0` are empty (sentinel pattern). Use
    /// [`Self::is_alert_empty`] or check `alert.id != 0` to filter active entries.
    #[inline]
    pub fn recent_alerts(&self) -> &[SecurityAlert] {
        &self.recent_alerts
    }

    /// Returns `true` if the alert slot is empty (sentinel value).
    #[inline]
    pub fn is_alert_empty(alert: &SecurityAlert) -> bool {
        alert.id == 0
    }

    /// Return the number of non-empty recent alerts currently stored.
    ///
    /// Filters out sentinel slots (id == 0) so callers don't need to
    /// manually check each alert.
    pub fn recent_alert_count_valid(&self) -> usize {
        self.recent_alerts.iter().filter(|a| a.id != 0).count()
    }

    /// Returns the total number of alerts that have been stored (may exceed
    /// `MAX_RECENT_ALERTS` if the buffer has wrapped).
    #[inline]
    pub fn recent_alert_total(&self) -> u32 {
        self.recent_alert_count
    }

    /// Drain recent alerts into `buf`, returning the number of alerts written.
    ///
    /// The internal ring buffer is cleared after this call.
    /// The callback throttle window and timestamp validator are intentionally
    /// **preserved** across drains so that an attacker who triggers frequent
    /// drains cannot reset the sliding window to bypass callback rate limiting.
    pub fn drain_recent_alerts_into(&mut self, buf: &mut [SecurityAlert]) -> usize {
        let count = core::cmp::min(self.recent_alert_count as usize, MAX_RECENT_ALERTS);
        let to_copy = core::cmp::min(count, buf.len());
        // Copy from ring buffer in order (oldest first).
        let start = if count >= MAX_RECENT_ALERTS {
            self.recent_alert_write_idx as usize
        } else {
            0
        };
        for (i, slot) in buf.iter_mut().enumerate().take(to_copy) {
            let src_idx = (start + i) % MAX_RECENT_ALERTS;
            *slot = self.recent_alerts[src_idx];
        }
        self.recent_alerts = [EMPTY_ALERT; MAX_RECENT_ALERTS];
        self.recent_alert_count = 0;
        self.recent_alert_write_idx = 0;
        to_copy
    }

    /// Drain all recent alerts, returning the count and the buffer contents.
    ///
    /// Prefer [`Self::drain_recent_alerts_into`] to avoid copying the full array
    /// onto the stack.
    #[deprecated(note = "Use drain_recent_alerts_into() to avoid large stack allocation")]
    pub fn drain_recent_alerts(&mut self) -> (usize, [SecurityAlert; MAX_RECENT_ALERTS]) {
        let count = core::cmp::min(self.recent_alert_count as usize, MAX_RECENT_ALERTS);
        let buf = self.recent_alerts;
        self.recent_alerts = [EMPTY_ALERT; MAX_RECENT_ALERTS];
        self.recent_alert_count = 0;
        self.recent_alert_write_idx = 0;
        (count, buf)
    }

    // -----------------------------------------------------------------------
    // Configuration audit log
    // -----------------------------------------------------------------------

    /// Returns a reference to the configuration audit log.
    pub fn config_audit(&self) -> &ConfigAuditLog<32> {
        &self.config_audit
    }

    /// Record a configuration change in the audit log.
    ///
    /// Does nothing if the system is not initialized or the timestamp is zero.
    pub fn record_config_change(
        &mut self,
        source_type: u8,
        change_type: ConfigChangeType,
        ts_us: u64,
    ) {
        if !self.is_initialized() {
            return;
        }
        if ts_us == 0 {
            return;
        }
        self.config_audit.record(source_type, change_type, ts_us);
    }

    // -----------------------------------------------------------------------
    // Monitor health
    // -----------------------------------------------------------------------

    /// Update monitor health status based on alert rate thresholds.
    ///
    /// If a monitor's `total_alerts / total_inspected` ratio exceeds 0.5
    /// over at least 100 inspected messages, its status
    /// is set to [`SubsystemStatus::Degraded`].
    pub fn update_monitor_health(&mut self) {
        if !self.is_initialized() {
            return; // Don't overwrite shutdown state
        }
        // Only query monitors that have received at least one submit call.
        // This avoids unnecessary work for protocols not in use.
        if self.active_monitors & MONITOR_MQTT != 0 {
            self.mqtt_status = Self::compute_health(
                self.mqtt_monitor.total_inspected(),
                self.mqtt_monitor.total_alerts(),
                self.mqtt_status,
            );
        }
        if self.active_monitors & MONITOR_COAP != 0 {
            self.coap_status = Self::compute_health(
                self.coap_monitor.total_inspected(),
                self.coap_monitor.total_alerts(),
                self.coap_status,
            );
        }
        if self.active_monitors & MONITOR_BLE != 0 {
            self.ble_status = Self::compute_health(
                self.ble_monitor.total_inspected(),
                self.ble_monitor.total_alerts(),
                self.ble_status,
            );
        }
        if self.active_monitors & MONITOR_ZIGBEE != 0 {
            self.zigbee_status = Self::compute_health(
                self.zigbee_monitor.total_inspected(),
                self.zigbee_monitor.total_alerts(),
                self.zigbee_status,
            );
        }
        if self.active_monitors & MONITOR_LORA != 0 {
            self.lora_status = Self::compute_health(
                self.lora_monitor.total_inspected(),
                self.lora_monitor.total_alerts(),
                self.lora_status,
            );
        }
        if self.active_monitors & MONITOR_MODBUS != 0 {
            self.modbus_status = Self::compute_health(
                self.modbus_monitor.total_inspected(),
                self.modbus_monitor.total_alerts(),
                self.modbus_status,
            );
        }
    }

    /// Compute health status from inspection/alert counts.
    ///
    /// Transitions to `Degraded` when `total_alerts > total_inspected / 2`.
    /// Recovers back to `Ready` when a previously `Degraded` monitor's ratio
    /// drops below 1/4 (`total_alerts * 4 < total_inspected`), providing
    /// hysteresis to avoid rapid status oscillation.
    #[inline]
    fn compute_health(
        total_inspected: u64,
        total_alerts: u64,
        current: SubsystemStatus,
    ) -> SubsystemStatus {
        if total_inspected >= HEALTH_MIN_MESSAGES && (total_alerts << 1) > total_inspected {
            SubsystemStatus::Degraded
        } else if matches!(current, SubsystemStatus::Degraded)
            && (total_alerts << 2) < total_inspected
        {
            // Recovered: alert ratio dropped below 25%.
            SubsystemStatus::Ready
        } else {
            current
        }
    }

    /// Returns the number of entries in the event log.
    pub fn event_log_count(&self) -> u64 {
        self.core.event_log_count()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;
    use super::*;
    use alloc::boxed::Box;
    use vs_mqtt_monitor::{QosPolicy, TopicAction};
    use vs_types_embedded::{MqttPacketType, MqttQoS};

    /// Allocate `EmbeddedShield` inside a thread with a large stack.
    /// The struct is ~30+ KB (more with capacity-large/xl) and exceeds
    /// the default test-thread stack on some platforms.
    fn make_shield() -> Box<EmbeddedShield<TestCrypto>> {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                Box::new(EmbeddedShield::init(PlatformConfig::default(), TestCrypto).unwrap())
            })
            .unwrap()
            .join()
            .unwrap()
    }

    /// Same as [`make_shield`] but with a callback.
    fn make_shield_with_callback<C: AlertCallback + Send + 'static>(
        cb: C,
    ) -> Box<EmbeddedShield<TestCrypto, C>> {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let config = PlatformConfig::default();
                Box::new(EmbeddedShield::init_with_callback(config, TestCrypto, cb).unwrap())
            })
            .unwrap()
            .join()
            .unwrap()
    }

    #[derive(Clone)]
    struct TestCrypto;

    impl CryptoProvider for TestCrypto {
        fn aes_gcm_encrypt(
            &self,
            _: vs_crypto::KeyId,
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
            _: vs_crypto::KeyId,
            _: &[u8; 12],
            _: &[u8],
            _: &[u8],
            _: &[u8; 16],
            _: &mut [u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            // Input-dependent non-zero output so self_test() passes all three
            // checks: non-zero, deterministic, and collision-resistant.
            let mut h: u32 = 0x811c_9dc5;
            for &b in data {
                h ^= b as u32;
                h = h.wrapping_mul(0x0100_0193);
            }
            let bytes = h.to_le_bytes();
            for (i, out) in hash_out.iter_mut().enumerate() {
                *out = bytes[i % 4] ^ (i as u8);
            }
            Ok(())
        }
        fn hmac_sha256(
            &self,
            _: vs_crypto::KeyId,
            _: &[u8],
            mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            *mac_out = [0xAA; 32];
            Ok(())
        }
        fn ecdh_derive_shared(
            &self,
            _: vs_crypto::KeyId,
            _: &[u8; 65],
            _: &mut [u8; 32],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn sign_p256(
            &self,
            _: vs_crypto::KeyId,
            _: &[u8; 32],
            _: &mut [u8; 64],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], sig: &[u8; 64]) -> Result<bool, VsError> {
            // Return false for all-zero signatures (C1 fix: test invalid sigs).
            if sig.iter().all(|&b| b == 0) {
                Ok(false)
            } else {
                Ok(true)
            }
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            // Must produce non-degenerate output: the core RNG health check
            // rejects buffers where every byte is identical.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x42);
            }
            Ok(())
        }
        fn delete_key(&mut self, _: vs_crypto::KeyId) -> Result<(), VsError> {
            Ok(())
        }
        fn generate_key(
            &mut self,
            _: vs_crypto::KeyId,
            _: vs_crypto::KeyType,
        ) -> Result<(), VsError> {
            Ok(())
        }
    }

    impl Default for TestCrypto {
        fn default() -> Self {
            Self
        }
    }

    #[test]
    fn embedded_init_succeeds() {
        let shield = make_shield();
        assert!(shield.is_initialized());
    }

    #[test]
    fn embedded_health_all_ready() {
        let shield = make_shield();
        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::Ready);
        assert_eq!(h.coap, SubsystemStatus::Ready);
        assert_eq!(h.ble, SubsystemStatus::Ready);
    }

    #[test]
    fn embedded_shutdown() {
        let mut shield = make_shield();
        shield.shutdown();
        assert!(!shield.is_initialized());
        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::NotInitialized);
        assert_eq!(h.coap, SubsystemStatus::NotInitialized);
        assert_eq!(h.ble, SubsystemStatus::NotInitialized);
    }

    #[test]
    #[allow(deprecated)]
    fn embedded_mqtt_integration() {
        let mut shield = make_shield();

        shield
            .mqtt_monitor_mut()
            .add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 0)
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos: MqttQoS::AtMostOnce,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let topic = b"sensors/temp";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        let result = shield.submit_mqtt_message(&mut msg, 1000);
        assert!(result.allowed);
    }

    #[test]
    fn embedded_ble_integration() {
        let mut shield = make_shield();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };

        let result = shield.submit_ble_event(&mut event, 1000);
        assert!(result.allowed);
    }

    #[test]
    fn embedded_try_new_constructor() {
        let shield: Box<EmbeddedShield<TestCrypto>> = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let config = PlatformConfig::default();
                Box::new(EmbeddedShield::try_new(&config).unwrap())
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(shield.is_initialized());
    }

    #[test]
    fn embedded_tick() {
        let mut shield = make_shield();
        shield.tick(1000).unwrap();
        assert_eq!(shield.tick_count(), 1);
    }

    #[test]
    fn embedded_event_log_count() {
        let shield = make_shield();
        assert_eq!(shield.event_log_count(), 0);
    }

    #[test]
    fn embedded_coap_integration() {
        let mut shield = make_shield();

        let mut msg = vs_types_embedded::CoapMessage::default();
        let uri = b"/sensors/temp";
        msg.uri[..uri.len()].copy_from_slice(uri);
        msg.uri_len = uri.len() as u8;
        msg.method = vs_types_embedded::CoapMethod::Get;
        msg.timestamp_us = 1000;
        msg.payload_len = 10;

        let result = shield.submit_coap_message(&mut msg, 1000);
        assert!(result.allowed);
    }

    #[test]
    #[allow(deprecated)]
    fn embedded_coap_amplification() {
        let mut shield = make_shield();
        shield.coap_monitor_mut().set_amplification_threshold(5);

        let mut msg = vs_types_embedded::CoapMessage {
            payload_len: 4,
            message_id: 42,
            token_len: 1,
            timestamp_us: 1000,
            ..vs_types_embedded::CoapMessage::default()
        };
        msg.token[0] = 0x01;
        let _ = shield.submit_coap_message(&mut msg, 1000);

        let alert = shield.check_coap_amplification(42, &[0x01], 500, 2000);
        assert!(alert.is_some());
    }

    #[test]
    fn embedded_watchdog() {
        let mut shield = make_shield();
        shield.tick(0).unwrap();
        assert!(shield.check_watchdog(500_000).is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn embedded_accessor_methods() {
        let mut shield = make_shield();
        let _ = shield.core();
        let _ = shield.core_mut();
        let _ = shield.mqtt_monitor();
        let _ = shield.mqtt_monitor_mut();
        let _ = shield.coap_monitor();
        let _ = shield.coap_monitor_mut();
        let _ = shield.ble_monitor();
        let _ = shield.ble_monitor_mut();
    }

    #[test]
    #[allow(deprecated)]
    fn embedded_ble_blocked_event_routes_alert() {
        let mut shield = make_shield();
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xBB, 0xBB, 0xBB, 0x01, 0x02, 0x03],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xBB, 0xBB, 0xBB, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };
        let r = shield.submit_ble_event(&mut event, 1000);
        assert!(!r.allowed);
        assert!(shield.event_log_count() > 0);
    }

    #[test]
    #[allow(deprecated)]
    fn embedded_mqtt_blocked_routes_alert() {
        let mut shield = make_shield();
        shield
            .mqtt_monitor_mut()
            .add_rule(
                b"admin/#",
                vs_mqtt_monitor::TopicAction::Block,
                vs_mqtt_monitor::QosPolicy::Any,
                0,
            )
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let topic = b"admin/secret";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        let r = shield.submit_mqtt_message(&mut msg, 1000);
        assert!(!r.allowed);
        assert!(shield.event_log_count() > 0);
    }

    // -----------------------------------------------------------------------
    // CAN / Ethernet pass-through (coverage for delegated methods)
    // -----------------------------------------------------------------------

    #[test]
    fn embedded_submit_can_frame() {
        let mut shield = make_shield();
        let frame = vs_runtime::CanFrame {
            id: 0x123,
            is_extended: false,
            is_fd: false,
            dlc: 8,
            data: [0u8; 64],
        };
        // Core CAN IDS may return an error if the IDS engine has no
        // rules configured — verify the call doesn't panic.
        let _result = shield.submit_can_frame(&frame, 1000);
    }

    #[test]
    fn embedded_submit_eth_packet() {
        let mut shield = make_shield();
        let payload = [0u8; 64];
        let pkt = vs_runtime::EthPacket {
            src_mac: [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(80),
            payload: &payload,
        };
        // Core Ethernet IDS may return an error if no firewall rules
        // are configured — verify the call doesn't panic.
        let _result = shield.submit_eth_packet(&pkt, 1000);
    }

    // -----------------------------------------------------------------------
    // C1 fix: test crypto verify_p256 returning false
    // -----------------------------------------------------------------------

    #[test]
    fn test_crypto_verify_p256_rejects_zero_signature() {
        let crypto = TestCrypto;
        let pub_key = [0u8; 65];
        let msg_hash = [0u8; 32];
        let zero_sig = [0u8; 64];
        let result = crypto.verify_p256(&pub_key, &msg_hash, &zero_sig).unwrap();
        assert!(!result, "zero signature should be rejected");
    }

    #[test]
    fn test_crypto_verify_p256_accepts_nonzero_signature() {
        let crypto = TestCrypto;
        let pub_key = [0u8; 65];
        let msg_hash = [0u8; 32];
        let nonzero_sig = [0x01; 64];
        let result = crypto
            .verify_p256(&pub_key, &msg_hash, &nonzero_sig)
            .unwrap();
        assert!(result, "nonzero signature should be accepted");
    }

    // -----------------------------------------------------------------------
    // CoAP amplification with token (new API)
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn embedded_coap_amplification_with_token() {
        let mut shield = make_shield();
        shield.coap_monitor_mut().set_amplification_threshold(5);

        let mut msg = vs_types_embedded::CoapMessage {
            payload_len: 4,
            message_id: 42,
            token_len: 2,
            timestamp_us: 1000,
            ..vs_types_embedded::CoapMessage::default()
        };
        msg.token[0] = 0xAB;
        msg.token[1] = 0xCD;
        let _ = shield.submit_coap_message(&mut msg, 1000);

        // Correct token matches.
        let alert = shield.check_coap_amplification(42, &[0xAB, 0xCD], 500, 2000);
        assert!(alert.is_some());

        // Wrong token does not match.
        let alert2 = shield.check_coap_amplification(42, &[0xFF, 0xFF], 500, 3000);
        assert!(alert2.is_none());
    }

    // -----------------------------------------------------------------------
    // Recent alerts ring buffer
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn recent_alerts_stores_alerts() {
        let mut shield = make_shield();

        // Block a BLE MAC so that submit generates an alert.
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xBB, 0xBB, 0xBB, 0x01, 0x02, 0x03],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xBB, 0xBB, 0xBB, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };

        assert_eq!(shield.recent_alert_total(), 0);
        let _ = shield.submit_ble_event(&mut event, 1000);
        assert!(shield.recent_alert_total() > 0);
        // At least one alert should be stored.
        assert!(shield.recent_alerts().iter().any(|a| a.id != 0));
    }

    #[test]
    #[allow(deprecated)]
    fn recent_alerts_ring_buffer_wraps() {
        let mut shield = make_shield();

        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xCC, 0xCC, 0xCC, 0x01, 0x02, 0x03],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xCC, 0xCC, 0xCC, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };

        // Submit more than MAX_RECENT_ALERTS times to wrap the buffer.
        for i in 0..40u64 {
            let _ = shield.submit_ble_event(&mut event, 1000 + i);
        }

        // Count should saturate or accumulate, buffer should be full.
        assert!(shield.recent_alert_total() >= 32);
        let filled = shield.recent_alerts().iter().filter(|a| a.id != 0).count();
        assert_eq!(filled, MAX_RECENT_ALERTS);
    }

    #[test]
    #[allow(deprecated)]
    fn drain_recent_alerts_clears_buffer() {
        let mut shield = make_shield();

        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xDD, 0xDD, 0xDD, 0x01, 0x02, 0x03],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xDD, 0xDD, 0xDD, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };

        let _ = shield.submit_ble_event(&mut event, 1000);
        let (count, buf) = shield.drain_recent_alerts();
        assert!(count > 0);
        assert!(buf.iter().any(|a| a.id != 0));

        // After drain, buffer should be empty.
        assert_eq!(shield.recent_alert_total(), 0);
        assert!(shield.recent_alerts().iter().all(|a| a.id == 0));
    }

    // -----------------------------------------------------------------------
    // Configuration audit log
    // -----------------------------------------------------------------------

    #[test]
    fn config_audit_log_records_changes() {
        let mut shield = make_shield();
        assert!(shield.config_audit().is_empty());

        shield.record_config_change(
            vs_types_embedded::SOURCE_MQTT,
            ConfigChangeType::RuleAdded,
            1000,
        );
        assert_eq!(shield.config_audit().len(), 1);

        let entry = shield.config_audit().get(0).unwrap();
        assert_eq!(entry.source_type, vs_types_embedded::SOURCE_MQTT);
        assert_eq!(entry.change_type, ConfigChangeType::RuleAdded);
        assert_eq!(entry.timestamp_us, 1000);
    }

    #[test]
    fn config_audit_log_multiple_entries() {
        let mut shield = make_shield();

        shield.record_config_change(
            vs_types_embedded::SOURCE_BLE,
            ConfigChangeType::ParameterChanged,
            2000,
        );
        shield.record_config_change(
            vs_types_embedded::SOURCE_COAP,
            ConfigChangeType::RulesCleared,
            3000,
        );
        assert_eq!(shield.config_audit().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Monitor health transitions
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn monitor_health_stays_ready_below_threshold() {
        let mut shield = make_shield();

        // Submit allowed MQTT messages — no alerts generated.
        shield
            .mqtt_monitor_mut()
            .add_rule(
                b"ok/#",
                vs_mqtt_monitor::TopicAction::Allow,
                vs_mqtt_monitor::QosPolicy::Any,
                0,
            )
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos: MqttQoS::AtMostOnce,
            ..MqttMessage::default()
        };
        let topic = b"ok/data";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        for i in 0..120u64 {
            msg.timestamp_us = i * 100;
            let _ = shield.submit_mqtt_message(&mut msg, i * 100);
        }

        shield.update_monitor_health();
        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::Ready);
    }

    #[test]
    #[allow(deprecated)]
    fn monitor_health_degrades_on_high_alert_rate() {
        let mut shield = make_shield();

        // Block a topic so all publishes generate alerts.
        shield
            .mqtt_monitor_mut()
            .add_rule(
                b"bad/#",
                vs_mqtt_monitor::TopicAction::Block,
                vs_mqtt_monitor::QosPolicy::Any,
                0,
            )
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos: MqttQoS::AtMostOnce,
            ..MqttMessage::default()
        };
        let topic = b"bad/stuff";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        for i in 0..120u64 {
            msg.timestamp_us = i * 100;
            let _ = shield.submit_mqtt_message(&mut msg, i * 100);
        }

        shield.update_monitor_health();
        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::Degraded);
    }

    #[test]
    #[allow(deprecated)]
    fn tick_updates_monitor_health() {
        let mut shield = make_shield();

        // Block a topic so all publishes generate alerts.
        shield
            .mqtt_monitor_mut()
            .add_rule(
                b"spam/#",
                vs_mqtt_monitor::TopicAction::Block,
                vs_mqtt_monitor::QosPolicy::Any,
                0,
            )
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos: MqttQoS::AtMostOnce,
            ..MqttMessage::default()
        };
        let topic = b"spam/flood";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        for i in 0..120u64 {
            msg.timestamp_us = i * 100;
            let _ = shield.submit_mqtt_message(&mut msg, i * 100);
        }

        // tick() should call update_monitor_health internally.
        shield.tick(20_000).unwrap();
        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::Degraded);
    }

    // -----------------------------------------------------------------------
    // Shutdown flush
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn shutdown_resets_monitor_state() {
        let mut shield = make_shield();

        // Submit some messages to accumulate state.
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xEE, 0xEE, 0xEE, 0x01, 0x02, 0x03],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xEE, 0xEE, 0xEE, 0x01, 0x02, 0x03],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 1000,
        };
        let _ = shield.submit_ble_event(&mut event, 1000);
        assert!(shield.recent_alert_total() > 0);

        shield.shutdown();

        // Recent alerts should be cleared.
        assert_eq!(shield.recent_alert_total(), 0);
        assert!(shield.recent_alerts().iter().all(|a| a.id == 0));

        // Monitor stats should be reset.
        assert_eq!(shield.ble_monitor().total_inspected(), 0);
        assert_eq!(shield.ble_monitor().total_alerts(), 0);

        // Health status should be NotInitialized.
        let h = shield.health_status();
        assert_eq!(h.ble, SubsystemStatus::NotInitialized);
    }

    #[test]
    fn shutdown_clears_all_monitor_stats() {
        let mut shield = make_shield();

        // Submit some MQTT messages.
        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            timestamp_us: 1000,
            ..MqttMessage::default()
        };
        let _ = shield.submit_mqtt_message(&mut msg, 1000);
        assert!(shield.mqtt_monitor().total_inspected() > 0);

        shield.shutdown();

        assert_eq!(shield.mqtt_monitor().total_inspected(), 0);
        assert_eq!(shield.coap_monitor().total_inspected(), 0);
        assert_eq!(shield.ble_monitor().total_inspected(), 0);
        assert_eq!(shield.zigbee_monitor().total_inspected(), 0);
        assert_eq!(shield.lora_monitor().total_inspected(), 0);
        assert_eq!(shield.modbus_monitor().total_inspected(), 0);
    }

    // -----------------------------------------------------------------------
    // S2: AlertCallback wiring
    // -----------------------------------------------------------------------

    /// A counting alert callback for testing.
    struct CountingCallback {
        count: u32,
    }
    impl AlertCallback for CountingCallback {
        fn on_alert(&mut self, _alert: &vs_types::SecurityAlert, _ts_us: u64) {
            self.count += 1;
        }
    }

    #[test]
    #[allow(deprecated)]
    fn alert_callback_receives_alerts() {
        let mut shield = make_shield_with_callback(CountingCallback { count: 0 });

        // Block a BLE MAC to guarantee an alert is generated.
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xFF, 0x11, 0x22, 0x33, 0x44, 0x55],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xFF, 0x11, 0x22, 0x33, 0x44, 0x55],
            rssi: -60,
            conn_handle: 2,
            timestamp_us: 5000,
        };

        assert_eq!(shield.alert_callback().count, 0);
        let _ = shield.submit_ble_event(&mut event, 5000);
        assert!(
            shield.alert_callback().count > 0,
            "callback should have been invoked for the blocked BLE event"
        );
    }

    #[test]
    fn alert_callback_not_invoked_on_allowed_event() {
        let mut shield = make_shield_with_callback(CountingCallback { count: 0 });

        // No rules — all events are allowed, no alerts generated.
        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33],
            rssi: -40,
            conn_handle: 3,
            timestamp_us: 6000,
        };

        let _ = shield.submit_ble_event(&mut event, 6000);
        assert_eq!(
            shield.alert_callback().count,
            0,
            "callback should not be called when no alert is generated"
        );
    }

    // -----------------------------------------------------------------------
    // V6: blocked-result helpers (zero-timestamp and not-initialized paths)
    // -----------------------------------------------------------------------

    #[test]
    fn submit_returns_blocked_on_zero_timestamp() {
        let mut shield = make_shield();

        // MQTT
        let mut msg = MqttMessage::default();
        let r = shield.submit_mqtt_message(&mut msg, 0);
        assert!(!r.allowed);

        // BLE
        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0x01; 6],
            rssi: -50,
            conn_handle: 1,
            timestamp_us: 0,
        };
        let r = shield.submit_ble_event(&mut event, 0);
        assert!(!r.allowed);

        // Zigbee
        let mut frame = vs_types_embedded::ZigbeeFrame::default();
        let r = shield.submit_zigbee_frame(&mut frame, 0);
        assert!(!r.allowed);

        // LoRa
        let mut lora = vs_types_embedded::LoraMessage::default();
        let r = shield.submit_lora_message(&mut lora, 0);
        assert!(!r.allowed);

        // Modbus RTU
        let mut rtu = vs_types_embedded::ModbusRtuMessage::default();
        let r = shield.submit_modbus_rtu(&mut rtu, 0);
        assert!(!r.allowed);

        // Modbus TCP
        let mut tcp = vs_types_embedded::ModbusTcpMessage::default();
        let r = shield.submit_modbus_tcp(&mut tcp, 0);
        assert!(!r.allowed);
    }

    #[test]
    fn submit_returns_blocked_after_shutdown() {
        let mut shield = make_shield();
        shield.shutdown();
        assert!(!shield.is_initialized());

        let mut msg = MqttMessage::default();
        let r = shield.submit_mqtt_message(&mut msg, 1000);
        assert!(!r.allowed);
    }

    #[test]
    #[allow(deprecated)]
    fn submit_zigbee_with_rules() {
        let mut shield = make_shield();
        shield
            .zigbee_monitor_mut()
            .add_rule(0x0002, 0xFFFF, vs_zigbee_monitor::AddrAction::Block, 0)
            .unwrap();

        let mut frame = ZigbeeFrame {
            src_addr: 0x0002,
            frame_type: vs_types_embedded::ZigbeeFrameType::Data,
            timestamp_us: 1_000_000,
            ..ZigbeeFrame::default()
        };
        let r = shield.submit_zigbee_frame(&mut frame, 1_000_000);
        assert!(!r.allowed, "blocked zigbee frame");
        assert!(r.alert_count > 0);
    }

    #[test]
    #[allow(deprecated)]
    fn submit_lora_with_rules() {
        let mut shield = make_shield();
        shield
            .lora_monitor_mut()
            .add_rule(
                [0x01, 0x02, 0x03, 0x04],
                vs_lora_monitor::DeviceAction::Block,
            )
            .unwrap();

        let mut msg = LoraMessage {
            dev_addr: [0x01, 0x02, 0x03, 0x04],
            frame_counter: 1,
            msg_type: vs_types_embedded::LoraMessageType::UnconfirmedUp,
            timestamp_us: 1_000_000,
            ..LoraMessage::default()
        };
        let r = shield.submit_lora_message(&mut msg, 1_000_000);
        assert!(!r.allowed, "blocked lora message");
    }

    #[test]
    #[allow(deprecated)]
    fn submit_modbus_rtu_with_rules() {
        let mut shield = make_shield();
        shield
            .modbus_monitor_mut()
            .add_rule(
                1,
                vs_modbus_monitor::UnitAction::Block,
                vs_modbus_monitor::FunctionPolicy::Any,
                0,
                u16::MAX,
                0,
            )
            .unwrap();

        let mut msg = ModbusRtuMessage {
            unit_id: 1,
            function: vs_types_embedded::ModbusFunction::ReadCoils,
            register_addr: 0,
            quantity: 10,
            payload_len: 0,
            timestamp_us: 1_000_000,
        };
        let r = shield.submit_modbus_rtu(&mut msg, 1_000_000);
        assert!(!r.allowed, "blocked modbus rtu");
    }

    #[test]
    #[allow(deprecated)]
    fn submit_coap_blocked_uri() {
        let mut shield = make_shield();
        shield
            .coap_monitor_mut()
            .add_rule(
                b"/admin",
                vs_coap_monitor::UriAction::Block,
                vs_coap_monitor::AllowedMethods::ALL,
                0,
            )
            .unwrap();

        let mut msg = CoapMessage {
            msg_type: vs_types_embedded::CoapMessageType::Confirmable,
            method: vs_types_embedded::CoapMethod::Get,
            uri_len: 6,
            timestamp_us: 1_000_000,
            ..CoapMessage::default()
        };
        msg.uri[..6].copy_from_slice(b"/admin");
        let r = shield.submit_coap_message(&mut msg, 1_000_000);
        assert!(!r.allowed, "blocked coap uri");
    }

    #[test]
    fn shutdown_blocks_all_protocols() {
        let mut shield = make_shield();
        shield.shutdown();

        // MQTT
        let mqtt = shield.submit_mqtt_message(&mut MqttMessage::default(), 1_000_000);
        assert!(!mqtt.allowed);
        // CoAP
        let coap = shield.submit_coap_message(&mut CoapMessage::default(), 1_000_000);
        assert!(!coap.allowed);
        // BLE
        let ble = shield.submit_ble_event(&mut BleEvent::default(), 1_000_000);
        assert!(!ble.allowed);
        // Zigbee
        let zigbee = shield.submit_zigbee_frame(&mut ZigbeeFrame::default(), 1_000_000);
        assert!(!zigbee.allowed);
        // LoRa
        let lora = shield.submit_lora_message(&mut LoraMessage::default(), 1_000_000);
        assert!(!lora.allowed);
        // Modbus RTU
        let modbus = shield.submit_modbus_rtu(&mut ModbusRtuMessage::default(), 1_000_000);
        assert!(!modbus.allowed);
    }

    #[test]
    fn shutdown_health_all_not_initialized() {
        let mut shield = make_shield();
        shield.shutdown();

        let h = shield.health_status();
        assert_eq!(h.mqtt, SubsystemStatus::NotInitialized);
        assert_eq!(h.coap, SubsystemStatus::NotInitialized);
        assert_eq!(h.ble, SubsystemStatus::NotInitialized);
        assert_eq!(h.zigbee, SubsystemStatus::NotInitialized);
        assert_eq!(h.lora, SubsystemStatus::NotInitialized);
        assert_eq!(h.modbus, SubsystemStatus::NotInitialized);
    }

    #[test]
    fn reinit_after_shutdown() {
        let mut shield = make_shield();
        shield.shutdown();
        assert!(!shield.is_initialized());

        // Re-create (init is a constructor, not a method)
        let mut shield = make_shield();
        assert!(shield.is_initialized());

        // Should work after re-init — BLE uses default-allow
        let mut evt = vs_types_embedded::BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03],
            rssi: -50,
            timestamp_us: 1_000_000,
            ..vs_types_embedded::BleEvent::default()
        };
        let r = shield.submit_ble_event(&mut evt, 1_000_000);
        assert!(r.allowed);
    }

    #[test]
    fn check_coap_amplification_zero_timestamp() {
        let mut shield = make_shield();
        let r = shield.check_coap_amplification(1, &[0x01], 100, 0);
        assert!(r.is_none(), "zero timestamp should return None");
    }

    #[test]
    fn check_coap_amplification_after_shutdown() {
        let mut shield = make_shield();
        shield.shutdown();
        let r = shield.check_coap_amplification(1, &[0x01], 100, 1_000_000);
        assert!(r.is_none(), "after shutdown should return None");
    }

    #[test]
    #[allow(deprecated)]
    fn accessor_methods_all_protocols() {
        let mut shield = make_shield();
        // Immutable accessors
        let _ = shield.zigbee_monitor();
        let _ = shield.lora_monitor();
        let _ = shield.modbus_monitor();
        // Mutable accessors
        let _ = shield.zigbee_monitor_mut();
        let _ = shield.lora_monitor_mut();
        let _ = shield.modbus_monitor_mut();
    }

    // -----------------------------------------------------------------------
    // Callback throttle sliding window
    // -----------------------------------------------------------------------

    /// A counting callback for throttle tests.
    /// Since `AlertCallback::on_alert` takes `&mut self`, a plain `u32` suffices.
    struct CellCountingCallback {
        count: u32,
    }
    impl AlertCallback for CellCountingCallback {
        fn on_alert(&mut self, _alert: &vs_types::SecurityAlert, _ts_us: u64) {
            self.count += 1;
        }
    }

    #[test]
    #[allow(deprecated)]
    fn callback_throttle_sliding_window() {
        let mut shield = make_shield_with_callback(CellCountingCallback { count: 0 });

        // Block a BLE MAC so every submit generates an alert.
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xAA, 0x11, 0x22, 0x33, 0x44, 0x55],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        // Generate >8 alerts within the same 1-second window.
        // The alert timestamp comes from event.timestamp_us. Use a base
        // timestamp of CALLBACK_THROTTLE_WINDOW_US + 1 so that the very
        // first alert resets the sliding window (since
        // alert_ts - window_start_us(0) > CALLBACK_THROTTLE_WINDOW_US).
        // All subsequent alerts within the burst stay inside the window.
        let base_ts = CALLBACK_THROTTLE_WINDOW_US + 1;
        for i in 0..12u64 {
            let mut event = BleEvent {
                event_type: vs_types_embedded::BleEventType::Connected,
                peer_addr: [0xAA, 0x11, 0x22, 0x33, 0x44, 0x55],
                rssi: -60,
                conn_handle: 1,
                timestamp_us: base_ts + i * 1000,
            };
            let _ = shield.submit_ble_event(&mut event, base_ts + i * 1000);
        }

        // Callback should have been invoked exactly MAX_CALLBACK_BURST times.
        assert_eq!(
            shield.alert_callback().count,
            MAX_CALLBACK_BURST as u32,
            "callback should be throttled to MAX_CALLBACK_BURST within one window"
        );

        // Advance past the 1-second window and submit another alert.
        let past_window = base_ts + CALLBACK_THROTTLE_WINDOW_US + 1;
        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xAA, 0x11, 0x22, 0x33, 0x44, 0x55],
            rssi: -60,
            conn_handle: 1,
            timestamp_us: past_window,
        };
        let _ = shield.submit_ble_event(&mut event, past_window);

        assert!(
            shield.alert_callback().count > MAX_CALLBACK_BURST as u32,
            "callbacks should resume after the throttle window expires"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn drain_recent_alerts_preserves_throttle() {
        let mut shield = make_shield_with_callback(CellCountingCallback { count: 0 });

        // Block a BLE MAC so every submit generates an alert.
        shield
            .ble_monitor_mut()
            .add_mac_filter(
                [0xBB, 0x11, 0x22, 0x33, 0x44, 0x55],
                vs_ble_monitor::MacAction::Block,
            )
            .unwrap();

        // Exhaust the throttle window with blocked events. Use a base
        // timestamp > CALLBACK_THROTTLE_WINDOW_US so the first alert resets
        // the sliding window from its initial state (start_us=0).
        let base_ts = CALLBACK_THROTTLE_WINDOW_US + 1;
        for i in 0..12u64 {
            let mut event = BleEvent {
                event_type: vs_types_embedded::BleEventType::Connected,
                peer_addr: [0xBB, 0x11, 0x22, 0x33, 0x44, 0x55],
                rssi: -60,
                conn_handle: 1,
                timestamp_us: base_ts + i * 1000,
            };
            let _ = shield.submit_ble_event(&mut event, base_ts + i * 1000);
        }
        let count_before_drain = shield.alert_callback().count;
        assert_eq!(
            count_before_drain, MAX_CALLBACK_BURST as u32,
            "throttle should cap callbacks at MAX_CALLBACK_BURST"
        );

        // Drain clears the alert buffer but preserves throttle state.
        // This prevents an attacker from resetting the throttle via repeated drains.
        let _ = shield.drain_recent_alerts();

        // Generate more alerts within the same throttle window.
        // Callbacks should NOT fire again because the throttle is still active.
        let after_drain_ts = base_ts + 200_000; // still within the 1s throttle window
        for i in 0..4u64 {
            let mut event = BleEvent {
                event_type: vs_types_embedded::BleEventType::Connected,
                peer_addr: [0xBB, 0x11, 0x22, 0x33, 0x44, 0x55],
                rssi: -60,
                conn_handle: 1,
                timestamp_us: after_drain_ts + i * 1000,
            };
            let _ = shield.submit_ble_event(&mut event, after_drain_ts + i * 1000);
        }
        assert_eq!(
            shield.alert_callback().count,
            count_before_drain,
            "callbacks should NOT fire again because drain preserves throttle"
        );

        // After the throttle window expires, callbacks should resume.
        let new_window_ts = base_ts + CALLBACK_THROTTLE_WINDOW_US + 1;
        let mut event = BleEvent {
            event_type: vs_types_embedded::BleEventType::Connected,
            peer_addr: [0xBB, 0x11, 0x22, 0x33, 0x44, 0x55],
            rssi: -60,
            conn_handle: 1,
            timestamp_us: new_window_ts,
        };
        let _ = shield.submit_ble_event(&mut event, new_window_ts);
        assert!(
            shield.alert_callback().count > count_before_drain,
            "callbacks should resume after throttle window expires"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn compute_health_no_overflow() {
        let mut shield = make_shield();

        // Block a topic so every publish generates an alert.
        shield
            .mqtt_monitor_mut()
            .add_rule(
                b"overflow/#",
                vs_mqtt_monitor::TopicAction::Block,
                vs_mqtt_monitor::QosPolicy::Any,
                0,
            )
            .unwrap();

        let mut msg = MqttMessage {
            packet_type: MqttPacketType::Publish,
            qos: MqttQoS::AtMostOnce,
            ..MqttMessage::default()
        };
        let topic = b"overflow/test";
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;

        // Submit many messages -- all generate alerts -- to exercise the
        // overflow-safe division in compute_health().
        for i in 0..200u64 {
            msg.timestamp_us = i * 100;
            let _ = shield.submit_mqtt_message(&mut msg, i * 100);
        }

        shield.update_monitor_health();
        let h = shield.health_status();
        assert_eq!(
            h.mqtt,
            SubsystemStatus::Degraded,
            "health should be Degraded when all messages generate alerts"
        );
    }

    // -----------------------------------------------------------------------
    // submit_modbus_tcp via EmbeddedShield
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn submit_modbus_tcp_with_rules() {
        let mut shield = make_shield();
        shield
            .modbus_monitor_mut()
            .add_rule(
                2,
                vs_modbus_monitor::UnitAction::Block,
                vs_modbus_monitor::FunctionPolicy::Any,
                0,
                u16::MAX,
                0,
            )
            .unwrap();

        let mut msg = ModbusTcpMessage {
            rtu: ModbusRtuMessage {
                unit_id: 2,
                function: vs_types_embedded::ModbusFunction::ReadCoils,
                register_addr: 0,
                quantity: 10,
                payload_len: 0,
                timestamp_us: 1_000_000,
            },
            transaction_id: 42,
            src_ip: vs_types_embedded::IpAddress::V4([192, 168, 0, 1]),
            src_port: 502,
        };
        let r = shield.submit_modbus_tcp(&mut msg, 1_000_000);
        assert!(!r.allowed, "blocked modbus tcp unit should be denied");
        assert!(
            r.alert_count > 0,
            "blocked modbus tcp should generate an alert"
        );
        assert!(
            shield.recent_alert_total() > 0,
            "alert should be stored in ring buffer"
        );
    }

    #[test]
    fn submit_modbus_tcp_zero_timestamp_blocked() {
        let mut shield = make_shield();
        let mut msg = ModbusTcpMessage::default();
        let r = shield.submit_modbus_tcp(&mut msg, 0);
        assert!(!r.allowed, "zero timestamp should be blocked");
    }
}
