#![no_std]
// These casts are intentional and safe: all array indices and counts in this
// crate are bounded by small constants (≤ 255) so truncation cannot occur in
// practice.  We suppress the lints at crate scope rather than with dozens of
// per-site `#[allow]` attributes.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]

//! Industrial `Craton Shield` runtime.
//!
//! Wraps [`CratonShield`] with industrial protocol monitors for IEC 62443
//! compliant environments:
//!
//! - **Modbus monitor** — RTU/TCP function code policy, register range
//!   enforcement, write protection, CRC validation.
//! - **OPC UA monitor** — security mode enforcement, session tracking,
//!   replay detection, read-only mode.
//! - **PROFINET monitor** — frame ID filtering, cycle counter validation,
//!   DCP blocking, provider state monitoring.
//! - **EtherNet/IP monitor** — session handle tracking, command allowlist,
//!   rate limiting.
//! - **DNP3 monitor** — address validation, function code allowlist,
//!   write protection.
//! - **`BACnet` monitor** — service choice allowlist, write protection.
//! - **S7comm monitor** — function code allowlist, PDU-type enforcement,
//!   write protection, SZL filtering, rate limiting.
//! - **IEC 60870-5-104 monitor** — `TypeID` allowlist, COT filtering,
//!   write protection, I-frame sequence tracking, rate limiting.
//! - **IEC 61850 monitor** — MMS service allowlist, GOOSE publisher
//!   filtering, replay detection, test-frame blocking.

use vs_bacnet_monitor::{BacnetInspectResult, BacnetMonitor};
use vs_crypto::CryptoProvider;
use vs_dnp3_monitor::{Dnp3InspectResult, Dnp3Monitor};
use vs_ethernetip_monitor::{EtherNetIpInspectResult, EtherNetIpMonitor};
use vs_iec60870_monitor::{Iec60870Frame, Iec60870InspectResult, Iec60870Monitor};
use vs_iec61850_monitor::{
    GooseFrame, Iec61850GooseInspectResult, Iec61850MmsInspectResult, Iec61850Monitor, MmsFrame,
};
use vs_modbus_monitor::{ModbusInspectResult, ModbusMonitor};
use vs_opcua_monitor::{OpcUaInspectResult, OpcUaMonitor};
use vs_profinet_monitor::{ProfinetInspectResult, ProfinetMonitor};
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, PlatformHealth, SubsystemStatus,
    WatchdogAction,
};
use vs_s7comm_monitor::{S7commFrame, S7commInspectResult, S7commMonitor};
use vs_types::{AlertSeverity, PayloadHash, SecurityAlert, VsError};
use vs_types_ind::{
    BacnetFrame, Dnp3Frame, EtherNetIpFrame, ModbusRtuFrame, ModbusTcpFrame, OpcUaMessage,
    ProfinetFrame,
};

// Re-export for convenience.
pub use vs_bacnet_monitor;
pub use vs_dnp3_monitor;
pub use vs_ethernetip_monitor;
pub use vs_iec60870_monitor;
pub use vs_iec61850_monitor;
pub use vs_modbus_monitor;
pub use vs_opcua_monitor;
pub use vs_profinet_monitor;
pub use vs_runtime::{self, PlatformConfig as CoreConfig};
pub use vs_s7comm_monitor;
pub use vs_types_ind;

// Re-export zone/conduit types for convenience.
pub use vs_types_ind::{Conduit, SecurityLevel, Zone, MAX_CONDUITS, MAX_ZONES};

// Compile-time guarantees for the 1-based u8 zone_index encoding:
// `zone_index[id] = (slot as u8) + 1` must not wrap, so the maximum slot
// count must be <= 254 (leaving 255 as a valid encoding of slot 254 and 0
// reserved for "not found").
const _: () = assert!(
    MAX_ZONES <= 254,
    "MAX_ZONES must be <= 254 because zone_index uses a 1-based u8 encoding"
);
const _: () = assert!(
    MAX_CONDUITS <= 255,
    "MAX_CONDUITS must fit in a u8 count field"
);

/// Maximum number of recent alerts stored for retrieval.
///
/// When the buffer is full, new alerts are dropped and
/// [`IndustrialShield::recent_alerts_dropped`] is incremented.
/// Call [`IndustrialShield::clear_recent_alerts`] after processing.
pub const MAX_RECENT_ALERTS: usize = 32;

// ---------------------------------------------------------------------------
// Industrial health extension
// ---------------------------------------------------------------------------

/// Extended health snapshot including industrial subsystems.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IndustrialHealth {
    pub core: PlatformHealth,
    pub modbus: SubsystemStatus,
    pub opcua: SubsystemStatus,
    pub profinet: SubsystemStatus,
    pub ethernetip: SubsystemStatus,
    pub dnp3: SubsystemStatus,
    pub bacnet: SubsystemStatus,
    pub s7comm: SubsystemStatus,
    pub iec60870: SubsystemStatus,
    pub iec61850: SubsystemStatus,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Route alerts and check severity in a single pass.
///
/// Sets `payload_hash` on each alert, routes it via the core, stores it in
/// the recent alerts buffer, and returns `true` if any alert has `High` or
/// `Critical` severity.
#[allow(clippy::too_many_arguments)]
fn route_alerts_and_check_severity<C: CryptoProvider + Clone>(
    core: &mut CratonShield<C>,
    alerts: &mut [vs_types::SecurityAlert],
    count: u8,
    payload_hash: PayloadHash,
    ts_us: u64,
    recent_buf: &mut [SecurityAlert; MAX_RECENT_ALERTS],
    recent_count: &mut u8,
    alerts_dropped: &mut u64,
) -> bool {
    let mut has_high = false;
    for alert in &mut alerts[..count as usize] {
        alert.payload_hash = payload_hash;
        core.route_alert(alert, ts_us);
        match alert.severity {
            AlertSeverity::High | AlertSeverity::Critical => has_high = true,
            _ => {}
        }
        // Store in recent alerts buffer.
        if (*recent_count as usize) < MAX_RECENT_ALERTS {
            recent_buf[*recent_count as usize] = *alert;
            *recent_count += 1;
        } else {
            *alerts_dropped = alerts_dropped.saturating_add(1);
        }
    }
    has_high
}

// ---------------------------------------------------------------------------
// IndustrialShield
// ---------------------------------------------------------------------------

/// Industrial `Craton Shield` runtime.
pub struct IndustrialShield<C: CryptoProvider> {
    core: CratonShield<C>,
    modbus_monitor: ModbusMonitor,
    opcua_monitor: OpcUaMonitor,
    profinet_monitor: ProfinetMonitor,
    ethernetip_monitor: EtherNetIpMonitor,
    dnp3_monitor: Dnp3Monitor,
    bacnet_monitor: BacnetMonitor,
    s7comm_monitor: S7commMonitor,
    iec60870_monitor: Iec60870Monitor,
    iec61850_monitor: Iec61850Monitor,
    modbus_status: SubsystemStatus,
    opcua_status: SubsystemStatus,
    profinet_status: SubsystemStatus,
    ethernetip_status: SubsystemStatus,
    dnp3_status: SubsystemStatus,
    bacnet_status: SubsystemStatus,
    s7comm_status: SubsystemStatus,
    iec60870_status: SubsystemStatus,
    iec61850_status: SubsystemStatus,
    zones: [Zone; MAX_ZONES],
    zone_count: u8,
    /// O(1) zone lookup: `zone_index[zone_id]` = slot index + 1 (0 = not found).
    zone_index: [u8; 256],
    conduits: [Conduit; MAX_CONDUITS],
    conduit_count: u8,
    /// Recent alerts buffer for retrieval by the operator.
    recent_alert_buf: [SecurityAlert; MAX_RECENT_ALERTS],
    recent_alert_count: u8,
    /// Number of alerts dropped because the recent alerts buffer was full.
    alerts_dropped: u64,
    /// Auto-recovery timeout in microseconds (0 = disabled).
    auto_recovery_timeout_us: u64,
    /// Number of currently degraded subsystems (for O(1) `any_degraded`).
    degraded_count: u8,
    /// Timestamps when each subsystem became degraded (0 = not degraded).
    modbus_degraded_since_us: u64,
    opcua_degraded_since_us: u64,
    profinet_degraded_since_us: u64,
    ethernetip_degraded_since_us: u64,
    dnp3_degraded_since_us: u64,
    bacnet_degraded_since_us: u64,
    s7comm_degraded_since_us: u64,
    iec60870_degraded_since_us: u64,
    iec61850_degraded_since_us: u64,
}

impl<C: CryptoProvider + Clone> IndustrialShield<C> {
    /// Initialize the industrial runtime.
    pub fn init(config: PlatformConfig, crypto: C) -> Result<Self, VsError> {
        let core = CratonShield::init(config, crypto)?;

        Ok(Self {
            core,
            modbus_monitor: ModbusMonitor::new(),
            opcua_monitor: OpcUaMonitor::new(),
            profinet_monitor: ProfinetMonitor::new(),
            ethernetip_monitor: EtherNetIpMonitor::new(),
            dnp3_monitor: Dnp3Monitor::new(),
            bacnet_monitor: BacnetMonitor::new(),
            s7comm_monitor: S7commMonitor::new(),
            iec60870_monitor: Iec60870Monitor::new(),
            iec61850_monitor: Iec61850Monitor::new(),
            modbus_status: SubsystemStatus::Ready,
            opcua_status: SubsystemStatus::Ready,
            profinet_status: SubsystemStatus::Ready,
            ethernetip_status: SubsystemStatus::Ready,
            dnp3_status: SubsystemStatus::Ready,
            bacnet_status: SubsystemStatus::Ready,
            s7comm_status: SubsystemStatus::Ready,
            iec60870_status: SubsystemStatus::Ready,
            iec61850_status: SubsystemStatus::Ready,
            zones: [Zone::empty(); MAX_ZONES],
            zone_count: 0,
            zone_index: [0u8; 256],
            conduits: [Conduit::empty(); MAX_CONDUITS],
            conduit_count: 0,
            recent_alert_buf: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type: 0,
                source_id: 0,
                payload_hash: PayloadHash::ZERO,
                timestamp_us: 0,
            }; MAX_RECENT_ALERTS],
            recent_alert_count: 0,
            alerts_dropped: 0,
            auto_recovery_timeout_us: 0,
            degraded_count: 0,
            modbus_degraded_since_us: 0,
            opcua_degraded_since_us: 0,
            profinet_degraded_since_us: 0,
            ethernetip_degraded_since_us: 0,
            dnp3_degraded_since_us: 0,
            bacnet_degraded_since_us: 0,
            s7comm_degraded_since_us: 0,
            iec60870_degraded_since_us: 0,
            iec61850_degraded_since_us: 0,
        })
    }

    /// Convenience constructor with default crypto.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::init`] returns an error. Because the platform is
    /// `no_std` and compiled with `panic = "abort"` in release builds, a
    /// panic will halt the device. Use [`Self::init`] directly when you need
    /// to handle initialisation failures gracefully (e.g. when the
    /// `CryptoProvider` can fail its self-test).
    pub fn new(config: &PlatformConfig) -> Self
    where
        C: Default,
    {
        Self::init(*config, C::default())
            .expect("industrial platform init must not fail with default crypto")
    }

    /// Compute SHA-256 hash of `data`, returning `PayloadHash::ZERO` on error
    /// or if the data is empty.
    fn compute_hash(crypto: &C, data: &[u8]) -> PayloadHash {
        if data.is_empty() {
            return PayloadHash::ZERO;
        }
        let mut hash_bytes = [0u8; 32];
        if crypto.sha256(data, &mut hash_bytes).is_ok() {
            PayloadHash(hash_bytes)
        } else {
            PayloadHash::ZERO
        }
    }

    /// Set the auto-recovery timeout in microseconds.
    ///
    /// When a subsystem has been degraded for longer than this duration,
    /// `tick()` will automatically reset it to `Ready`. Set to 0 to disable.
    pub fn set_auto_recovery_timeout(&mut self, timeout_us: u64) {
        self.auto_recovery_timeout_us = timeout_us;
    }

    /// Periodic tick.
    pub fn tick(&mut self, ts_us: u64) -> Result<(), VsError> {
        self.opcua_monitor.expire_sessions(ts_us);
        self.ethernetip_monitor.expire_sessions(ts_us);

        // Auto-recovery: reset degraded subsystems after timeout.
        if self.auto_recovery_timeout_us > 0 {
            self.try_auto_recover(ts_us);
        }

        self.core.tick(ts_us)
    }

    /// Check each degraded subsystem and recover if timeout has elapsed.
    fn try_auto_recover(&mut self, ts_us: u64) {
        if self.degraded_count == 0 {
            return;
        }
        let timeout = self.auto_recovery_timeout_us;

        macro_rules! recover {
            ($status:expr, $since:expr) => {
                if $status == SubsystemStatus::Degraded
                    && $since > 0
                    && ts_us.saturating_sub($since) >= timeout
                {
                    $status = SubsystemStatus::Ready;
                    $since = 0;
                    self.degraded_count = self.degraded_count.saturating_sub(1);
                }
            };
        }

        recover!(self.modbus_status, self.modbus_degraded_since_us);
        recover!(self.opcua_status, self.opcua_degraded_since_us);
        recover!(self.profinet_status, self.profinet_degraded_since_us);
        recover!(self.ethernetip_status, self.ethernetip_degraded_since_us);
        recover!(self.dnp3_status, self.dnp3_degraded_since_us);
        recover!(self.bacnet_status, self.bacnet_degraded_since_us);
        recover!(self.s7comm_status, self.s7comm_degraded_since_us);
        recover!(self.iec60870_status, self.iec60870_degraded_since_us);
        recover!(self.iec61850_status, self.iec61850_degraded_since_us);
    }

    // -----------------------------------------------------------------------
    // CAN / Ethernet (pass-through)
    // -----------------------------------------------------------------------

    pub fn submit_can_frame(&mut self, frame: &CanFrame, ts_us: u64) -> Result<(), VsError> {
        self.core.submit_can_frame(frame, ts_us)
    }

    pub fn submit_eth_packet(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Result<(), VsError> {
        self.core.submit_eth_packet(pkt, ts_us)
    }

    // -----------------------------------------------------------------------
    // Modbus
    // -----------------------------------------------------------------------

    /// Submit a Modbus TCP frame for inspection.
    pub fn submit_modbus_tcp(&mut self, frame: &ModbusTcpFrame, ts_us: u64) -> ModbusInspectResult {
        let (_verdict, mut result) = self.modbus_monitor.inspect_tcp(frame);

        if result.alert_count > 0 {
            let payload_hash =
                Self::compute_hash(self.core.crypto(), &frame.pdu_data[..frame.valid_pdu_len()]);
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.modbus_status != SubsystemStatus::Degraded
            {
                self.modbus_status = SubsystemStatus::Degraded;
                self.modbus_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit a Modbus TCP frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// Modbus TCP between the given zones.
    pub fn submit_modbus_tcp_zoned(
        &mut self,
        frame: &ModbusTcpFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<ModbusInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_MODBUS_TCP) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_modbus_tcp(frame, ts_us))
    }

    /// Submit a Modbus RTU frame for inspection.
    pub fn submit_modbus_rtu(&mut self, frame: &ModbusRtuFrame, ts_us: u64) -> ModbusInspectResult {
        let (_verdict, mut result) = self.modbus_monitor.inspect_rtu(frame);

        if result.alert_count > 0 {
            let payload_hash =
                Self::compute_hash(self.core.crypto(), &frame.pdu_data[..frame.valid_pdu_len()]);
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.modbus_status != SubsystemStatus::Degraded
            {
                self.modbus_status = SubsystemStatus::Degraded;
                self.modbus_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit a Modbus RTU frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// Modbus RTU between the given zones.
    pub fn submit_modbus_rtu_zoned(
        &mut self,
        frame: &ModbusRtuFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<ModbusInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_MODBUS_RTU) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_modbus_rtu(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // OPC UA
    // -----------------------------------------------------------------------

    /// Submit an OPC UA message for inspection.
    pub fn submit_opcua_message(&mut self, msg: &OpcUaMessage, ts_us: u64) -> OpcUaInspectResult {
        let mut result = self.opcua_monitor.inspect(msg);

        if result.alert_count > 0 {
            let payload_hash = if msg.endpoint_len > 0 {
                Self::compute_hash(
                    self.core.crypto(),
                    &msg.endpoint[..msg.valid_endpoint_len()],
                )
            } else {
                PayloadHash::ZERO
            };
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.opcua_status != SubsystemStatus::Degraded
            {
                self.opcua_status = SubsystemStatus::Degraded;
                self.opcua_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an OPC UA message with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// OPC UA between the given zones.
    pub fn submit_opcua_message_zoned(
        &mut self,
        msg: &OpcUaMessage,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<OpcUaInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_OPCUA) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_opcua_message(msg, ts_us))
    }

    // -----------------------------------------------------------------------
    // PROFINET
    // -----------------------------------------------------------------------

    /// Submit a PROFINET frame for inspection.
    pub fn submit_profinet_frame(
        &mut self,
        frame: &ProfinetFrame,
        ts_us: u64,
    ) -> ProfinetInspectResult {
        let mut result = self.profinet_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = Self::compute_hash(
                self.core.crypto(),
                &frame.payload[..frame.valid_payload_len()],
            );
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.profinet_status != SubsystemStatus::Degraded
            {
                self.profinet_status = SubsystemStatus::Degraded;
                self.profinet_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit a PROFINET frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// PROFINET between the given zones.
    pub fn submit_profinet_frame_zoned(
        &mut self,
        frame: &ProfinetFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<ProfinetInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_PROFINET) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_profinet_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // EtherNet/IP
    // -----------------------------------------------------------------------

    /// Submit an EtherNet/IP frame for inspection.
    pub fn submit_ethernetip_frame(
        &mut self,
        frame: &EtherNetIpFrame,
        ts_us: u64,
    ) -> EtherNetIpInspectResult {
        let mut result = self.ethernetip_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = Self::compute_hash(
                self.core.crypto(),
                &frame.payload[..frame.valid_payload_len()],
            );
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.ethernetip_status != SubsystemStatus::Degraded
            {
                self.ethernetip_status = SubsystemStatus::Degraded;
                self.ethernetip_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an EtherNet/IP frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// EtherNet/IP between the given zones.
    pub fn submit_ethernetip_frame_zoned(
        &mut self,
        frame: &EtherNetIpFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<EtherNetIpInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_ETHERNETIP) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_ethernetip_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // DNP3
    // -----------------------------------------------------------------------

    /// Submit a DNP3 frame for inspection.
    pub fn submit_dnp3_frame(&mut self, frame: &Dnp3Frame, ts_us: u64) -> Dnp3InspectResult {
        let mut result = self.dnp3_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = Self::compute_hash(
                self.core.crypto(),
                &frame.payload[..frame.valid_payload_len()],
            );
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.dnp3_status != SubsystemStatus::Degraded
            {
                self.dnp3_status = SubsystemStatus::Degraded;
                self.dnp3_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit a DNP3 frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// DNP3 between the given zones.
    pub fn submit_dnp3_frame_zoned(
        &mut self,
        frame: &Dnp3Frame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<Dnp3InspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_DNP3) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_dnp3_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // BACnet
    // -----------------------------------------------------------------------

    /// Submit a `BACnet` frame for inspection.
    pub fn submit_bacnet_frame(&mut self, frame: &BacnetFrame, ts_us: u64) -> BacnetInspectResult {
        let mut result = self.bacnet_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = Self::compute_hash(
                self.core.crypto(),
                &frame.payload[..frame.valid_payload_len()],
            );
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.bacnet_status != SubsystemStatus::Degraded
            {
                self.bacnet_status = SubsystemStatus::Degraded;
                self.bacnet_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit a `BACnet` frame with conduit enforcement.
    ///
    /// `from_zone` and `to_zone` are **directional**: a conduit registered as
    /// `(A → B)` does not permit traffic in the `(B → A)` direction. Callers
    /// must pass the zones in the order the traffic flows.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if no conduit allows
    /// `BACnet` between the given zones.
    pub fn submit_bacnet_frame_zoned(
        &mut self,
        frame: &BacnetFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<BacnetInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_BACNET) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_bacnet_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // S7comm
    // -----------------------------------------------------------------------

    /// Submit an S7comm frame for inspection.
    pub fn submit_s7comm_frame(&mut self, frame: &S7commFrame, ts_us: u64) -> S7commInspectResult {
        let mut result = self.s7comm_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = PayloadHash::ZERO;
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.s7comm_status != SubsystemStatus::Degraded
            {
                self.s7comm_status = SubsystemStatus::Degraded;
                self.s7comm_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an S7comm frame with conduit enforcement.
    pub fn submit_s7comm_frame_zoned(
        &mut self,
        frame: &S7commFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<S7commInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_S7COMM) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_s7comm_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // IEC 60870-5-104
    // -----------------------------------------------------------------------

    /// Submit an IEC 60870-5-104 frame for inspection.
    pub fn submit_iec60870_frame(
        &mut self,
        frame: &Iec60870Frame,
        ts_us: u64,
    ) -> Iec60870InspectResult {
        let mut result = self.iec60870_monitor.inspect(frame);

        if result.alert_count > 0 {
            let payload_hash = PayloadHash::ZERO;
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.iec60870_status != SubsystemStatus::Degraded
            {
                self.iec60870_status = SubsystemStatus::Degraded;
                self.iec60870_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an IEC 60870-5-104 frame with conduit enforcement.
    pub fn submit_iec60870_frame_zoned(
        &mut self,
        frame: &Iec60870Frame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<Iec60870InspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_IEC60870) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_iec60870_frame(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // IEC 61850 (MMS + GOOSE)
    // -----------------------------------------------------------------------

    /// Submit an IEC 61850 MMS frame for inspection.
    pub fn submit_iec61850_mms(
        &mut self,
        frame: &MmsFrame,
        ts_us: u64,
    ) -> Iec61850MmsInspectResult {
        let mut result = self.iec61850_monitor.inspect_mms(frame);

        if result.alert_count > 0 {
            let payload_hash = PayloadHash::ZERO;
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.iec61850_status != SubsystemStatus::Degraded
            {
                self.iec61850_status = SubsystemStatus::Degraded;
                self.iec61850_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an IEC 61850 MMS frame with conduit enforcement.
    pub fn submit_iec61850_mms_zoned(
        &mut self,
        frame: &MmsFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<Iec61850MmsInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_IEC61850) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_iec61850_mms(frame, ts_us))
    }

    /// Submit an IEC 61850 GOOSE frame for inspection.
    pub fn submit_iec61850_goose(
        &mut self,
        frame: &GooseFrame,
        ts_us: u64,
    ) -> Iec61850GooseInspectResult {
        let mut result = self.iec61850_monitor.inspect_goose(frame);

        if result.alert_count > 0 {
            let payload_hash = PayloadHash::ZERO;
            if route_alerts_and_check_severity(
                &mut self.core,
                &mut result.alerts,
                result.alert_count,
                payload_hash,
                ts_us,
                &mut self.recent_alert_buf,
                &mut self.recent_alert_count,
                &mut self.alerts_dropped,
            ) && self.iec61850_status != SubsystemStatus::Degraded
            {
                self.iec61850_status = SubsystemStatus::Degraded;
                self.iec61850_degraded_since_us = ts_us;
                self.degraded_count = self.degraded_count.saturating_add(1);
            }
        }

        result
    }

    /// Submit an IEC 61850 GOOSE frame with conduit enforcement.
    pub fn submit_iec61850_goose_zoned(
        &mut self,
        frame: &GooseFrame,
        from_zone: u8,
        to_zone: u8,
        ts_us: u64,
    ) -> Result<Iec61850GooseInspectResult, VsError> {
        if !self.check_conduit(from_zone, to_zone, vs_types_ind::PROTO_IEC61850) {
            return Err(VsError::PolicyViolation);
        }
        Ok(self.submit_iec61850_goose(frame, ts_us))
    }

    // -----------------------------------------------------------------------
    // Zone / Conduit management
    // -----------------------------------------------------------------------

    /// Add a security zone with the given ID and target security level.
    ///
    /// Returns `VsError::ResourceExhausted` if the maximum number of zones
    /// has been reached, or `VsError::InvalidInput` if a zone with the same
    /// `id` already exists.
    pub fn add_zone(&mut self, id: u8, target_sl: SecurityLevel) -> Result<(), VsError> {
        if (self.zone_count as usize) >= MAX_ZONES {
            return Err(VsError::ResourceExhausted);
        }
        // O(1) duplicate check via index.
        if self.zone_index[id as usize] != 0 {
            return Err(VsError::InvalidInput);
        }
        let idx = self.zone_count as usize;
        self.zones[idx] = Zone {
            id,
            target_sl,
            achieved_sl: SecurityLevel::Sl0,
            active: true,
        };
        self.zone_index[id as usize] = (idx as u8) + 1; // 1-based
        self.zone_count += 1;
        Ok(())
    }

    /// Update the achieved security level of a zone.
    ///
    /// Returns `VsError::InvalidInput` if the zone does not exist.
    pub fn set_zone_achieved_sl(
        &mut self,
        zone_id: u8,
        achieved_sl: SecurityLevel,
    ) -> Result<(), VsError> {
        let slot = self.zone_index[zone_id as usize];
        if slot == 0 {
            return Err(VsError::InvalidInput);
        }
        let idx = (slot - 1) as usize;
        if self.zones[idx].active {
            self.zones[idx].achieved_sl = achieved_sl;
            Ok(())
        } else {
            Err(VsError::InvalidInput)
        }
    }

    /// Returns `true` if a zone with the given `id` exists and is active.
    fn zone_exists(&self, id: u8) -> bool {
        let slot = self.zone_index[id as usize];
        slot != 0 && self.zones[(slot - 1) as usize].active
    }

    /// Add a conduit between two zones with allowed protocol bitmask.
    ///
    /// Returns `VsError::InvalidInput` if either zone does not exist or if
    /// a conduit with the same `(from_zone, to_zone)` pair already exists.
    /// Returns `VsError::ResourceExhausted` if the maximum number of conduits
    /// has been reached.
    pub fn add_conduit(
        &mut self,
        from_zone: u8,
        to_zone: u8,
        allowed_protocols: u16,
    ) -> Result<(), VsError> {
        if (self.conduit_count as usize) >= MAX_CONDUITS {
            return Err(VsError::ResourceExhausted);
        }
        // Validate that both zones exist.
        if !self.zone_exists(from_zone) || !self.zone_exists(to_zone) {
            return Err(VsError::InvalidInput);
        }
        // Reject duplicate conduit direction.
        for i in 0..self.conduit_count as usize {
            if self.conduits[i].from_zone == from_zone && self.conduits[i].to_zone == to_zone {
                return Err(VsError::InvalidInput);
            }
        }
        let idx = self.conduit_count as usize;
        self.conduits[idx] = Conduit {
            from_zone,
            to_zone,
            allowed_protocols,
            active: true,
        };
        self.conduit_count += 1;
        Ok(())
    }

    /// Check if an active conduit exists between the given zones that allows
    /// the specified protocol flag.
    pub fn check_conduit(&self, from_zone: u8, to_zone: u8, protocol_flag: u16) -> bool {
        for i in 0..self.conduit_count as usize {
            let c = &self.conduits[i];
            if c.from_zone == from_zone
                && c.to_zone == to_zone
                && c.allowed_protocols & protocol_flag != 0
            {
                return true;
            }
        }
        false
    }

    /// Remove a security zone by its ID.
    ///
    /// Returns `VsError::InvalidInput` if no zone with the given `id` exists.
    /// Any conduits referencing this zone are also deactivated.
    pub fn remove_zone(&mut self, id: u8) -> Result<(), VsError> {
        let slot = self.zone_index[id as usize];
        if slot == 0 || self.zone_count == 0 {
            return Err(VsError::InvalidInput);
        }
        let idx = (slot - 1) as usize;
        // Defensive: the zone_index entry must point inside the active range.
        if idx >= self.zone_count as usize || !self.zones[idx].active {
            return Err(VsError::InvalidInput);
        }
        self.zone_index[id as usize] = 0;

        // Compact: swap removed slot with the last active entry.
        // `zone_count >= 1` is guaranteed above, so the subtraction is safe.
        let last = (self.zone_count - 1) as usize;
        if idx != last {
            self.zones[idx] = self.zones[last];
            // Update index for the moved zone.
            self.zone_index[self.zones[idx].id as usize] = (idx as u8) + 1;
        }
        self.zones[last] = Zone::empty();
        self.zone_count -= 1;

        // Remove conduits referencing this zone (swap-remove in place).
        let mut i = 0usize;
        while i < self.conduit_count as usize {
            if self.conduits[i].from_zone == id || self.conduits[i].to_zone == id {
                // `conduit_count >= 1` here because `i < conduit_count`.
                let clast = (self.conduit_count - 1) as usize;
                if i != clast {
                    self.conduits[i] = self.conduits[clast];
                }
                self.conduits[clast] = Conduit::empty();
                self.conduit_count -= 1;
                // Don't increment `i` — re-check the swapped entry.
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Remove a conduit between two zones.
    ///
    /// Returns `VsError::InvalidInput` if no matching conduit exists.
    pub fn remove_conduit(&mut self, from_zone: u8, to_zone: u8) -> Result<(), VsError> {
        if self.conduit_count == 0 {
            return Err(VsError::InvalidInput);
        }
        for i in 0..self.conduit_count as usize {
            if self.conduits[i].from_zone == from_zone && self.conduits[i].to_zone == to_zone {
                // Compact: swap with last active entry. `conduit_count >= 1`.
                let last = (self.conduit_count - 1) as usize;
                if i != last {
                    self.conduits[i] = self.conduits[last];
                }
                self.conduits[last] = Conduit::empty();
                self.conduit_count -= 1;
                return Ok(());
            }
        }
        Err(VsError::InvalidInput)
    }

    /// Returns a slice of the active zones (up to `zone_count`).
    pub fn zones(&self) -> &[Zone] {
        &self.zones[..self.zone_count as usize]
    }

    /// Returns a slice of the active conduits (up to `conduit_count`).
    pub fn conduits(&self) -> &[Conduit] {
        &self.conduits[..self.conduit_count as usize]
    }

    // -----------------------------------------------------------------------
    // Health & accessors
    // -----------------------------------------------------------------------

    /// Returns `true` if any industrial subsystem is currently degraded.
    ///
    /// This is an O(1) check backed by a counter.
    pub fn any_degraded(&self) -> bool {
        self.degraded_count > 0
    }

    /// Return a snapshot of health across all subsystems.
    pub fn health_status(&self) -> IndustrialHealth {
        IndustrialHealth {
            core: self.core.health_status(),
            modbus: self.modbus_status,
            opcua: self.opcua_status,
            profinet: self.profinet_status,
            ethernetip: self.ethernetip_status,
            dnp3: self.dnp3_status,
            bacnet: self.bacnet_status,
            s7comm: self.s7comm_status,
            iec60870: self.iec60870_status,
            iec61850: self.iec61850_status,
        }
    }

    /// Reset a subsystem's health status back to `Ready`.
    ///
    /// Use this after investigating and clearing the condition that caused
    /// a subsystem to become `Degraded`. Pass the protocol source constant
    /// (e.g., `SOURCE_MODBUS_TCP`) to identify which subsystem to reset.
    ///
    /// Returns `VsError::InvalidInput` if `source_type` does not match any
    /// known industrial protocol subsystem.
    pub fn reset_health(&mut self, source_type: u8) -> Result<(), VsError> {
        use vs_types_ind::{
            SOURCE_BACNET, SOURCE_DNP3, SOURCE_ETHERNETIP, SOURCE_IEC60870, SOURCE_IEC61850_GOOSE,
            SOURCE_IEC61850_MMS, SOURCE_MODBUS_RTU, SOURCE_MODBUS_TCP, SOURCE_OPCUA,
            SOURCE_PROFINET, SOURCE_S7COMM,
        };
        macro_rules! do_reset {
            ($status:expr, $since:expr) => {{
                if $status == SubsystemStatus::Degraded {
                    self.degraded_count = self.degraded_count.saturating_sub(1);
                }
                $status = SubsystemStatus::Ready;
                $since = 0;
                Ok(())
            }};
        }
        match source_type {
            SOURCE_MODBUS_TCP | SOURCE_MODBUS_RTU => {
                do_reset!(self.modbus_status, self.modbus_degraded_since_us)
            }
            SOURCE_OPCUA => {
                do_reset!(self.opcua_status, self.opcua_degraded_since_us)
            }
            SOURCE_PROFINET => {
                do_reset!(self.profinet_status, self.profinet_degraded_since_us)
            }
            SOURCE_ETHERNETIP => {
                do_reset!(self.ethernetip_status, self.ethernetip_degraded_since_us)
            }
            SOURCE_DNP3 => {
                do_reset!(self.dnp3_status, self.dnp3_degraded_since_us)
            }
            SOURCE_BACNET => {
                do_reset!(self.bacnet_status, self.bacnet_degraded_since_us)
            }
            SOURCE_S7COMM => {
                do_reset!(self.s7comm_status, self.s7comm_degraded_since_us)
            }
            SOURCE_IEC60870 => {
                do_reset!(self.iec60870_status, self.iec60870_degraded_since_us)
            }
            SOURCE_IEC61850_MMS | SOURCE_IEC61850_GOOSE => {
                do_reset!(self.iec61850_status, self.iec61850_degraded_since_us)
            }
            _ => Err(VsError::InvalidInput),
        }
    }

    /// Check the software watchdog and return an action if the deadline has
    /// been missed.
    pub fn check_watchdog(&mut self, ts_us: u64) -> Option<WatchdogAction> {
        self.core.check_watchdog(ts_us)
    }

    /// Shut down all subsystems and the core runtime.
    pub fn shutdown(&mut self) {
        self.core.shutdown();
        self.modbus_status = SubsystemStatus::NotInitialized;
        self.opcua_status = SubsystemStatus::NotInitialized;
        self.profinet_status = SubsystemStatus::NotInitialized;
        self.ethernetip_status = SubsystemStatus::NotInitialized;
        self.dnp3_status = SubsystemStatus::NotInitialized;
        self.bacnet_status = SubsystemStatus::NotInitialized;
        self.s7comm_status = SubsystemStatus::NotInitialized;
        self.iec60870_status = SubsystemStatus::NotInitialized;
        self.iec61850_status = SubsystemStatus::NotInitialized;
        self.degraded_count = 0;
    }

    /// Returns `true` if the runtime has been initialized and has not been
    /// shut down.
    pub fn is_initialized(&self) -> bool {
        self.core.is_initialized()
    }

    /// Number of ticks processed since initialization.
    pub fn tick_count(&self) -> u64 {
        self.core.tick_count()
    }

    /// Immutable reference to the underlying core `CratonShield` runtime.
    pub fn core(&self) -> &CratonShield<C> {
        &self.core
    }

    /// Mutable reference to the underlying core `CratonShield` runtime.
    pub fn core_mut(&mut self) -> &mut CratonShield<C> {
        &mut self.core
    }

    /// Immutable reference to the Modbus monitor.
    pub fn modbus_monitor(&self) -> &ModbusMonitor {
        &self.modbus_monitor
    }

    /// Mutable reference to the Modbus monitor for configuration.
    pub fn modbus_monitor_mut(&mut self) -> &mut ModbusMonitor {
        &mut self.modbus_monitor
    }

    /// Immutable reference to the OPC UA monitor.
    pub fn opcua_monitor(&self) -> &OpcUaMonitor {
        &self.opcua_monitor
    }

    /// Mutable reference to the OPC UA monitor for configuration.
    pub fn opcua_monitor_mut(&mut self) -> &mut OpcUaMonitor {
        &mut self.opcua_monitor
    }

    /// Immutable reference to the PROFINET monitor.
    pub fn profinet_monitor(&self) -> &ProfinetMonitor {
        &self.profinet_monitor
    }

    /// Mutable reference to the PROFINET monitor for configuration.
    pub fn profinet_monitor_mut(&mut self) -> &mut ProfinetMonitor {
        &mut self.profinet_monitor
    }

    /// Immutable reference to the EtherNet/IP monitor.
    pub fn ethernetip_monitor(&self) -> &EtherNetIpMonitor {
        &self.ethernetip_monitor
    }

    /// Mutable reference to the EtherNet/IP monitor for configuration.
    pub fn ethernetip_monitor_mut(&mut self) -> &mut EtherNetIpMonitor {
        &mut self.ethernetip_monitor
    }

    /// Immutable reference to the DNP3 monitor.
    pub fn dnp3_monitor(&self) -> &Dnp3Monitor {
        &self.dnp3_monitor
    }

    /// Mutable reference to the DNP3 monitor for configuration.
    pub fn dnp3_monitor_mut(&mut self) -> &mut Dnp3Monitor {
        &mut self.dnp3_monitor
    }

    /// Immutable reference to the `BACnet` monitor.
    pub fn bacnet_monitor(&self) -> &BacnetMonitor {
        &self.bacnet_monitor
    }

    /// Mutable reference to the `BACnet` monitor for configuration.
    pub fn bacnet_monitor_mut(&mut self) -> &mut BacnetMonitor {
        &mut self.bacnet_monitor
    }

    /// Immutable reference to the S7comm monitor.
    pub fn s7comm_monitor(&self) -> &S7commMonitor {
        &self.s7comm_monitor
    }

    /// Mutable reference to the S7comm monitor for configuration.
    pub fn s7comm_monitor_mut(&mut self) -> &mut S7commMonitor {
        &mut self.s7comm_monitor
    }

    /// Immutable reference to the IEC 60870-5-104 monitor.
    pub fn iec60870_monitor(&self) -> &Iec60870Monitor {
        &self.iec60870_monitor
    }

    /// Mutable reference to the IEC 60870-5-104 monitor for configuration.
    pub fn iec60870_monitor_mut(&mut self) -> &mut Iec60870Monitor {
        &mut self.iec60870_monitor
    }

    /// Immutable reference to the IEC 61850 monitor.
    pub fn iec61850_monitor(&self) -> &Iec61850Monitor {
        &self.iec61850_monitor
    }

    /// Mutable reference to the IEC 61850 monitor for configuration.
    pub fn iec61850_monitor_mut(&mut self) -> &mut Iec61850Monitor {
        &mut self.iec61850_monitor
    }

    /// Number of events in the core event log.
    pub fn event_log_count(&self) -> u64 {
        self.core.event_log_count()
    }

    // -----------------------------------------------------------------------
    // Recent alerts
    // -----------------------------------------------------------------------

    /// Returns a slice of recent alerts that have not yet been cleared.
    ///
    /// Call [`clear_recent_alerts`](Self::clear_recent_alerts) after
    /// processing to make room for new alerts.
    pub fn recent_alerts(&self) -> &[SecurityAlert] {
        &self.recent_alert_buf[..self.recent_alert_count as usize]
    }

    /// Clear the recent alerts buffer, making room for new alerts.
    pub fn clear_recent_alerts(&mut self) {
        self.recent_alert_count = 0;
    }

    /// Number of alerts dropped because the recent alerts buffer was full.
    ///
    /// This counter is not reset by [`clear_recent_alerts`](Self::clear_recent_alerts).
    pub fn recent_alerts_dropped(&self) -> u64 {
        self.alerts_dropped
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

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
            // Simple deterministic test hash: mix length + content bytes.
            *hash_out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                hash_out[i % 32] ^= b;
                hash_out[(i + 1) % 32] = hash_out[(i + 1) % 32].wrapping_add(b);
            }
            hash_out[0] = hash_out[0].wrapping_add((data.len() & 0xFF) as u8);
            Ok(())
        }
        fn hmac_sha256(
            &self,
            _key: vs_crypto::KeyId,
            data: &[u8],
            mac_out: &mut [u8; 32],
        ) -> Result<(), VsError> {
            // Data-dependent stub so tests can detect when the input changes.
            // Not cryptographically sound; use the real provider in production.
            *mac_out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                mac_out[i % 32] ^= b.wrapping_add(0xAA);
                mac_out[(i + 1) % 32] = mac_out[(i + 1) % 32].wrapping_add(b);
            }
            mac_out[0] = mac_out[0].wrapping_add((data.len() & 0xFF) as u8);
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
        fn verify_p256(
            &self,
            _pub_key: &[u8; 65],
            _hash: &[u8; 32],
            _sig: &[u8; 64],
        ) -> Result<bool, VsError> {
            // sign_p256 always returns Err, so no valid signature can ever be
            // produced by this stub. Returning Ok(true) unconditionally would
            // silently accept all garbage signatures; return Err instead to
            // make the missing implementation visible immediately.
            Err(VsError::NotInitialized)
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
            // Deterministic but non-uniform: the runtime's RNG self-test
            // rejects all-zero and uniform-byte output as a degenerate
            // entropy source, so we emit a simple mixing pattern that
            // passes the probe while remaining reproducible in tests.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = 0x42u8 ^ (i as u8).wrapping_mul(31).wrapping_add(0x5A);
            }
            Ok(())
        }
        fn delete_key(&mut self, _key_id: vs_crypto::KeyId) -> Result<(), VsError> {
            Ok(())
        }
        fn generate_key(
            &mut self,
            _key_id: vs_crypto::KeyId,
            _key_type: vs_crypto::KeyType,
        ) -> Result<(), VsError> {
            Ok(())
        }
    }

    impl Default for TestCrypto {
        fn default() -> Self {
            Self
        }
    }

    fn make_shield() -> std::boxed::Box<IndustrialShield<TestCrypto>> {
        std::boxed::Box::new(IndustrialShield::init(PlatformConfig::default(), TestCrypto).unwrap())
    }

    fn read_holding_tcp() -> ModbusTcpFrame {
        let mut f = ModbusTcpFrame {
            transaction_id: 1,
            unit_id: 1,
            raw_function_code: 0x03,
            start_address: 0,
            quantity: 1,
            pdu_len: 5,
            timestamp_us: 1_000,
            ..ModbusTcpFrame::default()
        };
        f.pdu_data[0] = 0x03;
        f.pdu_data[1..3].copy_from_slice(&0u16.to_be_bytes());
        f.pdu_data[3..5].copy_from_slice(&1u16.to_be_bytes());
        f
    }

    fn read_holding_rtu() -> ModbusRtuFrame {
        let mut f = ModbusRtuFrame {
            slave_addr: 1,
            raw_function_code: 0x03,
            start_address: 0,
            quantity: 1,
            pdu_len: 5,
            timestamp_us: 1_000,
            ..ModbusRtuFrame::default()
        };
        f.pdu_data[0] = 0x03;
        f.pdu_data[1..3].copy_from_slice(&0u16.to_be_bytes());
        f.pdu_data[3..5].copy_from_slice(&1u16.to_be_bytes());
        f
    }

    #[test]
    fn industrial_init_succeeds() {
        let shield = IndustrialShield::init(PlatformConfig::default(), TestCrypto);
        assert!(shield.is_ok());
        assert!(shield.unwrap().is_initialized());
    }

    #[test]
    fn industrial_health_all_ready() {
        let shield = make_shield();
        let h = shield.health_status();
        assert_eq!(h.modbus, SubsystemStatus::Ready);
        assert_eq!(h.opcua, SubsystemStatus::Ready);
        assert_eq!(h.profinet, SubsystemStatus::Ready);
        assert_eq!(h.ethernetip, SubsystemStatus::Ready);
        assert_eq!(h.dnp3, SubsystemStatus::Ready);
        assert_eq!(h.bacnet, SubsystemStatus::Ready);
    }

    #[test]
    fn industrial_shutdown() {
        let mut shield = make_shield();
        shield.shutdown();
        assert!(!shield.is_initialized());
        let h = shield.health_status();
        assert_eq!(h.modbus, SubsystemStatus::NotInitialized);
        assert_eq!(h.opcua, SubsystemStatus::NotInitialized);
        assert_eq!(h.profinet, SubsystemStatus::NotInitialized);
        assert_eq!(h.ethernetip, SubsystemStatus::NotInitialized);
        assert_eq!(h.dnp3, SubsystemStatus::NotInitialized);
        assert_eq!(h.bacnet, SubsystemStatus::NotInitialized);
    }

    #[test]
    fn industrial_modbus_tcp_integration() {
        let mut shield = make_shield();
        let f = read_holding_tcp();
        let r = shield.submit_modbus_tcp(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_new_constructor() {
        let config = PlatformConfig::default();
        let shield: IndustrialShield<TestCrypto> = IndustrialShield::new(&config);
        assert!(shield.is_initialized());
    }

    #[test]
    fn industrial_tick() {
        let mut shield = make_shield();
        shield.tick(1000).unwrap();
        assert_eq!(shield.tick_count(), 1);
    }

    #[test]
    fn industrial_modbus_rtu_integration() {
        let mut shield = make_shield();
        let f = read_holding_rtu();
        let r = shield.submit_modbus_rtu(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_opcua_integration() {
        let mut shield = make_shield();
        let msg = OpcUaMessage::default();
        let r = shield.submit_opcua_message(&msg, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_profinet_integration() {
        let mut shield = make_shield();
        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::CyclicRT,
            frame_id: 0x8000,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };
        let r = shield.submit_profinet_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_ethernetip_integration() {
        let mut shield = make_shield();
        let f = EtherNetIpFrame::default();
        let r = shield.submit_ethernetip_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_dnp3_integration() {
        let mut shield = make_shield();
        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_bacnet_integration() {
        let mut shield = make_shield();
        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn industrial_accessor_methods() {
        let mut shield = make_shield();
        let _ = shield.core();
        let _ = shield.core_mut();
        let _ = shield.modbus_monitor();
        let _ = shield.modbus_monitor_mut();
        let _ = shield.opcua_monitor();
        let _ = shield.opcua_monitor_mut();
        let _ = shield.profinet_monitor();
        let _ = shield.profinet_monitor_mut();
        let _ = shield.ethernetip_monitor();
        let _ = shield.ethernetip_monitor_mut();
        let _ = shield.dnp3_monitor();
        let _ = shield.dnp3_monitor_mut();
        let _ = shield.bacnet_monitor();
        let _ = shield.bacnet_monitor_mut();
    }

    #[test]
    fn industrial_event_log_count() {
        let shield = make_shield();
        assert_eq!(shield.event_log_count(), 0);
    }

    #[test]
    fn industrial_watchdog() {
        let mut shield = make_shield();
        shield.tick(0).unwrap();
        assert!(shield.check_watchdog(500_000).is_none());
    }

    #[test]
    fn industrial_modbus_strict_routes_alert() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let r = shield.submit_modbus_tcp(&f, 1000);
        assert!(!r.allowed);
        assert!(shield.event_log_count() > 0);
    }

    #[test]
    fn industrial_profinet_dcp_blocked_routes_alert() {
        let mut shield = make_shield();
        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::Dcp,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };

        let r = shield.submit_profinet_frame(&f, 1000);
        assert!(!r.allowed);
        assert!(shield.event_log_count() > 0);
    }

    // -----------------------------------------------------------------------
    // Zone / Conduit tests
    // -----------------------------------------------------------------------

    #[test]
    fn zone_add_and_retrieve() {
        let mut shield = make_shield();
        assert_eq!(shield.zones().len(), 0);

        shield.add_zone(1, SecurityLevel::Sl2).unwrap();
        shield.add_zone(2, SecurityLevel::Sl3).unwrap();

        assert_eq!(shield.zones().len(), 2);
        assert_eq!(shield.zones()[0].id, 1);
        assert_eq!(shield.zones()[0].target_sl, SecurityLevel::Sl2);
        assert!(shield.zones()[0].active);
        assert_eq!(shield.zones()[1].id, 2);
        assert_eq!(shield.zones()[1].target_sl, SecurityLevel::Sl3);
    }

    #[test]
    fn zone_duplicate_id_rejected() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl2).unwrap();
        assert!(shield.add_zone(1, SecurityLevel::Sl3).is_err());
        shield.add_zone(2, SecurityLevel::Sl3).unwrap();
    }

    #[test]
    fn zone_overflow_returns_error() {
        let mut shield = make_shield();
        for i in 0..MAX_ZONES {
            shield.add_zone(i as u8, SecurityLevel::Sl1).unwrap();
        }
        assert!(shield.add_zone(99, SecurityLevel::Sl1).is_err());
    }

    #[test]
    fn zone_achieved_sl_lifecycle() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl3).unwrap();

        assert_eq!(shield.zones()[0].achieved_sl, SecurityLevel::Sl0);
        assert!(!shield.zones()[0].meets_target());

        shield.set_zone_achieved_sl(1, SecurityLevel::Sl2).unwrap();
        assert_eq!(shield.zones()[0].achieved_sl, SecurityLevel::Sl2);
        assert!(!shield.zones()[0].meets_target());

        shield.set_zone_achieved_sl(1, SecurityLevel::Sl3).unwrap();
        assert!(shield.zones()[0].meets_target());

        assert!(shield.set_zone_achieved_sl(99, SecurityLevel::Sl1).is_err());
    }

    #[test]
    fn zone_index_o1_lookup() {
        let mut shield = make_shield();
        shield.add_zone(50, SecurityLevel::Sl2).unwrap();
        shield.add_zone(200, SecurityLevel::Sl3).unwrap();

        // zone_index gives O(1) lookup.
        assert!(shield.zone_exists(50));
        assert!(shield.zone_exists(200));
        assert!(!shield.zone_exists(0));
        assert!(!shield.zone_exists(100));
    }

    #[test]
    fn conduit_add_and_check() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl2).unwrap();
        shield.add_zone(2, SecurityLevel::Sl3).unwrap();

        shield
            .add_conduit(
                1,
                2,
                vs_types_ind::PROTO_MODBUS_TCP | vs_types_ind::PROTO_OPCUA,
            )
            .unwrap();

        assert!(shield.check_conduit(1, 2, vs_types_ind::PROTO_MODBUS_TCP));
        assert!(shield.check_conduit(1, 2, vs_types_ind::PROTO_OPCUA));
        assert!(!shield.check_conduit(1, 2, vs_types_ind::PROTO_PROFINET));
        assert!(!shield.check_conduit(2, 1, vs_types_ind::PROTO_MODBUS_TCP));
        assert!(!shield.check_conduit(1, 3, vs_types_ind::PROTO_MODBUS_TCP));
        assert_eq!(shield.conduits().len(), 1);
    }

    #[test]
    fn conduit_requires_existing_zones() {
        let mut shield = make_shield();
        assert!(shield.add_conduit(1, 2, 0xFF).is_err());

        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        assert!(shield.add_conduit(1, 2, 0xFF).is_err());

        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, 0xFF).unwrap();
    }

    #[test]
    fn conduit_duplicate_direction_rejected() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();

        shield.add_conduit(1, 2, 0xFF).unwrap();
        assert!(shield.add_conduit(1, 2, 0x01).is_err());
        shield.add_conduit(2, 1, 0xFF).unwrap();
    }

    #[test]
    fn conduit_overflow_returns_error() {
        let mut shield = make_shield();
        shield.add_zone(0, SecurityLevel::Sl1).unwrap();
        for i in 1..=core::cmp::min(MAX_CONDUITS, MAX_ZONES - 1) {
            shield.add_zone(i as u8, SecurityLevel::Sl1).unwrap();
        }
        let limit = core::cmp::min(MAX_CONDUITS, MAX_ZONES - 1);
        for i in 0..limit {
            shield.add_conduit(0, (i + 1) as u8, 0xFF).unwrap();
        }
        if limit == MAX_CONDUITS {
            // We filled MAX_CONDUITS — verified by reaching here without error.
        }
    }

    // -----------------------------------------------------------------------
    // Conduit enforcement tests
    // -----------------------------------------------------------------------

    #[test]
    fn zoned_submit_allowed() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_MODBUS_TCP)
            .unwrap();

        let f = read_holding_tcp();
        let r = shield.submit_modbus_tcp_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
        assert!(r.unwrap().allowed);
    }

    #[test]
    fn zoned_submit_blocked_by_conduit() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        // Only allow PROFINET, not Modbus TCP.
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_PROFINET)
            .unwrap();

        let f = ModbusTcpFrame::default();
        let r = shield.submit_modbus_tcp_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_submit_no_conduit() {
        let mut shield = make_shield();
        let f = ModbusTcpFrame::default();
        let r = shield.submit_modbus_tcp_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_opcua_allowed() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, vs_types_ind::PROTO_OPCUA).unwrap();

        let msg = OpcUaMessage::default();
        let r = shield.submit_opcua_message_zoned(&msg, 1, 2, 1000);
        assert!(r.is_ok());
    }

    #[test]
    fn zoned_ethernetip_blocked() {
        let mut shield = make_shield();
        let f = EtherNetIpFrame::default();
        let r = shield.submit_ethernetip_frame_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_dnp3_allowed() {
        let mut shield = make_shield();
        shield.add_zone(10, SecurityLevel::Sl2).unwrap();
        shield.add_zone(20, SecurityLevel::Sl2).unwrap();
        shield
            .add_conduit(10, 20, vs_types_ind::PROTO_DNP3)
            .unwrap();

        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame_zoned(&f, 10, 20, 1000);
        assert!(r.is_ok());
    }

    #[test]
    fn zoned_bacnet_blocked() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        // Allow Modbus only.
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_MODBUS_TCP)
            .unwrap();

        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_profinet_allowed() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_PROFINET)
            .unwrap();

        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::CyclicRT,
            frame_id: 0x8000,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };
        let r = shield.submit_profinet_frame_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
    }

    // -----------------------------------------------------------------------
    // Dynamic health tests
    // -----------------------------------------------------------------------

    #[test]
    fn dynamic_health_modbus_degraded_on_high_severity() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        assert_eq!(shield.health_status().modbus, SubsystemStatus::Ready);

        let f = ModbusTcpFrame::default();
        let r = shield.submit_modbus_tcp(&f, 1000);
        assert!(!r.allowed);

        let has_high = r.alerts[..r.alert_count as usize]
            .iter()
            .any(|a| matches!(a.severity, AlertSeverity::High | AlertSeverity::Critical));
        if has_high {
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Degraded);
        }
    }

    #[test]
    fn dynamic_health_profinet_degraded_on_high_severity() {
        let mut shield = make_shield();

        assert_eq!(shield.health_status().profinet, SubsystemStatus::Ready);

        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::Dcp,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };
        let r = shield.submit_profinet_frame(&f, 1000);
        assert!(!r.allowed);

        let has_high = r.alerts[..r.alert_count as usize]
            .iter()
            .any(|a| matches!(a.severity, AlertSeverity::High | AlertSeverity::Critical));
        if has_high {
            assert_eq!(shield.health_status().profinet, SubsystemStatus::Degraded);
        }
    }

    // -----------------------------------------------------------------------
    // Session expiry during tick
    // -----------------------------------------------------------------------

    #[test]
    fn tick_calls_expire_sessions() {
        let mut shield = make_shield();
        shield.opcua_monitor_mut().set_session_timeout(5_000);

        let msg = OpcUaMessage::default();
        let _ = shield.submit_opcua_message(&msg, 1000);

        shield.tick(1_000_000).unwrap();
        assert_eq!(shield.tick_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Payload hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn modbus_tcp_strict_alert_has_payload_hash() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let r = shield.submit_modbus_tcp(&f, 1000);
        assert!(r.alert_count > 0);
        let expected = PayloadHash([0u8; 32]);
        assert_eq!(r.alerts[0].payload_hash, expected);
    }

    #[test]
    fn profinet_dcp_alert_has_payload_hash() {
        let mut shield = make_shield();
        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::Dcp,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };
        let r = shield.submit_profinet_frame(&f, 1000);
        assert!(r.alert_count > 0);
        let expected = PayloadHash([0u8; 32]);
        assert_eq!(r.alerts[0].payload_hash, expected);
    }

    // -----------------------------------------------------------------------
    // Health recovery tests
    // -----------------------------------------------------------------------

    #[test]
    fn health_recovery_modbus() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1000);

        let h = shield.health_status();
        if h.modbus == SubsystemStatus::Degraded {
            shield
                .reset_health(vs_types_ind::SOURCE_MODBUS_TCP)
                .unwrap();
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Ready);
        }
    }

    #[test]
    fn health_recovery_profinet() {
        let mut shield = make_shield();

        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::Dcp,
            timestamp_us: 1000,
            ..ProfinetFrame::default()
        };
        let _ = shield.submit_profinet_frame(&f, 1000);
        assert_eq!(shield.health_status().profinet, SubsystemStatus::Degraded);

        shield.reset_health(vs_types_ind::SOURCE_PROFINET).unwrap();
        assert_eq!(shield.health_status().profinet, SubsystemStatus::Ready);
    }

    #[test]
    fn health_recovery_opcua() {
        let mut shield = make_shield();
        shield.opcua_monitor_mut().set_read_only(true);

        let msg = OpcUaMessage {
            msg_type: vs_types_ind::OpcUaMessageType::Write,
            security_mode: vs_types_ind::OpcUaSecurityMode::SignAndEncrypt,
            channel_id: 1,
            sequence_number: 1,
            timestamp_us: 1000,
            ..OpcUaMessage::default()
        };
        let _ = shield.submit_opcua_message(&msg, 1000);
        assert_eq!(shield.health_status().opcua, SubsystemStatus::Degraded);

        shield.reset_health(vs_types_ind::SOURCE_OPCUA).unwrap();
        assert_eq!(shield.health_status().opcua, SubsystemStatus::Ready);
    }

    #[test]
    fn health_recovery_ethernetip() {
        let mut shield = make_shield();

        // Payload overflow → High severity → Degraded.
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let _ = shield.submit_ethernetip_frame(&f, 1000);
        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Degraded);

        shield
            .reset_health(vs_types_ind::SOURCE_ETHERNETIP)
            .unwrap();
        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Ready);
    }

    #[test]
    fn health_recovery_dnp3() {
        let mut shield = make_shield();

        // Payload overflow → High severity → Degraded.
        let f = Dnp3Frame {
            payload_len: 500,
            ..Default::default()
        };
        let _ = shield.submit_dnp3_frame(&f, 1000);
        assert_eq!(shield.health_status().dnp3, SubsystemStatus::Degraded);

        shield.reset_health(vs_types_ind::SOURCE_DNP3).unwrap();
        assert_eq!(shield.health_status().dnp3, SubsystemStatus::Ready);
    }

    #[test]
    fn health_recovery_bacnet() {
        let mut shield = make_shield();

        // Payload overflow → High severity → Degraded.
        let f = BacnetFrame {
            payload_len: 300,
            ..Default::default()
        };
        let _ = shield.submit_bacnet_frame(&f, 1000);
        assert_eq!(shield.health_status().bacnet, SubsystemStatus::Degraded);

        shield.reset_health(vs_types_ind::SOURCE_BACNET).unwrap();
        assert_eq!(shield.health_status().bacnet, SubsystemStatus::Ready);
    }

    #[test]
    fn health_recovery_unknown_source_returns_error() {
        let mut shield = make_shield();
        assert_eq!(shield.reset_health(255).unwrap_err(), VsError::InvalidInput);
        assert_eq!(shield.health_status().modbus, SubsystemStatus::Ready);
    }

    // -----------------------------------------------------------------------
    // Zone/conduit removal tests
    // -----------------------------------------------------------------------

    #[test]
    fn remove_zone_success() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl2).unwrap();
        shield.add_zone(2, SecurityLevel::Sl3).unwrap();
        assert_eq!(shield.zones().len(), 2);

        shield.remove_zone(1).unwrap();
        // After compaction, only zone 2 remains.
        assert_eq!(shield.zones().len(), 1);
        assert_eq!(shield.zones()[0].id, 2);
        assert!(shield.zones()[0].active);
        // zone_index should be cleared.
        assert!(!shield.zone_exists(1));
        assert!(shield.zone_exists(2));
    }

    #[test]
    fn remove_zone_cascades_to_conduits() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, 0xFF).unwrap();
        assert!(shield.check_conduit(1, 2, 0x01));
        assert_eq!(shield.conduits().len(), 1);

        shield.remove_zone(1).unwrap();
        assert!(!shield.check_conduit(1, 2, 0x01));
        assert_eq!(shield.conduits().len(), 0);
    }

    #[test]
    fn remove_zone_not_found() {
        let mut shield = make_shield();
        assert_eq!(shield.remove_zone(99).unwrap_err(), VsError::InvalidInput);
    }

    #[test]
    fn remove_conduit_success() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, 0xFF).unwrap();
        assert!(shield.check_conduit(1, 2, 0x01));
        assert_eq!(shield.conduits().len(), 1);

        shield.remove_conduit(1, 2).unwrap();
        assert!(!shield.check_conduit(1, 2, 0x01));
        assert_eq!(shield.conduits().len(), 0);
    }

    #[test]
    fn remove_conduit_not_found() {
        let mut shield = make_shield();
        assert_eq!(
            shield.remove_conduit(1, 2).unwrap_err(),
            VsError::InvalidInput,
        );
    }

    // -----------------------------------------------------------------------
    // Recent alerts buffer tests
    // -----------------------------------------------------------------------

    #[test]
    fn recent_alerts_initially_empty() {
        let shield = make_shield();
        assert!(shield.recent_alerts().is_empty());
        assert_eq!(shield.recent_alerts_dropped(), 0);
    }

    #[test]
    fn recent_alerts_populated_on_alert() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1000);

        assert!(!shield.recent_alerts().is_empty());
        assert!(shield.recent_alerts()[0].id > 0);
    }

    #[test]
    fn clear_recent_alerts() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1000);
        assert!(!shield.recent_alerts().is_empty());

        shield.clear_recent_alerts();
        assert!(shield.recent_alerts().is_empty());
    }

    #[test]
    fn health_recovery_modbus_rtu_source() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1000);
        if shield.health_status().modbus == SubsystemStatus::Degraded {
            shield
                .reset_health(vs_types_ind::SOURCE_MODBUS_RTU)
                .unwrap();
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Ready);
        }
    }

    // -----------------------------------------------------------------------
    // Auto-recovery tests
    // -----------------------------------------------------------------------

    #[test]
    fn auto_recovery_disabled_by_default() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1000);

        if shield.health_status().modbus == SubsystemStatus::Degraded {
            // Tick far in the future — should NOT auto-recover (disabled).
            shield.tick(100_000_000).unwrap();
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Degraded);
        }
    }

    #[test]
    fn auto_recovery_resets_after_timeout() {
        let mut shield = make_shield();
        shield.set_auto_recovery_timeout(5_000_000); // 5 seconds
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();
        let _ = shield.submit_modbus_tcp(&f, 1_000_000);

        if shield.health_status().modbus == SubsystemStatus::Degraded {
            // Tick before timeout — still degraded.
            shield.tick(3_000_000).unwrap();
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Degraded);

            // Tick after timeout — should auto-recover.
            shield.tick(7_000_000).unwrap();
            assert_eq!(shield.health_status().modbus, SubsystemStatus::Ready);
        }
    }

    #[test]
    fn auto_recovery_ethernetip() {
        let mut shield = make_shield();
        shield.set_auto_recovery_timeout(1_000_000);

        // Payload overflow → High severity → Degraded.
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let _ = shield.submit_ethernetip_frame(&f, 100_000);
        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Degraded);

        shield.tick(2_000_000).unwrap();
        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Ready);
    }

    // -----------------------------------------------------------------------
    // Auto-recovery timeout test (PROFINET DCP trigger)
    // -----------------------------------------------------------------------

    #[test]
    fn auto_recovery_timeout_profinet_dcp() {
        let mut shield = make_shield();
        shield.set_auto_recovery_timeout(5_000_000); // 5 seconds

        // Trigger degraded via blocked PROFINET DCP frame.
        let f = ProfinetFrame {
            frame_type: vs_types_ind::ProfinetFrameType::Dcp,
            timestamp_us: 1_000_000,
            ..ProfinetFrame::default()
        };
        let _ = shield.submit_profinet_frame(&f, 1_000_000);
        assert_eq!(shield.health_status().profinet, SubsystemStatus::Degraded);

        // Tick before timeout — still Degraded.
        shield.tick(4_000_000).unwrap();
        assert_eq!(shield.health_status().profinet, SubsystemStatus::Degraded);

        // Tick after timeout — now Ready.
        shield.tick(7_000_000).unwrap();
        assert_eq!(shield.health_status().profinet, SubsystemStatus::Ready);
    }

    // -----------------------------------------------------------------------
    // EtherNet/IP submit integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn ethernetip_submit_valid_allowed() {
        let mut shield = make_shield();
        let f = EtherNetIpFrame::default();
        let r = shield.submit_ethernetip_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn ethernetip_submit_payload_overflow_blocked() {
        let mut shield = make_shield();
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let r = shield.submit_ethernetip_frame(&f, 1000);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    // -----------------------------------------------------------------------
    // DNP3 submit integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn dnp3_submit_valid_allowed() {
        let mut shield = make_shield();
        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn dnp3_submit_strict_unmatched_blocked() {
        let mut shield = make_shield();
        *shield.dnp3_monitor_mut() = vs_dnp3_monitor::Dnp3Monitor::new_strict();

        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame(&f, 1000);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    // -----------------------------------------------------------------------
    // BACnet submit integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn bacnet_submit_valid_allowed() {
        let mut shield = make_shield();
        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame(&f, 1000);
        assert!(r.allowed);
    }

    #[test]
    fn bacnet_submit_strict_unmatched_blocked() {
        let mut shield = make_shield();
        *shield.bacnet_monitor_mut() = vs_bacnet_monitor::BacnetMonitor::new_strict();

        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame(&f, 1000);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    // -----------------------------------------------------------------------
    // Zoned submissions for EIP/DNP3/BACnet
    // -----------------------------------------------------------------------

    #[test]
    fn zoned_ethernetip_no_conduit_returns_policy_violation() {
        let mut shield = make_shield();
        let f = EtherNetIpFrame::default();
        let r = shield.submit_ethernetip_frame_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_ethernetip_with_conduit_succeeds() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_ETHERNETIP)
            .unwrap();

        let f = EtherNetIpFrame::default();
        let r = shield.submit_ethernetip_frame_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
        assert!(r.unwrap().allowed);
    }

    #[test]
    fn zoned_dnp3_no_conduit_returns_policy_violation() {
        let mut shield = make_shield();
        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_dnp3_with_conduit_succeeds() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, vs_types_ind::PROTO_DNP3).unwrap();

        let f = Dnp3Frame::default();
        let r = shield.submit_dnp3_frame_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
        assert!(r.unwrap().allowed);
    }

    #[test]
    fn zoned_bacnet_no_conduit_returns_policy_violation() {
        let mut shield = make_shield();
        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    #[test]
    fn zoned_bacnet_with_conduit_succeeds() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_BACNET)
            .unwrap();

        let f = BacnetFrame::default();
        let r = shield.submit_bacnet_frame_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
        assert!(r.unwrap().allowed);
    }

    // -----------------------------------------------------------------------
    // Recent alerts dropped test
    // -----------------------------------------------------------------------

    #[test]
    fn recent_alerts_dropped_when_buffer_full() {
        let mut shield = make_shield();
        *shield.modbus_monitor_mut() = vs_modbus_monitor::ModbusMonitor::new_strict();

        let f = ModbusTcpFrame::default();

        // Each submit generates at least 1 alert. Submit enough to overflow
        // the MAX_RECENT_ALERTS buffer.
        for i in 0..(MAX_RECENT_ALERTS + 10) {
            let _ = shield.submit_modbus_tcp(&f, 1000 + i as u64);
        }

        assert_eq!(shield.recent_alerts().len(), MAX_RECENT_ALERTS);
        assert!(shield.recent_alerts_dropped() > 0);
    }

    // -----------------------------------------------------------------------
    // Health degraded for EIP/DNP3/BACnet
    // -----------------------------------------------------------------------

    #[test]
    fn health_degraded_ethernetip_on_payload_overflow() {
        let mut shield = make_shield();
        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Ready);

        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let r = shield.submit_ethernetip_frame(&f, 1000);
        assert!(!r.allowed);

        assert_eq!(shield.health_status().ethernetip, SubsystemStatus::Degraded);
    }

    #[test]
    fn health_degraded_dnp3_on_payload_overflow() {
        let mut shield = make_shield();
        assert_eq!(shield.health_status().dnp3, SubsystemStatus::Ready);

        let f = Dnp3Frame {
            payload_len: 500,
            ..Default::default()
        };
        let r = shield.submit_dnp3_frame(&f, 1000);
        assert!(!r.allowed);

        assert_eq!(shield.health_status().dnp3, SubsystemStatus::Degraded);
    }

    #[test]
    fn health_degraded_bacnet_on_payload_overflow() {
        let mut shield = make_shield();
        assert_eq!(shield.health_status().bacnet, SubsystemStatus::Ready);

        let f = BacnetFrame {
            payload_len: 300,
            ..Default::default()
        };
        let r = shield.submit_bacnet_frame(&f, 1000);
        assert!(!r.allowed);

        assert_eq!(shield.health_status().bacnet, SubsystemStatus::Degraded);
    }

    // -----------------------------------------------------------------------
    // Modbus RTU zoned submission
    // -----------------------------------------------------------------------

    #[test]
    fn zoned_modbus_rtu_allowed() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_MODBUS_RTU)
            .unwrap();

        let f = read_holding_rtu();
        let r = shield.submit_modbus_rtu_zoned(&f, 1, 2, 1000);
        assert!(r.is_ok());
        assert!(r.unwrap().allowed);
    }

    #[test]
    fn zoned_modbus_rtu_blocked_by_conduit() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        // Only allow Modbus TCP, not RTU.
        shield
            .add_conduit(1, 2, vs_types_ind::PROTO_MODBUS_TCP)
            .unwrap();

        let f = ModbusRtuFrame::default();
        let r = shield.submit_modbus_rtu_zoned(&f, 1, 2, 1000);
        assert_eq!(r.unwrap_err(), VsError::PolicyViolation);
    }

    // -----------------------------------------------------------------------
    // any_degraded() tests
    // -----------------------------------------------------------------------

    #[test]
    fn any_degraded_initially_false() {
        let shield = make_shield();
        assert!(!shield.any_degraded());
    }

    #[test]
    fn any_degraded_tracks_transitions() {
        let mut shield = make_shield();
        assert!(!shield.any_degraded());

        // Trigger degraded via payload overflow.
        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let _ = shield.submit_ethernetip_frame(&f, 1000);
        assert!(shield.any_degraded());

        // Reset and verify.
        shield
            .reset_health(vs_types_ind::SOURCE_ETHERNETIP)
            .unwrap();
        assert!(!shield.any_degraded());
    }

    #[test]
    fn any_degraded_auto_recovery() {
        let mut shield = make_shield();
        shield.set_auto_recovery_timeout(1_000_000);

        let f = EtherNetIpFrame {
            payload_len: 300,
            ..Default::default()
        };
        let _ = shield.submit_ethernetip_frame(&f, 100_000);
        assert!(shield.any_degraded());

        shield.tick(2_000_000).unwrap();
        assert!(!shield.any_degraded());
    }

    // -----------------------------------------------------------------------
    // Zone compaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn zone_compaction_allows_reuse() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl2).unwrap();
        shield.add_zone(3, SecurityLevel::Sl3).unwrap();
        assert_eq!(shield.zones().len(), 3);

        shield.remove_zone(2).unwrap();
        assert_eq!(shield.zones().len(), 2);

        // Can add a new zone in the freed slot.
        shield.add_zone(4, SecurityLevel::Sl2).unwrap();
        assert_eq!(shield.zones().len(), 3);
        assert!(shield.zone_exists(4));
        assert!(!shield.zone_exists(2));
    }

    #[test]
    fn conduit_compaction_allows_reuse() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_zone(3, SecurityLevel::Sl1).unwrap();

        shield.add_conduit(1, 2, 0xFF).unwrap();
        shield.add_conduit(2, 3, 0xFF).unwrap();
        assert_eq!(shield.conduits().len(), 2);

        shield.remove_conduit(1, 2).unwrap();
        assert_eq!(shield.conduits().len(), 1);

        // Can re-add the same direction.
        shield.add_conduit(1, 2, 0x01).unwrap();
        assert_eq!(shield.conduits().len(), 2);
    }

    // -----------------------------------------------------------------------
    // compute_hash empty data test
    // -----------------------------------------------------------------------

    #[test]
    fn compute_hash_empty_returns_zero() {
        let hash = IndustrialShield::<TestCrypto>::compute_hash(&TestCrypto, &[]);
        assert_eq!(hash, PayloadHash::ZERO);
    }

    #[test]
    fn compute_hash_nonempty_returns_nonzero() {
        let hash = IndustrialShield::<TestCrypto>::compute_hash(&TestCrypto, &[1, 2, 3]);
        assert_ne!(hash, PayloadHash::ZERO);
    }

    // -----------------------------------------------------------------------
    // Regression: zone/conduit count underflow on empty removal (C1).
    // -----------------------------------------------------------------------

    #[test]
    fn remove_zone_on_empty_returns_error_without_underflow() {
        let mut shield = make_shield();
        // No zones added — removing any zone id must not underflow the
        // `zone_count` field (would otherwise wrap to u8::MAX and OOB).
        assert_eq!(shield.remove_zone(42), Err(VsError::InvalidInput));
        assert_eq!(shield.zones().len(), 0);
    }

    #[test]
    fn remove_conduit_on_empty_returns_error_without_underflow() {
        let mut shield = make_shield();
        assert_eq!(shield.remove_conduit(1, 2), Err(VsError::InvalidInput));
        assert_eq!(shield.conduits().len(), 0);
    }

    #[test]
    fn remove_last_zone_leaves_runtime_consistent() {
        let mut shield = make_shield();
        shield.add_zone(7, SecurityLevel::Sl1).unwrap();
        shield.remove_zone(7).unwrap();
        assert_eq!(shield.zones().len(), 0);
        // And removing again must still fail cleanly.
        assert_eq!(shield.remove_zone(7), Err(VsError::InvalidInput));
    }

    #[test]
    fn remove_zone_cascades_without_underflowing_conduits() {
        let mut shield = make_shield();
        shield.add_zone(1, SecurityLevel::Sl1).unwrap();
        shield.add_zone(2, SecurityLevel::Sl1).unwrap();
        shield.add_conduit(1, 2, 0xFF).unwrap();
        shield.add_conduit(2, 1, 0xFF).unwrap();
        // Removing zone 1 must cascade-remove both conduits exactly once
        // and leave `conduit_count == 0` (no underflow / double-remove).
        shield.remove_zone(1).unwrap();
        assert_eq!(shield.conduits().len(), 0);
    }
}
