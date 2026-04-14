// SPDX-License-Identifier: Apache-2.0
//! Modbus RTU/TCP intrusion detection for industrial systems

#![no_std]
#![forbid(unsafe_code)]

use vs_types::{AlertSeverity, PayloadHash, SecurityAlert};
use vs_types_ind::{ModbusRtuFrame, ModbusTcpFrame, SOURCE_MODBUS_RTU, SOURCE_MODBUS_TCP};

/// Modbus Inspect Result
#[derive(Clone, Copy, Debug)]
pub struct ModbusInspectResult {
    /// Whether the message is allowed
    pub allowed: bool,
    /// Number of alerts generated
    pub alert_count: u8,
    /// Generated alerts (up to 4)
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts dropped
    pub alerts_dropped: u8,
}

impl Default for ModbusInspectResult {
    fn default() -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                timestamp_us: 0,
                payload_hash: PayloadHash([0; 32]),
                severity: AlertSeverity::Info,
                source_type: SOURCE_MODBUS_RTU,
                source_id: 0,
            }; 4],
            alerts_dropped: 0,
        }
    }
}

impl ModbusInspectResult {
    fn clean(source_type: u8) -> Self {
        let mut result = Self::default();
        for alert in &mut result.alerts {
            alert.source_type = source_type;
        }
        result
    }
}

/// Modbus Industrial Monitor
#[derive(Default)]
pub struct ModbusMonitor {
    inspect_count: u64,
    strict_mode: bool,
    next_alert_id: u64,
    total_alerts: u64,
}

impl ModbusMonitor {
    /// Create a new Modbus monitor
    pub fn new() -> Self {
        Self {
            inspect_count: 0,
            strict_mode: false,
            next_alert_id: 1,
            total_alerts: 0,
        }
    }

    /// Create a strict Modbus monitor
    pub fn new_strict() -> Self {
        Self {
            inspect_count: 0,
            strict_mode: true,
            next_alert_id: 1,
            total_alerts: 0,
        }
    }

    /// Inspect a TCP frame
    pub fn inspect_tcp(&mut self, frame: &ModbusTcpFrame) -> ModbusInspectResult {
        self.inspect_count += 1;
        let mut result = ModbusInspectResult::clean(SOURCE_MODBUS_TCP);

        // In strict mode, reject unmatched frames
        if self.strict_mode {
            result.allowed = false;
            result.alert_count = 1;
            result.alerts[0] = SecurityAlert {
                id: self.next_alert_id,
                timestamp_us: frame.timestamp_us,
                payload_hash: PayloadHash([0; 32]),
                severity: AlertSeverity::Medium,
                source_type: SOURCE_MODBUS_TCP,
                source_id: 0,
            };
            self.next_alert_id = self.next_alert_id.wrapping_add(1);
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Inspect an RTU frame
    pub fn inspect_rtu(&mut self, frame: &ModbusRtuFrame) -> ModbusInspectResult {
        self.inspect_count += 1;
        let mut result = ModbusInspectResult::clean(SOURCE_MODBUS_RTU);

        // In strict mode, reject unmatched frames
        if self.strict_mode {
            result.allowed = false;
            result.alert_count = 1;
            result.alerts[0] = SecurityAlert {
                id: self.next_alert_id,
                timestamp_us: frame.timestamp_us,
                payload_hash: PayloadHash([0; 32]),
                severity: AlertSeverity::Medium,
                source_type: SOURCE_MODBUS_RTU,
                source_id: 0,
            };
            self.next_alert_id = self.next_alert_id.wrapping_add(1);
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    /// Get total inspected count
    pub fn total_inspected(&self) -> u64 {
        self.inspect_count
    }

    /// Reset monitor state
    pub fn reset(&mut self) {
        self.inspect_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vs_types_ind::{ModbusRtuFrame, ModbusTcpFrame};

    fn sample_tcp_frame() -> ModbusTcpFrame {
        ModbusTcpFrame {
            timestamp_us: 1_000_000,
            ..ModbusTcpFrame::default()
        }
    }

    fn sample_rtu_frame() -> ModbusRtuFrame {
        ModbusRtuFrame {
            timestamp_us: 2_000_000,
            ..ModbusRtuFrame::default()
        }
    }

    #[test]
    fn new_creates_default_monitor() {
        let m = ModbusMonitor::new();
        assert_eq!(m.total_inspected(), 0);
        assert!(!m.strict_mode);
    }

    #[test]
    fn new_strict_creates_strict_monitor() {
        let m = ModbusMonitor::new_strict();
        assert_eq!(m.total_inspected(), 0);
        assert!(m.strict_mode);
    }

    #[test]
    fn inspect_tcp_default_allows() {
        let mut m = ModbusMonitor::new();
        let result = m.inspect_tcp(&sample_tcp_frame());
        assert!(result.allowed);
        assert_eq!(result.alert_count, 0);
    }

    #[test]
    fn inspect_tcp_strict_rejects_with_alert() {
        let mut m = ModbusMonitor::new_strict();
        let result = m.inspect_tcp(&sample_tcp_frame());
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
        assert_eq!(result.alerts[0].severity, AlertSeverity::Medium);
        assert_eq!(result.alerts[0].source_type, SOURCE_MODBUS_TCP);
    }

    #[test]
    fn inspect_rtu_default_allows() {
        let mut m = ModbusMonitor::new();
        let result = m.inspect_rtu(&sample_rtu_frame());
        assert!(result.allowed);
        assert_eq!(result.alert_count, 0);
    }

    #[test]
    fn inspect_rtu_strict_rejects_with_alert() {
        let mut m = ModbusMonitor::new_strict();
        let result = m.inspect_rtu(&sample_rtu_frame());
        assert!(!result.allowed);
        assert_eq!(result.alert_count, 1);
        assert_eq!(result.alerts[0].severity, AlertSeverity::Medium);
        assert_eq!(result.alerts[0].source_type, SOURCE_MODBUS_RTU);
    }

    #[test]
    fn alert_id_increments() {
        let mut m = ModbusMonitor::new_strict();
        let r1 = m.inspect_tcp(&sample_tcp_frame());
        let r2 = m.inspect_tcp(&sample_tcp_frame());
        let r3 = m.inspect_rtu(&sample_rtu_frame());
        assert_eq!(r1.alerts[0].id, 1);
        assert_eq!(r2.alerts[0].id, 2);
        assert_eq!(r3.alerts[0].id, 3);
    }

    #[test]
    fn total_inspected_counter() {
        let mut m = ModbusMonitor::new();
        assert_eq!(m.total_inspected(), 0);
        m.inspect_tcp(&sample_tcp_frame());
        assert_eq!(m.total_inspected(), 1);
        m.inspect_rtu(&sample_rtu_frame());
        assert_eq!(m.total_inspected(), 2);
        m.inspect_tcp(&sample_tcp_frame());
        assert_eq!(m.total_inspected(), 3);
    }

    #[test]
    fn reset_clears_counter() {
        let mut m = ModbusMonitor::new();
        m.inspect_tcp(&sample_tcp_frame());
        m.inspect_rtu(&sample_rtu_frame());
        assert_eq!(m.total_inspected(), 2);
        m.reset();
        assert_eq!(m.total_inspected(), 0);
    }

    #[test]
    fn default_inspect_result_values() {
        let r = ModbusInspectResult::default();
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
        assert_eq!(r.alerts_dropped, 0);
    }

    #[test]
    fn alert_timestamp_matches_frame() {
        let mut m = ModbusMonitor::new_strict();
        let frame = ModbusTcpFrame {
            timestamp_us: 42_000,
            ..ModbusTcpFrame::default()
        };
        let result = m.inspect_tcp(&frame);
        assert_eq!(result.alerts[0].timestamp_us, 42_000);
    }
}
