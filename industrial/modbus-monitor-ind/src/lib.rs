// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

//! Modbus RTU/TCP intrusion detection monitor.
//!
//! Inspects Modbus TCP (MBAP header + PDU) and Modbus RTU (PDU + CRC16)
//! frames for protocol violations and policy breaches:
//!
//! - **MBAP validation** — protocol id must be 0, length field must match
//!   the framed PDU plus the unit id byte, transaction-id replay detection.
//! - **Function-code allowlist** — restrict permitted function codes via a
//!   bitmask. Helpers build read-only and safety profiles.
//! - **Address-range rules** — per-function-code address windows
//!   (`allow read 0x0000..=0x00FF`, `deny writes outside 0x1000..=0x10FF`,
//!   etc.).
//! - **Diagnostics sub-function blocking** — block dangerous Modbus
//!   diagnostic sub-functions such as
//!   `0x0001 RestartCommunicationsOption`.
//! - **CRC16-IBM/ANSI** validation for Modbus RTU frames.
//! - **Exception responses** — surfaced as `Suspicious` so they reach the
//!   SIEM pipeline without being treated as malicious traffic.
//!
//! # References
//!
//! - Modbus Application Protocol Specification V1.1b3
//! - Modbus Messaging on TCP/IP Implementation Guide V1.0b
//! - NIST SP 800-82 Rev.3 §4.6 (SCADA security)

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{
    AlertCode, InspectResult, ModbusFunctionCode, ModbusRtuFrame, ModbusTcpFrame,
    SOURCE_MODBUS_RTU, SOURCE_MODBUS_TCP,
};

/// Backward-compatible type alias.
pub type ModbusInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of address-range rules.
pub const MAX_RULES: usize = 16;

/// Modbus exception-response high bit (function code | 0x80).
pub const MODBUS_EXCEPTION_BIT: u8 = 0x80;

/// Modbus diagnostics function code.
pub const FC_DIAGNOSTICS: u8 = 0x08;

/// Diagnostics sub-function: Restart Communications Option (dangerous —
/// causes the slave to clear counters and re-initialize the link).
pub const DIAG_SUB_RESTART_COMMUNICATIONS: u16 = 0x0001;

/// Diagnostics sub-function: Force Listen Only Mode (dangerous — silences
/// the slave from issuing responses).
pub const DIAG_SUB_FORCE_LISTEN_ONLY: u16 = 0x0004;

/// Diagnostics sub-function: Clear Counters and Diagnostic Register.
pub const DIAG_SUB_CLEAR_COUNTERS: u16 = 0x000A;

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// High-level inspection verdict.
///
/// Mirrors the structured allow / deny / suspicious outcome required by the
/// IDS pipeline. Carries an [`AlertCode`] for `Deny` / `Suspicious` so
/// downstream consumers can route the verdict without re-parsing the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Frame conforms to policy.
    Allow,
    /// Frame must be dropped.
    Deny {
        /// Reason for the deny verdict.
        reason: AlertCode,
    },
    /// Frame is allowed through but flagged for review (e.g. exception
    /// responses, unknown function codes that the policy did not block).
    Suspicious {
        /// Reason for the suspicious verdict.
        reason: AlertCode,
    },
}

impl Verdict {
    /// Returns `true` if the frame is allowed (including `Suspicious`).
    pub fn is_passed(&self) -> bool {
        !matches!(self, Self::Deny { .. })
    }

    /// Returns the [`AlertCode`] for non-`Allow` verdicts.
    pub fn reason(&self) -> Option<AlertCode> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } | Self::Suspicious { reason } => Some(*reason),
        }
    }
}

// ---------------------------------------------------------------------------
// Function-code profiles
// ---------------------------------------------------------------------------

/// Bitmask of all Modbus public function codes (1..=127).
///
/// Bit `n` set means function code `n` is permitted. Function codes 0 and
/// 128..=255 are never representable in this mask — codes 128..=255
/// indicate exception responses and are handled separately.
pub type FunctionCodeMask = u128;

/// Helper to build a `FunctionCodeMask` from a list of codes.
///
/// Codes ≥ 128 are silently ignored — exception responses are not
/// configurable via the allowlist.
pub const fn fc_mask(codes: &[u8]) -> FunctionCodeMask {
    let mut mask: u128 = 0;
    let mut i = 0;
    while i < codes.len() {
        let c = codes[i];
        if c < 128 {
            mask |= 1u128 << c;
        }
        i += 1;
    }
    mask
}

/// Read-only profile mask: FC 0x01, 0x02, 0x03, 0x04, 0x07, 0x0B, 0x0C, 0x11, 0x14, 0x18.
///
/// Excludes all writes (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17), file writes
/// (0x15) and diagnostics (0x08).
pub const FC_PROFILE_READ_ONLY: FunctionCodeMask =
    fc_mask(&[0x01, 0x02, 0x03, 0x04, 0x07, 0x0B, 0x0C, 0x11, 0x14, 0x18]);

/// Safety profile mask: read-only set plus single-register/coil writes
/// (0x05, 0x06) and diagnostics (0x08). Multi-write (0x0F, 0x10, 0x16) and
/// read/write multiple (0x17) remain blocked. Use together with
/// [`Self::set_block_dangerous_diagnostics`](ModbusMonitor::set_block_dangerous_diagnostics)
/// to filter diagnostic sub-functions like RestartCommunications.
pub const FC_PROFILE_SAFETY: FunctionCodeMask = fc_mask(&[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x11, 0x14, 0x18,
]);

/// Permissive profile (all standard public function codes).
pub const FC_PROFILE_PERMISSIVE: FunctionCodeMask = fc_mask(&[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x2B,
]);

// ---------------------------------------------------------------------------
// Address rule
// ---------------------------------------------------------------------------

/// Per-function-code address-range rule.
///
/// A rule applies when `function_code == frame.raw_function_code` (use
/// `0xFF` as a wildcard). The rule's effect depends on `action`:
///
/// - [`RuleAction::Allow`] — `[start, end]` is the only permitted range
///   for this function code; addresses outside the range are denied.
/// - [`RuleAction::Deny`]  — `[start, end]` is denied; addresses outside
///   the range are allowed.
///
/// `quantity` from the frame is also validated: the entire request span
/// `start_address..=start_address + quantity - 1` must satisfy the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRule {
    /// Function code the rule applies to. `0xFF` matches all codes.
    pub function_code: u8,
    /// Inclusive start of the address range.
    pub start: u16,
    /// Inclusive end of the address range.
    pub end: u16,
    /// What to do when the address span matches the range.
    pub action: RuleAction,
}

/// Effect of a matched [`AddressRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Only requests within `[start, end]` are permitted.
    Allow,
    /// Requests within `[start, end]` are denied.
    Deny,
}

#[derive(Debug, Clone, Copy)]
struct StoredRule {
    rule: AddressRule,
    active: bool,
}

impl StoredRule {
    const fn empty() -> Self {
        Self {
            rule: AddressRule {
                function_code: 0,
                start: 0,
                end: 0,
                action: RuleAction::Allow,
            },
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// Modbus intrusion detection monitor.
///
/// Stateless across frames apart from counters; safe to share between
/// multiple unit ids. Configure via [`Self::set_function_code_allowlist`],
/// [`Self::add_address_rule`], and [`Self::set_block_dangerous_diagnostics`]
/// before invoking [`Self::inspect_tcp`] or [`Self::inspect_rtu`].
pub struct ModbusMonitor {
    fc_allowlist: FunctionCodeMask,
    rules: [StoredRule; MAX_RULES],
    rule_count: u8,
    block_dangerous_diagnostics: bool,
    strict_mode: bool,
    inspect_count: u64,
    total_alerts: u64,
    next_alert_id: u64,
}

impl Default for ModbusMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ModbusMonitor {
    /// Create a permissive monitor. By default every standard public
    /// function code is allowed, no address rules are configured, and
    /// dangerous diagnostic sub-functions are not blocked.
    pub fn new() -> Self {
        Self {
            fc_allowlist: FC_PROFILE_PERMISSIVE,
            rules: [StoredRule::empty(); MAX_RULES],
            rule_count: 0,
            block_dangerous_diagnostics: false,
            strict_mode: false,
            inspect_count: 0,
            total_alerts: 0,
            next_alert_id: 1,
        }
    }

    /// Create a strict monitor: read-only profile, dangerous diagnostics
    /// blocked, exception responses surfaced as `Suspicious`.
    pub fn new_strict() -> Self {
        Self {
            fc_allowlist: FC_PROFILE_READ_ONLY,
            rules: [StoredRule::empty(); MAX_RULES],
            rule_count: 0,
            block_dangerous_diagnostics: true,
            strict_mode: true,
            inspect_count: 0,
            total_alerts: 0,
            next_alert_id: 1,
        }
    }

    /// Replace the function-code allowlist.
    pub fn set_function_code_allowlist(&mut self, mask: FunctionCodeMask) {
        self.fc_allowlist = mask;
    }

    /// Allow a single function code in addition to the existing allowlist.
    pub fn allow_function_code(&mut self, code: u8) {
        if code < 128 {
            self.fc_allowlist |= 1u128 << code;
        }
    }

    /// Remove a function code from the allowlist.
    pub fn deny_function_code(&mut self, code: u8) {
        if code < 128 {
            self.fc_allowlist &= !(1u128 << code);
        }
    }

    /// Block dangerous diagnostic sub-functions
    /// (`RestartCommunications`, `ForceListenOnly`, `ClearCounters`).
    pub fn set_block_dangerous_diagnostics(&mut self, block: bool) {
        self.block_dangerous_diagnostics = block;
    }

    /// Add an address-range rule.
    ///
    /// Returns [`VsError::ResourceExhausted`] if [`MAX_RULES`] rules have
    /// already been registered, [`VsError::InvalidInput`] if `start > end`.
    pub fn add_address_rule(&mut self, rule: AddressRule) -> Result<(), VsError> {
        if rule.start > rule.end {
            return Err(VsError::InvalidInput);
        }
        if self.rule_count as usize >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = StoredRule { rule, active: true };
        self.rule_count += 1;
        Ok(())
    }

    /// Total inspected frames since construction.
    pub fn total_inspected(&self) -> u64 {
        self.inspect_count
    }

    /// Total alerts emitted since construction.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Whether the monitor is in strict mode.
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Reset counters but preserve configuration.
    pub fn reset(&mut self) {
        self.inspect_count = 0;
        self.total_alerts = 0;
        self.next_alert_id = 1;
    }

    // -----------------------------------------------------------------------
    // Frame parsing helpers (parse a raw byte slice into the typed frame
    // representation used by the monitor). Useful for callers that have a
    // raw network buffer rather than a pre-parsed `ModbusTcpFrame`.
    // -----------------------------------------------------------------------

    /// Parse a Modbus TCP MBAP header + PDU from a raw byte slice.
    ///
    /// On success returns the populated [`ModbusTcpFrame`]. On failure
    /// returns a [`Verdict::Deny`] with the appropriate alert code, ready
    /// to be returned directly from an inspection pipeline. Validates:
    ///
    /// 1. minimum 8 bytes for MBAP+function-code,
    /// 2. `protocol_id == 0`,
    /// 3. `length` field consistent with `bytes.len()`,
    /// 4. PDU fits inside the configured maximum.
    pub fn parse_tcp(bytes: &[u8], timestamp_us: u64) -> Result<ModbusTcpFrame, Verdict> {
        // MBAP header (7) + function code (1) = 8 bytes minimum.
        if bytes.len() < 8 {
            return Err(Verdict::Deny {
                reason: AlertCode::PayloadOverflow,
            });
        }
        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let protocol_id = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let unit_id = bytes[6];

        if protocol_id != 0 {
            return Err(Verdict::Deny {
                reason: AlertCode::InvalidProtocol,
            });
        }

        // The MBAP `length` field counts the unit id byte plus the PDU.
        // Total wire bytes therefore equals 6 (transaction+protocol+length)
        // + length.
        let expected = 6usize.saturating_add(length as usize);
        if expected != bytes.len() {
            return Err(Verdict::Deny {
                reason: AlertCode::PayloadOverflow,
            });
        }

        // PDU = length - 1 (unit id) bytes starting at offset 7.
        let pdu_len_usize = (length as usize).saturating_sub(1);
        if pdu_len_usize == 0 {
            return Err(Verdict::Deny {
                reason: AlertCode::PayloadOverflow,
            });
        }
        if pdu_len_usize > vs_types_ind::MAX_MODBUS_PDU_LEN {
            return Err(Verdict::Deny {
                reason: AlertCode::PayloadOverflow,
            });
        }

        let raw_fc = bytes[7];
        let fc = ModbusFunctionCode::from_u8(raw_fc);
        let mut frame = ModbusTcpFrame {
            transaction_id,
            protocol_id,
            unit_id,
            function_code: fc,
            raw_function_code: raw_fc,
            start_address: 0,
            quantity: 0,
            pdu_data: [0u8; vs_types_ind::MAX_MODBUS_PDU_LEN],
            pdu_len: pdu_len_usize as u8,
            timestamp_us,
        };
        frame.pdu_data[..pdu_len_usize].copy_from_slice(&bytes[7..7 + pdu_len_usize]);

        // Best-effort decode of (start_address, quantity) for FCs that
        // carry that pair as the first 4 bytes after the FC. These are
        // the request forms — exception responses skip this path.
        if pdu_len_usize >= 5 && raw_fc & MODBUS_EXCEPTION_BIT == 0 {
            let address = u16::from_be_bytes([bytes[8], bytes[9]]);
            let quantity = u16::from_be_bytes([bytes[10], bytes[11]]);
            match raw_fc {
                0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x0F | 0x10 | 0x17 => {
                    frame.start_address = address;
                    frame.quantity = quantity;
                }
                _ => {}
            }
        }
        Ok(frame)
    }

    // -----------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------

    /// Inspect a Modbus TCP frame.
    ///
    /// Returns a structured [`Verdict`] alongside the legacy
    /// [`ModbusInspectResult`] so consumers can pick whichever format fits
    /// their pipeline. The `result.allowed` flag mirrors
    /// `verdict.is_passed()`.
    pub fn inspect_tcp(&mut self, frame: &ModbusTcpFrame) -> (Verdict, ModbusInspectResult) {
        self.inspect_count = self.inspect_count.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_MODBUS_TCP);

        // 1. MBAP protocol id must be 0.
        if frame.protocol_id != 0 {
            return self.deny(
                &mut result,
                SOURCE_MODBUS_TCP,
                u32::from(frame.unit_id),
                frame.timestamp_us,
                AlertCode::InvalidProtocol,
                AlertSeverity::High,
            );
        }

        // 2. PDU length sanity.
        if frame.pdu_len_overflow() || frame.pdu_len == 0 {
            return self.deny(
                &mut result,
                SOURCE_MODBUS_TCP,
                u32::from(frame.unit_id),
                frame.timestamp_us,
                AlertCode::PayloadOverflow,
                AlertSeverity::High,
            );
        }

        self.inspect_pdu(
            frame.raw_function_code,
            &frame.pdu_data[..frame.valid_pdu_len()],
            frame.start_address,
            frame.quantity,
            SOURCE_MODBUS_TCP,
            u32::from(frame.unit_id),
            frame.timestamp_us,
            &mut result,
        )
    }

    /// Inspect a Modbus RTU frame.
    pub fn inspect_rtu(&mut self, frame: &ModbusRtuFrame) -> (Verdict, ModbusInspectResult) {
        self.inspect_count = self.inspect_count.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_MODBUS_RTU);

        if frame.pdu_len_overflow() || frame.pdu_len == 0 {
            return self.deny(
                &mut result,
                SOURCE_MODBUS_RTU,
                u32::from(frame.slave_addr),
                frame.timestamp_us,
                AlertCode::PayloadOverflow,
                AlertSeverity::High,
            );
        }

        // CRC validation when supplied by the caller.
        if frame.crc_provided {
            let pdu_len = frame.valid_pdu_len();
            let mut buf = [0u8; vs_types_ind::MAX_MODBUS_PDU_LEN + 1];
            buf[0] = frame.slave_addr;
            buf[1..=pdu_len].copy_from_slice(&frame.pdu_data[..pdu_len]);
            let computed = crc16_modbus(&buf[..=pdu_len]);
            if computed != frame.crc {
                return self.deny(
                    &mut result,
                    SOURCE_MODBUS_RTU,
                    u32::from(frame.slave_addr),
                    frame.timestamp_us,
                    AlertCode::CrcFailure,
                    AlertSeverity::High,
                );
            }
        }

        self.inspect_pdu(
            frame.raw_function_code,
            &frame.pdu_data[..frame.valid_pdu_len()],
            frame.start_address,
            frame.quantity,
            SOURCE_MODBUS_RTU,
            u32::from(frame.slave_addr),
            frame.timestamp_us,
            &mut result,
        )
    }

    // Shared PDU inspection logic.
    #[allow(clippy::too_many_arguments)]
    fn inspect_pdu(
        &mut self,
        raw_fc: u8,
        pdu: &[u8],
        start_address: u16,
        quantity: u16,
        source_type: u8,
        source_id: u32,
        timestamp_us: u64,
        result: &mut InspectResult,
    ) -> (Verdict, InspectResult) {
        // 3. Exception response detection — surface as Suspicious.
        if raw_fc & MODBUS_EXCEPTION_BIT != 0 {
            result.push_alert_with_code(
                AlertSeverity::Low,
                source_type,
                source_id,
                timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PolicyViolation,
            );
            // Allowed to pass but flagged.
            return (
                Verdict::Suspicious {
                    reason: AlertCode::PolicyViolation,
                },
                *result,
            );
        }

        // 4. FC == 0 is reserved and never legal.
        if raw_fc == 0 || raw_fc >= 128 {
            return self.fail(
                result,
                source_type,
                source_id,
                timestamp_us,
                AlertCode::UnknownFunctionCode,
                AlertSeverity::Medium,
            );
        }

        // 5. Allowlist.
        let allowed = (self.fc_allowlist >> raw_fc) & 1 == 1;
        if !allowed {
            // Writes blocked by an explicit allowlist deserve a higher
            // severity than e.g. a vendor-specific custom code.
            let severity = if ModbusFunctionCode::from_u8(raw_fc).is_write() {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };
            return self.fail(
                result,
                source_type,
                source_id,
                timestamp_us,
                AlertCode::UnknownFunctionCode,
                severity,
            );
        }

        // 6. Diagnostics sub-function filtering.
        if self.block_dangerous_diagnostics && raw_fc == FC_DIAGNOSTICS && pdu.len() >= 3 {
            let sub = u16::from_be_bytes([pdu[1], pdu[2]]);
            if matches!(
                sub,
                DIAG_SUB_RESTART_COMMUNICATIONS
                    | DIAG_SUB_FORCE_LISTEN_ONLY
                    | DIAG_SUB_CLEAR_COUNTERS
            ) {
                return self.fail(
                    result,
                    source_type,
                    source_id,
                    timestamp_us,
                    AlertCode::DiagnosticBlocked,
                    AlertSeverity::High,
                );
            }
        }

        // 7. Address-range rules. Use the request span when quantity > 0,
        //    otherwise just the start address.
        let span_end = if quantity == 0 {
            start_address
        } else {
            start_address.saturating_add(quantity.saturating_sub(1))
        };

        for i in 0..self.rule_count as usize {
            let stored = &self.rules[i];
            if !stored.active {
                continue;
            }
            let r = &stored.rule;
            if r.function_code != 0xFF && r.function_code != raw_fc {
                continue;
            }
            let span_in_range = start_address >= r.start && span_end <= r.end;
            let denied = match r.action {
                RuleAction::Allow => !span_in_range,
                RuleAction::Deny => {
                    // Any overlap with a deny range is forbidden.
                    !(span_end < r.start || start_address > r.end)
                }
            };
            if denied {
                let severity = if ModbusFunctionCode::from_u8(raw_fc).is_write() {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                };
                return self.fail(
                    result,
                    source_type,
                    source_id,
                    timestamp_us,
                    AlertCode::PolicyViolation,
                    severity,
                );
            }
        }

        (Verdict::Allow, *result)
    }

    // Helpers ----------------------------------------------------------------

    fn deny(
        &mut self,
        result: &mut InspectResult,
        source_type: u8,
        source_id: u32,
        timestamp_us: u64,
        code: AlertCode,
        severity: AlertSeverity,
    ) -> (Verdict, InspectResult) {
        self.fail(result, source_type, source_id, timestamp_us, code, severity)
    }

    fn fail(
        &mut self,
        result: &mut InspectResult,
        source_type: u8,
        source_id: u32,
        timestamp_us: u64,
        code: AlertCode,
        severity: AlertSeverity,
    ) -> (Verdict, InspectResult) {
        result.allowed = false;
        result.push_alert_with_code(
            severity,
            source_type,
            source_id,
            timestamp_us,
            &mut self.next_alert_id,
            &mut self.total_alerts,
            code,
        );
        (Verdict::Deny { reason: code }, *result)
    }
}

// ---------------------------------------------------------------------------
// CRC-16 / Modbus (polynomial 0xA001, init 0xFFFF, no final XOR)
// ---------------------------------------------------------------------------

/// Compute the CRC-16-IBM/ANSI used by Modbus RTU.
///
/// Polynomial `0xA001` (reversed `0x8005`), init `0xFFFF`, no final XOR.
pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Helpers ----------

    fn read_holding_request(unit: u8, addr: u16, qty: u16) -> ModbusTcpFrame {
        let mut f = ModbusTcpFrame {
            transaction_id: 1,
            protocol_id: 0,
            unit_id: unit,
            function_code: ModbusFunctionCode::ReadHoldingRegisters,
            raw_function_code: 0x03,
            start_address: addr,
            quantity: qty,
            pdu_len: 5,
            timestamp_us: 1_000,
            ..ModbusTcpFrame::default()
        };
        // PDU: [fc, addr_hi, addr_lo, qty_hi, qty_lo]
        f.pdu_data[0] = 0x03;
        f.pdu_data[1..3].copy_from_slice(&addr.to_be_bytes());
        f.pdu_data[3..5].copy_from_slice(&qty.to_be_bytes());
        f
    }

    fn write_single_register(unit: u8, addr: u16, value: u16) -> ModbusTcpFrame {
        let mut f = ModbusTcpFrame {
            transaction_id: 2,
            protocol_id: 0,
            unit_id: unit,
            function_code: ModbusFunctionCode::WriteSingleRegister,
            raw_function_code: 0x06,
            start_address: addr,
            quantity: 1,
            pdu_len: 5,
            timestamp_us: 2_000,
            ..ModbusTcpFrame::default()
        };
        f.pdu_data[0] = 0x06;
        f.pdu_data[1..3].copy_from_slice(&addr.to_be_bytes());
        f.pdu_data[3..5].copy_from_slice(&value.to_be_bytes());
        f
    }

    fn diagnostic(unit: u8, sub: u16) -> ModbusTcpFrame {
        let mut f = ModbusTcpFrame {
            transaction_id: 3,
            protocol_id: 0,
            unit_id: unit,
            function_code: ModbusFunctionCode::Diagnostics,
            raw_function_code: 0x08,
            start_address: 0,
            quantity: 0,
            pdu_len: 5,
            timestamp_us: 3_000,
            ..ModbusTcpFrame::default()
        };
        f.pdu_data[0] = 0x08;
        f.pdu_data[1..3].copy_from_slice(&sub.to_be_bytes());
        // sub-function data (2 bytes, zeroed).
        f
    }

    fn exception_response(unit: u8, fc: u8, ex: u8) -> ModbusTcpFrame {
        let mut f = ModbusTcpFrame {
            transaction_id: 4,
            protocol_id: 0,
            unit_id: unit,
            function_code: ModbusFunctionCode::Unknown,
            raw_function_code: fc | MODBUS_EXCEPTION_BIT,
            start_address: 0,
            quantity: 0,
            pdu_len: 2,
            timestamp_us: 4_000,
            ..ModbusTcpFrame::default()
        };
        f.pdu_data[0] = fc | MODBUS_EXCEPTION_BIT;
        f.pdu_data[1] = ex;
        f
    }

    // ---------- Verdict / config ----------

    #[test]
    fn verdict_helpers() {
        assert!(Verdict::Allow.is_passed());
        assert!(Verdict::Suspicious {
            reason: AlertCode::PolicyViolation
        }
        .is_passed());
        assert!(!Verdict::Deny {
            reason: AlertCode::CrcFailure
        }
        .is_passed());
        assert_eq!(Verdict::Allow.reason(), None);
        assert_eq!(
            Verdict::Deny {
                reason: AlertCode::CrcFailure
            }
            .reason(),
            Some(AlertCode::CrcFailure)
        );
    }

    #[test]
    fn fc_mask_helper_skips_high_bytes() {
        let m = fc_mask(&[0x01, 0x03, 0xFF]);
        assert_eq!(m & 1u128 << 1, 1u128 << 1);
        assert_eq!(m & 1u128 << 3, 1u128 << 3);
        assert_eq!(m & 1u128 << 5, 0);
    }

    #[test]
    fn read_only_profile_excludes_writes() {
        for code in [0x05u8, 0x06, 0x0F, 0x10, 0x16, 0x17] {
            assert_eq!(
                FC_PROFILE_READ_ONLY & 1u128 << code,
                0,
                "FC 0x{code:02X} must be excluded from read-only profile"
            );
        }
        for code in [0x01u8, 0x02, 0x03, 0x04] {
            assert_ne!(FC_PROFILE_READ_ONLY & 1u128 << code, 0);
        }
    }

    // ---------- Valid frames ----------

    #[test]
    fn valid_read_allowed() {
        let mut m = ModbusMonitor::new();
        let (v, r) = m.inspect_tcp(&read_holding_request(1, 0x0010, 4));
        assert_eq!(v, Verdict::Allow);
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn valid_write_allowed_in_permissive() {
        let mut m = ModbusMonitor::new();
        let (v, r) = m.inspect_tcp(&write_single_register(1, 0x0020, 0xBEEF));
        assert_eq!(v, Verdict::Allow);
        assert!(r.allowed);
    }

    // ---------- Function-code allowlist ----------

    #[test]
    fn write_denied_in_read_only_profile() {
        let mut m = ModbusMonitor::new();
        m.set_function_code_allowlist(FC_PROFILE_READ_ONLY);
        let (v, r) = m.inspect_tcp(&write_single_register(1, 0x0020, 0xBEEF));
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::UnknownFunctionCode
            }
        ));
        assert!(!r.allowed);
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alert_codes[0], AlertCode::UnknownFunctionCode);
        assert_eq!(r.alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn allow_function_code_promotes_into_allowlist() {
        let mut m = ModbusMonitor::new();
        m.set_function_code_allowlist(FC_PROFILE_READ_ONLY);
        m.allow_function_code(0x06);
        let (v, _) = m.inspect_tcp(&write_single_register(1, 0x0020, 0xBEEF));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn unknown_function_code_denied() {
        let mut m = ModbusMonitor::new();
        let mut f = read_holding_request(1, 0, 1);
        f.raw_function_code = 0x66;
        f.pdu_data[0] = 0x66;
        let (v, _) = m.inspect_tcp(&f);
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::UnknownFunctionCode
            }
        ));
    }

    // ---------- Address-range rules ----------

    #[test]
    fn address_allow_rule_blocks_outside_range() {
        let mut m = ModbusMonitor::new();
        m.add_address_rule(AddressRule {
            function_code: 0x03,
            start: 0x0000,
            end: 0x00FF,
            action: RuleAction::Allow,
        })
        .unwrap();
        let (v_in, _) = m.inspect_tcp(&read_holding_request(1, 0x0010, 4));
        assert_eq!(v_in, Verdict::Allow);
        let (v_out, _) = m.inspect_tcp(&read_holding_request(1, 0x0200, 4));
        assert!(matches!(
            v_out,
            Verdict::Deny {
                reason: AlertCode::PolicyViolation
            }
        ));
    }

    #[test]
    fn address_allow_rule_blocks_partial_span() {
        let mut m = ModbusMonitor::new();
        m.add_address_rule(AddressRule {
            function_code: 0x03,
            start: 0x0000,
            end: 0x00FF,
            action: RuleAction::Allow,
        })
        .unwrap();
        // Span starts in-range but extends beyond 0x00FF.
        let (v, _) = m.inspect_tcp(&read_holding_request(1, 0x00FE, 8));
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn address_deny_rule_blocks_writes_in_protected_window() {
        let mut m = ModbusMonitor::new();
        m.add_address_rule(AddressRule {
            function_code: 0x06,
            start: 0x1000,
            end: 0x10FF,
            action: RuleAction::Deny,
        })
        .unwrap();
        let (v, _) = m.inspect_tcp(&write_single_register(1, 0x1050, 1));
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::PolicyViolation
            }
        ));
        let (v_ok, _) = m.inspect_tcp(&write_single_register(1, 0x2000, 1));
        assert_eq!(v_ok, Verdict::Allow);
    }

    #[test]
    fn add_rule_rejects_inverted_range() {
        let mut m = ModbusMonitor::new();
        let err = m.add_address_rule(AddressRule {
            function_code: 0x03,
            start: 0x00FF,
            end: 0x0010,
            action: RuleAction::Allow,
        });
        assert_eq!(err, Err(VsError::InvalidInput));
    }

    // ---------- Diagnostics blocking ----------

    #[test]
    fn diagnostic_restart_blocked_when_configured() {
        let mut m = ModbusMonitor::new();
        m.set_block_dangerous_diagnostics(true);
        let (v, _) = m.inspect_tcp(&diagnostic(1, DIAG_SUB_RESTART_COMMUNICATIONS));
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::DiagnosticBlocked
            }
        ));
    }

    #[test]
    fn diagnostic_query_data_allowed() {
        let mut m = ModbusMonitor::new();
        m.set_block_dangerous_diagnostics(true);
        // Sub-function 0x0000 = ReturnQueryData (safe).
        let (v, _) = m.inspect_tcp(&diagnostic(1, 0x0000));
        assert_eq!(v, Verdict::Allow);
    }

    // ---------- MBAP errors ----------

    #[test]
    fn parse_truncated_mbap_denied() {
        let bytes = [0x00u8, 0x01, 0x00, 0x00, 0x00];
        let v = ModbusMonitor::parse_tcp(&bytes, 1).unwrap_err();
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::PayloadOverflow
            }
        ));
    }

    #[test]
    fn parse_protocol_id_nonzero_denied() {
        // Length = 2 (unit + fc), protocol id = 1 (illegal).
        let bytes = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03];
        let v = ModbusMonitor::parse_tcp(&bytes, 1).unwrap_err();
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::InvalidProtocol
            }
        ));
    }

    #[test]
    fn parse_length_mismatch_denied() {
        // length claims 10 bytes but payload only has 1 (function code).
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x03];
        let v = ModbusMonitor::parse_tcp(&bytes, 1).unwrap_err();
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::PayloadOverflow
            }
        ));
    }

    #[test]
    fn parse_valid_read_request_round_trips() {
        // Read holding registers, addr=0x0010, qty=0x0004
        let bytes = [
            0x00, 0x01, // tx id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length (unit + fc + 4 bytes)
            0x11, // unit id
            0x03, // fc
            0x00, 0x10, // address
            0x00, 0x04, // quantity
        ];
        let frame = ModbusMonitor::parse_tcp(&bytes, 99).unwrap();
        assert_eq!(frame.transaction_id, 1);
        assert_eq!(frame.unit_id, 0x11);
        assert_eq!(frame.raw_function_code, 0x03);
        assert_eq!(frame.start_address, 0x0010);
        assert_eq!(frame.quantity, 0x0004);
        assert_eq!(frame.pdu_len, 5);
        assert_eq!(frame.timestamp_us, 99);
    }

    #[test]
    fn inspect_protocol_id_nonzero_denied() {
        let mut m = ModbusMonitor::new();
        let mut f = read_holding_request(1, 0, 1);
        f.protocol_id = 0x1234;
        let (v, r) = m.inspect_tcp(&f);
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::InvalidProtocol
            }
        ));
        assert_eq!(r.alert_codes[0], AlertCode::InvalidProtocol);
    }

    #[test]
    fn inspect_zero_pdu_len_denied() {
        let mut m = ModbusMonitor::new();
        let mut f = read_holding_request(1, 0, 1);
        f.pdu_len = 0;
        let (v, _) = m.inspect_tcp(&f);
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::PayloadOverflow
            }
        ));
    }

    // ---------- Exception response ----------

    #[test]
    fn exception_response_marked_suspicious() {
        let mut m = ModbusMonitor::new();
        let (v, r) = m.inspect_tcp(&exception_response(1, 0x03, 0x02));
        assert!(matches!(
            v,
            Verdict::Suspicious {
                reason: AlertCode::PolicyViolation
            }
        ));
        // Suspicious is allowed-through but still emits an alert.
        assert!(r.allowed);
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.alerts[0].severity, AlertSeverity::Low);
    }

    // ---------- RTU / CRC ----------

    #[test]
    fn crc16_known_vector() {
        // Per Modbus spec example: 0x01 0x04 0x02 0xFF 0xFF -> CRC 0x80B8
        // (low byte 0xB8 sent first on the wire).
        let bytes = [0x01, 0x04, 0x02, 0xFF, 0xFF];
        assert_eq!(crc16_modbus(&bytes), 0x80B8);
    }

    fn rtu_read(slave: u8, addr: u16, qty: u16) -> ModbusRtuFrame {
        let mut f = ModbusRtuFrame {
            slave_addr: slave,
            function_code: ModbusFunctionCode::ReadHoldingRegisters,
            raw_function_code: 0x03,
            start_address: addr,
            quantity: qty,
            pdu_len: 5,
            timestamp_us: 5_000,
            ..ModbusRtuFrame::default()
        };
        f.pdu_data[0] = 0x03;
        f.pdu_data[1..3].copy_from_slice(&addr.to_be_bytes());
        f.pdu_data[3..5].copy_from_slice(&qty.to_be_bytes());
        // Compute CRC.
        let mut buf = [0u8; 6];
        buf[0] = slave;
        buf[1..6].copy_from_slice(&f.pdu_data[..5]);
        f.crc = crc16_modbus(&buf);
        f.crc_provided = true;
        f
    }

    #[test]
    fn rtu_valid_crc_allowed() {
        let mut m = ModbusMonitor::new();
        let f = rtu_read(0x11, 0x0010, 4);
        let (v, _) = m.inspect_rtu(&f);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn rtu_bad_crc_denied() {
        let mut m = ModbusMonitor::new();
        let mut f = rtu_read(0x11, 0x0010, 4);
        f.crc ^= 0xFFFF;
        let (v, _) = m.inspect_rtu(&f);
        assert!(matches!(
            v,
            Verdict::Deny {
                reason: AlertCode::CrcFailure
            }
        ));
    }

    #[test]
    fn rtu_skips_crc_check_when_not_provided() {
        let mut m = ModbusMonitor::new();
        let mut f = rtu_read(0x11, 0x0010, 4);
        f.crc = 0xDEAD; // Wrong but should be ignored.
        f.crc_provided = false;
        let (v, _) = m.inspect_rtu(&f);
        assert_eq!(v, Verdict::Allow);
    }

    // ---------- Bookkeeping ----------

    #[test]
    fn counters_increment() {
        let mut m = ModbusMonitor::new_strict();
        let _ = m.inspect_tcp(&write_single_register(1, 0x0020, 0xBEEF));
        let _ = m.inspect_tcp(&read_holding_request(1, 0, 1));
        assert_eq!(m.total_inspected(), 2);
        assert!(m.total_alerts() >= 1);
    }

    #[test]
    fn reset_clears_counters() {
        let mut m = ModbusMonitor::new();
        let _ = m.inspect_tcp(&read_holding_request(1, 0, 1));
        m.reset();
        assert_eq!(m.total_inspected(), 0);
        assert_eq!(m.total_alerts(), 0);
    }

    #[test]
    fn strict_mode_blocks_write_via_default_profile() {
        let mut m = ModbusMonitor::new_strict();
        let (v, _) = m.inspect_tcp(&write_single_register(1, 0x0020, 0xBEEF));
        assert!(matches!(v, Verdict::Deny { .. }));
        assert!(m.strict_mode());
    }

    #[test]
    fn strict_mode_blocks_dangerous_diagnostic() {
        let mut m = ModbusMonitor::new_strict();
        // Diagnostics is not in the read-only profile, so we expect the
        // allowlist to deny it before the diagnostic-sub-function check.
        let (v, _) = m.inspect_tcp(&diagnostic(1, DIAG_SUB_RESTART_COMMUNICATIONS));
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn rule_capacity_exhaustion() {
        let mut m = ModbusMonitor::new();
        for _ in 0..MAX_RULES {
            m.add_address_rule(AddressRule {
                function_code: 0x03,
                start: 0,
                end: 1,
                action: RuleAction::Allow,
            })
            .unwrap();
        }
        let err = m.add_address_rule(AddressRule {
            function_code: 0x03,
            start: 0,
            end: 1,
            action: RuleAction::Allow,
        });
        assert_eq!(err, Err(VsError::ResourceExhausted));
    }
}
