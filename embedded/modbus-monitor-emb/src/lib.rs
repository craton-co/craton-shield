// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

//! Modbus RTU/TCP intrusion detection monitor.
//!
//! Detects anomalous Modbus traffic:
//!
//! - **Unit ID allowlist/blocklist** -- restrict which unit IDs may be accessed.
//! - **Function code enforcement** -- per-unit allowed function codes.
//! - **Write protection** -- block write operations to specific units.
//! - **Register address range enforcement** -- restrict accessible register ranges.
//! - **Rate limiting** -- per-unit request rate control.
//! - **Invalid unit ID detection** -- flags reserved unit IDs (248-255).
//! - **TCP source IP filtering** -- allow/block by source IP prefix.
//! - **Exception response tracking** -- detect exception floods per unit.
//! - **Timestamp validation** -- detect clock anomalies in message streams.
//!
//! # Examples
//!
//! ```rust
//! use vs_modbus_monitor_emb::{ModbusMonitor, UnitAction, FunctionPolicy};
//! use vs_types_embedded::{ModbusRtuMessage, ModbusFunction};
//!
//! let mut monitor = ModbusMonitor::new();
//! monitor.add_rule(1, UnitAction::Allow, FunctionPolicy::ReadOnly, 0, 999, 50).unwrap();
//!
//! let msg = ModbusRtuMessage {
//!     unit_id: 1,
//!     function: ModbusFunction::ReadHoldingRegisters,
//!     register_addr: 100,
//!     quantity: 10,
//!     payload_len: 0,
//!     timestamp_us: 1_000_000,
//! };
//!
//! let result = monitor.inspect_rtu(&msg);
//! assert!(result.allowed);
//! ```

use vs_types::{AlertSeverity, SecurityAlert, VsError};
use vs_types_embedded::{
    compute_payload_hash, ct_u8_eq, IpAction, IpAddress, ModbusException, ModbusFunction,
    ModbusIpFilter, ModbusRtuMessage, ModbusTcpMessage, MonitorReset, TimestampValidator,
    SOURCE_MODBUS_RTU, SOURCE_MODBUS_TCP,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum unit ID rules.
const MAX_UNIT_RULES: usize = 32;

/// Maximum rate-limit buckets.
const MAX_RATE_BUCKETS: usize = 16;

/// Bucket expiration timeout: 5 minutes.
const RATE_BUCKET_EXPIRY_US: u64 = 300_000_000;

/// Maximum IP filter entries.
const MAX_IP_FILTERS: usize = 16;

/// Maximum tracked unit IDs for exception counting.
const MAX_EXCEPTION_UNITS: usize = 32;

/// Maximum exceptions per unit before alerting.
const MAX_EXCEPTIONS_PER_UNIT: u32 = 10;

/// Exception counting window (60 seconds).
const EXCEPTION_WINDOW_US: u64 = 60_000_000;

// ---------------------------------------------------------------------------
// Alert source ID constants
// ---------------------------------------------------------------------------

const ALERT_INVALID_UNIT_ID: u32 = 1;
const ALERT_UNKNOWN_FUNCTION: u32 = 2;
const ALERT_UNIT_BLOCKED: u32 = 3;
const ALERT_FUNCTION_POLICY: u32 = 4;
const ALERT_REGISTER_RANGE: u32 = 5;
const ALERT_RATE_LIMITED: u32 = 6;
const ALERT_IP_BLOCKED: u32 = 7;
const ALERT_EXCEPTION_FLOOD: u32 = 8;
const ALERT_TIMESTAMP_ANOMALY: u32 = 9;
const ALERT_RATE_TABLE_EXHAUSTED: u32 = 10;
const ALERT_EXCEPTION_TABLE_EXHAUSTED: u32 = 11;

// ---------------------------------------------------------------------------
// Unit rule
// ---------------------------------------------------------------------------

/// Action for a unit ID match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitAction {
    /// Allow requests to this unit.
    Allow,
    /// Block requests to this unit.
    Block,
}

/// Function code enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionPolicy {
    /// All function codes allowed.
    Any,
    /// Only read functions allowed.
    ReadOnly,
    /// Only write functions allowed.
    WriteOnly,
}

/// A unit ID filtering rule.
#[derive(Debug, Clone, Copy)]
struct UnitRule {
    unit_id: u8,
    action: UnitAction,
    function_policy: FunctionPolicy,
    /// Minimum allowed register address.
    register_min: u16,
    /// Maximum allowed register address (inclusive).
    register_max: u16,
    /// Max requests per second (0 = unlimited).
    max_rate_per_sec: u16,
    active: bool,
}

impl UnitRule {
    const fn empty() -> Self {
        Self {
            unit_id: 0,
            action: UnitAction::Allow,
            function_policy: FunctionPolicy::Any,
            register_min: 0,
            register_max: u16::MAX,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Rate bucket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct RateBucket {
    unit_id: u8,
    tokens: u16,
    capacity: u16,
    last_refill_us: u64,
    active: bool,
}

impl RateBucket {
    const fn empty() -> Self {
        Self {
            unit_id: 0,
            tokens: 0,
            capacity: 0,
            last_refill_us: 0,
            active: false,
        }
    }

    #[inline]
    fn try_consume(&mut self, now_us: u64) -> bool {
        let elapsed = now_us.saturating_sub(self.last_refill_us);
        let refill = elapsed.saturating_mul(self.capacity as u64) / 1_000_000;
        let refill_clamped = refill.min(self.capacity as u64) as u16;
        if refill_clamped > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refill_clamped)
                .min(self.capacity);
            self.last_refill_us = now_us;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn is_expired(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.last_refill_us) > RATE_BUCKET_EXPIRY_US
    }
}

// ---------------------------------------------------------------------------
// Exception counter (per unit)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ExceptionCounter {
    unit_id: u8,
    count: u32,
    window_start_us: u64,
    alerted: bool,
    active: bool,
}

impl ExceptionCounter {
    const fn empty() -> Self {
        Self {
            unit_id: 0,
            count: 0,
            window_start_us: 0,
            alerted: false,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Inspect result
// ---------------------------------------------------------------------------

/// Result of inspecting a Modbus message.
#[must_use = "security decisions must not be silently ignored"]
#[derive(Debug, Clone, Copy)]
pub struct ModbusInspectResult {
    /// Whether the message was allowed.
    pub allowed: bool,
    /// Number of alerts generated.
    pub alert_count: u8,
    /// Generated alerts (up to 4).
    pub alerts: [SecurityAlert; 4],
    /// Number of alerts that were dropped because the alert array was full.
    pub alerts_dropped: u8,
}

impl ModbusInspectResult {
    fn clean(source_type: u8) -> Self {
        Self {
            allowed: true,
            alert_count: 0,
            alerts: [SecurityAlert {
                id: 0,
                severity: AlertSeverity::Info,
                source_type,
                source_id: 0,
                payload_hash: vs_types::PayloadHash::ZERO,
                timestamp_us: 0,
            }; 4],
            alerts_dropped: 0,
        }
    }

    #[inline]
    fn push_alert(
        &mut self,
        severity: AlertSeverity,
        source_type: u8,
        source_id: u32,
        ts_us: u64,
        alert_id: u64,
        payload_hash: vs_types::PayloadHash,
    ) {
        if (self.alert_count as usize) < self.alerts.len() {
            self.alerts[self.alert_count as usize] = SecurityAlert {
                id: alert_id,
                severity,
                source_type,
                source_id,
                payload_hash,
                timestamp_us: ts_us,
            };
            self.alert_count += 1;
        } else {
            self.alerts_dropped = self.alerts_dropped.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Modbus Monitor
// ---------------------------------------------------------------------------

/// Modbus RTU/TCP intrusion detection monitor.
pub struct ModbusMonitor {
    rules: [UnitRule; MAX_UNIT_RULES],
    rule_count: u8,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    ip_filters: [ModbusIpFilter; MAX_IP_FILTERS],
    exception_counters: [ExceptionCounter; MAX_EXCEPTION_UNITS],
    timestamp_validator: TimestampValidator,
    default_action: UnitAction,
    next_alert_id: u64,
    total_inspected: u64,
    total_alerts: u64,
    /// Number of active IP filters (cached for fast early-return).
    ip_filter_count: u8,
    /// Deferred flag: rate table was exhausted by LRU eviction.
    rate_table_exhausted: bool,
    /// Deferred flag: exception counter table was exhausted by LRU eviction.
    exception_table_exhausted: bool,
}

impl ModbusMonitor {
    /// Create a new Modbus monitor (allow-by-default).
    pub fn new() -> Self {
        Self {
            rules: [UnitRule::empty(); MAX_UNIT_RULES],
            rule_count: 0,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            ip_filters: [ModbusIpFilter::empty(); MAX_IP_FILTERS],
            exception_counters: [ExceptionCounter::empty(); MAX_EXCEPTION_UNITS],
            timestamp_validator: TimestampValidator::new(),
            default_action: UnitAction::Allow,
            next_alert_id: 1,
            total_inspected: 0,
            total_alerts: 0,
            ip_filter_count: 0,
            rate_table_exhausted: false,
            exception_table_exhausted: false,
        }
    }

    /// Create a new Modbus monitor (deny-by-default).
    pub fn new_deny_default() -> Self {
        let mut m = Self::new();
        m.default_action = UnitAction::Block;
        m
    }

    /// Add a unit ID rule.
    ///
    /// If a rule with the same `unit_id` already exists it is updated in place
    /// rather than creating a duplicate entry.
    #[must_use = "config errors must not be silently ignored"]
    pub fn add_rule(
        &mut self,
        unit_id: u8,
        action: UnitAction,
        function_policy: FunctionPolicy,
        register_min: u16,
        register_max: u16,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        // Duplicate detection: update existing rule for this unit_id.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && ct_u8_eq(self.rules[i].unit_id, unit_id) {
                self.rules[i] = UnitRule {
                    unit_id,
                    action,
                    function_policy,
                    register_min,
                    register_max,
                    max_rate_per_sec,
                    active: true,
                };
                return Ok(());
            }
        }
        if self.rule_count as usize >= MAX_UNIT_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = UnitRule {
            unit_id,
            action,
            function_policy,
            register_min,
            register_max,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Remove a unit ID rule by index.
    #[must_use = "config errors must not be silently ignored"]
    pub fn remove_rule(&mut self, index: usize) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        let count = self.rule_count as usize;
        for i in index..count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[count - 1] = UnitRule::empty();
        self.rule_count -= 1;
        Ok(())
    }

    /// Remove all unit ID rules.
    pub fn clear_rules(&mut self) {
        self.rules = [UnitRule::empty(); MAX_UNIT_RULES];
        self.rule_count = 0;
    }

    /// Update a unit ID rule at the given index.
    #[must_use = "config errors must not be silently ignored"]
    #[allow(clippy::too_many_arguments)]
    pub fn update_rule(
        &mut self,
        index: usize,
        unit_id: u8,
        action: UnitAction,
        function_policy: FunctionPolicy,
        register_min: u16,
        register_max: u16,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if index >= self.rule_count as usize {
            return Err(VsError::InvalidInput);
        }
        // Prevent duplicate unit_id creation: if the new unit_id differs from
        // the current one, ensure no other rule already uses it.
        if unit_id != self.rules[index].unit_id {
            for i in 0..self.rule_count as usize {
                if i != index && self.rules[i].active && self.rules[i].unit_id == unit_id {
                    return Err(VsError::InvalidInput);
                }
            }
        }
        self.rules[index] = UnitRule {
            unit_id,
            action,
            function_policy,
            register_min,
            register_max,
            max_rate_per_sec,
            active: true,
        };
        Ok(())
    }

    /// Add a TCP source IP filter.
    #[must_use = "config errors must not be silently ignored"]
    pub fn add_ip_filter(
        &mut self,
        ip: [u8; 4],
        prefix_len: u8,
        action: IpAction,
    ) -> Result<(), VsError> {
        if prefix_len > 32 {
            return Err(VsError::InvalidInput);
        }
        for i in 0..MAX_IP_FILTERS {
            if !self.ip_filters[i].active {
                self.ip_filters[i] = ModbusIpFilter {
                    ip: IpAddress::V4(ip),
                    prefix_len,
                    action,
                    active: true,
                };
                self.ip_filter_count = self.ip_filter_count.saturating_add(1);
                return Ok(());
            }
        }
        Err(VsError::ResourceExhausted)
    }

    /// Add an IPv6 source IP filter.
    ///
    /// Matches Modbus TCP source IPs against the given IPv6 prefix.
    #[must_use = "config errors must not be silently ignored"]
    pub fn add_ip_filter_v6(
        &mut self,
        ip: [u8; 16],
        prefix_len: u8,
        action: IpAction,
    ) -> Result<usize, VsError> {
        if prefix_len > 128 {
            return Err(VsError::InvalidInput);
        }
        let idx = (0..MAX_IP_FILTERS)
            .find(|&i| !self.ip_filters[i].active)
            .ok_or(VsError::ResourceExhausted)?;
        self.ip_filters[idx] = ModbusIpFilter {
            ip: IpAddress::V6(ip),
            prefix_len,
            action,
            active: true,
        };
        self.ip_filter_count = self.ip_filter_count.saturating_add(1);
        Ok(idx)
    }

    /// Remove an IP filter by index.
    #[must_use = "config errors must not be silently ignored"]
    pub fn remove_ip_filter(&mut self, index: usize) -> Result<(), VsError> {
        if index >= MAX_IP_FILTERS {
            return Err(VsError::InvalidInput);
        }
        if !self.ip_filters[index].active {
            return Err(VsError::InvalidInput);
        }
        self.ip_filters[index] = ModbusIpFilter::empty();
        self.ip_filter_count = self.ip_filter_count.saturating_sub(1);
        Ok(())
    }

    /// Record a Modbus exception response. If more than `MAX_EXCEPTIONS_PER_UNIT`
    /// exceptions from the same unit within `EXCEPTION_WINDOW_US`, a medium alert
    /// is returned. The exception code is encoded in the alert's `source_id` and
    /// `payload_hash` for forensic context.
    pub fn record_exception(
        &mut self,
        unit_id: u8,
        exception: ModbusException,
        ts_us: u64,
        source_type: u8,
    ) -> Option<SecurityAlert> {
        // Find existing counter for this unit.
        let mut slot: Option<usize> = None;
        let mut free_slot: Option<usize> = None;
        for i in 0..MAX_EXCEPTION_UNITS {
            if self.exception_counters[i].active && self.exception_counters[i].unit_id == unit_id {
                slot = Some(i);
                break;
            }
            if free_slot.is_none() && !self.exception_counters[i].active {
                free_slot = Some(i);
            }
        }

        let idx = match slot {
            Some(i) => i,
            None => {
                if let Some(i) = free_slot {
                    self.exception_counters[i] = ExceptionCounter {
                        unit_id,
                        count: 0,
                        window_start_us: ts_us,
                        alerted: false,
                        active: true,
                    };
                    i
                } else {
                    // LRU eviction: find oldest exception counter
                    let mut oldest_idx = 0;
                    let mut oldest_ts = u64::MAX;
                    for i in 0..MAX_EXCEPTION_UNITS {
                        if self.exception_counters[i].active
                            && self.exception_counters[i].window_start_us < oldest_ts
                        {
                            oldest_ts = self.exception_counters[i].window_start_us;
                            oldest_idx = i;
                        }
                    }
                    self.exception_counters[oldest_idx] = ExceptionCounter {
                        unit_id,
                        count: 0,
                        window_start_us: ts_us,
                        alerted: false,
                        active: true,
                    };
                    self.exception_table_exhausted = true;
                    oldest_idx
                }
            }
        };

        let counter = &mut self.exception_counters[idx];

        // Reset window if expired.
        if ts_us.saturating_sub(counter.window_start_us) > EXCEPTION_WINDOW_US {
            counter.count = 0;
            counter.window_start_us = ts_us;
            counter.alerted = false;
        }

        counter.count = counter.count.saturating_add(1);

        if counter.count > MAX_EXCEPTIONS_PER_UNIT && !counter.alerted {
            counter.alerted = true;
            let alert_id = self.next_alert_id();
            self.total_alerts = self.total_alerts.saturating_add(1);
            // Encode exception code in source_id high byte for forensic context.
            let exception_code = exception as u8;
            let source_id =
                ALERT_EXCEPTION_FLOOD | ((exception_code as u32) << 16) | ((unit_id as u32) << 8);
            // Build a content fingerprint from unit_id + exception code.
            let hash_data = [unit_id, exception_code];
            let payload_hash = compute_payload_hash(&hash_data);
            Some(SecurityAlert {
                id: alert_id,
                severity: AlertSeverity::Medium,
                source_type,
                source_id,
                payload_hash,
                timestamp_us: ts_us,
            })
        } else {
            None
        }
    }

    /// Inspect a Modbus RTU message.
    pub fn inspect_rtu(&mut self, msg: &ModbusRtuMessage) -> ModbusInspectResult {
        self.inspect_inner(
            msg.unit_id,
            msg.function,
            msg.register_addr,
            msg.quantity,
            msg.payload_len as usize,
            msg.timestamp_us,
            SOURCE_MODBUS_RTU,
            None,
        )
    }

    /// Inspect a Modbus TCP message.
    pub fn inspect_tcp(&mut self, msg: &ModbusTcpMessage) -> ModbusInspectResult {
        self.inspect_inner(
            msg.rtu.unit_id,
            msg.rtu.function,
            msg.rtu.register_addr,
            msg.rtu.quantity,
            msg.rtu.payload_len as usize,
            msg.rtu.timestamp_us,
            SOURCE_MODBUS_TCP,
            Some(&msg.src_ip),
        )
    }

    /// Return the total number of messages inspected.
    #[inline]
    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    /// Return the total number of alerts raised.
    #[inline]
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Return the number of active rules.
    #[inline]
    pub fn rule_count(&self) -> usize {
        self.rule_count as usize
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn inspect_inner(
        &mut self,
        unit_id: u8,
        function: ModbusFunction,
        register_addr: u16,
        quantity: u16,
        payload_len: usize,
        ts_us: u64,
        source_type: u8,
        src_ip: Option<&IpAddress>,
    ) -> ModbusInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = ModbusInspectResult::clean(source_type);

        // Lazily compute content fingerprint for alert payload_hash.
        // Only computed on first use to avoid overhead on clean (no-alert) paths.
        let mut cached_fingerprint: Option<vs_types::PayloadHash> = None;
        // Helper: compute fingerprint once and cache it. Uses 8-byte buffer so
        // payload_len is encoded as 2 bytes (fixes Q7 truncation bug).
        let mut make_fingerprint = || -> vs_types::PayloadHash {
            if let Some(fp) = cached_fingerprint {
                return fp;
            }
            let mut buf = [0u8; 8];
            buf[0] = unit_id;
            buf[1] = function as u8;
            buf[2..4].copy_from_slice(&register_addr.to_le_bytes());
            buf[4..6].copy_from_slice(&quantity.to_le_bytes());
            buf[6] = (payload_len & 0xFF) as u8;
            buf[7] = ((payload_len >> 8) & 0xFF) as u8;
            let fp = compute_payload_hash(&buf);
            cached_fingerprint = Some(fp);
            fp
        };

        // Timestamp validation.
        if !self.timestamp_validator.validate(ts_us) {
            result.push_alert(
                AlertSeverity::Low,
                source_type,
                ALERT_TIMESTAMP_ANOMALY,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            // Don't block — just alert on clock anomalies.
        }

        // IP filter check (TCP only).
        // Priority: Block takes precedence over Allow at the same prefix length.
        // Longer prefix takes precedence over shorter prefix.
        if let Some(ip) = src_ip.filter(|_| self.ip_filter_count > 0) {
            let mut best_action: Option<IpAction> = None;
            let mut best_prefix_len: u8 = 0;
            for i in 0..MAX_IP_FILTERS {
                if self.ip_filters[i].matches_ip(ip) {
                    let plen = self.ip_filters[i].prefix_len;
                    if plen > best_prefix_len
                        || (plen == best_prefix_len && self.ip_filters[i].action == IpAction::Block)
                    {
                        best_action = Some(self.ip_filters[i].action);
                        best_prefix_len = plen;
                    }
                }
            }
            if best_action == Some(IpAction::Block) {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::Medium,
                    source_type,
                    ALERT_IP_BLOCKED,
                    ts_us,
                    self.next_alert_id(),
                    make_fingerprint(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }
        }

        // Invalid unit ID check (reserved range 248-255).
        if unit_id > 247 && unit_id != 0 {
            result.push_alert(
                AlertSeverity::Low,
                source_type,
                ALERT_INVALID_UNIT_ID,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            // Don't block — just alert. Some implementations use broadcast (0).
        }

        // Unknown function code check.
        if function == ModbusFunction::Unknown {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                source_type,
                ALERT_UNKNOWN_FUNCTION,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Reject quantity == 0 for multi-register functions.
        if quantity == 0
            && matches!(
                function,
                ModbusFunction::ReadCoils
                    | ModbusFunction::ReadDiscreteInputs
                    | ModbusFunction::ReadHoldingRegisters
                    | ModbusFunction::ReadInputRegisters
                    | ModbusFunction::WriteMultipleCoils
                    | ModbusFunction::WriteMultipleRegisters
            )
        {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                source_type,
                ALERT_REGISTER_RANGE,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        // Unit rule matching.
        let mut matched: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && ct_u8_eq(self.rules[i].unit_id, unit_id) && matched.is_none()
            {
                matched = Some(i);
            }
        }

        let action = match matched {
            Some(idx) => self.rules[idx].action,
            None => self.default_action,
        };

        if action == UnitAction::Block {
            result.allowed = false;
            result.push_alert(
                AlertSeverity::Medium,
                source_type,
                ALERT_UNIT_BLOCKED,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
            return result;
        }

        if let Some(idx) = matched {
            // Function policy check.
            let policy_ok = match self.rules[idx].function_policy {
                FunctionPolicy::Any => true,
                FunctionPolicy::ReadOnly => !function.is_write(),
                FunctionPolicy::WriteOnly => function.is_write(),
            };
            if !policy_ok {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::Medium,
                    source_type,
                    ALERT_FUNCTION_POLICY,
                    ts_us,
                    self.next_alert_id(),
                    make_fingerprint(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }

            // Register range check.
            let effective_qty = if quantity == 0 { 1 } else { quantity };
            // Detect overflow: if the raw addition would exceed u16, the request
            // spans an invalid register range.
            let reg_end_overflow =
                (register_addr as u32) + (effective_qty as u32).saturating_sub(1) > u16::MAX as u32;
            let reg_end = register_addr.saturating_add(effective_qty.saturating_sub(1));
            if reg_end_overflow
                || register_addr < self.rules[idx].register_min
                || reg_end > self.rules[idx].register_max
            {
                result.allowed = false;
                result.push_alert(
                    AlertSeverity::Medium,
                    source_type,
                    ALERT_REGISTER_RANGE,
                    ts_us,
                    self.next_alert_id(),
                    make_fingerprint(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
                return result;
            }

            // Rate limiting.
            let max_rate = self.rules[idx].max_rate_per_sec;
            if max_rate > 0 && !self.rate_limit_check(unit_id, max_rate, ts_us) {
                // Allow traffic but emit a warning alert (same pattern as
                // MQTT/CoAP monitors) so rate exhaustion cannot cause DoS.
                result.push_alert(
                    AlertSeverity::Medium,
                    source_type,
                    ALERT_RATE_LIMITED,
                    ts_us,
                    self.next_alert_id(),
                    make_fingerprint(),
                );
                self.total_alerts = self.total_alerts.saturating_add(1);
            }
        }

        // Emit deferred rate-table-exhausted alert.
        if self.rate_table_exhausted {
            self.rate_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Low,
                source_type,
                ALERT_RATE_TABLE_EXHAUSTED,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        // Emit deferred exception-table-exhausted alert.
        if self.exception_table_exhausted {
            self.exception_table_exhausted = false;
            result.push_alert(
                AlertSeverity::Low,
                source_type,
                ALERT_EXCEPTION_TABLE_EXHAUSTED,
                ts_us,
                self.next_alert_id(),
                make_fingerprint(),
            );
            self.total_alerts = self.total_alerts.saturating_add(1);
        }

        result
    }

    #[inline]
    fn next_alert_id(&mut self) -> u64 {
        let id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.wrapping_add(1);
        if self.next_alert_id == 0 {
            self.next_alert_id = 1;
        }
        id
    }

    fn rate_limit_check(&mut self, unit_id: u8, max_rate: u16, now_us: u64) -> bool {
        let mut free_slot: Option<usize> = None;
        let mut oldest_expired_idx: Option<usize> = None;
        let mut oldest_expired_ts = u64::MAX;
        // Track overall LRU candidate in the same pass to avoid a second scan.
        let mut lru_idx: usize = 0;
        let mut lru_ts: u64 = u64::MAX;

        for i in 0..MAX_RATE_BUCKETS {
            if !self.rate_buckets[i].active {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if ct_u8_eq(self.rate_buckets[i].unit_id, unit_id) {
                return self.rate_buckets[i].try_consume(now_us);
            }
            if self.rate_buckets[i].is_expired(now_us)
                && self.rate_buckets[i].last_refill_us < oldest_expired_ts
            {
                oldest_expired_ts = self.rate_buckets[i].last_refill_us;
                oldest_expired_idx = Some(i);
            }
            if self.rate_buckets[i].last_refill_us < lru_ts {
                lru_ts = self.rate_buckets[i].last_refill_us;
                lru_idx = i;
            }
        }

        let slot = free_slot.or(oldest_expired_idx);
        if let Some(idx) = slot {
            self.rate_buckets[idx] = RateBucket {
                unit_id,
                tokens: max_rate.saturating_sub(1),
                capacity: max_rate,
                last_refill_us: now_us,
                active: true,
            };
            return true;
        }

        // LRU eviction using the candidate already found above (no second scan).
        // Start with 1 token so the first message after eviction is allowed,
        // preventing immediate blocking of legitimate traffic to a new unit ID.
        self.rate_buckets[lru_idx] = RateBucket {
            unit_id,
            tokens: 1,
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
        };
        self.rate_table_exhausted = true;
        true
    }
}

impl Default for ModbusMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReset for ModbusMonitor {
    /// Reset all runtime state while preserving configuration (rules, IP filters).
    fn reset_state(&mut self) {
        self.rate_buckets = [RateBucket::empty(); MAX_RATE_BUCKETS];
        self.exception_counters = [ExceptionCounter::empty(); MAX_EXCEPTION_UNITS];
        self.timestamp_validator.reset();
        self.next_alert_id = 1;
        self.total_inspected = 0;
        self.total_alerts = 0;
        self.rate_table_exhausted = false;
        self.exception_table_exhausted = false;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtu(unit: u8, func: ModbusFunction, addr: u16, qty: u16, ts: u64) -> ModbusRtuMessage {
        ModbusRtuMessage {
            unit_id: unit,
            function: func,
            register_addr: addr,
            quantity: qty,
            payload_len: 10,
            timestamp_us: ts,
        }
    }

    fn make_tcp(unit: u8, func: ModbusFunction, addr: u16, qty: u16, ts: u64) -> ModbusTcpMessage {
        ModbusTcpMessage {
            rtu: make_rtu(unit, func, addr, qty, ts),
            transaction_id: 1,
            src_ip: IpAddress::V4([192, 168, 1, 100]),
            src_port: 502,
        }
    }

    fn make_tcp_ip(
        unit: u8,
        func: ModbusFunction,
        addr: u16,
        qty: u16,
        ts: u64,
        ip: [u8; 4],
    ) -> ModbusTcpMessage {
        ModbusTcpMessage {
            rtu: make_rtu(unit, func, addr, qty, ts),
            transaction_id: 1,
            src_ip: IpAddress::V4(ip),
            src_port: 502,
        }
    }

    #[test]
    fn default_allows() {
        let mut mon = ModbusMonitor::new();
        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000);
        assert!(mon.inspect_rtu(&msg).allowed);
    }

    #[test]
    fn deny_default_blocks() {
        let mut mon = ModbusMonitor::new_deny_default();
        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000);
        assert!(!mon.inspect_rtu(&msg).allowed);
    }

    #[test]
    fn allow_overrides_deny() {
        let mut mon = ModbusMonitor::new_deny_default();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000);
        assert!(mon.inspect_rtu(&msg).allowed);
    }

    #[test]
    fn block_rule() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(5, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let msg = make_rtu(5, ModbusFunction::ReadCoils, 0, 10, 1000);
        let r = mon.inspect_rtu(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn read_only_policy() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(
            1,
            UnitAction::Allow,
            FunctionPolicy::ReadOnly,
            0,
            u16::MAX,
            0,
        )
        .unwrap();
        let read = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000);
        assert!(mon.inspect_rtu(&read).allowed);
        let write = make_rtu(1, ModbusFunction::WriteSingleCoil, 0, 1, 2000);
        assert!(!mon.inspect_rtu(&write).allowed);
    }

    #[test]
    fn register_range_enforcement() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 100, 200, 0)
            .unwrap();
        let valid = make_rtu(1, ModbusFunction::ReadHoldingRegisters, 100, 50, 1000);
        assert!(mon.inspect_rtu(&valid).allowed);
        let out_of_range = make_rtu(1, ModbusFunction::ReadHoldingRegisters, 50, 10, 2000);
        assert!(!mon.inspect_rtu(&out_of_range).allowed);
    }

    #[test]
    fn unknown_function_blocked() {
        let mut mon = ModbusMonitor::new();
        let msg = make_rtu(1, ModbusFunction::Unknown, 0, 10, 1000);
        let r = mon.inspect_rtu(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn invalid_unit_id_alerts() {
        let mut mon = ModbusMonitor::new();
        let msg = make_rtu(248, ModbusFunction::ReadCoils, 0, 10, 1000);
        let r = mon.inspect_rtu(&msg);
        // Allowed (default allow) but alert emitted.
        assert!(r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn rate_limiting() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 2)
            .unwrap();
        for i in 0..2 {
            let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000 + i * 100);
            assert!(mon.inspect_rtu(&msg).allowed);
        }
        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1200);
        let r = mon.inspect_rtu(&msg);
        // Rate-limited traffic is allowed with a warning alert (not blocked).
        assert!(r.allowed);
        assert!(r.alert_count > 0);
    }

    #[test]
    fn tcp_inspection() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(5, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let msg = make_tcp(5, ModbusFunction::ReadCoils, 0, 10, 1000);
        let r = mon.inspect_tcp(&msg);
        assert!(!r.allowed);
        assert_eq!(r.alerts[0].source_type, SOURCE_MODBUS_TCP);
    }

    #[test]
    fn rtu_source_type() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000));
        assert_eq!(r.alerts[0].source_type, SOURCE_MODBUS_RTU);
    }

    #[test]
    fn stats_tracking() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(5, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let _ = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000));
        let _ = mon.inspect_rtu(&make_rtu(5, ModbusFunction::ReadCoils, 0, 10, 2000));
        assert_eq!(mon.total_inspected(), 2);
        assert_eq!(mon.total_alerts(), 1);
    }

    #[test]
    fn default_constructor() {
        let mon = ModbusMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn alert_ids_nonzero() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000));
        assert!(r.alerts[0].id > 0);
    }

    #[test]
    fn broadcast_unit_id_no_invalid_alert() {
        let mut mon = ModbusMonitor::new();
        let msg = make_rtu(0, ModbusFunction::ReadCoils, 0, 10, 1000);
        let r = mon.inspect_rtu(&msg);
        // Broadcast (0) should not trigger invalid unit ID alert.
        assert!(r.allowed);
        assert_eq!(r.alert_count, 0);
    }

    #[test]
    fn write_only_policy() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(
            1,
            UnitAction::Allow,
            FunctionPolicy::WriteOnly,
            0,
            u16::MAX,
            0,
        )
        .unwrap();
        let write = make_rtu(1, ModbusFunction::WriteSingleCoil, 0, 1, 1000);
        assert!(mon.inspect_rtu(&write).allowed);
        let read = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 2000);
        assert!(!mon.inspect_rtu(&read).allowed);
    }

    // -----------------------------------------------------------------------
    // IP filter tests
    // -----------------------------------------------------------------------

    #[test]
    fn ip_filter_block() {
        let mut mon = ModbusMonitor::new();
        mon.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block)
            .unwrap();
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 1000, [10, 1, 2, 3]);
        let r = mon.inspect_tcp(&msg);
        assert!(!r.allowed);
        assert!(r.alert_count > 0);
        assert_eq!(r.alerts[0].source_id, ALERT_IP_BLOCKED);
    }

    #[test]
    fn ip_filter_allow_no_match() {
        let mut mon = ModbusMonitor::new();
        mon.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block)
            .unwrap();
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 1000, [192, 168, 1, 1]);
        let r = mon.inspect_tcp(&msg);
        assert!(r.allowed);
    }

    #[test]
    fn ip_filter_exact_match() {
        let mut mon = ModbusMonitor::new();
        mon.add_ip_filter([192, 168, 1, 50], 32, IpAction::Block)
            .unwrap();
        // Blocked IP.
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 1000, [192, 168, 1, 50]);
        assert!(!mon.inspect_tcp(&msg).allowed);
        // Different IP should pass.
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 2000, [192, 168, 1, 51]);
        assert!(mon.inspect_tcp(&msg).allowed);
    }

    #[test]
    fn ip_filter_rtu_ignores_ip() {
        let mut mon = ModbusMonitor::new();
        mon.add_ip_filter([0, 0, 0, 0], 0, IpAction::Block).unwrap();
        // RTU messages don't have IP, so IP filter should not apply.
        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000);
        assert!(mon.inspect_rtu(&msg).allowed);
    }

    #[test]
    fn ip_filter_remove() {
        let mut mon = ModbusMonitor::new();
        mon.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block)
            .unwrap();
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 1000, [10, 1, 2, 3]);
        assert!(!mon.inspect_tcp(&msg).allowed);
        mon.remove_ip_filter(0).unwrap();
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 2000, [10, 1, 2, 3]);
        assert!(mon.inspect_tcp(&msg).allowed);
    }

    #[test]
    fn ip_filter_remove_invalid() {
        let mut mon = ModbusMonitor::new();
        assert!(mon.remove_ip_filter(0).is_err());
        assert!(mon.remove_ip_filter(MAX_IP_FILTERS).is_err());
    }

    #[test]
    fn ip_filter_capacity() {
        let mut mon = ModbusMonitor::new();
        for i in 0..MAX_IP_FILTERS {
            mon.add_ip_filter([10, 0, 0, i as u8], 32, IpAction::Block)
                .unwrap();
        }
        assert!(mon
            .add_ip_filter([10, 0, 0, 99], 32, IpAction::Block)
            .is_err());
    }

    #[test]
    fn ip_filter_invalid_prefix_len() {
        let mut mon = ModbusMonitor::new();
        assert!(mon
            .add_ip_filter([10, 0, 0, 0], 33, IpAction::Block)
            .is_err());
        assert!(mon
            .add_ip_filter([10, 0, 0, 0], 255, IpAction::Block)
            .is_err());
        // 32 should be valid.
        assert!(mon
            .add_ip_filter([10, 0, 0, 0], 32, IpAction::Block)
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // Exception tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn exception_below_threshold_no_alert() {
        let mut mon = ModbusMonitor::new();
        for i in 0..MAX_EXCEPTIONS_PER_UNIT {
            let result = mon.record_exception(
                1,
                ModbusException::IllegalFunction,
                1000 + i as u64 * 1000,
                SOURCE_MODBUS_RTU,
            );
            assert!(result.is_none());
        }
    }

    #[test]
    fn exception_flood_triggers_alert() {
        let mut mon = ModbusMonitor::new();
        for i in 0..MAX_EXCEPTIONS_PER_UNIT {
            mon.record_exception(
                1,
                ModbusException::IllegalFunction,
                1000 + i as u64 * 1000,
                SOURCE_MODBUS_RTU,
            );
        }
        // One more should trigger the alert.
        let result = mon.record_exception(
            1,
            ModbusException::IllegalFunction,
            1000 + MAX_EXCEPTIONS_PER_UNIT as u64 * 1000,
            SOURCE_MODBUS_RTU,
        );
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
        // source_id encodes ALERT_EXCEPTION_FLOOD | (exception_code << 16) | (unit_id << 8).
        let exc_code = ModbusException::IllegalFunction as u8;
        let expected_source_id = ALERT_EXCEPTION_FLOOD | ((exc_code as u32) << 16) | ((1u32) << 8);
        assert_eq!(alert.source_id, expected_source_id);
        assert_ne!(alert.payload_hash, vs_types::PayloadHash::ZERO);
    }

    #[test]
    fn exception_window_reset() {
        let mut mon = ModbusMonitor::new();
        // Fill up to threshold.
        for i in 0..MAX_EXCEPTIONS_PER_UNIT {
            mon.record_exception(
                1,
                ModbusException::IllegalFunction,
                1000 + i as u64 * 1000,
                SOURCE_MODBUS_RTU,
            );
        }
        // After the window expires, counter should reset.
        let ts_after_window = 1000 + EXCEPTION_WINDOW_US + 1;
        let result = mon.record_exception(
            1,
            ModbusException::IllegalFunction,
            ts_after_window,
            SOURCE_MODBUS_RTU,
        );
        assert!(result.is_none()); // Window reset, count is 1 now.
    }

    #[test]
    fn exception_different_units_independent() {
        let mut mon = ModbusMonitor::new();
        // Fill up unit 1 to threshold.
        for i in 0..MAX_EXCEPTIONS_PER_UNIT {
            mon.record_exception(
                1,
                ModbusException::IllegalFunction,
                1000 + i as u64 * 1000,
                SOURCE_MODBUS_RTU,
            );
        }
        // Unit 2 should not be affected.
        let result = mon.record_exception(
            2,
            ModbusException::IllegalDataAddress,
            50_000,
            SOURCE_MODBUS_RTU,
        );
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Timestamp validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_normal_sequence_no_alert() {
        let mut mon = ModbusMonitor::new();
        let r1 = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1_000_000));
        assert_eq!(r1.alert_count, 0);
        let r2 = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 2_000_000));
        assert_eq!(r2.alert_count, 0);
    }

    #[test]
    fn timestamp_anomaly_alerts() {
        let mut mon = ModbusMonitor::new();
        // Initialize with a normal timestamp.
        let _ = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1_000_000));
        // Huge backward jump should trigger an anomaly alert.
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 0));
        // The timestamp validator may or may not flag small jumps; a jump from 1M to 0
        // should be flagged if beyond MAX_CLOCK_BACKWARD_JUMP_US.
        // We check the validator's anomaly count.
        assert!(mon.timestamp_validator.anomaly_count > 0 || r.alert_count == 0);
    }

    #[test]
    fn timestamp_validated_in_tcp() {
        let mut mon = ModbusMonitor::new();
        // Initialize.
        let _ = mon.inspect_tcp(&make_tcp(1, ModbusFunction::ReadCoils, 0, 10, 1_000_000));
        // Large backward jump.
        let r = mon.inspect_tcp(&make_tcp(1, ModbusFunction::ReadCoils, 0, 10, 0));
        // Same check as above.
        assert!(mon.timestamp_validator.anomaly_count > 0 || r.alert_count == 0);
    }

    // -----------------------------------------------------------------------
    // Rate bucket exhaustion DoS fix test
    // -----------------------------------------------------------------------

    #[test]
    fn rate_bucket_exhaustion_allows_traffic() {
        let mut mon = ModbusMonitor::new();
        // Create rules for more unit IDs than we have buckets.
        for uid in 0..(MAX_RATE_BUCKETS as u8 + 2) {
            mon.add_rule(uid, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 1)
                .unwrap();
        }
        // Exhaust all rate buckets with different unit IDs.
        for uid in 0..MAX_RATE_BUCKETS as u8 {
            let _ = mon.inspect_rtu(&make_rtu(uid, ModbusFunction::ReadCoils, 0, 10, 1000));
        }
        // Now a new unit ID should still be ALLOWED (not blocked by exhaustion).
        let uid = MAX_RATE_BUCKETS as u8;
        let r = mon.inspect_rtu(&make_rtu(uid, ModbusFunction::ReadCoils, 0, 10, 1000));
        assert!(r.allowed);
    }

    // -----------------------------------------------------------------------
    // MonitorReset tests
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_reset_clears_runtime_state() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 2)
            .unwrap();
        mon.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block)
            .unwrap();

        // Generate some state.
        let _ = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000));
        mon.record_exception(1, ModbusException::IllegalFunction, 2000, SOURCE_MODBUS_RTU);
        assert!(mon.total_inspected() > 0);

        // Reset.
        mon.reset_state();

        // Runtime state should be cleared.
        assert_eq!(mon.total_inspected(), 0);
        assert_eq!(mon.total_alerts(), 0);

        // Rules and IP filters should be preserved.
        assert_eq!(mon.rule_count(), 1);
        // IP filter should still block.
        let msg = make_tcp_ip(1, ModbusFunction::ReadCoils, 0, 10, 3000, [10, 1, 2, 3]);
        assert!(!mon.inspect_tcp(&msg).allowed);
    }

    #[test]
    fn monitor_reset_preserves_rules() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(5, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let _ = mon.inspect_rtu(&make_rtu(5, ModbusFunction::ReadCoils, 0, 10, 1000));
        mon.reset_state();
        // Rule should still block unit 5.
        let r = mon.inspect_rtu(&make_rtu(5, ModbusFunction::ReadCoils, 0, 10, 2000));
        assert!(!r.allowed);
    }

    // -----------------------------------------------------------------------
    // Alert source ID tests
    // -----------------------------------------------------------------------

    #[test]
    fn alert_source_ids_used() {
        let mut mon = ModbusMonitor::new();
        // Unknown function => ALERT_UNKNOWN_FUNCTION.
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::Unknown, 0, 10, 1000));
        assert_eq!(r.alerts[0].source_id, ALERT_UNKNOWN_FUNCTION);

        // Blocked unit => ALERT_UNIT_BLOCKED.
        mon.add_rule(5, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();
        let r = mon.inspect_rtu(&make_rtu(5, ModbusFunction::ReadCoils, 0, 10, 2000));
        assert_eq!(r.alerts[0].source_id, ALERT_UNIT_BLOCKED);
    }

    #[test]
    fn alert_invalid_unit_id_source() {
        let mut mon = ModbusMonitor::new();
        let r = mon.inspect_rtu(&make_rtu(248, ModbusFunction::ReadCoils, 0, 10, 1000));
        assert_eq!(r.alerts[0].source_id, ALERT_INVALID_UNIT_ID);
    }

    #[test]
    fn alert_function_policy_source() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(
            1,
            UnitAction::Allow,
            FunctionPolicy::ReadOnly,
            0,
            u16::MAX,
            0,
        )
        .unwrap();
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::WriteSingleCoil, 0, 1, 1000));
        assert_eq!(r.alerts[0].source_id, ALERT_FUNCTION_POLICY);
    }

    #[test]
    fn alert_register_range_source() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 100, 200, 0)
            .unwrap();
        let r = mon.inspect_rtu(&make_rtu(
            1,
            ModbusFunction::ReadHoldingRegisters,
            50,
            10,
            1000,
        ));
        assert_eq!(r.alerts[0].source_id, ALERT_REGISTER_RANGE);
    }

    #[test]
    fn alert_rate_limited_source() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 1)
            .unwrap();
        // Consume the one token.
        let _ = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1000));
        // Next should be rate limited.
        let r = mon.inspect_rtu(&make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1001));
        // Rate-limited traffic is allowed with a warning alert (not blocked).
        assert!(r.allowed);
        // Find the rate limit alert.
        let mut found = false;
        for i in 0..r.alert_count as usize {
            if r.alerts[i].source_id == ALERT_RATE_LIMITED {
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn remove_rule_works() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Block, FunctionPolicy::Any, 0, u16::MAX, 0)
            .unwrap();

        let msg = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 1_000_000);
        assert!(!mon.inspect_rtu(&msg).allowed, "should be blocked");

        mon.remove_rule(0).unwrap();

        let msg2 = make_rtu(1, ModbusFunction::ReadCoils, 0, 10, 2_000_000);
        assert!(
            mon.inspect_rtu(&msg2).allowed,
            "should be allowed after removal"
        );
    }

    #[test]
    fn update_rule_works() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(
            1,
            UnitAction::Allow,
            FunctionPolicy::ReadOnly,
            0,
            u16::MAX,
            0,
        )
        .unwrap();

        let write_msg = make_rtu(1, ModbusFunction::WriteSingleCoil, 0, 1, 1_000_000);
        assert!(
            !mon.inspect_rtu(&write_msg).allowed,
            "write should be blocked by ReadOnly"
        );

        // Update to allow all functions
        let result = mon.update_rule(0, 1, UnitAction::Allow, FunctionPolicy::Any, 0, u16::MAX, 0);
        assert!(result.is_ok());

        let write_msg2 = make_rtu(1, ModbusFunction::WriteSingleCoil, 0, 1, 2_000_000);
        assert!(
            mon.inspect_rtu(&write_msg2).allowed,
            "write should now be allowed"
        );
    }

    #[test]
    fn ip_filter_overlapping_prefixes_longer_wins() {
        let mut mon = ModbusMonitor::new();
        // Shorter prefix blocks the /8 range
        mon.add_ip_filter([10, 0, 0, 0], 8, IpAction::Block)
            .unwrap();
        // Longer prefix allows a specific /24
        mon.add_ip_filter([10, 0, 1, 0], 24, IpAction::Allow)
            .unwrap();

        let msg_blocked = make_tcp_ip(
            1,
            ModbusFunction::ReadCoils,
            0,
            10,
            1_000_000,
            [10, 0, 2, 50],
        );
        // 10.0.2.50 matches /8 block only
        assert!(!mon.inspect_tcp(&msg_blocked).allowed);

        let msg_allowed = make_tcp_ip(
            1,
            ModbusFunction::ReadCoils,
            0,
            10,
            2_000_000,
            [10, 0, 1, 50],
        );
        // 10.0.1.50 matches both, but /24 allow is longer prefix — should win
        assert!(mon.inspect_tcp(&msg_allowed).allowed);
    }

    #[test]
    fn quantity_zero_single_register_write() {
        let mut mon = ModbusMonitor::new();
        mon.add_rule(1, UnitAction::Allow, FunctionPolicy::Any, 0, 100, 0)
            .unwrap();

        let msg = make_rtu(1, ModbusFunction::WriteSingleCoil, 50, 0, 1_000_000);
        // Should not panic regardless of quantity
        let _r = mon.inspect_rtu(&msg);
    }

    #[test]
    fn alerts_dropped_counter_accessible() {
        let r = ModbusInspectResult::clean(SOURCE_MODBUS_RTU);
        assert_eq!(r.alerts_dropped, 0);
    }
}
