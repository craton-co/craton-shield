#![no_std]

//! `BACnet` (Building Automation and Control) intrusion detection monitor.
//!
//! Monitors `BACnet` traffic for security violations:
//!
//! - **Service choice allowlist** — restrict which `BACnet` services are
//!   permitted (readProperty, writeProperty, etc.).
//! - **Write protection** — block write operations to protected objects.
//! - **Object-level access control** — per-object read/write rules based on
//!   the `BACnetObjectIdentifier` tag parsed from the APDU payload of
//!   `readProperty` / `writeProperty` / `writePropertyMultiple` requests.

use vs_types::{AlertSeverity, VsError};
use vs_types_ind::{AlertCode, BacnetFrame, InspectResult, RateBucket, SOURCE_BACNET};

/// Backward-compatible type alias.
pub type BacnetInspectResult = InspectResult;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum service rules.
const MAX_SERVICE_RULES: usize = 16;

const MAX_RATE_BUCKETS: usize = 16;

const MAX_OBJECT_RULES: usize = 16;

/// `BACnet` confirmed service choices for write/dangerous operations.
const BACNET_ATOMIC_WRITE_FILE: u8 = 7;
const BACNET_ADD_LIST_ELEMENT: u8 = 8;
const BACNET_REMOVE_LIST_ELEMENT: u8 = 9;
const BACNET_CREATE_OBJECT: u8 = 10;
const BACNET_DELETE_OBJECT: u8 = 11;
const BACNET_READ_PROPERTY: u8 = 12;
const BACNET_WRITE_PROPERTY: u8 = 15;
const BACNET_WRITE_PROPERTY_MULTIPLE: u8 = 16;
/// `DeviceCommunicationControl` (service 17) can disable device communications
/// for a configurable hold-off period — effectively a protocol-level `DoS` weapon.
/// Must be treated as a dangerous/write operation so that `read_only` rules block
/// it.
const BACNET_DEVICE_COMMUNICATION_CONTROL: u8 = 17;
const BACNET_REINITIALIZE_DEVICE: u8 = 20;

// ---------------------------------------------------------------------------
// Service rule
// ---------------------------------------------------------------------------

/// Security rule for a `BACnet` service.
#[derive(Debug, Clone, Copy)]
struct ServiceRule {
    /// Allowed service choice (0xFF = any).
    service_choice: u8,
    /// Block write operations.
    read_only: bool,
    max_rate_per_sec: u16,
    active: bool,
}

impl ServiceRule {
    const fn empty() -> Self {
        Self {
            service_choice: 0xFF,
            read_only: false,
            max_rate_per_sec: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Object access rule
// ---------------------------------------------------------------------------

/// Wildcard value that matches any object type in access rules.
pub const BACNET_OBJECT_TYPE_ANY: u16 = 0xFFFF;

/// Wildcard value that matches any instance in access rules.
pub const BACNET_INSTANCE_ANY: u32 = 0xFFFF_FFFF;

/// Object-level access control rule.
///
/// Matched against the `BACnetObjectIdentifier` parsed from the APDU
/// payload of `readProperty` / `writeProperty` / `writePropertyMultiple`
/// requests. The identifier is a 32-bit value where bits 31..22 encode
/// the object type and bits 21..0 encode the instance.
#[derive(Debug, Clone, Copy)]
struct ObjectAccessRule {
    /// Object type to match, or [`BACNET_OBJECT_TYPE_ANY`] for wildcard.
    object_type: u16,
    /// Instance number to match, or [`BACNET_INSTANCE_ANY`] for wildcard.
    instance: u32,
    /// If `true`, writes to this object are denied.
    read_only: bool,
    /// If `true`, *all* access (read or write) to this object is denied.
    deny: bool,
    active: bool,
}

impl ObjectAccessRule {
    const fn empty() -> Self {
        Self {
            object_type: 0,
            instance: 0,
            read_only: false,
            deny: false,
            active: false,
        }
    }

    #[inline]
    fn matches(&self, object_type: u16, instance: u32) -> bool {
        if !self.active {
            return false;
        }
        (self.object_type == BACNET_OBJECT_TYPE_ANY || self.object_type == object_type)
            && (self.instance == BACNET_INSTANCE_ANY || self.instance == instance)
    }
}

// ---------------------------------------------------------------------------
// BACnet APDU object-identifier parser
// ---------------------------------------------------------------------------

/// Parsed `BACnetObjectIdentifier` — object type (10 bits) and instance (22 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacnetObjectId {
    pub object_type: u16,
    pub instance: u32,
}

/// Parse the leading context-tagged `BACnetObjectIdentifier` (context tag 0)
/// from a confirmed-service APDU payload.
///
/// `BACnet` confirmed requests like `readProperty`, `writeProperty`, and
/// `writePropertyMultiple` encode their first argument as a context-tagged
/// `BACnetObjectIdentifier`:
///
/// - Tag byte: `0x0C` — context class (bit 3 = 1), tag number 0, length 4.
/// - Value: 4 big-endian bytes packing `object_type` (bits 31..22) and
///   `instance` (bits 21..0).
///
/// Returns `None` if the payload is too short, the tag does not match,
/// or the length field is not 4. This parser is deliberately strict and
/// fails closed: malformed or unrecognized APDUs do not produce a parsed
/// identifier, which causes the object-rule path to be skipped (the
/// service-level filter still runs).
#[inline]
fn parse_object_identifier(payload: &[u8]) -> Option<BacnetObjectId> {
    // Try the common encoding first: context tag 0, constructed=false,
    // length=4 → tag byte 0x0C at offset 0.
    if payload.len() >= 5 && payload[0] == 0x0C {
        let raw = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let object_type = ((raw >> 22) & 0x3FF) as u16;
        let instance = raw & 0x003F_FFFF;
        return Some(BacnetObjectId {
            object_type,
            instance,
        });
    }
    // Fallback: scan for context tag 0 (0x0C) within the first 8 bytes.
    // Some BACnet implementations prepend optional tags (e.g., opening tags
    // 0x0E, service-specific headers) before the object identifier.
    // Bounded scan to maintain deterministic timing.
    let limit = payload.len().min(8);
    for offset in 1..limit {
        if payload[offset] == 0x0C && offset + 5 <= payload.len() {
            let raw = u32::from_be_bytes([
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
            ]);
            let object_type = ((raw >> 22) & 0x3FF) as u16;
            let instance = raw & 0x003F_FFFF;
            return Some(BacnetObjectId {
                object_type,
                instance,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// BACnet Monitor
// ---------------------------------------------------------------------------

/// `BACnet` intrusion detection monitor.
///
/// # Stack budget
///
/// Approximate stack usage: ~300 bytes.
pub struct BacnetMonitor {
    rules: [ServiceRule; MAX_SERVICE_RULES],
    rule_count: u8,
    strict_mode: bool,
    total_inspected: u64,
    total_alerts: u64,
    next_alert_id: u64,
    rate_buckets: [RateBucket; MAX_RATE_BUCKETS],
    object_rules: [ObjectAccessRule; MAX_OBJECT_RULES],
    object_rule_count: u8,
    /// Monotonic tick counter for rate-bucket LRU eviction ordering.
    rate_tick: u32,
}

impl BacnetMonitor {
    /// Create a new `BACnet` monitor (permissive).
    pub fn new() -> Self {
        Self {
            rules: [ServiceRule::empty(); MAX_SERVICE_RULES],
            rule_count: 0,
            strict_mode: false,
            total_inspected: 0,
            total_alerts: 0,
            next_alert_id: 1,
            rate_buckets: [RateBucket::empty(); MAX_RATE_BUCKETS],
            object_rules: [ObjectAccessRule::empty(); MAX_OBJECT_RULES],
            object_rule_count: 0,
            rate_tick: 0,
        }
    }

    /// Create a `BACnet` monitor in strict mode.
    pub fn new_strict() -> Self {
        let mut m = Self::new();
        m.strict_mode = true;
        m
    }

    /// Add a service choice rule.
    ///
    /// Returns [`VsError::InvalidInput`] if a rule for the same
    /// `service_choice` already exists. A duplicate rule would be permanently
    /// shadowed by the first match and can never take effect, so we reject it
    /// early rather than silently invalidating the operator's intent.
    pub fn add_service_rule(
        &mut self,
        service_choice: u8,
        read_only: bool,
        max_rate_per_sec: u16,
    ) -> Result<(), VsError> {
        if self.rule_count as usize >= MAX_SERVICE_RULES {
            return Err(VsError::ResourceExhausted);
        }
        // Reject duplicate service_choice — the second rule would be silently
        // shadowed by first-match logic, leading to unexpected policy behaviour.
        for i in 0..self.rule_count as usize {
            if self.rules[i].active && self.rules[i].service_choice == service_choice {
                return Err(VsError::InvalidInput);
            }
        }
        let idx = self.rule_count as usize;
        self.rules[idx] = ServiceRule {
            service_choice,
            read_only,
            max_rate_per_sec,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Inspect a `BACnet` frame.
    #[allow(clippy::too_many_lines)] // single-pass inspection pipeline
    pub fn inspect(&mut self, frame: &BacnetFrame) -> BacnetInspectResult {
        self.total_inspected = self.total_inspected.saturating_add(1);
        let mut result = InspectResult::clean(SOURCE_BACNET);

        if frame.payload_len_overflow() {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::High,
                SOURCE_BACNET,
                frame.invoke_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::PayloadOverflow,
            );
            return result;
        }

        // Find matching service rule.
        // Always iterate all rules to avoid timing side-channels.
        let mut matched: Option<usize> = None;
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            if r.active
                && (r.service_choice == 0xFF || r.service_choice == frame.service_choice)
                && matched.is_none()
            {
                matched = Some(i);
            }
        }

        // Service-level write / dangerous-operation protection runs only
        // when a service rule matched. Object-level checks below run
        // regardless so that a `deny_object` rule still applies in
        // permissive mode (no service rules configured).
        if let Some(rule_idx) = matched {
            let rule = &self.rules[rule_idx];
            let is_write = frame.service_choice == BACNET_ATOMIC_WRITE_FILE
                || frame.service_choice == BACNET_ADD_LIST_ELEMENT
                || frame.service_choice == BACNET_REMOVE_LIST_ELEMENT
                || frame.service_choice == BACNET_CREATE_OBJECT
                || frame.service_choice == BACNET_DELETE_OBJECT
                || frame.service_choice == BACNET_WRITE_PROPERTY
                || frame.service_choice == BACNET_WRITE_PROPERTY_MULTIPLE
                || frame.service_choice == BACNET_DEVICE_COMMUNICATION_CONTROL
                || frame.service_choice == BACNET_REINITIALIZE_DEVICE;
            if rule.read_only && is_write {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::High,
                    SOURCE_BACNET,
                    frame.invoke_id as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::WriteProtection,
                );
                return result;
            }
        }

        // Object-level access control. Only services whose first argument
        // is a `BACnetObjectIdentifier` are parsed. For other services the
        // object-rule path is skipped entirely.
        let parses_object_id = matches!(
            frame.service_choice,
            BACNET_READ_PROPERTY | BACNET_WRITE_PROPERTY | BACNET_WRITE_PROPERTY_MULTIPLE
        );
        if parses_object_id && self.object_rule_count > 0 {
            let payload = &frame.payload[..frame.valid_payload_len()];
            if let Some(oid) = parse_object_identifier(payload) {
                for i in 0..self.object_rule_count as usize {
                    let orule = &self.object_rules[i];
                    if !orule.matches(oid.object_type, oid.instance) {
                        continue;
                    }
                    // Deny takes precedence — blocks reads AND writes.
                    if orule.deny {
                        result.allowed = false;
                        result.push_alert_with_code(
                            AlertSeverity::High,
                            SOURCE_BACNET,
                            frame.invoke_id as u32,
                            frame.timestamp_us,
                            &mut self.next_alert_id,
                            &mut self.total_alerts,
                            AlertCode::ObjectAccessDenied,
                        );
                        return result;
                    }
                    // Read-only object: block writes.
                    let is_object_write = frame.service_choice == BACNET_WRITE_PROPERTY
                        || frame.service_choice == BACNET_WRITE_PROPERTY_MULTIPLE;
                    if orule.read_only && is_object_write {
                        result.allowed = false;
                        result.push_alert_with_code(
                            AlertSeverity::High,
                            SOURCE_BACNET,
                            frame.invoke_id as u32,
                            frame.timestamp_us,
                            &mut self.next_alert_id,
                            &mut self.total_alerts,
                            AlertCode::ObjectAccessDenied,
                        );
                        return result;
                    }
                    // First matching rule wins.
                    break;
                }
            }
        }

        // Strict-mode "no matching service rule" rejection runs after
        // object-rule checks so that a more specific object-level deny
        // alert takes precedence when both would apply.
        let Some(rule_idx) = matched else {
            if self.strict_mode {
                result.allowed = false;
                result.push_alert_with_code(
                    AlertSeverity::Medium,
                    SOURCE_BACNET,
                    frame.invoke_id as u32,
                    frame.timestamp_us,
                    &mut self.next_alert_id,
                    &mut self.total_alerts,
                    AlertCode::NoMatchingRule,
                );
            }
            return result;
        };

        // Rate limiting (only when a service rule matched).
        let max_rate = self.rules[rule_idx].max_rate_per_sec;
        if max_rate > 0
            && !self.rate_check(frame.service_choice as u32, max_rate, frame.timestamp_us)
        {
            result.allowed = false;
            result.push_alert_with_code(
                AlertSeverity::Medium,
                SOURCE_BACNET,
                frame.invoke_id as u32,
                frame.timestamp_us,
                &mut self.next_alert_id,
                &mut self.total_alerts,
                AlertCode::RateExceeded,
            );
        }

        result
    }

    fn rate_check(&mut self, key: u32, max_rate: u16, now_us: u64) -> bool {
        self.rate_tick = self.rate_tick.wrapping_add(1);
        let now_tick = self.rate_tick;

        // Single-pass: find matching bucket, first free slot, and LRU victim.
        let mut first_free: Option<usize> = None;
        let mut lru_idx: usize = 0;
        let mut lru_age: u32 = 0;
        for (i, b) in self.rate_buckets.iter_mut().enumerate() {
            if b.active {
                if b.key == key {
                    b.last_used = now_tick;
                    return b.try_consume(now_us);
                }
                let age = now_tick.wrapping_sub(b.last_used);
                if age >= lru_age {
                    lru_age = age;
                    lru_idx = i;
                }
            } else if first_free.is_none() {
                first_free = Some(i);
            }
        }

        // Allocate in first free slot, or evict LRU.
        let slot = first_free.unwrap_or(lru_idx);
        self.rate_buckets[slot] = RateBucket {
            key,
            tokens: max_rate.saturating_sub(1),
            capacity: max_rate,
            last_refill_us: now_us,
            active: true,
            last_used: now_tick,
        };
        true
    }

    /// Add a read-only object-level access rule.
    ///
    /// Writes targeting the matching `BACnetObjectIdentifier` will be
    /// blocked and an [`AlertCode::ObjectAccessDenied`] alert emitted.
    /// Pass [`BACNET_OBJECT_TYPE_ANY`] or [`BACNET_INSTANCE_ANY`] for
    /// wildcard matching.
    pub fn add_object_rule(
        &mut self,
        object_type: u16,
        instance: u32,
        read_only: bool,
    ) -> Result<(), VsError> {
        if self.object_rule_count as usize >= MAX_OBJECT_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.object_rule_count as usize;
        self.object_rules[idx] = ObjectAccessRule {
            object_type,
            instance,
            read_only,
            deny: false,
            active: true,
        };
        self.object_rule_count += 1;
        Ok(())
    }

    /// Add a full-deny object-level access rule.
    ///
    /// Both reads and writes targeting the matching object are blocked.
    /// Pass [`BACNET_OBJECT_TYPE_ANY`] or [`BACNET_INSTANCE_ANY`] for
    /// wildcard matching.
    pub fn deny_object(&mut self, object_type: u16, instance: u32) -> Result<(), VsError> {
        if self.object_rule_count as usize >= MAX_OBJECT_RULES {
            return Err(VsError::ResourceExhausted);
        }
        let idx = self.object_rule_count as usize;
        self.object_rules[idx] = ObjectAccessRule {
            object_type,
            instance,
            read_only: false,
            deny: true,
            active: true,
        };
        self.object_rule_count += 1;
        Ok(())
    }

    /// Number of configured object-level access rules.
    pub fn object_rule_count(&self) -> usize {
        self.object_rule_count as usize
    }

    pub fn total_inspected(&self) -> u64 {
        self.total_inspected
    }

    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    pub fn next_alert_id(&self) -> u64 {
        self.next_alert_id
    }

    /// Reset all state. Settings (`strict_mode`) are preserved.
    pub fn reset(&mut self) {
        let strict = self.strict_mode;
        *self = Self::new();
        self.strict_mode = strict;
    }
}

impl Default for BacnetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_allows_all() {
        let mut mon = BacnetMonitor::new();
        let f = BacnetFrame::default();
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_blocks_unknown() {
        let mut mon = BacnetMonitor::new_strict();
        let f = BacnetFrame {
            service_choice: 12, // readProperty
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn strict_allows_configured_service() {
        let mut mon = BacnetMonitor::new_strict();
        mon.add_service_rule(12, false, 0).unwrap(); // readProperty
        let f = BacnetFrame {
            service_choice: 12,
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn write_protection() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap(); // Match any, read-only
        let f = BacnetFrame {
            service_choice: BACNET_WRITE_PROPERTY,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn read_allowed_when_write_protected() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: 12, // readProperty
            ..Default::default()
        };
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn payload_overflow_rejected() {
        let mut mon = BacnetMonitor::new();
        let f = BacnetFrame {
            payload_len: 300,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn reset_preserves_mode() {
        let mut mon = BacnetMonitor::new_strict();
        mon.add_service_rule(12, false, 0).unwrap();
        let _ = mon.inspect(&BacnetFrame {
            service_choice: 12,
            ..Default::default()
        });
        mon.reset();
        assert_eq!(mon.total_inspected(), 0);
        assert!(!mon.inspect(&BacnetFrame::default()).allowed);
    }

    #[test]
    fn default_constructor() {
        let mon = BacnetMonitor::default();
        assert_eq!(mon.total_inspected(), 0);
    }

    #[test]
    fn write_property_multiple_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_WRITE_PROPERTY_MULTIPLE,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn add_service_rule_at_capacity_returns_resource_exhausted() {
        let mut mon = BacnetMonitor::new();
        for i in 0..MAX_SERVICE_RULES {
            mon.add_service_rule(i as u8, false, 0).unwrap();
        }
        let err = mon.add_service_rule(99, false, 0).unwrap_err();
        assert!(matches!(err, VsError::ResourceExhausted));
    }

    #[test]
    fn create_object_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_CREATE_OBJECT,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn delete_object_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_DELETE_OBJECT,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn reinitialize_device_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_REINITIALIZE_DEVICE,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn wildcard_rule_with_specific_service_choice() {
        let mut mon = BacnetMonitor::new_strict();
        // Specific rule for readProperty (SC=12), not read-only.
        mon.add_service_rule(12, false, 0).unwrap();
        // Wildcard rule, read-only — matches everything else.
        mon.add_service_rule(0xFF, true, 0).unwrap();

        // readProperty should be allowed (matches specific rule first).
        let read_frame = BacnetFrame {
            service_choice: 12,
            ..Default::default()
        };
        assert!(mon.inspect(&read_frame).allowed);

        // writeProperty should be blocked (matches wildcard, read-only).
        let write_frame = BacnetFrame {
            service_choice: BACNET_WRITE_PROPERTY,
            ..Default::default()
        };
        assert!(!mon.inspect(&write_frame).allowed);

        // A non-write service not explicitly listed still matches wildcard
        // and is allowed (wildcard is read-only, but SC=14 is not a write).
        let other_frame = BacnetFrame {
            service_choice: 14,
            ..Default::default()
        };
        assert!(mon.inspect(&other_frame).allowed);
    }

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, false, 3).unwrap();
        for i in 0..3u64 {
            let f = BacnetFrame {
                service_choice: 12,
                timestamp_us: i * 100,
                ..Default::default()
            };
            assert!(mon.inspect(&f).allowed, "req {i} should pass");
        }
        let f = BacnetFrame {
            service_choice: 12,
            timestamp_us: 300,
            ..Default::default()
        };
        assert!(!mon.inspect(&f).allowed);
    }

    #[test]
    fn object_rule_storage() {
        let mut mon = BacnetMonitor::new();
        assert_eq!(mon.object_rule_count(), 0);
        mon.add_object_rule(8, 1, true).unwrap();
        assert_eq!(mon.object_rule_count(), 1);
    }

    #[test]
    fn object_rule_capacity() {
        let mut mon = BacnetMonitor::new();
        for i in 0..16u16 {
            mon.add_object_rule(i, 0, false).unwrap();
        }
        assert!(mon.add_object_rule(99, 0, false).is_err());
    }

    // -------------------------------------------------------------------
    // Object-identifier parser tests
    // -------------------------------------------------------------------

    /// Build an APDU payload containing a context-tag-0 `BACnetObjectIdentifier`
    /// (tag byte 0x0C + 4 big-endian value bytes), optionally followed by junk.
    fn oid_payload(object_type: u16, instance: u32) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = 0x0C;
        let raw = ((object_type as u32 & 0x3FF) << 22) | (instance & 0x003F_FFFF);
        let bytes = raw.to_be_bytes();
        buf[1..5].copy_from_slice(&bytes);
        buf
    }

    fn bacnet_frame_with_oid(service_choice: u8, object_type: u16, instance: u32) -> BacnetFrame {
        let buf = oid_payload(object_type, instance);
        let mut payload = [0u8; MAX_BACNET_PAYLOAD_LEN_FALLBACK];
        payload[..buf.len()].copy_from_slice(&buf);
        BacnetFrame {
            service_choice,
            payload,
            payload_len: buf.len() as u16,
            ..Default::default()
        }
    }

    // Pull in the canonical max length at test time via the re-export.
    const MAX_BACNET_PAYLOAD_LEN_FALLBACK: usize = vs_types_ind::MAX_BACNET_PAYLOAD_LEN;

    #[test]
    fn parse_object_identifier_valid() {
        // analog-input (type=0) instance 42
        let buf = oid_payload(0, 42);
        let oid = parse_object_identifier(&buf[..5]).expect("must parse");
        assert_eq!(oid.object_type, 0);
        assert_eq!(oid.instance, 42);

        // analog-value (type=2) instance 0x3FFFFF (max 22-bit)
        let buf = oid_payload(2, 0x3F_FFFF);
        let oid = parse_object_identifier(&buf[..5]).expect("must parse");
        assert_eq!(oid.object_type, 2);
        assert_eq!(oid.instance, 0x3F_FFFF);

        // binary-output (type=4) instance 7
        let buf = oid_payload(4, 7);
        let oid = parse_object_identifier(&buf[..5]).expect("must parse");
        assert_eq!(oid.object_type, 4);
        assert_eq!(oid.instance, 7);
    }

    #[test]
    fn parse_object_identifier_rejects_short_payload() {
        assert!(parse_object_identifier(&[]).is_none());
        assert!(parse_object_identifier(&[0x0C]).is_none());
        assert!(parse_object_identifier(&[0x0C, 0, 0, 0]).is_none());
    }

    #[test]
    fn parse_object_identifier_rejects_wrong_tag() {
        // Tag byte 0x00 (application class, not context class) — must fail.
        let bad = [0x00, 0, 0, 0, 42];
        assert!(parse_object_identifier(&bad).is_none());
        // Tag byte 0x1C (context tag number 1, not 0) — must fail.
        let bad = [0x1C, 0, 0, 0, 42];
        assert!(parse_object_identifier(&bad).is_none());
    }

    #[test]
    fn object_rule_blocks_write_to_specific_object() {
        let mut mon = BacnetMonitor::new();
        // Analog-output object instance 5 is read-only.
        mon.add_object_rule(1, 5, true).unwrap();

        // WriteProperty on (1, 5) → blocked.
        let f = bacnet_frame_with_oid(BACNET_WRITE_PROPERTY, 1, 5);
        let r = mon.inspect(&f);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::ObjectAccessDenied);

        // WriteProperty on (1, 6) → allowed.
        let f = bacnet_frame_with_oid(BACNET_WRITE_PROPERTY, 1, 6);
        assert!(mon.inspect(&f).allowed);

        // ReadProperty on (1, 5) → allowed (read-only rule permits reads).
        let f = bacnet_frame_with_oid(BACNET_READ_PROPERTY, 1, 5);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn object_rule_wildcard_type_blocks_all_writes_to_instance() {
        let mut mon = BacnetMonitor::new();
        mon.add_object_rule(BACNET_OBJECT_TYPE_ANY, 99, true)
            .unwrap();

        // Any object type, instance 99, write → blocked.
        for ot in [0u16, 1, 2, 4] {
            let f = bacnet_frame_with_oid(BACNET_WRITE_PROPERTY, ot, 99);
            assert!(!mon.inspect(&f).allowed, "type {ot} should be blocked");
        }
        // Instance 100 → allowed.
        let f = bacnet_frame_with_oid(BACNET_WRITE_PROPERTY, 1, 100);
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn object_deny_blocks_reads_and_writes() {
        let mut mon = BacnetMonitor::new();
        mon.deny_object(8, 1).unwrap(); // device object instance 1

        let fr = bacnet_frame_with_oid(BACNET_READ_PROPERTY, 8, 1);
        let r = mon.inspect(&fr);
        assert!(!r.allowed);
        assert_eq!(r.alert_codes[0], AlertCode::ObjectAccessDenied);

        let fw = bacnet_frame_with_oid(BACNET_WRITE_PROPERTY, 8, 1);
        assert!(!mon.inspect(&fw).allowed);
    }

    #[test]
    fn object_rule_ignored_for_non_property_services() {
        let mut mon = BacnetMonitor::new();
        mon.deny_object(BACNET_OBJECT_TYPE_ANY, BACNET_INSTANCE_ANY)
            .unwrap();

        // ReinitializeDevice does not carry a BACnetObjectIdentifier first —
        // object rule path is skipped, service-level logic applies.
        let f = BacnetFrame {
            service_choice: BACNET_REINITIALIZE_DEVICE,
            ..Default::default()
        };
        // No service-rule read-only, so it is allowed.
        assert!(mon.inspect(&f).allowed);
    }

    #[test]
    fn malformed_object_identifier_fails_closed_skips_object_rule() {
        let mut mon = BacnetMonitor::new();
        mon.deny_object(BACNET_OBJECT_TYPE_ANY, BACNET_INSTANCE_ANY)
            .unwrap();

        // WriteProperty with a malformed payload (bad tag byte).
        let mut payload = [0u8; MAX_BACNET_PAYLOAD_LEN_FALLBACK];
        payload[0] = 0xFF; // not a context-tag-0 object-id
        let f = BacnetFrame {
            service_choice: BACNET_WRITE_PROPERTY,
            payload,
            payload_len: 5,
            ..Default::default()
        };
        // Object rule cannot match → not blocked by object filter.
        // Service-level rule absent in permissive mode → allowed.
        assert!(mon.inspect(&f).allowed);
    }

    // -------------------------------------------------------------------
    // Missing write-service coverage (SC 7, 8, 9)
    // -------------------------------------------------------------------

    #[test]
    fn atomic_write_file_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_ATOMIC_WRITE_FILE,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f).allowed,
            "AtomicWriteFile must be blocked by read-only rule"
        );
    }

    #[test]
    fn add_list_element_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_ADD_LIST_ELEMENT,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f).allowed,
            "AddListElement must be blocked by read-only rule"
        );
    }

    #[test]
    fn remove_list_element_blocked_when_read_only() {
        let mut mon = BacnetMonitor::new();
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_REMOVE_LIST_ELEMENT,
            ..Default::default()
        };
        assert!(
            !mon.inspect(&f).allowed,
            "RemoveListElement must be blocked by read-only rule"
        );
    }

    // -------------------------------------------------------------------
    // VULN-01: DeviceCommunicationControl (service 17) is treated as a
    // write operation so that read-only rules block it.
    // Without this fix, a read-only wildcard rule would permit service 17,
    // giving an attacker a protocol-level DoS weapon to disable
    // communications for an arbitrary hold-off period.
    // -------------------------------------------------------------------

    #[test]
    fn vuln01_device_communication_control_blocked_by_read_only() {
        let mut mon = BacnetMonitor::new();
        // Wildcard read-only rule: allow any service, but block writes.
        mon.add_service_rule(0xFF, true, 0).unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_DEVICE_COMMUNICATION_CONTROL,
            ..Default::default()
        };
        let result = mon.inspect(&f);
        assert!(
            !result.allowed,
            "DeviceCommunicationControl (17) must be blocked by a read-only rule"
        );
        assert_eq!(result.alert_count, 1, "one write-protection alert expected");
    }

    #[test]
    fn vuln01_device_communication_control_allowed_if_not_read_only() {
        let mut mon = BacnetMonitor::new();
        // Explicit rule for service 17, not read-only.
        mon.add_service_rule(BACNET_DEVICE_COMMUNICATION_CONTROL, false, 0)
            .unwrap();
        let f = BacnetFrame {
            service_choice: BACNET_DEVICE_COMMUNICATION_CONTROL,
            ..Default::default()
        };
        let result = mon.inspect(&f);
        assert!(
            result.allowed,
            "service 17 must be allowed when explicitly permitted"
        );
    }

    // -------------------------------------------------------------------
    // VULN-05: Duplicate service choice in add_service_rule is rejected.
    // Without this fix, the second rule would be silently ignored, giving
    // operators a false sense of security when they attempt to tighten a
    // previously registered rule.
    // -------------------------------------------------------------------

    #[test]
    fn vuln05_duplicate_service_rule_rejected() {
        let mut mon = BacnetMonitor::new();
        // First rule: allow readProperty, not read-only.
        mon.add_service_rule(12, false, 0).unwrap();
        // Second rule for the same service_choice must be rejected.
        let result = mon.add_service_rule(12, true, 0);
        assert!(
            result.is_err(),
            "duplicate service_choice must return Err, got Ok"
        );
    }

    #[test]
    fn vuln05_different_service_choices_accepted() {
        let mut mon = BacnetMonitor::new_strict();
        mon.add_service_rule(12, false, 0).unwrap();
        // Different service_choice must succeed and be honoured.
        mon.add_service_rule(14, false, 0).unwrap();
        let f = BacnetFrame {
            service_choice: 14,
            ..Default::default()
        };
        assert!(
            mon.inspect(&f).allowed,
            "second distinct rule must be applied"
        );
    }
}
